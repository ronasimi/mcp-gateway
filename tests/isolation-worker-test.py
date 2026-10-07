"""Offline packet fixtures. No captures, probes, DNS requests or local sockets."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import scapy.config
# Disable network enumeration only in this offline test process.
scapy.config._set_conf_sockets = lambda: None
scapy.config.conf.route_autoload = False
scapy.config.conf.route6_autoload = False
from scapy.all import ARP, DNS, DNSQR, DNSRR, DNSRRSRV, Ether, IP, ICMP, UDP, Raw
spec = importlib.util.spec_from_file_location('worker', Path(__file__).resolve().parents[1] / 'src/domains/network/recon/isolation-worker.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
A = {'interface': 'wlan0', 'local_mac': '00:11:22:33:44:55', 'source_address': '192.168.1.20', 'gateway': '192.168.1.1',
     'local_addresses': [{'address': '192.168.1.20'}]}
GW = '00:aa:bb:cc:dd:ee'
PEER = '00:aa:bb:cc:dd:ff'

class Fixtures(unittest.TestCase):
    def test_arp_broadcast_and_unicast_separation(self):
        packet = Ether(src=PEER, dst='ff:ff:ff:ff:ff:ff')/ARP(psrc='192.168.1.9', hwsrc=PEER, pdst='192.168.1.1')
        row = w.packet_observations(packet, {'arp'})[0]
        self.assertEqual(row['claimed_sender_ip'], '192.168.1.9')
        packet[Ether].dst = GW
        self.assertEqual(w.packet_observations(packet, {'arp'}), [])

    def test_mdns_sources_and_advertised_addresses_remain_separate(self):
        dns = DNS(qr=1, an=[DNSRR(rrname='tv.local', type='A', ttl=120, rdata='192.168.20.4'),
                           DNSRRSRV(rrname='TV._http._tcp.local', port=8009, target='tv.local')])
        packet = Ether(src=GW, dst='01:00:5e:00:00:fb')/IP(src='192.168.1.1', dst='224.0.0.251')/UDP(sport=5353,dport=5353)/dns
        row = w.packet_observations(Ether(bytes(packet)), {'mdns'})[0]
        self.assertEqual(row['packet_source_address'], '192.168.1.1')
        self.assertEqual(row['records'][0]['advertised_address'], '192.168.20.4')
        self.assertEqual(row['records'][1]['port'], 8009)

    def test_llmnr_query_is_not_device_advertisement(self):
        packet = Ether(src=PEER,dst='01:00:5e:00:00:fc')/IP(src='192.168.1.4',dst='224.0.0.252')/UDP(sport=40000,dport=5355)/DNS(qd=DNSQR(qname='printer'))
        row = w.packet_observations(packet, {'llmnr'})[0]
        self.assertFalse(row['response'])
        self.assertEqual(row['questions'], ['printer'])
        self.assertEqual(row['records'], [])

    def test_ssdp_metadata_is_bounded_and_location_is_never_fetched(self):
        packet = Ether(src=PEER,dst='01:00:5e:7f:ff:fa')/IP(src='192.168.1.4',dst='239.255.255.250')/UDP(sport=1900,dport=1900)/Raw(b'NOTIFY * HTTP/1.1\r\nSERVER: TV\r\nLOCATION: http://192.168.1.4/device.xml\r\nAUTHORIZATION: hidden\r\n')
        row = w.packet_observations(packet, {'ssdp'})[0]
        self.assertEqual(row['headers']['server'], 'TV')
        self.assertNotIn('authorization', row['headers'])

    def test_capture_sends_nothing_and_reports_caps_local_sources_and_zero(self):
        pkt = Ether(src=PEER,dst='ff:ff:ff:ff:ff:ff')/ARP(psrc='192.168.1.9',hwsrc=PEER)
        def fake_sniff(**kwargs):
            self.assertFalse(kwargs['store']); self.assertFalse(kwargs['promisc'])
            for n in range(3):
                pkt[ARP].psrc = f'192.168.1.{9+n}'
                kwargs['prn'](pkt)
        with patch.object(w,'sniff',fake_sniff):
            result = w.observe({**A,'max_observations':1,'max_packets':3})
        self.assertFalse(result['complete']); self.assertEqual(len(result['observations']),1)
        self.assertEqual(result['packets_sent'],0)
        with patch.object(w,'sniff',lambda **kwargs: None):
            result = w.observe(A)
        self.assertEqual(result['observations'],[]);self.assertFalse(result['isolation_failure_confirmed'])

    def test_proxy_does_not_mark_gateway_claims_as_live(self):
        sent=w.arp_packet(A,'192.168.1.9')
        reply=Ether(src=GW)/ARP(op=2,psrc='192.168.1.9',hwsrc=GW)
        with patch.object(w,'gateway_mac',return_value=GW),patch.object(w,'srp',return_value=([(sent,reply)],[])) as probe:
            result=w.proxy({**A,'cidr':'192.168.1.0/28'})
        self.assertEqual(result['proxy_arp_candidate_ips'],['192.168.1.9'])
        self.assertFalse(result['responses'][0]['peer_liveness_confirmed'])
        self.assertEqual(probe.call_args.kwargs['inter'],0.1)
        self.assertFalse(probe.call_args.kwargs['multi'])

    def test_echo_validation_rejects_unrelated_and_accepts_quoted_ttl_control(self):
        peer='192.168.1.9'
        reply=Ether(src=GW,dst=A['local_mac'])/IP(src=peer)/ICMP(type=0,id=10,seq=2)
        self.assertTrue(w.echo_result(reply,peer,10,2)['target_echo_reply'])
        self.assertFalse(w.echo_result(reply,peer,11,2)['target_echo_reply'])
        quoted=IP(src=A['source_address'],dst=peer)/ICMP(id=10,seq=2)
        control=Ether(src=GW,dst=A['local_mac'])/IP(src=A['gateway'])/ICMP(type=11,code=0)/Raw(bytes(quoted)[:28])
        control=Ether(bytes(control))
        self.assertEqual(w.echo_result(control,peer,10,2)['status'],'matched_icmp_error')
        self.assertEqual(w.echo_result(control,peer,10,3)['status'],'unmatched_response')

    def test_forced_gateway_frame_retains_peer_ip_and_isolation_is_unconfirmed(self):
        peer='192.168.1.9'; frames=[]
        def respond(frame,**kwargs):
            frames.append(frame)
            if ARP in frame:return Ether(src=PEER)/ARP(op=2,psrc=peer,hwsrc=PEER)
            if frame[Ether].dst==PEER:return None
            if frame[IP].ttl==1:
                return Ether(src=GW)/IP(src=A['gateway'])/ICMP(type=11,code=0)/Raw(bytes(frame[IP])[:28])
            return Ether(src=GW)/IP(src=peer)/ICMP(type=0,id=frame[ICMP].id,seq=frame[ICMP].seq)
        with patch.object(w,'gateway_mac',return_value=GW),patch.object(w,'srp1',respond):
            result=w.hairpin({**A,'peer_targets':[peer]})
        row=result['results'][0]
        self.assertTrue(row['gateway_path_target_replied']);self.assertTrue(row['isolation_bypass_candidate'])
        self.assertFalse(row['isolation_bypass_confirmed'])
        self.assertTrue(all(f[IP].dst==peer for f in frames if IP in f))

    def test_dns_response_validation_checks_id_question_qr_and_class(self):
        response=DNS(id=10,qr=1,qd=DNSQR(qname='printer.lan',qtype='A'))
        self.assertTrue(w.valid_dns_response(response,10,'printer.lan',1))
        self.assertFalse(w.valid_dns_response(response,11,'printer.lan',1))
        self.assertFalse(w.valid_dns_response(response,10,'other.lan',1))
        response.qr=0;self.assertFalse(w.valid_dns_response(response,10,'printer.lan',1))

    def test_dns_uses_rd0_binds_source_and_ignores_wrong_transaction(self):
        class Sock:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def setsockopt(self,*args):self.option=args
            def bind(self,addr):self.bound=addr
            def connect(self,addr):self.server=addr
            def send(self,payload):self.query=DNS(payload);self.calls=0
            def settimeout(self,timeout):pass
            def recv(self,size):
                self.calls+=1
                return bytes(DNS(id=(self.query.id+1)%65536 if self.calls==1 else self.query.id,qr=1,ra=1,qd=self.query.qd,
                                 an=DNSRR(rrname='printer.lan',type='A',ttl=70,rdata='192.168.1.9')))
        sock=Sock()
        with patch.object(w.socket,'socket',return_value=sock):
            result=w.dns_sample(A['gateway'],A['source_address'],'printer.lan',1,1,'wlan0')
        self.assertEqual(sock.option[2],b'wlan0\0')
        self.assertEqual(sock.query.rd,0);self.assertEqual(sock.bound,(A['source_address'],0))
        self.assertEqual(sock.calls,2);self.assertEqual(result['cache_evidence'],'nonrecursive_non_authoritative_answer')

    def test_output_byte_budget_reports_omissions_without_broken_json(self):
        result={'complete':True,'observations':[{'protocol':'mdns','records':[{'txt':['x'*10000]}]} for _ in range(100)]}
        encoded=w.bounded_json(result,byte_limit=32000)
        decoded=w.json.loads(encoded)
        self.assertLessEqual(len(encoded.encode()),32000)
        self.assertFalse(decoded['complete'])
        self.assertTrue(decoded['output_byte_limit_reached'])
        self.assertGreater(decoded['evidence_entries_omitted_by_byte_limit'],0)

    def test_dns_baseline_applies_only_to_matching_rr_and_never_attributes_client(self):
        sample={'status':'response','answers':[{'name':'printer.lan','type':'A','ttl':50},{'name':'other.lan','type':'A','ttl':50}]}
        with patch.object(w,'dns_sample',return_value=sample):
            result=w.dns_cache({**A,'server':A['gateway'],'names':['printer.lan'],'samples':1,'baseline_ttl':100})
        row=result['results'][0]
        self.assertTrue(row['samples'][0]['answers'][0]['below_supplied_baseline'])
        self.assertNotIn('below_supplied_baseline',row['samples'][0]['answers'][1])
        self.assertFalse(row['querying_client_identified']);self.assertFalse(row['device_presence_confirmed'])

if __name__=='__main__':unittest.main()

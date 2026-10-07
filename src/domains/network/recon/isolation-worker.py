#!/usr/bin/env python3
"""Bounded host packet observations. Invoked only by the policy-checked service."""
import ipaddress
import json
import secrets
import socket
import sys
import time
from collections import Counter
from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, IPv6, UDP, conf, sniff, srp, srp1

conf.verb = 0
TYPES = {1: 'A', 28: 'AAAA', 12: 'PTR', 33: 'SRV', 16: 'TXT', 5: 'CNAME', 2: 'NS', 6: 'SOA'}
QTYPE = {v: k for k, v in TYPES.items()}


def text(value, cap=253):
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    return ''.join(c if c.isprintable() else ' ' for c in str(value))[:cap]


def records(dns, section='an', cap=32):
    out = []
    section_rr = getattr(dns, section, [])
    # Scapy >=2.5 provides list fields; older packet-chain form is supported too.
    if not isinstance(section_rr, list):
        chain = []
        rr = section_rr
        for _ in range(min(int(getattr(dns, section + 'count', 0) or 0), cap)):
            if not hasattr(rr, 'type'):
                break
            chain.append(rr)
            rr = rr.payload
        section_rr = chain
    for rr in section_rr[:cap]:
        row = {'name': text(rr.rrname).rstrip('.'), 'type': TYPES.get(int(rr.type), str(rr.type)), 'ttl': int(rr.ttl)}
        if rr.type == 33:
            row.update(target=text(rr.target).rstrip('.'), port=int(rr.port))
        elif rr.type in (1, 28):
            row['advertised_address'] = text(rr.rdata)
        elif rr.type in (2, 5, 12):
            row['target'] = text(rr.rdata).rstrip('.')
        elif rr.type == 16:
            row['txt'] = [text(v, 160) for v in (rr.rdata if isinstance(rr.rdata, list) else [rr.rdata])[:8]]
        out.append(row)
    return out


def packet_observations(packet, protocols):
    src_mac = text(packet[Ether].src, 17).lower() if Ether in packet else None
    if ARP in packet and 'arp' in protocols:
        arp = packet[ARP]
        # Restrict passive ARP findings to broadcast/multicast delivery.
        dst = packet[Ether].dst if Ether in packet else ''
        if not dst or not (int(dst.split(':')[0], 16) & 1):
            return []
        return [{'protocol': 'arp', 'packet_source_mac': src_mac,
                 'claimed_sender_ip': arp.psrc, 'claimed_sender_mac': arp.hwsrc.lower(),
                 'requested_ip': arp.pdst, 'operation': int(arp.op)}]
    if UDP not in packet or not (IP in packet or IPv6 in packet):
        return []
    network = packet[IP] if IP in packet else packet[IPv6]
    # Include broadcast and multicast only, never ordinary unicast DNS traffic.
    dst_ip = ipaddress.ip_address(network.dst)
    dst_mac = packet[Ether].dst if Ether in packet else ''
    if not dst_ip.is_multicast and not (dst_mac and int(dst_mac.split(':')[0], 16) & 1):
        return []
    udp = packet[UDP]
    ports = {int(udp.sport), int(udp.dport)}
    protocol = 'mdns' if 5353 in ports else 'llmnr' if 5355 in ports else 'ssdp' if 1900 in ports else None
    if protocol not in protocols:
        return []
    base = {'protocol': protocol, 'packet_source_address': network.src,
            'packet_source_mac': src_mac, 'destination_address': network.dst}
    payload = bytes(udp.payload)
    if protocol == 'ssdp':
        headers = {}
        for line in payload[:4096].decode('utf-8', 'replace').splitlines()[1:33]:
            key, sep, value = line.partition(':')
            if sep and key.strip().lower() in ('server', 'st', 'nt', 'usn', 'location'):
                headers[key.strip().lower()] = text(value.strip(), 256)
        return [{**base, 'headers': headers}] if headers else [base]
    dns = DNS(payload)
    rows = records(dns, 'an') + records(dns, 'ns') + records(dns, 'ar')
    questions = [text(q.qname).rstrip('.') for q in list(dns.qd or [])[:8]]
    return [{**base, 'response': bool(dns.qr), 'questions': questions, 'records': rows[:32],
             'record_limit_reached': sum(int(getattr(dns, section + 'count', 0) or 0) for section in ('an','ns','ar')) > 32
             or int(dns.qdcount or 0) > 8}]


def observe(a):
    protocols = set(a.get('protocols', ['arp', 'mdns', 'llmnr', 'ssdp']))
    count, malformed, omitted = 0, 0, 0
    observations, seen = [], set()
    by_protocol = Counter()
    local_ips = {x['address'] for x in a['local_addresses']}
    local_mac = (a.get('local_mac') or '').lower()
    filters = {'arp': 'arp', 'mdns': 'udp port 5353', 'llmnr': 'udp port 5355', 'ssdp': 'udp port 1900'}
    max_rows, max_packets = a.get('max_observations', 128), a.get('max_packets', 256)

    def collect(packet):
        nonlocal count, malformed, omitted
        count += 1
        try:
            for row in packet_observations(packet, protocols):
                by_protocol[row['protocol']] += 1
                source = row.get('packet_source_address', row.get('claimed_sender_ip'))
                row['local_source'] = source in local_ips or row.get('packet_source_mac') == local_mac
                key = json.dumps(row, sort_keys=True)
                if key in seen:
                    continue
                if len(observations) >= max_rows:
                    omitted += 1
                    continue
                seen.add(key)
                observations.append(row)
        except (ValueError, IndexError, AttributeError, TypeError, OverflowError):
            malformed += 1

    sniff(iface=a['interface'], filter=' or '.join(filters[p] for p in sorted(protocols)),
          timeout=a.get('duration_seconds', 10), count=max_packets, store=False, promisc=False, prn=collect)
    limited = count >= max_packets or omitted > 0 or any(r.get('record_limit_reached') for r in observations)
    return {'status': 'observed', 'complete': not limited, 'coverage': 'partial' if limited else 'bounded_window',
            'packets_sent': 0, 'matching_packets_seen': count, 'protocol_packet_counts': dict(by_protocol),
            'malformed_packets': malformed, 'observation_limit_reached': omitted > 0,
            'omitted_observations': omitted, 'observations': observations,
            'nonlocal_observation_count': sum(not r['local_source'] for r in observations),
            'isolation_failure_confirmed': False,
            'evidence_notes': ['Packet sources and ARP/DNS claims are untrusted observations.',
                               'Traffic delivery alone does not establish an isolation-policy violation.',
                               'No observations in this bounded window do not establish absence.',
                               'NIC/AP multicast filtering may limit visibility; group memberships are not changed.',
                               'Queries reveal requested names, not devices offering those names.']}


def arp_packet(a, ip):
    return Ether(src=a['local_mac'], dst='ff:ff:ff:ff:ff:ff') / ARP(
        hwsrc=a['local_mac'], psrc=a['source_address'], pdst=ip)


def arp_response(ip, packet):
    if packet is None or ARP not in packet or Ether not in packet:
        return None
    arp = packet[ARP]
    if int(arp.op) != 2 or arp.psrc != ip or arp.hwsrc.lower() != packet[Ether].src.lower():
        return None
    return arp.hwsrc.lower()


def gateway_mac(a, timeout):
    response = srp1(arp_packet(a, a['gateway']), iface=a['interface'], timeout=timeout, retry=0, verbose=0)
    mac = arp_response(a['gateway'], response)
    if not mac:
        raise RuntimeError('Gateway did not answer ARP; no gateway-path inference is possible')
    return mac


def proxy(a):
    timeout = a.get('timeout_seconds', 2)
    gw_mac = gateway_mac(a, timeout)
    subnet = ipaddress.ip_network(a['cidr'], strict=True)
    if subnet.num_addresses > a.get('max_hosts', 256):
        raise ValueError('ARP range exceeds max_hosts')
    targets = [str(ip) for ip in subnet.hosts() if str(ip) not in (a['source_address'], a['gateway'])]
    replies = []
    if targets:
        answered, _ = srp([arp_packet(a, ip) for ip in targets], iface=a['interface'],
                          timeout=timeout, inter=0.1, retry=0, multi=False, verbose=0)
        seen = set()
        for sent, received in answered:
            ip = sent[ARP].pdst
            mac = arp_response(ip, received)
            if mac and (ip, mac) not in seen:
                seen.add((ip, mac))
                replies.append({'claimed_ip': ip, 'responder_mac': mac, 'matches_gateway_mac': mac == gw_mac,
                                'peer_liveness_confirmed': False})
    counts = Counter(r['responder_mac'] for r in replies)
    return {'status': 'observed', 'complete': True, 'gateway': a['gateway'], 'gateway_mac': gw_mac,
            'cidr': a['cidr'], 'addresses_probed': len(targets), 'responses': replies,
            'proxy_arp_candidate_ips': [r['claimed_ip'] for r in replies if r['matches_gateway_mac']],
            'shared_responder_macs': [{'mac': m, 'claimed_ip_count': n} for m, n in counts.items() if n > 1],
            'proxy_arp_confirmed': False,
            'evidence_notes': ['A gateway can answer for unused addresses; responses do not confirm peer liveness.',
                               'Shared MACs can also represent bridges, virtual hosts or other proxies.',
                               'Negative results can reflect filtering or loss.']}


def echo_result(response, peer, ident, seq):
    if response is None or IP not in response or ICMP not in response:
        return {'target_echo_reply': False, 'status': 'no_matching_response'}
    ip, icmp = response[IP], response[ICMP]
    result = {'target_echo_reply': False, 'response_source': ip.src, 'icmp_type': int(icmp.type),
              'icmp_code': int(icmp.code), 'response_ttl': int(ip.ttl),
              'response_source_mac': response[Ether].src if Ether in response else None}
    if int(icmp.type) == 0 and ip.src == peer and int(icmp.id) == ident and int(icmp.seq) == seq:
        result.update(target_echo_reply=True, status='target_echo_reply')
    elif int(icmp.type) in (3, 11):
        inner = icmp.payload
        quoted_icmp = inner.payload
        matches = (getattr(inner, 'dst', None) == peer and getattr(quoted_icmp, 'id', None) == ident
                   and getattr(quoted_icmp, 'seq', None) == seq)
        result['status'] = 'matched_icmp_error' if matches else 'unmatched_response'
    else:
        result['status'] = 'unmatched_response'
    return result


def hairpin(a):
    timeout, probes = a.get('timeout_seconds', 1), a.get('probes', 1)
    deadline = time.monotonic() + 105
    gw_mac = gateway_mac(a, timeout)
    rows = []
    complete = True
    for peer in a['peer_targets']:
        if deadline - time.monotonic() < timeout * (2 * probes + 2):
            complete = False
            break
        response = srp1(arp_packet(a, peer), iface=a['interface'], timeout=timeout, retry=0, verbose=0)
        direct_mac = arp_response(peer, response)
        row = {'peer': peer, 'arp_responder_mac': direct_mac, 'gateway_mac': gw_mac,
               'direct_path_is_proxy': direct_mac == gw_mac, 'direct': [], 'via_gateway': []}
        ident = secrets.randbelow(65536)
        seq = 0
        for label, mac, ttl in [('direct', direct_mac, 64), ('via_gateway', gw_mac, 64), ('ttl1_control', gw_mac, 1)]:
            results = []
            if mac:
                for _ in range(1 if ttl == 1 else probes):
                    seq += 1
                    frame = Ether(src=a['local_mac'], dst=mac) / IP(src=a['source_address'], dst=peer, ttl=ttl) / ICMP(id=ident, seq=seq)
                    reply = srp1(frame, iface=a['interface'], timeout=timeout, retry=0, verbose=0)
                    results.append(echo_result(reply, peer, ident, seq))
            row[label] = results
        direct_ok = any(x['target_echo_reply'] for x in row['direct'])
        gateway_ok = any(x['target_echo_reply'] for x in row['via_gateway'])
        forwarded = any(x.get('icmp_type') == 11 and x.get('icmp_code') == 0 and
                        x.get('response_source') == a['gateway'] and x['status'] == 'matched_icmp_error'
                        for x in row['ttl1_control'])
        row.update(direct_test_available=bool(direct_mac), direct_target_replied=direct_ok,
                   gateway_path_target_replied=gateway_ok, gateway_forwarding_evidence=forwarded,
                   possible_hairpin_routing=gateway_ok and forwarded,
                   isolation_bypass_candidate=gateway_ok and bool(direct_mac) and not direct_ok and direct_mac != gw_mac,
                   isolation_bypass_confirmed=False)
        rows.append(row)
    return {'status': 'observed', 'complete': complete, 'coverage': 'complete' if complete else 'deadline_limited',
            'peers_requested': len(a['peer_targets']), 'peers_tested': len(rows), 'results': rows,
            'evidence_notes': ['Gateway path uses explicit Ethernet destination MAC, not a route change.',
                               'ICMP filtering/loss or missing ARP can explain a failed direct path.',
                               'TTL=1 time-exceeded supports forwarding; echo success alone does not.',
                               'Controlled known peers and a known isolation policy are required to confirm bypass.',
                               'No target reply does not establish host absence or effective isolation.']}


def valid_dns_response(dns, ident, name, qtype):
    questions = list(dns.qd or [])
    return (int(dns.id) == ident and bool(dns.qr) and int(dns.opcode) == 0 and len(questions) == 1
            and text(questions[0].qname).rstrip('.').lower() == name.rstrip('.').lower()
            and int(questions[0].qtype) == qtype and int(questions[0].qclass) == 1)


def dns_sample(server, source, name, qtype, timeout, interface=None):
    ident = secrets.randbelow(65536)
    query = bytes(DNS(id=ident, rd=0, qd=DNSQR(qname=name, qtype=qtype)))
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if interface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, (interface + '\0').encode())
        sock.bind((source, 0))
        sock.connect((server, 53))
        sock.send(query)
        while True:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                return {'status': 'timeout', 'recursion_requested': False}
            sock.settimeout(remaining)
            try:
                payload = sock.recv(65535)
                dns = DNS(payload)
                if not valid_dns_response(dns, ident, name, qtype):
                    continue
            except socket.timeout:
                return {'status': 'timeout', 'recursion_requested': False}
            except (ValueError, IndexError, AttributeError):
                continue
            elapsed = (time.monotonic() - started) * 1000
            authoritative, truncated = bool(dns.aa), bool(dns.tc)
            answers = records(dns)
            rcode = int(dns.rcode)
            return {'status': 'response', 'response_ms': round(elapsed, 3), 'rcode': rcode,
                    'recursion_requested': False, 'recursion_available': bool(dns.ra),
                    'authoritative': authoritative, 'truncated': truncated, 'answers': answers,
                    'authority': records(dns, 'ns'),
                    'record_limit_reached': int(dns.ancount or 0) > 32 or int(dns.nscount or 0) > 32,
                    'cache_evidence': 'nonrecursive_non_authoritative_answer' if answers and not authoritative and not truncated and rcode == 0
                    else 'authoritative_local_data' if authoritative else 'inconclusive'}


def dns_cache(a):
    rows = []
    for name in a['names']:
        samples = []
        for _ in range(a.get('samples', 2)):
            try:
                sample = dns_sample(a['server'], a['source_address'], name, QTYPE[a.get('record_type', 'A')], a.get('timeout_seconds', 1), a['interface'])
            except OSError as error:
                sample = {'status': 'unavailable', 'error': text(error, 160), 'recursion_requested': False}
            if a.get('baseline_ttl') is not None:
                for rr in sample.get('answers', []):
                    if rr['type'] == a.get('record_type', 'A') and rr['name'].lower() == name.rstrip('.').lower():
                        rr['below_supplied_baseline'] = rr['ttl'] < a['baseline_ttl']
            samples.append(sample)
        rows.append({'name': name, 'samples': samples, 'querying_client_identified': False, 'device_presence_confirmed': False})
    complete = all(s['status'] == 'response' and not s.get('truncated') and not s.get('record_limit_reached') for r in rows for s in r['samples'])
    return {'status': 'observed' if any(s['status'] == 'response' for r in rows for s in r['samples']) else 'unavailable',
            'complete': complete, 'server': a['server'], 'results': rows, 'recursion_requested': False,
            'evidence_notes': ['Non-authoritative nonrecursive answers suggest accessible cached data, not a specific client.',
                               'Authoritative answers may be local DHCP/static DNS records, not cache hits.',
                               'TTL baselines can vary with record changes, prefetch, resolver policy or stale serving.',
                               'Response timing alone is inconclusive; repeated samples are affected by these probes.',
                               'Refusal, referral, empty answer or timeout cannot establish cache absence.',
                               'No recursive warm-up query or upstream baseline lookup is performed.']}


def bounded_json(result, byte_limit=1024 * 1024):
    """Trim evidence arrays explicitly before crossing the transport byte budget."""
    omitted = 0
    while True:
        encoded = json.dumps(result, separators=(',', ':'), ensure_ascii=False)
        if len(encoded.encode('utf-8')) <= byte_limit:
            return encoded
        arrays = []
        def collect(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in ('observations', 'records', 'answers', 'authority') and isinstance(child, list) and child:
                        arrays.append(child)
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)
        collect(result)
        if not arrays:
            raise ValueError('Result metadata exceeds output byte limit')
        largest = max(arrays, key=lambda x: len(json.dumps(x, ensure_ascii=False).encode('utf-8')))
        retained = len(largest) // 2
        omitted += len(largest) - retained
        del largest[retained:]
        result.update(complete=False, coverage='partial', output_byte_limit_reached=True,
                      evidence_entries_omitted_by_byte_limit=omitted)


def main():
    name, args = sys.argv[1], json.loads(sys.argv[2])
    api = {'observe_broadcast_multicast': observe, 'probe_gateway_proxy_arp': proxy,
           'probe_gateway_hairpin': hairpin, 'observe_dns_cache': dns_cache}
    result=api[name](args)
    result['observed_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    print(bounded_json(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(text(error, 600), file=sys.stderr)
        sys.exit(1)

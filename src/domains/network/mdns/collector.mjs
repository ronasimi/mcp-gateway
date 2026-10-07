import dgram from 'node:dgram';
import { isIP } from 'node:net';
import { buildMdnsQuery, parseMdnsPacket } from './wire.mjs';

export async function collectMdns({ address, durationSeconds = 8, maxRecords = 256, maxQueries = 64, socketFactory = dgram.createSocket } = {}) {
  if (isIP(address) !== 4) throw new Error('Selected physical interface requires an IPv4 address for this mDNS transport.');
  if (!Number.isInteger(maxQueries) || maxQueries < 8 || maxQueries > 512) throw new Error('maxQueries must be an integer from 8 to 512');

  return new Promise(resolve => {
    const socket = socketFactory({ type: 'udp4', reuseAddr: true });
    const records = new Map();
    const sent = new Set();
    const suppressed = new Set();
    let timer;
    let finished = false;
    let packets = 0;
    let malformed = 0;
    let queries = 0;
    let recordLimited = false;
    let packetLimited = false;

    const finish = error => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try { socket.close(); } catch {}
      const queryLimited = suppressed.size > 0;
      const limited = recordLimited || packetLimited || queryLimited;
      const raw = [...records.values()];
      resolve({
        records: raw,
        raw_records: raw,
        transport: 'direct-udp4',
        available: !error,
        complete: !error && !limited,
        coverage: error ? 'unavailable' : limited ? 'partial' : 'complete',
        coverage_limitations: [
          ...(recordLimited ? ['record_limit_reached'] : []),
          ...(packetLimited ? ['packet_limit_reached'] : []),
          ...(queryLimited ? ['query_limit_reached'] : []),
        ],
        status: error ? 'unavailable' : records.size ? 'observed' : 'no_records_observed',
        diagnostics: error?.message || null,
        packets_received: packets,
        packet_limit: 2048,
        malformed_packets: malformed,
        queries_sent: queries,
        query_limit: maxQueries,
        query_limit_reached: queryLimited,
        queries_suppressed_by_limit: suppressed.size,
        record_limit: maxRecords,
        record_limit_reached: recordLimited,
        limited,
        ipv6_transport: false,
        note: 'AAAA records may arrive over IPv4 mDNS. IPv6-only multicast and non-advertising devices are not covered.',
      });
    };

    const send = (name, type) => {
      const lower = String(name || '').toLowerCase();
      const key = lower + ':' + type;
      if (finished || sent.has(key) || !lower.endsWith('.local')) return;
      if (queries >= maxQueries) {
        suppressed.add(key);
        return;
      }
      sent.add(key);
      queries++;
      try {
        socket.send(buildMdnsQuery(name, type), 5353, '224.0.0.251', error => { if (error) finish(error); });
      } catch (error) {
        finish(error);
      }
    };

    socket.on('error', finish);
    socket.on('message', (buffer, peer) => {
      if (finished || peer.port !== 5353) return;
      if (++packets > 2048) {
        packetLimited = true;
        finish();
        return;
      }
      let parsed;
      try { parsed = parseMdnsPacket(buffer); } catch { malformed++; return; }
      for (const record of parsed) {
        const key = [record.name.toLowerCase(), record.type, record.address || record.target || JSON.stringify(record.txt)].join('|');
        if (record.ttl === 0) {
          records.delete(key);
          continue;
        }
        if (!records.has(key) && records.size >= maxRecords) {
          recordLimited = true;
          continue;
        }
        records.set(key, { ...record, source_address: peer.address });
        if (record.type === 'PTR') {
          send(record.target, record.name.toLowerCase() === '_services._dns-sd._udp.local' ? 12 : 33);
          if (record.name.toLowerCase() !== '_services._dns-sd._udp.local') send(record.target, 16);
        }
        if (record.type === 'SRV') {
          send(record.target, 1);
          send(record.target, 28);
        }
      }
    });

    timer = setTimeout(() => finish(), durationSeconds * 1000);
    try {
      socket.bind(5353, '0.0.0.0', () => {
        if (finished) return;
        try {
          socket.addMembership('224.0.0.251', address);
          socket.setMulticastInterface(address);
          socket.setMulticastTTL(255);
          for (const type of ['_services._dns-sd._udp', '_http._tcp', '_ssh._tcp', '_smb._tcp', '_ipp._tcp', '_airplay._tcp', '_googlecast._tcp', '_workstation._tcp']) send(type + '.local', 12);
        } catch (error) {
          finish(error);
        }
      });
    } catch (error) {
      finish(error);
    }
  });
}

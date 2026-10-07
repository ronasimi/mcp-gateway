import { isIP } from 'node:net';
import { addressRange, addressScope, contains, localAddress, privateAddress } from './ip.mjs';

export function inferMdnsSubnets(records, { interfaces = [], routes = [], interface: iface, ipv4Prefix = 24, ipv6Prefix = 64 } = {}) {
  const local = interfaces.flatMap(item => (item.addr_info || [])
    .filter(address => ['inet', 'inet6'].includes(address.family) && isIP(address.local))
    .map(address => ({ ...addressRange(address.local, address.prefixlen), interface: item.ifname })));
  const candidates = new Map();
  const addresses = [];

  for (const record of records.filter(item => ['A', 'AAAA'].includes(item.type) && isIP(item.address))) {
    const address = record.address;
    const family = isIP(address);
    const same = local.filter(candidate => candidate.interface === iface && contains(address, candidate.cidr));
    const observed = { ...record, family, outside_selected_subnets: !localAddress(address) && same.length === 0 };

    if (localAddress(address)) {
      addresses.push({ ...observed, range_status: 'link_local_or_loopback', note: 'Not evidence of a remote subnet.' });
      continue;
    }

    const direct = local.filter(candidate => contains(address, candidate.cidr)).sort((a, b) => b.prefix_length - a.prefix_length)[0];
    const route = routes
      .filter(item => item.dst && item.dst !== 'default' && contains(address, item.dst))
      .sort((a, b) => Number(b.dst.split('/')[1]) - Number(a.dst.split('/')[1]))[0];

    let range;
    let basis;
    let maskKnown = false;
    if (direct) {
      range = addressRange(address, direct.prefix_length);
      basis = 'local_interface';
      maskKnown = true;
    } else if (route) {
      range = addressRange(address, Number(route.dst.split('/')[1]));
      basis = 'known_route';
    } else if (privateAddress(address)) {
      range = addressRange(address, family === 4 ? ipv4Prefix : ipv6Prefix);
      basis = 'heuristic';
    } else {
      addresses.push({ ...observed, range_status: 'unknown', note: 'Public address retained as evidence; no scan range inferred.' });
      continue;
    }

    addresses.push({ ...observed, candidate_cidr: range.cidr, range_status: basis });
    const group = candidates.get(range.cidr) || {
      ...range,
      basis,
      address_scope: addressScope(address),
      actual_subnet_mask_known: maskKnown,
      scan_automatically: false,
      observed_addresses: [],
      hostnames: [],
      note: basis === 'heuristic'
        ? 'Grouping hypothesis only. mDNS does not advertise a subnet mask.'
        : basis === 'known_route'
          ? 'Routing coverage is known; this does not establish the remote subnet mask.'
          : 'Prefix confirmed by a local interface address.',
    };
    group.observed_addresses = [...new Set([...group.observed_addresses, address])];
    group.hostnames = [...new Set([...group.hostnames, record.name])];
    candidates.set(range.cidr, group);
  }

  const outside = addresses.filter(address => address.outside_selected_subnets);
  return {
    addresses,
    candidate_networks: [...candidates.values()],
    possible_reflection: outside.length > 0,
    evidence: outside.map(address => ({
      address: address.address,
      hostname: address.name,
      reason: 'Advertised address is outside known selected-interface subnets; multihoming or stale advertisements are alternative explanations.',
    })),
    reflector_confirmed: false,
  };
}

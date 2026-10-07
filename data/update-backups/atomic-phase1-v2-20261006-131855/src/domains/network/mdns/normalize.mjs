import { isIP } from 'node:net';
import { addressScope } from './ip.mjs';

function add(map, key, value) {
  if (!key || value === undefined || value === null) return;
  const normalized = String(key).toLowerCase();
  const values = map.get(normalized) || [];
  if (!values.some(item => JSON.stringify(item) === JSON.stringify(value))) values.push(value);
  map.set(normalized, values);
}

function serviceTypeFromInstance(instance) {
  const match = String(instance || '').match(/(_[^.]+\._(?:tcp|udp)\.local)$/i);
  return match?.[1] || null;
}

function txtFields(txt = []) {
  const out = {};
  for (const item of txt || []) {
    const match = String(item).match(/^([^=]{1,64})=(.*)$/);
    if (match && !Object.hasOwn(out, match[1])) out[match[1]] = match[2];
  }
  return out;
}

export function normalizeMdnsRecords(records = []) {
  const addresses = new Map();
  const sources = new Map();
  const ptrTypes = new Map();
  const srvs = new Map();
  const txts = new Map();
  const serviceNames = new Set();

  for (const record of records) {
    const name = String(record.name || '').toLowerCase();
    if (record.source_address) add(sources, name, record.source_address);
    if (['A', 'AAAA'].includes(record.type) && isIP(record.address)) {
      add(addresses, name, { address: record.address, family: isIP(record.address), type: record.type, ttl: record.ttl });
    }
    if (record.type === 'PTR' && record.target) {
      const owner = String(record.name || '').toLowerCase();
      const target = String(record.target).toLowerCase();
      if (owner === '_services._dns-sd._udp.local') continue;
      if (/\._(?:tcp|udp)\.local$/i.test(owner)) {
        add(ptrTypes, target, record.name);
        serviceNames.add(target);
        if (record.source_address) add(sources, target, record.source_address);
      }
    }
    if (record.type === 'SRV' && record.target) {
      srvs.set(name, { target_hostname: record.target, port: record.port, ttl: record.ttl });
      serviceNames.add(name);
    }
    if (record.type === 'TXT') {
      txts.set(name, { txt: [...(record.txt || [])], ttl: record.ttl });
      serviceNames.add(name);
    }
  }

  const serviceInstances = [...serviceNames].sort().map(key => {
    const srv = srvs.get(key);
    const targetKey = String(srv?.target_hostname || '').toLowerCase();
    const advertised = (addresses.get(targetKey) || []).map(value => ({ ...value }));
    const packetSources = [...new Set([...(sources.get(key) || []), ...(targetKey ? sources.get(targetKey) || [] : [])])];
    const types = (ptrTypes.get(key) || []).map(String);
    const instance = records.find(record => String(record.name || '').toLowerCase() === key && ['SRV', 'TXT'].includes(record.type))?.name
      || records.find(record => record.type === 'PTR' && String(record.target || '').toLowerCase() === key)?.target
      || key;
    return {
      instance,
      service_types: types.length ? types : [serviceTypeFromInstance(instance)].filter(Boolean),
      target_hostname: srv?.target_hostname || null,
      port: srv?.port ?? null,
      txt: txts.get(key)?.txt || [],
      advertised_addresses: advertised,
      packet_source_addresses: packetSources,
    };
  });

  const serviceByHost = new Map();
  for (const service of serviceInstances) if (service.target_hostname) add(serviceByHost, service.target_hostname, service.instance);

  const advertisedHosts = [...addresses.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, advertised]) => ({
    hostname: records.find(record => ['A', 'AAAA'].includes(record.type) && String(record.name || '').toLowerCase() === key)?.name || key,
    advertised_addresses: advertised.map(value => ({ ...value })),
    packet_source_addresses: [...(sources.get(key) || [])],
    service_instances: [...(serviceByHost.get(key) || [])],
  }));

  const servicesByTarget = new Map();
  for (const service of serviceInstances) {
    if (!service.target_hostname) continue;
    const key = String(service.target_hostname).toLowerCase();
    const fields = txtFields(service.txt);
    const list = servicesByTarget.get(key) || [];
    list.push({
      instance: service.instance,
      service_types: [...service.service_types],
      port: service.port,
      model: fields.md || null,
      friendly_name: fields.fn || null,
    });
    servicesByTarget.set(key, list);
  }

  const reportHosts = advertisedHosts.map(host => {
    const scoped = host.advertised_addresses.map(address => ({ ...address, scope: addressScope(address.address) }));
    return {
      hostname: host.hostname,
      ipv4_addresses: scoped.filter(address => address.family === 4).map(address => address.address),
      ipv6_addresses: scoped.filter(address => address.family === 6).map(address => address.address),
      advertised_addresses: scoped,
      packet_source_addresses: [...host.packet_source_addresses],
      services: [...(servicesByTarget.get(String(host.hostname).toLowerCase()) || [])],
    };
  });

  return { advertised_hosts: advertisedHosts, services: serviceInstances, report_hosts: reportHosts };
}

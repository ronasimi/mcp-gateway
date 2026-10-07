import { isIP } from 'node:net';

export function ipNumber(ip) {
  if (isIP(ip) === 4) return ip.split('.').reduce((n, x) => (n << 8n) | BigInt(x), 0n);
  if (isIP(ip) !== 6) throw new Error('invalid IP address');
  let text = ip.split('%')[0];
  if (text.includes('.')) text = text.replace(/(?:\d+\.){3}\d+$/, value => {
    const n = ipNumber(value);
    return `${(n >> 16n).toString(16)}:${(n & 65535n).toString(16)}`;
  });
  const parts = text.split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const words = parts.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return words.reduce((n, x) => (n << 16n) | BigInt('0x' + x), 0n);
}

export function ipText(value, family) {
  if (family === 4) return [24n, 16n, 8n, 0n].map(bit => String((value >> bit) & 255n)).join('.');
  return Array.from({ length: 8 }, (_, index) => ((value >> BigInt((7 - index) * 16)) & 65535n).toString(16)).join(':');
}

export function addressRange(address, prefix) {
  const family = isIP(address);
  const bits = family === 4 ? 32 : 128;
  if (!family || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) throw new Error('invalid IP prefix');
  const size = 1n << BigInt(bits - prefix);
  const start = (ipNumber(address) / size) * size;
  const end = start + size - 1n;
  return {
    cidr: `${ipText(start, family)}/${prefix}`,
    family,
    prefix_length: prefix,
    range_start: ipText(start, family),
    range_end: ipText(end, family),
    address_count: String(size),
  };
}

export function contains(address, cidr) {
  try {
    const [ip, prefix] = cidr.split('/');
    if (isIP(ip) !== isIP(address)) return false;
    const range = addressRange(ip, Number(prefix));
    const n = ipNumber(address);
    return n >= ipNumber(range.range_start) && n <= ipNumber(range.range_end);
  } catch {
    return false;
  }
}

export function localAddress(ip) {
  return isIP(ip) === 4
    ? contains(ip, '169.254.0.0/16') || contains(ip, '127.0.0.0/8') || contains(ip, '224.0.0.0/4') || ip === '0.0.0.0'
    : contains(ip, 'fe80::/10') || contains(ip, 'ff00::/8') || contains(ip, '::1/128') || contains(ip, '::/128');
}

export function privateAddress(ip) {
  return isIP(ip) === 4
    ? ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some(cidr => contains(ip, cidr))
    : contains(ip, 'fc00::/7');
}

export function addressScope(address) {
  if (isIP(address) === 4) {
    if (contains(address, '169.254.0.0/16')) return 'link_local';
    if (privateAddress(address)) return 'private';
    return 'global_or_special';
  }
  if (isIP(address) === 6) {
    if (contains(address, 'fe80::/10')) return 'link_local';
    if (contains(address, 'fc00::/7')) return 'unique_local';
    return 'global_or_special';
  }
  return 'unknown';
}

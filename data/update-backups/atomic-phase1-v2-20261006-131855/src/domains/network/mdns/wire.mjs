function readName(buffer, start) {
  let offset = start;
  let next = null;
  const labels = [];
  const visited = new Set();
  for (let steps = 0; steps < 128; steps++) {
    if (offset >= buffer.length || visited.has(offset)) throw new Error('invalid DNS name');
    visited.add(offset);
    const len = buffer[offset++];
    if (len === 0) return { name: labels.join('.'), next: next ?? offset };
    if ((len & 192) === 192) {
      if (offset >= buffer.length) throw new Error('short DNS pointer');
      const target = ((len & 63) << 8) | buffer[offset++];
      next ??= offset;
      offset = target;
      continue;
    }
    if (len > 63 || offset + len > buffer.length) throw new Error('invalid DNS label');
    labels.push(buffer.subarray(offset, offset + len).toString('utf8'));
    offset += len;
  }
  throw new Error('DNS name too deep');
}

export function parseMdnsPacket(buffer) {
  if (buffer.length < 12 || !(buffer.readUInt16BE(2) & 0x8000)) return [];
  let offset = 12;
  const questions = buffer.readUInt16BE(4);
  const count = buffer.readUInt16BE(6) + buffer.readUInt16BE(8) + buffer.readUInt16BE(10);
  const records = [];
  if (questions > 128 || count > 512) throw new Error('DNS record limit');

  for (let index = 0; index < questions; index++) {
    offset = readName(buffer, offset).next + 4;
    if (offset > buffer.length) throw new Error('short question');
  }

  for (let index = 0; index < count; index++) {
    const name = readName(buffer, offset);
    offset = name.next;
    if (offset + 10 > buffer.length) throw new Error('short record');
    const type = buffer.readUInt16BE(offset);
    const cls = buffer.readUInt16BE(offset + 2) & 0x7fff;
    const ttl = buffer.readUInt32BE(offset + 4);
    const len = buffer.readUInt16BE(offset + 8);
    offset += 10;
    const end = offset + len;
    if (end > buffer.length) throw new Error('short record data');
    const base = { name: name.name, ttl };
    let record;
    if (cls === 1 && type === 1 && len === 4) record = { ...base, type: 'A', address: [...buffer.subarray(offset, end)].join('.') };
    else if (cls === 1 && type === 28 && len === 16) record = { ...base, type: 'AAAA', address: Array.from({ length: 8 }, (_, word) => buffer.readUInt16BE(offset + word * 2).toString(16)).join(':') };
    else if (cls === 1 && type === 12) {
      const value = readName(buffer, offset);
      if (value.next > end) throw new Error('invalid PTR data');
      record = { ...base, type: 'PTR', target: value.name };
    } else if (cls === 1 && type === 33 && len >= 7) {
      const value = readName(buffer, offset + 6);
      if (value.next > end) throw new Error('invalid SRV data');
      record = { ...base, type: 'SRV', port: buffer.readUInt16BE(offset + 4), target: value.name };
    } else if (cls === 1 && type === 16) {
      let cursor = offset;
      const txt = [];
      while (cursor < end) {
        const size = buffer[cursor++];
        if (cursor + size > end) throw new Error('invalid TXT data');
        txt.push(buffer.subarray(cursor, cursor + size).toString('utf8'));
        cursor += size;
      }
      record = { ...base, type: 'TXT', txt };
    }
    if (record) records.push(record);
    offset = end;
  }
  return records;
}

export function buildMdnsQuery(name, type) {
  const labels = name.split('.');
  if (labels.some(label => !label || Buffer.byteLength(label) > 63)) throw new Error('invalid query name');
  const head = Buffer.alloc(12);
  head.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(type, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([
    head,
    ...labels.map(label => Buffer.concat([Buffer.from([Buffer.byteLength(label)]), Buffer.from(label)])),
    Buffer.from([0]),
    tail,
  ]);
}

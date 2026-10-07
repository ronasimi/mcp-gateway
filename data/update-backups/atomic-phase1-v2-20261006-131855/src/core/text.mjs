export function clipText(value, max = 12000) {
  const text = String(value ?? '');
  return Buffer.byteLength(text) <= max ? text : text.slice(0, max) + `\n...[truncated at ${max} bytes]`;
}

export function unique(values = []) {
  return [...new Set(values.filter(Boolean))];
}

export function safeLabel(value) {
  return String(value ?? '').replace(/[\\{}|<>"\n\r]/g, ' ').replace(/\s+/g, ' ').trim();
}

export function dotEscape(value) {
  return String(value ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, '\\n');
}

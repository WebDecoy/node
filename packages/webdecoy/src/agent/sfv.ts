/**
 * RFC 8941 Structured Field Values — the subset Web Bot Auth headers use.
 *
 * `Signature-Input` is a dictionary of inner lists (the covered component
 * identifiers) with parameters (keyid, created, expires, tag, alg…).
 * `Signature` is a dictionary of byte-sequence values (the raw signatures).
 * `Signature-Agent` is a dictionary whose members are strings.
 *
 * The parser preserves the **verbatim** text of each dictionary member's value
 * (`DictEntry.raw`), which RFC 9421 requires to reconstruct the
 * `@signature-params` line of the signature base byte-for-byte.
 *
 * Zero dependencies, Edge-runtime safe: only `atob` is used (for byte
 * sequences).
 */

export type BareItem = string | number | boolean;

export interface Item {
  value: BareItem;
  params: Map<string, BareItem>;
  /** Set only for byte-sequence items (`:base64:`). */
  bytes?: Uint8Array;
}

export interface DictEntry {
  key: string;
  /** Verbatim value text after `key=` (before this member's own params for lists). */
  raw: string;
  /** True when the value is an inner list `( … )`. */
  isList: boolean;
  items: Item[];
  /** Parameters attached to the member (the inner list, or the single item). */
  params: Map<string, BareItem>;
}

class Cursor {
  constructor(
    public s: string,
    public i = 0,
  ) {}
  eof(): boolean {
    return this.i >= this.s.length;
  }
  peek(): string {
    return this.s[this.i];
  }
  skipSP(): void {
    while (!this.eof() && (this.peek() === ' ' || this.peek() === '\t')) this.i++;
  }
}

/** Parse an RFC 8941 dictionary header value. Throws on malformed input. */
export function parseDictionary(input: string): DictEntry[] {
  const p = new Cursor(input);
  const out: DictEntry[] = [];
  p.skipSP();
  while (!p.eof()) {
    const key = parseKey(p);
    const entry: DictEntry = { key, raw: '', isList: false, items: [], params: new Map() };
    if (!p.eof() && p.peek() === '=') {
      p.i++;
      const start = p.i;
      if (!p.eof() && p.peek() === '(') {
        entry.isList = true;
        parseInnerList(p, entry);
      } else {
        entry.items.push(parseItem(p));
        entry.params = entry.items[0].params;
      }
      entry.raw = input.slice(start, p.i);
    } else {
      // A valueless member is boolean-true, with optional parameters.
      entry.params = parseParams(p);
      entry.items.push({ value: true, params: new Map() });
      entry.raw = '?1';
    }
    out.push(entry);
    p.skipSP();
    if (p.eof()) break;
    if (p.peek() !== ',') throw new Error(`sfv: expected ',' at ${p.i}`);
    p.i++;
    p.skipSP();
    if (p.eof()) throw new Error('sfv: trailing comma');
  }
  return out;
}

function parseInnerList(p: Cursor, entry: DictEntry): void {
  p.i++; // consume '('
  for (;;) {
    p.skipSP();
    if (p.eof()) throw new Error('sfv: unterminated inner list');
    if (p.peek() === ')') {
      p.i++;
      break;
    }
    entry.items.push(parseItem(p));
    if (p.eof()) throw new Error('sfv: unterminated inner list');
    const c = p.peek();
    if (c !== ' ' && c !== ')') throw new Error(`sfv: bad inner list at ${p.i}`);
  }
  entry.params = parseParams(p);
}

function parseItem(p: Cursor): Item {
  const { value, bytes } = parseBareItem(p);
  const params = parseParams(p);
  return bytes ? { value, params, bytes } : { value, params };
}

function parseParams(p: Cursor): Map<string, BareItem> {
  const params = new Map<string, BareItem>();
  while (!p.eof() && p.peek() === ';') {
    p.i++;
    p.skipSP();
    const key = parseKey(p);
    let val: BareItem = true;
    if (!p.eof() && p.peek() === '=') {
      p.i++;
      val = parseBareItem(p).value;
    }
    params.set(key, val);
  }
  return params;
}

function parseKey(p: Cursor): string {
  const c = p.peek();
  if (!c || !/[a-z*]/.test(c)) throw new Error(`sfv: invalid key at ${p.i}`);
  const start = p.i;
  while (!p.eof() && /[a-z0-9_\-.*]/.test(p.peek())) p.i++;
  return p.s.slice(start, p.i);
}

function parseBareItem(p: Cursor): { value: BareItem; bytes?: Uint8Array } {
  const c = p.peek();
  if (c === '"') return { value: parseString(p) };
  if (c === ':') return { value: '', bytes: parseByteSequence(p) };
  if (c === '?') {
    p.i++;
    const b = p.s[p.i++];
    if (b === '1') return { value: true };
    if (b === '0') return { value: false };
    throw new Error('sfv: bad boolean');
  }
  if (c === '-' || /[0-9]/.test(c)) return { value: parseNumber(p) };
  if (/[a-zA-Z*]/.test(c)) return { value: parseToken(p) };
  throw new Error(`sfv: invalid bare item at ${p.i}`);
}

function parseString(p: Cursor): string {
  p.i++; // opening quote
  let out = '';
  while (!p.eof()) {
    const c = p.s[p.i++];
    if (c === '"') return out;
    if (c === '\\') {
      const e = p.s[p.i++];
      if (e !== '"' && e !== '\\') throw new Error('sfv: bad escape');
      out += e;
    } else {
      const code = c.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) throw new Error('sfv: bad char in string');
      out += c;
    }
  }
  throw new Error('sfv: unterminated string');
}

function parseByteSequence(p: Cursor): Uint8Array {
  p.i++; // ':'
  const start = p.i;
  while (!p.eof() && p.peek() !== ':') p.i++;
  if (p.eof()) throw new Error('sfv: unterminated byte sequence');
  const b64 = p.s.slice(start, p.i);
  p.i++; // closing ':'
  return base64StdToBytes(b64);
}

function parseNumber(p: Cursor): number {
  const start = p.i;
  if (p.peek() === '-') p.i++;
  while (!p.eof() && /[0-9]/.test(p.peek())) p.i++;
  if (!p.eof() && p.peek() === '.') {
    p.i++;
    while (!p.eof() && /[0-9]/.test(p.peek())) p.i++;
  }
  return Number(p.s.slice(start, p.i));
}

function parseToken(p: Cursor): string {
  const start = p.i;
  p.i++;
  while (!p.eof() && /[a-zA-Z0-9!#$%&'*+\-.^_`|~:/]/.test(p.peek())) p.i++;
  return p.s.slice(start, p.i);
}

/** Decode a standard (non-url) base64 string to bytes. */
export function base64StdToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

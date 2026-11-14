import { isIPv4, isIPv6 } from 'node:net';

/*
 * Address classification for the egress proxy (spec §3.2). Only `global` addresses may be used
 * for a non-loopback origin, and only `loopback` addresses for a loopback origin. Anything the
 * parser does not understand is `invalid` and therefore refused.
 */

export type AddressClass =
  | 'global'
  | 'loopback'
  | 'private'
  | 'link_local'
  | 'unique_local'
  | 'cgnat'
  | 'multicast'
  | 'unspecified'
  | 'reserved'
  | 'invalid';

type V4Range = readonly [base: number, prefix: number, cls: AddressClass];

function v4ToInt(address: string): number | null {
  if (!isIPv4(address)) return null;
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part > 255)) {
    return null;
  }
  const [a = 0, b = 0, c = 0, d = 0] = parts;
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}

function v4(cidr: string, cls: AddressClass): V4Range {
  const [base = '', prefix = '32'] = cidr.split('/');
  const value = v4ToInt(base);
  if (value === null) throw new Error(`bad range ${cidr}`);
  return [value, Number(prefix), cls];
}

// IANA IPv4 special-purpose registry, plus multicast and the class E block. Order matters
// only for readability: the ranges do not overlap except 0.0.0.0/32 inside 0.0.0.0/8.
const V4_RANGES: readonly V4Range[] = [
  v4('0.0.0.0/32', 'unspecified'),
  v4('0.0.0.0/8', 'reserved'),
  v4('10.0.0.0/8', 'private'),
  v4('100.64.0.0/10', 'cgnat'),
  v4('127.0.0.0/8', 'loopback'),
  v4('169.254.0.0/16', 'link_local'),
  v4('172.16.0.0/12', 'private'),
  v4('192.0.0.0/24', 'reserved'),
  v4('192.0.2.0/24', 'reserved'),
  v4('192.31.196.0/24', 'reserved'),
  v4('192.52.193.0/24', 'reserved'),
  v4('192.88.99.0/24', 'reserved'),
  v4('192.168.0.0/16', 'private'),
  v4('192.175.48.0/24', 'reserved'),
  v4('198.18.0.0/15', 'reserved'),
  v4('198.51.100.0/24', 'reserved'),
  v4('203.0.113.0/24', 'reserved'),
  v4('224.0.0.0/4', 'multicast'),
  v4('240.0.0.0/4', 'reserved'),
];

function inV4Range(value: number, [base, prefix]: V4Range): boolean {
  if (prefix === 0) return true;
  const mask = prefix === 32 ? 0xffffffff : (~((1 << (32 - prefix)) - 1) >>> 0) >>> 0;
  return (value & mask) >>> 0 === (base & mask) >>> 0;
}

function classifyV4Int(value: number): AddressClass {
  for (const range of V4_RANGES) {
    if (inV4Range(value, range)) return range[2];
  }
  return 'global';
}

/** Parses an IPv6 address (no zone id) into eight 16-bit groups, or null. */
export function parseIPv6(address: string): number[] | null {
  if (!isIPv6(address)) return null;
  let text = address.toLowerCase();
  // An embedded dotted quad (::ffff:1.2.3.4) becomes two hex groups.
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const value = v4ToInt(tail);
    if (value === null) return null;
    text = `${text.slice(0, lastColon + 1)}${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] === '' || halves[0] === undefined ? [] : halves[0].split(':');
  const rest = halves.length === 2 ? (halves[1] === '' ? [] : (halves[1] ?? '').split(':')) : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...rest];
  const numbers = groups.map((group) =>
    /^[0-9a-f]{1,4}$/.test(group) ? parseInt(group, 16) : NaN,
  );
  if (numbers.length !== 8 || numbers.some((n) => Number.isNaN(n))) return null;
  return numbers;
}

function embeddedV4(groups: readonly number[], highIndex: number): number {
  const high = groups[highIndex] ?? 0;
  const low = groups[highIndex + 1] ?? 0;
  return ((high << 16) >>> 0) + low;
}

function classifyV6(groups: readonly number[]): AddressClass {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = groups;
  const upperZero = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;

  if (upperZero && g5 === 0 && g6 === 0 && g7 === 0) return 'unspecified';
  if (upperZero && g5 === 0 && g6 === 0 && g7 === 1) return 'loopback';
  // IPv4-mapped ::ffff:a.b.c.d: judged by the IPv4 address it denotes.
  if (upperZero && g5 === 0xffff) return classifyV4Int(embeddedV4(groups, 6));
  // IPv4-translated ::ffff:0:a.b.c.d (RFC 2765) and IPv4-compatible ::a.b.c.d (deprecated).
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0xffff && g5 === 0) {
    return classifyV4Int(embeddedV4(groups, 6));
  }
  if (upperZero && g5 === 0) return 'reserved';
  // NAT64 well-known prefix 64:ff9b::/96: judged by the embedded IPv4 address.
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return classifyV4Int(embeddedV4(groups, 6));
  }
  // 6to4 2002::/16 embeds an IPv4 address in groups 1-2.
  if (g0 === 0x2002) {
    const inner = classifyV4Int(embeddedV4(groups, 1));
    return inner === 'global' ? 'global' : inner;
  }
  if ((g0 & 0xff00) === 0xff00) return 'multicast';
  if ((g0 & 0xffc0) === 0xfe80) return 'link_local';
  if ((g0 & 0xffc0) === 0xfec0) return 'reserved'; // deprecated site-local
  if ((g0 & 0xfe00) === 0xfc00) return 'unique_local';
  // Only 2000::/3 is global unicast; within it, exclude special-purpose blocks.
  if ((g0 & 0xe000) !== 0x2000) return 'reserved';
  if (g0 === 0x2001 && g1 < 0x0200) return 'reserved'; // 2001::/23 incl. Teredo, ORCHID, AMT
  if (g0 === 0x2001 && g1 === 0x0db8) return 'reserved'; // documentation
  if ((g0 & 0xfff0) === 0x3ff0) return 'reserved'; // 3fff::/20 documentation
  return 'global';
}

/** Classifies a literal IPv4 or IPv6 address. Bracketed and zoned forms are not accepted. */
export function classifyAddress(address: string): AddressClass {
  const v4Value = v4ToInt(address);
  if (v4Value !== null) return classifyV4Int(v4Value);
  if (address.includes('%')) {
    // A zone id only makes sense for link-local and multicast scopes.
    const groups = parseIPv6(address.slice(0, address.indexOf('%')));
    if (groups === null) return 'invalid';
    const cls = classifyV6(groups);
    return cls === 'global' ? 'reserved' : cls;
  }
  const groups = parseIPv6(address);
  return groups === null ? 'invalid' : classifyV6(groups);
}

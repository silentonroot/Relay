import { describe, expect, it } from 'vitest';
import { classifyAddress, parseIPv6 } from '../src/egress/ip-ranges.js';

describe('classifyAddress', () => {
  it.each([
    ['8.8.8.8', 'global'],
    ['93.184.216.34', 'global'],
    ['127.0.0.1', 'loopback'],
    ['127.255.255.254', 'loopback'],
    ['10.1.2.3', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['172.32.0.1', 'global'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'link_local'],
    ['100.64.0.1', 'cgnat'],
    ['100.127.255.255', 'cgnat'],
    ['100.128.0.1', 'global'],
    ['0.0.0.0', 'unspecified'],
    ['0.1.2.3', 'reserved'],
    ['224.0.0.1', 'multicast'],
    ['239.255.255.250', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['255.255.255.255', 'reserved'],
    ['192.0.2.1', 'reserved'],
    ['198.18.0.1', 'reserved'],
  ])('IPv4 %s is %s', (address, expected) => {
    expect(classifyAddress(address)).toBe(expected);
  });

  it.each([
    ['2606:4700:4700::1111', 'global'],
    ['2001:4860:4860::8888', 'global'],
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fe80::1', 'link_local'],
    ['febf::1', 'link_local'],
    ['fc00::1', 'unique_local'],
    ['fd12:3456::1', 'unique_local'],
    ['ff02::1', 'multicast'],
    ['fec0::1', 'reserved'],
    ['2001:db8::1', 'reserved'],
    ['2001::1', 'reserved'],
    ['3fff::1', 'reserved'],
    ['100::1', 'reserved'],
    ['::127.0.0.1', 'reserved'],
  ])('IPv6 %s is %s', (address, expected) => {
    expect(classifyAddress(address)).toBe(expected);
  });

  it.each([
    ['::ffff:127.0.0.1', 'loopback'],
    ['::ffff:7f00:1', 'loopback'],
    ['::ffff:10.0.0.1', 'private'],
    ['::ffff:192.168.0.1', 'private'],
    ['::ffff:169.254.169.254', 'link_local'],
    ['::ffff:100.64.0.1', 'cgnat'],
    ['::ffff:0.0.0.0', 'unspecified'],
    ['::ffff:8.8.8.8', 'global'],
    ['0:0:0:0:0:ffff:a00:1', 'private'],
    ['::ffff:0:10.0.0.1', 'private'],
    ['64:ff9b::a00:1', 'private'],
    ['64:ff9b::808:808', 'global'],
    ['2002:a00:1::1', 'private'],
    ['2002:808:808::1', 'global'],
  ])('IPv4-embedding form %s is %s', (address, expected) => {
    expect(classifyAddress(address)).toBe(expected);
  });

  it('refuses what it cannot parse', () => {
    expect(classifyAddress('localhost')).toBe('invalid');
    expect(classifyAddress('1.2.3')).toBe('invalid');
    expect(classifyAddress('[::1]')).toBe('invalid');
    expect(classifyAddress('')).toBe('invalid');
  });

  it('never treats a zoned address as global', () => {
    expect(classifyAddress('fe80::1%eth0')).toBe('link_local');
    expect(classifyAddress('2606:4700::1%eth0')).toBe('reserved');
  });

  it('parses IPv6 forms', () => {
    expect(parseIPv6('::')).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(parseIPv6('1::')).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
    expect(parseIPv6('::ffff:1.2.3.4')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x102, 0x304]);
    expect(parseIPv6('1:2:3:4:5:6:7:8')).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(parseIPv6('1.2.3.4')).toBeNull();
  });
});

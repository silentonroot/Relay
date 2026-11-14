import { z } from 'zod';

export const Uuid = z.uuid();
export type Uuid = z.infer<typeof Uuid>;

/** UTC ISO-8601 timestamp, as produced by Date.prototype.toISOString(). */
export const IsoDateTime = z.iso.datetime();
export type IsoDateTime = z.infer<typeof IsoDateTime>;

export const DisplayName = z.string().trim().min(1).max(120);

/**
 * Adapter operation name, e.g. `orders.list` or `orders.applyApprovedUpdate`.
 * Deliberately restrictive: operation names are used in grants, audit events and tool names.
 */
export const OperationName = z
  .string()
  .max(128)
  .regex(
    /^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)+$/,
    'expected a dotted name such as "orders.list"',
  );
export type OperationName = z.infer<typeof OperationName>;

/** Adapter identifier, e.g. `northstar`. */
export const AdapterId = z
  .string()
  .max(64)
  .regex(/^[a-z][a-z0-9-]*$/, 'expected lowercase letters, digits and dashes');

export const SemVer = z
  .string()
  .max(64)
  .regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/, 'expected a semantic version such as "1.2.3"');

export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]'
  );
}

const DNS_LABEL = '[a-z0-9](?:[a-z0-9-]*[a-z0-9])?';
const DNS_HOSTNAME = new RegExp(`^${DNS_LABEL}(?:\\.${DNS_LABEL})*$`);
const IPV4_LITERAL = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * A web origin (`scheme://host[:port]`, no path) that a connection may navigate to.
 * HTTPS is required everywhere except loopback hosts, which the local demo apps use.
 */
export const Origin = z
  .string()
  .max(255)
  .refine(
    (value) => {
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        return false;
      }
      if (url.origin !== value) return false;
      if (url.username !== '' || url.password !== '') return false;
      // The URL parser accepts hosts such as "*.example.com"; an allowlist entry must be one
      // exact host, so wildcards and other non-DNS characters are rejected here.
      if (url.hostname !== '[::1]' && !DNS_HOSTNAME.test(url.hostname)) return false;
      // An IP literal is never a legitimate application origin here, and accepting one would
      // let an allowlist name link-local or private targets such as a cloud metadata address.
      // Only the loopback literal is allowed. Hostnames that resolve to private addresses are
      // a separate check the worker performs at connection time.
      if (IPV4_LITERAL.test(url.hostname) && url.hostname !== '127.0.0.1') return false;
      if (url.protocol === 'https:') return true;
      return url.protocol === 'http:' && isLoopbackHost(url.hostname);
    },
    {
      message:
        'expected an origin such as "https://app.example.com"; http is allowed only for loopback hosts',
    },
  );
export type Origin = z.infer<typeof Origin>;

export const JsonPrimitive = z.union([z.string(), z.number(), z.boolean(), z.null()]);
export type JsonPrimitive = z.infer<typeof JsonPrimitive>;

export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export const JsonValue: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([JsonPrimitive, z.array(JsonValue), z.record(z.string(), JsonValue)]),
);

export const JsonObject = z.record(z.string(), JsonValue);
export type JsonObject = z.infer<typeof JsonObject>;

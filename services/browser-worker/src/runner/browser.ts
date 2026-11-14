import net from 'node:net';
import type { Socket } from 'node:net';
import { chromium } from 'playwright-core';
import type { Browser } from 'playwright-core';

/**
 * Loopback relay inside the sandbox: Chromium talks HTTP-proxy to 127.0.0.1:<port>, and every
 * connection is piped unchanged to the supervisor's egress socket. The relay makes no decisions;
 * the egress proxy outside the sandbox does.
 */
export interface Relay {
  readonly port: number;
  close(): void;
}

export async function startRelay(socketPath: string, maxConnections = 128): Promise<Relay> {
  const open = new Set<Socket>();
  const server = net.createServer((client) => {
    const upstream = net.connect(socketPath);
    open.add(client);
    open.add(upstream);
    client.once('close', () => open.delete(client));
    upstream.once('close', () => open.delete(upstream));
    client.pipe(upstream).pipe(client);
    client.on('error', () => upstream.destroy());
    upstream.on('error', () => client.destroy());
    client.on('close', () => upstream.destroy());
    upstream.on('close', () => client.destroy());
  });
  server.maxConnections = maxConnections;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('relay has no port');
  return {
    port: address.port,
    close(): void {
      server.close();
      for (const socket of open) socket.destroy();
    },
  };
}

export interface BrowserLaunchOptions {
  readonly executablePath: string;
  readonly chromiumSandbox: boolean;
  readonly relayPort: number;
  readonly headed: 'x11' | 'wayland' | null;
}

/**
 * Chromium flags. All traffic, loopback included, goes to the relay. Features that phone home
 * are switched off where a flag exists; whatever is left is refused by the egress proxy.
 */
export function chromiumArgs(options: BrowserLaunchOptions): string[] {
  const args = [
    `--proxy-server=http://127.0.0.1:${options.relayPort}`,
    // `<-loopback>` removes Chromium's implicit bypass for localhost, so loopback goes through
    // the proxy too.
    '--proxy-bypass-list=<-loopback>',
    '--disable-dev-shm-usage',
    '--no-first-run',
    '--no-default-browser-check',
    '--no-pings',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-domain-reliability',
    '--disable-sync',
    '--disable-breakpad',
    '--disable-crash-reporter',
    '--disable-client-side-phishing-detection',
    '--disable-default-apps',
    '--disable-extensions',
    '--metrics-recording-only',
    '--password-store=basic',
    '--use-mock-keychain',
    '--force-webrtc-ip-handling-policy',
    '--webrtc-ip-handling-policy=disable_non_proxied_udp',
  ];
  if (options.headed !== null) args.push(`--ozone-platform=${options.headed}`);
  return args;
}

export async function launchBrowser(options: BrowserLaunchOptions): Promise<Browser> {
  return chromium.launch({
    executablePath: options.executablePath,
    headless: options.headed === null,
    chromiumSandbox: options.chromiumSandbox,
    args: chromiumArgs(options),
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
    timeout: 30_000,
  });
}

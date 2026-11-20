import { existsSync, readdirSync, readFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';

/*
 * Isolation probe, run inside the sandbox in place of the runner (test-only entry override).
 * Reads one JSON line {paths, port, sockets} from stdin and reports what it could reach on stdout:
 * which paths exist and what they hold, whether a loopback port answers, and whether each Unix
 * socket path can be connected to.
 */

function contents(path: string): string | null {
  try {
    return readFileSync(path, 'utf8').slice(0, 200);
  } catch {
    return null;
  }
}

function connect(port: number): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve('timeout');
    }, 2_000);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve('connected');
    });
    socket.once('error', (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      resolve(error.code ?? 'error');
    });
  });
}

function connectUnix(socketPath: string): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.connect({ path: socketPath });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve('timeout');
    }, 2_000);
    socket.once('connect', () => {
      clearTimeout(timer);
      socket.destroy();
      resolve('connected');
    });
    socket.once('error', (error: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      resolve(error.code ?? 'error');
    });
  });
}

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', async (chunk: string) => {
  input += chunk;
  if (!input.includes('\n')) return;
  const request = JSON.parse(input.split('\n')[0] ?? '{}') as {
    paths: string[];
    port: number;
    sockets?: string[];
  };
  const result = {
    contents: Object.fromEntries(request.paths.map((path) => [path, contents(path)])),
    exists: Object.fromEntries(request.paths.map((path) => [path, existsSync(path)])),
    home: existsSync('/home') ? readdirSync('/home') : null,
    root: readdirSync('/'),
    app: readdirSync('/app'),
    interfaces: Object.keys(os.networkInterfaces()),
    loopback: await connect(request.port),
    unix: Object.fromEntries(
      await Promise.all(
        (request.sockets ?? []).map(async (socket) => [socket, await connectUnix(socket)] as const),
      ),
    ),
    envKeys: Object.keys(process.env).sort(),
    uid: process.getuid?.(),
  };
  process.stdout.write(`${JSON.stringify(result)}\n`, () => process.exit(0));
});

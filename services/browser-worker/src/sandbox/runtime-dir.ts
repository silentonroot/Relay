import { randomBytes } from 'node:crypto';
import { lstat, mkdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

/** Linux `sun_path` is 108 bytes including the terminator; keep a margin. */
export const MAX_SOCKET_PATH_BYTES = 100;
export const EGRESS_SOCKET_NAME = 'egress.sock';

/** `$XDG_RUNTIME_DIR/aab-worker`, falling back to `/tmp/aab-worker-<uid>`. */
export function defaultRuntimeBaseDir(env: NodeJS.ProcessEnv = process.env): string {
  const runtime = env['XDG_RUNTIME_DIR'];
  if (runtime !== undefined && path.isAbsolute(runtime)) return path.join(runtime, 'aab-worker');
  return path.join(os.tmpdir(), `aab-worker-${process.getuid?.() ?? 'user'}`);
}

/** Creates (or checks) the base directory: a real directory, owned by us, mode 0700. */
export async function ensureRuntimeBaseDir(baseDir: string): Promise<void> {
  if (!path.isAbsolute(baseDir)) throw new Error('runtime base directory must be absolute');
  await mkdir(baseDir, { recursive: true, mode: 0o700 });
  const info = await lstat(baseDir);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`runtime base directory ${baseDir} is not a directory`);
  }
  const uid = process.getuid?.();
  if (uid !== undefined && info.uid !== uid) {
    throw new Error(`runtime base directory ${baseDir} is not owned by this user`);
  }
  if ((info.mode & 0o077) !== 0) {
    throw new Error(`runtime base directory ${baseDir} must not be accessible to other users`);
  }
}

export function socketPathFits(socketPath: string): boolean {
  return Buffer.byteLength(socketPath) <= MAX_SOCKET_PATH_BYTES;
}

export interface JobRuntimeDir {
  readonly dir: string;
  readonly socketPath: string;
  remove(): Promise<void>;
}

/** Makes a fresh 0700 directory for one job. Fails clearly if the socket path is too long. */
export async function createJobRuntimeDir(baseDir: string): Promise<JobRuntimeDir> {
  await ensureRuntimeBaseDir(baseDir);
  const dir = path.join(baseDir, randomBytes(6).toString('hex'));
  const socketPath = path.join(dir, EGRESS_SOCKET_NAME);
  if (!socketPathFits(socketPath)) {
    throw new Error(
      `egress socket path would be ${Buffer.byteLength(socketPath)} bytes, over the ` +
        `${MAX_SOCKET_PATH_BYTES}-byte Unix socket limit; choose a shorter runtime base directory`,
    );
  }
  await mkdir(dir, { mode: 0o700 });
  return {
    dir,
    socketPath,
    remove: () => rm(dir, { recursive: true, force: true }),
  };
}

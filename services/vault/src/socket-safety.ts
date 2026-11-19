import { chmod, chown, lstat, mkdir, readFile, realpath, unlink } from 'node:fs/promises';
import type { Stats } from 'node:fs';
import { connect } from 'node:net';
import { dirname, join, sep } from 'node:path';
import { VAULT_ROLES } from '@aab/contracts';
import type { VaultIsolation, VaultRole } from '@aab/contracts';
import type { VaultConfig } from './config.js';

/*
 * Socket and directory safety (ADR-014 section 2, P3-3). On Linux, connecting to a Unix
 * socket needs write permission on the socket file and search permission on every directory
 * above it, so the kernel is the identity check. That only holds if the directories and
 * sockets are what we think they are, so the vault inspects them before it listens and again
 * after, and refuses to start on anything it cannot vouch for. Every message names a path or
 * a setting and never a secret.
 *
 * Layout: <socketDir>/<role>/vault.sock, one directory per role.
 *   separate-uid: role directory mode 0750 (setgid allowed), group = the role's group, so the
 *                 members of that group, and no other group, can search it; socket 0660.
 *   shared-uid:   role directory mode 0700, socket 0600; the kernel cannot tell roles apart.
 */

export class SocketSafetyError extends Error {
  override readonly name = 'SocketSafetyError';
}

/** Longest socket path we accept; `sun_path` is 108 bytes on Linux, leave headroom. */
export const MAX_SOCKET_PATH_BYTES = 100;
export const SOCKET_FILE_NAME = 'vault.sock';

const MODE_MASK = 0o7777;
const SETGID = 0o2000;

export interface SocketSafetyDeps {
  /** Defaults to `process.platform`. Injected by tests. */
  platform?: NodeJS.Platform;
  /** The vault's effective uid and gid. Default to the process's. */
  uid?: number;
  gid?: number;
  /** The repository root; a socket directory below it is refused (the sandbox mounts it). */
  repositoryRoot?: string;
  /** Resolves a group name or numeric gid to a gid; defaults to reading /etc/group. */
  resolveGroup?: (spec: string) => Promise<number>;
  /** Replaced by tests that cannot change group ownership. Default `fs.chown`. */
  chownPath?: (path: string, uid: number, gid: number) => Promise<void>;
}

export interface RolePaths {
  role: VaultRole;
  directory: string;
  socket: string;
  /** The group the directory and socket must belong to; null in `shared-uid`. */
  gid: number | null;
}

function isInside(path: string, ancestor: string): boolean {
  const base = ancestor.endsWith(sep) ? ancestor : ancestor + sep;
  return path === ancestor || path.startsWith(base);
}

/** Reads the numeric gid of a group name from /etc/group, or accepts a numeric gid. */
export async function resolveGroupFromFile(
  spec: string,
  groupFile = '/etc/group',
): Promise<number> {
  if (/^\d+$/.test(spec)) return Number(spec);
  let text: string;
  try {
    text = await readFile(groupFile, 'utf8');
  } catch {
    throw new SocketSafetyError('cannot read the group database to resolve a role group');
  }
  for (const line of text.split('\n')) {
    const [name, , gid] = line.split(':');
    if (name === spec && gid !== undefined && /^\d+$/.test(gid)) return Number(gid);
  }
  throw new SocketSafetyError('a configured role group does not exist');
}

// ---------------------------------------------------------------------------------------------
// Pure checks on stat results, so each refusal is testable without the owning user or root.

export interface DirectoryExpectation {
  isolation: VaultIsolation;
  uid: number;
  /** Required group of a role directory; null for the base directory. */
  gid: number | null;
  kind: 'base' | 'role';
}

/** Returns a problem description for a directory that is not safe, or null. */
export function directoryProblem(stat: Stats, expected: DirectoryExpectation): string | null {
  if (stat.isSymbolicLink()) return 'is a symbolic link';
  if (!stat.isDirectory()) return 'is not a directory';
  if (stat.uid !== expected.uid) return "is not owned by the vault's user";
  const mode = stat.mode & MODE_MASK;
  if (expected.kind === 'base') {
    // The base directory only has to let the callers reach their own subdirectory: group and
    // other must not write, and other must not list it. Search (x) for other is what lets the
    // three role groups through when they share no common group.
    if (expected.isolation === 'shared-uid') {
      if ((mode & 0o077) !== 0) return 'must be mode 0700 in shared-uid isolation';
    } else {
      if ((mode & 0o022) !== 0) return 'must not be writable by group or other';
      if ((mode & 0o004) !== 0) return 'must not be readable by other';
    }
    return null;
  }
  if ((mode & 0o007) !== 0) return 'is accessible to other (mode must have no other bits)';
  if (expected.isolation === 'shared-uid') {
    if ((mode & ~SETGID & MODE_MASK) !== 0o700 || (mode & SETGID) !== 0) {
      return 'must be mode 0700 in shared-uid isolation';
    }
    return null;
  }
  if ((mode & ~SETGID & MODE_MASK) !== 0o750) {
    return 'must be mode 0750 (or 2750); the role group may search it, never write to it';
  }
  if (expected.gid === null || stat.gid !== expected.gid) {
    return "does not belong to the role's group";
  }
  return null;
}

const STICKY = 0o1000;

/**
 * Returns a problem description for a directory ABOVE the socket directory, or null. Whoever can
 * write to an ancestor can rename the directory below it and put another one (and another socket)
 * in its place, so an ancestor must be owned by root or by the vault's user and must not be
 * writable by group or other. The one exception is a sticky directory owned by root (like /tmp):
 * there nobody can rename an entry they do not own.
 */
export function ancestorProblem(stat: Stats, uid: number): string | null {
  if (stat.isSymbolicLink()) return 'is a symbolic link';
  if (!stat.isDirectory()) return 'is not a directory';
  if (stat.uid !== 0 && stat.uid !== uid) {
    return "is owned by neither root nor the vault's user";
  }
  const mode = stat.mode & MODE_MASK;
  if ((mode & 0o022) !== 0 && !((mode & STICKY) !== 0 && stat.uid === 0)) {
    return 'is writable by group or other (and is not a sticky directory owned by root)';
  }
  return null;
}

export interface SocketExpectation {
  isolation: VaultIsolation;
  uid: number;
  gid: number | null;
}

/** Returns a problem description for a socket file that is not what we created, or null. */
export function socketProblem(stat: Stats, expected: SocketExpectation): string | null {
  if (stat.isSymbolicLink()) return 'is a symbolic link';
  if (!stat.isSocket()) return 'is not a socket';
  if (stat.uid !== expected.uid) return "is not owned by the vault's user";
  const mode = stat.mode & 0o777;
  const wanted = expected.isolation === 'shared-uid' ? 0o600 : 0o660;
  if (mode !== wanted) return 'has the wrong mode';
  if (
    expected.isolation === 'separate-uid' &&
    (expected.gid === null || stat.gid !== expected.gid)
  ) {
    return "does not belong to the role's group";
  }
  return null;
}

// ---------------------------------------------------------------------------------------------

async function lstatOrNull(path: string): Promise<Stats | null> {
  try {
    return await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new SocketSafetyError(`cannot inspect ${path}`);
  }
}

/** True when something accepts connections on the socket (another vault is running). */
function isLive(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = connect(path);
    const done = (live: boolean) => {
      probe.destroy();
      resolve(live);
    };
    probe.once('connect', () => done(true));
    probe.once('error', () => done(false));
    probe.setTimeout(500, () => done(false));
  });
}

/**
 * Checks the platform, the paths and the existing directories, creates the missing role
 * directories with the right owner and mode, and removes stale sockets. Returns the paths to
 * listen on. Throws `SocketSafetyError` on the first thing that is not safe.
 */
export async function prepareSocketDirectories(
  config: Pick<VaultConfig, 'socketDir' | 'kekDir' | 'isolation' | 'roleGroups'>,
  deps: SocketSafetyDeps = {},
): Promise<RolePaths[]> {
  const platform = deps.platform ?? process.platform;
  if (platform !== 'linux') {
    throw new SocketSafetyError(
      'the vault runs on Linux only: other platforms do not enforce permissions on socket files',
    );
  }
  const uid = deps.uid ?? process.geteuid?.();
  const vaultGid = deps.gid ?? process.getegid?.();
  if (uid === undefined || vaultGid === undefined) {
    throw new SocketSafetyError('cannot determine the vault user');
  }
  if (uid === 0) throw new SocketSafetyError('the vault must not run as root');
  const chownPath = deps.chownPath ?? chown;
  const resolveGroup = deps.resolveGroup ?? ((spec: string) => resolveGroupFromFile(spec));

  const base = config.socketDir;
  if (deps.repositoryRoot !== undefined && isInside(base, deps.repositoryRoot)) {
    throw new SocketSafetyError(
      'AAB_VAULT_SOCKET_DIR must not be inside the repository (the sandbox may mount it)',
    );
  }
  const longest = Buffer.byteLength(join(base, 'supervisor', SOCKET_FILE_NAME));
  if (longest > MAX_SOCKET_PATH_BYTES) {
    throw new SocketSafetyError(
      `AAB_VAULT_SOCKET_DIR is too long: socket paths would exceed ${MAX_SOCKET_PATH_BYTES} bytes`,
    );
  }
  if (isInside(base, config.kekDir) || isInside(config.kekDir, base)) {
    throw new SocketSafetyError(
      'AAB_VAULT_SOCKET_DIR and AAB_KEK_DIR must not contain one another',
    );
  }

  // The base directory must exist, be ours, and be reached without a symbolic link in any
  // component: the realpath equals the configured path.
  const baseStat = await lstatOrNull(base);
  if (baseStat === null) throw new SocketSafetyError(`socket directory does not exist: ${base}`);
  let real: string;
  try {
    real = await realpath(base);
  } catch {
    throw new SocketSafetyError(`cannot resolve the socket directory: ${base}`);
  }
  if (real !== base) {
    throw new SocketSafetyError(
      `AAB_VAULT_SOCKET_DIR contains a symbolic link (resolves elsewhere): ${base}`,
    );
  }
  // Every directory above it: none may be one another user could rename the base through.
  for (let ancestor = dirname(base); ; ancestor = dirname(ancestor)) {
    const stat = await lstatOrNull(ancestor);
    if (stat === null) throw new SocketSafetyError(`cannot inspect ${ancestor}`);
    const problem = ancestorProblem(stat, uid);
    if (problem !== null) {
      throw new SocketSafetyError(`ancestor of the socket directory ${problem}: ${ancestor}`);
    }
    if (ancestor === dirname(ancestor)) break;
  }
  const baseProblem = directoryProblem(baseStat, {
    isolation: config.isolation,
    uid,
    gid: null,
    kind: 'base',
  });
  if (baseProblem !== null) throw new SocketSafetyError(`socket directory ${baseProblem}: ${base}`);

  // Resolve and compare the role groups before touching anything.
  const gids = new Map<VaultRole, number | null>();
  if (config.isolation === 'separate-uid') {
    for (const role of VAULT_ROLES) {
      const spec = config.roleGroups[role];
      if (spec === undefined) throw new SocketSafetyError(`no group configured for role ${role}`);
      gids.set(role, await resolveGroup(spec));
    }
    const values = [...gids.values()];
    if (new Set(values).size !== values.length) {
      throw new SocketSafetyError('two roles resolve to the same group');
    }
    if (values.includes(vaultGid)) {
      // The vault's own primary group holds every file it creates; a role sharing it would
      // also share them.
      throw new SocketSafetyError("a role group must not be the vault's own primary group");
    }
  } else {
    for (const role of VAULT_ROLES) gids.set(role, null);
  }

  const paths: RolePaths[] = [];
  const identities = new Set<string>();
  for (const role of VAULT_ROLES) {
    const directory = join(base, role);
    const gid = gids.get(role) ?? null;
    let stat = await lstatOrNull(directory);
    if (stat === null) {
      // Created with no access for anyone else, then handed to the role's group.
      await mkdir(directory, { mode: 0o700 });
      // The umask (0117 in the entry point) shaves bits off `mkdir`'s mode: set it explicitly.
      await chmod(directory, 0o700);
      if (gid !== null) {
        try {
          await chownPath(directory, uid, gid);
        } catch {
          throw new SocketSafetyError(
            `cannot give role directory to its group (is the vault user a member?): ${directory}`,
          );
        }
        await chmod(directory, 0o750);
      }
      stat = await lstatOrNull(directory);
      if (stat === null) throw new SocketSafetyError(`cannot create role directory: ${directory}`);
    }
    const problem = directoryProblem(stat, {
      isolation: config.isolation,
      uid,
      gid,
      kind: 'role',
    });
    if (problem !== null) throw new SocketSafetyError(`role directory ${problem}: ${directory}`);
    const identity = `${stat.dev}:${stat.ino}`;
    if (identities.has(identity)) {
      throw new SocketSafetyError(`role directories are shared: ${directory}`);
    }
    identities.add(identity);

    const socket = join(directory, SOCKET_FILE_NAME);
    const existing = await lstatOrNull(socket);
    if (existing !== null) {
      // Remove a stale socket only after checking it is a socket we own and nobody is
      // listening on it: never a symlink, a regular file or someone else's file.
      if (existing.isSymbolicLink() || !existing.isSocket() || existing.uid !== uid) {
        throw new SocketSafetyError(
          `existing path is not a socket owned by the vault, refusing to remove it: ${socket}`,
        );
      }
      if (await isLive(socket)) {
        throw new SocketSafetyError(`another process is listening on: ${socket}`);
      }
      await unlink(socket);
    }
    paths.push({ role, directory, socket, gid });
  }
  return paths;
}

/**
 * Sets the socket's mode and group explicitly and checks the result, after `listen`. The
 * vault also sets its umask to 0117 at start, but this does not rely on it.
 */
export async function finalizeSocket(
  path: RolePaths,
  config: Pick<VaultConfig, 'isolation'>,
  deps: Pick<SocketSafetyDeps, 'uid' | 'chownPath'> = {},
): Promise<void> {
  const uid = deps.uid ?? process.geteuid?.();
  if (uid === undefined) throw new SocketSafetyError('cannot determine the vault user');
  if (config.isolation === 'separate-uid' && path.gid !== null) {
    try {
      await (deps.chownPath ?? chown)(path.socket, uid, path.gid);
    } catch {
      throw new SocketSafetyError(`cannot give socket to its group: ${path.socket}`);
    }
  }
  await chmod(path.socket, config.isolation === 'shared-uid' ? 0o600 : 0o660);
  const stat = await lstatOrNull(path.socket);
  const problem =
    stat === null
      ? 'is missing after listen'
      : socketProblem(stat, { isolation: config.isolation, uid, gid: path.gid });
  if (problem !== null) throw new SocketSafetyError(`socket ${problem}: ${path.socket}`);
}

/** Removes a socket file this process created, if it is still one of ours. */
export async function removeOwnSocket(path: string, uid = process.geteuid?.()): Promise<void> {
  const stat = await lstatOrNull(path).catch(() => null);
  if (stat !== null && stat.isSocket() && !stat.isSymbolicLink() && stat.uid === uid) {
    await unlink(path).catch(() => undefined);
  }
}

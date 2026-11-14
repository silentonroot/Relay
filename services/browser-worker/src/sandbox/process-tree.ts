import { readdir, readFile } from 'node:fs/promises';

/** Parent pid from `/proc/<pid>/stat`; the command name may contain spaces and parentheses. */
function parentOf(stat: string): number | null {
  const end = stat.lastIndexOf(')');
  if (end < 0) return null;
  const fields = stat.slice(end + 2).split(' ');
  const ppid = Number(fields[1]);
  return Number.isInteger(ppid) ? ppid : null;
}

/** Every descendant of `rootPid` visible in `/proc`, deepest last. Linux only. */
export async function listDescendants(rootPid: number): Promise<number[]> {
  let entries: string[];
  try {
    entries = await readdir('/proc');
  } catch {
    return [];
  }
  const children = new Map<number, number[]>();
  await Promise.all(
    entries
      .filter((entry) => /^\d+$/.test(entry))
      .map(async (entry) => {
        try {
          const ppid = parentOf(await readFile(`/proc/${entry}/stat`, 'utf8'));
          if (ppid === null) return;
          const list = children.get(ppid) ?? [];
          list.push(Number(entry));
          children.set(ppid, list);
        } catch {
          // The process exited while we looked.
        }
      }),
  );
  const result: number[] = [];
  const queue = [rootPid];
  while (queue.length > 0) {
    const pid = queue.shift() as number;
    for (const child of children.get(pid) ?? []) {
      result.push(child);
      queue.push(child);
    }
  }
  return result;
}

function signal(pid: number, name: NodeJS.Signals): void {
  try {
    process.kill(pid, name);
  } catch {
    // Already gone.
  }
}

/**
 * SIGKILLs a process, its process group and every descendant. The tree is first frozen with
 * SIGSTOP (so nothing can fork while we look) and collected before anything is killed, because
 * once a parent dies its children are re-parented and can no longer be found from the root.
 */
export async function killProcessTree(pid: number, options: { group: boolean }): Promise<void> {
  const seen = new Set<number>([pid]);
  signal(pid, 'SIGSTOP');
  for (let round = 0; round < 3; round += 1) {
    const found = (await listDescendants(pid)).filter((child) => !seen.has(child));
    if (found.length === 0) break;
    for (const child of found) {
      seen.add(child);
      signal(child, 'SIGSTOP');
    }
  }
  if (options.group) {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      // No such group.
    }
  }
  for (const target of seen) signal(target, 'SIGKILL');
}

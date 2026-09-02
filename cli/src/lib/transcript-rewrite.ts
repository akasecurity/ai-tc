/**
 * Symlink-safe containment plus the atomic in-place rewrite that `aka vault
 * prune` needs to put raw values back into a transcript.
 *
 * DELIBERATE COPY, NOT A NEW DESIGN. The same containment rule and the same
 * write-to-temp-then-rename already guard the Claude Code plugin's own at-rest
 * scrub, and this package does not depend on that one, so there is no import
 * that reaches them from here. Rewriting a user's transcript in place is the
 * last place to run a second, subtly different containment rule — so the
 * CONTAINMENT is transcribed rather than re-invented, and the two must stay in
 * step until the helpers move into a package both surfaces already depend on.
 *
 * The temp-file handling is where the two deliberately diverge, and the reason
 * is which bytes each one strands: the scrub's temp holds text it has already
 * redacted, while this one holds recovered PLAINTEXT. A crash mid-write is
 * therefore a spill here and not there, so this side names its temp per-process,
 * creates it exclusively, and sweeps what an earlier run left behind.
 *
 * IO is node:fs only: no store access, no network, no environment. The single
 * call outside that is `process.kill(pid, 0)` — a signal that is never sent,
 * asked only to tell a crashed run's temp file from a live run's.
 */
import {
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';

// The whole-file read cap. This verb reads each transcript entirely (it has to:
// a pointer may sit on any line), which is fine for a user-initiated command,
// but a pathological file must not be pulled into memory unbounded.
export const DEFAULT_MAX_REWRITE_BYTES = 32 * 1024 * 1024;

/**
 * The roots whose contained files this verb may rewrite: the Claude Code
 * transcript directory, and nothing else. `userHome` overrides the OS home —
 * the override moves the ROOT, never the `.claude/projects` shape under it, so
 * no spelling of the flag can widen the scope to an arbitrary directory.
 */
export function transcriptRoots(userHome?: string): readonly string[] {
  return [join(userHome ?? homedir(), '.claude', 'projects')];
}

/**
 * Read a contained file, capped. Returns null when it is oversized or
 * unreadable — the same "no bytes, no opinion" answer the rewrite gives, so the
 * plan pass and the apply pass agree about which files they can even see.
 */
export function readContainedFile(
  realPath: string,
  maxBytes: number = DEFAULT_MAX_REWRITE_BYTES,
): string | null {
  try {
    if (statSync(realPath).size > maxBytes) return null;
    return readFileSync(realPath, 'utf8');
  } catch {
    return null;
  }
}

/** The real (symlink-resolved) path, or null when it cannot be resolved. */
export function realPathOrNull(path: string): string | null {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

// True when `realTarget` (already resolved) sits strictly inside `root` — a
// nested descendant, never the root itself and never an escaping `..` sibling.
// The root is resolved too, so both sides are compared as real paths and a
// symlink planted inside a root cannot redirect a write outside it.
function isWithinRoot(realTarget: string, root: string): boolean {
  const realRoot = realPathOrNull(root);
  if (realRoot === null) return false;
  const rel = relative(realRoot, realTarget);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

/**
 * The real path of `filePath` when it is a contained transcript, else null.
 * Returns the RESOLVED path so the caller reads and writes exactly the
 * canonical in-scope file rather than a path a symlink could redirect.
 */
export function containedRealPath(filePath: string, roots: readonly string[]): string | null {
  const realTarget = realPathOrNull(resolve(filePath));
  if (realTarget === null) return null;
  return roots.some((root) => isWithinRoot(realTarget, root)) ? realTarget : null;
}

// The sibling this module writes before it renames, named
// `<transcript>.<pid>.aka-prune.tmp`.
//
// The pid is what makes the name per-process, the same way the store's own
// atomic writer names its temp: two runs never share an inode, so neither can
// publish the other's half-written bytes, and neither can inherit a leftover's
// permission bits (`writeFileSync` applies `mode` only when it CREATES). It is
// also the only thing that lets a later run tell a crashed run's leftover from
// a live run's work in progress.
const TMP_SUFFIX = '.aka-prune.tmp';

function tempPathFor(realPath: string): string {
  return `${realPath}.${String(process.pid)}${TMP_SUFFIX}`;
}

// True unless the OS says no such process. EPERM means a process that exists
// and is not ours — a live run, so its temp is not ours to sweep.
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

/**
 * Delete temp files an earlier, killed run stranded beside this transcript.
 *
 * A process killed between the write and the rename leaves a file holding
 * restored PLAINTEXT and nothing else would ever remove it, so the rewrite
 * sweeps before the transform has a say — a pass that goes on to abort still
 * clears the previous pass's spill.
 *
 * Deliberately the narrowest sweep that can do that, because it deletes: only
 * siblings of THIS transcript, only names this module itself mints (the exact
 * `<basename>.<digits>.aka-prune.tmp` shape — the trailing dot on the prefix
 * keeps the transcript itself from ever matching), only regular files, and only
 * when the pid in the name names no living process. A concurrent run's temp is
 * therefore left alone; our own pid needs no liveness check, since the process
 * asking is the one that would be using it.
 */
function sweepStrandedTemps(realPath: string): void {
  const dir = dirname(realPath);
  const prefix = `${basename(realPath)}.`;
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return; // best-effort: a directory we cannot list sweeps nothing
  }
  for (const name of names) {
    if (!name.startsWith(prefix) || !name.endsWith(TMP_SUFFIX)) continue;
    const pidPart = name.slice(prefix.length, name.length - TMP_SUFFIX.length);
    if (!/^\d+$/.test(pidPart)) continue;
    const pid = Number(pidPart);
    if (pid !== process.pid && isProcessAlive(pid)) continue;
    try {
      const stranded = join(dir, name);
      // lstat, and regular files only: a symlink or a directory wearing this
      // name is not something this module wrote, so it is not ours to remove.
      if (!lstatSync(stranded).isFile()) continue;
      rmSync(stranded, { force: true });
    } catch {
      // best-effort — a sweep that cannot run must not stop the rewrite.
    }
  }
}

/** What a transform decided about a file: new bytes, or an abort with a reason. */
export type TransformResult = { text: string; replaced: number } | { abort: string };

export type RewriteOutcome =
  | { status: 'rewritten'; replaced: number }
  | { status: 'unchanged' }
  | { status: 'aborted'; reason: string };

/**
 * Rewrite one contained file in place, atomically, or leave it byte-identical.
 *
 * Every failure path — an oversized file, an unreadable one, a transform that
 * aborts, a concurrent append, a failed write — returns `aborted` with the
 * original file untouched. That is the posture this verb needs: it writes
 * PLAINTEXT back to disk, so "did nothing" must always be reachable and must
 * always be the answer under any doubt.
 *
 * The one thing it does to a file it does not rewrite is sweep the temp files
 * an earlier killed run stranded beside it (`sweepStrandedTemps`) — removing
 * spilled plaintext, never the transcript, which stays byte-identical.
 */
export async function rewriteContainedFile(
  realPath: string,
  transform: (text: string) => Promise<TransformResult>,
  maxBytes: number = DEFAULT_MAX_REWRITE_BYTES,
): Promise<RewriteOutcome> {
  let before: ReturnType<typeof statSync>;
  let content: string;
  try {
    // Snapshot the stat up front: the size gates the read, the mode is
    // re-applied to the rewrite, and size+mtime detect a concurrent append
    // just before the rename below.
    before = statSync(realPath);
    if (before.size > maxBytes)
      return { status: 'aborted', reason: 'file is larger than the read cap' };
    content = readFileSync(realPath, 'utf8');
  } catch {
    return { status: 'aborted', reason: 'unreadable' };
  }

  // Before the transform, so every file this pass opens gets an earlier run's
  // spilled plaintext cleared even when this one goes on to abort. It never
  // touches the transcript itself, so "did nothing" stays true of the target.
  sweepStrandedTemps(realPath);

  let result: TransformResult;
  try {
    result = await transform(content);
  } catch {
    return { status: 'aborted', reason: 'the rewrite could not be computed' };
  }
  if ('abort' in result) return { status: 'aborted', reason: result.abort };
  if (result.text === content) return { status: 'unchanged' };

  const tmpPath = tempPathFor(realPath);
  try {
    // Preserve the transcript's permission bits: without an explicit mode the
    // temp file is created at the umask default, and the rename would widen a
    // 0600 transcript to world-readable — while carrying restored PLAINTEXT.
    // `wx` (O_EXCL) is what makes that mode binding: it creates the temp or
    // fails, so the bytes can never land in an inode someone else's mode
    // already decided, and it refuses to follow a symlink planted at the path.
    // Anything already sitting there — a directory, a leftover the sweep would
    // not touch — is doubt, and doubt aborts with the transcript untouched.
    writeFileSync(tmpPath, result.text, { mode: before.mode & 0o777, flag: 'wx' });
    // The transcript may be live. Renaming a snapshot over a file that changed
    // underneath would silently destroy the appended lines, so ANY difference
    // since the first stat aborts: a skipped restore can be re-run, lost
    // transcript lines cannot.
    const now = statSync(realPath);
    if (now.size !== before.size || now.mtimeMs !== before.mtimeMs) {
      rmSync(tmpPath, { force: true, recursive: true });
      return { status: 'aborted', reason: 'the file changed while it was being read' };
    }
    renameSync(tmpPath, realPath);
  } catch {
    try {
      // `recursive: true` also clears a tmpPath that turned out to be a
      // directory rather than a partially written file.
      rmSync(tmpPath, { force: true, recursive: true });
    } catch {
      // nothing to clean up
    }
    return { status: 'aborted', reason: 'the rewrite could not be written' };
  }
  return { status: 'rewritten', replaced: result.replaced };
}

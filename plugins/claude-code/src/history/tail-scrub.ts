/**
 * At-rest scrub of a live session's transcript file. Claude Code appends every
 * prompt to `~/.claude/projects/*.jsonl` even when a hook blocked it, so a raw
 * secret the tail scan just found is also sitting in plaintext on disk. This
 * module rewrites those secret spans IN PLACE to vault pointers (via the
 * injected vault-glue tokenizer), line by line, so the file stays valid
 * newline-delimited JSON and untouched lines stay byte-identical.
 *
 * SCOPE LIMIT: the target must resolve (symlink-safe, real-path containment)
 * inside the redaction scope's artifact roots. An out-of-scope path is never
 * opened for writing — the same structural containment the remediation
 * redactor enforces, reused from `remediation/redact.ts` rather than
 * re-implemented.
 *
 * FAULT POSTURE: any error returns null and leaves the file as it was — the
 * reconcile pass continues. The injected tokenizer is itself fail-secure: a
 * span it cannot vault degrades to the one-way `[REDACTED:CATEGORY]`
 * placeholder, so a fault destroys residue rather than leaking it. The one
 * tokenizer outcome treated as a fault HERE is the unclassifiable blanket
 * (a changed line the tokenizer accounted for in NONE of its three counts —
 * it could not tell secret from clean): rewriting whole transcript lines to a
 * blanket placeholder would destroy the user's transcript, so the scrub aborts
 * with the file untouched instead. All three counts have to be read, not just
 * the first two: a span the caller's pack policy said to strike one-way is
 * reported as `redacted`, mints no pointer and degrades nothing, so reading
 * two counts would abort the whole file on every line a Redact (non-vault)
 * detection legitimately rewrote.
 */
import {
  chmodSync,
  lstatSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';

import { type platformRedactionScope, resolveRedactableArtifact } from '../remediation/redact.ts';

// Files larger than this are skipped whole (return null): this scrub does a
// whole-file read — acceptable because it runs in the detached reconcile
// worker, off the hot hook path — but a pathological transcript must not
// balloon the worker, so the read is capped.
const DEFAULT_MAX_SCRUB_BYTES = 32 * 1024 * 1024;

// The sibling this module writes before it renames, named
// `<transcript>.<pid>.aka-scrub.tmp`.
//
// The pid is what makes the name per-process: two runs never share an inode, so
// neither can publish the other's half-written bytes, and neither can inherit a
// leftover's permission bits (`writeFileSync` applies `mode` only when it
// CREATES). It is also the only thing that lets a later run tell a crashed run's
// leftover from a live run's work in progress.
//
// PER-PROCESS, not per-call: the pid is all the name carries, and this rewrite
// awaits between the sweep and the write, so a caller must not drive two
// overlapping passes over one transcript. The callers drive it one file at a time.
// Were two to overlap, the second's exclusive create would fail EEXIST and its
// cleanup would remove the first's in-flight temp, so the first would abort at
// the rename and report having done nothing — nothing corrupted, and the next
// pass retries, but `wx` on its own does not hand two concurrent calls separate
// temps. A nonce in the name would.
const TMP_SUFFIX = '.aka-scrub.tmp';

function tempPathFor(realPath: string): string {
  return `${realPath}.${String(process.pid)}${TMP_SUFFIX}`;
}

// True unless the OS says no such process. EPERM means a process that exists and
// is not ours — a live run, so its temp is not ours to sweep.
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
 * A process killed between the write and the rename leaves a file holding a
 * whole copy of the transcript — the scrubbed lines, but also every other line
 * around them — and nothing else would ever remove it.
 *
 * Deliberately the narrowest sweep that can do that, because it deletes: only
 * siblings of THIS transcript, only names this module itself mints (the exact
 * `<basename>.<digits>.aka-scrub.tmp` shape, plus the pid-free
 * `<basename>.aka-scrub.tmp` a published build left behind — the trailing dot on
 * the prefix keeps the transcript itself from ever matching), only regular files,
 * and only when the pid in the name names no living process. A concurrent run's
 * temp is therefore left alone; our own pid needs no liveness check, since the
 * process asking is the one that would be using it.
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
    // An empty pid part is the LEGACY shape — `<basename>.aka-scrub.tmp`, the name
    // a published build wrote before the pid went into it. It names no owner to
    // ask about, so it is always swept: leaving it keeps a whole plaintext copy
    // of the transcript on disk for good, where the worst case of removing it is an
    // older build's rename failing, which that build already treats as having
    // done nothing.
    if (pidPart !== '') {
      if (!/^\d+$/.test(pidPart)) continue;
      const pid = Number(pidPart);
      if (pid !== process.pid && isProcessAlive(pid)) continue;
    }
    try {
      const stranded = join(dir, name);
      // lstat, and regular files only: a symlink or a directory wearing this
      // name is not something this module wrote, so it is not ours to remove.
      if (!lstatSync(stranded).isFile()) continue;
      rmSync(stranded, { force: true });
    } catch {
      // best-effort — a sweep that cannot run must not stop the scrub.
    }
  }
}

export interface TailScrubDeps {
  // The vault-glue text tokenizer: self-scans, shields existing pointers so a
  // re-run never re-tokenizes them, and replaces each secret span with a
  // pointer (or a one-way placeholder on degrade).
  tokenizeText(
    text: string,
    opts?: { findings?: unknown[] },
  ): Promise<{
    text: string;
    pointers: string[];
    degraded: { category: string }[];
    // Spans struck one-way because policy said Redact rather than Redact &
    // Vault. Required, not optional: it is the third reading the blanket test
    // below depends on, and a tokenizer that omits it would silently put every
    // policy-struck line back under the abort.
    redacted: { category: string }[];
  }>;
  // The artifact roots whose contained files may be rewritten in place.
  scope: ReturnType<typeof platformRedactionScope>;
  // Whole-file read cap in bytes; a larger file is skipped (null). Defaults to
  // 32 MiB when unset.
  maxBytes?: number;
}

/**
 * Scrub one transcript file: replace every detected secret span with a vault
 * pointer, in place, preserving line structure and the trailing newline
 * exactly as found. Returns the count of rewritten lines, `{ rewritten: 0 }`
 * without writing when nothing matched, and null when the path is out of
 * scope, oversized, unreadable, or anything failed (the file is then left
 * byte-identical).
 */
export async function scrubTranscriptTail(
  filePath: string,
  deps: TailScrubDeps,
): Promise<{ rewritten: number } | null> {
  try {
    // Containment first: out of scope → never opened for writing.
    const realPath = resolveRedactableArtifact(filePath, deps.scope);
    if (realPath === null) return null;
    // Ahead of every return below, because a stranded copy has to be cleared
    // even on a pass that scrubs nothing: a transcript over the byte cap is
    // skipped whole, and it only ever grows, so a pass that skips it once skips
    // it forever and the copy would never be reached again. Runs only after the
    // scope check, so an out-of-scope path is still never touched. It never
    // touches the transcript itself, which stays byte-identical.
    sweepStrandedTemps(realPath);
    // Snapshot the stat up front: the size gates the whole-file read, the mode
    // is re-applied to the rewrite, and size+mtime detect concurrent appends
    // just before the rename below.
    const statBefore = statSync(realPath);
    if (statBefore.size > (deps.maxBytes ?? DEFAULT_MAX_SCRUB_BYTES)) return null;

    const content = readFileSync(realPath, 'utf8');
    // Line-by-line so the rewrite can only ever change bytes WITHIN a line —
    // the newline structure (including a trailing newline, which survives the
    // split/join round-trip as a final empty element) is preserved exactly.
    const lines = content.split('\n');
    let rewritten = 0;
    for (const [i, line] of lines.entries()) {
      if (line === '') continue;
      const result = await deps.tokenizeText(line);
      if (result.text === line) continue;
      // A changed line the tokenizer accounted for in none of its three
      // counts is the unclassifiable blanket — abort rather than destroy
      // lines. A policy-struck span lands in `redacted`, which is why that
      // count belongs in the test: it is a deliberate rewrite, not a blanket.
      if (
        result.pointers.length === 0 &&
        result.degraded.length === 0 &&
        result.redacted.length === 0
      ) {
        return null;
      }
      lines[i] = result.text;
      rewritten += 1;
    }
    if (rewritten === 0) return { rewritten: 0 };

    // Atomic rewrite: full write to a per-process sibling temp file, then rename
    // over the original — a crash mid-write leaves the transcript intact.
    const tmpPath = tempPathFor(realPath);
    try {
      // Preserve the transcript's permission bits: without an explicit mode
      // the temp file is created at the umask default, and the rename would
      // widen a 0600 transcript to world-readable.
      //
      // `wx` (O_EXCL) is what makes that mode binding: it creates the temp or
      // fails, so the bytes can never land in an inode someone else's mode
      // already decided, and it refuses to follow a symlink planted at the path
      // — which would otherwise send this transcript's whole contents wherever
      // the link pointed and then rename the link itself over the transcript.
      // Anything already sitting there — a directory, a leftover the sweep would
      // not touch — is doubt, and doubt leaves the transcript untouched.
      writeFileSync(tmpPath, lines.join('\n'), {
        mode: statBefore.mode & 0o777,
        flag: 'wx',
      });
      // The `mode` option passes through the process umask, which can only
      // clear bits: a 0660 transcript would be created 0640 under the usual 0022,
      // so the write alone RE-APPLIES the bits rather than preserving them. The
      // chmod is what makes it exact, and it is safe for the same reason `wx`
      // is: the exclusive create means this path is an inode this call made.
      chmodSync(tmpPath, statBefore.mode & 0o777);
      // The transcript is LIVE — Claude Code may have appended lines while the
      // scrub tokenized its in-memory snapshot. Renaming the snapshot over a
      // file that changed underneath would silently destroy those lines, so
      // ANY difference since the first stat aborts the rewrite: a lost scrub
      // is retried by the next reconcile pass, but lost transcript lines do
      // not come back.
      const statNow = statSync(realPath);
      if (statNow.size !== statBefore.size || statNow.mtimeMs !== statBefore.mtimeMs) {
        rmSync(tmpPath, { force: true, recursive: true });
        return null;
      }
      renameSync(tmpPath, realPath);
    } catch {
      try {
        // `recursive: true` also clears a tmpPath that turned out to be a
        // directory, not just a partially written file.
        rmSync(tmpPath, { force: true, recursive: true });
      } catch {
        // temp file may not exist — nothing to clean up
      }
      return null;
    }
    return { rewritten };
  } catch {
    return null;
  }
}

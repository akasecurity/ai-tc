import { createHash, randomUUID } from 'node:crypto';
import { type Dirent, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, extname, join, resolve, sep } from 'node:path';

import type { FileEgressHits, MatchResult } from '@akasecurity/detections';
import {
  dropShieldedFindings,
  EGRESS_CODE_EXTENSIONS,
  extractEgress,
  extractManifestSdks,
  isVendoredPath,
  LOCKFILE_BASENAMES,
  manifestKindOf,
  maskMatch,
  redact,
  scan,
  shieldPointers,
} from '@akasecurity/detections';
import type { FingerprintKey, LocalDatabase } from '@akasecurity/persistence';
import {
  computeFindingKey,
  defaultDataDir,
  fingerprintValue,
  loadOrCreateFingerprintKey,
} from '@akasecurity/persistence';
import {
  childRel,
  evaluateIgnore,
  type IgnoreLayer,
  readIgnoreLayer,
  toPosix,
  withLayer,
} from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  DetectedFindingWithKey,
  EventMetadata,
  IngestEvent,
  Rule,
  SourceTool,
} from '@akasecurity/schema';
import { DEFAULT_ACTIONS, isActionAtLeast, SOURCE_TOOL } from '@akasecurity/schema';

// The filesystem scan pipeline shared by `aka scan` and the web-ui's Scan page:
// walk a file or directory, run the detection engine over each text file, and
// record findings into the local store. A FINDING never carries the raw match —
// it stores the masked value, and the event stores a sha256 of the original
// file. The event's copy of the file text is rewritten only where enforcement
// reaches: a span whose resolved action is redact-or-stronger is replaced, and
// a span a Monitor/Warn pack merely logged is stored as it was read. See
// scanPathIntoStore for why that floor is where it is.
//
// Ignore files follow the same two-tier semantics as the plugin's worktree
// scanner (packages/scanner):
//   .gitignore  → MARK: gitignored files ARE still scanned — local scratch and
//                 generated config are exactly where real secrets hide — but the
//                 event records `gitignored` provenance so policy and dashboards
//                 can weigh those findings differently.
//   .akaignore  → SKIP: explicit user intent aimed at this scanner. Same
//                 gitignore syntax, hard skip — no read, no stored event, no
//                 finding. A negation (`!vendor/`) also re-includes a directory
//                 from the default SKIP_DIRS/dot-directory floor — but NOT from
//                 the protected-path list below, which no ignore file can
//                 override.

const AKAIGNORE_FILENAME = '.akaignore';

// Paths this scanner must never read, whatever it is pointed at.
//
// These are not "files that contain secrets" — finding those is the whole job.
// They are LIVE CREDENTIALS that AKA or its host wrote for itself, which the
// user did not author and which a finding cannot help them fix. Reading one
// copies it into `audit_events.content`, and at the default policy that copy
// is BYTE-FOR-BYTE: `scanPathIntoStore` only masks spans whose action reaches
// `redact`, and a pack ships on `monitor`. So scanning them is not a detection,
// it is an exfiltration into AKA's own store.
//
// TWO bases, because they move independently. `home` is the OS home the hosts
// write under; `akaHome` is AKA's own home, which `--home` relocates on its own
// (`homeBase` in cli/src/lib/args.ts returns the AKA home, not an OS home). A
// single base would leave `aka scan --home ~/work-aka ~` protecting a `~/.aka`
// that holds nothing while walking the vault key and the control-plane
// credential in the home actually in use.
//
//   <home>/.claude/ide/<port>.lock   the host writes one per attached IDE, mode
//                                    0600, carrying a live auth token
//   <home>/.claude/.credentials.json the host's own stored credential
//   <home>/.codex/auth.json          the Codex CLI's stored credential, mode 0600
//   <akaHome>                        AKA's home: the vault key, the control-plane
//                                    credential, and the store this scan writes into
//
// Both host homes are read from `homedir()` and neither honours the host's own
// relocation variable (`CODEX_HOME`, `GEMINI_HOME`). That matches the readers
// this repo already ships — the transcript adapters resolve `homedir()` too —
// and `n/no-process-env` makes reading one a deliberate, file-scoped decision
// rather than a detail. The consequence is worth stating rather than implying:
// on a machine that sets one, the host writes its credential outside the path
// this list names, and the exclusion does not reach it.
//
// Two neighbouring paths are deliberately NOT here, because neither is
// credential material a host wrote for itself:
//   ~/.gemini      Antigravity's home. What this tree names under it is the
//                  conversation store (`antigravity/brain/<conversationId>/`),
//                  which is transcript material AKA reads on purpose — excluding
//                  the home would suppress the scanning, not a leak.
//   ~/.claude.json the `claude mcp add` target. Its `mcpServers` entries are
//                  user-authored, so a secret in one is a finding the user can
//                  act on — which is the job, not an exfiltration.
//
// Absolute, CANONICAL paths (see `canonicalize`) and a PREFIX match, so a
// directory covers what is under it. Deliberately NOT overridable by an
// `.akaignore` negation — see the precedence note at the directory branch.
function protectedPaths(home: string, akaHome: string): readonly string[] {
  return [
    resolve(home, '.claude', 'ide'),
    resolve(home, '.claude', '.credentials.json'),
    resolve(home, '.codex', 'auth.json'),
    resolve(akaHome),
  ].map(canonicalize);
}

// A path's ON-DISK identity, which `resolve` alone cannot give: `resolve` is
// purely lexical, while `statSync` and every read below FOLLOW symlinks and a
// case-insensitive volume folds case. Both gaps are bypasses of a lexical
// match, and both have an ordinary shape — a `~/.claude` a dotfiles manager
// points at `~/dotfiles/claude`, or `~/.claude/IDE/54321.lock` typed on APFS —
// so both sides of the comparison come through here.
//
// `realpathSync.native` rather than `realpathSync`: only the OS call returns
// the volume's own casing. Measured on APFS, `realpathSync` hands back a typed
// `…/.claude/IDE/1.lock` unchanged where `.native` returns `…/.claude/ide/1.lock`.
//
// A path that does not exist — a protected file this machine never wrote —
// falls back to the lexical form. That is safe rather than lax, and the reason
// is what also settles the Windows question: the two forms can disagree on more
// than case there, because `.native` may answer with an extended-length
// `\\?\C:\…` prefix the lexical form never carries. A mixed pair would fail
// the prefix match — but a mixed pair cannot arise where it would matter, since
// the fallback is reached only for a path that is ABSENT, and an absent root
// has no file under it to compare and an absent target is refused by `statSync`
// first. Every comparison that can decide anything has both sides through the
// same call.
function canonicalize(path: string): string {
  try {
    return realpathSync.native(path);
  } catch {
    return resolve(path);
  }
}

// Both arguments are already canonical: the roots come from `protectedPaths`,
// and every walked path is built by `join` from a canonicalized root. Nothing
// is resolved per entry, because this runs once per dirent over a tree that can
// hold half a million of them.
function isProtected(canonical: string, roots: readonly string[]): boolean {
  return roots.some((root) => canonical === root || canonical.startsWith(root + sep));
}

const PROTECTED_TARGET_ERROR_CODE = 'AKA_PROTECTED_SCAN_TARGET';

/**
 * A scan target that resolves inside the protected set.
 *
 * Thrown rather than answered with an empty walk, because both callers render
 * an empty walk as a completed scan — the CLI prints `Scanned 0 file(s) … 0
 * finding(s)` and exits 0, the Scan page renders a successful empty result.
 * That is the false negative `visit` already refuses for an unreadable root: a
 * target the user named and this scanner did not open must say so.
 *
 * `path` is the target as the caller spelled it, not its canonical form, so the
 * message names what the user typed.
 */
export class ProtectedTargetError extends Error {
  readonly code = PROTECTED_TARGET_ERROR_CODE;
  readonly path: string;

  constructor(path: string) {
    super(`refusing to scan ${path}: it holds credentials this scanner must never read`);
    this.name = 'ProtectedTargetError';
    this.path = path;
  }
}

/**
 * Whether `err` is this module's protected-target refusal, narrowed so `path`
 * can be read. A `code` check rather than `instanceof`: every shipped artifact
 * inlines this package (`noExternal`), so a caller and this module can hold two
 * copies of the class.
 */
export function isProtectedTarget(err: unknown): err is ProtectedTargetError {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { code?: unknown }).code === PROTECTED_TARGET_ERROR_CODE
  );
}

// Directories never worth scanning (vendored / build output / VCS). Not an
// absolute invariant: an `!` negation in .akaignore re-includes one.
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  '.next',
  'coverage',
  '.turbo',
  'build',
  'out',
]);
// Skip files larger than this — they're almost never hand-authored secrets, and
// reading them as text is wasteful. (1 MB.)
const MAX_BYTES = 1_000_000;

// The layer representation, the deepest-first lookup and the walk-relative path
// arithmetic all live in `@akasecurity/plugin-sdk`'s ./ignore-layers, shared
// with the SessionStart inventory walk and the standalone scanner. This walk
// carries ONE posix path per directory (`dirRel`, relative to the scan target)
// and every layer holds an integer offset into it, in place of the
// `relative(layer.base, absPath)` path diff this used to run per layer per
// entry — which allocated, normalised separators, and could never stop early.
//
// TWO stacks descend here, not one: `.gitignore` MARKS (provenance) and
// `.akaignore` SKIPS, so each entry was paying that diff twice.

export interface CollectedFile {
  path: string;
  // Excluded by a .gitignore between the walk root and the file. Marked, not
  // skipped — see the header comment.
  gitignored: boolean;
}

export interface CollectFilesOptions {
  // The OS home the coding-agent hosts write their own credentials under.
  home?: string | undefined;
  // AKA's own home (`~/.aka` by default). A SECOND base rather than a subpath of
  // `home`, because `--home` relocates this one alone.
  akaHome?: string | undefined;
}

export function* collectFiles(
  target: string,
  // Defaults resolved here rather than per entry: the roots are canonicalized
  // ONCE and threaded down, because this walk runs over the adversarial corpus
  // and a per-entry syscall would be charged to every file. Optional so the
  // bench and the existing callers keep their one-argument form.
  opts: CollectFilesOptions = {},
): Generator<CollectedFile> {
  const protectedRoots = protectedPaths(opts.home ?? homedir(), opts.akaHome ?? defaultDataDir());
  // The target's on-disk identity, taken once. Every path below is built from
  // it by `join`, so no walked entry pays a second `realpath` — an in-walk
  // symlink cannot reintroduce an alias, because a link is neither
  // `isDirectory()` nor `isFile()` on an lstat-based `Dirent` and is skipped.
  //
  // The canonical form is used for the protected comparison ONLY. What is
  // YIELDED stays the path the caller named, because `scanPathIntoStore` feeds
  // it to `computeFindingKey` and `metadata.filePath`, which the plugin's
  // worktree scanner keys against — resolving `/var` to `/private/var` there
  // would mint a second finding_key for the same file and never reconcile.
  const canonicalTarget = canonicalize(target);
  let st;
  try {
    st = statSync(target);
  } catch {
    return;
  }
  // Before the isFile/isDirectory split, so naming one of these paths directly
  // is refused as firmly as walking into it.
  if (isProtected(canonicalTarget, protectedRoots)) throw new ProtectedTargetError(target);
  if (st.isFile()) {
    // A directly-named file is explicit user intent: scan it unconditionally,
    // no ignore-file consultation — the protected list above being the one
    // thing that outranks that intent.
    if (st.size <= MAX_BYTES) yield { path: target, gitignored: false };
    return;
  }
  if (!st.isDirectory()) return;
  yield* visit(target, canonicalTarget, '', [], [], false, protectedRoots);
}

// inIgnoredDir: git semantics — once a directory is gitignored, nothing
// beneath it can be re-included, so we stop evaluating and mark everything.
// (The skip stack needs no equivalent: a skipped directory is never entered.)
//
// `dirRel` is `dir` as a posix path relative to the scan target ('' at the
// target itself), built by appending one component per descent. It is what both
// layer stacks are addressed through, so it is threaded rather than recomputed.
function* visit(
  dir: string,
  // `dir`'s canonical twin, threaded so the protected comparison is made
  // against on-disk identity while everything yielded keeps the caller's
  // spelling. The two are the SAME STRING on an unaliased tree, which is what
  // the per-entry branch below tests for.
  dirCanonical: string,
  dirRel: string,
  markLayers: readonly IgnoreLayer[],
  skipLayers: readonly IgnoreLayer[],
  inIgnoredDir: boolean,
  protectedRoots: readonly string[],
): Generator<CollectedFile> {
  // The listing comes FIRST, before either ignore file is read. Two reasons,
  // and the second is why this is not merely tidier: `@akasecurity/scanner`'s
  // walkTree — the walker this one is aligned with — has always been in this
  // order, and every directory that turns out to be unlistable was otherwise
  // paying two `readFileSync` attempts and up to two array copies to build
  // layer stacks for entries that will never be read. That is exactly the
  // hostile shape this walk now has coverage for.
  let dirents: Dirent[];
  try {
    dirents = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    // THE ROOT IS NOT BEST-EFFORT. `dirRel` is '' only at the scan target, and
    // a target the user named and we could not read is a FAILED scan, not an
    // empty one: `statSync` succeeds on a directory with no read bit (measured:
    // mode 0000 gives `isDirectory() === true` and `readdirSync` EACCES), so
    // swallowing this yields zero files, and `scanPathIntoStore` then records
    // `scanned: 0, findings: 0` — the Scan page rendering "no findings" for a
    // folder that was never opened. A false negative on the whole target is
    // worse than the error the caller used to see, so the root rethrows.
    if (dirRel === '') throw err;
    // A SUBTREE is best-effort, matching the other two walkers: one unreadable
    // directory costs its own subtree, never the whole scan. Unwrapped, a
    // permission-denied directory, an antivirus lock, a transient EMFILE — or a
    // path past the platform's ceiling, which is how the adversarial corpus
    // finds this — aborts `collectFiles` mid-generator and takes every file
    // already walked with it.
    //
    // That subtree is dropped SILENTLY, which is the same posture
    // `@akasecurity/scanner`'s walkTree documents. Reporting it to the caller
    // is worth doing and is a change to this function's contract, so it is
    // tracked separately rather than smuggled in here.
    return;
  }

  const dirMarkLayers = withLayer(
    markLayers,
    inIgnoredDir ? undefined : readIgnoreLayer(dir, '.gitignore', dirRel.length),
  );
  const dirSkipLayers = withLayer(
    skipLayers,
    readIgnoreLayer(dir, AKAIGNORE_FILENAME, dirRel.length),
  );

  for (const entry of dirents) {
    const path = join(dir, entry.name);
    // One extra `join` only where the walk root was an alias. On every other
    // tree the two are the same reference, so this is a pointer comparison per
    // entry rather than a second path build over half a million of them.
    const canonical = dirCanonical === dir ? path : join(dirCanonical, entry.name);
    if (entry.isDirectory()) {
      // Defence in depth, not the guarantee: the FILE branch below is a prefix
      // match, so every file under a protected directory is refused whether or
      // not this line exists. What this buys is that a directory of live auth
      // tokens is never even listed.
      //
      // Placed before the ignore evaluation rather than folded into it, because
      // that condition short-circuits on an `.akaignore` negation — and that
      // file is written by whoever wrote the tree being scanned. Verified by
      // mutation: folding it in leaves the suite green (the file branch still
      // covers it), so the placement is a reasoned choice rather than something
      // a test pins.
      if (isProtected(canonical, protectedRoots)) continue;
      const skipState = evaluateIgnore(dirSkipLayers, dirRel, entry.name, true);
      // Precedence: an explicit .akaignore re-include beats the default floor
      // (SKIP_DIRS + dot-directories); otherwise the floor and .akaignore
      // matches both hard-skip.
      if (
        skipState !== 'unignored' &&
        (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.') || skipState === 'ignored')
      ) {
        continue;
      }
      const dirIgnored =
        inIgnoredDir || evaluateIgnore(dirMarkLayers, dirRel, entry.name, true) === 'ignored';
      yield* visit(
        path,
        canonical,
        childRel(dirRel, entry.name),
        dirMarkLayers,
        dirSkipLayers,
        dirIgnored,
        protectedRoots,
      );
    } else if (entry.isFile()) {
      // THE guarantee for a walked tree: a prefix match, so it covers a
      // protected file named directly and everything under a protected
      // directory, whatever the ignore files say. Before the stat, so an
      // excluded file costs nothing.
      if (isProtected(canonical, protectedRoots)) continue;
      // .akaignore skip — before stat/read, so an excluded file costs nothing.
      if (evaluateIgnore(dirSkipLayers, dirRel, entry.name, false) === 'ignored') continue;
      // Apply the MAX_BYTES cap here too: without it, directory traversal reads
      // arbitrarily large files fully into memory (the isFile() branch above only
      // guards a directly-named target).
      let size: number;
      try {
        size = statSync(path).size;
      } catch {
        continue; // unreadable — skip
      }
      if (size > MAX_BYTES) continue;
      yield {
        path,
        gitignored:
          inIgnoredDir || evaluateIgnore(dirMarkLayers, dirRel, entry.name, false) === 'ignored',
      };
    }
  }
}

export interface ScanPathOptions {
  // The ruleset to evaluate, run IN-PROCESS and therefore without an upper
  // bound — so this is for a ruleset that already has one behind it: the
  // compiled-in packs, which the CI adversarial battery measures on every
  // commit. Omitted, the engine's process-global registry is used (the CLI,
  // after registerBundledPacks()).
  //
  // A ruleset that carries pulled or custom packs must arrive through
  // `scanText` instead — see createGuardedFileScanner. A regex from an
  // unreviewed pack has no upper bound at all, and `scan()` cannot be
  // interrupted mid-`exec` by anything on this thread.
  rules?: Rule[] | undefined;
  // Runs the detection engine over one file's text under a hard wall-clock
  // bound, on a thread that can be killed. Supplied by a caller whose ruleset
  // includes pulled/custom packs — the dashboard's folder scan. Takes
  // precedence over `rules`, which the guarded scanner already holds.
  scanText?: ((text: string) => Promise<MatchResult[]>) | undefined;
  // Per-rule enforcement action from the installed snapshot (installedRuleset().
  // ruleActions), so at-rest findings carry the SAME per-pack Monitor/Warn/Redact/
  // Block decision the live capture path resolves — not the per-category default.
  // A rule absent from the map (or no map) falls back to DEFAULT_ACTIONS[category].
  //
  // It decides more than the stamped `actionTaken`: the same resolution picks
  // which spans are masked in the stored file text, so a map that resolves every
  // rule below `redact` leaves the event content byte-identical to the file.
  ruleActions?: ReadonlyMap<string, ActionTaken> | undefined;
  sourceTool?: SourceTool | undefined;
  // The ~/.aka/data directory (the same one passed to openLocalDatabase) —
  // where the exception fingerprint key lives. Lets an at-rest finding's
  // finding_key use the SAME keyed-HMAC value fingerprint the plugin's live
  // capture path uses (see createPluginRuntime's keyForLedger), so a file
  // scanned by both `aka scan`/the web-ui AND the plugin reconciles onto one
  // row. Omitted (or an unreadable/corrupt key file) falls back to the masked
  // match — a finding_key is still produced, just keyed on a weaker identity.
  dataDir?: string | undefined;
  // AKA's own home — the BASE of the layout, `~/.aka` by default, of which
  // `dataDir` above is the `data/` subdirectory. It is what the protected-path
  // exclusion refuses to read, and it is passed separately rather than derived
  // from `dataDir` because a caller may point the store somewhere the layout
  // helpers did not build. `--home` moves it (`homeBase`), so the CLI passes its
  // own; a caller on the default home may omit it.
  akaHome?: string | undefined;
}

// Per-file detail for machine consumers (`aka scan --format json`, CI gates).
// Only files WITH findings appear; the findings are the store-safe shape —
// masked match + span, never the raw secret.
export interface ScannedFileFindings {
  path: string;
  gitignored: boolean;
  findings: DetectedFindingWithKey[];
}

export interface ScanPathResult {
  scanned: number;
  findings: number;
  files: ScannedFileFindings[];
  // Raw per-file egress extraction for every walked file that produced a hit.
  // `file` is the ABSOLUTE walked path here; the recording pass relativizes it
  // to the project root before anything reaches the store.
  egress: { files: FileEgressHits[] };
}

// What the egress pass extracts from one already-read file, or null when the
// file is out of scope. URL/IP extraction runs on code extensions only;
// manifests go through manifestKindOf, which returns null for lockfiles so
// their registry URLs are never extracted; a file carrying a NUL byte is
// treated as binary and yields nothing.
function extractFileEgress(file: string, text: string): FileEgressHits | null {
  if (text.includes('\u0000')) return null;

  const name = basename(file);
  // Lockfiles are regenerated dependency-resolution output — every transitive
  // package's registry URL is packaging noise, not egress. manifestKindOf
  // already returns null for these basenames, and none of them currently
  // carry a code extension, so this early-out changes nothing observable
  // today; it exists so the exclusion still holds if a future lockfile
  // basename ever does carry one, instead of relying on that gap staying
  // empty by chance.
  if (LOCKFILE_BASENAMES.has(name)) return null;

  const kind = manifestKindOf(name);
  const sdkHits = kind === null ? [] : extractManifestSdks(text, kind);
  // A manifest is never also scanned for URL literals: package.json's own
  // registry/repository URLs are packaging metadata, not egress.
  const endpoints =
    kind === null && EGRESS_CODE_EXTENSIONS.has(extname(file)) ? extractEgress(text) : [];

  if (endpoints.length === 0 && sdkHits.length === 0) return null;
  // isVendoredPath matches forward-slash segments, so the walked path is
  // normalized before the test. `file` is absolute here, so the match also sees
  // segments above the scan root; the recording pass recomputes the flag from
  // the project-relative key it stores.
  return { file, vendored: isVendoredPath(toPosix(file)), endpoints, sdkHits };
}

/**
 * Walk `target` and record one event + masked findings per file with matches.
 * The event's copy of the file is redacted where enforcement reaches — see the
 * at-rest floor below. The caller owns the database handle (and closes it).
 *
 * Async because a bounded scan has to be: the only thing that can interrupt a
 * regex that never returns is another thread, and reaching one is a message
 * round trip. A caller running the compiled-in packs passes no `scanText` and
 * pays nothing for that — the default matcher resolves without ever yielding.
 */
export async function scanPathIntoStore(
  db: LocalDatabase,
  target: string,
  opts: ScanPathOptions = {},
): Promise<ScanPathResult> {
  const matchText = opts.scanText ?? ((text: string) => Promise.resolve(scan(text, opts.rules)));
  let scanned = 0;
  let findingCount = 0;
  const files: ScannedFileFindings[] = [];
  const egressFiles: FileEgressHits[] = [];

  // Resolved (and possibly minted) at most once per scan call, mirroring
  // createPluginRuntime's keyForLedger(): the first finding is the moment a
  // stable value fingerprint becomes relevant, so a clean scan never touches
  // the key file. Fails open — a missing dataDir or a corrupt/unreadable key
  // file leaves the key unavailable (undefined = not tried yet, null =
  // unavailable) rather than aborting the scan; computeFindingKey still gets
  // called below, just with the masked-match fallback.
  let fingerprintKey: FingerprintKey | null | undefined;
  function resolveFingerprintKey(): FingerprintKey | null {
    if (fingerprintKey === undefined) {
      try {
        fingerprintKey = opts.dataDir ? loadOrCreateFingerprintKey(opts.dataDir) : null;
      } catch {
        fingerprintKey = null;
      }
    }
    return fingerprintKey;
  }

  // Absolutize the walk root before any path reaches computeFindingKey /
  // metadata.filePath. `aka scan` / `aka scan .` default `target` to a RELATIVE
  // path, but the plugin's worktree scanner keys on ABSOLUTE paths and
  // computeFindingKey only normalizes backslashes — so a relative target would
  // mint a different finding_key for the same file+secret and never reconcile
  // (ON CONFLICT (finding_key)) across the two tools. resolve() is relative to
  // process.cwd() — the same base the callers' statSync(target) already uses —
  // and is a no-op on the already-absolute paths the web-ui folder picker passes.
  for (const { path: file, gitignored } of collectFiles(resolve(target), {
    akaHome: opts.akaHome,
  })) {
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      continue; // unreadable / binary — skip
    }
    scanned++;
    // Egress rides every file whose content was read, before the finding
    // early-out below — a file with no detection match still has destinations.
    const fileEgress = extractFileEgress(file, text);
    if (fileEgress) egressFiles.push(fileEgress);

    // Files legitimately contain vault pointers (the plugin's Write/Edit hook
    // puts them there), and a pointer's base32 body is exactly what a generic
    // entropy rule matches. Shield pointer spans BEFORE the engine runs — the
    // same-length filler keeps every other span's offsets valid against the
    // original text, so redaction and stored spans below still line up — and
    // drop any finding that touches a shielded span.
    const shielded = shieldPointers(text);
    const matches = dropShieldedFindings(await matchText(shielded.text), shielded.spans);
    if (matches.length === 0) continue;

    // Per-pack action (monitor-by-default) when the installed snapshot supplies
    // one, else the per-category fallback — mirrors the live path's resolveAction.
    // Resolved ONCE per match here because two things read it: the stamped
    // actionTaken below, and the at-rest masking immediately after.
    const resolved = matches.map((match) => ({
      match,
      action: opts.ruleActions?.get(match.ruleId) ?? DEFAULT_ACTIONS[match.category],
    }));
    // At-rest masking is an ENFORCEMENT effect, not hygiene. A pack assigned
    // Monitor or Warn may log a match and do nothing else to the value, so only
    // a finding whose resolved action is redact-or-stronger has its span
    // rewritten in the stored copy. The live capture path applies the same
    // floor and writes this same column; a folder scan masking what a live
    // session leaves intact would give one store two different at-rest rules
    // and make the dashboard's two views of a file disagree.
    const enforced = resolved.filter(({ action }) => isActionAtLeast(action, 'redact'));

    const eventId = randomUUID();
    const metadata: EventMetadata = { filePath: file };
    // Provenance is presence-only: omitted (not false) for tracked files.
    if (gitignored) metadata.gitignored = true;
    const event: IngestEvent = {
      id: eventId,
      sourceTool: opts.sourceTool ?? SOURCE_TOOL.Cli,
      kind: 'code_change',
      occurredAt: new Date().toISOString(),
      contentHash: createHash('sha256').update(text).digest('hex'),
      // Only the enforced spans. `redact` folds overlapping findings into one
      // disjoint region, so narrowing its input narrows those regions too —
      // which is the intended reading rather than a hazard: an enforced span is
      // still covered end to end, because a region always spans at least the
      // finding that opened it. What goes away is the coverage a log-only
      // neighbour used to contribute to a merged region, and that coverage was
      // never enforcement the user asked for.
      content: redact(
        text,
        enforced.map(({ match }) => match),
      ),
      metadata,
    };
    const findings: DetectedFindingWithKey[] = resolved.map(({ match: m, action }) => {
      const maskedMatch = maskMatch(m.rawMatch);
      const key = resolveFingerprintKey();
      // The SAME keyed HMAC fingerprint used for detection exceptions /
      // blocked_detections when a fingerprint key is available; falls back to
      // the masked match when it is not (no dataDir, or a corrupt key file) —
      // mirrors createPluginRuntime's capture(), so the two callers derive
      // byte-identical finding_keys for the same (ruleId, filePath, value).
      const valueFingerprint = key ? fingerprintValue(key, m.rawMatch) : maskedMatch;
      return {
        id: randomUUID(),
        eventId,
        ruleId: m.ruleId,
        category: m.category,
        severity: m.severity,
        span: m.span,
        maskedMatch,
        actionTaken: action,
        confidence: m.confidence,
        // Every fs-scan finding is at-rest (kind: 'code_change' with a
        // filePath), unlike the plugin's in-flight captures, so — unlike
        // runtime.ts's isAtRest branch — a finding_key is unconditional here.
        findingKey: computeFindingKey({ ruleId: m.ruleId, filePath: file, valueFingerprint }),
      };
    });
    db.recordCapture(event, findings);
    files.push({ path: file, gitignored, findings });
    findingCount += findings.length;
  }
  return { scanned, findings: findingCount, files, egress: { files: egressFiles } };
}

import { createHash, randomUUID } from 'node:crypto';
import { type Dirent, readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, extname, join, resolve } from 'node:path';

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
import { DEFAULT_ACTIONS } from '@akasecurity/schema';

// The filesystem scan pipeline shared by `aka scan` and the web-ui's Scan page:
// walk a file or directory, run the detection engine over each text file, and
// record findings into the local store. The raw match never lands on disk —
// the event keeps a REDACTED copy of the file and findings store only the
// masked value + a sha256 content hash.
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
//                 from the default SKIP_DIRS/dot-directory floor.

const AKAIGNORE_FILENAME = '.akaignore';

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

export function* collectFiles(target: string): Generator<CollectedFile> {
  let st;
  try {
    st = statSync(target);
  } catch {
    return;
  }
  if (st.isFile()) {
    // A directly-named file is explicit user intent: scan it unconditionally,
    // no ignore-file consultation.
    if (st.size <= MAX_BYTES) yield { path: target, gitignored: false };
    return;
  }
  if (!st.isDirectory()) return;
  yield* visit(target, '', [], [], false);
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
  dirRel: string,
  markLayers: readonly IgnoreLayer[],
  skipLayers: readonly IgnoreLayer[],
  inIgnoredDir: boolean,
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
    if (entry.isDirectory()) {
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
      yield* visit(path, childRel(dirRel, entry.name), dirMarkLayers, dirSkipLayers, dirIgnored);
    } else if (entry.isFile()) {
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
 * Walk `target` and record one redacted event + masked findings per file with
 * matches. The caller owns the database handle (and closes it).
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
  for (const { path: file, gitignored } of collectFiles(resolve(target))) {
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

    const eventId = randomUUID();
    const metadata: EventMetadata = { filePath: file };
    // Provenance is presence-only: omitted (not false) for tracked files.
    if (gitignored) metadata.gitignored = true;
    const event: IngestEvent = {
      id: eventId,
      sourceTool: opts.sourceTool ?? 'cli',
      kind: 'code_change',
      occurredAt: new Date().toISOString(),
      contentHash: createHash('sha256').update(text).digest('hex'),
      content: redact(text, matches), // store the REDACTED file, never the raw secret
      metadata,
    };
    const findings: DetectedFindingWithKey[] = matches.map((m) => {
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
        // Per-pack action (monitor-by-default) when the installed snapshot supplies
        // one, else the per-category fallback — mirrors the live path's resolveAction.
        actionTaken: opts.ruleActions?.get(m.ruleId) ?? DEFAULT_ACTIONS[m.category],
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

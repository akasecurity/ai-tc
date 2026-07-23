import { createHash, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, extname, join, relative } from 'node:path';

import type { FileEgressHits } from '@akasecurity/detections';
import {
  EGRESS_CODE_EXTENSIONS,
  extractEgress,
  extractManifestSdks,
  isVendoredPath,
  LOCKFILE_BASENAMES,
  manifestKindOf,
  maskMatch,
  redact,
  scan,
} from '@akasecurity/detections';
import type { FingerprintKey, LocalDatabase } from '@akasecurity/persistence';
import { fingerprintValue, loadOrCreateFingerprintKey } from '@akasecurity/persistence';
import { computeFindingKey, toPosix } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  DetectedFindingWithKey,
  EventMetadata,
  IngestEvent,
  Rule,
  SourceTool,
} from '@akasecurity/schema';
import { DEFAULT_ACTIONS } from '@akasecurity/schema';
import ignore, { type Ignore } from 'ignore';

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

// One ignore file's rules, anchored to the directory that contains it (git
// patterns are relative to their own ignore file, not the repo root).
interface IgnoreLayer {
  base: string;
  matcher: Ignore;
}

// Read a directory's ignore file into a matcher layer. Fail-open: an
// unreadable or malformed file yields no layer — we scan MORE on error,
// never less.
function readIgnoreLayer(dir: string, filename: string): IgnoreLayer | undefined {
  try {
    const content = readFileSync(join(dir, filename), 'utf8');
    return { base: dir, matcher: ignore().add(content) };
  } catch {
    return undefined;
  }
}

type IgnoreState = 'ignored' | 'unignored' | 'unmatched';

// Evaluate the layered ignore state for a path, mirroring git's semantics:
// deeper ignore files are consulted later, so their verdicts (ignore OR
// re-include via `!`) override shallower ones. 'unignored' is distinct from
// 'unmatched' because an explicit `!` re-include also overrides the default
// directory-skip floor. Directories are tested with a trailing slash so
// `dir/`-style patterns match.
function evaluate(layers: IgnoreLayer[], absPath: string, isDir: boolean): IgnoreState {
  let state: IgnoreState = 'unmatched';
  for (const layer of layers) {
    // The ignore package expects posix-style relative paths.
    const rel = toPosix(relative(layer.base, absPath)) + (isDir ? '/' : '');
    const verdict = layer.matcher.test(rel);
    if (verdict.ignored) state = 'ignored';
    else if (verdict.unignored) state = 'unignored';
  }
  return state;
}

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
  yield* visit(target, [], [], false);
}

// inIgnoredDir: git semantics — once a directory is gitignored, nothing
// beneath it can be re-included, so we stop evaluating and mark everything.
// (The skip stack needs no equivalent: a skipped directory is never entered.)
function* visit(
  dir: string,
  markLayers: IgnoreLayer[],
  skipLayers: IgnoreLayer[],
  inIgnoredDir: boolean,
): Generator<CollectedFile> {
  const markLayer = inIgnoredDir ? undefined : readIgnoreLayer(dir, '.gitignore');
  const dirMarkLayers = markLayer ? [...markLayers, markLayer] : markLayers;
  const skipLayer = readIgnoreLayer(dir, AKAIGNORE_FILENAME);
  const dirSkipLayers = skipLayer ? [...skipLayers, skipLayer] : skipLayers;

  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      const skipState = evaluate(dirSkipLayers, path, true);
      // Precedence: an explicit .akaignore re-include beats the default floor
      // (SKIP_DIRS + dot-directories); otherwise the floor and .akaignore
      // matches both hard-skip.
      if (
        skipState !== 'unignored' &&
        (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.') || skipState === 'ignored')
      ) {
        continue;
      }
      const dirIgnored = inIgnoredDir || evaluate(dirMarkLayers, path, true) === 'ignored';
      yield* visit(path, dirMarkLayers, dirSkipLayers, dirIgnored);
    } else if (entry.isFile()) {
      // .akaignore skip — before stat/read, so an excluded file costs nothing.
      if (evaluate(dirSkipLayers, path, false) === 'ignored') continue;
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
        gitignored: inIgnoredDir || evaluate(dirMarkLayers, path, false) === 'ignored',
      };
    }
  }
}

export interface ScanPathOptions {
  // The ruleset to evaluate. The web-ui MUST pass this explicitly (the enabled
  // rules from the installed_packs DB snapshot — the scan authority); when
  // omitted, the engine's process-global registry is used (the CLI, after
  // registerBundledPacks()).
  rules?: Rule[] | undefined;
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
 */
export function scanPathIntoStore(
  db: LocalDatabase,
  target: string,
  opts: ScanPathOptions = {},
): ScanPathResult {
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

  for (const { path: file, gitignored } of collectFiles(target)) {
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

    const matches = scan(text, opts.rules);
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

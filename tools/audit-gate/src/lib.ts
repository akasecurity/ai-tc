// Pure logic for the dependency-audit CI gate: waiver validation, audit
// payload parsing (pnpm's v1 format and npm's v2 format), advisory
// classification, and Markdown report generation. The CLI entry
// (audit-dependencies.ts) owns the process spawning; everything here is
// side-effect-free so the unit suite can drive it with canned payloads.
//
// One exception, and it is deliberate: `readPnpmConfigSources` reads two files.
// It sits here rather than in the entry because the mute it detects is invisible
// in pnpm's OUTPUT — the whole defect was a guard that read the payload — so the
// reader that replaced it must itself be driven against real files rather than
// left in the one module nothing tests.
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

// The gate runs in one of two modes — `pnpm audit` over the workspace
// lockfile, or `npm audit` over an end-user resolution of the published CLI's
// runtime dependencies — and every waiver names the mode it applies to.
export const AUDIT_MODES = ['workspace', 'artifact'] as const;
export type AuditMode = (typeof AUDIT_MODES)[number];

export interface AuditAdvisory {
  id?: number;
  github_advisory_id?: string;
  cves?: string[];
  module_name?: string;
  severity?: string;
  title?: string;
  url?: string;
  findings?: { version?: string; paths?: string[] }[];
}

export interface AuditPayload {
  advisories: Record<string, AuditAdvisory>;
  muted?: unknown[];
  metadata?: { vulnerabilities?: Record<string, number> };
}

export interface Waiver {
  advisory: string;
  scope: AuditMode;
  reason: string;
  expires: string;
  module?: string;
  class?: string;
}

export interface WaivedAdvisory {
  advisory: AuditAdvisory;
  waiver: Waiver;
}

export interface StaleWaiver {
  waiver: Waiver;
  why: string;
}

export interface Classification {
  blocking: AuditAdvisory[];
  waived: WaivedAdvisory[];
  nonBlocking: AuditAdvisory[];
  stale: StaleWaiver[];
}

// A deterministic configuration problem (malformed waiver file, pnpm-native
// mutes). Distinct from transient audit failures so the CLI can exit 3 rather
// than 2 and callers never retry it.
export class WaiverConfigError extends Error {}

export const BLOCKING_SEVERITIES = new Set(['high', 'critical']);

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export function validateWaivers(raw: unknown): Waiver[] {
  if (
    raw === null ||
    typeof raw !== 'object' ||
    !Array.isArray((raw as { waivers?: unknown }).waivers)
  ) {
    throw new WaiverConfigError('audit-waivers.json must be an object with a "waivers" array');
  }
  const waivers = (raw as { waivers: unknown[] }).waivers;
  for (const entry of waivers) {
    if (entry === null || typeof entry !== 'object') {
      throw new WaiverConfigError('every waiver must be an object');
    }
    const waiver = entry as Partial<Waiver>;
    if (typeof waiver.advisory !== 'string' || waiver.advisory.trim() === '') {
      throw new WaiverConfigError('every waiver needs an "advisory" (a GHSA or CVE id)');
    }
    if (waiver.scope !== 'workspace' && waiver.scope !== 'artifact') {
      throw new WaiverConfigError(
        `waiver ${waiver.advisory} needs a "scope" ("workspace" or "artifact")`,
      );
    }
    if (typeof waiver.reason !== 'string' || waiver.reason.trim() === '') {
      throw new WaiverConfigError(`waiver ${waiver.advisory} needs a non-empty "reason"`);
    }
    if (
      typeof waiver.expires !== 'string' ||
      !ISO_DATE.test(waiver.expires) ||
      Number.isNaN(Date.parse(waiver.expires))
    ) {
      throw new WaiverConfigError(`waiver ${waiver.advisory} needs an "expires" date (YYYY-MM-DD)`);
    }
    if (
      waiver.module !== undefined &&
      (typeof waiver.module !== 'string' || waiver.module.trim() === '')
    ) {
      throw new WaiverConfigError(
        `waiver ${waiver.advisory}: "module" must be a non-empty package name`,
      );
    }
    if (waiver.class !== undefined && typeof waiver.class !== 'string') {
      throw new WaiverConfigError(`waiver ${waiver.advisory}: "class" must be a string`);
    }
  }
  return waivers as Waiver[];
}

// `pnpm audit` exits non-zero whenever it finds vulnerabilities, and it also
// reports transport failures as parseable JSON on stdout ({"error": {...}}) —
// so neither the exit status nor JSON.parse succeeding identifies a completed
// audit. A completed audit is JSON that carries an "advisories" object and no
// top-level "error"; anything else throws.
export function parseAuditPayload(stdout: string, stderr = ''): AuditPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    const detail = (stderr || stdout || '').trim().slice(0, 400);
    throw new Error(`pnpm audit did not return JSON (registry unreachable?): ${detail}`);
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    'error' in parsed ||
    !('advisories' in parsed)
  ) {
    const transport = (parsed as { error?: { code?: string; message?: string } } | null)?.error;
    const detail = transport
      ? `${transport.code ?? ''} ${transport.message ?? ''}`.trim()
      : 'output has no "advisories" field';
    throw new Error(`pnpm audit did not complete: ${detail.slice(0, 400)}`);
  }
  return parsed as AuditPayload;
}

// npm emits the v2 audit format instead: a "vulnerabilities" map keyed by
// package name, each entry's "via" mixing advisory objects with plain
// package-name strings (transitive links). Only the objects are advisories;
// they carry no CVE list, so an artifact-scoped waiver must use the GHSA id.
export interface NpmAuditVia {
  source?: number;
  name?: string;
  title?: string;
  url?: string;
  severity?: string;
  range?: string;
}

export interface NpmAuditEntry {
  name?: string;
  severity?: string;
  via?: (NpmAuditVia | string)[];
  nodes?: string[];
}

export interface NpmAuditPayload {
  vulnerabilities: Record<string, NpmAuditEntry>;
  metadata?: { vulnerabilities?: Record<string, number> };
}

// The same completed-audit test as parseAuditPayload, for npm's v2 output:
// JSON that carries a "vulnerabilities" object and no top-level "error".
export function parseNpmAuditPayload(stdout: string, stderr = ''): NpmAuditPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    const detail = (stderr || stdout || '').trim().slice(0, 400);
    throw new Error(`npm audit did not return JSON (registry unreachable?): ${detail}`);
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    'error' in parsed ||
    !('vulnerabilities' in parsed)
  ) {
    const transport = (parsed as { error?: { code?: string; summary?: string } } | null)?.error;
    const detail = transport
      ? `${transport.code ?? ''} ${transport.summary ?? ''}`.trim()
      : 'output has no "vulnerabilities" field';
    throw new Error(`npm audit did not complete: ${detail.slice(0, 400)}`);
  }
  return parsed as NpmAuditPayload;
}

const GHSA_URL = /\/advisories\/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i;

// Reduces an npm v2 payload to the AuditPayload shape pnpm produces, so
// classification and reporting are shared across both modes. Each advisory
// object becomes one entry keyed by advisory id and package, and the entry's
// resolved node paths stand in for pnpm's dependency paths. npm's counts
// carry a "total" the pnpm format does not; it is dropped so the report's
// totals line reads the same in both modes.
export function normalizeNpmAudit(payload: NpmAuditPayload): AuditPayload {
  const advisories: Record<string, AuditAdvisory> = {};
  for (const entry of Object.values(payload.vulnerabilities)) {
    for (const via of entry.via ?? []) {
      if (typeof via !== 'object') continue;
      const ghsa = GHSA_URL.exec(via.url ?? '')?.[1];
      const module = via.name ?? entry.name;
      const key = `${ghsa ?? String(via.source ?? '')}:${module ?? ''}`;
      const normalized: AuditAdvisory = { cves: [], findings: [{ paths: entry.nodes ?? [] }] };
      if (via.source !== undefined) normalized.id = via.source;
      if (ghsa !== undefined) normalized.github_advisory_id = ghsa;
      if (module !== undefined) normalized.module_name = module;
      if (via.severity !== undefined) normalized.severity = via.severity;
      if (via.title !== undefined) normalized.title = via.title;
      if (via.url !== undefined) normalized.url = via.url;
      advisories[key] ??= normalized;
    }
  }
  const counts = { ...(payload.metadata?.vulnerabilities ?? {}) };
  delete counts.total;
  return { advisories, metadata: { vulnerabilities: counts } };
}

// pnpm's own suppression channel (`auditConfig.ignoreCves`/`ignoreGhsas`) drops
// an advisory with no expiry, no reason and no report row. The gate refuses to
// run while it is configured, so audit-waivers.json stays the only suppression
// route.
//
// The payload cannot reveal it. pnpm 10 does carry a top-level `muted` array,
// but a muted advisory is filtered out of `advisories` and `muted` stays EMPTY
// — and the severity counts in `metadata` are decremented to match, so nothing
// in the output is inconsistent with a clean tree. The setting is therefore
// read from the files pnpm takes it from, not inferred from what pnpm returns.
export function assertNothingMuted(payload: AuditPayload): void {
  const muted = payload.muted ?? [];
  if (muted.length > 0) {
    throw new WaiverConfigError(
      `pnpm auditConfig mutes ${String(muted.length)} advisor${muted.length === 1 ? 'y' : 'ies'}; ` +
        'muted advisories carry no expiry or review trail — use .github/audit-waivers.json instead',
    );
  }
}

// The two files pnpm reads `auditConfig` from. `.npmrc` is not one of them —
// neither the flattened nor the camelCase spelling has any effect there — so
// these two are the whole surface. Each is optional: a caller passes undefined
// for a file that does not exist, which `exactOptionalPropertyTypes` makes a
// distinct thing from omitting the property — so both spellings are allowed.
export interface AuditConfigSources {
  manifest?: string | undefined;
  workspaceYaml?: string | undefined;
}

// A top-level `auditConfig:` mapping key, quoted or not. Anchored with no
// leading whitespace on purpose: a nested key of the same name belongs to
// something else and is not pnpm's setting.
const WORKSPACE_AUDIT_CONFIG = /^["']?auditConfig["']?\s*:/m;

// Names every place `auditConfig` is configured, so the refusal can point at
// the file to edit. **Presence of the key is enough, in both channels** — the
// gate never needs to know which advisories are named, so the key names are
// never enumerated and one added by a later pnpm is caught for free. An
// `auditConfig` that is present but empty suppresses nothing, and is refused
// anyway: it is a stub with no other purpose, and the two channels cannot
// answer differently without the rule becoming one nobody can state. The YAML
// half could not tell empty from non-empty without a parser regardless.
export function findAuditConfigMutes(sources: AuditConfigSources): string[] {
  const found: string[] = [];

  if (sources.manifest !== undefined) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(sources.manifest);
    } catch {
      throw new WaiverConfigError(
        'package.json is not valid JSON, so its pnpm config is unreadable',
      );
    }
    const auditConfig = (parsed as { pnpm?: { auditConfig?: unknown } } | null)?.pnpm?.auditConfig;
    if (auditConfig !== null && typeof auditConfig === 'object') {
      const keys = Object.keys(auditConfig).sort();
      // An empty object has no keys to name, so the suffix is dropped rather
      // than rendering as an empty pair of parentheses.
      const detail = keys.length > 0 ? ` (${keys.join(', ')})` : '';
      found.push(`package.json "pnpm.auditConfig"${detail}`);
    }
  }

  if (sources.workspaceYaml !== undefined && WORKSPACE_AUDIT_CONFIG.test(sources.workspaceYaml)) {
    found.push('pnpm-workspace.yaml "auditConfig"');
  }

  return found;
}

/**
 * Read the two files pnpm takes `auditConfig` from, off disk.
 *
 * Absent is not an error: only a file that exists is inspected, so a checkout
 * without a workspace manifest simply contributes nothing to look at. Absent
 * means **ENOENT and nothing else** — a file that exists but cannot be read is
 * refused rather than reported as "no config here", which is how the JSON parse
 * failure in `findAuditConfigMutes` already behaves. Reading a mute as absence
 * is the one outcome this check exists to prevent, so it must not be reachable
 * through a failed read either.
 *
 * It lives here rather than in the CLI entry so the suite can drive it against
 * REAL FILES — a real manifest carrying a real mute, a real ENOENT, and a real
 * unreadable file. The canned-payload-only test is what let the original defect
 * ship, so the fix's own reader is not left in the one file nothing drives.
 */
export function readIfPresent(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw new WaiverConfigError(
      `${basename(path)} exists but could not be read (${error instanceof Error ? error.message : String(error)}), so its contents are unknown`,
    );
  }
}

export function readPnpmConfigSources(
  manifestPath: string,
  workspaceYamlPath: string,
): AuditConfigSources {
  const manifest = readIfPresent(manifestPath);
  const workspaceYaml = readIfPresent(workspaceYamlPath);
  // Built by omission rather than by assigning `undefined`: the workspace runs
  // `exactOptionalPropertyTypes`, under which an explicit undefined is not an
  // absent property.
  const sources: AuditConfigSources = {};
  if (manifest !== undefined) sources.manifest = manifest;
  if (workspaceYaml !== undefined) sources.workspaceYaml = workspaceYaml;
  return sources;
}

export function assertNoAuditConfigMutes(sources: AuditConfigSources): void {
  const found = findAuditConfigMutes(sources);
  if (found.length > 0) {
    throw new WaiverConfigError(
      `pnpm auditConfig is set in ${found.join(' and ')}; it suppresses advisories with no expiry, ` +
        'no reason and no report row — remove it and use .github/audit-waivers.json instead',
    );
  }
}

// Waivers apply per audit: a run selects only the waivers scoped to it, so
// classify() never sees — and never marks stale — the other audit's waivers.
export function waiversFor(mode: AuditMode, waivers: Waiver[]): Waiver[] {
  return waivers.filter((waiver) => waiver.scope === mode);
}

export function waiverMatches(waiver: Waiver, advisory: AuditAdvisory): boolean {
  const id = waiver.advisory.toUpperCase();
  const idHit =
    id === (advisory.github_advisory_id ?? '').toUpperCase() ||
    (advisory.cves ?? []).some((cve) => cve.toUpperCase() === id);
  if (!idHit) return false;
  if (waiver.module !== undefined && waiver.module !== advisory.module_name) return false;
  return true;
}

export function classify(payload: AuditPayload, waivers: Waiver[], today: string): Classification {
  // `expires` is inclusive and compared in UTC: a waiver dated 2026-08-26
  // still suppresses on the 26th (UTC) and lapses at 2026-08-27T00:00Z.
  // Lexicographic comparison is correct for YYYY-MM-DD strings.
  const isActive = (waiver: Waiver): boolean => waiver.expires >= today;
  const advisories = Object.values(payload.advisories);

  const blocking: AuditAdvisory[] = [];
  const waived: WaivedAdvisory[] = [];
  const nonBlocking: AuditAdvisory[] = [];
  for (const advisory of advisories) {
    if (!BLOCKING_SEVERITIES.has(advisory.severity ?? '')) {
      nonBlocking.push(advisory);
      continue;
    }
    const waiver = waivers.find((w) => isActive(w) && waiverMatches(w, advisory));
    if (waiver) waived.push({ advisory, waiver });
    else blocking.push(advisory);
  }

  const stale: StaleWaiver[] = waivers.flatMap((waiver) => {
    if (!isActive(waiver)) return [{ waiver, why: `expired ${waiver.expires}` }];
    if (!advisories.some((advisory) => waiverMatches(waiver, advisory))) {
      return [{ waiver, why: 'matches no current advisory — likely fixed' }];
    }
    return [];
  });

  return { blocking, waived, nonBlocking, stale };
}

// The escaped text lands in Markdown table cells as plain text (never inside
// code spans, where backslash escapes do not apply), so escaping `|`, backticks
// and newlines is sufficient. Values come from the registry, not this repo.
export const mdEscape = (text: string | number | null | undefined): string =>
  String(text ?? '')
    .replaceAll('|', '\\|')
    .replaceAll('`', '\\`')
    .replaceAll('\n', ' ');

/**
 * The id an advisory is REPORTED under. A GHSA id where the registry supplies
 * one, and the numeric registry id otherwise — an advisory carrying neither is
 * the empty string, which no caller may treat as an identity.
 *
 * One function because the fallback used to be spelled inline at each of the
 * three sites that need it, and the daily report's new-vs-seen dedup — the
 * fourth — matched only the GHSA half. An advisory with no GHSA id therefore
 * rendered into the report perfectly and matched nothing, so nothing was ever
 * posted about it onto the tracking issue.
 */
export const advisoryId = (advisory: AuditAdvisory): string =>
  advisory.github_advisory_id ?? String(advisory.id ?? '');

/**
 * Every advisory id a rendered report carries, sorted and deduped.
 *
 * Reads the report's own markdown rather than an audit payload, because the
 * other side of the comparison is an ISSUE BODY — the same markdown, posted by
 * a previous run, with no payload behind it any more. One reader for both is
 * what keeps "an id we have already reported" answerable at all.
 *
 * The anchor is the advisory column's link, `[<id>](<url>)`, which is the only
 * bracket-paren pair `buildReport` emits. Matching a bare `GHSA-…` anywhere in
 * the text was the earlier form and is wrong in the other direction too: prose
 * on the issue naming an advisory would count as having reported it.
 *
 * Anchored to a TABLE CELL rather than to the link alone, because only one side
 * of the comparison is text this module wrote. The other is the tracking
 * issue's body and comments — arbitrary human markdown — where an ordinary
 * numbered link like `see [2](https://…/notes)` would otherwise put `2` into
 * the seen set and silence a later advisory carrying that registry id. Both row
 * shapes `buildReport` emits surround the link with cell pipes, and prose does
 * not.
 */
// The closing pipe is a LOOKAHEAD so it is not consumed: one row's trailing
// cell separator is the next cell's leading one, and consuming it would make
// two adjacent link cells mask each other. No row shape emitted today has two,
// which is exactly why the bug would be introduced by a later edit and found by
// nobody.
// Every quantifier here is BOUNDED, and that is a security property rather than
// tidiness. One side of the comparison this feeds is the tracking issue's own
// comments — anyone who can comment on a public repository — so this pattern
// runs on genuinely uncontrolled input inside a job with a ten-minute budget.
// Unbounded, `[A-Za-z0-9-]+` scans a long run, fails at the `]`, and `matchAll`
// retries from the next `| [`: quadratic, measured at 66x for 8x input on
// CodeQL's own witness string. A bound caps the work per start position, so the
// total is linear in the input again.
//
// The limits are far above anything real (a GHSA id is 19 characters, a
// registry id 7) and a value past them is not silently truncated — it simply
// does not match, exactly as an unrecognised shape already did not.
const ADVISORY_CELL = /\| \[(GHSA-[A-Za-z0-9-]{1,64}|\d{1,32})\]\([^)\n]{0,2048}\)(?= \|)/g;

export function advisoryIdsFromReport(markdown: string): string[] {
  const ids = new Set<string>();
  for (const match of markdown.matchAll(ADVISORY_CELL)) {
    // The group is mandatory, so a match always carries it; the guard is what
    // the compiler needs rather than a reachable state.
    if (match[1] !== undefined) ids.add(match[1]);
  }
  return [...ids].sort();
}

function advisoryRow(advisory: AuditAdvisory): string {
  const id = advisoryId(advisory);
  const paths = (advisory.findings ?? []).flatMap((finding) => finding.paths ?? []);
  const shown = paths
    .slice(0, 3)
    .map((path) => mdEscape(path))
    .join('<br>');
  const via = paths.length > 3 ? `${shown}<br>+${String(paths.length - 3)} more` : shown;
  return `| ${mdEscape(advisory.module_name)} | ${advisory.severity ?? ''} | [${id}](${advisory.url ?? ''}) | ${mdEscape(advisory.title)} | ${via} |`;
}

export const REPORT_STYLES: Record<
  AuditMode,
  { title: string; headline: string; fixHint: string[] }
> = {
  workspace: {
    title: 'Dependency audit — workspace',
    headline: '`pnpm audit` over the workspace lockfile',
    fixHint: [
      'Fix by upgrading the dependency or raising its floor via `pnpm.overrides`; if no fixed',
      'release exists, add an expiring waiver — see CONTRIBUTING.md ("Dependency advisories and waivers").',
    ],
  },
  artifact: {
    title: 'Dependency audit — shipped artifact',
    headline: "`npm audit` over an end-user resolution of the published CLI's runtime dependencies",
    fixHint: [
      'Fix by raising the affected range in cli/package.json `dependencies` so a fresh `npm install`',
      'resolves a patched release — workspace `pnpm.overrides` do not reach end-user installs, and a',
      'copy nested under another package is pinned by that package, not by this repo. If the fix is',
      'blocked upstream, add an expiring waiver — see CONTRIBUTING.md ("Dependency advisories and waivers").',
    ],
  },
};

export function buildReport({
  mode,
  counts,
  blocking,
  waived,
  stale,
  nonBlocking,
}: Classification & { mode: AuditMode; counts: Record<string, number> }): string {
  const style = REPORT_STYLES[mode];
  const lines = [`# ${style.title}`, ''];
  const totals = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([severity, n]) => `${String(n)} ${severity}`)
    .join(', ');
  lines.push(
    `${style.headline} — gate: **high/critical** — found: ${totals || 'no advisories'}.`,
    '',
  );

  if (blocking.length > 0) {
    lines.push(`## Blocking advisories (${String(blocking.length)})`, '');
    lines.push(
      '| Package | Severity | Advisory | Title | Via |',
      '| --- | --- | --- | --- | --- |',
    );
    for (const advisory of blocking) lines.push(advisoryRow(advisory));
    lines.push('');
    lines.push(...style.fixHint, '');
  } else {
    lines.push('No blocking advisories.', '');
  }

  if (waived.length > 0) {
    lines.push(`## Waived (${String(waived.length)})`, '');
    lines.push('| Package | Advisory | Expires | Reason |', '| --- | --- | --- | --- |');
    for (const { advisory, waiver } of waived) {
      const id = advisoryId(advisory);
      lines.push(
        `| ${mdEscape(advisory.module_name)} | [${id}](${advisory.url ?? ''}) | ${waiver.expires} | ${mdEscape(waiver.reason)} |`,
      );
    }
    lines.push('');
  }

  if (stale.length > 0) {
    lines.push(`## Stale waivers (${String(stale.length)}) — remove these`, '');
    for (const { waiver, why } of stale) {
      lines.push(`- ${mdEscape(waiver.advisory)} — ${why}`);
    }
    lines.push('');
  }

  if (nonBlocking.length > 0) {
    lines.push(`## Below the gate (${String(nonBlocking.length)}, non-blocking)`, '');
    lines.push(
      '| Package | Severity | Advisory | Title | Via |',
      '| --- | --- | --- | --- | --- |',
    );
    for (const advisory of nonBlocking) lines.push(advisoryRow(advisory));
    lines.push('');
  }

  return lines.join('\n');
}

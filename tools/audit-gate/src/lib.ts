// Pure logic for the dependency-audit CI gate: waiver validation, `pnpm audit`
// payload parsing, advisory classification, and Markdown report generation.
// The CLI entry (audit-dependencies.ts) owns all I/O; everything here is
// side-effect-free so the unit suite can drive it with canned payloads.

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

// pnpm's own suppression channel (`pnpm.auditConfig.ignoreCves`/`ignoreGhsas`)
// filters advisories out of the payload and into `muted` — with no expiry, no
// reason, and no report row. The gate refuses to run while anything is muted
// so audit-waivers.json stays the only suppression route.
export function assertNothingMuted(payload: AuditPayload): void {
  const muted = payload.muted ?? [];
  if (muted.length > 0) {
    throw new WaiverConfigError(
      `pnpm.auditConfig mutes ${String(muted.length)} advisor${muted.length === 1 ? 'y' : 'ies'}; ` +
        'muted advisories carry no expiry or review trail — use .github/audit-waivers.json instead',
    );
  }
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

function advisoryRow(advisory: AuditAdvisory): string {
  const id = advisory.github_advisory_id ?? String(advisory.id ?? '');
  const paths = (advisory.findings ?? []).flatMap((finding) => finding.paths ?? []);
  const shown = paths
    .slice(0, 3)
    .map((path) => mdEscape(path))
    .join('<br>');
  const via = paths.length > 3 ? `${shown}<br>+${String(paths.length - 3)} more` : shown;
  return `| ${mdEscape(advisory.module_name)} | ${advisory.severity ?? ''} | [${id}](${advisory.url ?? ''}) | ${mdEscape(advisory.title)} | ${via} |`;
}

export function buildReport({
  counts,
  blocking,
  waived,
  stale,
  nonBlocking,
}: Classification & { counts: Record<string, number> }): string {
  const lines = ['# Dependency audit', ''];
  const totals = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([severity, n]) => `${String(n)} ${severity}`)
    .join(', ');
  lines.push(`\`pnpm audit\` — gate: **high/critical** — found: ${totals || 'no advisories'}.`, '');

  if (blocking.length > 0) {
    lines.push(`## Blocking advisories (${String(blocking.length)})`, '');
    lines.push(
      '| Package | Severity | Advisory | Title | Via |',
      '| --- | --- | --- | --- | --- |',
    );
    for (const advisory of blocking) lines.push(advisoryRow(advisory));
    lines.push('');
    lines.push(
      'Fix by upgrading the dependency or raising its floor via `pnpm.overrides`; if no fixed',
      'release exists, add an expiring waiver — see CONTRIBUTING.md ("Dependency advisories and waivers").',
      '',
    );
  } else {
    lines.push('No blocking advisories.', '');
  }

  if (waived.length > 0) {
    lines.push(`## Waived (${String(waived.length)})`, '');
    lines.push('| Package | Advisory | Expires | Reason |', '| --- | --- | --- | --- |');
    for (const { advisory, waiver } of waived) {
      const id = advisory.github_advisory_id ?? String(advisory.id ?? '');
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

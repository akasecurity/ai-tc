// The pure view of the mod's findings log: parsing, merging and the text the
// widgets draw. It imports nothing, so it can be bundled into the engine module
// a mod loads with no Node and no zod. The shape on disk is the ModFinding
// contract in @akasecurity/schema; this reads it structurally.

export type ViewSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ViewFinding {
  id: string;
  /** Epoch milliseconds. */
  at: number;
  ruleId: string;
  label: string;
  category: string;
  severity: ViewSeverity;
  action: string;
  where: string;
  pointer?: string;
}

const KEYS: ReadonlySet<string> = new Set([
  'v',
  'id',
  'at',
  'ruleId',
  'shortName',
  'category',
  'severity',
  'action',
  'where',
  'pointer',
]);
const ACTIONS: ReadonlySet<string> = new Set([
  'redacted',
  'vaulted',
  'blocked',
  'warned',
  'logged',
]);
const WHERES: ReadonlySet<string> = new Set([
  'prompt',
  'attachment',
  'tool-input',
  'tool-output',
  'memory',
  'subagent',
]);
const SEVERITIES: ReadonlySet<string> = new Set(['critical', 'high', 'medium', 'low']);
const ID = /^[0-9a-f]{16}$/;
const CATEGORY = /^[a-z][a-z0-9_]*$/;
const ISO_UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const POINTER = /^\[\[aka:[a-z][a-z0-9_]*:[A-Z2-7]{2,7}\.[A-Z2-7]{26}\.[A-Z2-7]{16}\]\]$/;

export function labelFor(ruleId: string, shortName: string | undefined, fullName?: string): string {
  if (shortName !== undefined && shortName !== '') return shortName;
  return fullName !== undefined && fullName !== '' ? fullName : ruleId;
}

export function parseFindingRecord(value: unknown): ViewFinding | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const r = value as Record<string, unknown>;
  if (Object.keys(r).some((k) => !KEYS.has(k))) return null;
  if (r.v !== 1 || typeof r.id !== 'string' || !ID.test(r.id)) return null;
  if (
    typeof r.ruleId !== 'string' ||
    r.ruleId === '' ||
    typeof r.category !== 'string' ||
    !CATEGORY.test(r.category)
  ) {
    return null;
  }
  if (typeof r.action !== 'string' || !ACTIONS.has(r.action)) return null;
  if (typeof r.where !== 'string' || !WHERES.has(r.where)) return null;
  const at = typeof r.at === 'string' && ISO_UTC.test(r.at) ? Date.parse(r.at) : Number.NaN;
  if (Number.isNaN(at)) return null;
  if (r.pointer !== undefined && (typeof r.pointer !== 'string' || !POINTER.test(r.pointer))) {
    return null;
  }
  if ((r.action === 'vaulted') !== (r.pointer !== undefined)) return null;
  const shortName =
    typeof r.shortName === 'string' && r.shortName.length <= 64 ? r.shortName : undefined;
  const severity = SEVERITIES.has(r.severity as string) ? (r.severity as ViewSeverity) : 'low';
  return {
    id: r.id,
    at,
    ruleId: r.ruleId,
    label: labelFor(r.ruleId, shortName, undefined),
    category: r.category,
    severity,
    action: r.action,
    where: r.where,
    ...(r.pointer === undefined ? {} : { pointer: r.pointer }),
  };
}

export function parseFindingsJsonl(text: string): ViewFinding[] {
  const out: ViewFinding[] = [];
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    try {
      const f = parseFindingRecord(JSON.parse(line));
      if (f !== null) out.push(f);
    } catch {
      // A line cut short by a killed writer is skipped; the next complete one still counts.
    }
  }
  return out;
}

export function mergeFindings(
  held: readonly ViewFinding[],
  incoming: readonly ViewFinding[],
  cap = 500,
): ViewFinding[] {
  const byId = new Map<string, ViewFinding>();
  for (const f of [...held, ...incoming]) if (!byId.has(f.id)) byId.set(f.id, f);
  return [...byId.values()].sort((a, b) => b.at - a.at).slice(0, cap);
}

interface SeverityStyle {
  color: 'error' | 'warning' | 'suggestion' | 'inactive';
  word: string;
}

const STYLES: Record<ViewSeverity, SeverityStyle> = {
  critical: { color: 'error', word: 'CRITICAL' },
  high: { color: 'warning', word: 'HIGH' },
  medium: { color: 'suggestion', word: 'MEDIUM' },
  low: { color: 'inactive', word: 'LOW' },
};

export function severityStyle(severity: ViewSeverity): SeverityStyle {
  return STYLES[severity];
}

export function chipText(f: ViewFinding): string {
  return `${STYLES[f.severity].word}  ${f.label} · ${f.action} · ${f.where}`;
}

export function bandFindings(
  all: readonly ViewFinding[],
  now: number,
  windowMs = 2 * 60 * 1000,
): { shown: ViewFinding[]; more: number } {
  const recent = all.filter((f) => now - f.at >= 0 && now - f.at <= windowMs);
  return { shown: recent.slice(0, 3), more: Math.max(0, recent.length - 3) };
}

const MODE_TEXT: Record<'in-place', string> = { 'in-place': 'redacting in place' };

export function statusText(all: readonly ViewFinding[], mode: 'in-place'): string {
  const critical = all.filter((f) => f.severity === 'critical').length;
  const high = all.filter((f) => f.severity === 'high').length;
  const other = all.length - critical - high;
  return `AKA · ${MODE_TEXT[mode]} · ${String(critical)} critical  ${String(high)} high  ${String(other)} other`;
}

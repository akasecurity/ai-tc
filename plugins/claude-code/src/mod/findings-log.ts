import { createHash } from 'node:crypto';
import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { BUNDLED_PACKS, DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  ModFinding,
  ModFindingAction,
  ModFindingWhere,
} from '@akasecurity/schema';
import { MOD_FINDINGS_DIR } from '@akasecurity/schema';

const SAFE_SESSION = /^[A-Za-z0-9_-]{1,128}$/;

const SHORT_NAMES: ReadonlyMap<string, string> = new Map(
  BUNDLED_PACKS.flatMap((pack) => Object.entries(pack.shortNames)),
);

const MAX_LABEL = 64;

// A rule's label: its short name, else the full name of the rule that matched,
// cut to what a record holds. Undefined leaves the reader to show the rule id.
function labelOf(ruleId: string, names: CaptureResult['ruleNames']): string | undefined {
  const short = SHORT_NAMES.get(ruleId);
  if (short !== undefined) return short;
  const name = names?.[ruleId]?.trim();
  return name === undefined || name === '' ? undefined : name.slice(0, MAX_LABEL).trimEnd();
}

export function findingId(
  sessionId: string,
  kind: string,
  text: string,
  ruleId: string,
  span: { start: number; end: number },
): string {
  const textHash = createHash('sha256').update(text).digest('hex');
  return createHash('sha256')
    .update([sessionId, kind, ruleId, String(span.start), String(span.end), textHash].join('\0'))
    .digest('hex')
    .slice(0, 16);
}

export function actionFromCapture(action: ActionTaken, vaulted: boolean): ModFindingAction {
  if (action === 'block') return 'blocked';
  if (action === 'redact') return vaulted ? 'vaulted' : 'redacted';
  if (action === 'warn') return 'warned';
  return 'logged';
}

export function modFindingsFrom(input: {
  sessionId: string;
  kind: string;
  text: string;
  result: CaptureResult;
  where: ModFindingWhere;
  action: ModFindingAction;
  pointers?: ReadonlyMap<string, string> | undefined;
  now?: Date;
}): ModFinding[] {
  const at = (input.now ?? new Date()).toISOString();
  const enforced = input.result.enforcedFindings ?? input.result.findings;
  return enforced.map((f) => {
    const found = input.pointers?.get(findingKey(f));
    const action: ModFindingAction =
      input.action === 'vaulted' && found === undefined ? 'redacted' : input.action;
    const shortName = labelOf(f.ruleId, input.result.ruleNames);
    return {
      v: 1,
      id: findingId(input.sessionId, input.kind, input.text, f.ruleId, f.span),
      at,
      ruleId: f.ruleId,
      ...(shortName === undefined ? {} : { shortName }),
      category: f.category,
      severity: f.severity,
      action,
      where: input.where,
      ...(action === 'vaulted' && found !== undefined ? { pointer: found } : {}),
    };
  });
}

export function modFindingsPath(dataDir: string, sessionId: string): string | null {
  if (!SAFE_SESSION.test(sessionId)) return null;
  return join(dataDir, MOD_FINDINGS_DIR, `${sessionId}.jsonl`);
}

export function appendModFindings(
  dataDir: string,
  sessionId: string,
  findings: readonly ModFinding[],
): void {
  try {
    if (findings.length === 0) return;
    const path = modFindingsPath(dataDir, sessionId);
    if (path === null) return;
    mkdirSync(join(dataDir, MOD_FINDINGS_DIR), { recursive: true, mode: DATA_DIR_MODE });
    appendFileSync(path, findings.map((f) => `${JSON.stringify(f)}\n`).join(''), {
      mode: DATA_FILE_MODE,
    });
  } catch {
    // A finding the widgets cannot show is not a reason to fail the hook.
  }
}

/**
 * A finding's key in a pointer map: its rule and span, never its raw value, so a
 * value two findings share cannot lend one's pointer to the other.
 */
export function findingKey(f: Pick<CaptureResult['findings'][number], 'ruleId' | 'span'>): string {
  return [f.ruleId, String(f.span.start), String(f.span.end)].join('\0');
}

/**
 * The pointer the vault minted for each finding it kept, by `findingKey`.
 * The vault answers its pointers in span order and only for the findings it kept,
 * so they pair with the kept findings in span order. When the counts differ (an
 * overlap or a stale span was destroyed instead), which pointer belongs to which
 * finding is unknown and the map is empty: those findings are recorded as redacted.
 */
export function pointersByFinding(
  findings: readonly CaptureResult['findings'][number][],
  kept: ReadonlySet<CaptureResult['findings'][number]> | undefined,
  pointers: readonly string[],
): ReadonlyMap<string, string> {
  const ordered = findings
    .filter((f) => kept === undefined || kept.has(f))
    .sort((a, b) => a.span.start - b.span.start);
  const map = new Map<string, string>();
  if (ordered.length !== pointers.length) return map;
  ordered.forEach((f, i) => {
    const pointer = pointers[i];
    if (pointer !== undefined) map.set(findingKey(f), pointer);
  });
  return map;
}

/** The pointers the vault minted for a field, keyed by the field's text. */
export type PointersByText = Map<string, ReadonlyMap<string, string>>;

/**
 * Builds the records for one scanned field and appends them, inside one
 * try/catch so no fault here can reach the decision the caller is about to make.
 * Answers the records built, or none.
 */
export function recordModFindings(
  dataDir: string,
  sessionId: string,
  input: Parameters<typeof modFindingsFrom>[0],
): ModFinding[] {
  try {
    const records = modFindingsFrom(input);
    appendModFindings(dataDir, sessionId, records);
    return records;
  } catch {
    return [];
  }
}

/** A tool field's action: vaulted when the vault rewrote its redacted value to a pointer. */
export function toolFieldAction(
  result: CaptureResult,
  pointers: ReadonlyMap<string, string> | undefined,
): ModFindingAction {
  return result.action === 'redact' && pointers !== undefined && pointers.size > 0
    ? 'vaulted'
    : actionFromCapture(result.action, false);
}

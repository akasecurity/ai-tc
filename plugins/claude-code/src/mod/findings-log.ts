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
  pointers?: ReadonlyMap<string, string>;
  now?: Date;
}): ModFinding[] {
  const at = (input.now ?? new Date()).toISOString();
  const enforced = input.result.enforcedFindings ?? input.result.findings;
  return enforced.map((f) => {
    const found = input.pointers?.get(f.rawMatch);
    const action: ModFindingAction =
      input.action === 'vaulted' && found === undefined ? 'redacted' : input.action;
    const shortName = SHORT_NAMES.get(f.ruleId);
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

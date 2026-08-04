// Tests the pure PreToolUse decision module directly — NEVER via the hook
// entry file (src/hooks/*.ts run main() on import and hang vitest collection).
//
// Adapted from plugins/codex/test/hooks/pre-tool-use-decision.test.ts, but the
// DECISION RULE ITSELF differs here, not just the field table. Claude Code and
// Codex can rewrite a tool argument in place (`updatedInput`), so a redact
// policy escalates to a deny only on text that EXECUTES. Antigravity's
// PreToolUse output is `{ decision, reason, permissionOverrides }` with no
// argument-rewrite channel at all, so EVERY redact escalates — including on
// durable file content, which the siblings would have masked and let through.
// That is what the "stored text also denies" case below pins.
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CaptureResult, DataGateway } from '@akasecurity/plugin-sdk';
import { createPluginRuntime } from '@akasecurity/plugin-sdk';
import type { PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { PreToolUseOutput, ScannableField } from '../../src/hooks/pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  denyPointerMessage,
  NO_REWRITE_REDACT_NOTE,
  SCANNABLE_FIELDS,
} from '../../src/hooks/pre-tool-use-decision.ts';

const IP = ['45', '79', '142', '6'].join('.');
const EMAIL = ['user1', 'example.com'].join('@');

const RUN_COMMAND: ScannableField = { field: 'CommandLine', executable: true };
const WRITE_CONTENT: ScannableField = { field: 'CodeContent', executable: false };

type Finding = CaptureResult['findings'][number];

function finding(ruleId: string, rawMatch: string, text: string): Finding {
  const start = text.indexOf(rawMatch);
  return {
    ruleId,
    category: 'pii',
    severity: 'low',
    span: { start, end: start + rawMatch.length },
    rawMatch,
    confidence: 0.9,
  };
}

function redactResult(
  text: string,
  ruleId: string,
  rawMatch: string,
  reference?: string,
): CaptureResult {
  return {
    action: 'redact',
    text: text.replace(rawMatch, '[REDACTED:PII]'),
    findings: [finding(ruleId, rawMatch, text)],
    ...(reference ? { blockedReferences: [{ reference, ruleId, maskedValue: '4******6' }] } : {}),
  };
}

function denyReason(output: PreToolUseOutput): string {
  if (output.decision !== 'deny') {
    throw new Error(`expected deny, got ${output.decision}`);
  }
  return output.reason ?? '';
}

describe('SCANNABLE_FIELDS', () => {
  it('maps Antigravity tool args, marking only the shell command executable', () => {
    // The executable flag no longer decides whether a redact escalates (all of
    // them do here) — it gates the vault-pointer pre-check, which must only
    // fire on text the host is about to run.
    expect(SCANNABLE_FIELDS).toEqual({
      run_command: [{ field: 'CommandLine', executable: true }],
      write_to_file: [{ field: 'CodeContent', executable: false }],
      replace_file_content: [{ field: 'ReplacementContent', executable: false }],
    });
  });

  it('does not claim to cover multi_replace_file_content', () => {
    // Its args nest the edits in an undocumented container shape. A guessed
    // field name there would scan nothing while reading as covered, so the
    // absence is deliberate — see the module comment.
    expect(SCANNABLE_FIELDS).not.toHaveProperty('multi_replace_file_content');
  });
});

describe('decidePreToolUse — redact escalates to deny on executable text', () => {
  const COMMAND = `psql -c "DELETE FROM share_destination WHERE host = '${IP}';"`;

  it('denies the run_command call instead of rewriting the command', () => {
    const result = redactResult(COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const output = decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this run_command call — flagged core-pii/ip-address');
    expect(reason).toContain(NO_REWRITE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve 3f2a91');
    // No masked text may ride along: there is no field that would apply it, so
    // emitting one would leak a preview into a payload nothing consumes.
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('a plain block (no escalation) carries no escalation note', () => {
    const blocked: CaptureResult = {
      action: 'block',
      text: null,
      findings: [finding('secrets-infra/db-connection-string', IP, COMMAND)],
    };
    const reason = denyReason(
      decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result: blocked }]),
    );
    expect(reason).not.toContain(NO_REWRITE_REDACT_NOTE);
  });
});

describe('decidePreToolUse — redact on STORED text also denies', () => {
  it('write_to_file content denies rather than masking in place', () => {
    // This is the case that diverges from Claude Code and Codex, which would
    // both allow the call with a masked `updatedInput`. Antigravity has no such
    // field, so allowing here would write the RAW value to disk.
    const content = `support = ${EMAIL}\n`;
    const result = redactResult(content, 'core-pii/email', EMAIL, '9c04d7');
    const output = decidePreToolUse('write_to_file', [{ spec: WRITE_CONTENT, result }]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this write_to_file call — flagged core-pii/email');
    expect(reason).toContain(NO_REWRITE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve 9c04d7');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });
});

describe('decidePreToolUse — warn and clean both allow', () => {
  it('a warn allows: this event has no channel to carry the notice', () => {
    // PreToolUse output has no systemMessage/additionalContext field, and
    // `reason` accompanies a deny. A warned finding is still captured and
    // ledgered by the caller; it simply carries no inline notice here.
    const text = 'uses share_destination table';
    const warned: CaptureResult = {
      action: 'warn',
      text,
      findings: [finding('core-code-context/db-table-name', 'share_destination', text)],
    };
    expect(decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result: warned }])).toEqual({
      decision: 'allow',
    });
  });

  it('no findings allows', () => {
    const clean: CaptureResult = { action: 'log', text: 'ls -la', findings: [] };
    expect(decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result: clean }])).toEqual({
      decision: 'allow',
    });
  });

  it('nothing scanned allows — never an empty/absent decision', () => {
    // The host fails CLOSED: an omitted or unrecognised decision reads as a
    // deny. So the "nothing to say" path must still name `allow` explicitly.
    expect(decidePreToolUse('run_command', [])).toEqual({ decision: 'allow' });
  });
});

// ————————————————————————————————————————————————————————————————————————————
// End-to-end through the REAL runtime, with the enforcement posture pinned
// explicitly (a `pii` category policy set to `redact`, exactly as an operator's
// own policy would be) — cold-start defaults observe-first, so a test relying on
// them would prove nothing about the escalation path. Mirrors the incident
// regression in the Claude Code and Codex siblings, adapted to Antigravity's
// run_command field: while clearing seed data, a shell `psql -c` command
// inserted five host strings and deleted rows matching them; the pii/ip-address
// rule matched the lone IP literal, the hook rewrote the command in place, and
// the spliced `[REDACTED:PII]` executed — deleting only 4 of the 5 rows. Masking
// executable text changes what runs, so redact must escalate to deny here.
// The sensitive-looking literals are ASSEMBLED AT RUNTIME (see the IP/EMAIL
// consts above) so this repo's own scanning never rewrites the fixtures.

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
  };
}

function bundle(): PolicyBundle {
  return {
    version: 'test',
    policies: [
      {
        id: randomUUID(),
        scope: 'global',
        target: { category: 'pii' },
        action: 'redact',
        enabled: true,
      },
    ],
    rules: [],
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

// A fake gateway mirroring @akasecurity/plugin-sdk's runtime tests: fixed
// policy bundle, no-op writes.
function fakeGateway(b: PolicyBundle): DataGateway {
  return {
    recordCapture: () => Promise.resolve(),
    ensureInventory: () => Promise.resolve({}),
    recordAuditEvent: () => Promise.resolve(),
    recordLlmCall: () => Promise.resolve(),
    recordLlmCalls: () => Promise.resolve(),
    recordToolCalls: () => Promise.resolve(),
    recordConfigScan: () => Promise.resolve(),
    configInventoryReport: () =>
      Promise.resolve({
        scannedAt: null,
        skills: [],
        hooks: [],
        mcpServers: [],
        configFiles: [],
        topics: [],
      }),
    readSessionProvider: () => Promise.resolve(undefined),
    facets: () => Promise.resolve({ hosts: [], harnesses: [], osVersions: [], projects: [] }),
    getPolicyBundle: () => Promise.resolve(b),
    consumeException: () => Promise.resolve(false),
    recordBlockedDetection: () => Promise.resolve(),
    recentFindings: () => Promise.resolve([]),
    healthSummary: () =>
      Promise.resolve({
        findings: 0,
        byAction: {} as never,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        coverage: 0,
      }),
    activityByDay: () => Promise.resolve([]),
    tokenReports: () => Promise.resolve([]),
    knownContentHashes: () => Promise.resolve(new Set<string>()),
    scanLedger: () => Promise.resolve(new Map()),
    recordScanned: () => Promise.resolve(),
    openAtRestKeysForPath: () => Promise.resolve([]),
    resolvedAtRestKeysForPath: () => Promise.resolve([]),
    insertResolution: () => Promise.resolve(),
    getRuleProbeVerdict: () => Promise.resolve(undefined),
    setRuleProbeVerdict: () => Promise.resolve(),
    recordProjectEgress: () =>
      Promise.resolve({
        destinations: 0,
        endpoints: 0,
        callSites: 0,
        truncated: false,
        droppedFiles: [],
      }),
    close: () => Promise.resolve(),
  };
}

describe('incident regression — the seed-cleanup DELETE, end to end', () => {
  const INCIDENT_COMMAND =
    'docker exec aka-db psql -U aka -d aka -c "CREATE TEMP TABLE seed_hosts(host text); ' +
    "INSERT INTO seed_hosts VALUES ('newrelic.com'),('stripe.com'),('datadoghq.com')," +
    `('acme-partner.com'),('${IP}'); ` +
    'DELETE FROM share_destination sd USING seed_hosts sh WHERE sd.host = sh.host;"';

  it('runtime redacts the IP out of the SQL; the hook decision denies instead of executing it', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const result = await rt.processText(INCIDENT_COMMAND);
    await rt.close();

    expect(result.action).toBe('redact');
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');
    expect(result.text).not.toContain(IP);
    expect(result.text).toContain('[REDACTED:PII]');

    const output = decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]);
    const reason = denyReason(output);
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).toContain(NO_REWRITE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('drives the real ledger: the escalated deny surfaces a concrete approve ref', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-antigravity-pre-tool-use-'));
    try {
      const rt = createPluginRuntime(fakeGateway(bundle()), settings(), { dataDir: dir });
      const result = await rt.processText(INCIDENT_COMMAND);
      await rt.close();

      expect(result.action).toBe('redact');
      const ref = result.blockedReferences?.[0]?.reference ?? '';
      expect(ref).toMatch(/^[0-9a-f]{6}$/);

      const output = decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]);
      const reason = denyReason(output);
      expect(reason).toContain(NO_REWRITE_REDACT_NOTE);
      expect(reason).toContain(`aka exception approve ${ref}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// A shape-valid vault pointer (RFC 4648 base32 segments: 2-char key version,
// 26-char pointer id, 16-char tag) — pointerTokenScanner matches on shape, so
// any well-formed token exercises the deny.
const POINTER = `[[aka:secret:AA.${'A'.repeat(26)}.${'A'.repeat(16)}]]`;

describe('decideInputPointerDeny', () => {
  it('denies a pointer in an executable field, in every consent state', () => {
    const output = decideInputPointerDeny('run_command', { CommandLine: `echo ${POINTER}` }, [
      RUN_COMMAND,
    ]);
    expect(output?.decision).toBe('deny');
    const reason = output?.reason ?? '';
    expect(reason).toBe(denyPointerMessage('run_command'));
    // The reason tells the user how to proceed without ever suggesting the
    // plugin could substitute the value itself — the resolve path it names is
    // the audited CLI reveal, not an exception grant this harness cannot honor.
    expect(reason).toContain('aka vault show');
    expect(reason).not.toContain('aka exception approve');
  });

  it('lets a pointer in a NON-executable field pass to the normal scan', () => {
    // File content is durable text, not something the host executes — a pointer
    // there is data, decided by the regular capture pipeline.
    expect(
      decideInputPointerDeny('write_to_file', { CodeContent: `body ${POINTER}` }, [WRITE_CONTENT]),
    ).toBeNull();
  });

  it('ignores clean commands and lookalike tokens with an invented category', () => {
    expect(
      decideInputPointerDeny('run_command', { CommandLine: 'ls -la' }, [RUN_COMMAND]),
    ).toBeNull();
    // The category alternation is pinned to DetectionCategory members: a
    // lookalike must not trip the deny (it cannot reach a de-reference path
    // anywhere, so denying it would be pure friction).
    const lookalike = `[[aka:bogus:AA.${'A'.repeat(26)}.${'A'.repeat(16)}]]`;
    expect(
      decideInputPointerDeny('run_command', { CommandLine: `echo ${lookalike}` }, [RUN_COMMAND]),
    ).toBeNull();
  });
});

// Tests the pure PreToolUse decision module directly — NEVER via the hook
// entry file (src/hooks/*.ts run main() on import and hang vitest collection).
//
// Adapted from plugins/codex/test/hooks/pre-tool-use-decision.test.ts, but the
// SCOPE differs here, not just the field table. Claude Code and Codex can
// rewrite a tool argument in place (`updatedInput`), so only text that EXECUTES
// is unrewritable there. Antigravity's PreToolUse output is
// `{ decision, reason, permissionOverrides }` with no argument-rewrite channel
// at all, so EVERY field is unrewritable — including durable file content,
// which the siblings mask and let through. That is what the "stored text" case
// below pins.
//
// What a redact policy then DOES is a workspace setting (`redactFallback`), not
// a rule of this module: the runtime resolves it before the decision module
// sees anything, and says what it became on `redactDegradedTo`. Both settings are driven
// below, because the shipped default (`warn`) lets a call through that the
// strict setting (`block`) denies, and neither is inferable from the other.
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CaptureResult, DataGateway } from '@akasecurity/plugin-sdk';
import { createPluginRuntime } from '@akasecurity/plugin-sdk';
import type { PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
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

// What the runtime hands this module for a field this host cannot rewrite: the
// policy resolved to `redact`, the capture declared the field unrewritable, and
// the action is therefore the workspace's `redactFallback`. `redactDegradedTo`
// carries that fact — the ACTION the lost redact became — and it is the only
// thing separating this from a policy that genuinely said `warn`.
//
// The text is the ORIGINAL, unmasked — nothing was rewritten, which is the
// point. A block carries null, as decide() returns for one.
// `action` is what the fallback POLICY resolves to, not the policy id: the
// `monitor` fallback's action is `log` (BUILTIN_POLICY_SPECS), and ActionTaken
// carries no `monitor` member at all.
function degradedRedact(
  action: 'log' | 'warn' | 'block',
  text: string,
  ruleId: string,
  rawMatch: string,
  reference?: string,
): CaptureResult {
  return {
    action,
    text: action === 'block' ? null : text,
    findings: [finding(ruleId, rawMatch, text)],
    redactDegradedTo: action,
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

describe('decidePreToolUse — a redact this host cannot perform follows the fallback', () => {
  const COMMAND = `psql -c "DELETE FROM share_destination WHERE host = '${IP}';"`;

  it('denies the run_command call under a block fallback, and says masking was not possible', () => {
    const result = degradedRedact('block', COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const output = decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this run_command call — flagged core-pii/ip-address');
    expect(reason).toContain(NO_REWRITE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve 3f2a91');
    // No masked text may ride along: there is no field that would apply it, so
    // emitting one would leak a preview into a payload nothing consumes.
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('LETS THE CALL THROUGH under the shipped warn fallback', () => {
    // The consequence of the shipped default, pinned rather than left implicit:
    // this host denied every redact before the fallback existed, and under
    // `warn` the same command now runs with the value unmasked. Antigravity's
    // PreToolUse has no message channel either, so `warn` is invisible on
    // screen — it differs from `monitor` only in the recorded action.
    const result = degradedRedact('warn', COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const output = decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]);

    expect(output.decision).toBe('allow');
    expect(output.reason).toBeUndefined();
  });

  it('lets it through under a monitor fallback too, with nothing said', () => {
    // The `monitor` fallback resolves to the `log` ACTION — there is no
    // `monitor` member on ActionTaken.
    const result = degradedRedact('log', COMMAND, 'core-pii/ip-address', IP);
    expect(decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]).decision).toBe('allow');
  });

  it('does NOT explain a deny that some OTHER finding produced', () => {
    // The mixed shape: one capture carrying a degraded redact AND a finding
    // whose own policy is `block`. `action` is `block` because that is the
    // worst of the two, but the fallback resolved to `warn` — so the deny is
    // the credential's doing and a note naming a `block` fallback would state
    // a setting this workspace does not have.
    //
    // Both findings DO reach the deny here, and that is worth saying because
    // the opposite is easy to assume: the rule-id filter keys on the RESULT's
    // action, not each finding's, so a blocking result contributes every rule
    // id it carries — `core-pii/ip-address` included, asserted below. The
    // starvation case where a degraded finding contributes nothing needs it in
    // a SEPARATE scanned field whose own action is `warn`, which is the shape
    // the Claude Code sibling builds rather than this one.
    const mixed: CaptureResult = {
      action: 'block',
      text: null,
      findings: [
        finding('secrets-infra/db-connection-string', 'SECRET', COMMAND),
        finding('core-pii/ip-address', IP, COMMAND),
      ],
      redactDegradedTo: 'warn',
      blockedReferences: [
        { reference: 'aa11bb', ruleId: 'secrets-infra/db-connection-string', maskedValue: 'S***T' },
      ],
    };
    const reason = denyReason(
      decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result: mixed }]),
    );
    expect(reason).toContain('secrets-infra/db-connection-string');
    // The comment above, asserted rather than claimed.
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).not.toContain(NO_REWRITE_REDACT_NOTE);
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

describe('decidePreToolUse — STORED text is unrewritable here too', () => {
  it('write_to_file content denies under a block fallback rather than masking in place', () => {
    // This is the case that diverges from Claude Code and Codex, which would
    // both allow the call with a masked `updatedInput`. Antigravity has no such
    // field, so the capture declares even file content unrewritable — and
    // under a `warn` fallback the RAW value reaches disk, which is exactly what
    // the setting is choosing between.
    const content = `support = ${EMAIL}\n`;
    const result = degradedRedact('block', content, 'core-pii/email', EMAIL, '9c04d7');
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

function settings(redactFallback: WorkspaceSettings['redactFallback'] = 'warn'): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    redactFallback,
    bodyRetention: { enabled: false, retainDays: 30 },
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

  // Driven through `capture` with `rewritable: false` — the call the hook
  // really makes — rather than through `processText`, which has no such option
  // and so could never exercise the degrade. That distinction is the point of
  // the change these cases cover: the resolution moved INTO the runtime, so a
  // test that never passes the flag proves nothing about it.
  const command = (text: string) =>
    ({ kind: 'tool_use', sourceTool: SOURCE_TOOL.Antigravity, text }) as const;

  it('resolves the redact to a deny INSIDE the runtime under a block fallback', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings('block'));
    const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
    await rt.close();

    // The runtime, not the hook, is what refused: the emitted decision and the
    // recorded action are one value, which is what the old escalation broke.
    expect(result.action).toBe('block');
    expect(result.redactDegradedTo).toBe(result.action);
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');

    const output = decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]);
    const reason = denyReason(output);
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).toContain(NO_REWRITE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('lets the same command run under the shipped warn fallback, recorded as warn', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
    await rt.close();

    // The incident this module exists for, under the shipped default: the
    // policy asked for a redact, the host cannot mask an argument, and the
    // fallback lets the command through. The row says `warn` — never `redact`,
    // which would claim a masking that did not happen.
    expect(result.action).toBe('warn');
    expect(result.redactDegradedTo).toBe(result.action);
    expect(result.text).toContain(IP);

    expect(decidePreToolUse('run_command', [{ spec: RUN_COMMAND, result }]).decision).toBe('allow');
  });

  it('drives the real ledger: the deny surfaces a concrete approve ref', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-antigravity-pre-tool-use-'));
    try {
      const rt = createPluginRuntime(fakeGateway(bundle()), settings('block'), { dataDir: dir });
      const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
      await rt.close();

      expect(result.action).toBe('block');
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

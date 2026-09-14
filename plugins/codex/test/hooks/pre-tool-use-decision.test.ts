// Tests the pure PreToolUse decision module directly — NEVER via the hook
// entry file (src/hooks/*.ts run main() on import and hang vitest collection).
//
// The decision logic here is ported verbatim from
// plugins/claude-code/src/hooks/pre-tool-use-decision.test.ts (same
// hookSpecificOutput shape, same escalate-redact-on-executable-field rule);
// only SCANNABLE_FIELDS differs, so this suite exercises it against Codex's
// own Bash/apply_patch fields instead of Claude Code's Bash/Write/Edit/WebFetch.
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
  EXECUTABLE_REDACT_NOTE,
  SCANNABLE_FIELDS,
  UNREDACTABLE_NOTE,
} from '../../src/hooks/pre-tool-use-decision.ts';

const IP = ['45', '79', '142', '6'].join('.');
const EMAIL = ['user1', 'example.com'].join('@');

const BASH_COMMAND: ScannableField = { field: 'command', executable: true };
const APPLY_PATCH_INPUT: ScannableField = { field: 'input', executable: false };

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

// What the runtime hands this module for a field the hook declared
// unrewritable — an executable one. The policy resolved to `redact`, the
// capture said it could not be carried out, and the action is the workspace's
// `redactFallback`; `redactDegradedTo` says what it became. The text is the
// ORIGINAL, unmasked, because nothing was rewritten.
//
// `redactResult` above stays the shape for apply_patch, which IS rewritable and
// keeps true redaction — the two helpers are the per-field split, not a style
// choice.
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

function denyReason(output: PreToolUseOutput | null): string {
  if (output === null || !('hookSpecificOutput' in output)) {
    throw new Error('expected a hookSpecificOutput decision');
  }
  const decision = output.hookSpecificOutput;
  if (decision.permissionDecision !== 'deny') {
    throw new Error(`expected deny, got ${decision.permissionDecision}`);
  }
  return decision.permissionDecisionReason;
}

describe('SCANNABLE_FIELDS', () => {
  it('marks Bash command as executable and apply_patch input as stored', () => {
    // The executable flag is the whole fix — flipping one silently reopens
    // in-place rewriting of command text (or breaks stored-text redaction).
    expect(SCANNABLE_FIELDS).toEqual({
      Bash: [{ field: 'command', executable: true }],
      apply_patch: [{ field: 'input', executable: false }],
    });
  });
});

describe('decidePreToolUse — a redact on executable text follows the fallback', () => {
  const COMMAND = `psql -c "DELETE FROM share_destination WHERE host = '${IP}';"`;

  it('denies the Bash call under a block fallback, and says masking was not possible', () => {
    const result = degradedRedact('block', COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const output = decidePreToolUse('Bash', { command: COMMAND }, [{ spec: BASH_COMMAND, result }]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this Bash call — flagged core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve 3f2a91');
    expect(JSON.stringify(output)).not.toContain('updatedInput');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('LETS THE COMMAND RUN under the shipped warn fallback, saying so on screen', () => {
    // The consequence of the shipped default, pinned rather than left implicit:
    // this command was denied before the fallback existed. Unlike Antigravity,
    // Codex has a message channel, so `warn` is at least visible — and the
    // payload still carries no `updatedInput`, because nothing was masked.
    const result = degradedRedact('warn', COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const output = decidePreToolUse('Bash', { command: COMMAND }, [{ spec: BASH_COMMAND, result }]);

    const emitted = JSON.stringify(output);
    expect(emitted).toContain('AKA flagged sensitive content in Bash input');
    expect(emitted).not.toContain('updatedInput');
    expect(emitted).not.toContain('AKA redacted');
  });

  it('a plain block (no escalation) carries no escalation note', () => {
    const blocked: CaptureResult = {
      action: 'block',
      text: null,
      findings: [finding('secrets-infra/db-connection-string', IP, COMMAND)],
    };
    const reason = denyReason(
      decidePreToolUse('Bash', { command: COMMAND }, [{ spec: BASH_COMMAND, result: blocked }]),
    );
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
  });
});

describe('decidePreToolUse — a redact carrying no text denies instead of allowing', () => {
  // CaptureResult.text is `string | null`, so { action: 'redact', text: null }
  // is protocol-legal. Allowing it emitted the ORIGINAL input back to Codex
  // under the "AKA redacted sensitive content" systemMessage — the raw value
  // sent, and the transcript claiming it was masked.
  const PATCH = `*** Update File: notes.md\n+contact ${EMAIL}\n`;

  const unredactable = (): CaptureResult => ({
    action: 'redact',
    text: null,
    findings: [finding('core-pii/email-address', EMAIL, PATCH)],
  });

  it('denies the apply_patch call rather than passing the input through', () => {
    const output = decidePreToolUse('apply_patch', { input: PATCH }, [
      { spec: APPLY_PATCH_INPUT, result: unredactable() },
    ]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this apply_patch call — flagged core-pii/email-address');
    expect(reason).toContain(UNREDACTABLE_NOTE);
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);

    const emitted = JSON.stringify(output);
    expect(emitted).not.toContain('updatedInput');
    expect(emitted).not.toContain('AKA redacted');
    expect(emitted).not.toContain(EMAIL);
  });

  it('is scoped to a REWRITABLE field, which is the only place it can arise', () => {
    // An executable field is captured with `rewritable: false`, so its redact
    // becomes the fallback inside the runtime and never reaches this module as
    // `redact` at all — `{ action: 'redact', text: null }` is therefore a shape
    // only a rewritable field can produce. The two notes answer different
    // questions and cannot both apply: this one is a runtime failure, the
    // executable one is a host limitation.
    const output = decidePreToolUse('apply_patch', { input: PATCH }, [
      { spec: APPLY_PATCH_INPUT, result: unredactable() },
    ]);
    const reason = denyReason(output);
    expect(reason).toContain(UNREDACTABLE_NOTE);
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
  });

  it('is not displaced by a field that merely WARNED under the fallback', () => {
    // The note-precedence edge this host has and the other two do not:
    // `escalatedExecutable` wins below, so a Bash field that only warned must
    // not claim a deny the apply_patch field alone caused. Both halves of that
    // message would be wrong — masking WAS possible here (the tokenizer simply
    // produced nothing), and the fallback is `warn`, not `block`.
    //
    // Driving both fields in one call is what makes this reachable: every
    // other degraded-redact case in this file is single-finding, and the
    // module's job is precisely not to cross-attribute between them.
    const output = decidePreToolUse('apply_patch', { input: PATCH }, [
      { spec: BASH_COMMAND, result: degradedRedact('warn', PATCH, 'core-pii/ip-address', IP) },
      { spec: APPLY_PATCH_INPUT, result: unredactable() },
    ]);
    const reason = denyReason(output);
    expect(reason).toContain(UNREDACTABLE_NOTE);
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
  });

  it('carries the executable note instead when the fallback denied a degraded redact', () => {
    const reason = denyReason(
      decidePreToolUse('Bash', { command: PATCH }, [
        {
          spec: BASH_COMMAND,
          result: degradedRedact('block', PATCH, 'core-pii/email-address', EMAIL),
        },
      ]),
    );
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).not.toContain(UNREDACTABLE_NOTE);
  });
});

describe('decidePreToolUse — apply_patch stored text keeps true redaction', () => {
  it('apply_patch input: allow with the redacted field in updatedInput', () => {
    const input = `*** Begin Patch\n*** Update File: notes.txt\n+support = ${EMAIL}\n*** End Patch`;
    const result = redactResult(input, 'core-pii/email', EMAIL, '9c04d7');
    const output = decidePreToolUse('apply_patch', { input }, [
      { spec: APPLY_PATCH_INPUT, result },
    ]);

    if (output === null || !('hookSpecificOutput' in output) || !('systemMessage' in output)) {
      throw new Error('expected an allow decision with updatedInput');
    }
    expect(output.hookSpecificOutput.permissionDecision).toBe('allow');
    expect(output.hookSpecificOutput.updatedInput).toEqual({
      input: input.replace(EMAIL, '[REDACTED:PII]'),
    });
    expect(output.systemMessage).toBe(
      'AKA redacted sensitive content in apply_patch input — flagged core-pii/email.' +
        ' To allow this exact value intentionally, run: aka exception approve 9c04d7.',
    );
  });

  it('warn stays a systemMessage; no findings stays silent', () => {
    const text = 'uses share_destination table';
    const warned: CaptureResult = {
      action: 'warn',
      text,
      findings: [finding('core-code-context/db-table-name', 'share_destination', text)],
    };
    const output = decidePreToolUse('Bash', { command: text }, [
      { spec: BASH_COMMAND, result: warned },
    ]);
    expect(output).toEqual({
      systemMessage:
        'AKA flagged sensitive content in Bash input (core-code-context/db-table-name).',
    });

    const clean: CaptureResult = { action: 'log', text, findings: [] };
    expect(
      decidePreToolUse('Bash', { command: text }, [{ spec: BASH_COMMAND, result: clean }]),
    ).toBeNull();
  });
});

// ————————————————————————————————————————————————————————————————————————————
// End-to-end through the REAL runtime, with the enforcement posture pinned
// explicitly (a `pii` category policy set to `redact`, exactly as an
// operator's own policy would be) — cold-start defaults observe-first, so a
// test relying on them would prove nothing about the escalation path. Mirrors
// the incident regression in plugins/claude-code/src/hooks/
// pre-tool-use-decision.test.ts, adapted to Codex's Bash field: while
// clearing seed data, a Bash `docker exec … psql -c` command inserted five
// host strings and deleted rows matching them; the pii/ip-address rule
// matched the lone IP literal, the hook rewrote the command in place, and the
// spliced `[REDACTED:PII]` executed — deleting only 4 of the 5 rows. Masking
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

  // Driven through `capture` with the hook's own `rewritable: !spec.executable`
  // rather than through `processText`, which takes no such option and so could
  // never exercise the degrade. That is the point of the change these cases
  // cover: the resolution moved INTO the runtime.
  const command = (text: string) =>
    ({ kind: 'tool_use', sourceTool: SOURCE_TOOL.Codex, text }) as const;

  it('resolves the redact to a deny INSIDE the runtime under a block fallback', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings('block'));
    const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
    await rt.close();

    // The runtime refused, so the emitted decision and the recorded action are
    // one value — which is what the old escalation in this module broke.
    expect(result.action).toBe('block');
    expect(result.redactDegradedTo).toBe(result.action);
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');

    const output = decidePreToolUse('Bash', { command: INCIDENT_COMMAND }, [
      { spec: BASH_COMMAND, result },
    ]);
    const reason = denyReason(output);
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain('updatedInput');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('lets the same command run under the shipped warn fallback, recorded as warn', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
    await rt.close();

    // The incident this module exists for, under the shipped default: the
    // policy asked for a redact, an executable field cannot carry one, and the
    // fallback lets the command through. The row says `warn` — never `redact`,
    // which would claim a masking that did not happen.
    expect(result.action).toBe('warn');
    expect(result.redactDegradedTo).toBe(result.action);
    expect(result.text).toContain(IP);

    const emitted = JSON.stringify(
      decidePreToolUse('Bash', { command: INCIDENT_COMMAND }, [{ spec: BASH_COMMAND, result }]),
    );
    expect(emitted).toContain('AKA flagged sensitive content in Bash input');
    expect(emitted).not.toContain('updatedInput');
  });

  it('keeps true redaction on the REWRITABLE apply_patch field at the same settings', async () => {
    // The per-field split, end to end: the same workspace that let the command
    // through masks the stored patch in place, because that field can be
    // rewritten. A per-HOST flag would have lost this.
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const patch = `*** Update File: seed.md\n+host ${IP}\n`;
    const result = await rt.capture(
      { kind: 'code_change', sourceTool: SOURCE_TOOL.Codex, text: patch },
      { rewritable: true },
    );
    await rt.close();

    expect(result.action).toBe('redact');
    expect(result.redactDegradedTo).toBeUndefined();
    expect(result.text).not.toContain(IP);
  });

  it('drives the real ledger: the deny surfaces a concrete approve ref', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-codex-pre-tool-use-'));
    try {
      const rt = createPluginRuntime(fakeGateway(bundle()), settings('block'), { dataDir: dir });
      const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
      await rt.close();

      expect(result.action).toBe('block');
      const ref = result.blockedReferences?.[0]?.reference ?? '';
      expect(ref).toMatch(/^[0-9a-f]{6}$/);

      const output = decidePreToolUse('Bash', { command: INCIDENT_COMMAND }, [
        { spec: BASH_COMMAND, result },
      ]);
      const reason = denyReason(output);
      expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
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
    const output = decideInputPointerDeny('Bash', { command: `echo ${POINTER}` }, [BASH_COMMAND]);
    expect(output?.hookSpecificOutput.permissionDecision).toBe('deny');
    const reason = output?.hookSpecificOutput.permissionDecisionReason ?? '';
    expect(reason).toBe(denyPointerMessage('Bash'));
    // The reason tells the user how to proceed without ever suggesting the
    // plugin could substitute the value itself — the resolve path it names is
    // the audited CLI reveal, not an exception grant this harness cannot honor.
    expect(reason).toContain('aka vault show');
    expect(reason).not.toContain('aka exception approve');
  });

  it('lets a pointer in a NON-executable field pass to the normal scan', () => {
    // apply_patch content is durable text, not something the host executes —
    // a pointer there is data, decided by the regular capture pipeline.
    expect(
      decideInputPointerDeny('apply_patch', { input: `body ${POINTER}` }, [APPLY_PATCH_INPUT]),
    ).toBeNull();
  });

  it('ignores clean commands and lookalike tokens with an invented category', () => {
    expect(decideInputPointerDeny('Bash', { command: 'ls -la' }, [BASH_COMMAND])).toBeNull();
    // The category alternation is pinned to DetectionCategory members: a
    // lookalike must not trip the deny (it cannot reach a de-reference path
    // anywhere, so denying it would be pure friction).
    const lookalike = `[[aka:bogus:AA.${'A'.repeat(26)}.${'A'.repeat(16)}]]`;
    expect(
      decideInputPointerDeny('Bash', { command: `echo ${lookalike}` }, [BASH_COMMAND]),
    ).toBeNull();
  });
});

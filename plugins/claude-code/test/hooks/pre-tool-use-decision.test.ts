// Tests the pure PreToolUse decision module directly — NEVER via the hook
// entry file (src/hooks/*.ts run main() on import and hang vitest collection).
//
// The incident this file pins: while clearing seed data, a Bash `docker exec …
// psql -c` command inserted five host strings into a temp table and deleted
// share_destination rows matching them. The bundled core-pii/ip-address rule
// (default action: redact) matched the lone IP literal, the hook rewrote the
// command via `updatedInput`, and the spliced-in `[REDACTED:PII]` executed:
// the INSERT still reported 5 rows, the DELETE matched only the 4 domain
// hosts, and the IP rows silently survived. Masking executable text doesn't
// remove a value from what happens — it changes what happens. A redact
// decision on an executable field must therefore escalate to a deny; only
// stored text (Write/Edit content) is redacted in place.
//
// Every sensitive-looking literal below (the IP, the email) is ASSEMBLED AT
// RUNTIME instead of written contiguously: this repo is developed with the
// AKA plugin active, so a contiguous literal in this file would be redacted
// out of the test source the moment an agent writes it — which happened while
// authoring this very file, rewriting the fixtures AND inverting a
// `not.toContain(<ip>)` assertion into `not.toContain('[REDACTED:PII]')`.
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { CaptureResult, DataGateway } from '@akasecurity/plugin-sdk';
import { createPluginRuntime } from '@akasecurity/plugin-sdk';
import type { PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { PreToolUseOutput } from '../../src/hooks/pre-tool-use-decision.ts';
import {
  decidePreToolUse,
  EXECUTABLE_REDACT_NOTE,
  UNREDACTABLE_NOTE,
} from '../../src/hooks/pre-tool-use-decision.ts';
import type { ScannableField } from '../../src/hooks/pre-tool-use-fields.ts';

const IP = ['45', '79', '142', '6'].join('.');
const EMAIL = ['user1', 'example.com'].join('@');
const EMAIL2 = ['user2', 'example.org'].join('@');

const BASH_COMMAND: ScannableField = { path: ['command'], executable: true };
const WRITE_CONTENT: ScannableField = { path: ['content'], executable: false };
const WEBFETCH_URL: ScannableField = { path: ['url'], executable: true };
const WEBFETCH_PROMPT: ScannableField = { path: ['prompt'], executable: false };

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

// The decision is async now (it may tokenize); these tests exercise the
// pre-vault paths, so unwrap the payload and default the scanned text.
// What the runtime hands this module for an EXECUTABLE field, which the hook
// captures with `rewritable: false`: the policy resolved to `redact`, no
// masking was possible, and the action is the workspace's `redactFallback`.
// `redactDegraded` is what says so — without it this is indistinguishable from
// a policy that genuinely said `warn`.
//
// `redactResult` above stays the shape for a DATA field, which is rewritable
// and keeps true redaction (including the reversible vault rewrite). The two
// helpers are the per-field split.
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
    redactDegraded: true,
    ...(reference ? { blockedReferences: [{ reference, ruleId, maskedValue: '4******6' }] } : {}),
  };
}

async function decide(
  toolName: string,
  toolInput: Record<string, unknown>,
  scanned: { spec: ScannableField; result: CaptureResult; text?: string }[],
): Promise<PreToolUseOutput | null> {
  const decision = await decidePreToolUse(
    toolName,
    toolInput,
    scanned.map((s) => ({ spec: s.spec, result: s.result, text: s.text ?? '' })),
  );
  return decision?.output ?? null;
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

// The per-tool field map moved to pre-tool-use-fields.ts; its executable-flag
// guard lives in pre-tool-use-fields.test.ts alongside it.

describe('decidePreToolUse — redact on executable text escalates to deny', () => {
  const COMMAND = `psql -c "DELETE FROM share_destination WHERE host = '${IP}';"`;

  it('denies the Bash call under a block fallback, and says masking was not possible', async () => {
    const result = degradedRedact('block', COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const output = await decide('Bash', { command: COMMAND }, [{ spec: BASH_COMMAND, result }]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this Bash call — flagged core-pii/ip-address');
    // The deny explains why the policy's redact did not rewrite in place…
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    // …and keeps the approve escape hatch (the runtime ledgers redacted
    // values too, so the ref is available).
    expect(reason).toContain('aka exception approve 3f2a91');
    // The rewritten command must not ship anywhere in the payload.
    expect(JSON.stringify(output)).not.toContain('updatedInput');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('folds an escalated redact into a true block on another field: one deny, both rules', async () => {
    const blockText = 'curl -H "x: SECRET"';
    const blocked: CaptureResult = {
      action: 'block',
      text: null,
      findings: [finding('secrets-infra/db-connection-string', 'SECRET', blockText)],
      blockedReferences: [
        { reference: 'aa11bb', ruleId: 'secrets-infra/db-connection-string', maskedValue: 'S***T' },
      ],
    };
    const output = await decide('Bash', { command: COMMAND }, [
      { spec: { path: ['other'], executable: true }, result: blocked },
      {
        spec: BASH_COMMAND,
        result: degradedRedact('block', COMMAND, 'core-pii/ip-address', IP),
      },
    ]);

    const reason = denyReason(output);
    expect(reason).toContain('secrets-infra/db-connection-string, core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve aa11bb');
    expect(JSON.stringify(output)).not.toContain('updatedInput');
  });

  it('a plain block (no escalation) carries no escalation note', async () => {
    const blocked: CaptureResult = {
      action: 'block',
      text: null,
      findings: [finding('secrets-infra/db-connection-string', IP, COMMAND)],
    };
    const reason = denyReason(
      await decide('Bash', { command: COMMAND }, [{ spec: BASH_COMMAND, result: blocked }]),
    );
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);
  });
});

describe('decidePreToolUse — a redact with no redacted text denies', () => {
  // CaptureResult.text is `string | null`, so { action: 'redact', text: null }
  // is protocol-legal. Allowing it emitted the ORIGINAL toolInput under the
  // "AKA redacted sensitive content" systemMessage — raw value sent, transcript
  // claiming it was masked. Checked after the tokenizer runs, since a null
  // `text` can still yield redacted text through it.
  it('Write content: denies rather than allowing the original through', async () => {
    const content = `support = ${EMAIL}`;
    const output = await decide('Write', { content, file_path: '/tmp/a.ts' }, [
      {
        spec: WRITE_CONTENT,
        result: {
          action: 'redact',
          text: null,
          findings: [finding('core-pii/email', EMAIL, content)],
        },
        text: content,
      },
    ]);

    const reason = denyReason(output);
    expect(reason).toContain(UNREDACTABLE_NOTE);
    expect(reason).not.toContain(EXECUTABLE_REDACT_NOTE);

    const emitted = JSON.stringify(output);
    expect(emitted).not.toContain('updatedInput');
    expect(emitted).not.toContain('AKA redacted');
    expect(emitted).not.toContain(EMAIL);
  });
});

describe('decidePreToolUse — stored text keeps true redaction', () => {
  it('Write content: allow with the redacted field in updatedInput', async () => {
    const content = `support = ${EMAIL}`;
    const result = redactResult(content, 'core-pii/email', EMAIL, '9c04d7');
    const output = await decide('Write', { content, file_path: '/tmp/a.ts' }, [
      { spec: WRITE_CONTENT, result },
    ]);

    // Both discriminants present ⇒ the allow+updatedInput variant.
    if (output === null || !('hookSpecificOutput' in output) || !('systemMessage' in output)) {
      throw new Error('expected an allow decision with updatedInput');
    }
    expect(output.hookSpecificOutput.permissionDecision).toBe('allow');
    // The redacted text replaces the field; untouched fields ride along.
    expect(output.hookSpecificOutput.updatedInput).toEqual({
      content: 'support = [REDACTED:PII]',
      file_path: '/tmp/a.ts',
    });
    expect(output.systemMessage).toBe(
      'AKA redacted sensitive content in Write input — flagged core-pii/email.' +
        ' To allow this exact value intentionally, run: aka exception approve 9c04d7.',
    );
  });

  it('warn stays a systemMessage; no findings stays silent', async () => {
    const text = 'uses share_destination table';
    const warned: CaptureResult = {
      action: 'warn',
      text,
      findings: [finding('core-code-context/db-table-name', 'share_destination', text)],
    };
    const output = await decide('Bash', { command: text }, [
      { spec: BASH_COMMAND, result: warned },
    ]);
    expect(output).toEqual({
      systemMessage:
        'AKA flagged sensitive content in Bash input (core-code-context/db-table-name).',
    });

    const clean: CaptureResult = { action: 'log', text, findings: [] };
    expect(
      await decide('Bash', { command: text }, [{ spec: BASH_COMMAND, result: clean }]),
    ).toBeNull();
  });
});

describe('decidePreToolUse — WebFetch, the pre-execution exfil channel', () => {
  it('a redact on the url denies under a block fallback: the request leaves with neither the value nor a mask', async () => {
    // A secret spliced into the fetched URL is gone the moment the request is
    // made — post-hooks are too late — and a masked URL silently requests a
    // different resource. Deny is the only decision that is both visible and
    // at least as strong as the policy, which is why `block` is the fallback to
    // choose for this surface. Under the shipped `warn` it goes out; the case
    // below pins that, because it is the setting's whole consequence.
    const url = `https://${IP}/collect?src=aka`;
    const result = degradedRedact('block', url, 'core-pii/ip-address', IP, '7b20c4');
    const output = await decide('WebFetch', { url, prompt: 'summarize' }, [
      { spec: WEBFETCH_URL, result },
    ]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this WebFetch call — flagged core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve 7b20c4');
    expect(JSON.stringify(output)).not.toContain('updatedInput');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('the analysis prompt is stored text: redacted in place, url rides along unchanged', async () => {
    const prompt = `find mentions of ${EMAIL} in this page`;
    const result = redactResult(prompt, 'core-pii/email', EMAIL);
    const output = await decide('WebFetch', { url: 'https://docs.example.com', prompt }, [
      { spec: WEBFETCH_PROMPT, result },
    ]);

    if (output === null || !('hookSpecificOutput' in output) || !('systemMessage' in output)) {
      throw new Error('expected an allow decision with updatedInput');
    }
    expect(output.hookSpecificOutput.permissionDecision).toBe('allow');
    expect(output.hookSpecificOutput.updatedInput).toEqual({
      url: 'https://docs.example.com',
      prompt: 'find mentions of [REDACTED:PII] in this page',
    });
    expect(output.systemMessage).toContain(
      'AKA redacted sensitive content in WebFetch input — flagged core-pii/email.',
    );
  });

  it('end to end through the real runtime under a block fallback: denied, never fetched masked', async () => {
    // Driven through `capture` with `rewritable: false` — the call the hook
    // really makes for a url — rather than `processText`, which takes no such
    // option and so cannot exercise the degrade at all.
    const rt = createPluginRuntime(fakeGateway(bundle()), settings('block'));
    const url = `https://${IP}/ingest?d=payload`;
    const result = await rt.capture(
      { kind: 'tool_use', sourceTool: SOURCE_TOOL.ClaudeCode, text: url },
      { rewritable: false },
    );
    await rt.close();

    // The runtime refused: the real bundled rule matches inside the URL, the
    // default pii action asks for a redact, and a url cannot carry one.
    expect(result.action).toBe('block');
    expect(result.redactDegraded).toBe(true);
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');

    const output = await decide('WebFetch', { url, prompt: 'summarize' }, [
      { spec: WEBFETCH_URL, result },
    ]);
    const reason = denyReason(output);
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain('updatedInput');
  });

  it('THE REQUEST GOES OUT, value intact, under the shipped warn fallback', async () => {
    // The sharpest consequence of the shipped default, pinned so it cannot be
    // discovered in the field: a url carrying a detected value used to be
    // denied unconditionally, and now leaves the machine unless the workspace
    // sets `redactFallback: 'block'`. Post-hooks are too late for a fetch, so
    // nothing downstream recovers this.
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const url = `https://${IP}/ingest?d=payload`;
    const result = await rt.capture(
      { kind: 'tool_use', sourceTool: SOURCE_TOOL.ClaudeCode, text: url },
      { rewritable: false },
    );
    await rt.close();

    expect(result.action).toBe('warn');
    expect(result.redactDegraded).toBe(true);

    const output = await decide('WebFetch', { url, prompt: 'summarize' }, [
      { spec: WEBFETCH_URL, result },
    ]);
    const emitted = JSON.stringify(output);
    expect(emitted).toContain('AKA flagged sensitive content in WebFetch input');
    expect(emitted).not.toContain('updatedInput');
  });
});

// ─── End-to-end incident regression, through the REAL runtime ───────────────
// Real bundled rule packs, a real redact splice — then the decision module
// must turn it into a deny. The cold-start category floor no longer resolves
// pii to redact by default, so this fixture pins the incident's actual
// enforcement posture explicitly: a `pii` category policy set to `redact`,
// exactly as an operator's own policy would. If a rule or the redact action
// changes out from under this, the precondition assertions say which half
// moved.

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

// A fake gateway mirroring @akasecurity/plugin-sdk's runtime tests: fixed policy
// bundle, no-op writes.
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

  const command = (text: string) =>
    ({ kind: 'tool_use', sourceTool: SOURCE_TOOL.ClaudeCode, text }) as const;

  it('resolves the redact to a deny INSIDE the runtime under a block fallback', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings('block'));
    const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
    await rt.close();

    // The incident's first half: core-pii/ip-address matches the lone IP
    // literal and the default pii action asks for a redact. Its second half is
    // impossible because the RUNTIME refused — one value for the emitted
    // decision and the recorded action, where the hook used to deny while the
    // row said `redact`.
    expect(result.action).toBe('block');
    expect(result.redactDegraded).toBe(true);
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');

    const output = await decide('Bash', { command: INCIDENT_COMMAND }, [
      { spec: BASH_COMMAND, result },
    ]);
    const reason = denyReason(output);
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain('updatedInput');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('LETS THE SPLICED COMMAND RUN under the shipped warn fallback', async () => {
    // The incident this suite is named for, under the shipped default. The
    // command runs with the IP intact and the user sees a systemMessage. That
    // is the setting working as decided, not a regression — and it is why this
    // case exists rather than the behaviour being left to be discovered.
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
    await rt.close();

    expect(result.action).toBe('warn');
    expect(result.redactDegraded).toBe(true);
    expect(result.text).toContain(IP);

    const emitted = JSON.stringify(
      await decide('Bash', { command: INCIDENT_COMMAND }, [{ spec: BASH_COMMAND, result }]),
    );
    expect(emitted).toContain('AKA flagged sensitive content in Bash input');
    expect(emitted).not.toContain('updatedInput');
  });

  it('drives the real ledger: the escalated deny surfaces a concrete approve ref', async () => {
    // The whole reason to escalate (rather than plain-deny) is that the runtime
    // ledgers the redacted value, so `aka exception approve <ref>` stays usable
    // on the Bash path. The test above threads a SYNTHETIC ref; this one runs
    // the REAL runtime with a real dataDir so it mints a fingerprint key and
    // records the blocked detection, then asserts the escalated deny surfaces
    // THAT concrete ledger reference — closing the loop end to end.
    const dir = mkdtempSync(join(tmpdir(), 'aka-pre-tool-use-'));
    try {
      const rt = createPluginRuntime(fakeGateway(bundle()), settings('block'), { dataDir: dir });
      const result = await rt.capture(command(INCIDENT_COMMAND), { rewritable: false });
      await rt.close();

      expect(result.action).toBe('block');
      // Default to '' so the type narrows to string; the 6-hex regex below still
      // fails loudly if the runtime produced no ledger reference.
      const ref = result.blockedReferences?.[0]?.reference ?? '';
      // A concrete 6-hex ledger reference — not the bare degraded approve form.
      expect(ref).toMatch(/^[0-9a-f]{6}$/);

      const output = await decide('Bash', { command: INCIDENT_COMMAND }, [
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

// The hook-level half of the Redact & Vault archetype: the decision module is
// what turns a CaptureResult's per-finding custody split into the argument the
// vault glue actually receives. Nothing else can see that hand-off — the runtime
// tests prove the split is COMPUTED, and the tokenize tests prove the glue
// HONOURS it, but a decision module that dropped the third argument would leave
// both green while vaulting every redacted value on the machine.
describe('decidePreToolUse — passes the custody split to the tokenizer', () => {
  const TEXT = `contact ${EMAIL} and ${EMAIL2}`;

  function mixedResult(): CaptureResult {
    const a = finding('pii/email-a', EMAIL, TEXT);
    const b = finding('pii/email-b', EMAIL2, TEXT);
    return {
      action: 'redact',
      text: TEXT.replace(EMAIL, '[REDACTED:PII]').replace(EMAIL2, '[REDACTED:PII]'),
      findings: [a, b],
      enforcedFindings: [a, b],
      // Only the first detection chose Redact & Vault.
      reversibleFindings: [a],
    };
  }

  it('hands the tokenizer exactly the reversible subset, not every enforced finding', async () => {
    const seen: { findings: unknown[]; reversible: ReadonlySet<unknown> }[] = [];
    await decidePreToolUse(
      'Write',
      { content: TEXT },
      [{ spec: WRITE_CONTENT, result: mixedResult(), text: TEXT }],
      (text, findings, reversible) => {
        seen.push({ findings: [...findings], reversible });
        return Promise.resolve({ text, pointers: [], degraded: [] });
      },
    );

    expect(seen).toHaveLength(1);
    const call = seen[0];
    if (call === undefined) throw new Error('the tokenizer was never called');
    // Every enforced span is handed over — the tokenizer performs the WHOLE
    // rewrite, so a narrower list would leave the other value in the clear.
    expect(call.findings).toHaveLength(2);
    // …and exactly one of them is marked to keep.
    expect(call.reversible.size).toBe(1);
  });

  it('passes an EMPTY reversible set when no detection chose to keep', async () => {
    // The default posture. A decision module defaulting to "all" here would
    // vault every redacted value on a machine that never asked for it.
    const result = mixedResult();
    const noneReversible: CaptureResult = { ...result, reversibleFindings: [] };
    let captured: ReadonlySet<unknown> | undefined;
    await decidePreToolUse(
      'Write',
      { content: TEXT },
      [{ spec: WRITE_CONTENT, result: noneReversible, text: TEXT }],
      (text, _findings, reversible) => {
        captured = reversible;
        return Promise.resolve({ text, pointers: [], degraded: [] });
      },
    );
    expect(captured?.size).toBe(0);
  });

  it('passes an EMPTY set when the field is absent (an older runtime)', async () => {
    // Built without the field rather than destructured away, so nothing here
    // relies on an unused binding to express "absent".
    const { findings, text, ...rest } = mixedResult();
    const withoutField: CaptureResult = {
      action: rest.action,
      text,
      findings,
      enforcedFindings: rest.enforcedFindings ?? [],
    };
    let captured: ReadonlySet<unknown> | undefined;
    await decidePreToolUse(
      'Write',
      { content: TEXT },
      [{ spec: WRITE_CONTENT, result: withoutField, text: TEXT }],
      (text, _findings, reversible) => {
        captured = reversible;
        return Promise.resolve({ text, pointers: [], degraded: [] });
      },
    );
    // Absent must mean "keep nothing": destroying a value that could have been
    // recovered is recoverable-from; retaining one the policy said to destroy is not.
    expect(captured?.size).toBe(0);
  });
});

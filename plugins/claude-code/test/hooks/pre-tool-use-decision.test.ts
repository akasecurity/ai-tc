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
import { describe, expect, it } from 'vitest';

import type { PreToolUseOutput } from '../../src/hooks/pre-tool-use-decision.ts';
import { decidePreToolUse, EXECUTABLE_REDACT_NOTE } from '../../src/hooks/pre-tool-use-decision.ts';
import type { ScannableField } from '../../src/hooks/pre-tool-use-fields.ts';

const IP = ['45', '79', '142', '6'].join('.');
const EMAIL = ['user1', 'example.com'].join('@');

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

  it('denies the Bash call instead of rewriting the command', () => {
    const result = redactResult(COMMAND, 'core-pii/ip-address', IP, '3f2a91');
    const output = decidePreToolUse('Bash', { command: COMMAND }, [{ spec: BASH_COMMAND, result }]);

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

  it('folds an escalated redact into a true block on another field: one deny, both rules', () => {
    const blockText = 'curl -H "x: SECRET"';
    const blocked: CaptureResult = {
      action: 'block',
      text: null,
      findings: [finding('secrets-infra/db-connection-string', 'SECRET', blockText)],
      blockedReferences: [
        { reference: 'aa11bb', ruleId: 'secrets-infra/db-connection-string', maskedValue: 'S***T' },
      ],
    };
    const output = decidePreToolUse('Bash', { command: COMMAND }, [
      { spec: { path: ['other'], executable: true }, result: blocked },
      { spec: BASH_COMMAND, result: redactResult(COMMAND, 'core-pii/ip-address', IP) },
    ]);

    const reason = denyReason(output);
    expect(reason).toContain('secrets-infra/db-connection-string, core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve aa11bb');
    expect(JSON.stringify(output)).not.toContain('updatedInput');
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

describe('decidePreToolUse — stored text keeps true redaction', () => {
  it('Write content: allow with the redacted field in updatedInput', () => {
    const content = `support = ${EMAIL}`;
    const result = redactResult(content, 'core-pii/email', EMAIL, '9c04d7');
    const output = decidePreToolUse('Write', { content, file_path: '/tmp/a.ts' }, [
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

describe('decidePreToolUse — WebFetch, the pre-execution exfil channel', () => {
  it('a redact on the url escalates to deny: the request must not leave with OR without the value', () => {
    // A secret spliced into the fetched URL is gone the moment the request is
    // made — post-hooks are too late — and a masked URL silently requests a
    // different resource. Deny is the only decision that is both visible and
    // at least as strong as the policy.
    const url = `https://${IP}/collect?src=aka`;
    const result = redactResult(url, 'core-pii/ip-address', IP, '7b20c4');
    const output = decidePreToolUse('WebFetch', { url, prompt: 'summarize' }, [
      { spec: WEBFETCH_URL, result },
    ]);

    const reason = denyReason(output);
    expect(reason).toContain('AKA blocked this WebFetch call — flagged core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(reason).toContain('aka exception approve 7b20c4');
    expect(JSON.stringify(output)).not.toContain('updatedInput');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
  });

  it('the analysis prompt is stored text: redacted in place, url rides along unchanged', () => {
    const prompt = `find mentions of ${EMAIL} in this page`;
    const result = redactResult(prompt, 'core-pii/email', EMAIL);
    const output = decidePreToolUse('WebFetch', { url: 'https://docs.example.com', prompt }, [
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

  it('end to end through the real runtime: a URL carrying a detected value is denied, never fetched masked', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const url = `https://${IP}/ingest?d=payload`;
    const result = await rt.processText(url);
    await rt.close();

    // Precondition: the real bundled rule matches inside the URL and the
    // default pii action splices it.
    expect(result.action).toBe('redact');
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');

    const output = decidePreToolUse('WebFetch', { url, prompt: 'summarize' }, [
      { spec: WEBFETCH_URL, result },
    ]);
    const reason = denyReason(output);
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain('updatedInput');
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

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
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

    // Precondition — the incident's first half: core-pii/ip-address matches
    // the lone IP literal and the default pii action splices the SQL.
    expect(result.action).toBe('redact');
    expect(result.findings.map((f) => f.ruleId)).toContain('core-pii/ip-address');
    expect(result.text).not.toContain(IP);
    expect(result.text).toContain('[REDACTED:PII]');

    // The fix — the incident's second half must be impossible: the decision
    // is a deny, and the spliced command never leaves the hook.
    const output = decidePreToolUse('Bash', { command: INCIDENT_COMMAND }, [
      { spec: BASH_COMMAND, result },
    ]);
    const reason = denyReason(output);
    expect(reason).toContain('core-pii/ip-address');
    expect(reason).toContain(EXECUTABLE_REDACT_NOTE);
    expect(JSON.stringify(output)).not.toContain('updatedInput');
    expect(JSON.stringify(output)).not.toContain('[REDACTED');
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
      const rt = createPluginRuntime(fakeGateway(bundle()), settings(), { dataDir: dir });
      const result = await rt.processText(INCIDENT_COMMAND);
      await rt.close();

      expect(result.action).toBe('redact');
      // Default to '' so the type narrows to string; the 6-hex regex below still
      // fails loudly if the runtime produced no ledger reference.
      const ref = result.blockedReferences?.[0]?.reference ?? '';
      // A concrete 6-hex ledger reference — not the bare degraded approve form.
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

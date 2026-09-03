import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PolicyBundle, Rule, WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { CaptureRecord, DataGateway } from '../src/data-gateway.ts';
import { contentHashOf } from '../src/events.ts';
import { registerRulePack } from '../src/rule-packs.ts';
import { createPluginRuntime } from '../src/runtime.ts';

// Markers resolved by DEFAULT_ACTIONS (secret: warn, pii: warn) when the
// bundle carries no explicit policy. Registered into the global bundled packs.
registerRulePack('test-pack', [
  {
    specVersion: 1,
    id: 'test/secret-marker',
    name: 'Test secret marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['SECRET_MARKER'] },
    examples: ['SECRET_MARKER'],
  },
  {
    specVersion: 1,
    id: 'test/pii-marker',
    name: 'Test PII marker',
    category: 'pii',
    severity: 'medium',
    matcher: { type: 'keyword', keywords: ['PII_MARKER'] },
    examples: ['PII_MARKER'],
  },
  // Two markers whose spans PARTIALLY overlap on the text below — neither
  // contains the other, and each carries bytes the other does not. That is the
  // shape redact()'s region folding has to survive; a containment pair would
  // pass whether or not the folding worked.
  {
    specVersion: 1,
    id: 'test/overlap-left',
    name: 'Test overlap left',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['AAA_BBB'] },
    examples: ['AAA_BBB'],
  },
  {
    specVersion: 1,
    id: 'test/overlap-right',
    name: 'Test overlap right',
    category: 'pii',
    severity: 'low',
    matcher: { type: 'keyword', keywords: ['BBB_CCC'] },
    examples: ['BBB_CCC'],
  },
]);

// A rule that exists ONLY in a pulled bundle (not in the bundled packs), used to
// prove getPolicyBundle().rules are registered into the engine.
const PULLED_RULE: Rule = {
  specVersion: 1,
  id: 'pulled/secret-marker',
  name: 'Pulled secret marker',
  category: 'secret',
  severity: 'critical',
  matcher: { type: 'keyword', keywords: ['PULLED_MARKER'], caseSensitive: false },
  examples: ['PULLED_MARKER'],
};

function settings(policy: 'redact' | 'warn' = 'redact'): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy,
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    redactFallback: 'warn',
  };
}

function bundle(rules: Rule[] = []): PolicyBundle {
  return {
    version: 'test',
    policies: [],
    rules,
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

// A fake gateway: returns a fixed bundle and records every recordCapture call.
function fakeGateway(b: PolicyBundle): DataGateway & { records: CaptureRecord[] } {
  const records: CaptureRecord[] = [];
  return {
    records,
    recordCapture: (record) => {
      records.push(record);
      return Promise.resolve();
    },
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
    getRuleProbeVerdict: () => Promise.resolve(undefined),
    setRuleProbeVerdict: () => Promise.resolve(),
    openAtRestKeysForPath: () => Promise.resolve([]),
    resolvedAtRestKeysForPath: () => Promise.resolve([]),
    insertResolution: () => Promise.resolve(),
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

describe('createPluginRuntime — decisions from the pulled bundle (DEFAULT_ACTIONS fallback)', () => {
  it('passes benign text through as log', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    expect(await rt.processText('nothing to see here')).toMatchObject({
      action: 'log',
      text: 'nothing to see here',
    });
    await rt.close();
  });

  it('warns on secrets by default (severity-floor cold start)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const result = await rt.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('warn');
    expect(result.text).toBe('deploy with SECRET_MARKER now');
    expect(result.findings.map((f) => f.ruleId)).toContain('test/secret-marker');
    await rt.close();
  });

  it('warns on PII by default (severity-floor cold start)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    expect(await rt.processText('contact PII_MARKER please')).toMatchObject({
      action: 'warn',
      text: 'contact PII_MARKER please',
    });
    await rt.close();
  });

  it('per-category policy still hard-enforces under settings.policy warn (ceiling retired)', async () => {
    const rt = createPluginRuntime(
      fakeGateway({
        ...bundle(),
        policies: [
          {
            id: randomUUID(),
            scope: 'global',
            target: { category: 'secret' },
            action: 'block',
            enabled: true,
          },
        ],
      }),
      settings('warn'),
    );
    const result = await rt.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('block');
    expect(result.text).toBeNull();
    await rt.close();
  });
});

// A ruleId-targeted policy is how the standalone gateway carries a detection's
// per-detection Monitor/Warn/Redact/Block assignment (installed_packs.policy_id)
// into enforcement. It must win over both the category default and an explicit
// category policy — otherwise "set this detection to Monitor" never takes effect.
describe('createPluginRuntime — per-detection (ruleId-targeted) policies', () => {
  function bundleWithPolicies(policies: PolicyBundle['policies']): PolicyBundle {
    return { ...bundle(), policies };
  }

  it('downgrades a would-be block to log when the rule is set to Monitor', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '11111111-1111-4111-8111-111111111111',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'log',
            enabled: true,
          },
        ]),
      ),
      settings(),
    );
    // Without the ruleId policy this secret would warn (DEFAULT_ACTIONS); the
    // Monitor assignment takes it down to log.
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'log',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
  });

  it('a ruleId policy beats an explicit category policy for the same category', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '22222222-2222-4222-8222-222222222222',
            scope: 'global',
            target: { category: 'secret' },
            action: 'block',
            enabled: true,
          },
          {
            id: '33333333-3333-4333-8333-333333333333',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'log',
            enabled: true,
          },
        ]),
      ),
      settings(),
    );
    expect((await rt.processText('deploy with SECRET_MARKER now')).action).toBe('log');
    await rt.close();
  });

  it('falls back to the category default when the ruleId policy is disabled', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '44444444-4444-4444-8444-444444444444',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'log',
            enabled: false,
          },
        ]),
      ),
      settings(),
    );
    // Disabled → ignored → secret warns via DEFAULT_ACTIONS.
    expect((await rt.processText('deploy with SECRET_MARKER now')).action).toBe('warn');
    await rt.close();
  });

  it('collapses mixed Block + Monitor detections in one input to the worst action (block)', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '55555555-5555-4555-8555-555555555555',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'block',
            enabled: true,
          },
          {
            id: '66666666-6666-4666-8666-666666666666',
            scope: 'global',
            target: { ruleId: 'test/pii-marker' },
            action: 'log',
            enabled: true,
          },
        ]),
      ),
      settings(),
    );
    // One input trips both a Block detection and a Monitor detection → block wins.
    const result = await rt.processText('SECRET_MARKER and PII_MARKER together');
    expect(result.action).toBe('block');
    expect(result.text).toBeNull();
    await rt.close();
  });
});

describe('rules pull', () => {
  it('detects with rules pulled from the bundle (not just bundled packs)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([PULLED_RULE])), settings());
    const result = await rt.processText('ship PULLED_MARKER today');
    expect(result.action).toBe('warn');
    expect(result.findings.map((f) => f.ruleId)).toContain('pulled/secret-marker');
    await rt.close();
  });
});

describe('rulesComplete — the bundle rules replace the compiled-in packs', () => {
  it('scans ONLY the bundle rules when the bundle marks them complete', async () => {
    const complete = { ...bundle([PULLED_RULE]), rulesComplete: true };
    const rt = createPluginRuntime(fakeGateway(complete), settings());
    // The bundled test-pack marker is NOT in the complete ruleset → passes through.
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'log',
      text: 'deploy with SECRET_MARKER now',
    });
    // The snapshot rule still detects.
    const result = await rt.processText('ship PULLED_MARKER today');
    expect(result.action).toBe('warn');
    expect(result.findings.map((f) => f.ruleId)).toContain('pulled/secret-marker');
    await rt.close();
  });

  it('respects a complete-and-empty ruleset (user disabled every pack)', async () => {
    const rt = createPluginRuntime(fakeGateway({ ...bundle([]), rulesComplete: true }), settings());
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'log',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
  });

  it('keeps bundled packs when rulesComplete is absent (historical composition)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([])), settings());
    const result = await rt.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('warn');
    await rt.close();
  });
});

// The collapse across a capture's findings used to index a hand-listed
// worst-first array private to the runtime; it now asks the one schema ladder.
// The orderings are the same fact, so the only thing worth pinning is that the
// fact did not move: strongest wins, whichever finding carries it.
describe('decision collapse — strongest action wins', () => {
  const rungs = [
    { weaker: 'allow', stronger: 'log' },
    { weaker: 'log', stronger: 'warn' },
    { weaker: 'warn', stronger: 'redact' },
    { weaker: 'redact', stronger: 'block' },
  ] as const;

  for (const { weaker, stronger } of rungs) {
    it(`picks ${stronger} over ${weaker}, whichever finding carries it`, async () => {
      // Run it both ways round: the collapse must not depend on the order the
      // scan happened to emit the findings in.
      for (const [secretAction, piiAction] of [
        [stronger, weaker],
        [weaker, stronger],
      ] as const) {
        const b = bundle();
        b.policies = [
          {
            id: randomUUID(),
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: secretAction,
            enabled: true,
          },
          {
            id: randomUUID(),
            scope: 'global',
            target: { ruleId: 'test/pii-marker' },
            action: piiAction,
            enabled: true,
          },
        ];
        const rt = createPluginRuntime(fakeGateway(b), settings());
        const result = await rt.processText('deploy with SECRET_MARKER and PII_MARKER now');
        await rt.close();
        expect(result.action).toBe(stronger);
      }
    });
  }

  it("floors at 'log' when every finding resolved to allow", async () => {
    // 'allow' is weaker than the floor the collapse starts from, so a capture
    // made entirely of allowed findings still reports the benign 'log' — an
    // allowed value is recorded, never announced as an enforcement decision.
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { category: 'secret' },
        action: 'allow',
        enabled: true,
      },
    ];
    const rt = createPluginRuntime(fakeGateway(b), settings());
    const result = await rt.processText('deploy with SECRET_MARKER now');
    await rt.close();
    expect(result.action).toBe('log');
    expect(result.findings).toHaveLength(1);
  });
});

describe('capture', () => {
  it('records the event + masked findings and returns the same decision', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
    });
    expect(result.action).toBe('warn');
    await rt.close();

    expect(gw.records).toHaveLength(1);
    const record = gw.records[0];
    expect(record?.findings).toHaveLength(1);
    expect(record?.findings[0]?.ruleId).toBe('test/secret-marker');
    expect(record?.findings[0]?.actionTaken).toBe('warn');
    // The raw secret is masked before it reaches the gateway.
    expect(record?.findings[0]?.maskedMatch).not.toContain('SECRET_MARKER');
    // Warn only warns: the value crossed intact, so the stored record shows it
    // intact. Masking here would describe a stricter capture than the one that
    // happened. content_hash is of the original either way.
    expect(record?.event.content).toBe('deploy with SECRET_MARKER now');
    expect(record?.event.contentHash).toBe(contentHashOf('deploy with SECRET_MARKER now'));
  });

  it('masks the at-rest content only for findings whose own action is redact or stronger', async () => {
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'test/secret-marker' },
        action: 'redact',
        enabled: true,
      },
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'test/pii-marker' },
        action: 'log',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings());
    const text = 'deploy with SECRET_MARKER and PII_MARKER now';
    await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text });
    await rt.close();

    const content = gw.records[0]?.event.content;
    // The redacted detection's span is gone...
    expect(content).not.toContain('SECRET_MARKER');
    // ...and the positive control on the SAME bytes: a Monitor detection was
    // asked to log the value, not strip it, so its span is still there. Without
    // this the absence assertion above would also pass on an empty string.
    expect(content).toContain('PII_MARKER');
    expect(content).toContain('[REDACTED:SECRET]');
    // Hashed over the ORIGINAL, whatever was masked.
    expect(gw.records[0]?.event.contentHash).toBe(contentHashOf(text));
  });

  it('masks a block-action finding at rest — block outranks redact', async () => {
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'test/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();

    const content = gw.records[0]?.event.content;
    expect(content).not.toContain('SECRET_MARKER');
    // Positive control on the same bytes: the surrounding text survived, so the
    // absence above is a mask and not an empty or wholesale-destroyed record.
    expect(content).toContain('deploy with ');
    expect(content).toContain('[REDACTED:SECRET]');
  });

  // engine.redact() folds OVERLAPPING findings into one region covering their
  // union, so narrowing the input to the redact-or-stronger findings could in
  // principle leave a masked span only PARTLY covered — a security regression
  // that would read as a smaller placeholder. It cannot: every finding handed
  // to redact() lies wholly inside a region, and dropping the log-action
  // neighbour only shrinks the region back to the masked span itself.
  it('fully masks a redact-action span that overlaps a log-action span', async () => {
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'test/overlap-left' },
        action: 'redact',
        enabled: true,
      },
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'test/overlap-right' },
        action: 'log',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings());
    // 'AAA_BBB' spans [2,9) and 'BBB_CCC' spans [6,13): they share 'BBB' and
    // each keeps bytes of its own.
    const text = 'x AAA_BBB_CCC y';
    const result = await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text });
    await rt.close();

    // Both rules matched, at their own actions.
    const byRule = new Map(gw.records[0]?.findings.map((f) => [f.ruleId, f.actionTaken] as const));
    expect(byRule.get('test/overlap-left')).toBe('redact');
    expect(byRule.get('test/overlap-right')).toBe('log');
    const content = gw.records[0]?.event.content;
    // Not one character of the redact-action span survives — neither its own
    // head 'AAA' nor the 'BBB' it shares with the log-action span.
    expect(content).not.toContain('AAA');
    expect(content).not.toContain('BBB');
    expect(content).toContain('[REDACTED:SECRET]');
    // Positive controls on the same bytes: the record is a real masked capture
    // rather than an empty or wholesale-destroyed one, the log-action span's
    // own tail survived, and the capture itself did redact.
    expect(content).toContain('x ');
    expect(content).toContain('_CCC y');
    expect(result.action).toBe('redact');
  });

  it('records each finding at its own action, not the capture-wide decision', async () => {
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { category: 'secret' },
        action: 'block',
        enabled: true,
      },
      {
        id: randomUUID(),
        scope: 'global',
        target: { category: 'pii' },
        action: 'warn',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER and PII_MARKER now',
    });
    await rt.close();

    // The capture as a whole collapses worst-first to 'block'...
    expect(result.action).toBe('block');
    // ...but the PII match only warns, so it is recorded as 'warn'.
    const byRule = new Map(gw.records[0]?.findings.map((f) => [f.ruleId, f.actionTaken] as const));
    expect(byRule.get('test/secret-marker')).toBe('block');
    expect(byRule.get('test/pii-marker')).toBe('warn');
  });

  it('stamps the supplied occurredAt on the event (historical backfill)', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const occurredAt = '2026-05-01T09:00:00.000Z';
    await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER',
      occurredAt,
    });
    await rt.close();
    expect(gw.records[0]?.event.occurredAt).toBe(occurredAt);
  });

  it("persist 'with-findings' skips benign text but records hits", async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture(
      { kind: 'prompt', sourceTool: 'claude-code', text: 'nothing here' },
      {
        persist: 'with-findings',
      },
    );
    expect(gw.records).toHaveLength(0); // benign → nothing stored
    await rt.capture(
      { kind: 'prompt', sourceTool: 'claude-code', text: 'SECRET_MARKER' },
      {
        persist: 'with-findings',
      },
    );
    expect(gw.records).toHaveLength(1); // a hit → recorded
    await rt.close();
  });
});

describe('capture — added-latency measurement (metadata.inspectionMs)', () => {
  it('stamps a whole-millisecond measurement on a live capture', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text: 'SECRET_MARKER' });
    await rt.close();

    const inspectionMs = gw.records[0]?.event.metadata?.inspectionMs;
    // Asserted as a SHAPE, never against an elapsed budget — what a scan costs
    // is the runner's business, and a millisecond ceiling here would be a
    // measurement of the machine rather than of this code.
    expect(typeof inspectionMs).toBe('number');
    expect(Number.isInteger(inspectionMs)).toBe(true);
    expect(inspectionMs).toBeGreaterThanOrEqual(0);
  });

  it('leaves it absent on a REPLAYED capture (one carrying its own occurredAt)', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER',
      occurredAt: '2026-05-01T09:00:00.000Z',
    });
    await rt.close();

    // The transcript backfill and the worktree scan both pass occurredAt.
    // Their scan duration is latency no host session waited on, so timing them
    // would mix background work into a p50 that answers what inspection costs
    // a live session. Absent, never 0 — a 0 is a real measurement of a real
    // capture, and the read side has to be able to tell the two apart.
    expect(gw.records[0]?.event.metadata?.inspectionMs).toBeUndefined();
  });

  it('carries the measurement alongside metadata the caller supplied, without dropping it', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER',
      metadata: { filePath: 'src/app.ts', repo: 'acme/app' },
    });
    await rt.close();

    const metadata = gw.records[0]?.event.metadata;
    expect(metadata?.filePath).toBe('src/app.ts');
    expect(metadata?.repo).toBe('acme/app');
    expect(typeof metadata?.inspectionMs).toBe('number');
  });

  it("persists no measurement for a benign 'with-findings' capture — the sample is the RECORDED set, not the scanned one", async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture(
      { kind: 'tool_use', sourceTool: 'claude-code', text: 'nothing here' },
      { persist: 'with-findings' },
    );
    await rt.capture(
      { kind: 'tool_use', sourceTool: 'claude-code', text: 'SECRET_MARKER' },
      { persist: 'with-findings' },
    );
    await rt.close();

    // The clean capture ran the full ruleset and was still not recorded, so its
    // measurement reaches no reader. That is the sampling skew `capture()`
    // documents: whenever a LIVE capture is made at 'with-findings', the
    // recorded set is the findings-bearing subset, which does strictly more
    // work. Pinned so it cannot be silently widened (another kind moved onto
    // 'with-findings') or quietly closed without the wording moving.
    expect(gw.records).toHaveLength(1);
    expect(typeof gw.records[0]?.event.metadata?.inspectionMs).toBe('number');
  });

  it("persists no measurement for a benign 'with-findings' RESPONSE either — the skew follows the condition, not the kind", async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture(
      { kind: 'response', sourceTool: 'claude-code', text: 'nothing here' },
      { persist: 'with-findings' },
    );
    await rt.capture(
      { kind: 'response', sourceTool: 'claude-code', text: 'SECRET_MARKER' },
      { persist: 'with-findings' },
    );
    await rt.close();

    // Both post-tool-use hooks capture kind:'response' at 'with-findings' with
    // no occurredAt, so responses are timed and then dropped when clean —
    // exactly the tool_use case above. Pinning only tool_use would leave a kind
    // that is ALREADY in the widened state unguarded.
    expect(gw.records).toHaveLength(1);
    expect(gw.records[0]?.event.kind).toBe('response');
    expect(typeof gw.records[0]?.event.metadata?.inspectionMs).toBe('number');
  });

  it('records a benign capture too — the cost is the same whether anything was found', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text: 'nothing here' });
    await rt.close();

    // A clean prompt still ran the full ruleset, so its latency belongs in the
    // p50; measuring only the captures that FOUND something would bias the
    // median toward the slower half of the population.
    expect(gw.records).toHaveLength(1);
    expect(typeof gw.records[0]?.event.metadata?.inspectionMs).toBe('number');
  });
});

describe('rulesetFingerprint', () => {
  it('is stable across runtimes over the same effective ruleset', async () => {
    const rt1 = createPluginRuntime(fakeGateway(bundle()), settings());
    const rt2 = createPluginRuntime(fakeGateway(bundle()), settings());
    expect(await rt1.rulesetFingerprint()).toBe(await rt2.rulesetFingerprint());
    await rt1.close();
    await rt2.close();
  });

  it('changes when the pulled bundle adds a rule', async () => {
    const without = createPluginRuntime(fakeGateway(bundle()), settings());
    const withPulled = createPluginRuntime(fakeGateway(bundle([PULLED_RULE])), settings());
    expect(await without.rulesetFingerprint()).not.toBe(await withPulled.rulesetFingerprint());
    await without.close();
    await withPulled.close();
  });

  it('returns a non-reusable nonce when the bundle pull fails (fail toward rescan)', async () => {
    const broken: DataGateway = {
      ...fakeGateway(bundle()),
      getPolicyBundle: () => Promise.reject(new Error('offline')),
    };
    const rt = createPluginRuntime(broken, settings());
    const first = await rt.rulesetFingerprint();
    expect(first).toMatch(/^unresolved-/);
    await rt.close();
  });
});

describe('runtime rule quarantine', () => {
  it('excludes a catastrophic pulled-pack regex rule from the active ruleset', async () => {
    // '(a+)+$' requires only 'a' characters and anchors at the end, so it
    // WOULD match a run of 'a's if it were registered — proving the finding's
    // absence below is the quarantine actually excluding the rule, not
    // coincidental non-matching.
    const evilRule: Rule = {
      specVersion: 1,
      id: 'pulled/evil-redos',
      name: 'evil redos',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: '(a+)+$', flags: 'g' },
    };
    const gw = fakeGateway({ ...bundle([evilRule]), rulesComplete: true });
    const rt = createPluginRuntime(gw, settings());

    const decision = await rt.processText('some text ending in aaaa');
    expect(decision.findings).toEqual([]);
    await rt.close();
  });
});

describe('capture — dedupe threading', () => {
  it("threads dedupe: 'content-hash' through to the gateway record", async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture(
      { kind: 'code_change', sourceTool: 'claude-code', text: 'SECRET_MARKER' },
      { persist: 'with-findings', dedupe: 'content-hash' },
    );
    expect(gw.records[0]?.dedupe).toBe('content-hash');
    await rt.close();
  });

  it('leaves dedupe unset on the live hook path', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text: 'SECRET_MARKER' });
    expect(gw.records[0]?.dedupe).toBeUndefined();
    await rt.close();
  });
});

describe('capture — appliesTo file-context threading', () => {
  // A Python-only rule delivered via the pulled bundle, so this test does not
  // pollute the global bundled packs shared by other tests.
  const pyOnlyRule: Rule = {
    specVersion: 1,
    id: 'pulled/py-only-marker',
    name: 'Python-only marker',
    category: 'code_flaw',
    severity: 'high',
    matcher: { type: 'keyword', keywords: ['PY_ONLY_MARKER'], caseSensitive: false },
    appliesTo: { extensions: ['.py'] },
    examples: ['PY_ONLY_MARKER'],
  };

  it('gates a scoped rule by the capture metadata filePath', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([pyOnlyRule])), settings());
    const tsResult = await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'PY_ONLY_MARKER',
      metadata: { filePath: '/repo/src/app.ts' },
    });
    expect(tsResult.findings.map((f) => f.ruleId)).not.toContain('pulled/py-only-marker');

    const pyResult = await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'PY_ONLY_MARKER',
      metadata: { filePath: '/repo/src/app.py' },
    });
    expect(pyResult.findings.map((f) => f.ruleId)).toContain('pulled/py-only-marker');
    await rt.close();
  });

  it('runs scoped rules when no file context exists (prompt path)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([pyOnlyRule])), settings());
    const result = await rt.processText('PY_ONLY_MARKER');
    expect(result.findings.map((f) => f.ruleId)).toContain('pulled/py-only-marker');
    await rt.close();
  });
});

describe('capture — at-rest finding_key', () => {
  it('is stable across two captures of the same rule/path/value (re-scan reconciliation)', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'aka-runtime-fk-'));
    try {
      const gw1 = fakeGateway(bundle());
      const rt1 = createPluginRuntime(gw1, settings(), { dataDir });
      await rt1.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/a.ts' },
      });
      await rt1.close();

      // A second scan (fresh runtime instance — a hook is short-lived — but the
      // SAME dataDir, so the same on-disk fingerprint key is read back).
      const gw2 = fakeGateway(bundle());
      const rt2 = createPluginRuntime(gw2, settings(), { dataDir });
      await rt2.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/a.ts' },
      });
      await rt2.close();

      const key1 = gw1.records[0]?.findings[0]?.findingKey;
      const key2 = gw2.records[0]?.findings[0]?.findingKey;
      expect(key1).toMatch(/^[0-9a-f]{64}$/);
      expect(key1).toBe(key2);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it('changes when the file path changes (same rule/value, different location)', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'aka-runtime-fk-'));
    try {
      const gw = fakeGateway(bundle());
      const rt = createPluginRuntime(gw, settings(), { dataDir });
      await rt.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/a.ts' },
      });
      await rt.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/b.ts' },
      });
      await rt.close();

      const keyA = gw.records[0]?.findings[0]?.findingKey;
      const keyB = gw.records[1]?.findings[0]?.findingKey;
      expect(keyA).toBeDefined();
      expect(keyA).not.toBe(keyB);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it('never attaches a finding_key to in-flight (prompt) findings', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
    expect(gw.records[0]?.findings[0]?.findingKey).toBeUndefined();
  });

  it('falls back to the masked match when no fingerprint key is available (no dataDir)', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings()); // no dataDir → keyForLedger() is null
    await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
      metadata: { filePath: '/repo/src/a.ts' },
    });
    await rt.close();
    expect(gw.records[0]?.findings[0]?.findingKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('gives two distinct secrets in the same file two distinct finding_keys', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER and PII_MARKER both here',
      metadata: { filePath: '/repo/src/a.ts' },
    });
    await rt.close();

    const keys = gw.records[0]?.findings.map((f) => f.findingKey) ?? [];
    expect(keys).toHaveLength(2);
    expect(new Set(keys).size).toBe(2);
  });
});

describe('capture() — CaptureResult.findingKeys (scanner re-scan resolver hook)', () => {
  it('echoes the at-rest finding_keys produced onto the returned decision', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER and PII_MARKER both here',
      metadata: { filePath: '/repo/src/a.ts' },
    });
    await rt.close();

    const recordedKeys = gw.records[0]?.findings.map((f) => f.findingKey) ?? [];
    expect(result.findingKeys).toHaveLength(2);
    expect(result.findingKeys).toEqual(recordedKeys);
  });

  it('leaves findingKeys unset for in-flight (prompt) captures — nothing to correlate against', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture(
      { kind: 'prompt', sourceTool: 'claude-code', text: 'deploy with SECRET_MARKER now' },
      { persist: 'always' },
    );
    await rt.close();
    expect(result.findingKeys).toBeUndefined();
  });

  it('leaves findingKeys unset when the with-findings short-circuit returns before persisting', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture(
      {
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'nothing sensitive here',
        metadata: { filePath: '/repo/src/a.ts' },
      },
      { persist: 'with-findings' },
    );
    await rt.close();
    expect(result.findingKeys).toBeUndefined();
    expect(gw.records).toHaveLength(0);
  });
});

// A redact the caller cannot carry out (CaptureOptions.rewritable: false).
//
// Antigravity's PreToolUse has no `updatedInput` at all, and Codex and Claude
// Code decline to mask a field that EXECUTES, so on those fields a `redact`
// policy has to become something else. Which action it becomes is
// `settings.redactFallback`, and the point of resolving it inside the runtime
// is that ONE resolution feeds the decision, the persisted finding and the
// blocked-detections ledger — so the audit trail cannot claim a masking that
// never happened.
describe('a redact the caller cannot carry out', () => {
  function redactBundle(): PolicyBundle {
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'test/secret-marker' },
        action: 'redact',
        enabled: true,
      },
    ];
    return b;
  }

  const settingsWith = (fallback: 'monitor' | 'warn' | 'block'): WorkspaceSettings => ({
    ...settings('redact'),
    redactFallback: fallback,
  });

  it('still redacts in place when the caller CAN rewrite (the control)', async () => {
    // Without this the cases below would pass on a runtime that had simply
    // stopped redacting anything.
    const gateway = fakeGateway(redactBundle());
    const runtime = createPluginRuntime(gateway, settingsWith('warn'));
    const out = await runtime.capture({
      kind: 'tool_use',
      sourceTool: 'claude-code',
      text: 'here is SECRET_MARKER',
    });
    expect(out.action).toBe('redact');
    expect(out.text).not.toContain('SECRET_MARKER');
    await runtime.close();
  });

  it.each([
    ['warn', 'warn'],
    ['monitor', 'log'],
    ['block', 'block'],
  ] as const)('degrades to the configured fallback: %s', async (fallback, expected) => {
    const gateway = fakeGateway(redactBundle());
    const runtime = createPluginRuntime(gateway, settingsWith(fallback));
    const out = await runtime.capture(
      { kind: 'tool_use', sourceTool: 'claude-code', text: 'here is SECRET_MARKER' },
      { rewritable: false },
    );
    expect(out.action).toBe(expected);
    await runtime.close();
  });

  it('records the action that ACTUALLY applied, not the policy it came from', async () => {
    // The load-bearing one. Recording 'redact' here would describe a masking
    // that did not happen while the raw value went through — the same class of
    // untruth as an escalated deny recorded as a redact, in the other
    // direction.
    const gateway = fakeGateway(redactBundle());
    const runtime = createPluginRuntime(gateway, settingsWith('warn'));
    await runtime.capture(
      { kind: 'tool_use', sourceTool: 'claude-code', text: 'here is SECRET_MARKER' },
      { rewritable: false },
    );
    const [record] = gateway.records;
    expect(record?.findings.map((f) => f.actionTaken)).toEqual(['warn']);
    await runtime.close();
  });

  it('leaves the value unmasked at rest when the fallback is below redact', async () => {
    // The at-rest mask reads the same resolution, so a degraded finding is
    // stored as it was seen. That is the honest record of a capture nothing
    // stripped — and the reason the fallback is a deliberate choice rather
    // than a default nobody looked at.
    const gateway = fakeGateway(redactBundle());
    const runtime = createPluginRuntime(gateway, settingsWith('warn'));
    await runtime.capture(
      { kind: 'tool_use', sourceTool: 'claude-code', text: 'here is SECRET_MARKER' },
      { rewritable: false },
    );
    expect(gateway.records[0]?.event.content).toContain('SECRET_MARKER');
    await runtime.close();
  });

  it('masks at rest when the fallback RAISES to block', async () => {
    // block outranks redact, so the same capture is stored masked — the
    // fallback moves both halves together.
    //
    // The at-rest assertion alone cannot carry this case: an UNdegraded redact
    // masks at rest too, so it holds whether or not the fallback applied. What
    // separates them is the recorded action, so both are asserted here.
    const gateway = fakeGateway(redactBundle());
    const runtime = createPluginRuntime(gateway, settingsWith('block'));
    await runtime.capture(
      { kind: 'tool_use', sourceTool: 'claude-code', text: 'here is SECRET_MARKER' },
      { rewritable: false },
    );
    expect(gateway.records[0]?.event.content).not.toContain('SECRET_MARKER');
    expect(gateway.records[0]?.findings.map((f) => f.actionTaken)).toEqual(['block']);
    await runtime.close();
  });
});

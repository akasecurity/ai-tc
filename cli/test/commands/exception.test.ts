import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { getLoadedRules } from '@akasecurity/detections';
import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import type { DataGateway } from '@akasecurity/plugin-sdk';
import {
  createPluginRuntime,
  dataDir,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  registerBundledPacks,
} from '@akasecurity/plugin-sdk';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runException } from '../../src/commands/exception.ts';
import { homeBase } from '../../src/lib/args.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

// The test value comes from the bundled rule's own `examples` fixture, so no
// secret-shaped literal lives in this file and the value stays in step with
// the rule definition.
const RULE_ID = 'secrets/aws-access-key';
registerBundledPacks();
const RULE = getLoadedRules().find((r) => r.id === RULE_ID);
const exampleValue = RULE?.examples?.[0];
if (exampleValue === undefined) throw new Error(`bundled rule ${RULE_ID} has no example fixture`);
// Re-bound after the guard so the narrowing survives into the hoisted
// `function` helpers below (tsc drops it there for the original binding).
const VALUE: string = exampleValue;

// Scripted, non-interactive Prompter: output captured, value via "stdin".
function scriptedIo(stdin = ''): Prompter & { output: () => string } {
  const chunks: string[] = [];
  return {
    output: () => chunks.join(''),
    out: (text) => {
      chunks.push(text);
    },
    err: (text) => {
      chunks.push(text);
    },
    isInteractive: false,
    ask: () => Promise.reject(new Error('non-interactive test io')),
    askHidden: () => Promise.reject(new Error('non-interactive test io')),
    readAllStdin: () => Promise.resolve(stdin),
  };
}

// Minimal DataGateway over the REAL local store + REAL key file, so the test
// proves the CLI and the enforcement path agree on dataDir/key co-location.
function gatewayOver(db: LocalDatabase, dir: string): DataGateway {
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
    getPolicyBundle: async () => ({
      version: 'test',
      policies: await db.policies.readPolicies(),
      rules: [],
      exceptions: await db.exceptions.activeBundleEntries(loadOrCreateFingerprintKey(dir).version),
      customKeywords: [],
      fetchedAt: new Date().toISOString(),
    }),
    consumeException: (id) => db.exceptions.consume(id),
    recordBlockedDetection: (entry) => db.exceptions.recordBlocked(entry),
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
    openAtRestKeysForPath: (path) => Promise.resolve(db.resolutions.openAtRestKeysForPath(path)),
    resolvedAtRestKeysForPath: (path) =>
      Promise.resolve(db.resolutions.resolvedAtRestKeysForPath(path)),
    insertResolution: (input) => {
      db.resolutions.insertResolution(input);
      return Promise.resolve();
    },
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

let home: string;
let dir: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-cli-ex-'));
  dir = dataDir(homeBase(home));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe('aka exception add → enforcement full loop', () => {
  it('creates a --once grant from stdin that the runtime honors exactly once', async () => {
    await runException(
      ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--once', '--reason', 'loop test'],
      scriptedIo(`${VALUE}\n`),
    );

    const db = openLocalDatabase(dir);
    try {
      // The cold-start floor no longer resolves secret to block by default, so
      // pin an explicit enforcing policy — this test's whole point is proving
      // the exception downgrades a real enforcement, not a bare warn.
      db.policies.upsertCategoryAction('secret', 'block');
      const grants = await db.exceptions.list();
      expect(grants).toHaveLength(1);
      const grant = grants[0];
      expect(grant?.ruleId).toBe(RULE_ID);
      expect(grant?.scope).toBe('once');
      expect(grant?.maxUses).toBe(1);
      // Nothing recoverable at rest: preview is masked, fingerprint is not the value.
      expect(grant?.maskedValue).not.toBe(VALUE);
      expect(grant?.valueFingerprint).not.toContain(VALUE);

      const runtime = createPluginRuntime(gatewayOver(db, dir), defaultWorkspaceSettings(), {
        dataDir: dir,
      });
      try {
        // First submission: the grant applies. The capture-level action reads
        // 'log' — the excepted finding is downgraded to allow, so nothing is
        // enforced (asserted exactly: a regression to redact/warn must fail).
        const first = await runtime.processText(`deploy with ${VALUE} now`);
        expect(first.action).toBe('log');
        // Second submission: the one-time budget is spent — blocked again.
        const second = await runtime.processText(`deploy with ${VALUE} again`);
        expect(second.action).toBe('block');
      } finally {
        await runtime.close();
      }
    } finally {
      db.close();
    }
  });

  it('refuses a value that does not match the rule (no dangling grant)', async () => {
    await expect(
      runException(
        ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--once', '--reason', 'nope'],
        scriptedIo('not-a-credential\n'),
      ),
    ).rejects.toThrow(/does not match rule/);

    const db = openLocalDatabase(dir);
    try {
      expect(await db.exceptions.list()).toHaveLength(0);
    } finally {
      db.close();
    }
  });
});

describe('aka exception approve — from the blocked-detections ledger', () => {
  // Seed the ledger the way the hook does: fingerprint under the real key.
  async function seedBlocked(reference: string, ruleId = RULE_ID): Promise<void> {
    const key = loadOrCreateFingerprintKey(dir);
    const db = openLocalDatabase(dir);
    try {
      await db.exceptions.recordBlocked({
        reference,
        ruleId,
        category: 'secret',
        valueFingerprint: fingerprintValue(key, VALUE),
        keyVersion: key.version,
        maskedValue: 'A******E',
        sessionId: 'sess-1',
        repo: null,
      });
    } finally {
      db.close();
    }
  }

  it('creates the grant from the ledger row — no value handling — and it enforces', async () => {
    await seedBlocked('3f2a91');
    await runException(
      ['approve', '3f2a91', '--home', home, '--once', '--reason', 'approve flow'],
      scriptedIo(),
    );

    const db = openLocalDatabase(dir);
    try {
      // The cold-start floor no longer resolves secret to block by default, so
      // pin an explicit enforcing policy — this test's whole point is proving
      // the exception downgrades a real enforcement, not a bare warn.
      db.policies.upsertCategoryAction('secret', 'block');
      const grant = (await db.exceptions.list())[0];
      expect(grant?.ruleId).toBe(RULE_ID);
      expect(grant?.createdVia).toBe('cli-approve');
      expect(grant?.maskedValue).toBe('A******E');

      const runtime = createPluginRuntime(gatewayOver(db, dir), defaultWorkspaceSettings(), {
        dataDir: dir,
      });
      try {
        const result = await runtime.processText(`use ${VALUE} once`);
        expect(result.action).toBe('log');
      } finally {
        await runtime.close();
      }
    } finally {
      db.close();
    }
  });

  it('accepts the masked value as the selector (what the block message showed)', async () => {
    await seedBlocked('9c04d7');
    await runException(
      ['approve', 'A******E', '--home', home, '--for', '1h', '--reason', 'mask selector'],
      scriptedIo(),
    );
    const db = openLocalDatabase(dir);
    try {
      expect((await db.exceptions.list())[0]?.scope).toBe('temporary');
    } finally {
      db.close();
    }
  });

  it('accepts the blocked value itself as the selector, matched by fingerprint', async () => {
    await seedBlocked('4b7e12');
    const io = scriptedIo();
    await runException(
      ['approve', VALUE, '--home', home, '--once', '--reason', 'value selector'],
      io,
    );

    const db = openLocalDatabase(dir);
    try {
      const grant = (await db.exceptions.list())[0];
      expect(grant?.ruleId).toBe(RULE_ID);
      expect(grant?.createdVia).toBe('cli-approve');
      expect(grant?.maskedValue).toBe('A******E');
    } finally {
      db.close();
    }
    // The raw value must never be echoed back.
    expect(io.output()).not.toContain(VALUE);
  });

  it('trims paste artifacts (embedded newlines) from the selector', async () => {
    await seedBlocked('81cc09');
    await runException(
      ['approve', `\n${VALUE}\n\n`, '--home', home, '--once', '--reason', 'pasted'],
      scriptedIo(),
    );
    const db = openLocalDatabase(dir);
    try {
      expect(await db.exceptions.list()).toHaveLength(1);
    } finally {
      db.close();
    }
  });

  it('does not echo an unmatched selector — it may be a live secret', async () => {
    await seedBlocked('f00d42');
    const unmatched = 'AKIAZZZZNOTBLOCKEDZZ';
    const err = await runException(
      ['approve', unmatched, '--home', home, '--once', '--reason', 'nope'],
      scriptedIo(),
    ).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    expect(err?.message).toMatch(/no blocked detection matches/);
    expect(err?.message).not.toContain(unmatched);
  });

  it('refuses a value blocked under multiple rules — the rule choice is real', async () => {
    await seedBlocked('aa1111');
    await seedBlocked('bb2222', 'secrets/generic-credential');
    await expect(
      runException(
        ['approve', VALUE, '--home', home, '--once', '--reason', 'ambiguous'],
        scriptedIo(),
      ),
    ).rejects.toThrow(/blocked under 2 different rules/);

    const db = openLocalDatabase(dir);
    try {
      expect(await db.exceptions.list()).toHaveLength(0);
    } finally {
      db.close();
    }
  });
});

describe('aka exception list / revoke', () => {
  it('lists the masked grant and revoke ends it', async () => {
    await runException(
      ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--for', '1h', '--reason', 'window'],
      scriptedIo(`${VALUE}\n`),
    );

    const listIo = scriptedIo();
    await runException(['list', '--home', home], listIo);
    expect(listIo.output()).toContain(RULE_ID);
    expect(listIo.output()).not.toContain(VALUE);

    const db = openLocalDatabase(dir);
    let id: string;
    try {
      const grant = (await db.exceptions.list())[0];
      if (!grant) throw new Error('grant missing');
      id = grant.id;
    } finally {
      db.close();
    }

    await runException(
      ['revoke', id.slice(0, 6), '--home', home, '--yes', '--reason', 'done'],
      scriptedIo(),
    );

    const after = openLocalDatabase(dir);
    try {
      expect(await after.exceptions.list()).toHaveLength(0);
      const all = await after.exceptions.list({ includeTerminal: true });
      expect(all).toHaveLength(1);
      expect(all[0]?.revokedAt).not.toBeNull();
    } finally {
      after.close();
    }

    // The empty active list points at the retained terminal rows instead of
    // reading like the grant vanished.
    const emptyIo = scriptedIo();
    await runException(['list', '--home', home], emptyIo);
    expect(emptyIo.output()).toContain("'aka exception list --all'");
  });
});

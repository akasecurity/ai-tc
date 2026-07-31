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
  readFingerprintKey,
  registerBundledPacks,
  rotateFingerprintKey,
} from '@akasecurity/plugin-sdk';
import type { DetectionException } from '@akasecurity/schema';
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
    getRuleProbeVerdict: (ruleKey) => Promise.resolve(db.ruleProbeCache.getVerdict(ruleKey)),
    setRuleProbeVerdict: (ruleKey, verdict, worstProbeMs) => {
      db.ruleProbeCache.setVerdict(ruleKey, verdict, worstProbeMs);
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

  // The ledger is retained for a day, so it outlives a key rotation and keeps
  // offering rows whose fingerprint was computed under the old material.
  // Enforcement fingerprints under the CURRENT key and scopes its bundle query
  // to that version, so a grant built from such a row is inert the moment it is
  // created — and reporting success for it is worse than the grant simply going
  // quiet, because the operator just deliberately created this one.
  describe('a row keyed to a version that is no longer current', () => {
    async function grants(): Promise<unknown[]> {
      const db = openLocalDatabase(dir);
      try {
        return await db.exceptions.list({ includeTerminal: true });
      } finally {
        db.close();
      }
    }

    it('refuses a row blocked before a rotation', async () => {
      await seedBlocked('c0ffee');
      const rotated = rotateFingerprintKey(dir);
      expect(rotated.version).toBe(2);

      await expect(
        runException(
          ['approve', 'c0ffee', '--home', home, '--once', '--reason', 'stale'],
          scriptedIo(),
        ),
      ).rejects.toThrow(/could never match/);
      expect(await grants()).toHaveLength(0);
    });

    it('refuses a row whose key was deleted and re-minted, not just rotated', async () => {
      // Version alone is not an identity — minting used to restart the counter,
      // so a key deleted at v1 and re-minted came back as v1 and made this row
      // look current. The mint now takes the first version the store has not
      // already claimed.
      await seedBlocked('deadbe');
      rmSync(join(dir, 'exception.key'));
      const reminted = loadOrCreateFingerprintKey(dir);
      expect(reminted.version).toBe(2);

      await expect(
        runException(
          ['approve', 'deadbe', '--home', home, '--once', '--reason', 'reminted'],
          scriptedIo(),
        ),
      ).rejects.toThrow(/could never match/);
      expect(await grants()).toHaveLength(0);
    });

    it('refuses when the key file is missing, and mints nothing to answer the read', async () => {
      await seedBlocked('ba5eba');
      rmSync(join(dir, 'exception.key'));

      await expect(
        runException(
          ['approve', 'ba5eba', '--home', home, '--once', '--reason', 'no key'],
          scriptedIo(),
        ),
      ).rejects.toThrow(/key file is missing/);
      expect(await grants()).toHaveLength(0);
      // A refusal that minted a key would rotate the machine's whole grant set
      // to answer a lookup.
      expect(readFingerprintKey(dir)).toBeNull();
    });

    it('marks unapprovable rows in the picker instead of offering them', async () => {
      // The picker is the CLI's twin of the web strip, which disables these
      // rows. Listing one unmarked spends the user's choice on something the
      // very next step refuses.
      await seedBlocked('aa0001');
      await seedBlocked('bb0002');
      rotateFingerprintKey(dir);

      const io = scriptedIo();
      const err = await runException(
        ['approve', '--home', home, '--once', '--reason', 'listing'],
        io,
      ).then(
        () => undefined,
        (e: unknown) => e as Error,
      );
      // Non-interactive with more than one row lists them and asks for a
      // reference, which is the branch that prints the annotated lines.
      expect(err?.message).toMatch(/pass the reference/);
      const listed = io.output();
      expect(listed).toContain('aa0001');
      expect(listed).toContain('bb0002');
      expect(listed.match(/not approvable: recorded under key v1/g)).toHaveLength(2);
    });

    it('does not mint a key when a by-value selector finds nothing', async () => {
      // The by-value path fingerprints the selector to compare it, which used to
      // load-or-create. On a store with no key that minted one as a side effect
      // of a failed search.
      await seedBlocked('fa11ed');
      rmSync(join(dir, 'exception.key'));
      const unmatched = 'AKIAZZZZNOTBLOCKEDZZ';

      const err = await runException(
        ['approve', unmatched, '--home', home, '--once', '--reason', 'nope'],
        scriptedIo(),
      ).then(
        () => undefined,
        (e: unknown) => e as Error,
      );
      expect(err?.message).toMatch(/needs the fingerprint key/);
      expect(err?.message).not.toContain(unmatched);
      expect(readFingerprintKey(dir)).toBeNull();
    });
  });
});

describe('aka exception show', () => {
  it('prints the id, masked value, and key version — never a fingerprint fragment', async () => {
    await runException(
      ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--for', '1h', '--reason', 'render'],
      scriptedIo(`${VALUE}\n`),
    );

    const db = openLocalDatabase(dir);
    let grant: DetectionException | undefined;
    try {
      grant = (await db.exceptions.list())[0];
    } finally {
      db.close();
    }
    if (!grant) throw new Error('grant missing');

    const io = scriptedIo();
    await runException(['show', grant.id.slice(0, 6), '--home', home], io);
    const out = io.output();

    // Positive control first: an empty capture would pass every absence
    // assertion below vacuously.
    expect(out).toContain(grant.id.slice(0, 6));
    expect(out).toContain(grant.maskedValue);
    expect(out).toContain(`key v${String(grant.keyVersion)}`);
    expect(out).not.toContain(VALUE);

    // The keyed fingerprint is a correlation key: no window of it may be
    // echoed. Window by window rather than the whole digest — a truncated
    // echo is still a stable correlation key. The shape guard keeps the loop
    // from passing vacuously on a short or malformed digest.
    expect(grant.valueFingerprint).toMatch(/^[0-9a-f]{64}$/);
    const WINDOW = 6;
    for (let i = 0; i + WINDOW <= grant.valueFingerprint.length; i++) {
      expect(out).not.toContain(grant.valueFingerprint.slice(i, i + WINDOW));
    }
    // The fragment shape this command used to print sits below the window
    // size above (4-char prefix…4-char suffix); pin its absence directly.
    expect(out).not.toContain(
      `${grant.valueFingerprint.slice(0, 4)}…${grant.valueFingerprint.slice(-4)}`,
    );
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

  it('tags a reveal-to-model grant so it cannot be read as a plain suppression', async () => {
    // A suppress grant via the normal add flow...
    await runException(
      ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--for', '1h', '--reason', 'window'],
      scriptedIo(`${VALUE}\n`),
    );
    // ...and a reveal-to-model grant seeded the way the mint flow writes it.
    const key = loadOrCreateFingerprintKey(dir);
    const db = openLocalDatabase(dir);
    try {
      await db.exceptions.create({
        ruleId: 'secrets/generic-credential',
        category: 'secret',
        valueFingerprint: fingerprintValue(key, 'not-the-listed-value'),
        keyVersion: key.version,
        maskedValue: 'gh*…ret',
        capability: 'reveal_to_model',
        scope: 'temporary',
        expiresAt: new Date(Date.now() + 60 * 60_000).toISOString(),
        maxUses: null,
        justification: 'agent needs the live key',
        conditions: null,
        createdBy: 'tester (local)',
        createdVia: 'cli-approve',
      });
    } finally {
      db.close();
    }

    const listIo = scriptedIo();
    await runException(['list', '--home', home], listIo);
    const out = listIo.output();
    // Only the reveal row carries the tag; the suppress row is unchanged.
    expect(out).toContain('gh*…ret · REVEALS-TO-MODEL');
    expect(out.match(/REVEALS-TO-MODEL/g)).toHaveLength(1);
    // The list is metadata-only even for reveal grants — masked, never raw.
    expect(out).not.toContain(VALUE);
    expect(out).not.toContain('not-the-listed-value');
  });
});

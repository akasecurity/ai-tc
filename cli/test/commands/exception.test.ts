import { chmodSync, mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
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
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runException } from '../../src/commands/exception.ts';
import { homeBase } from '../../src/lib/args.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { main } from '../../src/main.ts';

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

// Scripted TERMINAL Prompter — the branches a non-interactive run never reaches
// (the numbered picker, the scope/reason prompts). Questions are recorded so a
// test can assert what the user was NOT asked, and an unscripted question
// rejects rather than hanging.
function interactiveIo(
  answers: string[],
): Prompter & { output: () => string; asked: () => string[] } {
  const chunks: string[] = [];
  const questions: string[] = [];
  const queued = [...answers];
  return {
    output: () => chunks.join(''),
    asked: () => questions,
    out: (text) => {
      chunks.push(text);
    },
    err: (text) => {
      chunks.push(text);
    },
    isInteractive: true,
    ask: (question) => {
      questions.push(question);
      const next = queued.shift();
      return next === undefined
        ? Promise.reject(new Error(`unscripted prompt: ${question}`))
        : Promise.resolve(next);
    },
    askHidden: () => Promise.reject(new Error('no hidden prompt expected')),
    readAllStdin: () => Promise.resolve(''),
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

    it('refuses a row blocked before a rotation, naming both key versions', async () => {
      await seedBlocked('c0ffee');
      const rotated = rotateFingerprintKey(dir);
      expect(rotated.version).toBe(2);

      const err = await runException(
        ['approve', 'c0ffee', '--home', home, '--once', '--reason', 'stale'],
        scriptedIo(),
      ).then(
        () => undefined,
        (e: unknown) => e as Error,
      );
      // "cannot approve" alone leaves the operator guessing at a store they
      // cannot inspect: the row's version and the live one are what say the
      // grant is unwritable rather than the request being malformed.
      expect(err?.message).toMatch(/could never match/);
      expect(err?.message).toContain('v1');
      expect(err?.message).toContain(`v${String(rotated.version)}`);
      expect(await grants()).toHaveLength(0);
    });

    it('refuses before asking for a scope or a reason', async () => {
      // The refusal has to come first: an unusable row stays unusable whatever
      // the user answers, and a permanent grant would otherwise make someone
      // retype a masked value only to be told no.
      await seedBlocked('5c09e5');
      rotateFingerprintKey(dir);

      const io = interactiveIo([]);
      await expect(runException(['approve', '5c09e5', '--home', home], io)).rejects.toThrow(
        /could never match/,
      );
      expect(io.asked()).toEqual([]);
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

    it('reports a corrupt key file with recovery guidance, not a crash', async () => {
      // Truncated, not garbage: a half-written key is what an interrupted write
      // leaves, and it is the shape the store's own fault matrix injects. The
      // strict parse throws with no errno, which is the ONE key failure that may
      // be answered with "delete it" — a permissions error must not be.
      await seedBlocked('c0dec0');
      const keyPath = join(dir, 'exception.key');
      truncateSync(keyPath, 10);
      const onDisk = readFileSync(keyPath);

      const err = await runException(
        ['approve', 'c0dec0', '--home', home, '--once', '--reason', 'corrupt'],
        scriptedIo(),
      ).then(
        () => undefined,
        (e: unknown) => e as Error,
      );
      expect(err?.message).toMatch(/cannot read the fingerprint key/);
      expect(err?.message).toMatch(/Delete .*exception\.key to start fresh/);
      expect(await grants()).toHaveLength(0);
      // Deleting is the operator's deliberate act, not a side effect of a
      // refused approve — and a replacement minted here would orphan every
      // grant on the machine to answer a lookup.
      expect(readFileSync(keyPath)).toEqual(onDisk);
    });

    it('never answers an UNREADABLE key with "delete it"', async (ctx) => {
      // The corrupt guidance is the only one safe to act on. Aimed at a
      // permissions failure it destroys every grant on the machine to fix a
      // chmod — and the replacement key is exactly what makes a stale ledger row
      // look current again, which is the failure this whole guard exists to
      // stop. Mirrors the web action's split; one wording drifting is how the
      // two surfaces come to give opposite advice about the same file.
      if (process.platform === 'win32') {
        ctx.skip('POSIX mode bits do not gate reads under Windows ACLs');
      }
      if (process.getuid?.() === 0) {
        ctx.skip('root bypasses the mode bits this case depends on');
      }
      await seedBlocked('10cked0');
      const keyPath = join(dir, 'exception.key');
      chmodSync(keyPath, 0o000);
      try {
        const err = await runException(
          ['approve', '10cked0', '--home', home, '--once', '--reason', 'unreadable'],
          scriptedIo(),
        ).then(
          () => undefined,
          (e: unknown) => e as Error,
        );
        expect(err?.message).toMatch(/cannot read the fingerprint key/);
        expect(err?.message).toMatch(/do not delete it/i);
        expect(err?.message).not.toMatch(/delete .*exception\.key to start fresh/i);
        expect(await grants()).toHaveLength(0);
      } finally {
        chmodSync(keyPath, 0o600); // so the temp tree can be removed
      }
    });

    it('rejects through the CLI dispatch, so the command exits non-zero', async () => {
      // The exit code itself belongs to the bin shim (`cli.ts` maps a rejected
      // main() to process.exitCode = 1). What can still go wrong is a swallow
      // between runApprove and main(), which would report success for a grant
      // that was never written — so pin that the refusal propagates that far.
      await seedBlocked('e1e1e1');
      rotateFingerprintKey(dir);

      await expect(
        main(['exception', 'approve', 'e1e1e1', '--home', home, '--once', '--reason', 'stale']),
      ).rejects.toThrow(/could never match/);
      expect(await grants()).toHaveLength(0);
    });

    // Selecting a row and granting from it are separate steps, and only the
    // by-value search had a version filter — it needs the current key to
    // fingerprint the selector at all, so the filter fell out of the mechanism
    // rather than guarding the grant. Every other path reached the grant with no
    // check of its own. They are enumerated here because the guard is only
    // trustworthy if it sits where all of them converge.
    //
    // LEDGER paths only. A pointer selector with --reveal-to-model is a sixth way
    // into `aka exception approve` and is deliberately not one of these: a reveal
    // grant is matched on its vault row's own triple, so the current fingerprint
    // key has no say in whether it resolves. See exception-reveal.test.ts.
    describe('every ledger selection path ends at the same refusal', () => {
      it('refuses a row selected by the masked value from the block message', async () => {
        await seedBlocked('9c04d7');
        rotateFingerprintKey(dir);

        await expect(
          runException(
            ['approve', 'A******E', '--home', home, '--for', '1h', '--reason', 'mask selector'],
            scriptedIo(),
          ),
        ).rejects.toThrow(/could never match/);
        expect(await grants()).toHaveLength(0);
      });

      it('refuses the sole recent block it would otherwise pick automatically', async () => {
        // No selector and exactly one row: the flow picks it without asking, so
        // nothing the user typed stands between the stale row and the grant.
        await seedBlocked('501e01');
        rotateFingerprintKey(dir);

        const io = scriptedIo();
        await expect(
          runException(['approve', '--home', home, '--once', '--reason', 'auto-pick'], io),
        ).rejects.toThrow(/could never match/);
        expect(io.output()).toContain('not approvable: recorded under key v1');
        expect(await grants()).toHaveLength(0);
      });

      it('refuses a row chosen from the interactive picker', async () => {
        await seedBlocked('aa0003');
        await seedBlocked('bb0004');
        rotateFingerprintKey(dir);

        // No scope and no reason on the command line: on a healthy row the flow
        // would go on to prompt for both, so the picker question being the ONLY
        // one asked is what shows the refusal came first.
        const io = interactiveIo(['1']);
        await expect(runException(['approve', '--home', home], io)).rejects.toThrow(
          /could never match/,
        );
        expect(io.asked()).toHaveLength(1);
        expect(io.asked()[0]).toMatch(/Which one\?/);
        expect(await grants()).toHaveLength(0);
      });

      it('never reaches a stale row by its raw value, and grants nothing', async () => {
        // After a real rotation the search cannot reach the row at all — the new
        // material fingerprints the pasted value differently, so nothing matches
        // before any version is compared. That is the ordinary case, and it is
        // why the by-value filter reads as belt-and-braces; the case that
        // actually exercises the filter is the next test.
        await seedBlocked('4b7e12');
        rotateFingerprintKey(dir);

        const io = scriptedIo();
        const err = await runException(
          ['approve', VALUE, '--home', home, '--once', '--reason', 'value selector'],
          io,
        ).then(
          () => undefined,
          (e: unknown) => e as Error,
        );
        // The search comes up empty, so this refuses inside pickBlocked and never
        // reaches the grant site — pin the wording, or a TypeError from a broken
        // search would satisfy the case it is named for.
        expect(err?.message).toMatch(/no blocked detection matches/);
        expect(await grants()).toHaveLength(0);
        // The selector may be a live secret however the refusal is reached.
        expect(err?.message).not.toContain(VALUE);
        expect(io.output()).not.toContain(VALUE);
      });

      it('grants nothing by value when the version moved but the material did not', async () => {
        // The one shape where the by-value path can still FIND a stale row: the
        // key file keeps its material and only its version advances, so the
        // pasted value fingerprints to exactly what the row stored. Rotation
        // never produces this — it is what a hand-edited key file leaves.
        //
        // Both layers have to go before a grant is written: drop the search's
        // version filter and the grant site still throws; drop the grant site and
        // the search still finds nothing. This is the only construction where
        // dropping BOTH writes a grant the enforcement bundle, scoped to the
        // current version, could never match.
        await seedBlocked('ab1e01');
        const key = readFingerprintKey(dir);
        if (!key) throw new Error('seeded store has no key');
        writeFileSync(
          join(dir, 'exception.key'),
          `${JSON.stringify({ version: key.version + 1, material: key.material.toString('base64') })}\n`,
          { mode: 0o600 },
        );

        const io = scriptedIo();
        const err = await runException(
          ['approve', VALUE, '--home', home, '--once', '--reason', 'same material'],
          io,
        ).then(
          () => undefined,
          (e: unknown) => e as Error,
        );
        // Same refusal site as the case above: the version filter drops the row
        // from the search, so pickBlocked reports no match rather than the grant
        // site reporting a stale version.
        expect(err?.message).toMatch(/no blocked detection matches/);
        expect(await grants()).toHaveLength(0);
        expect(err?.message).not.toContain(VALUE);
        expect(io.output()).not.toContain(VALUE);
      });
    });
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

import { chmodSync, mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { getLoadedRules, maskMatch } from '@akasecurity/detections';
import type { LocalDatabase } from '@akasecurity/persistence';
import { BLOCKED_DETECTIONS_RETENTION_MS, openLocalDatabase } from '@akasecurity/persistence';
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
import {
  defaultWorkspaceSettings,
  LEDGER_WINDOW_HOURS,
  rotationBlockedLedgerNote,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runException } from '../../src/commands/exception.ts';
import { homeBase } from '../../src/lib/args.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { main } from '../../src/main.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { removeTree } from '../helpers/remove-tree.ts';

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

// A second value the SAME rule detects: the ASIA form of the fixture. Distinct
// from VALUE with identical entropy, derived rather than written out, and it
// masks to the same `A******E` preview — which is the point wherever a test
// needs two values one surface must keep apart.
const SECOND_VALUE = `ASIA${VALUE.slice(4)}`;

// A value the engine detects under a DIFFERENT rule, for the branch that builds
// the "did you mean" hint out of the other matches — the one rejection in this
// command that composes a message while holding the raw value in scope.
const OTHER_RULE_ID = 'secrets/gitlab-token';
const otherExample = getLoadedRules().find((r) => r.id === OTHER_RULE_ID)?.examples?.[0];
if (otherExample === undefined) throw new Error(`bundled rule ${OTHER_RULE_ID} has no example`);
const OTHER_VALUE: string = otherExample;

// expectNoEchoOf is shared across this package's suites (see its own tests in
// test/helpers/no-echo.test.ts), and this file applies it to BOTH surfaces the
// command has, which is wider than the web-ui original it mirrors: an ERROR,
// where no part of the value has any business appearing, and STDOUT, where the
// only thing this command ever prints of a blocked SECRET is maskMatch's
// first-and-last-character preview (`A******E`) — two characters, so it cannot
// fill the window. That scoping is load-bearing: maskMatch's email branch
// reveals the whole domain, so the stdout half does not extend to a surface
// printing a pii/email preview. Where a path prints nothing at all, assert the
// emptiness instead — searching empty bytes proves nothing.

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
  removeTree(home);
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

  // `add` is the ONLY verb here that holds a raw value in this process: it reads
  // it from stdin and composes every refusal below with that value still in
  // scope (approve works from a ledger row and never sees one). So this is where
  // an echo would come from, and each rejection is asserted run by run against
  // the value THAT call piped in.
  it('refuses a value that does not match the rule (no dangling grant)', async () => {
    // High-entropy but rule-shaped for nothing: an English-phrase fixture would
    // put ordinary words in the sliding window, where they can collide with the
    // message's own wording instead of catching a leak.
    const supplied = 'zq7vk2mx9tw4hb6n';
    const io = scriptedIo(`${supplied}\n`);
    const err = await runException(
      ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--once', '--reason', 'nope'],
      io,
    ).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    expect(err?.message).toMatch(/does not match rule/);
    // Nothing else matched, so the "did you mean" hint is absent — pin that, or
    // the case cannot be told apart from the one below it.
    expect(err?.message).not.toMatch(/did you mean/);
    expectNoEchoOf(err?.message, supplied);
    // The refusal prints NOTHING. Asserted as emptiness rather than as an
    // absence within it: `not.toContain` over bytes that are always empty
    // passes however the branch is worded.
    expect(io.output()).toBe('');

    const db = openLocalDatabase(dir);
    try {
      expect(await db.exceptions.list()).toHaveLength(0);
    } finally {
      db.close();
    }
  });

  it('names the rule that DID match without echoing the value it was handed', async () => {
    const io = scriptedIo(`${OTHER_VALUE}\n`);
    const err = await runException(
      ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--once', '--reason', 'wrong rule'],
      io,
    ).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    // Positive control: the hint branch really ran, so the message under test is
    // the one built FROM the scan of the piped value — not the bare rejection.
    expect(err?.message).toMatch(/does not match rule/);
    expect(err?.message).toContain(OTHER_RULE_ID);
    // Rule ids are the only thing that branch may carry out of the scan.
    expectNoEchoOf(err?.message, OTHER_VALUE);
    expect(io.output()).toBe('');

    const db = openLocalDatabase(dir);
    try {
      expect(await db.exceptions.list()).toHaveLength(0);
    } finally {
      db.close();
    }
  });

  it('refuses an input holding two distinct values for the rule, echoing neither', async () => {
    const io = scriptedIo(`${VALUE} and ${SECOND_VALUE}\n`);
    const err = await runException(
      ['add', '--home', home, '--rule', RULE_ID, '--stdin', '--once', '--reason', 'two spans'],
      io,
    ).then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    // The count is what the operator needs; the spans themselves are two live
    // credentials, and they mask identically, so the message could not name one
    // usefully even if it were safe to.
    expect(err?.message).toMatch(/contains 2 distinct values/);
    expectNoEchoOf(err?.message, VALUE);
    expectNoEchoOf(err?.message, SECOND_VALUE);
    expect(io.output()).toBe('');

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
    // Positive control FIRST: this path really does print, and what it prints of
    // the value is the masked preview. Without it the assertion below could not
    // tell a clean confirmation from a capture that stopped receiving anything.
    expect(io.output()).toContain('A******E');
    // The raw value must never be echoed back — not even a run of it.
    expectNoEchoOf(io.output(), VALUE);
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
    expectNoEchoOf(err?.message, unmatched);
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
      expectNoEchoOf(err?.message, unmatched);
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
        expectNoEchoOf(err?.message, VALUE);
        // This path prints nothing at all before it throws, so the property is
        // emptiness — asserted directly. Pointing expectNoEchoOf at a capture
        // that is always empty would pass however the branch is worded, and this
        // form goes red the moment anything at all is printed here.
        expect(io.output()).toBe('');
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
        expectNoEchoOf(err?.message, VALUE);
        // Same refusal site, same reason for asserting emptiness as above.
        expect(io.output()).toBe('');
      });
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
    expectNoEchoOf(listIo.output(), VALUE);

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
        ruleId: OTHER_RULE_ID,
        category: 'secret',
        // A different value from the suppress row's, and a high-entropy one:
        // the absence check below slides an eight-character window over it, and
        // an English-phrase fixture invites a collision with ordinary output
        // text rather than catching a leak.
        valueFingerprint: fingerprintValue(key, OTHER_VALUE),
        keyVersion: key.version,
        maskedValue: maskMatch(OTHER_VALUE),
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
    // Only the reveal row carries the tag; the suppress row is unchanged. The
    // two previews differ, so the tag is pinned to a nameable row rather than to
    // whichever one the renderer happened to emit.
    expect(out).toContain(`${maskMatch(OTHER_VALUE)} · REVEALS-TO-MODEL`);
    expect(out.match(/REVEALS-TO-MODEL/g)).toHaveLength(1);
    // The list is metadata-only even for reveal grants — masked, never raw.
    expectNoEchoOf(out, VALUE);
    expectNoEchoOf(out, OTHER_VALUE);
  });
});

// Rotation is one-way, and the two stores holding GRANTABLE fingerprints are
// the permanent grants and the blocked-detections ledger. This command listed
// the first and said nothing about the second, while the dashboard's rotate
// dialog disclosed both — two surfaces stating different costs for the same
// irreversible action, and this is the one that runs unattended under `--yes`.
//
// The ledger half is the easy one to miss precisely because it degrades so
// politely: those rows go on appearing under `aka exception approve`
// afterwards, correctly refused, which is a worse place to learn it than in the
// confirmation.
describe('aka exception rotate-key — the cost it discloses before committing', () => {
  // Seeds a ledger row under whatever key is current, the way the enforcement
  // path writes one.
  async function seedBlocked(reference: string): Promise<void> {
    const key = loadOrCreateFingerprintKey(dir);
    const db = openLocalDatabase(dir);
    try {
      await db.exceptions.recordBlocked({
        reference,
        ruleId: RULE_ID,
        category: 'secret',
        valueFingerprint: fingerprintValue(key, VALUE),
        keyVersion: key.version,
        maskedValue: maskMatch(VALUE),
        sessionId: 'sess-rotate',
        repo: null,
      });
    } finally {
      db.close();
    }
  }

  // `recordBlocked` stamps `blocked_at` with the wall clock, so ageing a row is
  // the one thing the repository API cannot express. Written straight to the
  // real store rather than by mocking a clock — the property under test is
  // which WINDOW the command reads over, and a faked clock would move the
  // command's cutoff along with the row and assert nothing.
  function backdate(reference: string, ageMs: number): void {
    const raw = new DatabaseSync(join(dir, 'aka.db'));
    try {
      const changes = raw
        .prepare('UPDATE blocked_detections SET blocked_at = ? WHERE reference = ?')
        .run(Date.now() - ageMs, reference).changes;
      // An UPDATE matching nothing exits happily and would leave the row at
      // `now`, where the assertion below passes for the wrong reason.
      expect(Number(changes)).toBe(1);
    } finally {
      raw.close();
    }
  }

  // Interactive prompter that also captures what had ALREADY been printed at
  // the moment the confirm prompt was asked. `interactiveIo` above records the
  // questions and the output separately, so it cannot tell a disclosure made
  // before the decision from one made after it — which is the whole property
  // here, not an incidental detail of layout.
  function confirmIo(answer: string): Prompter & {
    output: () => string;
    printedBeforePrompt: () => string | null;
  } {
    const chunks: string[] = [];
    let atPrompt: string | null = null;
    return {
      output: () => chunks.join(''),
      printedBeforePrompt: () => atPrompt,
      out: (text) => {
        chunks.push(text);
      },
      err: (text) => {
        chunks.push(text);
      },
      isInteractive: true,
      ask: () => {
        atPrompt = chunks.join('');
        return Promise.resolve(answer);
      },
      askHidden: () => Promise.reject(new Error('no hidden prompt expected')),
      readAllStdin: () => Promise.resolve(''),
    };
  }

  function keyVersion(): number | undefined {
    return readFingerprintKey(dir)?.version;
  }

  it('states the ledger cost under --yes, which skips the prompt but not the preamble', async () => {
    await seedBlocked('a11ce5');

    const io = scriptedIo();
    await runException(['rotate-key', '--home', home, '--yes'], io);

    const out = io.output();
    expect(out).toContain('invalidates EVERY existing exception grant');
    expect(out).toContain(rotationBlockedLedgerNote(1));
    // The unattended path is the one that most needs the disclosure and the
    // least likely to be read, so pin that it really rotated — a version still
    // at 1 would mean this asserted the copy on a run that did nothing.
    expect(keyVersion()).toBe(2);
  });

  it('states it before the confirm prompt, not after the decision', async () => {
    await seedBlocked('b22dee');

    const io = confirmIo('n');
    await runException(['rotate-key', '--home', home], io);

    // Printed by the time the user was asked — "tell them before, not after" is
    // the entire point, and a note emitted after the answer is worth nothing.
    expect(io.printedBeforePrompt()).toContain(rotationBlockedLedgerNote(1));
    expect(io.output()).toContain('Aborted — key unchanged.');
    expect(keyVersion()).toBe(1);
  });

  it('counts over the ledger retention window, not the approve picker default', async () => {
    // Two hours old: outside `recentBlocked`'s 30-minute default — which is the
    // `aka exception approve` picker's lookback, not a retention bound — and
    // well inside the day the ledger is actually kept for. A count taken over
    // the default would report nothing here and understate a one-way action by
    // the better part of a day.
    await seedBlocked('c33fff');
    backdate('c33fff', 2 * 60 * 60_000);

    const io = scriptedIo();
    await runException(['rotate-key', '--home', home, '--yes'], io);

    expect(io.output()).toContain(rotationBlockedLedgerNote(1));
  });

  it('counts only the rows still matchable under the current key', async () => {
    await seedBlocked('d44aaa');
    const rotated = rotateFingerprintKey(dir);
    expect(rotated.version).toBe(2);
    // Recorded under the key that is now current — the positive control. Without
    // it a zero would be indistinguishable from a reader that finds nothing.
    await seedBlocked('e55bbb');

    const io = scriptedIo();
    await runException(['rotate-key', '--home', home, '--yes'], io);

    const out = io.output();
    // Two rows in the ledger, one of them already unapprovable because it was
    // blocked under v1. Counting both would overstate what THIS rotation costs.
    expect(out).toContain(rotationBlockedLedgerNote(1));
    expect(out).not.toContain(rotationBlockedLedgerNote(2));
  });

  it('states the caveat with nothing approvable, on both paths', async () => {
    // The ledger refills within minutes of a rotation, so a note shown only
    // when the count is non-zero reads as a caveat that only sometimes applies.
    // Asserted on both paths because they print through different branches.
    const zero = rotationBlockedLedgerNote(0);

    const interactive = confirmIo('n');
    await runException(['rotate-key', '--home', home], interactive);
    expect(interactive.output()).toContain(zero);

    const unattended = scriptedIo();
    await runException(['rotate-key', '--home', home, '--yes'], unattended);
    expect(unattended.output()).toContain(zero);
  });

  it('lists the permanent grants and the ledger cost together, without the value', async () => {
    // `--yes` stands in for the retype a permanent grant asks for on a
    // terminal; this suite is non-interactive.
    await runException(
      [
        'add',
        '--home',
        home,
        '--rule',
        RULE_ID,
        '--stdin',
        '--permanent',
        '--reason',
        'pinned',
        '--yes',
      ],
      scriptedIo(`${VALUE}\n`),
    );
    await seedBlocked('f66ccc');

    const io = scriptedIo();
    await runException(['rotate-key', '--home', home, '--yes'], io);

    const out = io.output();
    // Both halves of what rotation invalidates, in the order the dashboard
    // dialog shows them: the grants that stop applying, then the ledger rows
    // that stop being approvable.
    const grants = out.indexOf('Active PERMANENT exceptions');
    const ledger = out.indexOf(rotationBlockedLedgerNote(1));
    expect(grants).toBeGreaterThanOrEqual(0);
    expect(ledger).toBeGreaterThan(grants);
    // Everything here is metadata and masked previews; the raw value has no
    // business on a screen that is only naming what stops working.
    expectNoEchoOf(out, VALUE);
  });

  it('prints the dashboard dialog’s own sentence rather than a second copy', async () => {
    // `rotationBlockedLedgerNote` is exported from @akasecurity/schema and
    // re-exported by @akasecurity/dashboard-ui, so this command and the rotate
    // dialog cannot word the same disclosure differently. Asserted against the
    // shared function itself — a literal here would be the duplicate the shared
    // helper exists to prevent, and would go green while the two drifted apart.
    await seedBlocked('077ddd');

    const io = scriptedIo();
    await runException(['rotate-key', '--home', home, '--yes'], io);

    expect(io.output()).toContain(rotationBlockedLedgerNote(1));
  });

  it('names a window that matches the one the count is actually taken over', () => {
    // The sentence hard-codes 24 hours; the read passes
    // BLOCKED_DETECTIONS_RETENTION_MS. @akasecurity/schema cannot import the
    // authority (persistence depends on schema, not the reverse), so the two
    // are pinned here — at the consumer that holds both. Widen the retention
    // and this goes red rather than the copy quietly describing a window the
    // count no longer spans.
    expect(LEDGER_WINDOW_HOURS * 60 * 60 * 1000).toBe(BLOCKED_DETECTIONS_RETENTION_MS);
  });
});

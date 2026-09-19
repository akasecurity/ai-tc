/**
 * The store-open branch, driven IN-PROCESS — both halves of it.
 *
 * The fail-open e2e matrix already drives this branch against the BUILT hooks —
 * but in a child process, where v8 collects nothing, so the branch that decides
 * WHAT THE USER IS TOLD (and the pass-through it returns from) read as untested
 * to the diff-coverage gate while the e2e proves they run. A built hook cannot
 * be imported either (`scripts/` is spawn-only), so this file drives the SOURCE
 * entry with the one input a test cannot hand a hook — its stdin — replaced, and
 * everything else left real: the config, the store, the failure, the message.
 *
 * Both halves are here because either alone proves the wrong thing. The store
 * this build cannot open shows that the warning is raised and is caused; the
 * store that opens shows that the capture really reaches the store through the
 * gateway the pass-through hands over. A file with only the first half would
 * pass with an entry that warned and then did nothing.
 *
 * The store it fails on is the SKEW shape rather than a corrupt file, which is
 * the stricter of the two. The message is chosen by `instanceof
 * StoreAheadOfBuildError` reaching across the package boundary, so a case that
 * gets the skew wording out of the entry has proven that identity survives this
 * host's own import graph, and it has proven it for the wrapped case — a corrupt
 * store fails earlier, in the applier, and never reaches the repository
 * constructors this branch exists for.
 *
 * This host has no message channel on PreToolUse, so the once-per-session
 * notice goes to STDERR (`process.stderr.write` inside `main()`), while stdout
 * carries the fail-open allow payload `runHookFailOpen` guarantees. Both are
 * asserted: the warning because it is the point, the allow because on a host
 * that fails closed, silence would deny every tool call for the session.
 */
import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type * as Shared from '../../src/hooks/shared.ts';

// Lexically past every real tag, so it sorts last and cannot collide with one a
// future migration adds.
const FUTURE_MIGRATION_TAG = '9999_from_a_newer_build';

// A value the bundled rules detect, so the healthy case has something that MUST
// reach the store. The canonical AWS example key, which is what the detection
// suites plant when they need a real match rather than a stub.
const PLANTED_SECRET = 'AKIAIOSFODNN7EXAMPLE';

// The one thing a test cannot hand a hook: its stdin. `readStdin` is replaced
// with a holder the cases fill in; every other export of the module stays real,
// `emit` and `runHookFailOpen` included, so the payloads asserted below are the
// ones that ship.
const stdin = vi.hoisted(() => ({ payload: '' }));
vi.mock('../../src/hooks/shared.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof Shared>()),
  readStdin: () => Promise.resolve(stdin.payload),
}));

/** `<home>/.aka/data` — the store directory `loadConfig` resolves for this home. */
function storeDir(home: string): string {
  return join(home, '.aka', 'data');
}

/**
 * A store this build cannot use BECAUSE IT IS NEWER: a ledger tag from a
 * migration it does not define, plus a table its repositories prepare against
 * turned into a view — the shape `0014_drop_legacy_events_findings` gave
 * `events`/`findings`. Every byte is intact and an up-to-date build reads it
 * fine.
 */
function seedStoreAheadOfBuild(home: string): void {
  mkdirSync(storeDir(home), { recursive: true });
  openLocalDatabase(storeDir(home)).close();
  const raw = new DatabaseSync(join(storeDir(home), 'aka.db'));
  try {
    raw.exec('ALTER TABLE classified_data RENAME TO classified_data_backing');
    raw.exec('CREATE VIEW classified_data AS SELECT * FROM classified_data_backing');
    raw
      .prepare('INSERT OR IGNORE INTO migration_ledger (tag, applied_at) VALUES (?, ?)')
      .run(FUTURE_MIGRATION_TAG, Date.now());
    raw.exec('PRAGMA user_version = 9999');
  } finally {
    raw.close();
  }
}

/** How many findings the hook committed to the store on this home. */
async function storedFindings(home: string): Promise<number> {
  const db = openLocalDatabase(storeDir(home));
  try {
    return (await db.findings.recentFindings()).length;
  } finally {
    db.close();
  }
}

/** Everything a hook wrote to stdout, as one payload. */
function onlyWrite(writes: readonly string[]): Record<string, unknown> {
  expect(writes, 'the hook must emit its fail-open allow payload').toHaveLength(1);
  return JSON.parse(writes[0] ?? '') as Record<string, unknown>;
}

/** Everything a hook wrote to stderr, as one line. */
function onlyStderrLine(writes: readonly string[]): string {
  expect(writes, 'the hook must say something about the store it cannot open').toHaveLength(1);
  return writes[0] ?? '';
}

describe('the store-open branch, driven through the hook entry', () => {
  let home: string;
  let originalHome: string | undefined;
  let originalUserProfile: string | undefined;
  let exit: MockInstance<typeof process.exit>;
  let stdout: MockInstance<typeof process.stdout.write>;
  let stderr: MockInstance<typeof process.stderr.write>;
  let stdoutWrites: string[];
  let stderrWrites: string[];

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-entry-store-open-'));
    // BOTH variables: `homedir()` reads $HOME on POSIX and %USERPROFILE% on
    // Windows, so pointing only one at the throwaway home would have this open
    // the developer's own store on the other — a silent contamination rather
    // than a failure, and so one nobody would notice.
    // eslint-disable-next-line n/no-process-env -- test needs to redirect ~/.aka to a throwaway home
    originalHome = process.env.HOME;
    // eslint-disable-next-line n/no-process-env -- test needs to redirect ~/.aka to a throwaway home
    originalUserProfile = process.env.USERPROFILE;
    // eslint-disable-next-line n/no-process-env -- test needs to redirect ~/.aka to a throwaway home
    process.env.HOME = home;
    // eslint-disable-next-line n/no-process-env -- test needs to redirect ~/.aka to a throwaway home
    process.env.USERPROFILE = home;
    // `runHookFailOpen` ends in `process.exit(0)`, which in-process would take
    // the whole vitest worker with it.
    exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as typeof process.exit);
    // `emit` resolves on the write callback, so the mock has to call it or the
    // wrapper's own await never settles and the import hangs. The stderr write
    // is spied for the same settle reason on the redirect path and to capture
    // the store warning, which is emitted there rather than on stdout.
    stdoutWrites = [];
    stderrWrites = [];
    stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((
      chunk: string,
      cb: () => void,
    ) => {
      stdoutWrites.push(chunk);
      cb();
      return true;
    }) as typeof process.stdout.write);
    stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((
      chunk: string,
      cb?: () => void,
    ) => {
      stderrWrites.push(chunk);
      cb?.();
      return true;
    }) as typeof process.stderr.write);
  });

  afterEach(() => {
    stdout.mockRestore();
    stderr.mockRestore();
    exit.mockRestore();
    // eslint-disable-next-line n/no-process-env -- restore the host HOME after the test
    if (originalHome === undefined) delete process.env.HOME;
    // eslint-disable-next-line n/no-process-env -- restore the host HOME after the test
    else process.env.HOME = originalHome;
    // eslint-disable-next-line n/no-process-env -- restore the host USERPROFILE after the test
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    // eslint-disable-next-line n/no-process-env -- restore the host USERPROFILE after the test
    else process.env.USERPROFILE = originalUserProfile;
    removeTree(home);
  });

  describe('when the store was written by a newer build', () => {
    // Each case runs the entry's top-level `main()` again, and the module
    // registry would otherwise hand back the evaluation the case before it
    // already ran.
    it('pre-tool-use names the version gap on stderr, and still fails open on stdout', async () => {
      seedStoreAheadOfBuild(home);
      vi.resetModules();
      stdin.payload = JSON.stringify({
        toolCall: { name: 'run_command', args: { CommandLine: 'echo hello' } },
        conversationId: 'in-process-pre-tool-use-ahead',
        stepIdx: 0,
        workspacePaths: [home],
      });

      await import('../../src/hooks/pre-tool-use.ts');

      const notice = onlyStderrLine(stderrWrites);
      expect(notice).toContain(FUTURE_MIGRATION_TAG);
      // The remedy is updating AKA. Advice to move the store aside is data loss
      // here: the corpus is intact and an up-to-date build reads it fine.
      expect(notice).not.toMatch(/aside/i);
      // Fail-open, with the allow payload the fail-closed host requires —
      // asserting on it is the positive control for the stderr write being a
      // side channel and not the whole output.
      const payload = onlyWrite(stdoutWrites);
      expect(payload).toEqual({ decision: 'allow' });
      expect(exit).toHaveBeenCalledWith(0);
    });
  });

  describe('when the store opens', () => {
    // The other half of the branch, and the reason the warning above is worth
    // anything: with a store that opens, the entry must take the gateway and
    // get on with the call. The capture reaching the STORE is what makes that a
    // presence assertion rather than "nothing was printed" — only the
    // pass-through hands a gateway to the runtime that commits it.
    it('pre-tool-use takes the gateway, commits the capture, and still allows', async () => {
      vi.resetModules();
      stdin.payload = JSON.stringify({
        toolCall: { name: 'run_command', args: { CommandLine: `echo ${PLANTED_SECRET}` } },
        conversationId: 'in-process-pre-tool-use-open',
        stepIdx: 0,
        workspacePaths: [home],
      });

      await import('../../src/hooks/pre-tool-use.ts');

      // A healthy store records a shell command ONLY when a rule matched it —
      // the capture is persisted `with-findings`, so an ordinary command is not
      // copied into the store — which is why the payload carries a value the
      // bundled rules detect. The findings row is the whole control.
      // `> 0` rather than an exact count: how many rules match this key is the
      // detection suite's business, and a rule change must not redden this file.
      expect(await storedFindings(home)).toBeGreaterThan(0);
      // Under the default log-only enforcement the decision is the plain allow,
      // and it is asserted rather than assumed: this host always emits a
      // payload, so "still allow" is a presence assertion here, not an absence.
      expect(onlyWrite(stdoutWrites)).toEqual({ decision: 'allow' });
      // No store trouble to report, so the stderr side channel stays silent —
      // the case in the describe above is the positive control for this absence.
      expect(stderrWrites).toEqual([]);
      expect(exit).toHaveBeenCalledWith(0);
    });
  });
});

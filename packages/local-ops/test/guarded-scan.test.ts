/**
 * The ReDoS bound on the filesystem scan — the one the dashboard's folder scan
 * runs the installed-pack snapshot through.
 *
 * Three things have to hold together, and none is visible from the guard alone:
 * a walk whose pulled rule never returns still finishes and records findings;
 * the rules that DO have an upper bound keep detecting through it; and the
 * machine converges — the culprit is quarantined in the shared verdict cache,
 * so neither a later scan nor a hook process ever loads it again.
 *
 * The two hostile shapes are the ones the plugin's own isolation suite pins,
 * because they fail at DIFFERENT gates and either alone would leave half the
 * bound untested: one clears the timing battery and then backtracks forever on
 * real text (only the scan deadline catches it), the other hangs the battery
 * itself (only a killable measurement catches it).
 */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, ruleProbeKey } from '@akasecurity/plugin-sdk';
import type { Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import type { ScanPathResult } from '../src/fs-scan.ts';
import { scanPathIntoStore } from '../src/fs-scan.ts';
import { createGuardedFileScanner } from '../src/guarded-scan.ts';
import { countWorkerStarts } from './helpers/worker-starts.ts';

// The worker as this repo runs it: Node hands the `.ts` straight to the
// type-stripper. The BUILT artifact the dashboard ships is a different file and
// is proven separately — see web-ui/test/e2e/scan-worker-bundle.e2e.test.ts.
const WORKER = new URL('../../plugin-sdk/src/scan-worker.ts', import.meta.url);

// Points the guard at a module that throws on load, so a case whose premise is
// "no worker is needed here" fails loudly if one is ever started.
const CRASHING_WORKER = new URL('./helpers/crashing-scan-worker.ts', import.meta.url);

// Clears the timing battery in microseconds — every probe fails at the `zzq`
// literal before reaching the nested quantifier — and then backtracks without
// end on text that carries it. Only the scan's own deadline can stop this one.
const BATTERY_BLIND: Rule = {
  specVersion: 1,
  id: 'pulled/battery-blind',
  name: 'Battery-blind pulled rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`(?:zzq)(a+)+$`, flags: 'g' },
};
const BATTERY_BLIND_TEXT = `zzq${'a'.repeat(34)}!`;

// The other shape. Measuring a rule means driving its own pattern into
// backtracking, so a pattern that is catastrophic on the battery's OWN derived
// probe hangs the measurement — before any scan runs.
const BATTERY_KILLER: Rule = {
  specVersion: 1,
  id: 'pulled/battery-killer',
  name: 'Battery-killing pulled rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`(a|a|a|a)+$`, flags: 'g' },
};

// A pulled REGEX rule that is perfectly well behaved: no quantified group whose
// body can match the same text two ways, so it cannot backtrack. It is still
// `unverified` — no CI gate has ever seen it — so it runs under the bound and is
// dropped as COLLATERAL when a neighbour hangs and isolation retires.
//
// That is what makes it the instrument for the scanner's lifetime. A quarantined
// rule is gone from every later scan by design, so it can say nothing about
// whether the next scan got a fresh scanner; a rule dropped only as collateral
// is supposed to come BACK, and does so only if the next scan builds its own.
const BENIGN_PULLED: Rule = {
  specVersion: 1,
  id: 'pulled/benign',
  name: 'Benign pulled rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`PULLEDMARKER-[A-Z0-9]{8}`, flags: 'g' },
};
const BENIGN_PULLED_TEXT = 'PULLEDMARKER-7QW2ZK4M';

// A pulled KEYWORD rule. Its matcher compiles one fully-escaped literal per
// keyword, so nothing its author writes can make it backtrack: it needs no
// worker, and a keyword-only custom pack must start none.
const PULLED_KEYWORD: Rule = {
  specVersion: 1,
  id: 'pulled/keyword',
  name: 'Pulled keyword rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'keyword', keywords: ['TOKENX'], caseSensitive: false },
};

// A real compiled-in rule and text it matches, taken from the packs themselves
// rather than restated here — this is the control for "the rules with a bound
// behind them keep detecting", so it has to be one the guard actually treats as
// CI-verified, which is decided by probe key.
function bundledControl(): { rule: Rule; text: string } {
  for (const pack of bundledDetections()) {
    for (const rule of pack.rules) {
      const example = rule.examples?.[0];
      if (rule.matcher.type === 'regex' && example !== undefined && example.length > 0) {
        return { rule, text: example };
      }
    }
  }
  throw new Error('no bundled regex rule with an example — the control cannot be built');
}
const CONTROL = bundledControl();

const BUDGET_MS = 1_500;

// Startup grace for every worker built here, and the reason is this environment
// rather than the product's: CI runs the type-stripped `.ts` worker with the
// whole workspace's suites in parallel, where a cold start has been seen past
// 5s on a Windows runner — against ~15ms for the bundled script the dashboard
// actually ships. On the product's own ISOLATED_START_BUDGET_MS the runner's
// speed would decide whether the assertion under test runs at all: the scanner
// reports `unavailable` and the case fails on something it never measured.
const START_MS = 30_000;

// A worker start is granted START_MS above, so any elapsed ceiling has to budget
// that per start or it can be blown by a start this file explicitly permits.
// `starts` is how many workers the path builds; `budgetUnits` is whatever
// multiple of BUDGET_MS the case justifies.
const ceilingMs = (starts: number, budgetUnits: number): number =>
  starts * START_MS + budgetUnits * BUDGET_MS;

// Above every ceiling below, so a path that blows its bound fails on the
// assertion — which names what was exceeded — rather than on the package's
// 20s default, which just says the test timed out.
const CASE_TIMEOUT_MS = 150_000;

let root: string;
let store: string;
let db: LocalDatabase;

// Pre-seed the verdict cache the way a real machine looks after its first scan.
// Every case whose premise is "the battery CLEARED this rule and the SCAN is
// what has to catch it" needs it: without it the rule must survive a live
// measurement on the runner first, and a slow one can quarantine it at the gate
// instead. The scan bound then never runs and the case still passes on its
// other assertions, because the bundled control did the detecting — a green
// test that exercised nothing it was written for.
function clearedByPreflight(...rules: Rule[]): void {
  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key !== undefined) db.ruleProbeCache.setVerdict(key, 'safe', 0.1);
  }
}

function verdictOf(rule: Rule): string | undefined {
  const key = ruleProbeKey(rule);
  return key === undefined ? undefined : db.ruleProbeCache.getVerdict(key)?.verdict;
}

async function foundRuleIds(): Promise<string[]> {
  const findings = await db.findings.recentFindings({ limit: 50 });
  return findings.map((f) => f.ruleId);
}

// What ONE walk found, from the walk's own result rather than from the store.
// The store accumulates across scans, so a case that runs two of them cannot ask
// it which scan a finding came from — and "the second scan still detects this"
// is satisfied by the first scan's row if it does.
function ruleIdsIn(result: ScanPathResult): string[] {
  return result.files.flatMap((file) => file.findings.map((finding) => finding.ruleId));
}

// Both gates report on stderr by design — that line is the only place the
// machine ever mentions a quarantine. Keep the suite's own output readable.
function silenceStderr(): void {
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-guarded-scan-'));
  store = mkdtempSync(join(tmpdir(), 'aka-guarded-scan-db-'));
  db = openLocalDatabase(store);
});

afterEach(() => {
  vi.restoreAllMocks();
  db.close();
  removeTrees([root, store]);
});

// Walk a tree exactly as the dashboard's Scan action does — one scanner per
// call, built inside and closed in a `finally`, which is the per-request
// lifetime the Server Action has. Two calls therefore mean two scanners, and
// that is what the lifetime case below rests on.
//
// `starts` counts the threads THIS scan builds. It is the shape instrument the
// elapsed ceilings cannot be: a ceiling has to grant START_MS per start, so an
// extra recovery cycle costs ~1.6s and disappears inside a 63s bound.
async function guardedScan(
  rules: Rule[],
  workerUrl: URL | undefined,
  opts: { passBudgetMs?: number; path?: string } = {},
) {
  const starts = countWorkerStarts();
  const guard = await createGuardedFileScanner(db, rules, {
    workerUrl,
    budgetMs: BUDGET_MS,
    probeBudgetMs: BUDGET_MS,
    startBudgetMs: START_MS,
    passBudgetMs: opts.passBudgetMs,
    onWorkerStart: starts.onWorkerStart,
  });
  try {
    const result = await scanPathIntoStore(db, opts.path ?? root, { scanText: guard.scanText });
    return { result, dropped: guard.dropped(), starts };
  } finally {
    await guard.close();
  }
}

// How many files carry the hostile text. THREE, not one, and the count is
// load-bearing in both directions.
//
// Bounded, it costs nothing: the first file's hang retires isolation, so the
// remaining two are scanned by the rules that never needed a bound. Unbounded,
// it costs three hangs — and that is what makes the elapsed ceiling below able
// to fail at all. The ceiling has to grant two worker starts (see START_MS), so
// it sits at 63s, while ONE unbounded pass over this text measures ~50-80s on an
// arm64 Mac. A single hostile file would therefore slip under the ceiling, and
// the case would be left pinning the bound with nothing but its `dropped`
// count. Three does not slip under it on any machine.
const HOSTILE_FILES = 3;

describe('a pulled rule that never returns', () => {
  it(
    'is terminated mid-walk, and the walk finishes every remaining file',
    async () => {
      silenceStderr();
      for (let i = 0; i < HOSTILE_FILES; i++) {
        writeFileSync(join(root, `app${String(i)}.ts`), `${BATTERY_BLIND_TEXT}\n${CONTROL.text}\n`);
      }
      clearedByPreflight(BATTERY_BLIND);

      const started = performance.now();
      const { result, dropped, starts } = await guardedScan([CONTROL.rule, BATTERY_BLIND], WORKER);
      const elapsedMs = performance.now() - started;

      // The property the whole change exists for. Left in-process these files
      // take longer than anyone will wait, and a Server Action has no harness
      // timeout to kill it — the request simply never answers. Worst case here
      // is TWO budgets (the scan, then the retry that names the rule) on TWO
      // worker starts, which is what the ceiling has to cover.
      expect(elapsedMs).toBeLessThan(ceilingMs(2, 2));

      // TWO threads, and that is the number rather than a bound on it: the scan
      // that hung, then the fresh thread the attributing retry runs on so the
      // rule can be NAMED. The pre-flight builds none, because both verdicts are
      // pre-seeded above — a third thread here would mean it re-measured a rule
      // the cache already answered.
      //
      // The ceiling above cannot make this check. It has to grant START_MS per
      // start (see `ceilingMs`), so it sits at 63s while a whole extra recovery
      // cycle costs about 1.6s — an added cycle hides inside it with room to
      // spare. That is the same blind spot the hook path had, and the count is
      // the same instrument that closed it there.
      expect(starts.count()).toBe(2);

      // The walk did not stop at the file that hung.
      expect(result.scanned).toBe(HOSTILE_FILES);
      expect(result.files).toHaveLength(HOSTILE_FILES);

      // And the rules that DO have a bound behind them kept detecting through
      // it — in the file that hung as well as the ones after it.
      expect(await foundRuleIds()).toEqual(Array(HOSTILE_FILES).fill(CONTROL.rule.id));

      // The request can also say what it cost: the guard dropped the isolated
      // rule rather than silently scanning without it.
      expect(dropped).toEqual({ quarantined: 0, unmeasured: 0, bound: 1, isolated: true });

      // Convergence. The verdict is shared with the hooks, so the next scan —
      // and the next hook process — drops this rule before it reaches a scan at
      // all, instead of paying the deadline again.
      expect(verdictOf(BATTERY_BLIND)).toBe('quarantined');
    },
    CASE_TIMEOUT_MS,
  );
});

describe('a pulled rule that hangs the timing battery itself', () => {
  it(
    'is quarantined at the pre-flight, before the walk starts',
    async () => {
      silenceStderr();
      writeFileSync(join(root, 'app.ts'), `${CONTROL.text}\n`);
      // No pre-seeded verdict: measuring this one for real is the point.

      const started = performance.now();
      const { result, dropped } = await guardedScan([CONTROL.rule, BATTERY_KILLER], WORKER);
      const elapsedMs = performance.now() - started;

      expect(elapsedMs).toBeLessThan(ceilingMs(2, 1));
      expect(result.scanned).toBe(1);
      expect(await foundRuleIds()).toContain(CONTROL.rule.id);
      // MEASURED, so it left a row behind — which is what makes `aka detections`
      // able to name it, and what the Scan page's notice may point at.
      expect(dropped).toEqual({ quarantined: 1, unmeasured: 0, bound: 0, isolated: true });

      // A measurement that had to be TERMINATED is the strongest unsafe verdict
      // there is, so unlike a rule the pass budget merely ran out on, this one
      // is persisted: the pattern did not exceed a budget, it never came back.
      expect(verdictOf(BATTERY_KILLER)).toBe('quarantined');
    },
    CASE_TIMEOUT_MS,
  );
});

describe('a build that ships no scan worker', () => {
  it(
    'drops the rules it cannot bound and says so, rather than running them',
    async () => {
      silenceStderr();
      writeFileSync(join(root, 'app.ts'), `${BATTERY_BLIND_TEXT}\n${CONTROL.text}\nTOKENX\n`);
      // Cached safe, so nothing here is about the pre-flight's own verdict: the
      // question is what happens to a rule that CLEARED it when there is
      // nowhere to enforce the runtime bound. Promoting it into the in-process
      // set would put back exactly the unbounded call the worker exists to
      // remove — the battery is empirical, and this pattern beat it.
      clearedByPreflight(BATTERY_BLIND);

      const started = performance.now();
      const { result, dropped } = await guardedScan(
        [CONTROL.rule, BATTERY_BLIND, PULLED_KEYWORD],
        undefined,
      );
      const elapsedMs = performance.now() - started;

      expect(elapsedMs).toBeLessThan(ceilingMs(0, 1));
      expect(result.scanned).toBe(1);
      // UNMEASURED, not quarantined: nothing was timed here, so nothing is
      // cached and the notice must not send anyone to `aka detections`.
      expect(dropped).toEqual({ quarantined: 0, unmeasured: 1, bound: 0, isolated: false });
      expect(db.ruleProbeCache.countQuarantined()).toBe(0);

      // The two matchers that cannot backtrack still ran: a compiled-in rule,
      // and a pulled KEYWORD rule, whose fully-escaped literals are safe
      // whatever the pack author wrote.
      const found = await foundRuleIds();
      expect(found).toContain(CONTROL.rule.id);
      expect(found).toContain(PULLED_KEYWORD.id);
      expect(found).not.toContain(BATTERY_BLIND.id);

      // Nothing was measured, so nothing is cached: quarantining a rule forever
      // on the strength of a missing file would be a wrong verdict, not a
      // cautious one.
      expect(verdictOf(BATTERY_BLIND)).toBe('safe');
    },
    CASE_TIMEOUT_MS,
  );
});

describe('a ruleset with nothing to isolate', () => {
  it(
    'starts no worker at all',
    async () => {
      writeFileSync(join(root, 'app.ts'), `${CONTROL.text}\nTOKENX\n`);

      // The tripwire: this worker throws at load. Any path that builds one —
      // the pre-flight's prober or the scan's own — reports `unavailable`,
      // which shows up as a dropped rule below. A green run here is a run that
      // never went near a thread.
      const { result, dropped, starts } = await guardedScan(
        [CONTROL.rule, PULLED_KEYWORD],
        CRASHING_WORKER,
      );

      // The case's own name, asserted rather than inferred. The tripwire above
      // catches a worker that is constructed AND loads; this catches one that is
      // constructed at all, which is the thing the name claims.
      expect(starts.count()).toBe(0);
      expect(dropped).toEqual({ quarantined: 0, unmeasured: 0, bound: 0, isolated: true });
      expect(result.scanned).toBe(1);
      const found = await foundRuleIds();
      expect(found).toContain(CONTROL.rule.id);
      expect(found).toContain(PULLED_KEYWORD.id);
    },
    CASE_TIMEOUT_MS,
  );
});

describe('a pre-flight that runs out of time before it reaches a rule', () => {
  it(
    'reports the rule as unmeasured and caches nothing for it',
    async () => {
      silenceStderr();
      writeFileSync(join(root, 'app.ts'), `${CONTROL.text}\n`);
      // A pass budget already spent, which is what a cold cache full of slow
      // rules produces on a real machine. The rule is excluded WITHOUT a
      // verdict — deliberately, since it was never timed — and that is what
      // makes it different from one the battery measured and failed.
      const { dropped } = await guardedScan([CONTROL.rule, BATTERY_BLIND], WORKER, {
        passBudgetMs: 0,
      });

      expect(dropped).toEqual({ quarantined: 0, unmeasured: 1, bound: 0, isolated: true });
      // The half a `preflight` count could not express, and the reason the Scan
      // page must not offer `aka detections` here: that command prints its
      // quarantine block only when this count is above zero.
      expect(verdictOf(BATTERY_BLIND)).toBeUndefined();
      expect(db.ruleProbeCache.countQuarantined()).toBe(0);

      // …and a build WITH a worker is what makes this distinct from the
      // missing-worker case, which wants a different message entirely.
      expect(dropped.isolated).toBe(true);
    },
    CASE_TIMEOUT_MS,
  );
});

describe("a scanner's degradation, seen from the next scan", () => {
  it(
    'is gone — a scan gets its own scanner, so collateral comes back',
    async () => {
      silenceStderr();
      // Two trees under one root, because the walk is what a scan is: the first
      // has the rule that hangs, the second has only the collateral's marker, so
      // what the second scan finds is decided entirely by the ruleset it runs.
      const hostile = join(root, 'hostile');
      const later = join(root, 'later');
      mkdirSync(hostile);
      mkdirSync(later);
      for (let i = 0; i < HOSTILE_FILES; i++) {
        writeFileSync(
          join(hostile, `app${String(i)}.ts`),
          `${BATTERY_BLIND_TEXT}\n${CONTROL.text}\n`,
        );
      }
      writeFileSync(join(later, 'app.ts'), `${BENIGN_PULLED_TEXT}\n${CONTROL.text}\n`);
      clearedByPreflight(BATTERY_BLIND, BENIGN_PULLED);

      const rules = [CONTROL.rule, BATTERY_BLIND, BENIGN_PULLED];
      const first = await guardedScan(rules, WORKER, { path: hostile });

      // The premise, asserted rather than assumed. BOTH pulled rules were under
      // the bound when it fired, so both were dropped — the one that hung and
      // the one that merely happened to be in the same ruleset. Without this the
      // case below could pass on a first scan that never degraded at all.
      expect(first.dropped).toEqual({
        quarantined: 0,
        unmeasured: 0,
        bound: 2,
        isolated: true,
      });
      // Only the culprit left a verdict. The collateral is still `safe`, which
      // is precisely why the next scan is entitled to run it.
      expect(verdictOf(BATTERY_BLIND)).toBe('quarantined');
      expect(verdictOf(BENIGN_PULLED)).toBe('safe');

      const second = await guardedScan(rules, WORKER, { path: later });

      // The property. A second scanner was built, so the collateral is back and
      // detecting; a scanner hoisted out of the request would hand this scan the
      // retired one, whose unverified rules are gone for good.
      expect(ruleIdsIn(second.result)).toContain(BENIGN_PULLED.id);
      // …and the second scan is not itself degraded: it dropped the culprit at
      // the pre-flight, on the cached verdict, and nothing at the bound.
      expect(second.dropped).toEqual({
        quarantined: 1,
        unmeasured: 0,
        bound: 0,
        isolated: true,
      });

      // The same property read as threads, which is the shape a `toContain` on
      // findings cannot state. A fresh scanner builds its own worker for the
      // collateral; a shared one that already retired builds none, because it
      // has no unverified rule left to bound.
      expect(second.starts.count()).toBe(1);
    },
    CASE_TIMEOUT_MS,
  );
});

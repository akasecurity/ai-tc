import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { dataDir, type LocalDatabase, openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, ruleProbeKey } from '@akasecurity/plugin-sdk';
import type { Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { runScan } from '../../app/(app)/scan/actions.ts';

/**
 * The dashboard's folder scan against a hostile installed pack.
 *
 * This action runs the INSTALLED-PACK snapshot — pulled and custom packs
 * included, none of them reviewed by this repository — over a user-chosen tree.
 * A regex has no upper bound, so one catastrophic pattern would not slow the
 * request down, it would stop it answering: unlike a plugin hook, a Server
 * Action has no harness timeout to be killed by, so nothing would ever return.
 *
 * The bound itself is covered where it lives (packages/local-ops/test/
 * guarded-scan.test.ts). What only this suite can show is that the ACTION is
 * wired to it — including the half that is invisible from source, because the
 * action resolves its worker from a path this package's build produces. The
 * `test` script builds it first for exactly that reason.
 *
 * Setup follows the four steps every web-ui Server Action test needs: redirect
 * the home dir by mocking `node:os` (the action resolves ~/.aka from it, and
 * n/no-process-env rules out an env override), stub `next/cache` (revalidatePath
 * needs a Next render context that does not exist under vitest), and close and
 * drop the memoised DB handle on globalThis around every test.
 */
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Clears the timing battery in microseconds — every probe fails at the `zzq`
// literal before reaching the nested quantifier — and then backtracks without
// end on text that carries it. The rule is schema-valid: `matchesEmptyString`
// turns away a `*`-quantified outer group, and this one requires a character.
const HOSTILE: Rule = {
  specVersion: 1,
  id: 'hostile/battery-blind',
  name: 'Battery-blind pulled rule',
  category: 'custom',
  severity: 'low',
  matcher: { type: 'regex', pattern: String.raw`(?:zzq)(a+)+$`, flags: 'g' },
};
const HOSTILE_TEXT = `zzq${'a'.repeat(34)}!`;

// See guarded-scan.test.ts: three hostile files, so an unbounded walk is
// decisively past the ceiling below rather than merely near it.
const HOSTILE_FILES = 3;

// A real compiled-in rule and text it matches, taken from the packs rather than
// restated here. This is the control for "the rules that never needed a bound
// keep detecting", so it has to be one the guard really treats as CI-verified.
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

// The action runs the SHIPPED budgets (there is no seam to shorten them, and a
// seam here would be a seam in production code for a test's benefit), so the
// worst case is two worker starts at ISOLATED_START_BUDGET_MS = 5s plus two
// scan deadlines at ISOLATED_SCAN_BUDGET_MS = 2s. x2 for a loaded runner.
const CEILING_MS = 2 * (2 * 5_000 + 2 * 2_000);

// Above the ceiling, so a blown bound fails on the assertion — which names what
// was exceeded — rather than on the package's 20s default, which just says the
// test timed out.
const CASE_TIMEOUT_MS = 120_000;

let home: string;
let target: string;

function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

// Install the bundled packs plus a pulled pack carrying `rules`, and mark every
// regex rule in that pulled pack as already measured SAFE.
//
// The pre-seeded verdict is what makes this a test of the SCAN bound. Without
// it the hostile rule has to survive a live measurement on the runner first, and
// a slow one quarantines it at the pre-flight instead — the scan bound then
// never runs and the case still passes on its other assertions, because the
// bundled control did the detecting. It is also the honest steady state: a real
// machine measures a rule once, ever.
function installPulled(rules: Rule[]): void {
  const db = openLocalDatabase(dataDir());
  try {
    db.installedPacks.recordInventory([
      ...bundledDetections(),
      {
        namespace: 'hostile',
        packId: 'redos',
        version: '1.0.0',
        name: 'Hostile pulled pack',
        rules,
      },
    ]);
    for (const rule of rules) {
      const key = ruleProbeKey(rule);
      if (key !== undefined) db.ruleProbeCache.setVerdict(key, 'safe', 0.1);
    }
  } finally {
    db.close();
  }
  // The action reads through the memoised handle, so it has to reopen and see
  // what this second handle just wrote.
  resetSingleton();
}

async function recordedRuleIds(): Promise<string[]> {
  const db = openLocalDatabase(dataDir());
  try {
    const findings = await db.findings.recentFindings({ limit: 50 });
    return findings.map((f) => f.ruleId);
  } finally {
    db.close();
  }
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-scan-'));
  osHome.dir = home;
  target = mkdtempSync(join(tmpdir(), 'aka-web-scan-target-'));
  resetSingleton();
  // The guard reports on stderr as well as in the response; keep the suite's
  // own output readable.
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  resetSingleton();
  rmSync(home, { recursive: true, force: true });
  rmSync(target, { recursive: true, force: true });
});

describe('runScan — a pulled rule that never returns', () => {
  it(
    'answers, records what the bounded rules found, and names what it dropped',
    async () => {
      for (let i = 0; i < HOSTILE_FILES; i++) {
        writeFileSync(join(target, `app${String(i)}.ts`), `${HOSTILE_TEXT}\n${CONTROL.text}\n`);
      }
      installPulled([HOSTILE]);

      const started = performance.now();
      const result = await runScan(target);
      const elapsedMs = performance.now() - started;

      // The whole point: the request came back.
      expect(elapsedMs).toBeLessThan(CEILING_MS);
      expect(result.ok).toBe(true);
      expect(result.scanned).toBe(HOSTILE_FILES);

      // The compiled-in packs detected right through it — in every file, not
      // just the ones after the hang. (Counted rather than compared as a set:
      // the snapshot here is the whole bundled inventory, so an example that
      // matches one rule by design also matches its neighbours.)
      const ids = await recordedRuleIds();
      expect(ids.filter((id) => id === CONTROL.rule.id)).toHaveLength(HOSTILE_FILES);
      expect(ids).not.toContain(HOSTILE.id);
      expect(result.findings).toBe(ids.length);

      // And it says what was dropped — a scan that quietly ran a smaller
      // ruleset than the Detections page lists is the failure mode this whole
      // surface has to avoid.
      expect(result.droppedRules).toBeDefined();
      expect(result.droppedRules).toContain('1 rule');
      expect(result.droppedRules).toContain('time bound');

      // The pointer is offered here BECAUSE the bound named its culprit and
      // cached a verdict — so `aka detections` really does have something to
      // print. The wiring is what this asserts: the action reads that count
      // from the store rather than assuming it. (What the sentence does when
      // the count is zero is pinned in test/actions/dropped-rules.test.ts.)
      const store = openLocalDatabase(dataDir());
      try {
        expect(store.ruleProbeCache.countQuarantined()).toBeGreaterThan(0);
      } finally {
        store.close();
      }
      expect(result.droppedRules).toContain('aka detections');
    },
    CASE_TIMEOUT_MS,
  );
});

describe('runScan — an ordinary installed snapshot', () => {
  it(
    'reports nothing dropped and detects normally',
    async () => {
      writeFileSync(join(target, 'app.ts'), `${CONTROL.text}\n`);
      installPulled([]);

      const result = await runScan(target);

      expect(result.ok).toBe(true);
      expect(result.scanned).toBe(1);
      const ids = await recordedRuleIds();
      expect(ids).toContain(CONTROL.rule.id);
      expect(result.findings).toBe(ids.length);
      // The negative control for the case above: with nothing to bound, the
      // response carries no notice at all, so a `droppedRules` that appeared on
      // every scan would fail here rather than reading as normal.
      expect(result.droppedRules).toBeUndefined();
    },
    CASE_TIMEOUT_MS,
  );
});

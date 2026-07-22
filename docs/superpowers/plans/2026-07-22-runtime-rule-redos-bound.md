# Runtime Rule ReDoS Bound Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the runtime ReDoS gap (akasecurity/engineering#3) so a regex rule arriving from a pulled or custom pack — never checked by the CI adversarial battery — cannot hang the synchronous, uninterruptible `scan()` on the hook path.

**Architecture:** Extract the existing adversarial probe battery (`packages/detections/test/security/redos.test.ts`) into a reusable pure module, add a one-time timing pre-flight for regex rules sourced from the local SQLite "installed packs" snapshot, and cache the safe/quarantined verdict across hook process invocations (each hook is a fresh short-lived process, so an in-memory cache alone would be rebuilt every tool call). Bundled rules bypass the pre-flight entirely — they're already gated by the CI battery on every commit.

**Tech Stack:** TypeScript strict/ESM, Vitest, Node 24 `node:sqlite`, Zod (`@akasecurity/schema`), pnpm workspaces.

## Global Constraints

- Package dependency graph is ESLint/CI-enforced (`CLAUDE.md` "Package dependency rules") — do not add an import across a forbidden package wall. Specifically: `@akasecurity/persistence` depends only on `node:sqlite` + `@akasecurity/schema` (no `@akasecurity/detections`); `@akasecurity/plugin-runtime` depends only on `plugin-sdk` + `persistence` + `schema` (no `detections`); `@akasecurity/plugin-sdk` depends on `detections` + `persistence` + `schema` — it is the only layer allowed to touch both `detections` and `persistence`, so the actual timing measurement must happen there, not in `persistence` or `plugin-runtime`.
- `@akasecurity/persistence` is public-only for `node:sqlite`/`schema` — no Drizzle import (CLAUDE.md rule).
- New cross-package data shapes belong in `@akasecurity/schema`'s Zod layer first (CLAUDE.md "Contracts before code").
- Comments explain *what*, never internal *why*/narration (this repo is public) — no design-doc/issue references in shipped code comments.
- No `process.env` reads, no `fetch()` anywhere in the OSS surface (unrelated to this change, but applies to any new code written).
- Every plugin-local SQLite table is created idempotently (`CREATE TABLE IF NOT EXISTS`) in `packages/persistence/src/migrations.ts`, never through the Drizzle-generated canonical migrations — mirrors `scan_ledger`/`blocked_detections`.
- Test runner per package: `pnpm --filter <package-name> test` runs `vitest run`.

---

### Task 1: Schema — add the `RuleProbeVerdict` enum

**Files:**
- Modify: `packages/schema/src/zod/rule.ts`
- Test: `packages/schema/test/zod/rule.test.ts`

**Interfaces:**
- Produces: `RuleProbeVerdict` (Zod enum schema + inferred type) = `'safe' | 'quarantined'`, exported from `@akasecurity/schema` (via the existing `export * from './zod/rule.ts'` → `zod/index.ts` → `src/index.ts` barrel chain — no barrel file edits needed).

- [ ] **Step 1: Write the failing test**

Add to the end of `packages/schema/test/zod/rule.test.ts`:

```ts
import { RuleProbeVerdict } from '../../src/zod/rule.ts';

describe('RuleProbeVerdict', () => {
  it('accepts safe and quarantined', () => {
    expect(RuleProbeVerdict.safeParse('safe').success).toBe(true);
    expect(RuleProbeVerdict.safeParse('quarantined').success).toBe(true);
  });

  it('rejects any other value', () => {
    expect(RuleProbeVerdict.safeParse('unknown').success).toBe(false);
    expect(RuleProbeVerdict.safeParse('').success).toBe(false);
  });
});
```

(Add the `RuleProbeVerdict` import to the existing `import { Rule } from '../../src/zod/rule.ts';` line at the top of the file instead of a new import line — combine into one import.)

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @akasecurity/schema test -- rule.test.ts`
Expected: FAIL — `RuleProbeVerdict` is not exported from `../../src/zod/rule.ts`.

- [ ] **Step 3: Write minimal implementation**

In `packages/schema/src/zod/rule.ts`, add directly after the `MatcherType` export (after line 7, before `KeywordMatcher`):

```ts
// The one-time ReDoS timing verdict for a regex rule, cached locally so a
// rule already measured is never re-measured on a later hook invocation.
// 'safe' means the rule passed the adversarial probe battery within budget;
// 'quarantined' means it was excluded from the active ruleset.
export const RuleProbeVerdict = z.enum(['safe', 'quarantined']).meta({ id: 'RuleProbeVerdict' });
export type RuleProbeVerdict = z.infer<typeof RuleProbeVerdict>;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @akasecurity/schema test -- rule.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/schema/src/zod/rule.ts packages/schema/test/zod/rule.test.ts
git commit -m "feat(schema): add RuleProbeVerdict enum"
```

---

### Task 2: Detections — extract the probe battery and add `checkRuleTiming`

**Files:**
- Create: `packages/detections/src/security/redos-probe.ts`
- Create: `packages/detections/test/security/redos-probe.test.ts`
- Modify: `packages/detections/test/security/redos.test.ts` (extraction refactor — behavior unchanged)
- Modify: `packages/detections/src/index.ts`

**Interfaces:**
- Produces: `BUDGET_MS: number`, `CATASTROPHIC_RATIO: number`, `EXPONENTIAL_PROBES: string[]`, `POLYNOMIAL_PROBES: string[]`, `worstProbeMs(rule: Rule): { ms: number; probe: string }`, `benignBaselineMs(rule: Rule, length: number): number`, `backtrackRatio(rule: Rule): { ratio: number; ms: number; benignMs: number }`, `checkRuleTiming(rule: Rule): { safe: boolean; worstMs: number; probe: string }` — all from `packages/detections/src/security/redos-probe.ts`, and `checkRuleTiming` additionally re-exported from `@akasecurity/detections`'s public `index.ts` (needed by Task 6).

- [ ] **Step 1: Create the shared module**

Write `packages/detections/src/security/redos-probe.ts`:

```ts
import type { Rule } from '@akasecurity/schema';

import { scan } from '../index.ts';

// scan() is synchronous and cannot be interrupted mid-exec, so a catastrophic
// regex rule can hang the hook path. This module measures a rule's worst-case
// execution time against an adversarial probe battery — used both by the CI
// gate for bundled rules (redos.test.ts) and by the runtime pre-flight check
// for rules that arrive from a pulled or custom pack.
export const BUDGET_MS = 100;

// Two FIXED probe tiers, because the two failure modes need opposite inputs.
//
// Exponential backtracking blows up on SHORT input — 26 chars is already
// seconds — so a long probe would hang the run instead of failing it. Each
// unit is a near-miss run capped with a character that forces the match to
// fail, which is what drives the backtracking.
const EXPONENTIAL_UNITS = [
  'a',
  '0',
  ' ',
  'x',
  'ab',
  'a.',
  'a-',
  'a_',
  'a@',
  'a/',
  'a:',
  'a=',
  'a;',
  'aA0',
  '\t',
];
export const EXPONENTIAL_PROBES = EXPONENTIAL_UNITS.flatMap((unit) =>
  [24, 26].map((len) => unit.repeat(Math.ceil(len / unit.length)).slice(0, len) + '!'),
);

// Quadratic backtracking only shows up at scale — this is the tier that
// catches slow-but-not-catastrophic patterns a short probe would miss.
export const POLYNOMIAL_PROBES = ['abc-', 'a.', 'a ', 'a=', 'x', '0', 'a@', 'a/', 'ab'].map(
  (unit) => unit.repeat(10_000).slice(0, 40_000) + '!',
);

// The literal prefix a pattern requires before its first variable construct.
// A rule like `ghp_([A-Za-z0-9]+)+$` fails at the literal `ghp_` for every
// probe that does not start with it, so its catastrophic tail is unreachable
// unless the probe is prefixed. Anchors and boundaries are skipped; a `\d`,
// `\w`, `.` etc. ends the prefix.
function literalPrefix(pattern: string): string {
  let prefix = '';
  let i = 0;
  if (pattern[i] === '^') i++;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === undefined) break;
    if (c === '\\') {
      const next = pattern[i + 1];
      if (next === 'b' || next === 'B') {
        i += 2;
        continue;
      }
      if (next === undefined || /[dDwWsSnrtfv.]/.test(next)) break;
      prefix += next;
      i += 2;
      continue;
    }
    if ('([{.*+?|)]}^$'.includes(c)) break;
    prefix += c;
    i++;
  }
  return prefix;
}

// One representative character per character class / shorthand the pattern uses,
// so a probe run is made of characters the pattern's repeated group actually
// consumes. Falls back to 'a' when the pattern names no class.
function fuelChars(pattern: string): string[] {
  const fuel = new Set<string>();
  for (const m of pattern.matchAll(/\[\^?([^\]]+)\]/g)) {
    const body = m[1];
    if (body === undefined) continue;
    const range = /([A-Za-z0-9])-[A-Za-z0-9]/.exec(body);
    const rangeStart = range?.[1];
    if (rangeStart !== undefined) fuel.add(rangeStart);
    else {
      const literal = body.replace(/\\/g, '')[0];
      if (literal !== undefined && literal !== '^') fuel.add(literal);
    }
  }
  if (pattern.includes('\\w')) fuel.add('a');
  if (pattern.includes('\\d')) fuel.add('0');
  if (pattern.includes('\\s')) fuel.add(' ');
  if (/(?<!\\)\./.test(pattern)) fuel.add('a');
  if (fuel.size === 0) fuel.add('a');
  return [...fuel];
}

// Adversarial inputs derived from the pattern itself: `<prefix><fuel×N><term>`,
// where `term` is a character the fuel class does not contain, forcing the
// repeated group to fail and backtrack. Exponential-scale only (26/28 chars) —
// a long derived probe would false-positive on rules that are linear-but-slow
// on a big input of their own alphabet.
function derivedProbes(pattern: string): string[] {
  const prefix = literalPrefix(pattern);
  const fuel = fuelChars(pattern);
  const terminators = ['!', '#', '~', '\n'];
  const probes: string[] = [];
  for (const f of fuel) {
    for (const term of terminators) {
      if (term === f) continue;
      for (const len of [26, 28]) probes.push(prefix + f.repeat(len) + term);
    }
  }
  return probes;
}

// Fixed short probes and per-rule derived probes run FIRST (both cheap on a safe
// rule, budget-blowing on a bad one); the fixed 40KB polynomial tier runs last.
// The ordering matters: a pattern that backtracks catastrophically on a short
// probe takes geological time on a 40KB one, so it must fail on a short probe
// before the polynomial tier is ever reached. `scan()` cannot be interrupted
// mid-exec, so the walk stops at the first over-budget probe.
function probesFor(rule: Rule): string[] {
  const derived = rule.matcher.type === 'regex' ? derivedProbes(rule.matcher.pattern) : [];
  return [...derived, ...EXPONENTIAL_PROBES, ...POLYNOMIAL_PROBES];
}

/** The slowest probe against `rule`, in ms; stops early once one blows the budget. */
export function worstProbeMs(rule: Rule): { ms: number; probe: string } {
  let ms = 0;
  let probe = '';
  for (const text of probesFor(rule)) {
    const start = performance.now();
    scan(text, [rule]);
    const elapsed = performance.now() - start;
    if (elapsed > ms) {
      ms = elapsed;
      probe = text;
    }
    if (ms >= BUDGET_MS) break;
  }
  return { ms, probe };
}

// A same-length ordinary input for `rule` that cannot enter the pattern's
// repeated group, so scan() runs linearly over it. Its cost is this machine's
// baseline for an input of this size — the denominator a catastrophic probe is
// measured against, so the ratio reflects backtracking blowup rather than raw
// machine speed. 'z' matches none of the meta-test patterns' required prefixes
// or character classes, so every probe fails before the group and never
// backtracks. `min` over several samples rejects scheduler noise on a
// sub-millisecond measurement.
export function benignBaselineMs(rule: Rule, length: number): number {
  const text = 'z'.repeat(length);
  scan(text, [rule]);
  let ms = Infinity;
  for (let i = 0; i < 7; i++) {
    const start = performance.now();
    scan(text, [rule]);
    ms = Math.min(ms, performance.now() - start);
  }
  return ms;
}

// A catastrophic probe must cost dramatically more than an ordinary input of the
// same length on the SAME machine. This ratio is scale-free: hardware speed and
// CPU contention slow both measurements together and cancel out, where an
// absolute-millisecond threshold does not.
export const CATASTROPHIC_RATIO = 50;

// Below any genuine scan cost, so it only replaces an unmeasurably fast baseline
// that rounded to zero and never distorts a real measurement.
const MIN_BASELINE_MS = 1e-6;

// The worst probe's slowdown over a same-length benign baseline for `rule`.
export function backtrackRatio(rule: Rule): { ratio: number; ms: number; benignMs: number } {
  const { ms, probe } = worstProbeMs(rule);
  const benignMs = Math.max(benignBaselineMs(rule, probe.length), MIN_BASELINE_MS);
  return { ratio: ms / benignMs, ms, benignMs };
}

// The runtime pre-flight check: is `rule`'s regex matcher safe against this
// same probe battery? `safe: false` means the rule must be excluded from the
// active ruleset entirely — never registered and never silently allowed
// through.
export function checkRuleTiming(rule: Rule): { safe: boolean; worstMs: number; probe: string } {
  const { ms, probe } = worstProbeMs(rule);
  return { safe: ms < BUDGET_MS, worstMs: ms, probe };
}
```

- [ ] **Step 2: Refactor `redos.test.ts` to import from the shared module**

In `packages/detections/test/security/redos.test.ts`, replace lines 1–205 (everything from the top of the file through the `backtrackRatio` function, i.e. everything before the `describe('bundled rules survive adversarial input'` block) with:

```ts
import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/index.ts';
import {
  backtrackRatio,
  BUDGET_MS,
  CATASTROPHIC_RATIO,
  EXPONENTIAL_PROBES,
  POLYNOMIAL_PROBES,
  worstProbeMs,
} from '../../src/security/redos-probe.ts';
import { discoverBundledRuleFiles, loadRule } from '../helpers/rules.ts';

// scan() is synchronous and runs on the hook path. A rule that backtracks
// catastrophically cannot be interrupted — the fail-open catch in the plugin
// runtime only catches throws, and a hook killed at its 10s timeout fails open,
// letting the call through UNSCANNED. So a slow rule is a detection bypass, not
// just a stall.
//
// SCOPE. This gate binds the rules in this repository only, and within them it
// proves "no bundled rule backtracks on the inputs the battery constructs" —
// not "no bundled rule can ReDoS at all". The probe battery
// (packages/detections/src/security/redos-probe.ts) mixes a FIXED
// lowercase-and-digit alphabet with per-rule DERIVED probes built from each
// pattern's own literal prefix and character classes, so a rule gated behind a
// literal like `ghp_(...)+$` is actually exercised past its prefix on its own
// alphabet. Residual gaps, all documented rather than silently covered:
// backtracking that needs a literal (non-class) character the pattern
// repeats; polynomial blowup reachable only on a non-lowercase alphabet (the
// fixed polynomial tier is lowercase-and-digit); and any rule that arrives at
// runtime from a pulled or custom pack, which this suite never sees — that
// path has its own runtime gate, built on this same battery.

const bundled = discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) =>
  loadRule(packDirAbs, ruleFile),
);
```

Leave everything from `describe('bundled rules survive adversarial input'` (the rest of the original file) completely unchanged.

- [ ] **Step 3: Run the refactored test to verify no behavior change**

Run: `pnpm --filter @akasecurity/detections test -- redos.test.ts`
Expected: PASS — same tests, same count, as before the refactor.

- [ ] **Step 4: Write the failing test for `checkRuleTiming`**

Create `packages/detections/test/security/redos-probe.test.ts`:

```ts
import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { BUDGET_MS, checkRuleTiming } from '../../src/security/redos-probe.ts';

function regexRule(pattern: string): Rule {
  return Rule.parse({
    specVersion: 1,
    id: 'test-pack/evil',
    name: 'evil',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
  });
}

describe('checkRuleTiming', () => {
  it('flags a catastrophic pattern as unsafe', () => {
    const result = checkRuleTiming(regexRule('^(a+)+$'));
    expect(result.safe).toBe(false);
    expect(result.worstMs).toBeGreaterThanOrEqual(BUDGET_MS);
  });

  it('passes a benign pattern as safe', () => {
    const result = checkRuleTiming(regexRule('AKIA[A-Z0-9]{16}'));
    expect(result.safe).toBe(true);
    expect(result.worstMs).toBeLessThan(BUDGET_MS);
  });
});
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm --filter @akasecurity/detections test -- redos-probe.test.ts`
Expected: PASS (the implementation already exists from Step 1 — this step proves it).

- [ ] **Step 6: Export `checkRuleTiming` from the package's public surface**

In `packages/detections/src/index.ts`, add one line (anywhere in the export list — alphabetically after the `mask.ts` export and before `posture/config-posture.ts` is fine):

```ts
export { checkRuleTiming } from './security/redos-probe.ts';
```

- [ ] **Step 7: Run the full detections suite**

Run: `pnpm --filter @akasecurity/detections test`
Expected: PASS — all existing suites (including `redos.test.ts`'s 101-bundled-rule gate) plus the two new tests.

- [ ] **Step 8: Commit**

```bash
git add packages/detections/src/security/redos-probe.ts \
        packages/detections/src/index.ts \
        packages/detections/test/security/redos.test.ts \
        packages/detections/test/security/redos-probe.test.ts
git commit -m "refactor(detections): extract ReDoS probe battery into a reusable module

Adds checkRuleTiming, the runtime pre-flight primitive the next tasks
wire into rule registration for pulled/custom pack rules. The CI gate
for bundled rules (redos.test.ts) is unchanged in behavior."
```

---

### Task 3: Persistence — `rule_probe_cache` table and repository

**Files:**
- Modify: `packages/persistence/src/migrations.ts`
- Create: `packages/persistence/src/repositories/rule-probe-cache.ts`
- Modify: `packages/persistence/src/database.ts`
- Modify: `packages/persistence/src/index.ts`
- Test: `packages/persistence/test/repositories/rule-probe-cache.test.ts`

**Interfaces:**
- Consumes: `RuleProbeVerdict` from `@akasecurity/schema` (Task 1).
- Produces: `SqliteRuleProbeCacheRepository` class with `getVerdict(ruleKey: string): RuleProbeCacheEntry | undefined` and `setVerdict(ruleKey: string, verdict: RuleProbeVerdict, worstProbeMs: number): void`; `RuleProbeCacheEntry` interface `{ verdict: RuleProbeVerdict; worstProbeMs: number }`; `LocalDatabase.ruleProbeCache: SqliteRuleProbeCacheRepository`. Both exported from `@akasecurity/persistence`.

- [ ] **Step 1: Write the failing repository test**

Create `packages/persistence/test/repositories/rule-probe-cache.test.ts`:

```ts
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { openLocalDatabase } from '../../src/database.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-rule-probe-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('SqliteRuleProbeCacheRepository (via LocalDatabase.ruleProbeCache)', () => {
  it('returns undefined for an unseen rule key', () => {
    const db = openLocalDatabase(dir);
    expect(db.ruleProbeCache.getVerdict('unseen')).toBeUndefined();
    db.close();
  });

  it('round-trips a safe verdict', () => {
    const db = openLocalDatabase(dir);
    db.ruleProbeCache.setVerdict('rule-a', 'safe', 1.8);
    expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 1.8 });
    db.close();
  });

  it('round-trips a quarantined verdict', () => {
    const db = openLocalDatabase(dir);
    db.ruleProbeCache.setVerdict('rule-b', 'quarantined', 250);
    expect(db.ruleProbeCache.getVerdict('rule-b')).toEqual({
      verdict: 'quarantined',
      worstProbeMs: 250,
    });
    db.close();
  });

  it('upserts on rule_key: a re-check overwrites the verdict', () => {
    const db = openLocalDatabase(dir);
    db.ruleProbeCache.setVerdict('rule-a', 'quarantined', 500);
    db.ruleProbeCache.setVerdict('rule-a', 'safe', 2.1);
    expect(db.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 2.1 });
    db.close();
  });

  it('persists across reopen', () => {
    const db1 = openLocalDatabase(dir);
    db1.ruleProbeCache.setVerdict('rule-a', 'safe', 1.2);
    db1.close();

    const db2 = openLocalDatabase(dir);
    expect(db2.ruleProbeCache.getVerdict('rule-a')).toEqual({ verdict: 'safe', worstProbeMs: 1.2 });
    db2.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @akasecurity/persistence test -- rule-probe-cache.test.ts`
Expected: FAIL — `db.ruleProbeCache` is undefined (no such table/repository/field yet).

- [ ] **Step 3: Create the repository**

Create `packages/persistence/src/repositories/rule-probe-cache.ts`:

```ts
import type { DatabaseSync, StatementSync } from 'node:sqlite';

import type { RuleProbeVerdict } from '@akasecurity/schema';

import { getRow } from '../internal/rows.ts';
import { failOpenTransaction } from '../internal/transactions.ts';

// One rule's cached ReDoS timing verdict.
export interface RuleProbeCacheEntry {
  verdict: RuleProbeVerdict;
  worstProbeMs: number;
}

/**
 * rule_probe_cache reader/writer, bound to one open DB. One row per rule,
 * keyed by a content hash of its pattern+flags, recording the one-time
 * adversarial-probe timing verdict for a regex rule that arrived from a
 * pulled or custom pack — so a rule already measured is never re-measured on
 * a later hook invocation. Bundled rules never reach this cache: they are
 * gated by the CI adversarial battery instead.
 */
export class SqliteRuleProbeCacheRepository {
  private readonly upsertStmt: StatementSync;
  private readonly readStmt: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.upsertStmt = db.prepare(
      `INSERT INTO rule_probe_cache (rule_key, verdict, worst_probe_ms, checked_at)
       VALUES (:ruleKey, :verdict, :worstProbeMs, :checkedAt)
       ON CONFLICT (rule_key) DO UPDATE SET
         verdict = excluded.verdict,
         worst_probe_ms = excluded.worst_probe_ms,
         checked_at = excluded.checked_at`,
    );
    this.readStmt = db.prepare(
      `SELECT verdict, worst_probe_ms AS worstProbeMs FROM rule_probe_cache WHERE rule_key = :ruleKey`,
    );
  }

  getVerdict(ruleKey: string): RuleProbeCacheEntry | undefined {
    return getRow<RuleProbeCacheEntry>(this.readStmt, { ruleKey });
  }

  setVerdict(ruleKey: string, verdict: RuleProbeVerdict, worstProbeMs: number): void {
    // Fail-open: losing this cache entry only costs a re-measurement next
    // time, never a wrong safety decision now (the caller already has the
    // freshly computed verdict in memory for the current invocation).
    failOpenTransaction(this.db, () => {
      this.upsertStmt.run({ ruleKey, verdict, worstProbeMs, checkedAt: Date.now() });
    });
  }
}
```

- [ ] **Step 4: Add the idempotent table creation to migrations**

In `packages/persistence/src/migrations.ts`, add this function after `ensureBlockedDetectionsTable` (after its closing brace, currently the last function in the file):

```ts
// Runtime ReDoS timing cache: one row per rule (by content hash of its
// pattern+flags) recording the one-time adversarial-probe verdict for a
// regex rule sourced from a pulled or custom pack. Plugin-local, so like
// `scan_ledger` it stays out of the canonical schema and is created here,
// idempotently.
function ensureRuleProbeCacheTable(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS rule_probe_cache (
    rule_key TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    worst_probe_ms REAL NOT NULL,
    checked_at INTEGER NOT NULL
  )`);
}
```

Then add a call to it in `applyMigrations`, right after the existing `ensureBlockedDetectionsTable(db);` line:

```ts
  ensureScanLedgerTable(db);
  ensureBlockedDetectionsTable(db);
  ensureRuleProbeCacheTable(db);
```

- [ ] **Step 5: Wire the repository into `LocalDatabase`**

In `packages/persistence/src/database.ts`:

Add the import near the other repository imports (alphabetically, after the `SqliteResolutionsRepository` import and before `SqliteScanLedgerRepository`):

```ts
import { SqliteRuleProbeCacheRepository } from './repositories/rule-probe-cache.ts';
```

Add the field to the `LocalDatabase` interface, after the `resolutions` field (after its closing comment/declaration, before `security`):

```ts
  // Runtime ReDoS timing cache — see SqliteRuleProbeCacheRepository. Read and
  // written by the plugin SDK's rule-registration filter, never by the
  // dashboard.
  readonly ruleProbeCache: SqliteRuleProbeCacheRepository;
```

Instantiate it in `openLocalDatabase`, next to the other repository instantiations (after `const resolutions = new SqliteResolutionsRepository(db);`):

```ts
  const ruleProbeCache = new SqliteRuleProbeCacheRepository(db);
```

Add it to the returned object, next to `resolutions`:

```ts
    resolutions,
    ruleProbeCache,
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pnpm --filter @akasecurity/persistence test -- rule-probe-cache.test.ts`
Expected: PASS

- [ ] **Step 7: Export from the package's public surface**

In `packages/persistence/src/index.ts`, add these two lines, alphabetically between the `SqliteResolutionsRepository` export and the `SqliteScanLedgerRepository` export:

```ts
export type { RuleProbeCacheEntry } from './repositories/rule-probe-cache.ts';
export { SqliteRuleProbeCacheRepository } from './repositories/rule-probe-cache.ts';
```

- [ ] **Step 8: Run the full persistence suite**

Run: `pnpm --filter @akasecurity/persistence test`
Expected: PASS — including `migrations.test.ts` (the new idempotent table creation must not break existing migration-ledger tests).

- [ ] **Step 9: Commit**

```bash
git add packages/persistence/src/migrations.ts \
        packages/persistence/src/repositories/rule-probe-cache.ts \
        packages/persistence/src/database.ts \
        packages/persistence/src/index.ts \
        packages/persistence/test/repositories/rule-probe-cache.test.ts
git commit -m "feat(persistence): add rule_probe_cache table and repository

Stores the one-time ReDoS timing verdict for a regex rule, keyed by a
content hash of its pattern+flags, so the runtime pre-flight check
(next tasks) only ever measures a given rule once."
```

---

### Task 4: plugin-sdk — extend the `DataGateway` port

**Files:**
- Modify: `packages/plugin-sdk/src/data-gateway.ts`
- Modify: `packages/plugin-sdk/src/index.ts`
- Modify: `packages/plugin-sdk/test/runtime.test.ts` (fake gateway must implement the new methods to keep compiling)
- Modify: `packages/plugin-sdk/test/runtime-exceptions.test.ts` (same)

**Interfaces:**
- Consumes: `RuleProbeVerdict` from `@akasecurity/schema` (Task 1).
- Produces: `DataGateway.getRuleProbeVerdict(ruleKey: string): Promise<RuleProbeVerdictEntry | undefined>`, `DataGateway.setRuleProbeVerdict(ruleKey: string, verdict: RuleProbeVerdict, worstProbeMs: number): Promise<void>`, `RuleProbeVerdictEntry` interface `{ verdict: RuleProbeVerdict; worstProbeMs: number }` — exported from `@akasecurity/plugin-sdk`.

This task only changes the *type contract* (no runtime behavior yet — Task 5 implements it for real). It's TDD in the sense that the two test-file updates are what make the interface change compile; there's no separate "write a failing test" step because a TypeScript interface addition fails at typecheck, not at a runtime assertion.

- [ ] **Step 1: Add the port methods and mirrored type**

In `packages/plugin-sdk/src/data-gateway.ts`, add `RuleProbeVerdict` to the existing type-only import from `@akasecurity/schema` (it currently imports `ActionTaken`, `AuditEventInput`, etc. — add `RuleProbeVerdict` alphabetically to that list).

Add this interface near the top, right after the existing `ScanLedgerState` interface (before the `DataGateway` doc comment):

```ts
// One rule's cached ReDoS timing verdict. Structurally identical to
// @akasecurity/persistence's RuleProbeCacheEntry — persistence cannot depend
// on the SDK, so the port shape lives here and structural typing joins them
// in plugin-runtime.
export interface RuleProbeVerdictEntry {
  verdict: RuleProbeVerdict;
  worstProbeMs: number;
}
```

Add these two methods to the `DataGateway` interface, right after `recordScanned(entries: ScanLedgerEntry[]): Promise<void>;`:

```ts
  // The one-time ReDoS timing verdict for a regex rule (keyed by a content
  // hash of its pattern+flags), so a rule already measured safe — or
  // quarantined — is never re-measured on a later hook invocation. Only
  // pulled/custom-pack regex rules are ever looked up here; bundled rules are
  // gated by the CI adversarial battery instead and never reach this cache.
  getRuleProbeVerdict(ruleKey: string): Promise<RuleProbeVerdictEntry | undefined>;
  setRuleProbeVerdict(
    ruleKey: string,
    verdict: RuleProbeVerdict,
    worstProbeMs: number,
  ): Promise<void>;
```

- [ ] **Step 2: Export the new type from the package's public surface**

In `packages/plugin-sdk/src/index.ts`, change:

```ts
export type {
  CaptureRecord,
  DataGateway,
  ScanLedgerEntry,
  ScanLedgerState,
} from './data-gateway.ts';
```

to:

```ts
export type {
  CaptureRecord,
  DataGateway,
  RuleProbeVerdictEntry,
  ScanLedgerEntry,
  ScanLedgerState,
} from './data-gateway.ts';
```

- [ ] **Step 3: Run typecheck to see the two now-broken fake gateways**

Run: `pnpm --filter @akasecurity/plugin-sdk typecheck`
Expected: FAIL — `packages/plugin-sdk/test/runtime.test.ts` and `packages/plugin-sdk/test/runtime-exceptions.test.ts` each construct an object literal typed as `DataGateway` that is now missing `getRuleProbeVerdict`/`setRuleProbeVerdict`.

- [ ] **Step 4: Fix `runtime.test.ts`'s fake gateway**

In `packages/plugin-sdk/test/runtime.test.ts`, inside the `fakeGateway` function's returned object, add these two lines immediately after the existing `scanLedger: () => Promise.resolve(new Map()),` / `recordScanned: () => Promise.resolve(),` lines:

```ts
    getRuleProbeVerdict: () => Promise.resolve(undefined),
    setRuleProbeVerdict: () => Promise.resolve(),
```

- [ ] **Step 5: Fix `runtime-exceptions.test.ts`'s fake gateway**

In `packages/plugin-sdk/test/runtime-exceptions.test.ts`, inside the `fakeGateway` function's returned object, add the same two lines immediately after its `scanLedger: () => Promise.resolve(new Map()),` / `recordScanned: () => Promise.resolve(),` lines:

```ts
    getRuleProbeVerdict: () => Promise.resolve(undefined),
    setRuleProbeVerdict: () => Promise.resolve(),
```

- [ ] **Step 6: Run typecheck and the full plugin-sdk suite**

Run: `pnpm --filter @akasecurity/plugin-sdk typecheck && pnpm --filter @akasecurity/plugin-sdk test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add packages/plugin-sdk/src/data-gateway.ts \
        packages/plugin-sdk/src/index.ts \
        packages/plugin-sdk/test/runtime.test.ts \
        packages/plugin-sdk/test/runtime-exceptions.test.ts
git commit -m "feat(plugin-sdk): add rule-probe-verdict methods to the DataGateway port"
```

---

### Task 5: plugin-runtime — implement the port in `StandaloneDataGateway`

**Files:**
- Modify: `packages/plugin-runtime/src/standalone-gateway.ts`
- Test: `packages/plugin-runtime/test/standalone-gateway.test.ts`

**Interfaces:**
- Consumes: `db.ruleProbeCache` (Task 3), `RuleProbeVerdictEntry`/`RuleProbeVerdict` port types (Task 4).
- Produces: a working `getRuleProbeVerdict`/`setRuleProbeVerdict` implementation on the concrete gateway class used by the real plugin/CLI.

- [ ] **Step 1: Write the failing test**

Add to `packages/plugin-runtime/test/standalone-gateway.test.ts` (follow the file's existing pattern of constructing `new StandaloneDataGateway(dir)` — check the top of the file for its `dir`/`beforeEach`/`afterEach` setup and reuse it; add this as a new `describe` block):

```ts
describe('rule probe verdict', () => {
  it('returns undefined for an unseen rule key', async () => {
    const gw = new StandaloneDataGateway(dir);
    expect(await gw.getRuleProbeVerdict('unseen')).toBeUndefined();
    await gw.close();
  });

  it('round-trips a verdict', async () => {
    const gw = new StandaloneDataGateway(dir);
    await gw.setRuleProbeVerdict('rule-a', 'quarantined', 150);
    expect(await gw.getRuleProbeVerdict('rule-a')).toEqual({
      verdict: 'quarantined',
      worstProbeMs: 150,
    });
    await gw.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @akasecurity/plugin-runtime test -- standalone-gateway.test.ts`
Expected: FAIL — `gw.getRuleProbeVerdict` is not a function (not yet implemented on the class; TypeScript would also already flag `StandaloneDataGateway` as not satisfying `DataGateway` after Task 4).

- [ ] **Step 3: Implement the methods**

In `packages/plugin-runtime/src/standalone-gateway.ts`, add `RuleProbeVerdict` to the existing type-only import from `@akasecurity/schema` (alphabetically into that list).

Add the two methods right after `recordScanned(entries: ScanLedgerEntry[]): Promise<void> { ... }`:

```ts
  getRuleProbeVerdict(
    ruleKey: string,
  ): Promise<{ verdict: RuleProbeVerdict; worstProbeMs: number } | undefined> {
    return Promise.resolve(this.db.ruleProbeCache.getVerdict(ruleKey));
  }

  setRuleProbeVerdict(
    ruleKey: string,
    verdict: RuleProbeVerdict,
    worstProbeMs: number,
  ): Promise<void> {
    this.db.ruleProbeCache.setVerdict(ruleKey, verdict, worstProbeMs);
    return Promise.resolve();
  }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @akasecurity/plugin-runtime test -- standalone-gateway.test.ts`
Expected: PASS

- [ ] **Step 5: Run the full plugin-runtime suite**

Run: `pnpm --filter @akasecurity/plugin-runtime test`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add packages/plugin-runtime/src/standalone-gateway.ts \
        packages/plugin-runtime/test/standalone-gateway.test.ts
git commit -m "feat(plugin-runtime): implement rule-probe-verdict on StandaloneDataGateway"
```

---

### Task 6: plugin-sdk — `filterUnsafeRules`

**Files:**
- Create: `packages/plugin-sdk/src/rule-quarantine.ts`
- Create: `packages/plugin-sdk/test/rule-quarantine.test.ts`
- Modify: `packages/plugin-sdk/src/index.ts`

**Interfaces:**
- Consumes: `checkRuleTiming` from `@akasecurity/detections` (Task 2), `contentHashOf` from `./events.ts` (already exists), `DataGateway`/`RuleProbeVerdictEntry` from `./data-gateway.ts` (Task 4).
- Produces: `filterUnsafeRules(rules: Rule[], gateway: RuleProbeGateway, opts?: { passBudgetMs?: number }): Promise<Rule[]>`, `ruleProbeKey(rule: Rule): string | undefined`, `RuleProbeGateway` type — consumed by Task 7's `runtime.ts` wiring.

- [ ] **Step 1: Write the failing tests**

Create `packages/plugin-sdk/test/rule-quarantine.test.ts`:

```ts
import type { Rule } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import { filterUnsafeRules, ruleProbeKey } from '../src/rule-quarantine.ts';

function regexRule(id: string, pattern: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
  };
}

function keywordRule(id: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'low',
    matcher: { type: 'keyword', keywords: ['x'], caseSensitive: false },
  };
}

function fakeCacheGateway() {
  const store = new Map<string, { verdict: 'safe' | 'quarantined'; worstProbeMs: number }>();
  const getRuleProbeVerdict = vi.fn((key: string) => Promise.resolve(store.get(key)));
  const setRuleProbeVerdict = vi.fn(
    (key: string, verdict: 'safe' | 'quarantined', worstProbeMs: number) => {
      store.set(key, { verdict, worstProbeMs });
      return Promise.resolve();
    },
  );
  return { getRuleProbeVerdict, setRuleProbeVerdict, store };
}

describe('filterUnsafeRules', () => {
  it('passes a benign regex rule through and caches it as safe', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/benign', 'AKIA[A-Z0-9]{16}');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(1);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('safe');
  });

  it('excludes a catastrophic regex rule and caches it as quarantined', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/evil', '^(a+)+$');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict.mock.calls[0]?.[1]).toBe('quarantined');
  });

  it('passes non-regex rules through unchecked', async () => {
    const gateway = fakeCacheGateway();
    const rule = keywordRule('pack/keyword');

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([rule]);
    expect(gateway.getRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('reuses a cached verdict instead of re-measuring', async () => {
    const gateway = fakeCacheGateway();
    const rule = regexRule('pack/evil', '^(a+)+$');
    const key = ruleProbeKey(rule);
    if (key === undefined) throw new Error('expected a rule key for a regex rule');
    gateway.store.set(key, { verdict: 'quarantined', worstProbeMs: 150 });

    const result = await filterUnsafeRules([rule], gateway);

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict).not.toHaveBeenCalled();
  });

  it('quarantines remaining unchecked rules once the pass budget is exhausted', async () => {
    const gateway = fakeCacheGateway();
    const ruleA = regexRule('pack/a', 'AKIA[A-Z0-9]{16}');
    const ruleB = regexRule('pack/b', 'ghp_[A-Za-z0-9]{36}');

    const result = await filterUnsafeRules([ruleA, ruleB], gateway, { passBudgetMs: -1 });

    expect(result).toEqual([]);
    expect(gateway.setRuleProbeVerdict).toHaveBeenCalledTimes(2);
    for (const call of gateway.setRuleProbeVerdict.mock.results) {
      expect(call).toBeDefined();
    }
    for (const call of gateway.setRuleProbeVerdict.mock.calls) {
      expect(call[1]).toBe('quarantined');
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @akasecurity/plugin-sdk test -- rule-quarantine.test.ts`
Expected: FAIL — `../src/rule-quarantine.ts` does not exist yet.

- [ ] **Step 3: Write the implementation**

Create `packages/plugin-sdk/src/rule-quarantine.ts`:

```ts
import { checkRuleTiming } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { DataGateway } from './data-gateway.ts';
import { contentHashOf } from './events.ts';

// Overall wall-clock budget for one filtering pass across all not-yet-cached
// rules. Protects the hook's timeout against a pack containing many
// never-before-seen slow rules at once: once the cap is hit, every remaining
// unchecked rule is quarantined without measurement rather than continuing to
// spend time on it.
const PASS_BUDGET_MS = 2_000;

// The subset of DataGateway this module actually needs — narrower than the
// full port so callers (and tests) don't have to construct a complete fake
// gateway just to exercise the filter.
export type RuleProbeGateway = Pick<DataGateway, 'getRuleProbeVerdict' | 'setRuleProbeVerdict'>;

/**
 * The cache key for a regex rule's timing verdict: a content hash of its
 * pattern+flags only — not the whole rule — so a metadata-only change
 * (severity, category, name) doesn't invalidate a still-valid verdict, and an
 * unrelated rule with an identical pattern reuses the same verdict. Returns
 * undefined for a non-regex rule (keyword/validator rules are never checked).
 */
export function ruleProbeKey(rule: Rule): string | undefined {
  if (rule.matcher.type !== 'regex') return undefined;
  return contentHashOf(`${rule.matcher.pattern} ${rule.matcher.flags}`);
}

function warnQuarantined(rule: Rule, worstMs: number | undefined): void {
  const timing = worstMs === undefined ? 'not verified in time' : `${worstMs.toFixed(1)}ms`;
  process.stderr.write(
    `[aka] quarantined rule "${rule.id}": regex matcher exceeded the ReDoS timing budget ` +
      `(${timing}); excluded from this scan.\n`,
  );
}

/**
 * Filters `rules` down to those whose regex matcher is verified safe against
 * the adversarial probe battery — the runtime gate for rules that arrive from
 * a pulled or custom pack (bundled rules are gated by the CI battery instead
 * and should never be passed here). A regex rule's verdict is measured at
 * most once, ever, and cached via `gateway`; a rule that exceeds the timing
 * budget is excluded from the result and logged to stderr, never silently
 * dropped. Non-regex rules (keyword, validator) pass through unchecked.
 */
export async function filterUnsafeRules(
  rules: Rule[],
  gateway: RuleProbeGateway,
  opts?: { passBudgetMs?: number },
): Promise<Rule[]> {
  const passBudgetMs = opts?.passBudgetMs ?? PASS_BUDGET_MS;
  const passStart = performance.now();
  const safe: Rule[] = [];

  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key === undefined) {
      safe.push(rule);
      continue;
    }

    const cached = await gateway.getRuleProbeVerdict(key);
    if (cached) {
      if (cached.verdict === 'safe') safe.push(rule);
      else warnQuarantined(rule, cached.worstProbeMs);
      continue;
    }

    if (performance.now() - passStart >= passBudgetMs) {
      await gateway.setRuleProbeVerdict(key, 'quarantined', passBudgetMs);
      warnQuarantined(rule, undefined);
      continue;
    }

    const { safe: isSafe, worstMs } = checkRuleTiming(rule);
    await gateway.setRuleProbeVerdict(key, isSafe ? 'safe' : 'quarantined', worstMs);
    if (isSafe) safe.push(rule);
    else warnQuarantined(rule, worstMs);
  }

  return safe;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @akasecurity/plugin-sdk test -- rule-quarantine.test.ts`
Expected: PASS

- [ ] **Step 5: Export from the package's public surface**

In `packages/plugin-sdk/src/index.ts`, add (placed alphabetically, after the `repo.ts` export block and before the `rule-packs.ts` export block):

```ts
export type { RuleProbeGateway } from './rule-quarantine.ts';
export { filterUnsafeRules, ruleProbeKey } from './rule-quarantine.ts';
```

- [ ] **Step 6: Run the full plugin-sdk suite**

Run: `pnpm --filter @akasecurity/plugin-sdk test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add packages/plugin-sdk/src/rule-quarantine.ts \
        packages/plugin-sdk/src/index.ts \
        packages/plugin-sdk/test/rule-quarantine.test.ts
git commit -m "feat(plugin-sdk): add filterUnsafeRules runtime ReDoS quarantine gate"
```

---

### Task 7: plugin-sdk — wire the filter into rule registration

**Files:**
- Modify: `packages/plugin-sdk/src/runtime.ts`
- Modify: `packages/plugin-sdk/test/runtime.test.ts`

**Interfaces:**
- Consumes: `filterUnsafeRules` from `./rule-quarantine.ts` (Task 6).

- [ ] **Step 1: Write the failing test**

In `packages/plugin-sdk/test/runtime.test.ts`, add a new test in the existing `describe('rulesetFingerprint...` block or as its own new `describe` block (place it near the existing `'changes when the pulled bundle adds a rule'` test, since it exercises the same `PULLED_RULE`/bundle-merge path):

```ts
describe('runtime rule quarantine', () => {
  it('excludes a catastrophic pulled-pack regex rule from the active ruleset', async () => {
    const evilRule: Rule = {
      specVersion: 1,
      id: 'pulled/evil-redos',
      name: 'evil redos',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: '^(a+)+$', flags: 'g' },
    };
    const gw = fakeGateway({ ...bundle([evilRule]), rulesComplete: true });
    const rt = createPluginRuntime(gw, settings());

    // The quarantined rule must never fire — processText proves it directly
    // by scanning text an unquarantined copy of this pattern would still
    // (harmlessly, since it requires 'a' repeats) leave alone; the real
    // assertion is that registering it never breaks the runtime and it
    // contributes no findings.
    const decision = await rt.processText('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!');
    expect(decision.findings).toEqual([]);
    await rt.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @akasecurity/plugin-sdk test -- runtime.test.ts`
Expected: This test may actually PASS even before the wiring change, since an unregistered rule simply produces no findings by coincidence — that is not a meaningful signal either way. Run it anyway to confirm the harness executes; the real proof of this task is Step 5's assertion that `ensureInitialized` calls through `filterUnsafeRules` (verified by the unit tests in Task 6, plus the manual verification in Step 6 below). Proceed to Step 3.

- [ ] **Step 3: Wire `filterUnsafeRules` into `ensureInitialized`**

In `packages/plugin-sdk/src/runtime.ts`, add the import at the top, alphabetically with the existing local imports:

```ts
import { filterUnsafeRules } from './rule-quarantine.ts';
```

Replace the existing rule-composition line inside `ensureInitialized`:

```ts
    rules = bundle.rulesComplete
      ? (bundle.rules ?? [])
      : [...getLoadedRules(), ...(bundle.rules ?? [])];
```

with:

```ts
    // Only bundle.rules (the pulled/custom-pack path) passes through the
    // runtime timing gate — the compiled-in bundled packs from
    // getLoadedRules() are already proven safe by the CI adversarial battery
    // on every commit, so re-checking them here would only add steady-state
    // cache-lookup overhead for zero additional safety.
    const safeBundleRules = await filterUnsafeRules(bundle.rules ?? [], gateway);
    rules = bundle.rulesComplete
      ? safeBundleRules
      : [...getLoadedRules(), ...safeBundleRules];
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @akasecurity/plugin-sdk test -- runtime.test.ts`
Expected: PASS

- [ ] **Step 5: Add a stronger regression test proving the quarantine actually excludes the rule from matching**

Replace the Step 1 test with one that proves exclusion using a rule shape that WOULD otherwise match, so a silent no-op wiring bug can't hide behind "it just didn't match anyway": use a keyword-adjacent regex that trivially matches its own probe-safe text, then flip it to a catastrophic pattern and confirm the finding disappears. Update the test in `packages/plugin-sdk/test/runtime.test.ts` to:

```ts
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
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pnpm --filter @akasecurity/plugin-sdk test -- runtime.test.ts`
Expected: PASS. (Sanity-check the negative: temporarily change `'(a+)+$'` to a benign pattern like `'a+$'` and re-run — the test should then FAIL with a non-empty `findings` array, proving the assertion is meaningful. Revert back to `'(a+)+$'` afterward — do not leave the sanity-check change in place.)

- [ ] **Step 7: Run the full plugin-sdk suite**

Run: `pnpm --filter @akasecurity/plugin-sdk test`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add packages/plugin-sdk/src/runtime.ts packages/plugin-sdk/test/runtime.test.ts
git commit -m "feat(plugin-sdk): quarantine unsafe pulled/custom-pack rules at registration

Wires filterUnsafeRules into ensureInitialized so a regex rule from the
local installed-packs snapshot is measured against the adversarial
probe battery once, cached, and excluded from the active ruleset if it
exceeds the timing budget. Bundled rules bypass the check entirely —
they're already gated by the CI battery."
```

---

### Task 8: Documentation

**Files:**
- Modify: `skills/write-detection-rule/SKILL.md`

- [ ] **Step 1: Add the ReDoS protection section**

In `skills/write-detection-rule/SKILL.md`, add this new subsection immediately after the existing paragraph that ends with `"...dropping \`g\` is not a way around it."` (the whole-match-empty-string paragraph, currently lines 38–46) and before the `### Optional gating fields` heading:

```markdown
### ReDoS protection

Two defenses stop a catastrophic regex from hanging a scan:

- **Authoring time.** Every bundled rule is measured against an adversarial
  probe battery in CI (`packages/detections/test/security/redos.test.ts`) — a
  rule that backtracks catastrophically fails the build before it can land in
  `rules/`.
- **Runtime.** A regex rule that arrives from a pulled or custom pack (never
  seen by the CI battery) is measured once against the same probe battery when
  it is first loaded, and the verdict is cached locally. A rule that exceeds
  the timing budget is excluded from the active ruleset and logged to stderr
  (`[aka] quarantined rule ...`) — never silently skipped, and never allowed
  to hang a scan.
```

- [ ] **Step 2: Commit**

```bash
git add skills/write-detection-rule/SKILL.md
git commit -m "docs(write-detection-rule): document the runtime ReDoS quarantine gate"
```

---

### Task 9: Full verification pass

**Files:** none (verification only)

- [ ] **Step 1: Run every touched package's test suite**

```bash
pnpm --filter @akasecurity/schema test
pnpm --filter @akasecurity/detections test
pnpm --filter @akasecurity/persistence test
pnpm --filter @akasecurity/plugin-sdk test
pnpm --filter @akasecurity/plugin-runtime test
```

Expected: PASS for all five.

- [ ] **Step 2: Run typecheck across the touched packages**

```bash
pnpm --filter @akasecurity/schema typecheck 2>/dev/null || true
pnpm --filter @akasecurity/detections typecheck 2>/dev/null || true
pnpm --filter @akasecurity/persistence typecheck 2>/dev/null || true
pnpm --filter @akasecurity/plugin-sdk typecheck
pnpm --filter @akasecurity/plugin-runtime typecheck 2>/dev/null || true
```

(Some packages may not define a `typecheck` script — the `|| true` guards let the loop continue; check whether each command reports "Missing script" versus a real type error, and treat only the latter as a failure.)

Expected: no real type errors. If `pnpm --filter @akasecurity/scanner test` or `pnpm --filter @akasecurity/scanner typecheck` reveals that `packages/scanner/test/scan.test.ts`'s mocked gateway object needs the two new methods (it mocks `resolveDataGateway` rather than constructing a real `DataGateway`-typed literal, so this is unlikely, but confirm), add the same two stub lines used in Task 4 Steps 4–5 to its mock object and re-run.

- [ ] **Step 3: Confirm no regression across the whole workspace**

```bash
pnpm turbo run test
```

Expected: PASS across every package, confirming the 101-bundled-rule ReDoS gate (Issue 1's test, now importing from the extracted module) still passes and nothing downstream of `DataGateway`/`LocalDatabase` broke.

- [ ] **Step 4: Manual sanity check of the quarantine log line**

Run the plugin-sdk test in verbose mode and visually confirm the stderr warning fires with a readable message:

```bash
pnpm --filter @akasecurity/plugin-sdk test -- rule-quarantine.test.ts --reporter=verbose 2>&1 | grep -A1 "quarantined rule"
```

Expected output includes a line like:

```
[aka] quarantined rule "pack/evil": regex matcher exceeded the ReDoS timing budget (100.0ms); excluded from this scan.
```

- [ ] **Step 5: Final commit (if any fixups were needed in this task)**

Only if Step 2's scanner check required a change:

```bash
git add packages/scanner/test/scan.test.ts
git commit -m "test(scanner): satisfy the extended DataGateway mock shape"
```

If no fixups were needed, this task produces no commit — verification only.

---

## Self-Review Notes

- **Spec coverage:** Task 1 → schema shape; Task 2 → shared probe module + `checkRuleTiming` (spec section 1); Task 3 → persistence cache (spec section 2); Tasks 4–5 → `DataGateway` seam (spec section 3); Task 6 → `filterUnsafeRules` + backstop wall-clock cap (spec sections 4–5); Task 7 → wiring point in `ensureInitialized`, scoped to `bundle.rules` only (spec section 4); Task 8 → `SKILL.md` doc (acceptance criteria); Task 9 → the "all 101 bundled rules still pass" and "test asserts the chosen failure mode" acceptance criteria.
- **Type consistency:** `RuleProbeVerdict` (schema, Task 1) flows unchanged through `RuleProbeCacheEntry` (persistence, Task 3), `RuleProbeVerdictEntry` (plugin-sdk port, Task 4 — structurally identical, mirroring the existing `ScanLedgerEntry` dual-definition pattern), and the `checkRuleTiming`/`filterUnsafeRules` boundary (Tasks 2 and 6), which deliberately uses a plain `{ safe: boolean }` in-memory shape rather than the stored enum — `filterUnsafeRules` is the one place that maps `safe → 'safe' | 'quarantined'` when writing to the cache.
- **Layering check:** confirmed against `CLAUDE.md`'s enforced dependency graph before writing this plan — the measurement logic (`checkRuleTiming`) only ever runs inside `plugin-sdk` (Task 6), the one package allowed to depend on both `@akasecurity/detections` and `@akasecurity/persistence`; `persistence` (Task 3) and `plugin-runtime` (Task 5) touch only the cache's stored primitive values, never the detections engine.

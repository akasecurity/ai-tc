import { randomUUID } from 'node:crypto';
import type * as NodeOs from 'node:os';

import {
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  type SqliteResolutionsRepository,
} from '@akasecurity/persistence';
import type { DetectedFindingWithKey, IngestEvent } from '@akasecurity/schema';
import { DISMISS_CONFIRMATION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { dismissRecommendation } from '../../app/(app)/security/actions.ts';
import { expectNoRejection } from '../helpers/no-throw.ts';
import { emptyStore } from '../helpers/store-templates.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// The Recommended Actions card's one mutation, against a real node:sqlite store.
//
// Three properties carry the suite, and they fail differently:
//
//   - The confirmation and the method are re-checked HERE. The dialog gate is a
//     convenience a caller can skip entirely, so every refusal below is asserted
//     together with "and the store is unchanged" — a refusal that still wrote is
//     the failure this action exists to prevent, and it is invisible from the
//     return value alone.
//   - What it writes is the set the CARD COUNTED. A dismissal acting on a wider
//     set closes findings the row never named; on a narrower one, the row comes
//     back after a successful write and the button reads as broken.
//   - It never REJECTS. A Server Action's refusal has to arrive as a value the
//     dialog can render; a thrown one becomes a framework error page and the
//     reader loses the dialog and its guidance. The signature says `unknown` for
//     exactly this reason — the arguments arrive as JSON over a POST and no
//     runtime checked them.
//
// The action resolves the store from `homedir()` (never process.env), so the
// suite redirects it by mocking `node:os`; `next/cache` is stubbed because
// revalidatePath needs a Next render context that does not exist under vitest.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const RULE = 'secrets/aws-access-key';
const OTHER_RULE = 'secrets/github-token';

const newHome = tempHomes('aka-web-rec-');
let home: string;

function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

/**
 * One at-rest finding, which is what this card counts and this action closes.
 *
 * `findingKey` varies per call unless one is named: the key is what a
 * disposition is written against, so a shared constant would make every seeded
 * finding one key and collapse every count assertion below to 1. `contentHash`
 * varies for the same reason one layer up — it feeds the event's
 * content-addressed id, so a shared value lands the second capture as zero rows.
 */
function seed(db: LocalDatabase, opts: { ruleId?: string; findingKey?: string } = {}): string {
  const id = randomUUID();
  const findingKey = opts.findingKey ?? `key-${randomUUID()}`;
  const event: IngestEvent = {
    id,
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: new Date().toISOString(),
    contentHash: id,
    content: 'x',
  };
  const finding: DetectedFindingWithKey = {
    id: randomUUID(),
    eventId: id,
    ruleId: opts.ruleId ?? RULE,
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 1 },
    maskedMatch: 'x',
    actionTaken: 'block',
    confidence: 0.9,
    findingKey,
  };
  db.recordCapture(event, [finding]);
  return findingKey;
}

/** The store the action itself writes through, reopened for assertions. */
function store(): LocalDatabase {
  return openLocalDatabase(dataDir());
}

/** Every rule the card would still list as open. */
async function openRules(db: LocalDatabase): Promise<string[]> {
  return (await db.security.recommendationInputs()).map((r) => r.ruleId).sort();
}

function latest(
  resolutions: SqliteResolutionsRepository,
  key: string,
): ReturnType<SqliteResolutionsRepository['latestByKey']> {
  return resolutions.latestByKey(key);
}

const valid = { ruleId: RULE, method: 'acknowledged', confirmation: DISMISS_CONFIRMATION };

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
  emptyStore.seed(dataDir());
  resetSingleton();
});

afterEach(() => {
  resetSingleton();
});

describe('dismissRecommendation — what it writes', () => {
  it('closes every open finding of the named rule and nothing else', async () => {
    const db = store();
    const mine = [seed(db), seed(db)];
    const theirs = seed(db, { ruleId: OTHER_RULE });
    db.close();
    resetSingleton();

    const res = await expectNoRejection(() => dismissRecommendation(valid));
    expect(res.ok).toBe(true);
    expect(res.dismissed).toBe(2);

    resetSingleton();
    const after = store();
    for (const key of mine) {
      expect(latest(after.resolutions, key)).toMatchObject({
        status: 'dismissed',
        method: 'acknowledged',
      });
    }
    // The control: the other rule's finding was never touched, so what closed is
    // the named set rather than the whole store.
    expect(latest(after.resolutions, theirs)).toBeUndefined();
    expect(await openRules(after)).toEqual([OTHER_RULE]);
    after.close();
  });

  it('records the method the caller chose, not a fixed one', async () => {
    const db = store();
    const key = seed(db);
    db.close();
    resetSingleton();

    await expectNoRejection(() => dismissRecommendation({ ...valid, method: 'false-positive' }));

    resetSingleton();
    const after = store();
    // Asserted as the exact value: a hardcoded 'acknowledged' would satisfy a
    // "some method was written" check while discarding the reader's answer.
    expect(latest(after.resolutions, key)?.method).toBe('false-positive');
    after.close();
  });

  it('succeeds with nothing to close, reporting zero', async () => {
    // A rule whose findings someone else closed between the render and the
    // click. There is nothing to write and nothing has gone wrong, so this is a
    // success reporting 0 rather than a refusal the reader has to interpret.
    const res = await expectNoRejection(() => dismissRecommendation(valid));
    expect(res).toEqual({ ok: true, dismissed: 0 });
  });

  it('reports KEYS closed, not findings — several findings of one value are one key', async () => {
    const db = store();
    seed(db, { findingKey: 'shared' });
    seed(db, { findingKey: 'shared' });
    db.close();
    resetSingleton();

    const res = await expectNoRejection(() => dismissRecommendation(valid));
    // Two findings, one value, one key. The card counted 2; this closes them
    // both with one row, and must not claim to have written two.
    expect(res.dismissed).toBe(1);

    resetSingleton();
    const after = store();
    expect(await openRules(after)).toEqual([]);
    after.close();
  });

  it('is idempotent — a second dismissal of the same rule writes nothing', async () => {
    const db = store();
    seed(db);
    db.close();
    resetSingleton();

    expect((await dismissRecommendation(valid)).dismissed).toBe(1);
    resetSingleton();
    // Already-dismissed keys are outside the open set, so the repeat finds none.
    expect(await expectNoRejection(() => dismissRecommendation(valid))).toEqual({
      ok: true,
      dismissed: 0,
    });
  });
});

describe('dismissRecommendation — the gates, each with the store unchanged', () => {
  /** Assert a refusal wrote nothing: the rule is still open and the key is clean. */
  async function expectRefused(input: unknown, seededKey: string): Promise<string> {
    const res = await expectNoRejection(() => dismissRecommendation(input));
    expect(res.ok).toBe(false);
    expect(res.dismissed).toBeUndefined();
    expect(res.error).toBeDefined();
    expect(res.error).not.toBe('');

    resetSingleton();
    const after = store();
    expect(latest(after.resolutions, seededKey)).toBeUndefined();
    expect(await openRules(after)).toEqual([RULE]);
    after.close();
    resetSingleton();
    return res.error ?? '';
  }

  let key: string;
  beforeEach(() => {
    const db = store();
    key = seed(db);
    db.close();
    resetSingleton();
  });

  it('refuses a wrong confirmation word', async () => {
    const error = await expectRefused({ ...valid, confirmation: 'yes' }, key);
    expect(error).toContain(DISMISS_CONFIRMATION);
  });

  it('refuses a confirmation that differs only in case or padding', async () => {
    // Compared exactly, like `rotate` and `purge` on the sibling surfaces. A
    // forgiving compare here would arm a button the dialog's own gate disables,
    // so the two would disagree about what counts as confirmed.
    await expectRefused({ ...valid, confirmation: 'Dismiss' }, key);
    await expectRefused({ ...valid, confirmation: ` ${DISMISS_CONFIRMATION} ` }, key);
  });

  it('refuses a machine verdict a person has no standing to claim', async () => {
    // Each is a real ResolutionMethod that insertResolution's own re-parse would
    // accept, so nothing below this action would stop them. 'fixed-at-source'
    // asserts a re-scan no longer finds the value — it feeds the caught bucket
    // and the MTTR trend, so accepting it here would report unfixed secrets as
    // remediated.
    for (const method of ['fixed-at-source', 'enforced-in-flight', 'redetected', 'exception']) {
      const error = await expectRefused({ ...valid, method }, key);
      expect(error).toContain('method');
    }
  });

  it('refuses an unknown method outright', async () => {
    await expectRefused({ ...valid, method: 'whatever' }, key);
  });

  it('refuses a blank rule id rather than matching every finding', async () => {
    await expectRefused({ ...valid, ruleId: '   ' }, key);
  });

  it('leaves an unmatched rule id alone', async () => {
    // Not a refusal — a well-formed request naming a rule with nothing open.
    const res = await expectNoRejection(() =>
      dismissRecommendation({ ...valid, ruleId: 'no/such-rule' }),
    );
    expect(res).toEqual({ ok: true, dismissed: 0 });
    resetSingleton();
    const after = store();
    expect(await openRules(after)).toEqual([RULE]);
    after.close();
  });
});

describe('dismissRecommendation — untyped input reaches no field', () => {
  // The signature says `unknown` because that is the truth: these arrive as JSON
  // over a POST. Each value below would throw at a `.trim()`, a template literal
  // or a bind parameter, and a thrown Server Action rejects — the browser gets a
  // framework error page instead of the refusal the dialog can render.
  const hostile: [name: string, input: unknown][] = [
    ['not an object', 'dismiss'],
    ['null', null],
    ['undefined', undefined],
    ['an array', []],
    ['a number for ruleId', { ...valid, ruleId: 42 }],
    ['null for ruleId', { ...valid, ruleId: null }],
    ['an object for ruleId', { ...valid, ruleId: { toString: () => RULE } }],
    ['a number for method', { ...valid, method: 7 }],
    ['a boolean for confirmation', { ...valid, confirmation: true }],
    ['ruleId missing', { method: 'acknowledged', confirmation: DISMISS_CONFIRMATION }],
    ['every field missing', {}],
  ];

  for (const [name, input] of hostile) {
    it(`refuses ${name} without rejecting`, async () => {
      const db = store();
      const key = seed(db);
      db.close();
      resetSingleton();

      const res = await expectNoRejection(() => dismissRecommendation(input));
      expect(res.ok).toBe(false);
      // Naming something specific is what stops the two checks below going
      // vacuous: every `not.toContain` passes on an empty string.
      expect(res.error).toBeDefined();
      expect(res.error).not.toBe('');
      // The refusal names a schema KEY, never the payload.
      expect(res.error).not.toContain('42');
      expect(res.error).not.toContain('[object Object]');

      resetSingleton();
      const after = store();
      expect(latest(after.resolutions, key)).toBeUndefined();
      after.close();
    });
  }

  it('accepts a well-formed payload — the control for every refusal above', async () => {
    const db = store();
    seed(db);
    db.close();
    resetSingleton();

    expect((await dismissRecommendation(valid)).ok).toBe(true);
  });
});

import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isDisableRefused } from '@akasecurity/dashboard-ui';
import {
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  packEnablementRefusal,
  POLICY_CACHE_FILENAME,
  SETTINGS_FILENAME,
  settingsDir,
} from '@akasecurity/persistence';
import type { ActionTaken, InstalledPackInput, Policy, PolicyBundle } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { setDetectionEnabled } from '../../app/(app)/detections/actions.ts';
import { db } from '../../app/lib/db.ts';
import {
  DETECTION_ID_INVALID,
  DETECTION_MISSING,
  DETECTION_STAYS_ON_REFUSAL,
  DETECTION_WRITE_ERROR,
} from '../../app/lib/detection-refusals.ts';
import { ECHO_RUN, expectNoEchoOf } from '../helpers/no-echo.ts';
import { expectNoRejection } from '../helpers/no-throw.ts';

// The Detections page's OTHER write, driven against a real store in a real temp
// `~/.aka` with a real settings.json and a real cached policy bundle.
//
// The defect this suite exists to keep closed: the floor governed which POLICY a
// detection could carry and said nothing about whether it ran at all, so a user
// could switch a governed detection off — and whether that reduced enforcement
// turned on something invisible to them, since the organization's bundle
// re-supplies an ACTION for a rule, never the rule itself. What only this level
// can check is that the store's refusal REACHES the page in words, rather than
// being swallowed into a silent no-op that looks exactly like the bug.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const NAMESPACE = 'aka';
const PACK = 'floor-fixture';
const DETECTION_ID = `${NAMESPACE}/${PACK}`;
const RULE_ID = 'floor-fixture/one';

let home: string;
let base: string;

function seedPack(): void {
  const pack: InstalledPackInput = {
    namespace: NAMESPACE,
    packId: PACK,
    version: '1.0.0',
    name: 'Floor fixture',
    rules: [
      {
        specVersion: 1,
        id: RULE_ID,
        name: 'Fixture rule',
        category: 'secret',
        severity: 'high',
        matcher: { type: 'keyword', keywords: ['fixture'], caseSensitive: false },
      },
    ],
  };
  const db = openLocalDatabase(dataDir(base));
  try {
    db.installedPacks.recordInventory([pack]);
  } finally {
    db.close();
  }
}

/** Both halves of an attachment, since `isAttached` demands both. */
function attach(): void {
  mkdirSync(settingsDir(base), { recursive: true });
  writeFileSync(
    join(settingsDir(base), SETTINGS_FILENAME),
    JSON.stringify({
      specVersion: 1,
      runMode: 'attached',
      controlPlane: {
        endpoint: 'https://cp.example.internal',
        attachedAt: new Date(0).toISOString(),
      },
    }),
  );
}

/** The on-disk shape the sync child publishes: the bundle plus its freshness. */
function governBy(action: ActionTaken, provenance?: Policy['provenance']): void {
  const policy: Policy = {
    // Policy.id is a guid, so a placeholder string fails the parse this fixture
    // exists to get past.
    id: '00000000-0000-4000-8000-000000000001',
    scope: 'global',
    enabled: true,
    target: { ruleId: RULE_ID },
    action,
    ...(provenance === undefined ? {} : { provenance }),
  };
  const bundle: PolicyBundle = {
    version: '1',
    policies: [policy],
    customKeywords: [],
    fetchedAt: new Date(0).toISOString(),
  };
  mkdirSync(dataDir(base), { recursive: true });
  writeFileSync(
    join(dataDir(base), POLICY_CACHE_FILENAME),
    JSON.stringify({ bundle, fetchedAtMs: 0 }),
  );
}

/**
 * Whether the detection is actually running, read on a fresh handle rather than
 * the action's — and through the repository's own read rather than raw SQL, so
 * this asserts what the page would render rather than a column the schema owns.
 */
async function storedEnabled(): Promise<boolean | undefined> {
  const db = openLocalDatabase(dataDir(base));
  try {
    return (await db.detections.getDetectionDetail(DETECTION_ID))?.enabled;
  } finally {
    db.close();
  }
}

function resetSingleton(): void {
  const globals = globalThis as unknown as { __akaDb?: LocalDatabase };
  globals.__akaDb?.close();
  delete globals.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-detection-enabled-'));
  osHome.dir = home;
  base = join(home, '.aka');
  resetSingleton();
});

afterEach(() => {
  vi.restoreAllMocks();
  resetSingleton();
  removeTree(home);
});

describe('setDetectionEnabled on a standalone machine', () => {
  it('switches a detection off and says so', async () => {
    seedPack();
    const result = await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false));
    expect(result).toEqual({ ok: true });
    expect(await storedEnabled()).toBe(false);
  });
});

describe('setDetectionEnabled on a detection the organization governs', () => {
  beforeEach(() => {
    attach();
  });

  it('refuses to switch it off and says whose decision that is', async () => {
    seedPack();
    governBy('block');
    const result = await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false));
    expect(result.ok).toBe(false);
    expect(result.error).toBe(DETECTION_STAYS_ON_REFUSAL);
    // A refusal, not a silent no-op: the detection is still running, and the
    // page is about to render it that way.
    expect(await storedEnabled()).toBe(true);
    // And it must not be reported as breakage — that message sends someone to
    // fix a permission on ~/.aka they do not have, while never telling them
    // their organization asked for this.
    expect(result.error).not.toBe(DETECTION_WRITE_ERROR);
  });

  it('refuses under the WEAKEST floor too, where no assignment is restricted', async () => {
    // The case that separates this constraint from the picker's. A control plane
    // asking only for Monitor forbids no archetype, and still forbids the
    // detection not running: "off" supplies no rules at all, so the floor it set
    // would be unreachable rather than merely lowered.
    seedPack();
    governBy('log');
    const result = await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false));
    expect(result.error).toBe(DETECTION_STAYS_ON_REFUSAL);
    expect(await storedEnabled()).toBe(true);
  });

  it('lets a detection that is already off be turned back on', async () => {
    // The positive control the refusals above need, and a property in its own
    // right: a store can hold a detection switched off from before this refusal
    // existed, and re-enabling moves toward what the organization asked for.
    seedPack();
    expect(await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false))).toEqual({
      ok: true,
    });
    resetSingleton();
    governBy('block', 'authored');
    expect(await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, true))).toEqual({
      ok: true,
    });
    expect(await storedEnabled()).toBe(true);
  });

  it('constrains nothing the organization has not spoken for', async () => {
    // Attached, with a bundle that reaches no rule of this pack. An attachment
    // that constrained by itself would put a decision on screen that nobody made.
    seedPack();
    governBy('block');
    // Same bundle, a rule id it does not name: the floor is null, so the write
    // is the machine's own again.
    const empty: PolicyBundle = {
      version: '1',
      policies: [],
      customKeywords: [],
      fetchedAt: new Date(0).toISOString(),
    };
    writeFileSync(
      join(dataDir(base), POLICY_CACHE_FILENAME),
      JSON.stringify({ bundle: empty, fetchedAtMs: 0 }),
    );
    expect(await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false))).toEqual({
      ok: true,
    });
    expect(await storedEnabled()).toBe(false);
  });

  it('withholds the toggle for EXACTLY the writes the store refuses', async () => {
    // The property the page rests on. The pane decides what to offer from the
    // floor descriptor the Server Component hands down; the store decides what
    // to accept from the same three files. If those two ever differ, the page is
    // back to offering a switch that does not stick — or withholding one that
    // would have worked.
    seedPack();
    governBy('redact');
    const store = openLocalDatabase(dataDir(base));
    const floor = store.installedPacks.policyFloor(NAMESPACE, PACK);
    store.close();
    expect(floor, 'the fixture produced no floor to compare against').not.toBeNull();

    // The two read the same fact from opposite ends — the pane is handed the
    // state the detection is IN, the store the state a write is asking FOR — so
    // the comparison has to flip one of them. Getting that wrong is exactly how
    // the two would come to disagree, which is why the write path is driven
    // underneath as the tiebreaker rather than trusted to the pair above.
    for (const current of [true, false]) {
      const withheld = isDisableRefused(current, floor);
      expect(withheld).toBe(packEnablementRefusal(!current, floor) !== null);
      const result = await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, !current));
      expect(result.ok, `a detection that is on=${String(current)}`).toBe(!withheld);
      resetSingleton();
    }
    // Non-vacuous: the loop has to have exercised both answers, or two matching
    // constants would agree while proving nothing.
    expect(isDisableRefused(true, floor)).toBe(true);
    expect(isDisableRefused(false, floor)).toBe(false);
  });
});

describe('setDetectionEnabled on input it cannot act on', () => {
  it('answers a malformed detection id rather than returning silently', async () => {
    seedPack();
    const posted = 'no-slash-cGFzc3dvcmQ';
    const result = await expectNoRejection(() => setDetectionEnabled(posted, false));
    expect(result).toEqual({ ok: false, error: DETECTION_ID_INVALID });
    // It reaches the page as untrusted input to an HTTP POST, so the message
    // must not echo it — and not a truncated run of it either.
    expectNoEchoOf(result.error, posted);
    // Positive control on the same bytes: the run IS findable in a string that
    // carries it, so the absence above is a property of the message.
    expect(`${DETECTION_ID_INVALID} ${posted}`).toContain(posted.slice(0, ECHO_RUN));
    // Nothing was written: the detection is still running.
    expect(await storedEnabled()).toBe(true);
  });

  it('says so when the detection is not installed here', async () => {
    // No pack seeded at all: the write changes no row.
    const result = await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false));
    expect(result).toEqual({ ok: false, error: DETECTION_MISSING });
  });
});

/**
 * A SECOND copy of the store's error class: same name, unrelated prototype —
 * what the page sees once a bundler has handed it and the store their own
 * copies of the module. The real store cannot be made to throw one, so it is
 * thrown from the real store's own write method here; everything downstream of
 * the throw is the production path.
 */
class ForeignPolicyFloorError extends Error {
  readonly refusal = 'disable';

  constructor() {
    super('refusing to disable');
    this.name = 'PolicyFloorError';
  }
}

describe('setDetectionEnabled when the refusal arrives from another copy of the class', () => {
  it("still reports it as the organization's decision, not a broken store", async () => {
    // An identity check would fail here and answer DETECTION_WRITE_ERROR, which
    // tells the user to retry and to check that ~/.aka is writable — a problem
    // they do not have, while never learning that their organization asked for
    // this detection to keep running.
    seedPack();
    vi.spyOn(db().installedPacks, 'setEnabled').mockImplementation(() => {
      throw new ForeignPolicyFloorError();
    });
    const result = await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false));
    expect(result).toEqual({ ok: false, error: DETECTION_STAYS_ON_REFUSAL });
  });

  it('still reports a genuine store fault as one', async () => {
    // The other half of the same read: strictness. A write that failed for a
    // real reason must keep the message that tells the user to retry, or the
    // structural check would have turned every fault into somebody else's
    // decision.
    seedPack();
    vi.spyOn(db().installedPacks, 'setEnabled').mockImplementation(() => {
      throw new Error('SQLITE_BUSY: database is locked');
    });
    const result = await expectNoRejection(() => setDetectionEnabled(DETECTION_ID, false));
    expect(result).toEqual({ ok: false, error: DETECTION_WRITE_ERROR });
  });
});

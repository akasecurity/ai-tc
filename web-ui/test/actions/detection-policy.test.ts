import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { unavailableUnderFloor } from '@akasecurity/dashboard-ui';
import {
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  POLICY_CACHE_FILENAME,
  SETTINGS_FILENAME,
  settingsDir,
} from '@akasecurity/persistence';
import type { InstalledPackInput, Policy, PolicyBundle, Rule } from '@akasecurity/schema';
import { KNOWN_BUILTIN_IDS } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { setDetectionPolicy } from '../../app/(app)/detections/actions.ts';
import { db } from '../../app/lib/db.ts';
import {
  DETECTION_POLICY_INVALID,
  DETECTION_POLICY_MISSING,
  DETECTION_POLICY_WRITE_ERROR,
  policyFloorRefusal,
} from '../../app/lib/detection-refusals.ts';
import { ECHO_RUN, expectNoEchoOf } from '../helpers/no-echo.ts';
import { expectNoRejection } from '../helpers/no-throw.ts';

// The Detections page's one write, driven against a real store in a real temp
// `~/.aka` with a real settings.json and a real cached policy bundle — the three
// files that decide whether this machine is its own authority.
//
// The defect this suite exists to keep closed: a user could pick Monitor for a
// detection whose organization requires Warn, the picker showed Monitor, and
// enforcement quietly applied Warn. The store refuses that write now; what only
// this level can check is that the refusal REACHES the page, in words, rather
// than being swallowed into a silent no-op that looks identical to the bug.
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

function rule(category: Rule['category']): Rule {
  return {
    specVersion: 1,
    id: RULE_ID,
    name: 'Fixture rule',
    category,
    severity: 'high',
    matcher: { type: 'keyword', keywords: ['fixture'], caseSensitive: false },
  };
}

function seedPack(category: Rule['category'] = 'secret'): void {
  const pack: InstalledPackInput = {
    namespace: NAMESPACE,
    packId: PACK,
    version: '1.0.0',
    name: 'Floor fixture',
    rules: [rule(category)],
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

// Distinct guids per policy: Policy.id is a guid, so a placeholder string fails
// the parse this fixture exists to get past.
let policySeq = 0;
function policy(partial: Omit<Policy, 'id' | 'scope' | 'enabled'> & Partial<Policy>): Policy {
  policySeq += 1;
  return {
    id: `00000000-0000-4000-8000-${String(policySeq).padStart(12, '0')}`,
    scope: 'global',
    enabled: true,
    ...partial,
  };
}

/** The on-disk shape the sync child publishes: the bundle plus its freshness. */
function cacheBundle(policies: Policy[]): void {
  const bundle: PolicyBundle = {
    version: '1',
    policies,
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
 * The policy actually stored, read on a fresh handle rather than the action's —
 * and through the repository's own read rather than raw SQL, so this asserts
 * what the page would render rather than a column list the schema owns.
 * Undefined for a detection that is not installed at all.
 */
async function storedPolicy(): Promise<string | undefined> {
  const db = openLocalDatabase(dataDir(base));
  try {
    return (await db.detections.getDetectionDetail(DETECTION_ID))?.policyId;
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
  home = mkdtempSync(join(tmpdir(), 'aka-detection-policy-'));
  osHome.dir = home;
  base = join(home, '.aka');
  resetSingleton();
});

afterEach(() => {
  vi.restoreAllMocks();
  resetSingleton();
  removeTree(home);
});

describe('setDetectionPolicy on a standalone machine', () => {
  it('assigns whatever the user picks and says so', async () => {
    seedPack();
    const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, 'monitor'));
    expect(result).toEqual({ ok: true });
    expect(await storedPolicy()).toBe('monitor');
  });
});

describe('setDetectionPolicy under a control-plane floor', () => {
  beforeEach(() => {
    attach();
  });

  it('refuses a choice below the floor and says whose decision it is', async () => {
    seedPack();
    cacheBundle([policy({ target: { ruleId: RULE_ID }, action: 'block' })]);
    // The positive control comes first: the same store, the same attachment, a
    // choice that satisfies the floor. Without it the refusal below could be a
    // store that refuses everything.
    expect(await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, 'block'))).toEqual({
      ok: true,
    });
    expect(await storedPolicy()).toBe('block');
    resetSingleton();

    const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, 'monitor'));
    expect(result.ok).toBe(false);
    expect(result.error).toBe(policyFloorRefusal({ floor: 'block', refusal: 'floor' }));
    // A refusal, not a substitution: the value that was already there stands.
    expect(await storedPolicy()).toBe('block');
  });

  it('refuses every re-assignment for a detection the organization has authored', async () => {
    seedPack();
    cacheBundle([policy({ target: { ruleId: RULE_ID }, action: 'warn', kind: 'custom' })]);
    for (const id of KNOWN_BUILTIN_IDS) {
      const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, id));
      expect(result.ok, `expected '${id}' to be refused on a locked detection`).toBe(false);
      expect(result.error).toBe(policyFloorRefusal({ floor: 'warn', refusal: 'lock' }));
      resetSingleton();
    }
  });

  it('constrains nothing when the organization asks for no more than the default', async () => {
    // An observe-only category with an empty bundle: attached, and still the
    // machine's own choice. An attachment that restricted by itself would put a
    // constraint on screen that nobody imposed.
    seedPack('config');
    cacheBundle([]);
    expect(await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, 'monitor'))).toEqual({
      ok: true,
    });
    expect(await storedPolicy()).toBe('monitor');
  });

  it('greys out EXACTLY what the store refuses', async () => {
    // The property the whole page rests on. The picker decides what to offer
    // from the floor descriptor; the store decides what to accept from the same
    // three files. If those two sets ever differ, the page is back to offering a
    // choice that does not stick — in one direction — or hiding one that would
    // have worked, in the other.
    seedPack();
    cacheBundle([policy({ target: { ruleId: RULE_ID }, action: 'redact' })]);
    const db = openLocalDatabase(dataDir(base));
    const floor = db.installedPacks.policyFloor(NAMESPACE, PACK);
    db.close();
    expect(floor, 'the fixture produced no floor to compare against').not.toBeNull();

    const greyed = new Set(Object.keys(unavailableUnderFloor(floor) ?? {}));
    const refused = new Set<string>();
    for (const id of KNOWN_BUILTIN_IDS) {
      const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, id));
      if (!result.ok) refused.add(id);
      resetSingleton();
    }
    expect([...greyed].sort()).toEqual([...refused].sort());
    // Non-vacuous: both sets have to actually hold something, or two empty sets
    // would agree while proving nothing.
    expect(greyed.size).toBeGreaterThan(0);
    expect(greyed.size).toBeLessThan(KNOWN_BUILTIN_IDS.length);
  });
});

describe('setDetectionPolicy on input it cannot act on', () => {
  it('answers a malformed detection id rather than returning silently', async () => {
    seedPack();
    // Assigned first, so "nothing was written" is distinguishable from "nothing
    // was ever there" — the latter would pass whatever the action did.
    await setDetectionPolicy(DETECTION_ID, 'warn');
    resetSingleton();
    const result = await expectNoRejection(() => setDetectionPolicy('no-slash', 'block'));
    expect(result).toEqual({ ok: false, error: DETECTION_POLICY_INVALID });
    expect(await storedPolicy()).toBe('warn');
  });

  it('answers a policy id no archetype claims, without quoting it back', async () => {
    seedPack();
    await setDetectionPolicy(DETECTION_ID, 'warn');
    resetSingleton();
    // A value a stale or hand-made client can post; it reaches the page as
    // untrusted input, so the message must not echo it.
    const posted = 'not-a-policy-cGFzc3dvcmQ';
    const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, posted));
    expect(result).toEqual({ ok: false, error: DETECTION_POLICY_INVALID });
    // Not a whole-value check: a message that quoted a TRUNCATED run of what
    // was posted would pass one, and "help the user spot their typo" is exactly
    // the well-meaning change that would write it.
    expectNoEchoOf(result.error, posted);
    // Positive control on the same bytes: the run IS findable in a string that
    // carries it, so the absence above is a property of the message rather than
    // of the window.
    expect(`${DETECTION_POLICY_INVALID} ${posted}`).toContain(posted.slice(0, ECHO_RUN));
    expect(await storedPolicy()).toBe('warn');
  });

  it('says so when the detection is not installed here', async () => {
    // No pack seeded at all: the write changes no row.
    const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, 'block'));
    expect(result).toEqual({ ok: false, error: DETECTION_POLICY_MISSING });
  });
});

/**
 * A SECOND copy of the store's error class: same name, same fields, unrelated
 * prototype — what the page sees once a bundler has handed it and the store
 * their own copies of the module. The real store cannot be made to throw one,
 * so it is thrown from the real store's own write method here; everything
 * downstream of the throw is the production path.
 */
class ForeignPolicyFloorError extends Error {
  readonly floor: string;
  readonly refusal: string;

  constructor(floor: string, refusal: string) {
    super('refusing to re-assign');
    this.name = 'PolicyFloorError';
    this.floor = floor;
    this.refusal = refusal;
  }
}

describe('setDetectionPolicy when the refusal arrives from another copy of the class', () => {
  it("still reports it as the organization's decision, not a broken store", async () => {
    // An identity check would fail here and answer DETECTION_POLICY_WRITE_ERROR,
    // which tells the user to retry and to check that ~/.aka is writable — a
    // permission problem they do not have, while never learning that their
    // organization set the policy. The refusal is therefore read by its fields.
    seedPack();
    vi.spyOn(db().installedPacks, 'setPolicy').mockImplementation(() => {
      throw new ForeignPolicyFloorError('block', 'floor');
    });
    const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, 'monitor'));
    expect(result.error).toBe(policyFloorRefusal({ floor: 'block', refusal: 'floor' }));
    expect(result.error).not.toBe(DETECTION_POLICY_WRITE_ERROR);
    expect(result.ok).toBe(false);
  });

  it('still reports a genuine store fault as one', async () => {
    // The other half of the same read: strictness. A write that failed for a
    // real reason must keep the message that tells the user to retry, or the
    // structural check would have turned every fault into somebody else's
    // decision.
    seedPack();
    vi.spyOn(db().installedPacks, 'setPolicy').mockImplementation(() => {
      throw new Error('SQLITE_BUSY: database is locked');
    });
    const result = await expectNoRejection(() => setDetectionPolicy(DETECTION_ID, 'monitor'));
    expect(result).toEqual({ ok: false, error: DETECTION_POLICY_WRITE_ERROR });
  });
});

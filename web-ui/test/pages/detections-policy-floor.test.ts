import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  dataDir,
  openLocalDatabase,
  POLICY_CACHE_FILENAME,
  SETTINGS_FILENAME,
  settingsDir,
} from '@akasecurity/persistence';
import type { InstalledPackInput, Policy, PolicyBundle } from '@akasecurity/schema';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import DetectionsPage from '../../app/(app)/detections/page.tsx';

// The Server Component's half of the fix: the floor is computed where the local
// store is (the browser has no access to it) and travels down as plain data,
// because a function cannot cross that boundary.
//
// What only this level can see is the WIRING — that the record reaches the
// client shell at all, that it is keyed by the same detection id the list rows
// carry, and that a machine nothing manages sends an empty one. The decisions
// taken from the record are covered in @akasecurity/dashboard-ui; the refusal it
// pre-empts is covered against a real store in test/actions.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const DETECTION_ID = 'aka/floor-fixture';
const RULE_ID = 'floor-fixture/one';

let home: string;
let base: string;

function seedPack(): void {
  const pack: InstalledPackInput = {
    namespace: 'aka',
    packId: 'floor-fixture',
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

function policy(partial: Omit<Policy, 'id' | 'scope' | 'enabled'> & Partial<Policy>): Policy {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    scope: 'global',
    enabled: true,
    ...partial,
  };
}

function resetSingleton(): void {
  const globals = globalThis as { __akaDb?: { close: () => void } };
  globals.__akaDb?.close();
  delete globals.__akaDb;
}

/** The `floors` prop the page hands the client shell. */
async function renderedFloors(): Promise<Record<string, { floor: string; locked: boolean }>> {
  const element = (await DetectionsPage({ searchParams: Promise.resolve({}) })) as ReactElement;
  const found = JSON.parse(JSON.stringify(element)) as unknown;
  // Walk for the prop rather than indexing a path through the element tree: the
  // page's layout is free to change, and a hard-coded path would fail as a
  // missing floor rather than as the reshuffle it is.
  const stack: unknown[] = [found];
  while (stack.length > 0) {
    const node = stack.pop();
    if (typeof node !== 'object' || node === null) continue;
    const record = node as Record<string, unknown>;
    if ('floors' in record) {
      return record.floors as Record<string, { floor: string; locked: boolean }>;
    }
    stack.push(...Object.values(record));
  }
  throw new Error('the page rendered no `floors` prop at all');
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-floor-page-'));
  osHome.dir = home;
  base = join(home, '.aka');
  resetSingleton();
});

afterEach(() => {
  resetSingleton();
  removeTree(home);
});

describe('the Detections page floor record', () => {
  it('is empty on a machine nothing manages', async () => {
    // Every install that has not attached. The page must hand down nothing, so
    // every surface below renders as it did before any of this existed.
    seedPack();
    expect(await renderedFloors()).toEqual({});
  });

  it('carries what the organization requires, keyed by detection id', async () => {
    seedPack();
    attach();
    cacheBundle([policy({ target: { ruleId: RULE_ID }, action: 'block' })]);
    expect(await renderedFloors()).toEqual({ [DETECTION_ID]: { floor: 'block', locked: false } });
  });

  it('marks a detection the organization has authored a policy for as locked', async () => {
    seedPack();
    attach();
    cacheBundle([policy({ target: { ruleId: RULE_ID }, action: 'warn', kind: 'custom' })]);
    expect(await renderedFloors()).toEqual({ [DETECTION_ID]: { floor: 'warn', locked: true } });
  });

  it('renders the page without constraints when the settings cannot be read', async () => {
    // Fail-open like every other read here: a machine whose settings file is
    // garbage must lose the constraint, never the page. The write path still
    // refuses, so the cost is a refusal the user reads rather than an
    // assignment that silently sticks.
    seedPack();
    mkdirSync(settingsDir(base), { recursive: true });
    writeFileSync(join(settingsDir(base), SETTINGS_FILENAME), 'not json at all');
    expect(await renderedFloors()).toEqual({});
  });
});

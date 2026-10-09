import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import { dataDir, openLocalDatabase } from '@akasecurity/persistence';
import type { InstalledPackInput } from '@akasecurity/schema';
import { createElement, type ReactElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { tempHomes } from '../helpers/temp-home.ts';

// The Policies page's copy against what the local store actually counts.
//
// dashboard-ui pins the wording for whatever counts it is handed, and the
// persistence suite pins the counts. Neither can see whether the two agree. The
// local store counts a pack with no policy of its own under Monitor (the policy
// it runs under), so on this host the Monitor row and detail include packs
// nobody assigned anything. Copy that calls those counts "assigned" is wrong
// here, and only a render over a real store shows it.
//
// The fixture straddles the two meanings: one pack assigned Block, one left
// unassigned. Copy aimed at a store of assigned packs alone would pass every
// wording check below, so the unassigned pack's presence under Monitor is
// pinned first. The pack names avoid the word "assigned", so the page can be
// searched for it.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

// PoliciesClient reaches the router through the shared navigation hook. The
// render is static and runs no effects, so a no-op router is enough.
vi.mock('next/navigation', () => ({
  usePathname: () => '/policies',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}));

const { default: PoliciesPage } = await import('../../app/(app)/policies/page.tsx');
const { NavigationTransitionProvider } =
  await import('../../app/components/NavigationTransition.tsx');

const newHome = tempHomes('aka-policies-page-');

let base: string;

function resetSingleton(): void {
  const globals = globalThis as { __akaDb?: { close: () => void } };
  globals.__akaDb?.close();
  delete globals.__akaDb;
}

function pack(packId: string, name: string): InstalledPackInput {
  return {
    namespace: 'aka',
    packId,
    version: '1.0.0',
    name,
    rules: [
      {
        specVersion: 1,
        id: `${packId}/one`,
        name: 'Fixture rule',
        category: 'secret',
        severity: 'high',
        matcher: { type: 'keyword', keywords: ['fixture'], caseSensitive: false },
      },
    ],
  };
}

function seed(): void {
  const db = openLocalDatabase(dataDir(base));
  try {
    db.installedPacks.recordInventory([
      pack('chosen', 'Chosen fixture'),
      pack('defaulted', 'Defaulted fixture'),
    ]);
    db.installedPacks.setPolicy('aka', 'chosen', 'block');
  } finally {
    db.close();
  }
}

async function renderPage(id?: string): Promise<string> {
  const element = (await PoliciesPage({
    searchParams: Promise.resolve(id === undefined ? {} : { id }),
  })) as ReactElement;
  return renderToStaticMarkup(createElement(NavigationTransitionProvider, null, element));
}

/** The row button for one policy, by its name. */
function row(html: string, name: string): string {
  const at = html.indexOf(`title="${name}"`);
  expect(at).toBeGreaterThan(-1);
  const open = html.lastIndexOf('<button', at);
  return html.slice(open, html.indexOf('</button>', at));
}

beforeEach(() => {
  osHome.dir = newHome();
  base = join(osHome.dir, '.aka');
  resetSingleton();
  seed();
});

afterEach(() => {
  resetSingleton();
});

describe('the Policies page over the local store', () => {
  it('lists the unassigned pack under Monitor, the policy it runs under', async () => {
    // The page opens on Monitor, the first built-in.
    const html = await renderPage();

    expect(html).toContain('>Defaulted fixture<');
    expect(html).not.toContain('>Chosen fixture<');
    expect(row(html, 'Monitor')).toContain('>1 detection<');
  });

  it('does not call the counts "assigned"', async () => {
    const monitor = await renderPage();
    const block = await renderPage('block');

    // Block's count is of a pack that IS assigned it, and reads the same way.
    expect(row(block, 'Block')).toContain('>1 detection<');
    expect(block).toContain('>Chosen fixture<');

    for (const html of [monitor, block]) {
      expect(html).toContain('>Detections governed<');
      expect(html).toContain('>Applied by<');
      expect(html).not.toMatch(/assigned/i);
    }
  });

  it('says no detection uses a policy nothing runs under', async () => {
    const html = await renderPage('warn');

    expect(row(html, 'Warn')).toContain('>0 detections<');
    expect(html).toContain('>No detections use this policy yet.<');
  });
});

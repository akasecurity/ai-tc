// @vitest-environment jsdom
//
// The vault lists' page selector, driven through the real client with the Server
// Actions stubbed. Each list keeps its own run of fetched pages, and the
// assertions are about what each move asks the store for.
import type {
  ListVaultDerefsResponse,
  ListVaultInventoryResponse,
  ListVaultReuseResponse,
  VaultDeref,
  VaultInventoryEntry,
} from '@akasecurity/schema';
import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const loadMoreVaultInventory = vi.fn<(q: unknown) => Promise<ListVaultInventoryResponse>>();
const loadMoreVaultReuse = vi.fn<(q: unknown) => Promise<ListVaultReuseResponse>>();
const revokeRevealGrant = vi.fn<(q: unknown) => Promise<{ ok: boolean }>>();
const loadVaultDerefs = vi.fn<(q: unknown) => Promise<ListVaultDerefsResponse>>();

vi.mock('../../app/(app)/vault/actions', () => ({
  loadMoreVaultInventory: (q: unknown) => loadMoreVaultInventory(q),
  loadMoreVaultReuse: (q: unknown) => loadMoreVaultReuse(q),
  loadVaultDerefs: (q: unknown) => loadVaultDerefs(q),
  purgeVault: vi.fn(),
  revealEntry: vi.fn(),
  revokeRevealGrant: (q: unknown) => revokeRevealGrant(q),
  rotateVaultKey: vi.fn(),
}));

const { VaultDashboardClient } = await import('../../app/(app)/vault/VaultDashboardClient.tsx');

const AT = '2026-01-01T00:00:00.000Z';

function entry(pointerId: string, revealGrantId: string | null = null): VaultInventoryEntry {
  return {
    pointerId,
    category: 'secret',
    ruleId: 'rule',
    maskedMatch: `MASK-${pointerId}`,
    occurrences: 2,
    firstSeen: AT,
    lastSeen: AT,
    sightings: [],
    revealGrantId,
  } as unknown as VaultInventoryEntry;
}

function deref(id: string): VaultDeref {
  return {
    id,
    pointerId: 'p',
    at: AT,
    target: 'human',
    reason: 'explicit-reveal',
    outcome: 'revealed',
    pointerCount: 1,
  };
}

const inventoryPage = (
  ids: string[],
  nextCursor: string | null,
  values = 500,
): ListVaultInventoryResponse => ({
  totals: { values },
  items: ids.map((id) => entry(id)),
  nextCursor,
});

const derefPage = (
  ids: string[],
  nextCursor: string | null,
  derefs = 500,
): ListVaultDerefsResponse => ({
  totals: { derefs },
  items: ids.map(deref),
  nextCursor,
  hiddenBatched: 0,
});

let container: HTMLElement;
let root: Root;

beforeEach(() => {
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  loadMoreVaultInventory.mockReset();
  loadMoreVaultReuse.mockReset();
  loadVaultDerefs.mockReset();
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
  act(() => {
    root.render(
      createElement(VaultDashboardClient, {
        inventory: inventoryPage(['v1'], 'inv-1'),
        reuse: { totals: { reused: 500 }, items: [entry('r1')], nextCursor: 'reuse-1' },
        derefs: derefPage(['d1'], 'deref-1'),
        renderedAt: Date.parse(AT),
        locale: 'en-US',
      }),
    );
  });
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
});

const field = (): HTMLInputElement => {
  const el = container.querySelector(
    '[role="tabpanel"]:not([hidden]) input[aria-label="Go to page"]',
  );
  if (!(el instanceof HTMLInputElement)) throw new Error('no page field');
  return el;
};

const status = (): string =>
  container.querySelector('[role="tabpanel"]:not([hidden]) [data-slot="pagination-status"]')
    ?.textContent ?? '';

async function jumpTo(page: number): Promise<void> {
  const input = field();
  await act(async () => {
    // A property descriptor's `set`, applied with an explicit receiver below.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    if (setter === undefined) throw new Error('no value setter');
    Reflect.apply(setter, input, [String(page)]);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    await Promise.resolve();
  });
  await act(async () => {
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await Promise.resolve();
  });
}

async function clickSlot(slot: string): Promise<void> {
  const button = container.querySelector(`[role="tabpanel"]:not([hidden]) [data-slot="${slot}"]`);
  if (button === null) throw new Error(`no ${slot}`);
  await act(async () => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await Promise.resolve();
  });
}

function openTab(name: RegExp): void {
  const tab = [...container.querySelectorAll('[role="tab"]')].find((t) => name.test(t.textContent));
  if (tab === undefined) throw new Error(`no ${String(name)} tab`);
  act(() => {
    tab.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }));
  });
}

const lastQuery = (fn: { mock: { calls: unknown[][] } }): Record<string, unknown> =>
  fn.mock.calls.at(-1)?.[0] as Record<string, unknown>;

describe('the inventory list', () => {
  it('reads a jumped-to page from its row position', async () => {
    loadMoreVaultInventory.mockResolvedValue(inventoryPage(['v7'], 'inv-7'));
    await jumpTo(7);

    expect(lastQuery(loadMoreVaultInventory)).toEqual({ offset: 300 });
    expect(field().value).toBe('7');
    expect(status()).toBe('301–301 of 500 values');
  });

  it('carries on by cursor, and reads the page before the run by position', async () => {
    loadMoreVaultInventory.mockResolvedValueOnce(inventoryPage(['v7'], 'inv-7'));
    await jumpTo(7);

    loadMoreVaultInventory.mockResolvedValueOnce(inventoryPage(['v8'], 'inv-8'));
    await clickSlot('pagination-next');
    expect(lastQuery(loadMoreVaultInventory)).toEqual({ cursor: 'inv-7' });
    expect(field().value).toBe('8');

    await clickSlot('pagination-previous');
    expect(field().value).toBe('7');
    expect(loadMoreVaultInventory).toHaveBeenCalledTimes(2);

    loadMoreVaultInventory.mockResolvedValueOnce(inventoryPage(['v6'], 'inv-6'));
    await clickSlot('pagination-previous');
    expect(lastQuery(loadMoreVaultInventory)).toEqual({ offset: 250 });
    expect(field().value).toBe('6');
  });

  it('reads page 1 again rather than replaying it, so a rewritten row stays rewritten', async () => {
    loadMoreVaultInventory.mockResolvedValueOnce(inventoryPage(['v7'], 'inv-7'));
    await jumpTo(7);
    loadMoreVaultInventory.mockResolvedValueOnce(inventoryPage(['v1'], 'inv-1'));
    await jumpTo(1);

    expect(lastQuery(loadMoreVaultInventory)).toEqual({ offset: 0 });
    expect(field().value).toBe('1');
  });

  it('clears a revoked grant from the row on screen', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    revokeRevealGrant.mockResolvedValue({ ok: true });
    loadMoreVaultInventory.mockResolvedValue({
      ...inventoryPage([], null),
      items: [entry('v2', 'grant-2')],
    });
    await clickSlot('pagination-next');
    const revoke = () =>
      [...container.querySelectorAll('button')].find((b) => b.textContent.includes('Revoke'));
    expect(revoke(), 'the row offered no revoke').toBeTruthy();

    await act(async () => {
      revoke()?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });

    expect(revokeRevealGrant).toHaveBeenCalledWith({ grantId: 'grant-2' });
    expect(revoke()).toBeUndefined();
  });

  it('keeps the forward pages when stepping back from a jump', async () => {
    loadMoreVaultInventory.mockResolvedValueOnce(inventoryPage(['v7'], 'inv-7'));
    await jumpTo(7);
    loadMoreVaultInventory.mockResolvedValueOnce(inventoryPage(['v6'], 'inv-6'));
    await clickSlot('pagination-previous');
    expect(field().value).toBe('6');

    await clickSlot('pagination-next');
    expect(field().value).toBe('7');
    expect(loadMoreVaultInventory).toHaveBeenCalledTimes(2);
  });

  it('follows the total of the latest read, and never counts below the page', async () => {
    loadMoreVaultInventory.mockResolvedValue(inventoryPage(['v2'], 'inv-2', 40));
    await clickSlot('pagination-next');

    expect(status()).toBe('51–51 of 40 values');
    expect(field().value).toBe('2');
    expect(container.querySelector('[data-slot="pagination"]')?.textContent).toContain('of 2');
  });

  it('takes the total of an empty next page while staying put', async () => {
    loadMoreVaultInventory.mockResolvedValue(inventoryPage([], null, 1));
    await clickSlot('pagination-next');

    expect(field().value).toBe('1');
    expect(status()).toBe('1–1 of 1 values');
  });

  it('says so and stays put when the list has shrunk past the page', async () => {
    loadMoreVaultInventory.mockResolvedValue(inventoryPage([], null));
    await jumpTo(7);

    expect(field().value).toBe('1');
    expect(container.textContent).toContain('That page of vaulted values is no longer there.');
  });

  it('says so and stays put when the read fails', async () => {
    loadMoreVaultInventory.mockRejectedValue(new Error('locked'));
    await jumpTo(7);

    expect(field().value).toBe('1');
    expect(container.textContent).toContain('That page of vaulted values could not be read.');
  });
});

describe('the reuse list', () => {
  it('drops a value an earlier page already showed', async () => {
    openTab(/reuse/i);
    loadMoreVaultReuse.mockResolvedValue({
      totals: { reused: 500 },
      items: [entry('r1'), entry('r2')],
      nextCursor: null,
    });
    await clickSlot('pagination-next');

    expect(container.textContent).toContain('MASK-r2');
    expect(container.textContent).not.toContain('MASK-r1');
  });

  it('reads a jumped-to page from its row position', async () => {
    openTab(/reuse/i);
    loadMoreVaultReuse.mockResolvedValue({
      totals: { reused: 500 },
      items: [entry('r7')],
      nextCursor: null,
    });
    await jumpTo(7);

    expect(lastQuery(loadMoreVaultReuse)).toEqual({ offset: 300 });
    expect(field().value).toBe('7');
    expect(status()).toBe('301–301 of 500 reused values');
  });
});

describe('the de-reference trail', () => {
  beforeEach(() => {
    openTab(/audit/i);
  });

  it('counts its pages from the trail total', () => {
    expect(status()).toBe('1–1 of 500 resolutions');
    expect(container.textContent).toContain('of 10');
  });

  it('reads a jumped-to page from its row position', async () => {
    loadVaultDerefs.mockResolvedValue(derefPage(['d7'], 'deref-7'));
    await jumpTo(7);

    expect(lastQuery(loadVaultDerefs)).toEqual({ offset: 300 });
    expect(field().value).toBe('7');
    expect(status()).toBe('301–301 of 500 resolutions');
  });

  it('reads the page before the run by position', async () => {
    loadVaultDerefs.mockResolvedValueOnce(derefPage(['d7'], 'deref-7'));
    await jumpTo(7);

    loadVaultDerefs.mockResolvedValueOnce(derefPage(['d6'], 'deref-6'));
    await clickSlot('pagination-previous');
    expect(lastQuery(loadVaultDerefs)).toEqual({ offset: 250 });
    expect(field().value).toBe('6');
  });

  it('says so and stays put when the trail has shrunk past the page', async () => {
    loadVaultDerefs.mockResolvedValue(derefPage([], null));
    await jumpTo(7);

    expect(field().value).toBe('1');
    expect(container.textContent).toContain(
      'That page of the de-reference trail is no longer there.',
    );
  });

  it('shows the hidden count of the latest read', async () => {
    loadVaultDerefs.mockResolvedValue({ ...derefPage(['d2'], null), hiddenBatched: 9 });
    await clickSlot('pagination-next');

    expect(container.textContent).toContain('9 display/render');
  });

  it('adopts a fresh first page from the server, turning the filter back off', async () => {
    const trail = (hiddenBatched: number) => ({
      ...derefPage(['d5'], null, 3),
      hiddenBatched,
    });
    loadVaultDerefs.mockResolvedValue(trail(3));
    await clickSlot('pagination-next');
    expect(field().value).toBe('2');

    act(() => {
      root.render(
        createElement(VaultDashboardClient, {
          inventory: inventoryPage(['v1'], 'inv-1'),
          reuse: { totals: { reused: 500 }, items: [entry('r1')], nextCursor: 'reuse-1' },
          derefs: derefPage(['d8'], null, 8),
          renderedAt: Date.parse(AT),
          locale: 'en-US',
        }),
      );
    });

    expect(status()).toBe('1–1 of 8 resolutions');
    expect(field().value).toBe('1');
  });

  it('says so when the filter’s own read fails', async () => {
    loadVaultDerefs.mockResolvedValueOnce({ ...derefPage(['d2'], 'deref-2'), hiddenBatched: 3 });
    await clickSlot('pagination-next');
    loadVaultDerefs.mockRejectedValueOnce(new Error('locked'));
    const toggle = [...container.querySelectorAll('button')].find((b) =>
      b.textContent.includes('Show them'),
    );
    expect(toggle, 'the toggle was not offered').toBeTruthy();
    await act(async () => {
      toggle?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });

    expect(container.textContent).toContain('The de-reference trail could not be read.');
  });

  it('drops a page still in flight when the filter flips', async () => {
    loadVaultDerefs.mockResolvedValueOnce({ ...derefPage(['d2'], 'deref-2'), hiddenBatched: 3 });
    await clickSlot('pagination-next');
    let release: ((page: ListVaultDerefsResponse) => void) | undefined;
    loadVaultDerefs.mockReturnValueOnce(
      new Promise((resolve) => {
        release = resolve;
      }),
    );
    await act(async () => {
      container
        .querySelector('[role="tabpanel"]:not([hidden]) [data-slot="pagination-next"]')
        ?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });
    // The filter's own read never answers here, so only the token can drop the page.
    let releaseFlip: ((page: ListVaultDerefsResponse) => void) | undefined;
    loadVaultDerefs.mockReturnValueOnce(
      new Promise((resolve) => {
        releaseFlip = resolve;
      }),
    );
    const toggle = [...container.querySelectorAll('button')].find((b) =>
      b.textContent.includes('Show them'),
    );
    expect(toggle, 'the toggle was not offered').toBeTruthy();
    await act(async () => {
      toggle?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });

    await act(async () => {
      release?.(derefPage(['stale'], null));
      await Promise.resolve();
    });

    expect(status()).toBe('51–51 of 500 resolutions');

    // A pending async transition holds up every later one, so it must not outlive
    // this case.
    await act(async () => {
      releaseFlip?.(derefPage(['d9'], null));
      await Promise.resolve();
    });
  });

  it('keeps the filter it was flipped to when paging', async () => {
    const fresh = { ...derefPage(['d1'], 'deref-1'), hiddenBatched: 3 };
    loadVaultDerefs.mockResolvedValueOnce(fresh);
    await clickSlot('pagination-next');
    const toggle = [...container.querySelectorAll('button')].find((b) =>
      b.textContent.includes('Show them'),
    );
    expect(toggle, 'the toggle was not offered').toBeTruthy();
    loadVaultDerefs.mockResolvedValueOnce(derefPage(['d3'], 'deref-3'));
    await act(async () => {
      toggle?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await Promise.resolve();
    });
    expect(lastQuery(loadVaultDerefs)).toEqual({ includeBatched: true });

    loadVaultDerefs.mockResolvedValueOnce(derefPage(['d4'], null));
    await clickSlot('pagination-next');
    expect(lastQuery(loadVaultDerefs)).toEqual({ includeBatched: true, cursor: 'deref-3' });
  });

  it('takes its total from each read, since the filter can change it', async () => {
    loadVaultDerefs.mockResolvedValue(derefPage(['d2'], null, 700));
    await clickSlot('pagination-next');
    expect(status()).toBe('51–51 of 700 resolutions');
  });
});

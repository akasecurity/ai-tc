import { describe, expect, it, vi } from 'vitest';

import {
  makeCloseDrawerHandler,
  makeExpandToggleHandler,
  makeOnBackHandler,
  makeOnPickHandler,
  makeOpenDestHandler,
  makeOpenEndpointHandler,
  makeOpenReviewedDestHandler,
  makeReviewOpenHandler,
  makeReviewSheetOpenChangeHandler,
  makeSetDecisionHandler,
  makeTabsValueChangeHandler,
} from '../../app/(app)/data-shares/interactions.ts';

describe('makeOpenDestHandler', () => {
  it('pushes the current search term with the opened destination id', () => {
    const push = vi.fn();
    makeOpenDestHandler(push, 'okta')('dest-1');
    expect(push).toHaveBeenCalledExactlyOnceWith({ q: 'okta', dest: 'dest-1' });
  });
});

describe('makeCloseDrawerHandler', () => {
  it('clears the decision error and pushes the current search term with no selection', () => {
    const push = vi.fn();
    const setDecisionError = vi.fn();
    makeCloseDrawerHandler(push, 'okta', setDecisionError)();
    expect(setDecisionError).toHaveBeenCalledExactlyOnceWith(null);
    expect(push).toHaveBeenCalledExactlyOnceWith({ q: 'okta' });
  });
});

describe('makeOpenReviewedDestHandler', () => {
  it('switches to the tab the destination lives under before opening it', () => {
    const push = vi.fn();
    const setActiveKind = vi.fn();
    makeOpenReviewedDestHandler(push, 'okta', () => 'ip', setActiveKind)('dest-1');
    expect(setActiveKind).toHaveBeenCalledExactlyOnceWith('ip');
    expect(push).toHaveBeenCalledExactlyOnceWith({ q: 'okta', dest: 'dest-1' });
  });

  it('leaves the tab alone when the destination is in no rendered group', () => {
    const push = vi.fn();
    const setActiveKind = vi.fn();
    makeOpenReviewedDestHandler(push, '', () => undefined, setActiveKind)('dest-gone');
    expect(setActiveKind).not.toHaveBeenCalled();
    // Still navigates — the detail read is its own server query.
    expect(push).toHaveBeenCalledExactlyOnceWith({ q: '', dest: 'dest-gone' });
  });
});

describe('makeReviewOpenHandler', () => {
  it('opens the review sheet', () => {
    const setReviewOpen = vi.fn();
    makeReviewOpenHandler(setReviewOpen)();
    expect(setReviewOpen).toHaveBeenCalledExactlyOnceWith(true);
  });
});

describe('makeTabsValueChangeHandler', () => {
  it('sets the active kind from the tab value', () => {
    const setActiveKind = vi.fn();
    makeTabsValueChangeHandler(setActiveKind)('ip');
    expect(setActiveKind).toHaveBeenCalledExactlyOnceWith('ip');
  });
});

describe('makeExpandToggleHandler', () => {
  it('flips only the toggled id, leaving the rest of the map untouched', () => {
    let captured: ((m: Record<string, boolean>) => Record<string, boolean>) | undefined;
    const setExpanded = vi.fn(
      (updater: (m: Record<string, boolean>) => Record<string, boolean>) => {
        captured = updater;
      },
    );
    makeExpandToggleHandler(setExpanded)('dest-2');
    expect(captured?.({ 'dest-1': true, 'dest-2': false })).toEqual({
      'dest-1': true,
      'dest-2': true,
    });
  });

  it('toggles an id absent from the map on, not off', () => {
    let captured: ((m: Record<string, boolean>) => Record<string, boolean>) | undefined;
    const setExpanded = vi.fn(
      (updater: (m: Record<string, boolean>) => Record<string, boolean>) => {
        captured = updater;
      },
    );
    makeExpandToggleHandler(setExpanded)('dest-new');
    expect(captured?.({})).toEqual({ 'dest-new': true });
  });
});

describe('makeOpenEndpointHandler', () => {
  it('pushes the current search term with the destination and endpoint ids', () => {
    const push = vi.fn();
    makeOpenEndpointHandler(push, 'okta')('dest-1', 'ep-1');
    expect(push).toHaveBeenCalledExactlyOnceWith({ q: 'okta', dest: 'dest-1', ep: 'ep-1' });
  });
});

describe('makeOnPickHandler', () => {
  it('pushes the fixed destination id with the picked endpoint id', () => {
    const push = vi.fn();
    makeOnPickHandler(push, 'okta', 'dest-1')('ep-2');
    expect(push).toHaveBeenCalledExactlyOnceWith({ q: 'okta', dest: 'dest-1', ep: 'ep-2' });
  });
});

describe('makeOnBackHandler', () => {
  it('pushes the destination id with no endpoint', () => {
    const push = vi.fn();
    makeOnBackHandler(push, 'okta', 'dest-1')();
    expect(push).toHaveBeenCalledExactlyOnceWith({ q: 'okta', dest: 'dest-1' });
  });
});

describe('makeReviewSheetOpenChangeHandler', () => {
  it('does nothing when the sheet is opening', () => {
    const closeDrawer = vi.fn();
    const setReviewOpen = vi.fn();
    makeReviewSheetOpenChangeHandler(true, closeDrawer, setReviewOpen)(true);
    expect(closeDrawer).not.toHaveBeenCalled();
    expect(setReviewOpen).not.toHaveBeenCalled();
  });

  it('keeps the review list open when a detail is dismissed — "back to list"', () => {
    const closeDrawer = vi.fn();
    const setReviewOpen = vi.fn();
    makeReviewSheetOpenChangeHandler(true, closeDrawer, setReviewOpen)(false);
    expect(closeDrawer).toHaveBeenCalledOnce();
    expect(setReviewOpen).not.toHaveBeenCalled();
  });

  it('clears the destination too when the list itself is dismissed', () => {
    // Not just cosmetic: `drawerOpen` is captured at render time, so a
    // dismissal landing while a "Review" push is in flight still sees false.
    // Clearing `dest` supersedes that push, which is what stops the sheet
    // re-opening on the destination the user just dismissed.
    const closeDrawer = vi.fn();
    const setReviewOpen = vi.fn();
    makeReviewSheetOpenChangeHandler(false, closeDrawer, setReviewOpen)(false);
    expect(setReviewOpen).toHaveBeenCalledExactlyOnceWith(false);
    expect(closeDrawer).toHaveBeenCalledOnce();
  });
});

describe('makeSetDecisionHandler', () => {
  function deps(overrides: Partial<Parameters<typeof makeSetDecisionHandler>[0]> = {}) {
    let ran: Promise<void> | undefined;
    const setDecisionError = vi.fn();
    const setEgressDecision = vi.fn().mockResolvedValue(true);
    const startTransition = vi.fn((cb: () => void | Promise<void>) => {
      ran = Promise.resolve(cb());
    });
    return {
      deps: {
        isSettingDecision: false,
        destinationId: 'dest-1',
        setDecisionError,
        startTransition,
        setEgressDecision,
        ...overrides,
      },
      setDecisionError,
      setEgressDecision,
      startTransition,
      settle: async () => {
        await ran;
      },
    };
  }

  it('is a no-op while a decision write is already in flight', () => {
    const { deps: d, setDecisionError, startTransition } = deps({ isSettingDecision: true });
    makeSetDecisionHandler(d)('block');
    expect(setDecisionError).not.toHaveBeenCalled();
    expect(startTransition).not.toHaveBeenCalled();
  });

  it('clears the prior error and writes the decision', async () => {
    const { deps: d, setDecisionError, setEgressDecision, settle } = deps();
    makeSetDecisionHandler(d)('block');
    expect(setDecisionError).toHaveBeenCalledWith(null);
    await settle();
    expect(setEgressDecision).toHaveBeenCalledExactlyOnceWith('dest-1', 'block');
  });

  it('surfaces a message when the destination is gone (write returns false)', async () => {
    const { deps: d, setDecisionError, settle } = deps();
    d.setEgressDecision = vi.fn().mockResolvedValue(false);
    makeSetDecisionHandler(d)(null);
    await settle();
    expect(setDecisionError).toHaveBeenLastCalledWith(
      'This destination no longer exists — reload to refresh the list.',
    );
  });

  it('surfaces a generic message when the write throws', async () => {
    const { deps: d, setDecisionError, settle } = deps();
    d.setEgressDecision = vi.fn().mockRejectedValue(new Error('boom'));
    makeSetDecisionHandler(d)('allow');
    await settle();
    expect(setDecisionError).toHaveBeenLastCalledWith(
      'Could not update the egress decision. Please try again.',
    );
  });
});

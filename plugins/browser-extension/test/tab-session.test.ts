import { WebEnforcementState } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import type { SharedScope } from '../src/tab-session.ts';
import {
  notifyDomSend,
  publishEnforcementState,
  readEnforcementState,
  resolveSessionId,
  setDomSendListener,
  setEnforcementListener,
} from '../src/tab-session.ts';

// The channel between this extension's two content scripts. They run in one
// isolated world and share its global, which is the only way they can agree on
// anything — a package wall does not separate them, a bundle boundary does.

describe('resolveSessionId', () => {
  it('mints an id the first time and hands the same one back after', () => {
    const scope: SharedScope = {};
    const first = resolveSessionId(scope);
    expect(first).not.toBe('');
    expect(resolveSessionId(scope)).toBe(first);
  });

  it('adopts an id whichever script minted it', () => {
    // The property the whole module exists for: two ids in one tab would put
    // the DOM path's prompts under a different session root than the network
    // path's exchanges, and neither could be joined to the other.
    const scope: SharedScope = {};
    const network = resolveSessionId(scope);
    const dom = resolveSessionId(scope);
    expect(dom).toBe(network);
  });

  it('mints rather than adopting an empty value', () => {
    const scope: SharedScope = { __akaWebSessionId: '' };
    expect(resolveSessionId(scope)).not.toBe('');
  });

  it('gives separate tabs separate ids', () => {
    // A different isolated world is a different scope object.
    expect(resolveSessionId({})).not.toBe(resolveSessionId({}));
  });
});

describe('the DOM-send signal', () => {
  it('reaches the listener the network path registered', () => {
    const scope: SharedScope = {};
    const listener = vi.fn();
    setDomSendListener(scope, listener);
    notifyDomSend(scope);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('is a no-op when nothing registered', () => {
    // The DOM script runs at document_idle whether or not the network half
    // resolved an adapter for this page.
    expect(() => {
      notifyDomSend({});
    }).not.toThrow();
  });

  it('never lets a listener fault reach the send it is reporting on', () => {
    const scope: SharedScope = {};
    setDomSendListener(scope, () => {
      throw new Error('health reporting broke');
    });
    expect(() => {
      notifyDomSend(scope);
    }).not.toThrow();
  });
});

describe('enforcement state', () => {
  it("reads 'unknown' before the DOM half has published anything", () => {
    // Not 'unattached'. The network half can report before the DOM half has
    // run at all, and a tab that has not yet been measured must not be
    // reported as one that was measured and found dead.
    expect(readEnforcementState({})).toBe('unknown');
  });

  it('hands the network half whatever the DOM half last published', () => {
    const scope: SharedScope = {};
    publishEnforcementState(scope, 'watching');
    expect(readEnforcementState(scope)).toBe('watching');
  });

  it('overwrites on republish, so a composer that drifts away is reported', () => {
    // reattach() runs on every SPA mutation. A state that only ever moved
    // toward 'watching' would report the healthy moment forever.
    const scope: SharedScope = {};
    publishEnforcementState(scope, 'watching');
    publishEnforcementState(scope, 'composer-only');
    expect(readEnforcementState(scope)).toBe('composer-only');
  });

  it("reads 'unknown' rather than trusting a value the page could have planted", () => {
    // The shared scope is isolated-world only, so this is defence against a
    // future bundling mistake rather than against the page today.
    expect(readEnforcementState({ __akaEnforcement: 'watching!' })).toBe('unknown');
  });
});

describe('the carried enforcement vocabulary', () => {
  it("matches schema's, which the content-script bundle cannot import at runtime", () => {
    // tab-session.ts carries its own copy of these members because the shipped
    // content scripts take no runtime dependency on @akasecurity/schema. A test
    // is under no such rule, so it is what holds the two in step: a member
    // added to WebEnforcementState and not here would be published by the DOM
    // half and read back as 'unknown'.
    const carried = new Set<string>();
    for (const state of WebEnforcementState.options) {
      publishEnforcementState({}, state);
      carried.add(state);
    }
    for (const state of WebEnforcementState.options) {
      const scope: SharedScope = {};
      publishEnforcementState(scope, state);
      expect(readEnforcementState(scope)).toBe(state);
    }
    expect(carried.size).toBe(WebEnforcementState.options.length);
  });
});

describe('publishing an enforcement state tells the network half at once', () => {
  it('notifies a registered listener, so a change is never left unreported', () => {
    // The two halves are separate content scripts. The network half is what
    // relays status, and it recomputes only on its OWN events — so without
    // this a DOM-path change sits in the shared scope until some unrelated
    // network traffic happens to fire. On a quiet tab that is for ever.
    const scope: SharedScope = {};
    const seen: string[] = [];
    setEnforcementListener(scope, () => {
      seen.push(readEnforcementState(scope));
    });

    publishEnforcementState(scope, 'watching');
    publishEnforcementState(scope, 'composer-only');

    expect(seen).toEqual(['watching', 'composer-only']);
  });

  it('publishes fine when nothing is listening', () => {
    // The DOM half runs at document_idle and the network half at
    // document_start, but a page where the latter never installed must not
    // break the former.
    const scope: SharedScope = {};
    expect(() => {
      publishEnforcementState(scope, 'watching');
    }).not.toThrow();
    expect(readEnforcementState(scope)).toBe('watching');
  });

  it('a listener that throws costs the report, never the state', () => {
    const scope: SharedScope = {};
    setEnforcementListener(scope, () => {
      throw new Error('relay gone');
    });
    expect(() => {
      publishEnforcementState(scope, 'unattached');
    }).not.toThrow();
    expect(readEnforcementState(scope)).toBe('unattached');
  });
});

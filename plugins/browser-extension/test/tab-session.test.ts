import { describe, expect, it, vi } from 'vitest';

import type { SharedScope } from '../src/tab-session.ts';
import { notifyDomSend, resolveSessionId, setDomSendListener } from '../src/tab-session.ts';

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

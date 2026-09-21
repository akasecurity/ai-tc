// @vitest-environment jsdom
import { WEB_CAPTURE_DRIFT_STATES } from '@akasecurity/plugin-sdk';
import { WebSourceTool } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { BackgroundRequest, BackgroundResponse } from '../src/messaging.ts';
import type { CaptureStateResponse } from '../src/native-host/protocol.ts';

// popup/index.ts calls `void refresh()` — and so `chrome.runtime.sendMessage`
// — the instant it is imported, so a `chrome` stub has to exist BEFORE that
// import runs. `vi.hoisted` is what runs before every import in this file
// (including the popup's own), which a plain top-level statement cannot do:
// ES module imports are evaluated before any of this file's own statements,
// regardless of where they are written.
type RelayFn = (message: unknown) => Promise<unknown>;

const relayImpl: { current: RelayFn } = vi.hoisted(() => ({
  current: () =>
    Promise.resolve({
      type: 'error',
      requestId: undefined,
      ok: false,
      message: 'unset stub',
    }),
}));

vi.hoisted(() => {
  (globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: { sendMessage: (message: unknown) => relayImpl.current(message) },
    tabs: { create: () => Promise.resolve() },
  };
});

const { DRIFT_STATES, refresh, renderCaptureSites } = await import('../src/popup/index.ts');

// The fragment of popup.html this module actually touches.
const FRAGMENT = `
  <div id="status-dot" class="dot"></div>
  <span id="status-text"></span>
  <div id="findings-row" class="row muted" hidden>
    <span id="findings-text"></span>
  </div>
  <div id="capture-section" hidden>
    <div id="capture-not-enabled" class="row muted" hidden>network capture not enabled</div>
    <div id="capture-sites"></div>
  </div>
  <button id="open-dashboard"></button>
`;

function response(overrides: Partial<CaptureStateResponse> = {}): CaptureStateResponse {
  return {
    type: 'capture_state',
    requestId: 'r1',
    ok: true,
    consented: true,
    sites: [
      { tool: 'chatgpt', state: 'standby' },
      { tool: 'claude-ai', state: 'idle' },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  document.body.innerHTML = FRAGMENT;
  // The default stub for the module's own auto-refresh, so importing it
  // anywhere in this file never produces an unhandled rejection.
  relayImpl.current = () =>
    Promise.resolve({ type: 'error', requestId: undefined, ok: false, message: 'no relay set' });
});

describe('renderCaptureSites: the DOM enforcement half', () => {
  const sitesText = (): string => document.getElementById('capture-sites')?.textContent ?? '';

  it('says so when the send button no longer resolves, naming which half is missing', () => {
    // The live signed-in chatgpt.com shape. Without this the popup shows the
    // network state and nothing else, and a tab enforcing nothing reads exactly
    // like a healthy one.
    renderCaptureSites(
      response({ sites: [{ tool: 'chatgpt', state: 'idle', enforcement: 'composer-only' }] }),
    );
    expect(sitesText()).toContain('send button');
  });

  it('says so when the composer no longer resolves', () => {
    renderCaptureSites(
      response({ sites: [{ tool: 'chatgpt', state: 'idle', enforcement: 'button-only' }] }),
    );
    expect(sitesText()).toContain('composer');
  });

  it('marks a site enforcing nothing with the error tone', () => {
    renderCaptureSites(
      response({ sites: [{ tool: 'chatgpt', state: 'idle', enforcement: 'unattached' }] }),
    );
    const rows = [...(document.getElementById('capture-sites')?.children ?? [])];
    expect(rows.some((r) => r.className.includes('tone-error'))).toBe(true);
  });

  it('stays quiet while the watcher is bound', () => {
    renderCaptureSites(
      response({ sites: [{ tool: 'chatgpt', state: 'idle', enforcement: 'watching' }] }),
    );
    expect(sitesText()).not.toContain('send button');
    // 'not enforcing', not 'not watching': every note ENFORCEMENT_NOTES can
    // produce opens with the former, and the latter is a string this popup
    // never renders — so asserting its absence could not fail whatever the
    // notes said. Verified by mutation: adding a note for `watching` reds
    // this case and left the old assertion green.
    expect(sitesText()).not.toContain('not enforcing');
  });

  it('stays quiet when the site has never reported an enforcement state', () => {
    // 'unknown' is the absence of an opinion, not a fault. Rendering it as one
    // would put a warning on every tab whose DOM half has not run yet.
    renderCaptureSites(response({ sites: [{ tool: 'chatgpt', state: 'idle' }] }));
    expect(sitesText()).not.toContain('send button');
    expect(sitesText()).not.toContain('not enforcing');
  });
});

describe('renderCaptureSites', () => {
  it('renders one row per site with its state word', () => {
    renderCaptureSites(response());
    const sitesEl = document.getElementById('capture-sites');
    expect(sitesEl?.textContent).toContain('standby');
    expect(sitesEl?.textContent).toContain('idle');
    expect(sitesEl?.children).toHaveLength(2);
  });

  it('renders a drift state with the error tone; standby renders the neutral one', () => {
    renderCaptureSites(
      response({
        sites: [
          { tool: 'chatgpt', state: 'degraded' },
          { tool: 'claude-ai', state: 'standby' },
        ],
      }),
    );
    const rows = [...(document.getElementById('capture-sites')?.children ?? [])];
    expect(rows[0]?.className).toContain('tone-error');
    expect(rows[1]?.className).not.toContain('tone-error');
    expect(rows[1]?.className).toContain('muted');
  });

  it('renders idle as the neutral tone too, never as error', () => {
    // A separate case from the mixed one above so a mapping that reads every
    // non-active state as error would still fail here, specifically on idle.
    renderCaptureSites(response({ sites: [{ tool: 'chatgpt', state: 'idle' }] }));
    const row = document.getElementById('capture-sites')?.children[0];
    expect(row?.className).not.toContain('tone-error');
  });

  it('renders the not-enabled line and no per-site rows when consent is absent', () => {
    renderCaptureSites(response({ consented: false }));
    const notEnabled = document.getElementById('capture-not-enabled');
    const sitesEl = document.getElementById('capture-sites');
    expect(notEnabled?.hidden).toBe(false);
    expect(sitesEl?.children).toHaveLength(0);
  });

  it('unhides the capture section', () => {
    const section = document.getElementById('capture-section');
    expect(section?.hidden).toBe(true);
    renderCaptureSites(response());
    expect(section?.hidden).toBe(false);
  });

  it('the site label map covers every WebSourceTool', () => {
    // Drives the schema's own enum rather than a hand-written pair — the
    // annotated Record<WebSourceTool, …> in popup/index.ts already fails to
    // compile on its own if a label is missing; this is what would catch an
    // EMPTY label string, which the compiler cannot.
    renderCaptureSites(
      response({
        sites: WebSourceTool.options.map((tool) => ({ tool, state: 'idle' as const })),
      }),
    );
    const sitesEl = document.getElementById('capture-sites');
    for (const tool of WebSourceTool.options) {
      expect(sitesEl?.textContent).toContain(tool === 'chatgpt' ? 'ChatGPT' : 'Claude.ai');
    }
  });
});

// The same guard bridge-constants.test.ts puts on the bridge's copy of
// RESPONSE_TEXT_MAX_BYTES: a browser bundle cannot import the original, and a
// test is Node, so this is where the copy is held true. Without it a state
// added to the drift set colours the CLI line red and leaves the popup neutral,
// with the whole suite green.
describe('the popup drift-state copy', () => {
  it('is the same set as the one the rule fires on', () => {
    expect([...DRIFT_STATES].sort()).toEqual([...WEB_CAPTURE_DRIFT_STATES].sort());
  });

  it('is a real set, not two empty ones that happen to agree', () => {
    expect(WEB_CAPTURE_DRIFT_STATES.size).toBeGreaterThan(0);
  });
});

describe('the popup refresh flow', () => {
  it('leaves the capture section hidden when the host does not answer capture_state', async () => {
    relayImpl.current = (message: unknown) => {
      const type = (message as BackgroundRequest).type;
      if (type === 'ping') {
        return Promise.resolve({
          type: 'ping',
          requestId: 'p',
          ok: true,
          dbPath: '',
          onboarded: true,
        });
      }
      if (type === 'health') {
        return Promise.resolve({
          type: 'health',
          requestId: 'h',
          ok: true,
          findings: 0,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        });
      }
      // capture_state: an old host that does not recognise the type.
      const errorResponse: BackgroundResponse = {
        type: 'error',
        requestId: 'e',
        ok: false,
        message: 'unsupported request type: capture_state',
      };
      return Promise.resolve(errorResponse);
    };

    await expect(refresh()).resolves.toBeUndefined();

    expect(document.getElementById('capture-section')?.hidden).toBe(true);
  });
});

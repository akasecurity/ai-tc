/**
 * The one content script injected on every provider this package knows about
 * (manifest.json's content_scripts.matches) — resolves the adapter for
 * location.hostname, watches its composer for a send attempt, and relays the
 * text to background.ts → the native host for detection + persistence,
 * exactly the block/redact/warn decision the CLI hooks already make, just
 * enforced here (composer rewrite / preventDefault) instead of after the
 * fact. Client-side scanning happens in the native host today (same
 * detection engine, one process hop); running it here too — via
 * @akasecurity/plugin-sdk/browser, the one Node-free slice of the SDK — is a
 * possible future latency optimization.
 *
 * SPA-safe: the composer AND the send button get unmounted/remounted as the
 * user navigates between conversations without a full page reload, so a
 * MutationObserver keeps re-resolving both rather than caching stale nodes.
 * The decision loop itself lives in interceptor.ts (unit-tested there).
 */
import { createSubmitInterceptor } from './interceptor.ts';
import type { BackgroundRequest, BackgroundResponse } from './messaging.ts';
import { resolveAdapter } from './providers/registry.ts';
import type { ProviderAdapter } from './providers/types.ts';
import type { SharedScope } from './tab-session.ts';
import type { EnforcementState } from './tab-session.ts';
import { notifyDomSend, publishEnforcementState, resolveSessionId } from './tab-session.ts';

const adapter = resolveAdapter(location.hostname);
if (adapter) {
  bootstrap(adapter);
}

// What the two halves of the gate below add up to. Both misses are named
// separately because each points at a different selector list, and one site has
// shown both: its signed-in build resolves a composer and no send button, its
// anonymous build a send button and no composer.
function enforcementState(
  composerEl: HTMLElement | null,
  buttonEl: HTMLElement | null,
): EnforcementState {
  if (composerEl && buttonEl) return 'watching';
  if (composerEl) return 'composer-only';
  if (buttonEl) return 'button-only';
  return 'unattached';
}

// How long a DEGRADED enforcement state must persist before it is believed.
//
// reattach runs on every DOM mutation, and a page load legitimately passes
// through a half-resolved state on its way to a bound one — measured live as
// unknown -> button-only -> watching within a few frames. Publishing each step
// puts a "not enforcing" row in the store and a warning in the popup for a tab
// that is perfectly healthy, on every load. Only a state that OUTLASTS the
// mount is a fault worth reporting.
const ENFORCEMENT_SETTLE_MS = 2000;

// Synchronous: the watcher must be attached before anything can be sent, so
// nothing here is allowed to await. session_start is fired and left to settle
// on its own (see below).
//
// Exported so it can be driven with a stand-in adapter. The call below runs it
// for real only when `location.hostname` resolves to an adapter, so importing
// this module anywhere else does nothing.
export function bootstrap(activeAdapter: ProviderAdapter): void {
  // Shared with the network path rather than minted here: the two run as
  // separate content scripts in one isolated world, and a second id would put
  // this tab's prompts under a different session root than the exchanges that
  // answered them.
  const scope = window as unknown as SharedScope;
  const sessionId = resolveSessionId(scope);
  const interceptor = createSubmitInterceptor({
    adapter: activeAdapter,
    sessionId,
    relay,
    showBanner,
    // A send that actually left the composer is this tab's one observation
    // that the user asked for a turn. The network path counts it as a turn it
    // must see an exchange for, so a run of sends with no exchange behind them
    // is how a tap that installed and sees nothing becomes visible.
    noteSend: () => {
      notifyDomSend(scope);
    },
  });

  // Asymmetric on purpose: `watching` is published at once, because a bound
  // watcher is never provisional — it either bound or it did not. Everything
  // else waits out ENFORCEMENT_SETTLE_MS, and is cancelled if the page reaches
  // `watching` first. An identical repeat does NOT restart the wait, or the
  // churn of a busy SPA would defer a genuinely broken page for ever.
  let publishedEnforcement: EnforcementState = 'unknown';
  let pendingEnforcement: EnforcementState | null = null;
  let enforcementTimer: ReturnType<typeof setTimeout> | null = null;

  function reportEnforcement(state: EnforcementState): void {
    if (state === 'watching') {
      if (enforcementTimer) clearTimeout(enforcementTimer);
      enforcementTimer = null;
      pendingEnforcement = null;
      if (publishedEnforcement !== 'watching') {
        publishedEnforcement = 'watching';
        publishEnforcementState(scope, 'watching');
      }
      return;
    }
    if (state === publishedEnforcement || state === pendingEnforcement) return;
    if (enforcementTimer) clearTimeout(enforcementTimer);
    pendingEnforcement = state;
    enforcementTimer = setTimeout(() => {
      enforcementTimer = null;
      pendingEnforcement = null;
      publishedEnforcement = state;
      publishEnforcementState(scope, state);
    }, ENFORCEMENT_SETTLE_MS);
  }

  let composer: HTMLElement | null = null;
  let sendButton: HTMLElement | null = null;
  let unwatch: (() => void) | null = null;
  let reattachScheduled = false;

  function reattach(): void {
    reattachScheduled = false;
    const nextComposer = activeAdapter.findComposer();
    // The send button is tracked alongside the composer: an SPA re-render can
    // replace just the button while the composer node survives, and a
    // remounted button would otherwise send unwatched (watchSubmit binds its
    // click listener to the node it saw at attach time).
    const nextButton = activeAdapter.findSendButton();
    // Reported on every pass, and BEFORE the identity check below. On a page
    // where neither half resolves, that check compares null against null on the
    // very first pass and returns — so a tab that never attached would
    // otherwise report nothing at all, for its whole life, which is
    // indistinguishable from a tab nobody typed in.
    reportEnforcement(enforcementState(nextComposer, nextButton));
    if (nextComposer === composer && nextButton === sendButton) return;
    unwatch?.();
    composer = nextComposer;
    sendButton = nextButton;
    // BOTH halves must resolve before anything is intercepted. A composer with
    // no send button leaves no way to complete a send the interceptor has
    // already preventDefault()ed, so watching would eat every message rather
    // than fail open — the opposite of what the adapters' own comments promise
    // ("a miss here means … this adapter silently does nothing"). That holds
    // when the composer is missing; without this it was false when only the
    // button drifted. Unwatched, the site keeps working normally.
    if (composer && sendButton) {
      const target = composer;
      unwatch = activeAdapter.watchSubmit(target, (event) => {
        interceptor.handleSubmit(event, target);
      });
    } else {
      unwatch = null;
    }
  }

  function scheduleReattach(): void {
    if (reattachScheduled) return;
    reattachScheduled = true;
    requestAnimationFrame(reattach);
  }

  // Watch FIRST, announce the session after. session_start cold-starts the MV3
  // service worker and has Chrome spawn the native host process — hundreds of
  // milliseconds during which nothing was listening, so a user who landed on
  // the page and immediately pasted and sent got no interception at all. The
  // session id is generated locally and decide() already tolerates a host that
  // is not ready yet, so no ordering here depends on that round trip.
  scheduleReattach();
  new MutationObserver(scheduleReattach).observe(document.body, {
    childList: true,
    subtree: true,
  });

  void relay({
    type: 'session_start',
    sessionId,
    tool: activeAdapter.id,
    hostname: location.hostname,
  }).catch(() => {
    // Fail-open: no native host reachable yet (extension not installed via
    // `aka extension install`) must never break the page — capture requests
    // fail open independently the same way (see interceptor.ts).
  });
}

function relay(request: BackgroundRequest): Promise<BackgroundResponse> {
  return chrome.runtime.sendMessage<BackgroundRequest, BackgroundResponse>(request);
}

let bannerHost: HTMLElement | null = null;
let bannerHideTimer: ReturnType<typeof setTimeout> | null = null;

// A fixed, viewport-anchored toast rather than one positioned relative to the
// composer: every provider's layout differs enough (sidebar widths, mobile
// breakpoints, …) that a fixed bottom-center placement stays visible and
// unclipped everywhere. Rendered in a shadow root so the host page's CSS
// can neither hide it nor be affected by it.
function showBanner(message: string, tone: 'block' | 'warn' | 'redact'): void {
  if (!bannerHost) {
    bannerHost = document.createElement('div');
    bannerHost.style.all = 'initial';
    bannerHost.style.position = 'fixed';
    bannerHost.style.zIndex = '2147483647';
    bannerHost.style.bottom = '24px';
    bannerHost.style.left = '50%';
    bannerHost.style.transform = 'translateX(-50%)';
    document.body.append(bannerHost);
  }
  const shadow = bannerHost.shadowRoot ?? bannerHost.attachShadow({ mode: 'open' });
  const color = tone === 'block' ? '#dc2626' : tone === 'redact' ? '#d97706' : '#2563eb';
  const box = document.createElement('div');
  box.style.font = '13px/1.4 system-ui, sans-serif';
  box.style.background = color;
  box.style.color = 'white';
  box.style.padding = '8px 14px';
  box.style.borderRadius = '8px';
  box.style.boxShadow = '0 4px 12px rgba(0,0,0,0.25)';
  box.style.maxWidth = '480px';
  box.textContent = message;
  shadow.replaceChildren(box);

  if (bannerHideTimer) clearTimeout(bannerHideTimer);
  bannerHideTimer = setTimeout(() => {
    bannerHost?.remove();
    bannerHost = null;
  }, 6000);
}

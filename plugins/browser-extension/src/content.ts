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

const adapter = resolveAdapter(location.hostname);
if (adapter) {
  void bootstrap(adapter);
}

async function bootstrap(activeAdapter: ProviderAdapter): Promise<void> {
  const sessionId = crypto.randomUUID();
  const interceptor = createSubmitInterceptor({
    adapter: activeAdapter,
    sessionId,
    relay,
    showBanner,
  });

  await relay({
    type: 'session_start',
    sessionId,
    tool: activeAdapter.id,
    hostname: location.hostname,
  }).catch(() => {
    // Fail-open: no native host reachable yet (extension not installed via
    // `aka extension install`) must never break the page — capture requests
    // fail open independently the same way (see interceptor.ts).
  });

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
    if (nextComposer === composer && nextButton === sendButton) return;
    unwatch?.();
    composer = nextComposer;
    sendButton = nextButton;
    if (composer) {
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

  scheduleReattach();
  new MutationObserver(scheduleReattach).observe(document.body, {
    childList: true,
    subtree: true,
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

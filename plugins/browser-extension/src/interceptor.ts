// The submit-interception decision loop, factored out of content.ts so it
// unit-tests without a real page (content.ts runs its bootstrap on import).
//
// The one subtle invariant lives here: letting an approved send proceed means
// programmatically re-triggering the SAME send gesture this interceptor is
// watching (adapter.submit() clicks the send button; the watcher's capture
// listener sees that click too). Without a guard, every approved send
// re-enters handleSubmit — re-relaying the capture (duplicate store rows) and
// re-preventing the default — so the message never actually leaves and the
// loop never ends. `bypassNextSubmit` is armed immediately before each
// programmatic submit and consumed by the very next handleSubmit invocation,
// which returns BEFORE preventDefault so the site's own handler finally runs.
import type { BackgroundRequest, BackgroundResponse } from './messaging.ts';
import type { ProviderAdapter } from './providers/types.ts';

export type BannerTone = 'block' | 'warn' | 'redact';

export interface SubmitInterceptor {
  // Wired as the adapter's watchSubmit callback. Synchronous on the event
  // (preventDefault must happen before the handler returns); the relay and
  // resulting resubmit happen on the promise it starts internally.
  handleSubmit(event: Event, composer: HTMLElement): void;
}

export function createSubmitInterceptor(opts: {
  adapter: ProviderAdapter;
  sessionId: string;
  relay: (request: BackgroundRequest) => Promise<BackgroundResponse>;
  showBanner: (message: string, tone: BannerTone) => void;
}): SubmitInterceptor {
  const { adapter, sessionId, relay, showBanner } = opts;
  let bypassNextSubmit = false;

  function passThrough(composer: HTMLElement): void {
    bypassNextSubmit = true;
    // The bypass is meant to be consumed synchronously by the re-entrant
    // click. If submit() found no button to click (selector drift), nothing
    // consumes it — clear on the next macrotask so a stale flag can't let
    // the user's NEXT real send through unscanned.
    setTimeout(() => {
      bypassNextSubmit = false;
    }, 0);
    adapter.submit(composer);
  }

  async function decide(composer: HTMLElement, text: string): Promise<void> {
    const response = await relay({
      type: 'capture',
      sessionId,
      tool: adapter.id,
      kind: 'prompt',
      text,
    }).catch((): BackgroundResponse => ({
      type: 'error',
      requestId: undefined,
      ok: false,
      message: 'relay failed',
    }));

    if (response.type !== 'capture') {
      // No native host reachable — fail open: let the original message through.
      passThrough(composer);
      return;
    }

    if (response.action === 'block') {
      showBanner(
        `AKA blocked this message — flagged ${response.ruleIds.join(', ')}. Remove it and resend.`,
        'block',
      );
      return;
    }
    if (response.action === 'redact' && typeof response.text === 'string') {
      adapter.setText(composer, response.text);
      showBanner(
        `AKA redacted sensitive content (${response.ruleIds.join(', ')}) before sending.`,
        'redact',
      );
    } else if (response.action === 'warn') {
      showBanner(
        `AKA flagged sensitive content (${response.ruleIds.join(', ')}) — sent unchanged.`,
        'warn',
      );
    }
    passThrough(composer);
  }

  return {
    handleSubmit(event, composer) {
      if (bypassNextSubmit) {
        bypassNextSubmit = false;
        return; // before preventDefault: the site's own handler takes it now
      }
      const text = adapter.extractText(composer);
      // Nothing to intercept — let an empty send no-op exactly as the site would.
      if (text.trim() === '') return;

      event.preventDefault();
      event.stopImmediatePropagation();
      void decide(composer, text);
    },
  };
}

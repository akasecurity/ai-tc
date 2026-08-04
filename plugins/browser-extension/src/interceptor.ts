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
  // One decision at a time per composer. Without it, Enter pressed twice while
  // a slow host is still deciding relays the same text twice — two rows in the
  // audit store — and both resolutions call passThrough, firing two sends.
  let inFlight = false;

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
    if (response.action === 'redact') {
      // `text` is typed `string | null`, so { action: 'redact', text: null } is
      // protocol-legal. It used to fail this branch's typeof guard AND the warn
      // branch below, falling to passThrough with the composer still holding
      // the secret — sent, and with no banner at all, so the user's read was
      // "nothing was flagged". A redact the client cannot carry out blocks.
      if (typeof response.text !== 'string') {
        showBanner(
          `AKA could not redact this message (${response.ruleIds.join(', ')}) — remove the flagged content and resend.`,
          'block',
        );
        return;
      }
      adapter.setText(composer, response.text);
      // Read back rather than trusting the write. Both composers are framework
      // -backed (Claude.ai's is ProseMirror) and the adapters warn their
      // selectors are best-effort, so a reverted write or a stale node would
      // otherwise still show "AKA redacted …" and then send the original — a
      // false assurance about the one action the product exists to perform.
      if (adapter.extractText(composer).trim() !== response.text.trim()) {
        showBanner(
          'AKA could not redact this message — remove the flagged content and resend.',
          'block',
        );
        return;
      }
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
      if (inFlight) return;
      inFlight = true;
      void decide(composer, text).finally(() => {
        inFlight = false;
      });
    },
  };
}

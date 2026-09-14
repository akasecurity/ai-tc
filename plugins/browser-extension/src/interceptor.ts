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
import { blockGuidance, exceptionPointer } from './exception-guidance.ts';
import type { BackgroundRequest, BackgroundResponse } from './messaging.ts';
import type { ProviderAdapter } from './providers/types.ts';

export type BannerTone = 'block' | 'warn' | 'redact';

// What one banner renders. `exception` rides as its own field rather than
// inside `message` for two reasons: the command has to be a selectable element
// (a reference nobody can copy is a reference nobody can use), and its presence
// is what tells the banner to stay on screen — a block whose approve command
// scrolls away after six seconds offers a route the user cannot take.
export interface BannerRequest {
  tone: BannerTone;
  message: string;
  exception?: { intro: string; command: string; help: string };
}

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
  showBanner: (banner: BannerRequest) => void;
  // Called once per message that actually left the composer, and never for one
  // this interceptor stopped. The network path counts each of these as a turn
  // it must see an exchange for, so a decision that blocks — or a redact it
  // could not carry out, or a send button that went missing — must not be
  // charged to it: nothing was sent, so nothing on the network can answer.
  noteSend: () => void;
}): SubmitInterceptor {
  const { adapter, sessionId, relay, showBanner, noteSend } = opts;
  let bypassNextSubmit = false;
  // One decision at a time per composer. Without it, Enter pressed twice while
  // a slow host is still deciding relays the same text twice — two rows in the
  // audit store — and both resolutions call passThrough, firing two sends.
  let inFlight = false;

  // Returns whether the message actually went out. Callers must not claim a
  // send happened without checking.
  function passThrough(composer: HTMLElement): boolean {
    bypassNextSubmit = true;
    // The bypass is meant to be consumed synchronously by the re-entrant
    // click. If submit() found no button to click (selector drift), nothing
    // consumes it — clear on the next macrotask so a stale flag can't let
    // the user's NEXT real send through unscanned.
    setTimeout(() => {
      bypassNextSubmit = false;
    }, 0);
    if (adapter.submit(composer)) {
      // After the send, not before: submit() clicks the site's own button, so
      // the request it starts is already on its way when this runs and the
      // network path can pair the two. Wrapped because health reporting may
      // never break the send it is reporting on.
      try {
        noteSend();
      } catch {
        // A reporting fault costs the count, never the message.
      }
      return true;
    }
    // Selector drift: there was no send button to click. handleSubmit has
    // already preventDefault()ed the user's own send, so nothing sent this
    // message and nothing else is going to. Staying silent here is the worst
    // outcome the extension can produce — the user watches their message
    // vanish and reads it as sent. Clear the bypass immediately (nothing
    // consumed it) rather than leaving it armed until the timer.
    bypassNextSubmit = false;
    showBanner({
      tone: 'block',
      message:
        'AKA could not send this message — the send button was not found, so the site may have changed. Your text is still in the composer and was NOT sent.',
    });
    return false;
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
      const guidance = blockGuidance({
        ruleIds: response.ruleIds.join(', '),
        blockedRef: response.blockedReferences?.[0],
      });
      showBanner({
        tone: 'block',
        message: `${guidance.headline} ${guidance.advice}`,
        exception: {
          intro: guidance.approveIntro,
          command: guidance.command,
          help: guidance.help,
        },
      });
      return;
    }
    if (response.action === 'redact') {
      // `text` is typed `string | null`, so { action: 'redact', text: null } is
      // protocol-legal. It used to fail this branch's typeof guard AND the warn
      // branch below, falling to passThrough with the composer still holding
      // the secret — sent, and with no banner at all, so the user's read was
      // "nothing was flagged". A redact the client cannot carry out blocks.
      if (typeof response.text !== 'string') {
        showBanner({
          tone: 'block',
          message: `AKA could not redact this message (${response.ruleIds.join(', ')}) — remove the flagged content and resend.${exceptionPointer(response.blockedReferences)}`,
        });
        return;
      }
      adapter.setText(composer, response.text);
      // Read back rather than trusting the write. Both composers are framework
      // -backed (Claude.ai's is ProseMirror) and the adapters warn their
      // selectors are best-effort, so a reverted write or a stale node would
      // otherwise still show "AKA redacted …" and then send the original — a
      // false assurance about the one action the product exists to perform.
      if (adapter.extractText(composer).trim() !== response.text.trim()) {
        showBanner({
          tone: 'block',
          message: `AKA could not redact this message — remove the flagged content and resend.${exceptionPointer(response.blockedReferences)}`,
        });
        return;
      }
      // Banner AFTER the send, and only if it happened: both of these name a
      // completed send ("before sending", "sent unchanged"), so showing them
      // first would state an outcome that passThrough may be about to fail to
      // produce — the same false assurance the read-back above guards against.
      if (!passThrough(composer)) return;
      showBanner({
        tone: 'redact',
        message: `AKA redacted sensitive content (${response.ruleIds.join(', ')}) before sending.${exceptionPointer(response.blockedReferences)}`,
      });
      return;
    }
    if (response.action === 'warn') {
      if (!passThrough(composer)) return;
      showBanner({
        tone: 'warn',
        message: `AKA flagged sensitive content (${response.ruleIds.join(', ')}) — sent unchanged.${exceptionPointer(response.blockedReferences)}`,
      });
      return;
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

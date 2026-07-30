/**
 * MessageDisplay — fires once per assistant streaming delta. Display-only:
 * vault pointers are rewritten in what the terminal renders, while the
 * transcript and the model's context keep the original text.
 *
 * stdin:  { session_id, message_id, index, final, delta, ... } — `delta` is
 * one chunk of assistant text for content block `index`; `final` marks the
 * block's last delta.
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"MessageDisplay","displayContent":"..."}}
 *     → replaces this delta on screen
 *   no output → the delta renders unchanged
 *
 * A pointer can split across deltas, and each delta is a fresh hook process,
 * so the in-flight state (held tail, markdown-region flags, reveal count) is
 * persisted in a per-session file under the data dir. Inside it, tail and
 * region state are keyed by content block and die when the block ends; the
 * reveal count is keyed by message, so full mode's cap spans every block of
 * one message. A lost or clobbered carry degrades to raw pointer display —
 * pointers carry no secret material. Fail-open: any error → no output,
 * exit 0 — never a broken session.
 */
import { describePointerSafe, detokenizeText, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, VAULT_INLINE_REVEAL_MAX_PER_MESSAGE } from '@akasecurity/schema';

import type { CarryKeys, DisplayDeps } from './message-display-transform.ts';
import {
  carryFilePath,
  finalizeCarry,
  loadCarry,
  saveCarry,
  transformDelta,
} from './message-display-transform.ts';
import { emit, getString, parseJson, readStdin } from './shared.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;
  const delta = getString(input, 'delta');
  if (delta === undefined) return;

  // Consent gate before anything heavy: without a valid vault consent, or
  // with inline reveal off, this hook is inert. loadConfig reads only
  // settings.json — no store is opened on this path.
  const config = loadConfig();
  if (!isVaultConsentValid(config.settings.vaultConsent)) return;
  const mode = config.settings.vaultInlineReveal;
  if (mode === 'off') return;

  const sessionId = getString(input, 'session_id') ?? '';
  const messageId = getString(input, 'message_id') ?? '';
  const index = input.index;
  const keys: CarryKeys = {
    blockKey: [
      sessionId,
      messageId,
      typeof index === 'number' || typeof index === 'string' ? String(index) : '',
    ].join('/'),
    messageKey: [sessionId, messageId].join('/'),
  };
  const final = input.final === true;
  const file = carryFilePath(config.dataDir, sessionId);
  const carry = loadCarry(file, keys);

  // Fast path: no pointer can start ('['), no region state can change
  // ('`'/'~' fence or span markers, '>' quote), and nothing is pending for
  // this block or message — the delta renders unchanged and no state needs
  // writing. Mid-line state (lineSeen/lineIndent) counts as pending so the
  // line-position tracking stays accurate until the next newline.
  const pending =
    carry.tail !== '' ||
    carry.fence !== null ||
    carry.tickOpen ||
    carry.lineQuoted ||
    carry.lineSeen ||
    carry.lineIndent > 0 ||
    carry.revealedCount > 0;
  if (
    !pending &&
    !delta.includes('[') &&
    !delta.includes('`') &&
    !delta.includes('~') &&
    !delta.includes('>') &&
    !final
  ) {
    return;
  }

  const deps: DisplayDeps = {
    mode,
    maxRevealsPerMessage: VAULT_INLINE_REVEAL_MAX_PER_MESSAGE,
    describe: (token) => describePointerSafe(token),
    // One audit row per reveal: per-delta processes cannot batch per message
    // without persisting raw values across processes, which is off the table.
    reveal: async (token) => {
      const result = await detokenizeText(token, { target: 'human', reason: 'display' });
      return result.revealed === 1 ? result.text : null;
    },
  };

  const result = await transformDelta(delta, carry, final, deps);
  if (final) finalizeCarry(file, keys, result.carry);
  else saveCarry(file, keys, result.carry);

  if (result.display !== null) {
    await emit({
      hookSpecificOutput: { hookEventName: 'MessageDisplay', displayContent: result.display },
    });
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);

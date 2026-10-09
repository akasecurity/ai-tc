/**
 * The helper the ui.render mod runs through `$.process.run`:
 * `node <plugin root>/scripts/mod-reveal.js`.
 *
 * The mod draws vault pointers as the real value, or as a masked badge, and can
 * open neither the vault nor the settings. It hands the distinct complete
 * pointers it met here, once each, and caches the answers; it never asks again
 * for one it holds.
 *
 * This is the MessageDisplay hook's reveal, minus its delta plumbing: the same
 * consent gate, the same `vaultInlineReveal` mode, the same descriptor lookup
 * for the badge and the same audited resolve (`target: 'human'`,
 * `reason: 'display'`). Whether a pointer may be revealed where it stands (code,
 * quote, per-message cap) is the mod's call; a value is resolved only for an
 * item the mod asks to reveal.
 *
 * stdin:  {"v":1,"items":[{"token":"[[aka:...]]","reveal":true}, ...]}
 * stdout: {"v":1,"mode":"masked"|"full"|"off","items":[{"token","badge","revealed"}]}
 *   `badge` is what a masked pointer shows; `revealed` is the complete
 *   replacement for a revealed one (the value and its category marker), null
 *   unless the mode is full, the item asked for it and the vault answered.
 *   Mode `off` (no valid vault consent, or the setting off) answers no items:
 *   every pointer is left as written.
 * Exit 1 with nothing on stdout means "no answer": the mod shows the pointers
 * unchanged.
 *
 * A revealed value goes to stdout, which the mod draws and holds in `$.state`,
 * and nowhere else. Nothing is written to stderr.
 */
import { describePointerSafe, detokenizeText, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, PointerToken } from '@akasecurity/schema';

import { maskedBadge } from '../hooks/message-display-transform.ts';
import { countFailOpen, parseJson, readStdin } from '../hooks/shared.ts';

// Distinct pointers one call may resolve; the mod sends the few one redraw met.
const MAX_ITEMS = 32;

interface Item {
  token: string;
  reveal: boolean;
}

function parseItems(raw: unknown): Item[] | null {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_ITEMS) return null;
  const items: Item[] = [];
  for (const entry of raw as unknown[]) {
    if (typeof entry !== 'object' || entry === null) return null;
    const { token, reveal } = entry as { token?: unknown; reveal?: unknown };
    if (!PointerToken.safeParse(token).success || typeof reveal !== 'boolean') return null;
    items.push({ token: token as string, reveal });
  }
  return items;
}

function categoryOf(token: string): string {
  return token.split(':')[1] ?? 'unknown';
}

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  const items = input?.v === 1 ? parseItems(input.items) : null;
  if (items === null) process.exit(1);

  const config = loadConfig();
  const mode = isVaultConsentValid(config.settings.vaultConsent)
    ? config.settings.vaultInlineReveal
    : 'off';
  if (mode === 'off') {
    process.stdout.write(`${JSON.stringify({ v: 1, mode, items: [] })}\n`);
    return;
  }

  const answered: { token: string; badge: string; revealed: string | null }[] = [];
  for (const { token, reveal } of items) {
    const badge = await maskedBadge(token, {
      mode,
      maxRevealsPerMessage: 0,
      describe: (t) => describePointerSafe(t),
      reveal: () => Promise.resolve(null),
    });
    let revealed: string | null = null;
    if (mode === 'full' && reveal) {
      try {
        const result = await detokenizeText(token, { target: 'human', reason: 'display' });
        if (result.revealed === 1) revealed = `${result.text} [scrubbed:${categoryOf(token)}]`;
      } catch {
        revealed = null;
      }
    }
    answered.push({ token, badge, revealed });
  }
  process.stdout.write(`${JSON.stringify({ v: 1, mode, items: answered })}\n`);
}

try {
  await main();
} catch {
  countFailOpen();
  process.exit(1);
}
process.exit(0);

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
 * so the in-flight state (held pointer tail, markdown-region flags, reveal
 * count) is persisted in one file under the data dir, keyed by
 * session/message/block and reset when the block ends. A lost or clobbered
 * carry degrades to raw pointer display — pointers carry no secret material.
 * Fail-open: any error → no output, exit 0 — never a broken session.
 */
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { describePointerSafe, detokenizeText, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, VAULT_INLINE_REVEAL_MAX_PER_MESSAGE } from '@akasecurity/schema';

import type { DisplayCarry, DisplayDeps } from './message-display-transform.ts';
import { EMPTY_CARRY, transformDelta } from './message-display-transform.ts';
import { emit, getString, parseJson, readStdin } from './shared.ts';

const CARRY_FILE = 'display-carry.json';

function loadCarry(file: string, key: string): DisplayCarry {
  try {
    const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return EMPTY_CARRY;
    const record = parsed as Record<string, unknown>;
    if (record.key !== key || typeof record.carry !== 'object' || record.carry === null) {
      return EMPTY_CARRY;
    }
    const carry = record.carry as Record<string, unknown>;
    return {
      tail: typeof carry.tail === 'string' ? carry.tail : '',
      fenceOpen: carry.fenceOpen === true,
      tickOpen: carry.tickOpen === true,
      lineQuoted: carry.lineQuoted === true,
      revealedCount:
        typeof carry.revealedCount === 'number' && Number.isFinite(carry.revealedCount)
          ? carry.revealedCount
          : 0,
    };
  } catch {
    return EMPTY_CARRY;
  }
}

// Single-entry overwrite, atomic via tmp+rename, owner-only mode. Concurrent
// content blocks are rare, and a lost carry only degrades to raw pointer
// display on screen.
function saveCarry(file: string, key: string, carry: DisplayCarry): void {
  try {
    mkdirSync(dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    writeFileSync(tmp, JSON.stringify({ key, carry, updatedAt: new Date().toISOString() }), {
      mode: 0o600,
    });
    renameSync(tmp, file);
  } catch {
    // Carry loss is a display degrade, never a crash.
  }
}

function deleteCarry(file: string): void {
  try {
    rmSync(file, { force: true });
  } catch {
    // A leftover carry file is keyed and simply won't match the next block.
  }
}

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

  const index = input.index;
  const key = [
    getString(input, 'session_id') ?? '',
    getString(input, 'message_id') ?? '',
    typeof index === 'number' || typeof index === 'string' ? String(index) : '',
  ].join('/');
  const final = input.final === true;
  const file = join(config.dataDir, CARRY_FILE);
  const carry = loadCarry(file, key);

  // Fast path: no pointer can start ('['), no region state can change
  // ('`' fence/span, '>' quote), and nothing is carried for this block —
  // the delta renders unchanged and no state needs writing.
  const pending =
    carry.tail !== '' ||
    carry.fenceOpen ||
    carry.tickOpen ||
    carry.lineQuoted ||
    carry.revealedCount > 0;
  if (!pending && !delta.includes('[') && !delta.includes('`') && !delta.includes('>') && !final) {
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
  if (final) deleteCarry(file);
  else saveCarry(file, key, result.carry);

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

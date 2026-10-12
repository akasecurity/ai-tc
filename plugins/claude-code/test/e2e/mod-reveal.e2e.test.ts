/**
 * The ui.render mod's helper (scripts/mod-reveal.js), driven as a process against
 * a throwaway store and vault, the way the mod runs it. A real pointer is minted
 * by the tokenizing helper first, so the reveal resolves a value the vault holds.
 *
 * What the mod relies on, and these cases pin: a value only where the mode is
 * full, consent is valid and the item asks for it; the masked badge otherwise;
 * no items at all when reveal is off or consent is missing; exit 1 and silence
 * for input that is not exactly the request; and the value on stdout only.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const RULE_ID = 'secrets/twilio-key';
function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const found = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = found?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (found === undefined || example === undefined) throw new Error(`${RULE_ID} has no example`);
  return { pack: found, example };
}
const { pack, example: SECRET } = secretFixture();

type Mode = 'full' | 'masked' | 'off';

function env(home: string): Record<string, string> {
  return { ...tempHomeEnv(home), NODE_OPTIONS: '' };
}

function setup(home: string, mode: Mode | undefined, consent = true): string {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(pack.namespace, pack.packId, 'vault');
  } finally {
    db.close();
  }
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({
      onboardedAt: '2026-01-01T00:00:00Z',
      ...(mode === undefined ? {} : { vaultInlineReveal: mode }),
      ...(consent
        ? {
            vaultConsent: {
              acknowledgedAt: new Date().toISOString(),
              version: VAULT_CONSENT_VERSION,
            },
          }
        : {}),
    }),
  );
  mkdirSync(join(home, 'project'), { recursive: true });
  const minted = runHook(
    'mod-tokenize',
    JSON.stringify({ v: 1, text: `key ${SECRET}`, sessionId: 's', cwd: join(home, 'project') }),
    { env: env(home) },
  );
  const text = (JSON.parse(minted.stdout) as { text: string }).text;
  return /\[\[aka:[^\]]+\]\]/.exec(text)?.[0] ?? '';
}

function reveal(home: string, items: unknown) {
  return runHook('mod-reveal', JSON.stringify({ v: 1, items }), { env: env(home) });
}

interface Answer {
  v: number;
  mode: Mode;
  items: { token: string; badge: string; revealed: string | null }[];
}

describe('mod-reveal helper', () => {
  it('full mode: the value, with its category marker, for an item that asks; the badge for one that does not', () => {
    withTempHome((home) => {
      const token = setup(home, 'full');
      const asked = JSON.parse(reveal(home, [{ token, reveal: true }]).stdout) as Answer;
      const declined = JSON.parse(reveal(home, [{ token, reveal: false }]).stdout) as Answer;

      expect(asked.mode).toBe('full');
      expect(asked.items[0]?.revealed).toBe(`${SECRET} [scrubbed:secret]`);
      expect(asked.items[0]?.badge).toMatch(/^\[scrubbed:secret/);
      expect(asked.items[0]?.badge).not.toContain(SECRET);
      expect(declined.items[0]?.revealed).toBeNull();
      expect(JSON.stringify(declined)).not.toContain(SECRET);
    }, 'aka-mod-reveal-full-');
  });

  it('masked mode never resolves a value', () => {
    withTempHome((home) => {
      const token = setup(home, 'masked');
      const run = reveal(home, [{ token, reveal: true }]);
      const answer = JSON.parse(run.stdout) as Answer;

      expect(answer.mode).toBe('masked');
      expect(answer.items[0]?.revealed).toBeNull();
      expect(run.stdout).not.toContain(SECRET);
    }, 'aka-mod-reveal-masked-');
  });

  it('reveal off, or no valid consent, answers no items', () => {
    withTempHome((home) => {
      const token = setup(home, 'off');
      const answer = JSON.parse(reveal(home, [{ token, reveal: true }]).stdout) as Answer;
      expect(answer).toEqual({ v: 1, mode: 'off', items: [] });
    }, 'aka-mod-reveal-off-');
    withTempHome((home) => {
      const token = setup(home, 'full', false);
      expect(token).toBe('');
      const answer = JSON.parse(
        reveal(home, [
          { token: `[[aka:secret:AB.${'A'.repeat(26)}.${'B'.repeat(16)}]]`, reveal: true },
        ]).stdout,
      ) as Answer;
      expect(answer.mode).toBe('off');
      expect(answer.items).toEqual([]);
    }, 'aka-mod-reveal-noconsent-');
  });

  it('a pointer the vault does not hold is shown masked, never as an error', () => {
    withTempHome((home) => {
      setup(home, 'full');
      const unknown = `[[aka:secret:AB.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
      const answer = JSON.parse(reveal(home, [{ token: unknown, reveal: true }]).stdout) as Answer;

      expect(answer.items[0]?.revealed).toBeNull();
      expect(answer.items[0]?.badge).toContain('[scrubbed:secret');
    }, 'aka-mod-reveal-unknown-');
  });

  it('input that is not exactly the request gives exit 1 and nothing on stdout', () => {
    withTempHome((home) => {
      setup(home, 'full');
      const good = `[[aka:secret:AB.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
      for (const run of [
        runHook('mod-reveal', 'not json', { env: env(home) }),
        runHook('mod-reveal', '', { env: env(home) }),
        runHook('mod-reveal', JSON.stringify({ v: 2, items: [{ token: good, reveal: true }] }), {
          env: env(home),
        }),
        reveal(home, []),
        reveal(home, [{ token: 'not a pointer', reveal: true }]),
        reveal(home, [{ token: good }]),
        reveal(
          home,
          Array.from({ length: 33 }, () => ({ token: good, reveal: false })),
        ),
      ]) {
        expect(run.status).toBe(1);
        expect(run.stdout).toBe('');
      }
    }, 'aka-mod-reveal-bad-');
  });
});

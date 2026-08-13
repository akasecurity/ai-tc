/**
 * The UserPromptSubmit wire contract for the arm nothing else pins: **allow is
 * silence**. Driving the REAL built script, because "writes nothing" is a
 * property of the process's stdout, not of a return value — the decision
 * module returning null is a different claim, and a unit test cannot see the
 * difference between that and an entry that emits anyway.
 *
 * Why the gap existed. The two neighbouring suites both assert around this
 * case without covering it:
 *
 *   - `test/hooks/user-prompt-submit.test.ts` asserts a clean prompt carries
 *     `not.toContain('"decision":"block"')`, which is satisfied by the
 *     onboarding nudge — a payload, not silence.
 *   - `test/e2e/fail-open.e2e.test.ts`'s enforcement matrix runs its
 *     `monitor` row against an UN-onboarded home, so it expects
 *     `"systemMessage"` (the nudge) rather than an empty stdout.
 *
 * Neither home is onboarded, so no test has ever driven the one configuration
 * in which this hook is supposed to say nothing at all.
 *
 * An empty stdout is the weakest possible assertion — a hook that crashed on
 * import, or one whose store never opened, satisfies it perfectly. So the
 * silence case is bracketed by two controls on the same built script: an
 * onboarded home that still BLOCKS a flagged prompt (the hook is alive and
 * reaching the store), and an un-onboarded home that emits the nudge for the
 * very same clean prompt (the silence is attributable to `onboardedAt`, not to
 * a store that failed open).
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { ONBOARDING_NUDGE } from '../../src/hooks/onboarding-nudge.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'ups-wire-e2e-session';
const CLEAN_PROMPT = 'rename this variable across the module';

// `runHook` layers its env over the HOST's, so an inherited NODE_OPTIONS would
// put Node's own diagnostics on the child's stderr and redden the empty-stderr
// assertion for a reason that has nothing to do with the hook. Blank it.
function hookEnv(home: string): Record<string, string> {
  return { ...tempHomeEnv(home), NODE_OPTIONS: '' };
}

// The secret comes from the bundled rule's own `examples` fixture, so no
// secret-shaped literal lives in this file. Same rule the sibling suite picks,
// and for the same reason: its example matches no other bundled rule.
const RULE_ID = 'secrets/twilio-key';

function secretExample(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { pack, example };
}

const { pack: SECRET_PACK, example: SECRET } = secretExample();

function projectDir(home: string): string {
  const dir = join(home, 'project');
  mkdirSync(dir, { recursive: true });
  return dir;
}

// `config.onboarded` is `settings.onboardedAt != null` — the single field that
// decides whether the allow path is silent or carries the calibration nudge.
function markOnboarded(home: string): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({ onboardedAt: '2026-01-01T00:00:00Z' }),
  );
}

function seedPolicy(home: string, policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, policy);
  } finally {
    db.close();
  }
}

function submit(home: string, prompt: string): ReturnType<typeof runHook> {
  return runHook(
    'user-prompt-submit',
    JSON.stringify({
      prompt,
      session_id: SESSION_ID,
      cwd: projectDir(home),
      hook_event_name: 'UserPromptSubmit',
    }),
    { env: hookEnv(home) },
  );
}

describe('user-prompt-submit wire contract — allow is silence', () => {
  it('onboarded machine, clean prompt → exit 0 and an empty stdout', () => {
    withTempHome((home) => {
      markOnboarded(home);
      const run = submit(home, CLEAN_PROMPT);

      expect(run.status).toBe(0);
      // The whole point: no opinion is the ABSENCE of a payload, not an
      // `{"decision":"allow"}`. Claude Code reads exit-0-and-silence as allow.
      expect(run.stdout).toBe('');
      expect(run.stderr).toBe('');
    });
  });

  it('control: the same onboarded home still blocks a flagged prompt', () => {
    withTempHome((home) => {
      markOnboarded(home);
      seedPolicy(home, 'block');
      const run = submit(home, `please deploy using this key: ${SECRET}`);

      // Without this the silence above is worthless — a hook that emits
      // nothing under every input satisfies an empty-stdout assertion. Assert
      // the emptiness directly rather than letting JSON.parse('') throw, so a
      // regression names the property instead of a SyntaxError.
      expect(run.status).toBe(0);
      expect(run.stdout).not.toBe('');
      const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
      expect(payload.decision).toBe('block');
      expect(payload.reason).toContain(RULE_ID);
      expectNoEchoOf(run.stdout, SECRET);
    });
  });

  it('control: an un-onboarded home emits the nudge for the same clean prompt', () => {
    withTempHome((home) => {
      const run = submit(home, CLEAN_PROMPT);

      // Attributes the silence above to `onboardedAt` specifically. Without
      // this, a store that failed to open would produce the same empty stdout
      // and read as a passing allow case.
      expect(run.status).toBe(0);
      expect(run.stdout).not.toBe('');
      const payload = JSON.parse(run.stdout) as { systemMessage?: string };
      // Against the exported constant, not a substring of it: the constant is
      // the single source of truth for this copy, and a substring match would
      // also accept a regression to the stale installation-type framing.
      expect(payload.systemMessage).toBe(ONBOARDING_NUDGE);
    });
  });
});

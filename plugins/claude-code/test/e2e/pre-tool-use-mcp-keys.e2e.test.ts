/**
 * A secret an agent writes as an MCP tool argument's OBJECT KEY — rather than
 * its value — never reached the detection engine: pre-tool-use-fields.ts's
 * `mcpFields` walk addressed every string VALUE leaf for scanning but used
 * each object key only to build that leaf's path, discarding the key text
 * itself. `{ "<secret>": "x" }` (or the same shape nested, or inside an array
 * of objects) passed PreToolUse with no finding, while `{ "field": "<secret>"
 * }` was caught — an attacker (or a confused agent) only had to put the
 * credential on the left-hand side of the colon.
 *
 * This drives the REAL built hook (via runHook, from test/helpers/run-hook.ts)
 * against a real local store seeded with the bundled packs, exactly the way
 * fail-open.e2e.test.ts and user-prompt-submit-wire.e2e.test.ts do — so this
 * is the plugin's actual PreToolUse decision path, not a mock of it.
 */
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'pre-tool-use-mcp-keys-e2e-session';

// The value comes from a bundled rule's own `examples`, so no secret-shaped
// literal lives in this file. Same rule fail-open.e2e.test.ts pins its matrix
// on, for the same reason: it matches no OTHER bundled rule, so a two-rule
// overlap can't change the emitted shape underneath this test.
const RULE_ID = 'secrets/twilio-key';

function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(
      `bundled rule ${RULE_ID} is missing from the pack registry or has no example, so this ` +
        'suite would drive clean input through every case and assert nothing',
    );
  }
  return { pack, example };
}

const { pack: SECRET_PACK, example: SECRET } = secretFixture();

// Pins the pack to `block` so every positive case denies outright — the
// mechanics of a redact-on-an-executable-field fallback are already covered
// by fail-open.e2e.test.ts's policy matrix and pre-tool-use-decision.test.ts;
// this suite is about WHETHER a key-borne secret is seen at all.
function seedBlockPolicy(home: string): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, 'block');
  } finally {
    db.close();
  }
}

function preToolUse(home: string, toolInput: Record<string, unknown>): ReturnType<typeof runHook> {
  return runHook(
    'pre-tool-use',
    JSON.stringify({
      tool_name: 'mcp__example__call',
      tool_input: toolInput,
      session_id: SESSION_ID,
      cwd: home,
      hook_event_name: 'PreToolUse',
    }),
    { env: tempHomeEnv(home) },
  );
}

function isDenied(stdout: string): boolean {
  return stdout.includes('"permissionDecision":"deny"');
}

describe('PreToolUse — a secret placed as an MCP tool_input object KEY', () => {
  it('is caught at the top level, exactly like the same secret as a value', () => {
    withTempHome((home) => {
      seedBlockPolicy(home);

      const asValue = preToolUse(home, { field: SECRET });
      expect(asValue.status).toBe(0);
      expect(isDenied(asValue.stdout)).toBe(true);

      const asKey = preToolUse(home, { [SECRET]: 'harmless placeholder' });
      expect(asKey.status).toBe(0);
      expect(isDenied(asKey.stdout)).toBe(true);

      expectNoEchoOf(asValue.stdout, SECRET);
      expectNoEchoOf(asKey.stdout, SECRET);
    });
  });

  it('is caught nested inside the payload', () => {
    withTempHome((home) => {
      seedBlockPolicy(home);
      const run = preToolUse(home, { wrapper: { inner: { [SECRET]: 'x' } } });
      expect(run.status).toBe(0);
      expect(isDenied(run.stdout)).toBe(true);
      expectNoEchoOf(run.stdout, SECRET);
    });
  });

  it('is caught inside an array of objects', () => {
    withTempHome((home) => {
      seedBlockPolicy(home);
      const run = preToolUse(home, {
        items: [{ note: 'first, benign' }, { [SECRET]: 'x' }],
      });
      expect(run.status).toBe(0);
      expect(isDenied(run.stdout)).toBe(true);
      expectNoEchoOf(run.stdout, SECRET);
    });
  });

  it('is caught when a key and an unrelated value sit side by side', () => {
    withTempHome((home) => {
      seedBlockPolicy(home);
      const run = preToolUse(home, {
        [SECRET]: 'harmless placeholder',
        other: 'nothing sensitive',
      });
      expect(run.status).toBe(0);
      expect(isDenied(run.stdout)).toBe(true);
      expectNoEchoOf(run.stdout, SECRET);
    });
  });

  it('allows a payload carrying no secret at all, in a key or a value', () => {
    withTempHome((home) => {
      seedBlockPolicy(home);
      const run = preToolUse(home, { field: 'nothing sensitive here', other: 'also clean' });
      expect(run.status).toBe(0);
      expect(isDenied(run.stdout)).toBe(false);
    });
  });
});

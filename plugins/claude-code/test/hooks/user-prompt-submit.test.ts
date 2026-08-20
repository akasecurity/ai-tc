import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { ONBOARDING_NUDGE } from '../../src/hooks/onboarding-nudge.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { withTempHome } from '../helpers/run-hook.ts';

const CANONICAL_NUDGE =
  'AKA Security is installed but not calibrated — run /aka:setup to tune notifications to this machine (about a minute).';
const STALE_INSTALL_NUDGE = 'choose your installation type';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/hooks -> plugins/claude-code
const PLUGIN_ROOT = join(HERE, '..', '..');
const HOOK_SOURCE = join(PLUGIN_ROOT, 'src', 'hooks', 'user-prompt-submit.ts');
// The built entry the suite's global setup compiles (test/journey/global-setup.ts).
// Driving it proves the emit SITE, not just the exported constant.
const HOOK_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'user-prompt-submit.js');

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

// Drive the real built hook against a throwaway ~/.aka home, feeding a Claude
// Code UserPromptSubmit payload on stdin. process.execPath is an absolute node
// path, so the child needs no host PATH and inherits no ambient environment.
function runHook(home: string, payload: unknown): HookRun {
  try {
    const stdout = execFileSync(process.execPath, [HOOK_SCRIPT], {
      env: { HOME: home, USERPROFILE: home },
      input: JSON.stringify(payload),
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

describe('ONBOARDING_NUDGE', () => {
  it('is the canonical calibration-wizard copy', () => {
    expect(ONBOARDING_NUDGE).toBe(CANONICAL_NUDGE);
  });

  it('drops the stale installation-type framing', () => {
    expect(ONBOARDING_NUDGE).not.toContain(STALE_INSTALL_NUDGE);
  });
});

describe('user-prompt-submit hook source', () => {
  it('no longer references the stale installation-type string', () => {
    // The stale installation-type string no longer exists in the hook source.
    expect(readFileSync(HOOK_SOURCE, 'utf8')).not.toContain(STALE_INSTALL_NUDGE);
  });
});

describe('user-prompt-submit hook — driven end-to-end', () => {
  it('emits the calibration nudge (not the stale copy) on a clean prompt from an un-calibrated machine', () => {
    withTempHome((home) => {
      const run = runHook(home, {
        prompt: 'what does this function do?',
        session_id: 'sess-nudge',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
      });
      expect(run.status).toBe(0);
      expect(run.stderr).toBe('');
      const payload = JSON.parse(run.stdout) as { systemMessage?: string };
      // Proves the emit SITE carries the constant: a regression to any other copy
      // at the emit call fails here, which the constant-equality check cannot catch.
      expect(payload.systemMessage).toBe(ONBOARDING_NUDGE);
      expect(run.stdout).not.toContain(STALE_INSTALL_NUDGE);
    }, 'aka-ups-nudge-');
  });

  it('emits no block on a clean prompt', () => {
    withTempHome((home) => {
      const run = runHook(home, {
        prompt: 'rename this variable across the module',
        session_id: 'sess-clean',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
      });
      expect(run.status).toBe(0);
      expect(run.stdout).not.toContain('"decision":"block"');
    }, 'aka-ups-clean-');
  });

  it('falls back to allow and never throws when a store fault is injected (fail-open)', () => {
    withTempHome((home) => {
      // Injected fault: an unreadable store (not the SQLite header) so enforcement
      // cannot complete before the nudge. The hook must still resolve to allow.
      const dataDir = join(home, '.aka', 'data');
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(join(dataDir, 'aka.db'), 'not a database\n'.repeat(64));

      const run = runHook(home, {
        prompt: 'what does this function do?',
        session_id: 'sess-failopen',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
      });
      // Allow = exit 0, no exception escaped (empty stderr), and never a block.
      expect(run.status).toBe(0);
      expect(run.stderr).toBe('');
      expect(run.stdout).not.toContain('"decision":"block"');
    }, 'aka-ups-failopen-');
  });
});

// The enforcement matrix, driven through the REAL built hook against a seeded
// throwaway store. The secret value comes from the bundled rule's own
// `examples` fixture so no secret-shaped literal lives in this file, and the
// runHook env carries no PATH — the hook's best-effort clipboard spawn cannot
// find a utility, so no real clipboard is ever written by this suite. The rule
// is one whose example matches NO other bundled rule: a value two rules match
// on overlapping spans degrades one-way by design (no pointer to assert on).
const RULE_ID = 'secrets/twilio-key';
function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { pack, example };
}
const { pack: SECRET_PACK, example: SECRET_EXAMPLE } = secretFixture();
const SECRET_PROMPT = `please deploy using this key: ${SECRET_EXAMPLE}`;

// Install the bundled packs the way the gateway does on open, then assign the
// secrets pack the policy under test — per-rule pack policies are what the
// runtime's action resolution prefers.
function seedSecretPolicy(home: string, policyId: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(home, '.aka', 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, policyId);
  } finally {
    db.close();
  }
}

function grantVaultConsent(home: string): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({
      vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
    }),
  );
}

function submitSecretPrompt(home: string): HookRun {
  return runHook(home, {
    prompt: SECRET_PROMPT,
    session_id: 'sess-enforce',
    cwd: '/tmp',
    hook_event_name: 'UserPromptSubmit',
  });
}

describe('user-prompt-submit enforcement — redact blocks in every consent state', () => {
  it('redact policy, no vault consent → block with the plain removal message, raw never on stdout', () => {
    withTempHome((home) => {
      seedSecretPolicy(home, 'redact');
      const run = submitSecretPrompt(home);
      expect(run.status).toBe(0);
      const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
      expect(payload.decision).toBe('block');
      expect(payload.reason).toContain('twilio-key');
      expect(payload.reason).toContain('Remove the flagged content and resubmit');
      // Consent-off surfaces never touch the vault: no pointer, no vault talk.
      expect(run.stdout).not.toContain('[[aka:');
      // The never-leak assertion: the raw value appears nowhere on stdout.
      expectNoEchoOf(run.stdout, SECRET_EXAMPLE);
    }, 'aka-ups-redact-off-');
  });

  it('redact policy, valid vault consent → block with NO pointerized rewrite', () => {
    // Changed by the per-detection custody split, and the change is the point.
    // A REDACT decision means the archetype already stated the value's fate, and
    // Redact's catalog copy says it is destroyed and cannot be recovered — so
    // the resubmit rewrite may only keep findings whose detection chose Redact &
    // Vault. This machine is configured by CATEGORY policy, an axis that cannot
    // express that archetype at all, so nothing is kept and the user gets the
    // removal-based guidance instead.
    //
    // Consent alone no longer buys a pointerized rewrite on the redact path.
    // That is a real loss of an affordance, taken deliberately: the alternative
    // is vaulting a value whose own policy copy promises it was destroyed.
    withTempHome((home) => {
      seedSecretPolicy(home, 'redact');
      grantVaultConsent(home);
      const run = submitSecretPrompt(home);
      expect(run.status).toBe(0);
      const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
      expect(payload.decision).toBe('block');
      // The same removal-based guidance the no-consent sibling above gets: with
      // nothing kept, there is no pointerized prompt to hand back.
      expect(payload.reason).toContain('Remove the flagged content and resubmit');
      expect(payload.reason).not.toContain('[[aka:');
      // The raw value still appears nowhere.
      expectNoEchoOf(run.stdout, SECRET_EXAMPLE);
    }, 'aka-ups-redact-on-');
  });

  it('block policy, no vault consent → the plain removal-based block, unchanged', () => {
    withTempHome((home) => {
      seedSecretPolicy(home, 'block');
      const run = submitSecretPrompt(home);
      expect(run.status).toBe(0);
      const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
      expect(payload.decision).toBe('block');
      expect(payload.reason).toMatch(/^AKA blocked this prompt — flagged /);
      expect(payload.reason).toContain('Remove the flagged content and resubmit');
      expect(run.stdout).not.toContain('[[aka:');
      expectNoEchoOf(run.stdout, SECRET_EXAMPLE);
    }, 'aka-ups-block-off-');
  });

  it('block policy, valid vault consent → block whose reason carries the resubmit rewrite', () => {
    withTempHome((home) => {
      seedSecretPolicy(home, 'block');
      grantVaultConsent(home);
      const run = submitSecretPrompt(home);
      expect(run.status).toBe(0);
      const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
      expect(payload.decision).toBe('block');
      expect(payload.reason).toContain('[[aka:');
      expectNoEchoOf(run.stdout, SECRET_EXAMPLE);
    }, 'aka-ups-block-on-');
  });

  it('warn policy → the prompt continues with a warning, never a block', () => {
    withTempHome((home) => {
      seedSecretPolicy(home, 'warn');
      const run = submitSecretPrompt(home);
      expect(run.status).toBe(0);
      expect(run.stdout).not.toContain('"decision":"block"');
      const payload = JSON.parse(run.stdout) as { systemMessage?: string };
      expect(payload.systemMessage).toContain('twilio-key');
      expect(payload.systemMessage).toContain('sent unchanged');
      // The stale claim that prompts cannot be redacted is gone.
      expect(payload.systemMessage).not.toContain('cannot be redacted');
    }, 'aka-ups-warn-');
  });
});

import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { withTempHome } from '../helpers/run-hook.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/hooks -> plugins/codex
const PLUGIN_ROOT = join(HERE, '..', '..');
// The built entry (built before tests run — turbo's test task depends on
// build). Driving it proves the emit SITE, not just the exported constants.
const HOOK_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'user-prompt-submit.js');
// The onboarding writer — stamping onboardedAt is what retires the first-run
// nudge, so the onboarded-home case below runs the real built script.
const ONBOARD_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'onboard.js');

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

// Drive the real built hook against a throwaway ~/.aka home, feeding a Codex
// UserPromptSubmit payload on stdin. process.execPath is an absolute node
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

// The enforcement matrix, driven through the REAL built hook against a seeded
// throwaway store. The secret value comes from the bundled rule's own
// `examples` fixture so no secret-shaped literal lives in this file.
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

function submitSecretPrompt(home: string): HookRun {
  return runHook(home, {
    prompt: SECRET_PROMPT,
    session_id: 'sess-enforce',
    cwd: '/tmp',
    hook_event_name: 'UserPromptSubmit',
  });
}

describe('user-prompt-submit enforcement — redact blocks, it never leaks the raw prompt', () => {
  it('redact policy → block with the removal message, raw never on stdout', () => {
    // This hook has no prompt-rewrite channel, so a redact policy must STOP
    // the prompt — warning and passing it through would send the raw secret
    // to the model. Same semantics as the Claude Code hook.
    withTempHome((home) => {
      seedSecretPolicy(home, 'redact');
      const run = submitSecretPrompt(home);
      expect(run.status).toBe(0);
      const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
      expect(payload.decision).toBe('block');
      expect(payload.reason).toContain('twilio-key');
      expect(payload.reason).toContain('Remove the flagged content and resubmit');
      // The never-leak assertion: no run of the raw value appears on stdout.
      // Run by run rather than whole — a branch echoing a truncated value is
      // still echoing a live credential's prefix.
      expectNoEchoOf(run.stdout, SECRET_EXAMPLE);
    }, 'aka-codex-ups-redact-');
  });

  it('block policy → the removal-based block, raw never on stdout', () => {
    withTempHome((home) => {
      seedSecretPolicy(home, 'block');
      const run = submitSecretPrompt(home);
      expect(run.status).toBe(0);
      const payload = JSON.parse(run.stdout) as { decision?: string; reason?: string };
      expect(payload.decision).toBe('block');
      expect(payload.reason).toMatch(/^AKA blocked this prompt — flagged /);
      expect(payload.reason).toContain('Remove the flagged content and resubmit');
      expectNoEchoOf(run.stdout, SECRET_EXAMPLE);
    }, 'aka-codex-ups-block-');
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
    }, 'aka-codex-ups-warn-');
  });

  it('emits no block on a clean prompt', () => {
    withTempHome((home) => {
      seedSecretPolicy(home, 'redact');
      const run = runHook(home, {
        prompt: 'what does this function do?',
        session_id: 'sess-clean',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
      });
      expect(run.status).toBe(0);
      expect(run.stderr).toBe('');
      expect(run.stdout).not.toContain('"decision":"block"');
    }, 'aka-codex-ups-clean-');
  });
});

function submitCleanPrompt(home: string, sessionId: string): HookRun {
  return runHook(home, {
    prompt: 'what does this function do?',
    session_id: sessionId,
    cwd: '/tmp',
    hook_event_name: 'UserPromptSubmit',
  });
}

describe('user-prompt-submit first-run nudge — once per session, retired by onboarding', () => {
  it('nudges a clean prompt from an un-onboarded home, naming the setup skill', () => {
    withTempHome((home) => {
      const first = submitCleanPrompt(home, 'sess-nudge');
      expect(first.status).toBe(0);
      const payload = JSON.parse(first.stdout) as { systemMessage?: string };
      expect(payload.systemMessage).toContain('aka-setup');
      expect(first.stdout).not.toContain('"decision":"block"');

      // Same session id against the same home: the one-per-session claim keeps
      // every later prompt silent instead of re-nudging on each submit.
      const second = submitCleanPrompt(home, 'sess-nudge');
      expect(second.status).toBe(0);
      expect(second.stdout).toBe('');
    }, 'aka-codex-ups-nudge-');
  });

  it('emits nothing once the home is onboarded', () => {
    withTempHome((home) => {
      // The real onboarding writer stamps onboardedAt — the flag the nudge
      // keys on — so this is the post-setup state, not a seeded lookalike.
      execFileSync(process.execPath, [ONBOARD_SCRIPT, '--historical', 'session-only'], {
        env: { HOME: home, USERPROFILE: home },
        encoding: 'utf8',
      });
      const run = submitCleanPrompt(home, 'sess-onboarded');
      expect(run.status).toBe(0);
      expect(run.stdout).toBe('');
    }, 'aka-codex-ups-onboarded-');
  });
});

// SessionStart's standing vault-protocol brief is strictly consent-gated:
// without a valid vaultConsent grant the hook emits nothing at all (today's
// behavior, byte for byte), and with one it emits exactly one JSON object
// whose additionalContext is the brief. Drives the REAL built script via
// runHook, the same harness the fail-open suite uses.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'session-start-brief-e2e';

function payload(home: string): string {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  return JSON.stringify({
    session_id: SESSION_ID,
    cwd,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
}

function writeSettings(home: string, settings: Record<string, unknown>): void {
  const dir = join(home, '.aka', 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'settings.json'), JSON.stringify(settings));
}

describe('session-start standing vault brief', () => {
  it('consent absent → emits nothing (stdout stays empty)', () => {
    withTempHome((home) => {
      const result = runHook('session-start', payload(home), { env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      expect(result.stdout).toBe('');
    });
  });

  it('consent recorded against an older version → still emits nothing', () => {
    withTempHome((home) => {
      writeSettings(home, {
        vaultConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION + 1,
        },
      });
      const result = runHook('session-start', payload(home), { env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      expect(result.stdout).toBe('');
    });
  });

  it('valid consent → additionalContext carries the brief', () => {
    withTempHome((home) => {
      writeSettings(home, {
        vaultConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION,
        },
      });
      const result = runHook('session-start', payload(home), { env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      const output = JSON.parse(result.stdout) as {
        hookSpecificOutput: { hookEventName: string; additionalContext: string };
      };
      expect(output.hookSpecificOutput.hookEventName).toBe('SessionStart');
      const brief = output.hookSpecificOutput.additionalContext;
      expect(brief).toContain('[[aka:<category>:...]]');
      expect(brief).toContain('verbatim');
      expect(brief).toContain('untrusted data');
      // Default inlineReveal is 'masked' → no inline-visibility claim.
      expect(brief).not.toContain('inline');
      expect(brief).toContain('aka vault show');
      // The marker rides the brief and persists for the session.
      expect(brief).toMatch(/\[AKA [0-9a-f]{16}\]/);
    });
  });
});

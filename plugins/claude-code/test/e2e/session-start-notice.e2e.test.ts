// What SessionStart shows the USER goes out as systemMessage, the one channel
// the host puts in front of them at session start: stderr from a hook that
// exits 0 reaches only the debug log. Drives the REAL built script via runHook.
//
// The stale-session notice is the line driven here because it needs no
// attachment: a newer binary recorded the pack mirror, and this session runs
// an older plugin generation. The forwarding line takes the same route —
// sessionStartNotice joins both into the one systemMessage — and its three
// states are covered against the runtime in plugin-runtime's
// session-start-scoped-credential suite, without a hook process that would
// try to reach a control plane.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { StandaloneDataGateway } from '@akasecurity/plugin-runtime';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

// The session's plugin generation, from the manifest the hook command passes.
const SESSION_VERSION = '0.0.1';
// A newer CLI generation that recorded the mirror before this session started.
const RECORDED_BY = 'aka-cli@99.0.0';

// What that newer CLI recorded: the packs this plugin ships, at a version
// above its own. The hook's binary is then behind the mirror, so its inventory
// write leaves the newer stamps in place, which is the state a real upgrade of
// the CLI ahead of the plugin leaves behind.
const NEWER_PACKS = bundledDetections().map((pack) => ({ ...pack, version: '99.0.0' }));

interface Setup {
  stdin: string;
  args: string[];
}

function setUp(home: string, sessionId: string, options: { newerRecorded: boolean }): Setup {
  const dataDir = join(home, '.aka', 'data');
  mkdirSync(dataDir, { recursive: true });
  if (options.newerRecorded) {
    const newer = new StandaloneDataGateway(dataDir, NEWER_PACKS, { recordedBy: RECORDED_BY });
    void newer.close();
  }
  const manifest = join(home, 'plugin.json');
  writeFileSync(manifest, JSON.stringify({ version: SESSION_VERSION }));
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  return {
    stdin: JSON.stringify({
      session_id: sessionId,
      cwd,
      hook_event_name: 'SessionStart',
      source: 'startup',
    }),
    args: [manifest],
  };
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

describe('session-start user notice', () => {
  it('without vault consent, the notice is the whole output, as a bare systemMessage', () => {
    withTempHome((home) => {
      const { stdin, args } = setUp(home, 'notice-bare', { newerRecorded: true });
      const result = runHook('session-start', stdin, { args, env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      const output = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(Object.keys(output)).toEqual(['systemMessage']);
      const shown = output.systemMessage as string;
      expect(shown.startsWith('[aka] ')).toBe(true);
      expect(shown).toContain(`v${SESSION_VERSION}`);
      expect(shown).toContain('aka-cli v99.0.0');
      // Not on stderr as well: one channel, the one the user sees.
      expect(result.stderr).not.toContain('aka-cli v99.0.0');
    });
  });

  it('with vault consent, the notice rides beside the brief in one object', () => {
    withTempHome((home) => {
      const { stdin, args } = setUp(home, 'notice-with-brief', { newerRecorded: true });
      grantVaultConsent(home);
      const result = runHook('session-start', stdin, { args, env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      const output = JSON.parse(result.stdout) as {
        hookSpecificOutput: { hookEventName: string; additionalContext: string };
        systemMessage: string;
      };
      expect(output.hookSpecificOutput.hookEventName).toBe('SessionStart');
      expect(output.hookSpecificOutput.additionalContext).toContain('[[aka:<category>:...]]');
      expect(output.systemMessage).toContain('aka-cli v99.0.0');
      // The model gets the brief, the user gets the notice: neither carries the other.
      expect(output.hookSpecificOutput.additionalContext).not.toContain('aka-cli v99.0.0');
    });
  });

  it('with nothing to show, the brief goes out alone and carries no systemMessage', () => {
    withTempHome((home) => {
      const { stdin, args } = setUp(home, 'notice-none', { newerRecorded: false });
      grantVaultConsent(home);
      const result = runHook('session-start', stdin, { args, env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      const output = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(Object.keys(output)).toEqual(['hookSpecificOutput']);
    });
  });
});

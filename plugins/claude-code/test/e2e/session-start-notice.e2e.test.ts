// What SessionStart shows the USER goes out as systemMessage, the one channel
// the host puts in front of them at session start: stderr from a hook that
// exits 0 reaches only the debug log. Drives the REAL built script via runHook.
//
// Two notices are driven. The stale-session notice needs no attachment: a
// newer binary recorded the pack mirror, and this session runs an older plugin
// generation. The forwarding line needs one, so its cases attach the temp home
// to a closed loopback port: the line is read from the gateway and the local
// store, so nothing has to answer there, and every send the session start
// attempts is refused on the machine itself.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { writeControlPlaneCredential } from '@akasecurity/persistence';
import { StandaloneDataGateway, SYNC_MARKER_NAME } from '@akasecurity/plugin-runtime';
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

// A deployment on a loopback port nothing listens on. Loopback is the one
// address an http endpoint may name, so the attachment is accepted, and a
// connect to it is refused at once rather than timing out.
const ENDPOINT = 'http://127.0.0.1:9';
const AT = '2026-10-01T09:00:00.000Z';
const WORK_KEY = 'github.com/acme/payments-api';

/**
 * The temp home attached to ENDPOINT, labelled Acme: the settings half and the
 * credential half, for `mode`, enrolling the work repository. The policy pull's
 * throttle marker is fresh, so the session start spawns no detached sync child
 * to outlive the test.
 */
function attachHome(home: string, mode: 'machine' | 'scoped'): void {
  const settingsDir = join(home, '.aka', 'settings');
  const dataDir = join(home, '.aka', 'data');
  mkdirSync(settingsDir, { recursive: true });
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(
    join(settingsDir, 'settings.json'),
    JSON.stringify({
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, label: 'Acme', attachedAt: AT },
      attachmentScope: {
        endpoint: ENDPOINT,
        entries: [{ kind: 'repo', identity: WORK_KEY, enrolledAt: AT }],
      },
    }),
  );
  writeControlPlaneCredential(
    settingsDir,
    mode === 'scoped'
      ? { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: 'placeholder', mintedAt: AT }
      : { specVersion: 1, endpoint: ENDPOINT, apiKey: 'placeholder', mintedAt: AT },
  );
  writeFileSync(join(dataDir, SYNC_MARKER_NAME), String(Date.now()));
}

/** A SessionStart payload in `cwd`, a checkout whose origin is `origin` when given. */
function startIn(home: string, sessionId: string, origin?: string): string {
  const cwd = join(home, 'checkout');
  mkdirSync(join(cwd, '.git'), { recursive: true });
  if (origin !== undefined) {
    writeFileSync(
      join(cwd, '.git', 'config'),
      `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${origin}\n`,
    );
  }
  return JSON.stringify({
    session_id: sessionId,
    cwd,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
}

function shownBy(stdout: string): unknown {
  return (JSON.parse(stdout) as Record<string, unknown>).systemMessage;
}

describe('session-start forwarding line', () => {
  it('says everything forwards on a machine attachment', () => {
    withTempHome((home) => {
      attachHome(home, 'machine');
      const stdin = startIn(home, 'line-machine');
      const result = runHook('session-start', stdin, { env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      expect(shownBy(result.stdout)).toBe('AKA: forwarding everything to Acme (machine-wide)');
      expect(result.stderr).not.toContain('AKA: forwarding');
    });
  });

  it('names the enrolled repository a scoped session starts in', () => {
    withTempHome((home) => {
      attachHome(home, 'scoped');
      const stdin = startIn(home, 'line-enrolled', 'https://github.com/acme/payments-api.git');
      const result = runHook('session-start', stdin, { env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      expect(shownBy(result.stdout)).toBe(`AKA: forwarding to Acme (${WORK_KEY})`);
    });
  });

  it('says local-only for a scoped session in a repository nobody enrolled', () => {
    withTempHome((home) => {
      attachHome(home, 'scoped');
      const stdin = startIn(home, 'line-personal', 'https://github.com/someone/side-project.git');
      const result = runHook('session-start', stdin, { env: tempHomeEnv(home) });
      expect(result.status).toBe(0);
      expect(shownBy(result.stdout)).toBe(
        'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded',
      );
    });
  });
});

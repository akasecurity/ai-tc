import { existsSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  applyOnboarding,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  CLAUDE_ACCOUNT_ENV_NAMES,
  claudeConfigPath,
  readClaudeAccountEnv,
} from '@akasecurity/plugin-sdk/account';
import { ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../test/helpers/remove-tree.ts';
import { runStatus } from '../src/commands/attach.ts';
import type { Prompter } from '../src/lib/prompter.ts';

// A suite that names no Claude Code home reads one anyway: `aka status` looks
// for the login file under the real home unless told where else to look. The
// setup file wired in vitest.config.ts moves that default to an empty directory
// for every case, and these cases show where it lands.

describe('the Claude Code config location a suite starts with', () => {
  it('is an empty directory under the temp root, not the real home', () => {
    const file = claudeConfigPath(readClaudeAccountEnv());
    expect(file).not.toBe(join(homedir(), '.claude.json'));
    expect(file.startsWith(tmpdir())).toBe(true);
    expect(existsSync(file)).toBe(false);
    expect(readdirSync(dirname(file))).toEqual([]);
  });
});

describe('aka status with no Claude Code home named', () => {
  let base: string;

  beforeEach(() => {
    base = join(tmpdir(), `aka-claude-guard-${String(process.pid)}-${String(Date.now())}`);
    // Every account variable but the config location the guard moved: a variable
    // the developer's own session exports would change the answer.
    for (const name of CLAUDE_ACCOUNT_ENV_NAMES) {
      if (name !== 'CLAUDE_CONFIG_DIR') vi.stubEnv(name, '');
    }
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    removeTree(base);
  });

  it('finds no login file', async () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: {
          endpoint: 'https://plane.example.com',
          label: 'Acme',
          attachedAt: '2026-10-01T09:00:00.000Z',
        },
        attachmentScope: {
          endpoint: 'https://plane.example.com',
          tenantName: 'Acme',
          userEmail: ['member', 'example.test'].join('@'),
          entries: [],
        },
      },
      base,
      null,
    );
    const key = `test-${String(Date.now())}`;
    writeControlPlaneCredential(settingsDirOf(base), {
      specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
      mode: 'scoped',
      endpoint: 'https://plane.example.com',
      apiKey: key,
    });
    const out: string[] = [];
    const unscripted = (): Promise<string> => Promise.reject(new Error('unscripted prompt'));
    const io: Prompter = {
      out: (text) => {
        out.push(text);
      },
      err: () => undefined,
      isInteractive: true,
      ask: unscripted,
      askHidden: unscripted,
      readAllStdin: () => Promise.resolve(''),
    };
    await runStatus([], { base, prompter: io, managedSettings: null });
    expect(out.join('')).toContain('  this login Claude Code — login file not found\n');
  });
});

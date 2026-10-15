import { readdirSync, realpathSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  CLAUDE_ACCOUNT_ENV_NAMES,
  codexEnvVetoed,
  codexHomeDir,
  readCodexAccountEnv,
} from '@akasecurity/plugin-sdk/account';
import { ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../test/helpers/remove-tree.ts';
import { runStatus } from '../src/commands/attach.ts';
import type { Prompter } from '../src/lib/prompter.ts';

// A suite that names no Codex home reads one anyway: `aka status` looks for the
// login file under the real home unless told where else to look, and a Codex key,
// token or gateway address in the environment vetoes the login before the file is
// read. The setup file wired in vitest.config.ts moves the home to an empty
// directory and clears those variables for every case, and these cases show where
// it lands.

describe('the Codex environment a suite starts with', () => {
  it('names an empty directory under the temp root as the Codex home, not the real home', () => {
    const home = codexHomeDir();
    if (home === undefined) throw new Error('the Codex home is not a usable directory');
    expect(home === join(homedir(), '.codex')).toBe(false);
    expect(home.startsWith(realpathSync(tmpdir()))).toBe(true);
    expect(readdirSync(home)).toEqual([]);
  });

  it('sets no key, token or gateway address, so nothing vetoes a login', () => {
    expect(readCodexAccountEnv().credentialEnv).toBe(false);
    expect(readCodexAccountEnv().gateway).toBe(false);
    expect(codexEnvVetoed()).toBe(false);
  });
});

describe('aka status with no Codex home named', () => {
  let base: string;

  beforeEach(() => {
    base = join(tmpdir(), `aka-codex-guard-${String(process.pid)}-${String(Date.now())}`);
    // Every Claude variable but the config location its own guard moved: one the
    // developer's session exports would change the Claude Code line beside it.
    for (const name of CLAUDE_ACCOUNT_ENV_NAMES) {
      if (name !== 'CLAUDE_CONFIG_DIR') vi.stubEnv(name, '');
    }
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    removeTree(base);
  });

  it('finds no Codex login file', async () => {
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
    expect(out.join('')).toContain('Codex — login file not found\n');
  });
});

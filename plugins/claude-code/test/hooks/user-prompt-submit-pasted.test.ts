import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  createSightingKeyStore,
  keysDir,
  settingsDir as settingsDirOf,
  sightingKeyEndpointFingerprint,
  sightingToken,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { formatCredentialHandle } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { saveCredentialLookups } from '../../src/credentials/pasted.ts';
import { withTempHome } from '../helpers/run-hook.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK_SCRIPT = join(HERE, '..', '..', 'scripts', 'user-prompt-submit.js');
const ENDPOINT = 'http://127.0.0.1:9';
const KEY_BYTES = new Uint8Array(32).fill(7);
const VALUE = `github_pat_${'Q7r2M9w4K1'.repeat(8)}zt`;

function attach(home: string): void {
  const base = join(home, '.aka');
  mkdirSync(join(base, 'data'), { recursive: true });
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: new Date().toISOString() },
    },
    base,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: 'not-a-real-key-pasted',
  });
  createSightingKeyStore('file', keysDir(base)).replace({
    keyVersion: 1,
    algorithm: 'hmac-sha256',
    key: Buffer.from(KEY_BYTES).toString('base64url'),
    fetchedAtMs: Date.now(),
    endpointFingerprint: sightingKeyEndpointFingerprint(ENDPOINT),
  });
  const token = sightingToken({ keyVersion: 1, key: KEY_BYTES }, VALUE);
  saveCredentialLookups(join(base, 'data'), [
    { slug: 'github-demo', description: '', lookups: [token] },
  ]);
}

function everyFileText(dir: string): string {
  let text = '';
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    text += statSync(path).isDirectory() ? everyFileText(path) : readFileSync(path, 'latin1');
  }
  return text;
}

describe('user-prompt-submit with a pasted vaulted credential', () => {
  it('records the prompt with the handle in place of the value', () => {
    withTempHome((home) => {
      attach(home);
      execFileSync(process.execPath, [HOOK_SCRIPT], {
        env: { HOME: home, USERPROFILE: home },
        input: JSON.stringify({
          prompt: `use this token: ${VALUE}`,
          session_id: 'sess-pasted',
          cwd: '/tmp',
          hook_event_name: 'UserPromptSubmit',
        }),
        encoding: 'utf8',
      });
      const stored = everyFileText(join(home, '.aka', 'data'));
      expect(stored).toContain(formatCredentialHandle('github-demo'));
      expect(stored).not.toContain(VALUE);
    });
  });
});

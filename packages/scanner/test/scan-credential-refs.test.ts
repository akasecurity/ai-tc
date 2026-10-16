import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGatewayFactory } from '@akasecurity/plugin-runtime';
import {
  setDefaultGatewayFactory,
  sightingToken,
  standaloneGatewayFactory,
} from '@akasecurity/plugin-runtime';
import type { PluginConfig, RecordProjectEgressInput } from '@akasecurity/plugin-sdk';
import { applyOnboarding, loadConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { encodeIndex } from '../../../test/helpers/git-index.ts';
import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { scanWorktree } from '../src/scan.ts';

// Assembled at runtime so no key-shaped literal or variable read sits in this file.
const INSIDE = ['AK', 'IA'].join('') + ['R7XM', '2QTB', '9KZP', '4HWN'].join('');
const OUTSIDE = ['AK', 'IA'].join('') + ['T4QW', '8NZX', '3LKP', '7VBM'].join('');
const ENV = ['process', 'env'].join('.');
const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const KEY_BYTES = Buffer.alloc(32, 6);
const KEY = { keyVersion: 3, key: new Uint8Array(KEY_BYTES) };
const REMOTE = 'https://github.com/acme/widgets.git';

const SOURCE = [
  `const fallback = '${OUTSIDE}';`,
  `export const charge = () =>`,
  `  fetch('https://api.stripe.com/v1/charges', {`,
  `    headers: { 'X-Literal': '${INSIDE}', 'X-Read': ${ENV}.STRIPE_SECRET_KEY },`,
  `  });`,
  '',
].join('\n');

let home: string;
let repo: string;
let recorded: RecordProjectEgressInput[];
let restoreGateway: () => void;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-scan-refs-home-'));
  repo = mkdtempSync(join(tmpdir(), 'aka-scan-refs-repo-'));
  mkdirSync(join(repo, '.git'));
  writeFileSync(
    join(repo, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${REMOTE}\n`,
  );
  writeFileSync(join(repo, 'charge.ts'), SOURCE);
  writeFileSync(join(repo, '.git', 'index'), encodeIndex(['charge.ts']));
  recorded = [];
  const capturing: DataGatewayFactory = (config, meta) => {
    const inner = standaloneGatewayFactory(config, meta);
    const record = inner.recordProjectEgress.bind(inner);
    inner.recordProjectEgress = (input, context) => {
      recorded.push(input);
      return record(input, context);
    };
    return inner;
  };
  restoreGateway = setDefaultGatewayFactory(capturing);
});

afterEach(() => {
  restoreGateway();
  removeTrees([home, repo]);
});

function attach(consent: boolean): PluginConfig {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: MINTED_AT },
      ...(consent
        ? {
            sightingShareConsent: {
              acknowledgedAt: new Date().toISOString(),
              version: 2,
              endpoint: ENDPOINT,
            },
          }
        : {}),
    },
    home,
    null,
  );
  writeFileSync(
    join(home, 'settings', 'control-plane-credential.json'),
    JSON.stringify({
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: ['test', 'plugin', 'key'].join('-'),
      mintedAt: MINTED_AT,
    }),
    { mode: 0o600 },
  );
  mkdirSync(join(home, 'keys'), { recursive: true });
  writeFileSync(
    join(home, 'keys', 'sighting.key'),
    JSON.stringify({
      keyVersion: 3,
      algorithm: 'hmac-sha256',
      key: KEY_BYTES.toString('base64url'),
      fetchedAtMs: Date.now(),
      endpointFingerprint: createHash('sha256').update(ENDPOINT).digest('hex'),
    }),
    { mode: 0o600 },
  );
  return loadConfig(home);
}

const scan = (config: PluginConfig) =>
  scanWorktree(config, {
    rootDir: repo,
    sourceTool: 'claude-code',
    sendSightings: () => Promise.resolve({ ok: true, accepted: 0 }),
    managedSettings: null,
  });

const chargeHit = () =>
  recorded.flatMap((input) => input.hits).find((hit) => hit.host === 'api.stripe.com');

describe('scanWorktree — credential references', () => {
  it('hands the register the literal inside the call as its token, with the variable', async () => {
    await scan(attach(true));

    expect(chargeHit()?.credentialRefs).toEqual([
      expect.objectContaining({ kind: 'literal', token: sightingToken(KEY, INSIDE) }),
      { kind: 'variable', variableName: 'STRIPE_SECRET_KEY' },
    ]);
    const register = JSON.stringify(recorded);
    expect(register).not.toContain(sightingToken(KEY, OUTSIDE));
    expect(JSON.stringify(chargeHit()?.credentialRefs)).not.toContain(INSIDE);
  });

  it('searches for no credential references while this machine does not share sightings', async () => {
    await scan(attach(false));

    expect(chargeHit()).toBeDefined();
    expect(chargeHit()?.credentialRefs).toBeUndefined();
  });
});

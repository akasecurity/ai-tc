// This plugin's store-health seam. The shared module is tested once, in
// packages/plugin-runtime/test/store-health.test.ts; this suite pins that the
// seam re-exports it rather than a copy, the gateway open this plugin keeps for
// its hook server, and what each hook passes in.
import { randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { writeControlPlaneCredential } from '@akasecurity/persistence';
import * as shared from '@akasecurity/plugin-runtime';
import { governanceApplies } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import * as seam from '../../src/hooks/store-health.ts';
import { openGateway, openGatewayOrNull } from '../../src/hooks/store-health.ts';

function configFor(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 1,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: join(dataDir, 'settings'),
    onboarded: false,
    provider: { provider: 'anthropic' },
  };
}

describe('the store-health seam', () => {
  it.each([
    'claimStoreDegradedWarning',
    'claimStoreUnavailableWarning',
    'isSessionMarked',
    'markSession',
    'storeAheadMessage',
    'storeBusyMessage',
    'storeDegradedMessage',
    'storeOpenCause',
    'storeRedirectedMessage',
    'storeUnavailableMessage',
    'warnIfStoreRedirected',
  ] as const)('re-exports the shared %s', (name) => {
    expect(seam[name]).toBe(shared[name]);
  });
});

describe('the event each hook names on a locked store', () => {
  it.each([
    ['pre-tool-use-run.ts', 'tool call', 'opened.error'],
    ['user-prompt-submit.ts', 'prompt', 'opened.error'],
  ])('%s names a %s', (file: string, subject: string, errorArg: string) => {
    const source = readFileSync(new URL(`../../src/hooks/${file}`, import.meta.url), 'utf8');
    expect(source).toContain(`storeDegradedMessage(config.dbPath, ${errorArg}, '${subject}')`);
    // The claim must see the same error, or a lock falls back to the
    // once-per-session gate.
    expect(source).toMatch(
      new RegExp(
        `claimStoreDegradedWarning\\(config\\.dataDir, [^\\n]+, ${errorArg.replace('.', '\\.')}\\)`,
        'u',
      ),
    );
  });
});

describe('openGatewayOrNull — observable store-open failure', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-health-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns null when aka.db is not a database (corrupt bytes)', () => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'aka.db'), 'garbage bytes, definitely not sqlite');

    expect(openGatewayOrNull(configFor(dir))).toBeNull();
  });

  it('returns a working gateway for a healthy (fresh) data dir', async () => {
    const gateway = openGatewayOrNull(configFor(dir));
    expect(gateway).not.toBeNull();
    await gateway?.close();
  });
});

// Which message the user gets is decided by WHY the open failed, so the reason
// has to survive the open. It used to be swallowed by a bare catch, which made
// a store written by a newer AKA build read exactly like an unreadable one —
// and sent the user to move an intact corpus aside over a stale binary.
describe('openGateway — the reason survives the failure', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-reason-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('carries the failure out instead of collapsing it to null', () => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'aka.db'), 'garbage bytes, definitely not sqlite');

    const opened = openGateway(configFor(dir));

    expect(opened.gateway).toBeNull();
    expect(opened.error).toBeInstanceOf(Error);
  });

  // This plugin's openGateway wraps the shared one for the hook server, so it
  // is not pinned by identity. It must still report a failure exactly as the
  // shared open does, or a fix to the shared classification would skip it.
  it('reports the same failure as the shared openGateway', () => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'aka.db'), 'garbage bytes, definitely not sqlite');

    const local = openGateway(configFor(dir));
    const reference = shared.openGateway(configFor(dir));

    expect(local.gateway).toBeNull();
    expect(reference.gateway).toBeNull();
    expect(shared.storeOpenCause(local.error)).toEqual(shared.storeOpenCause(reference.error));
    expect(shared.storeOpenCause(local.error)?.text).toMatch(/^SQLite error 26/u);
    expect(shared.storeDegradedMessage('/x/aka.db', local.error, 'tool call')).toBe(
      shared.storeDegradedMessage('/x/aka.db', reference.error, 'tool call'),
    );
  });

  it('reports no error at all when the store opens', async () => {
    const opened = openGateway(configFor(dir));

    expect(opened.gateway).not.toBeNull();
    expect(opened.error).toBeUndefined();
    await opened.gateway?.close();
  });
});

// The hop between the runtime's door and the model-guard sites. Each site asks
// governanceApplies of the gateway openGateway hands it, so a wrapper here that
// kept only the port's members would hide the attached gateway's answer, and a
// scoped machine would be governed in every repository again. A real scoped
// credential, real settings and the real factory: the client is built and never
// called, so nothing is sent.
describe('openGateway — a scoped attachment keeps its governance answer', () => {
  const ENDPOINT = 'https://plane.example.test';
  const AT = '2026-10-08T09:00:00.000Z';
  const WORK = 'github.com/acme/payments-api';
  const PERSONAL = 'github.com/someone/side-project';
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-store-scoped-'));
  });
  afterEach(() => {
    removeTree(home);
  });

  function scopedConfig(): PluginConfig {
    const config = configFor(home);
    writeControlPlaneCredential(config.settingsDir, {
      specVersion: 2,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: randomUUID(),
      mintedAt: AT,
    });
    return {
      ...config,
      settings: {
        ...config.settings,
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
        attachmentScope: {
          endpoint: ENDPOINT,
          entries: [{ kind: 'repo', identity: WORK, enrolledAt: AT }],
        },
      },
    };
  }

  it('hands the sites a gateway that governs an enrolled repository and no other', async () => {
    const opened = openGateway(scopedConfig());
    expect(opened.error).toBeUndefined();
    const { gateway } = opened;
    if (gateway === null) throw new Error('the store did not open');
    try {
      expect(governanceApplies(gateway, WORK)).toBe(true);
      expect(governanceApplies(gateway, PERSONAL)).toBe(false);
    } finally {
      await gateway.close();
    }
  });
});

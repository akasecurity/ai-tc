import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { renderAttachedStatus } from '../../src/attached/status.ts';

// `aka status` on a machine whose credential file really is a scoped (v2) one,
// read by the real reader. A build that predates scoped attachments printed
// "no usable credential, re-attach" for this file — and a re-attach from that
// build writes a v1 credential, which is a machine-wide attachment. Reading it
// as usable is what keeps this surface from recommending that downgrade.

const ENDPOINT = 'https://aka.acme.test';
const TEST_KEY = 'not-a-real-key';

let root: string;
let settingsDir: string;
let dataDir: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-status-scoped-'));
  settingsDir = settingsDirOf(root);
  dataDir = dataDirOf(root);
  mkdirSync(settingsDir, { recursive: true });
  mkdirSync(dataDir, { recursive: true });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('renderAttachedStatus — a scoped (specVersion 2) credential', () => {
  it('renders it as attached, not as a credential to replace', () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: '2026-10-01T09:00:00.000Z' },
      },
      root,
      // No managed overlay: an administrator's file on the machine running
      // this suite must not decide what it sees.
      null,
    );
    writeControlPlaneCredential(settingsDir, {
      specVersion: 2,
      mode: 'scoped',
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      keyPrefix: 'akp_scoped',
    });

    const out = renderAttachedStatus({ base: root, settingsDir, dataDir });

    expect(out.split('\n')[0]).toBe('AKA: attached');
    expect(out).not.toContain('no usable credential');
    expect(out).toMatch(/key\s+akp_scoped…/);
    expect(out).not.toContain(TEST_KEY);
  });
});

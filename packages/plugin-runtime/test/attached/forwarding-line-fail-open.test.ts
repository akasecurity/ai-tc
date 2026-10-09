import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { writeControlPlaneCredential } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type * as SchemaModule from '@akasecurity/schema';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { forwardingLine } from '../../src/attached/forwarding-line.ts';

// The forwarding line is computed inside handleSessionStart's own try, after the
// stale-session check's inputs are in hand. A throw out of it would cost the
// session both notices, so it answers null instead, the same answer a machine
// that forwards nothing gets. A deployment label is what drives the fault here:
// naming it is the one step past resolving the attachment, and the real
// functions on that step have nothing in valid data that throws.
const EXPLODING_LABEL = 'explode-on-naming';

vi.mock('@akasecurity/schema', async (importOriginal) => {
  const actual = await importOriginal<typeof SchemaModule>();
  return {
    ...actual,
    controlPlaneName: (connection: Parameters<typeof actual.controlPlaneName>[0]) => {
      if (connection.label === EXPLODING_LABEL) throw new Error('naming failed');
      return actual.controlPlaneName(connection);
    },
  };
});

const ENDPOINT = 'https://plane.example.test';
const AT = '2026-10-01T00:00:00.000Z';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-forwarding-line-'));
  writeControlPlaneCredential(dir, {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: 'placeholder',
    mintedAt: AT,
  });
});

afterEach(() => {
  removeTree(dir);
});

function configLabelled(label: string): PluginConfig {
  return {
    settings: {
      ...defaultWorkspaceSettings(),
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, label, attachedAt: AT },
    },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

describe('forwardingLine fails open', () => {
  it('answers null when naming the deployment throws', () => {
    expect(forwardingLine(configLabelled(EXPLODING_LABEL), undefined)).toBeNull();
  });

  it('names the deployment when it does not', () => {
    // The control: the same attachment under another label reaches the line,
    // so the null above is the fault's doing.
    expect(forwardingLine(configLabelled('Acme'), undefined)).toBe(
      'AKA: forwarding everything to Acme (machine-wide)',
    );
  });
});

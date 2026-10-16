// The onboarding writer's credential-sightings flags, run in-process so
// coverage sees the source the built script is bundled from. The script does
// its work at module load, so the module registry is reset before every import,
// `process.exit` throws to stop it where the script would, and `os.homedir()`
// points at a throwaway home per case.
import { mkdtempSync, readFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  isSightingShareConsentValid,
  SIGHTING_SHARE_PAYLOAD_NOTE,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { readFrameJsonBlock } from '../src/setup-frame-json.ts';

const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return {
    ...actual,
    homedir: () => {
      if (osHome.dir === '') throw new Error('no home directory');
      return osHome.dir;
    },
  };
});

const ENDPOINT = 'https://cp.example';

class Exit extends Error {
  constructor(readonly code: number) {
    super(`exit ${String(code)}`);
  }
}

beforeEach(() => {
  osHome.dir = mkdtempSync(join(tmpdir(), 'aka-claude-code-sighting-'));
});

afterEach(() => {
  vi.restoreAllMocks();
  removeTree(osHome.dir);
  osHome.dir = '';
});

async function onboard(args: string[]): Promise<{ stdout: string; code: number }> {
  vi.resetModules();
  const argv = process.argv;
  process.argv = [process.execPath, 'onboard.js', ...args];
  let stdout = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stdout += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
    return true;
  });
  vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Exit(code ?? 0);
  }) as typeof process.exit);
  try {
    await import('../src/onboard.ts');
    return { stdout, code: 0 };
  } catch (err) {
    if (err instanceof Exit) return { stdout, code: err.code };
    throw err;
  } finally {
    process.argv = argv;
    vi.restoreAllMocks();
  }
}

const base = (): string => join(osHome.dir, '.aka');
const settingsFile = (): string => join(base(), 'settings', 'settings.json');

function attach(): void {
  const attachedAt = '2026-10-01T00:00:00.000Z';
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt } },
    base(),
    null,
  );
  writeControlPlaneCredential(settingsDir(base()), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: ['test', 'only'].join('-'),
    mintedAt: attachedAt,
  });
}

describe('onboard credential-sightings flags', () => {
  it('--sighting-share-ask says not to ask while standalone, and writes nothing', async () => {
    const result = await onboard(['--sighting-share-ask']);
    expect(result.code).toBe(0);
    expect(readFrameJsonBlock(result.stdout)).toEqual({ askSightingShare: false });
    expect(() => readFileSync(settingsFile(), 'utf8')).toThrow();
  });

  it('--sighting-share-ask says to ask once attached', async () => {
    attach();
    const result = await onboard(['--sighting-share-ask']);
    expect(readFrameJsonBlock(result.stdout)).toEqual({ askSightingShare: true });
  });

  it('grant records a grant for the attached deployment, and revoke removes it', async () => {
    attach();
    const granted = await onboard(['--sighting-share-consent', 'grant']);
    expect(granted.code).toBe(0);
    expect(granted.stdout).toContain('Credential sightings: on (attached, scoped)');
    expect(granted.stdout).toContain(SIGHTING_SHARE_PAYLOAD_NOTE);
    const settings = WorkspaceSettings.parse(JSON.parse(readFileSync(settingsFile(), 'utf8')));
    expect(isSightingShareConsentValid(settings.sightingShareConsent, ENDPOINT)).toBe(true);
    const revoked = await onboard(['--sighting-share-consent', 'revoke']);
    expect(revoked.code).toBe(0);
    expect(revoked.stdout).toContain('Credential sightings: off (attached, scoped)');
    expect(readFileSync(settingsFile(), 'utf8')).not.toContain('sightingShareConsent');
  });

  it('refuses a grant while standalone and writes nothing', async () => {
    const result = await onboard(['--sighting-share-consent', 'grant']);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain('not attached to an organization');
    expect(() => readFileSync(settingsFile(), 'utf8')).toThrow();
  });

  it('refuses any other value', async () => {
    const result = await onboard(['--sighting-share-consent', 'maybe']);
    expect(result.code).toBe(1);
    expect(result.stdout).toContain('invalid --sighting-share-consent "maybe"');
  });
});

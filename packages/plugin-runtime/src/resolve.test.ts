import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import type { RunMode } from '@akasecurity/schema';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveDataGateway } from './resolve.ts';
import { StandaloneDataGateway } from './standalone-gateway.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-resolve-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function makeConfig(runMode: RunMode): PluginConfig {
  return {
    settings: { ...defaultWorkspaceSettings(), runMode },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

describe('resolveDataGateway', () => {
  it('returns the standalone gateway in standalone mode', async () => {
    const gw = resolveDataGateway(makeConfig('standalone'));
    expect(gw).toBeInstanceOf(StandaloneDataGateway);
    await gw.close();
  });

  it('delegates to an injected gateway factory (the extension seam)', async () => {
    const injected = new StandaloneDataGateway(dir, []);
    let sawConfig: PluginConfig | undefined;
    const gw = resolveDataGateway(
      makeConfig('standalone'),
      { recordedBy: 'plugin@test' },
      (config): DataGateway => {
        sawConfig = config;
        return injected;
      },
    );
    expect(gw).toBe(injected);
    expect(sawConfig?.dataDir).toBe(dir);
    await gw.close();
  });
});

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import type { RunMode } from '@akasecurity/schema';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  resolveDataGateway,
  setDefaultGatewayFactory,
  standaloneGatewayFactory,
} from '../src/resolve.ts';
import { StandaloneDataGateway } from '../src/standalone-gateway.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-resolve-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  // The seam is process-global: a test that leaves it set would leak into the
  // next one.
  setDefaultGatewayFactory();
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

  const stub = { close: (): Promise<void> => Promise.resolve() } as unknown as DataGateway;

  it('setDefaultGatewayFactory replaces the factory used when none is passed', () => {
    setDefaultGatewayFactory(() => stub);
    expect(resolveDataGateway(makeConfig('standalone'))).toBe(stub);
  });

  it('an explicit factory argument still wins over the default', () => {
    const other = { close: (): Promise<void> => Promise.resolve() } as unknown as DataGateway;
    setDefaultGatewayFactory(() => stub);
    expect(resolveDataGateway(makeConfig('standalone'), undefined, () => other)).toBe(other);
  });

  it('reads the default on every call, not once at import', () => {
    // The first resolve happens BEFORE the setter — this is the property the
    // composition root depends on, and a captured default would break it.
    const first = resolveDataGateway(makeConfig('standalone'), undefined, () => stub);
    expect(first).toBe(stub);
    setDefaultGatewayFactory(() => stub);
    expect(resolveDataGateway(makeConfig('standalone'))).toBe(stub);
  });

  it('setDefaultGatewayFactory() with no argument restores the standalone default', async () => {
    setDefaultGatewayFactory(() => stub);
    setDefaultGatewayFactory();
    const gw = resolveDataGateway(makeConfig('standalone'));
    expect(gw).toBeInstanceOf(StandaloneDataGateway);
    await gw.close();
  });

  it('exports the standalone factory so a substitute can fall back to it', async () => {
    const gw = standaloneGatewayFactory(makeConfig('standalone'));
    expect(gw).toBeInstanceOf(StandaloneDataGateway);
    await gw.close();
  });
});

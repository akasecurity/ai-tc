import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import type { RunMode } from '@akasecurity/schema';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
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
  removeTree(dir);
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

  it('reads the default on every call, not once at import', async () => {
    // The first resolve passes no factory argument, so it reads whatever the
    // default is at that moment — still the standalone default here, since no
    // setter has run yet.
    const first = resolveDataGateway(makeConfig('standalone'));
    expect(first).toBeInstanceOf(StandaloneDataGateway);
    await first.close();
    // Setting the default now changes what the NEXT no-argument call sees.
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

  it('the returned thunk restores the PREVIOUS factory, not the standalone default', () => {
    // Two registrants: an embedder at process start, then a test substituting
    // over it. Unwinding with `setDefaultGatewayFactory()` would reset to
    // standalone and silently discard the embedder's registration — and the
    // embedder ran before any resolving code, so it has no call site left to
    // notice from. The thunk puts the embedder back.
    const embedder = { close: (): Promise<void> => Promise.resolve() } as unknown as DataGateway;
    setDefaultGatewayFactory(() => embedder);

    const restore = setDefaultGatewayFactory(() => stub);
    expect(resolveDataGateway(makeConfig('standalone'))).toBe(stub);

    restore();
    expect(resolveDataGateway(makeConfig('standalone'))).toBe(embedder);
  });

  it('nested substitutions unwind exactly, innermost first', () => {
    const outer = { close: (): Promise<void> => Promise.resolve() } as unknown as DataGateway;
    const inner = { close: (): Promise<void> => Promise.resolve() } as unknown as DataGateway;

    const restoreOuter = setDefaultGatewayFactory(() => outer);
    const restoreInner = setDefaultGatewayFactory(() => inner);
    expect(resolveDataGateway(makeConfig('standalone'))).toBe(inner);

    restoreInner();
    expect(resolveDataGateway(makeConfig('standalone'))).toBe(outer);

    restoreOuter();
    const gw = resolveDataGateway(makeConfig('standalone'));
    expect(gw).toBeInstanceOf(StandaloneDataGateway);
    return gw.close();
  });

  it("the no-argument form's own thunk restores what IT replaced", async () => {
    // The reset is still a substitution like any other, so a teardown that
    // resets can itself be unwound.
    setDefaultGatewayFactory(() => stub);
    const restore = setDefaultGatewayFactory();
    const reset = resolveDataGateway(makeConfig('standalone'));
    expect(reset).toBeInstanceOf(StandaloneDataGateway);
    await reset.close();

    restore();
    expect(resolveDataGateway(makeConfig('standalone'))).toBe(stub);
  });

  it('exports the standalone factory so a substitute can fall back to it', async () => {
    const gw = standaloneGatewayFactory(makeConfig('standalone'));
    expect(gw).toBeInstanceOf(StandaloneDataGateway);
    await gw.close();
  });
});

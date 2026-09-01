import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { readSessionModel, recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { refuseProhibitedTurn } from '../../src/hooks/model-guard.ts';
import { runPostModelSwitch, runPreModelSwitch } from '../../src/hooks/model-switch-run.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-switch-run-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const config = (): PluginConfig => ({ dataDir: dir }) as unknown as PluginConfig;

/** A gateway stubbed down to the one read these paths perform. */
function gatewayWith(prohibited: string[] | undefined, onClose = vi.fn()): DataGateway {
  return {
    getPolicyBundle: () =>
      Promise.resolve({ prohibitedModels: prohibited } as unknown as Awaited<
        ReturnType<DataGateway['getPolicyBundle']>
      >),
    close: onClose,
  } as unknown as DataGateway;
}

describe('runPreModelSwitch', () => {
  it('refuses the switch and records NOTHING when the target is prohibited', () => {
    // A refused switch never happened, so recording its target would make the
    // next turn enforce against a model the session is not running.
    const emit = vi.fn(() => Promise.resolve());
    return runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5']),
      emit,
      warnIfStoreRedirected: vi.fn(),
    }).then((refused) => {
      expect(refused).toBe(true);
      expect(emit).toHaveBeenCalledTimes(1);
      expect(readSessionModel(dir, 's1')).toBeUndefined();
    });
  });

  it('allows an approved switch, emits nothing, and records the new model', async () => {
    const emit = vi.fn(() => Promise.resolve());
    const refused = await runPreModelSwitch({}, 'claude-sonnet-4-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5']),
      emit,
      warnIfStoreRedirected: vi.fn(),
    });
    expect(refused).toBe(false);
    expect(emit).not.toHaveBeenCalled();
    expect(readSessionModel(dir, 's1')).toBe('claude-sonnet-4-5');
  });

  it('allows — silently — when the store cannot be opened', async () => {
    // Fail-open: no store means no bundle means no prohibition to enforce, and
    // this hook deliberately does not explain store health.
    const emit = vi.fn(() => Promise.resolve());
    const refused = await runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () => null,
      emit,
      warnIfStoreRedirected: vi.fn(),
    });
    expect(refused).toBe(false);
    expect(emit).not.toHaveBeenCalled();
  });

  it('closes the gateway on both the refusal and the allow path', async () => {
    for (const [target, label] of [
      ['claude-opus-5', 'refusal'],
      ['claude-sonnet-4-5', 'allow'],
    ] as const) {
      const close = vi.fn(() => Promise.resolve());
      await runPreModelSwitch({}, target, 's1', {
        config: config(),
        openGateway: () => gatewayWith(['claude-opus-5'], close),
        emit: vi.fn(() => Promise.resolve()),
        warnIfStoreRedirected: vi.fn(),
      });
      expect(close, `gateway left open on the ${label} path`).toHaveBeenCalledTimes(1);
    }
  });

  it('surfaces a redirected home before deciding', async () => {
    const warn = vi.fn();
    await runPreModelSwitch({}, 'claude-opus-5', 's1', {
      config: config(),
      openGateway: () => gatewayWith([]),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: warn,
    });
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('runPostModelSwitch', () => {
  it('records the model the harness switched to', () => {
    runPostModelSwitch('s1', 'claude-opus-5', {
      config: config(),
      warnIfStoreRedirected: vi.fn(),
    });
    expect(readSessionModel(dir, 's1')).toBe('claude-opus-5');
  });

  it('records nothing when the harness named no model', () => {
    runPostModelSwitch('s1', undefined, { config: config(), warnIfStoreRedirected: vi.fn() });
    expect(readSessionModel(dir, 's1')).toBeUndefined();
  });
});

describe('refuseProhibitedTurn', () => {
  it('refuses a turn on a model the marker says is prohibited', async () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const out = await refuseProhibitedTurn(gatewayWith(['claude-opus-5']), dir, 's1', undefined);
    expect(out?.decision).toBe('block');
    expect(out?.reason).toContain('claude-opus-5');
  });

  it('falls back to the transcript when no marker covers the session', async () => {
    const transcript = join(dir, 't.jsonl');
    writeFileSync(
      transcript,
      JSON.stringify({ type: 'assistant', message: { model: 'claude-opus-5' } }),
    );
    expect(
      await refuseProhibitedTurn(gatewayWith(['claude-opus-5']), dir, 's1', transcript),
    ).not.toBeNull();
  });

  it('never reads the transcript when the bundle prohibits nothing', async () => {
    // The ordering that keeps an unenforced tenant off the transcript entirely:
    // a bundle with no list short-circuits before the model is resolved.
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(await refuseProhibitedTurn(gatewayWith([]), dir, 's1', undefined)).toBeNull();
    expect(await refuseProhibitedTurn(gatewayWith(undefined), dir, 's1', undefined)).toBeNull();
  });

  it('allows when the bundle cannot be read at all', async () => {
    const broken = {
      getPolicyBundle: () => Promise.reject(new Error('store gone')),
    } as unknown as DataGateway;
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(await refuseProhibitedTurn(broken, dir, 's1', undefined)).toBeNull();
  });

  it('allows when the model cannot be resolved from either source', async () => {
    expect(
      await refuseProhibitedTurn(gatewayWith(['claude-opus-5']), dir, 's1', undefined),
    ).toBeNull();
  });
});

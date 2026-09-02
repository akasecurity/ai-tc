import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { handleProhibitedTurn, resolveCodexSessionModel } from '../../src/hooks/model-guard.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-codex-model-guard-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** One Codex rollout line naming the turn's model. */
function turnContext(model: string): string {
  return JSON.stringify({ type: 'turn_context', payload: { model } });
}

describe('resolveCodexSessionModel', () => {
  it('prefers the marker the Stop hook recorded', () => {
    const rollout = join(dir, 'r.jsonl');
    writeFileSync(rollout, turnContext('gpt-4o'));
    recordSessionModel(dir, 's1', 'o3');
    expect(resolveCodexSessionModel(dir, 's1', rollout)).toBe('o3');
  });

  it('falls back to the rollout when no marker covers this session', () => {
    const rollout = join(dir, 'r.jsonl');
    writeFileSync(rollout, turnContext('gpt-4o'));
    recordSessionModel(dir, 'other-session', 'o3');
    expect(resolveCodexSessionModel(dir, 's1', rollout)).toBe('gpt-4o');
  });

  it('returns undefined on the first turn, before either source can speak', () => {
    // The known hole on this host, pinned rather than glossed: Codex has no
    // model-switch event and no SessionStart model, so nothing knows the model
    // until a turn has completed. That first turn is allowed.
    expect(resolveCodexSessionModel(dir, 's1', join(dir, 'missing.jsonl'))).toBeUndefined();
  });
});

describe('handleProhibitedTurn', () => {
  /** A gateway stubbed to the one read this path performs. */
  function gatewayWith(prohibited: string[] | undefined, onClose = vi.fn()) {
    return {
      getPolicyBundle: () => Promise.resolve({ prohibitedModels: prohibited }),
      close: onClose,
    } as unknown as Parameters<typeof handleProhibitedTurn>[0];
  }

  it('closes the gateway and emits the block, then tells the caller to stop', async () => {
    recordSessionModel(dir, 's1', 'o3');
    const close = vi.fn(() => Promise.resolve());
    const emitted: { decision: 'block'; reason: string }[] = [];
    const stop = await handleProhibitedTurn(
      gatewayWith(['o3'], close),
      dir,
      's1',
      undefined,
      (o) => {
        emitted.push(o);
        return Promise.resolve();
      },
    );
    expect(stop).toBe(true);
    expect(close).toHaveBeenCalledTimes(1);
    expect(emitted[0]?.reason).toContain('o3');
  });

  it('leaves the gateway OPEN and emits nothing when the turn is allowed', async () => {
    // The caller builds a runtime over this same gateway and closes it in its
    // own `finally`; closing here would pull it out from under the scan.
    const close = vi.fn(() => Promise.resolve());
    const emitted: unknown[] = [];
    const stop = await handleProhibitedTurn(gatewayWith([], close), dir, 's1', undefined, (o) => {
      emitted.push(o);
      return Promise.resolve();
    });
    expect(stop).toBe(false);
    expect(close).not.toHaveBeenCalled();
    expect(emitted).toHaveLength(0);
  });

  it('allows when the bundle cannot be read at all', async () => {
    recordSessionModel(dir, 's1', 'o3');
    const broken = {
      getPolicyBundle: () => Promise.reject(new Error('store gone')),
      close: vi.fn(),
    } as unknown as Parameters<typeof handleProhibitedTurn>[0];
    expect(await handleProhibitedTurn(broken, dir, 's1', undefined, () => Promise.resolve())).toBe(
      false,
    );
  });

  it('never resolves the model when the bundle prohibits nothing', async () => {
    // Ordering that keeps an unenforced tenant off the transcript entirely.
    recordSessionModel(dir, 's1', 'o3');
    expect(
      await handleProhibitedTurn(gatewayWith(undefined), dir, 's1', undefined, () =>
        Promise.resolve(),
      ),
    ).toBe(false);
  });
});

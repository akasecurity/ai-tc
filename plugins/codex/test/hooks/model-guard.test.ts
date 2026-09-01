import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveCodexSessionModel } from '../../src/hooks/model-guard.ts';

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

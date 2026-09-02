import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  decidePreModelSwitch,
  decideSubagentSpawn,
  handleSubagentSpawn,
  resolveSessionModel,
} from '../../src/hooks/model-guard.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-model-guard-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('decidePreModelSwitch', () => {
  it('denies a switch onto a prohibited model, in PreModelSwitch vocabulary', () => {
    // The shape is the substantive claim, not the denial: PreToolUse's
    // `hookSpecificOutput` is structurally identical apart from
    // `hookEventName`, and the host honors only the one naming its own event —
    // so a borrowed shape emits valid JSON and silently allows.
    const output = decidePreModelSwitch('claude-opus-5', ['claude-opus-5']);
    expect(output?.hookSpecificOutput.hookEventName).toBe('PreModelSwitch');
    expect(output?.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(output?.hookSpecificOutput.permissionDecisionReason).toContain('claude-opus-5');
  });

  it('denies a dated build of a prohibited base model', () => {
    expect(decidePreModelSwitch('claude-haiku-4-5-20251001', ['claude-haiku-4-5'])).not.toBeNull();
  });

  it.each([
    ['an approved model', 'claude-sonnet-4-5', ['claude-opus-5']],
    ['no target model', undefined, ['claude-opus-5']],
    ['no prohibition list', 'claude-opus-5', undefined],
    ['an empty prohibition list', 'claude-opus-5', []],
  ])('has no opinion on %s', (_label, model, prohibited) => {
    expect(decidePreModelSwitch(model, prohibited)).toBeNull();
  });
});

describe('resolveSessionModel', () => {
  it('prefers the recorded marker over the transcript', () => {
    // The marker is written by the model-switch hooks at the moment the model
    // changes, so it is newer than anything the transcript can show.
    const transcript = join(dir, 't.jsonl');
    writeFileSync(
      transcript,
      JSON.stringify({ type: 'assistant', message: { model: 'claude-haiku-4-5' } }),
    );
    recordSessionModel(dir, 's1', 'claude-opus-5');
    expect(resolveSessionModel(dir, 's1', transcript)).toBe('claude-opus-5');
  });

  it('falls back to the transcript when no marker covers this session', () => {
    const transcript = join(dir, 't.jsonl');
    writeFileSync(
      transcript,
      JSON.stringify({ type: 'assistant', message: { model: 'claude-haiku-4-5' } }),
    );
    recordSessionModel(dir, 'other-session', 'claude-opus-5');
    expect(resolveSessionModel(dir, 's1', transcript)).toBe('claude-haiku-4-5');
  });

  it('returns undefined when neither source can answer', () => {
    // The known hole, pinned rather than glossed: the first turn of a session
    // that started on a prohibited model without SessionStart announcing it has
    // no marker and no assistant record, and is therefore ALLOWED.
    expect(resolveSessionModel(dir, 's1', join(dir, 'missing.jsonl'))).toBeUndefined();
  });
});

// The spawn seam. Neither seam above can reach a subagent: a subagent turn is
// not a user prompt and not a switch, and both of those resolve the PARENT's
// model — which is exactly the model a spawn overrides. So without this a
// session on an approved model runs unbounded work on a prohibited one.
describe('decideSubagentSpawn', () => {
  const PROHIBITED = ['claude-sonnet-5'];

  it('denies a spawn onto a prohibited model, in PreToolUse vocabulary', () => {
    // The shape is the substantive claim, as it is for the switch seam above:
    // PreModelSwitch's output is structurally identical apart from
    // `hookEventName`, and the host honors only the one naming its own event.
    const out = decideSubagentSpawn('Agent', { model: 'claude-sonnet-5' }, PROHIBITED);
    expect(out?.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(out?.hookSpecificOutput.permissionDecision).toBe('deny');
  });

  it('denies the tier word an Agent call actually carries', () => {
    // The live spelling. Matching only ids leaves the seam blind to the single
    // value the harness ever sends here.
    const out = decideSubagentSpawn('Agent', { model: 'sonnet' }, PROHIBITED);
    expect(out?.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out?.hookSpecificOutput.permissionDecisionReason).toContain('subagent');
  });

  it('denies under the older Task spelling too', () => {
    expect(decideSubagentSpawn('Task', { model: 'sonnet' }, PROHIBITED)).not.toBeNull();
  });

  it.each([
    ['a spawn that names no model — it inherits the vetted parent', 'Agent', {}],
    ['an explicit inherit', 'Agent', { model: 'inherit' }],
    ['a non-string model', 'Agent', { model: 5 }],
    ['an allowed tier', 'Agent', { model: 'opus' }],
    ['a tool that is not a spawn', 'Bash', { model: 'sonnet' }],
  ])('has no opinion on %s', (_label, tool, input) => {
    expect(decideSubagentSpawn(tool, input as Record<string, unknown>, PROHIBITED)).toBeNull();
  });

  it('has no opinion when nothing is prohibited', () => {
    expect(decideSubagentSpawn('Agent', { model: 'sonnet' }, undefined)).toBeNull();
    expect(decideSubagentSpawn('Agent', { model: 'sonnet' }, [])).toBeNull();
  });
});

describe('handleSubagentSpawn', () => {
  function gatewayWith(prohibited: string[] | undefined) {
    const recorded: unknown[] = [];
    let closed = false;
    return {
      recorded,
      wasClosed: () => closed,
      gateway: {
        getPolicyBundle: () => Promise.resolve({ prohibitedModels: prohibited }),
        recordAuditEvent: (e: unknown) => {
          recorded.push(e);
          return Promise.resolve();
        },
        close: () => {
          closed = true;
          return Promise.resolve();
        },
      },
    };
  }

  it('refuses, records the refusal, and closes the gateway', async () => {
    const g = gatewayWith(['claude-sonnet-5']);
    const emitted: unknown[] = [];
    const stop = await handleSubagentSpawn(
      () => g.gateway as never,
      'Agent',
      { model: 'sonnet' },
      's1',
      async (o) => {
        emitted.push(o);
        await Promise.resolve();
      },
    );

    expect(stop).toBe(true);
    expect(emitted).toHaveLength(1);
    expect(g.wasClosed()).toBe(true);
    // The audit row is what lets an operator tell enforcement from silence, and
    // it carries the seam so a spawn refusal is distinguishable from a switch.
    expect(g.recorded).toHaveLength(1);
    expect((g.recorded[0] as { attributes: Record<string, unknown> }).attributes).toMatchObject({
      model: 'sonnet',
      refusal_seam: 'spawn',
    });
  });

  it('opens NOTHING for a call that is not a spawn naming a model', async () => {
    // The cost argument for putting this ahead of the scan: every Bash, Edit
    // and MCP leaf crosses this line too, and must not pay a store open.
    let opened = 0;
    const stop = await handleSubagentSpawn(
      () => {
        opened += 1;
        return null;
      },
      'Bash',
      { command: 'ls' },
      's1',
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
    expect(opened).toBe(0);
  });

  it('allows and closes when the model is not prohibited', async () => {
    const g = gatewayWith(['claude-opus-5']);
    const stop = await handleSubagentSpawn(
      () => g.gateway as never,
      'Agent',
      { model: 'sonnet' },
      's1',
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
    expect(g.wasClosed(), 'no leaked handle on the allow path').toBe(true);
  });

  it('fails OPEN when the store cannot be opened', async () => {
    const stop = await handleSubagentSpawn(
      () => null,
      'Agent',
      { model: 'sonnet' },
      's1',
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
  });

  it('fails OPEN when the bundle will not load', async () => {
    const stop = await handleSubagentSpawn(
      () =>
        ({
          getPolicyBundle: () => Promise.reject(new Error('nope')),
          close: () => Promise.resolve(),
        }) as never,
      'Agent',
      { model: 'sonnet' },
      's1',
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
  });

  it('still refuses when the refusal cannot be recorded', async () => {
    // A refusal that cannot be written down is still a refusal — the one way an
    // audit trail could leave a session LESS governed than before it existed.
    const emitted: unknown[] = [];
    const stop = await handleSubagentSpawn(
      () =>
        ({
          getPolicyBundle: () => Promise.resolve({ prohibitedModels: ['claude-sonnet-5'] }),
          recordAuditEvent: () => Promise.reject(new Error('store full')),
          close: () => Promise.resolve(),
        }) as never,
      'Agent',
      { model: 'sonnet' },
      's1',
      async (o) => {
        emitted.push(o);
        await Promise.resolve();
      },
    );
    expect(stop).toBe(true);
    expect(emitted).toHaveLength(1);
  });
});

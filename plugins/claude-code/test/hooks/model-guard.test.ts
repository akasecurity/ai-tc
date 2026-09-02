import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  decidePreModelSwitch,
  decideSubagentSpawn,
  handleSubagentSpawn,
  resolveSessionModel,
  resolveSpawnModel,
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
// The spawn seam. Neither seam above can reach a subagent: a subagent turn is
// not a user prompt and not a switch, and both resolve the PARENT's model —
// which is exactly the model a spawn overrides.
describe('resolveSpawnModel', () => {
  function writeAgent(root: string, name: string, body: string): void {
    mkdirSync(join(root, '.claude', 'agents'), { recursive: true });
    writeFileSync(join(root, '.claude', 'agents', `${name}.md`), body, 'utf8');
  }

  it('prefers an explicit model argument', () => {
    writeAgent(dir, 'helper', '---\nmodel: haiku\n---\nbody');
    expect(resolveSpawnModel({ model: 'opus', subagent_type: 'helper' }, dir)).toBe('opus');
  });

  it("falls back to the agent definition's frontmatter", () => {
    // The bypass this closes. An absent `model` argument does NOT mean the
    // spawn inherits the vetted parent — the harness resolves the agent
    // definition first, and that definition is an ordinary writable repo file.
    writeAgent(dir, 'helper', '---\nname: helper\nmodel: haiku\n---\nbody');
    expect(resolveSpawnModel({ subagent_type: 'helper' }, dir)).toBe('haiku');
  });

  it('returns undefined when nothing names a model — the genuine inherit', () => {
    writeAgent(dir, 'helper', '---\nname: helper\n---\nbody');
    expect(resolveSpawnModel({ subagent_type: 'helper' }, dir)).toBeUndefined();
    expect(resolveSpawnModel({}, dir)).toBeUndefined();
  });

  it('refuses a subagent_type that is not a plain name', () => {
    // Caller-chosen and joined into a path: unchecked it addresses any file on
    // disk, from a hook running inside the user's own checkout.
    writeAgent(dir, 'helper', '---\nmodel: haiku\n---\nbody');
    expect(resolveSpawnModel({ subagent_type: '../agents/helper' }, dir)).toBeUndefined();
    expect(resolveSpawnModel({ subagent_type: '/etc/passwd' }, dir)).toBeUndefined();
  });

  it('says nothing when the definition is absent or unreadable', () => {
    expect(resolveSpawnModel({ subagent_type: 'missing' }, dir)).toBeUndefined();
    expect(resolveSpawnModel({ subagent_type: 'helper' }, undefined)).toBeUndefined();
  });
});

describe('decideSubagentSpawn', () => {
  const PROHIBITED = ['claude-opus-5'];

  it('denies in PreToolUse vocabulary and returns the matched id', () => {
    // The shape is the substantive claim: PreModelSwitch's output is
    // structurally identical apart from `hookEventName`, and the host honors
    // only the one naming its own event.
    const out = decideSubagentSpawn('opus', PROHIBITED);
    expect(out?.output.hookSpecificOutput.hookEventName).toBe('PreToolUse');
    expect(out?.output.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(out?.matched, 'the id the prohibition was keyed on').toBe('claude-opus-5');
    expect(out?.output.hookSpecificOutput.permissionDecisionReason).toContain('subagent');
  });

  it.each([
    ['no model at all', undefined],
    ['an allowed tier', 'sonnet'],
    ['an unrelated id', 'claude-sonnet-5'],
  ])('has no opinion on %s', (_label, requested) => {
    expect(decideSubagentSpawn(requested, PROHIBITED)).toBeNull();
  });

  it('has no opinion when nothing is prohibited', () => {
    expect(decideSubagentSpawn('opus', undefined)).toBeNull();
    expect(decideSubagentSpawn('opus', [])).toBeNull();
  });
});

describe('handleSubagentSpawn', () => {
  function gatewayWith(prohibited: string[] | undefined, onClose?: () => void) {
    const recorded: unknown[] = [];
    const order: string[] = [];
    return {
      recorded,
      order,
      gateway: {
        getPolicyBundle: () => Promise.resolve({ prohibitedModels: prohibited }),
        recordAuditEvent: (e: unknown) => {
          recorded.push(e);
          return Promise.resolve();
        },
        close: () => {
          order.push('close');
          onClose?.();
          return Promise.resolve();
        },
      },
    };
  }

  it('refuses, and records the MATCHED id with the caller spelling beside it', async () => {
    const g = gatewayWith(['claude-opus-5']);
    const emitted: unknown[] = [];
    const stop = await handleSubagentSpawn(
      () => g.gateway as never,
      'Agent',
      { model: 'opus' },
      's1',
      dir,
      async (o) => {
        g.order.push('emit');
        emitted.push(o);
        await Promise.resolve();
      },
    );

    expect(stop).toBe(true);
    expect(emitted).toHaveLength(1);
    // An operator filtering on the prohibited id must see this refusal beside
    // the switch and turn ones, which recording `opus` would prevent.
    expect((g.recorded[0] as { attributes: Record<string, unknown> }).attributes).toMatchObject({
      model: 'claude-opus-5',
      requested_model: 'opus',
      refusal_seam: 'spawn',
    });
  });

  it('EMITS before it closes, so a close failure cannot discard the deny', async () => {
    // `close()` can throw on a handle it cannot close. Emitting after it would
    // let that rejection escape to the entry's outer catch and leave empty
    // stdout — which this host reads as no opinion, i.e. allow.
    const g = gatewayWith(['claude-opus-5']);
    await handleSubagentSpawn(
      () => g.gateway as never,
      'Agent',
      { model: 'opus' },
      's1',
      dir,
      async () => {
        g.order.push('emit');
        await Promise.resolve();
      },
    );
    expect(g.order).toEqual(['emit', 'close']);
  });

  it('still refuses when the close throws', async () => {
    const emitted: unknown[] = [];
    const stop = await handleSubagentSpawn(
      () =>
        ({
          getPolicyBundle: () => Promise.resolve({ prohibitedModels: ['claude-opus-5'] }),
          recordAuditEvent: () => Promise.resolve(),
          close: () => Promise.reject(new Error('cannot close')),
        }) as never,
      'Agent',
      { model: 'opus' },
      's1',
      dir,
      async (o) => {
        emitted.push(o);
        await Promise.resolve();
      },
    );
    expect(stop).toBe(true);
    expect(emitted).toHaveLength(1);
  });

  it('refuses a spawn whose MODEL COMES FROM THE AGENT DEFINITION', async () => {
    // End to end for the bypass: no `model` argument anywhere in the call.
    mkdirSync(join(dir, '.claude', 'agents'), { recursive: true });
    writeFileSync(join(dir, '.claude', 'agents', 'helper.md'), '---\nmodel: opus\n---\n', 'utf8');
    const g = gatewayWith(['claude-opus-5']);
    const stop = await handleSubagentSpawn(
      () => g.gateway as never,
      'Agent',
      { subagent_type: 'helper', prompt: 'go' },
      's1',
      dir,
      () => Promise.resolve(),
    );
    expect(stop).toBe(true);
  });

  it('opens NOTHING for a call that is not a spawn tool', async () => {
    // Every Bash, Edit and MCP leaf crosses this line too and must not pay a
    // store open.
    let opened = 0;
    const stop = await handleSubagentSpawn(
      () => {
        opened += 1;
        return null;
      },
      'Bash',
      { command: 'ls' },
      's1',
      dir,
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
    expect(opened).toBe(0);
  });

  it('reads NO agent definition when the organization prohibits nothing', async () => {
    // Bundle first: with an empty list there is nothing to enforce, and
    // resolving the model would be a file read spent to reach the same allow.
    mkdirSync(join(dir, '.claude', 'agents'), { recursive: true });
    writeFileSync(join(dir, '.claude', 'agents', 'helper.md'), '---\nmodel: opus\n---\n', 'utf8');
    const g = gatewayWith([]);
    const stop = await handleSubagentSpawn(
      () => g.gateway as never,
      'Agent',
      { subagent_type: 'helper' },
      's1',
      dir,
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
    expect(g.order, 'the gateway was still closed').toEqual(['close']);
  });

  it.each([
    ['the store cannot be opened', () => null],
    [
      'the bundle will not load',
      () =>
        ({
          getPolicyBundle: () => Promise.reject(new Error('nope')),
          close: () => Promise.resolve(),
        }) as never,
    ],
  ])('fails OPEN when %s', async (_label, open) => {
    const stop = await handleSubagentSpawn(
      open,
      'Agent',
      { model: 'opus' },
      's1',
      dir,
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
  });

  it('still refuses when the refusal cannot be recorded', async () => {
    const emitted: unknown[] = [];
    const stop = await handleSubagentSpawn(
      () =>
        ({
          getPolicyBundle: () => Promise.resolve({ prohibitedModels: ['claude-opus-5'] }),
          recordAuditEvent: () => Promise.reject(new Error('store full')),
          close: () => Promise.resolve(),
        }) as never,
      'Agent',
      { model: 'opus' },
      's1',
      dir,
      async (o) => {
        emitted.push(o);
        await Promise.resolve();
      },
    );
    expect(stop).toBe(true);
    expect(emitted).toHaveLength(1);
  });
});

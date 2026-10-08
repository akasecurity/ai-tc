import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { GovernanceScope } from '@akasecurity/plugin-runtime';
import { recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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

  it('reads a definition written with CRLF line endings', () => {
    // A checkout on Windows, or any file saved with CRLF, leaves a trailing
    // \r on every line. The parser trims it; nothing pinned that, and the leg
    // where it would bite is the one this repo runs slowest and reads least.
    writeAgent(dir, 'crlf', '---\r\nname: crlf\r\nmodel: haiku\r\n---\r\nbody\r\n');
    expect(resolveSpawnModel({ subagent_type: 'crlf' }, dir)).toBe('haiku');
  });

  it('finds a definition from a SUBDIRECTORY of the project', () => {
    // The hook payload's cwd is not the project root. A session working in a
    // package of a monorepo has no `.claude/` beneath it, so joining cwd
    // directly missed the project definition and fell through to the user one.
    writeAgent(dir, 'helper', '---\nmodel: haiku\n---\nbody');
    const deep = join(dir, 'packages', 'schema', 'src');
    mkdirSync(deep, { recursive: true });
    expect(resolveSpawnModel({ subagent_type: 'helper' }, deep)).toBe('haiku');
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
    const stop = await handleSubagentSpawn(open, 'Agent', { model: 'opus' }, 's1', dir, () =>
      Promise.resolve(),
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

  it('stamps the refusal with the scope key of the checkout the spawn ran in', async () => {
    // Keyed from the payload cwd, and only on this refusal path, so the tool
    // calls this seam waves through pay no `.git` walk for it.
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(
      join(dir, '.git', 'config'),
      '[remote "origin"]\n\turl = https://github.com/acme/work-repo.git\n',
    );
    const g = gatewayWith(['claude-opus-5']);
    const stop = await handleSubagentSpawn(
      () => g.gateway as never,
      'Agent',
      { model: 'opus' },
      's1',
      dir,
      () => Promise.resolve(),
    );
    expect(stop).toBe(true);
    expect((g.recorded[0] as { attributes: Record<string, unknown> }).attributes.scope_key).toBe(
      'github.com/acme/work-repo',
    );
  });

  // ON A SCOPED ATTACHMENT the organization's model policy governs only the
  // repositories enrolled on this device. The spawn is decided on the full list
  // first; only once the list refuses is it keyed from the payload cwd and the
  // gateway asked whether governance applies there, and the same key stamps the
  // row. Every gateway above answers nothing, and is governed everywhere.
  describe('on a scoped attachment, only enrolled repositories are governed', () => {
    const WORK_REMOTE = 'https://github.com/acme/work-repo.git';
    const WORK_KEY = 'github.com/acme/work-repo';
    const PERSONAL_REMOTE = 'https://github.com/someone/dotfiles.git';
    const PERSONAL_KEY = 'github.com/someone/dotfiles';

    /**
     * `gateway`, answering where governance applies the way the attached gateway
     * does: for the `enrolled` keys only, or for every key (`'every'`, a
     * machine-wide attachment). The answer reads `this`, as the real method does,
     * so a caller that detached it from its gateway would throw, which reads as
     * not governed, and the machine-wide case would fail.
     */
    function governed<G extends object>(
      gateway: G,
      enrolled: readonly string[] | 'every',
    ): G & GovernanceScope {
      const capability = {
        enrolled,
        governanceAppliesTo(scopeKey: string | undefined): boolean {
          return (
            this.enrolled === 'every' ||
            (scopeKey !== undefined && this.enrolled.includes(scopeKey))
          );
        },
      };
      return Object.assign(gateway, capability);
    }

    /** A checkout under this test's directory whose origin is `remote`, or none. */
    function checkout(name: string, remote: string | undefined): string {
      const repo = join(dir, name);
      mkdirSync(join(repo, '.git'), { recursive: true });
      writeFileSync(
        join(repo, '.git', 'config'),
        remote === undefined
          ? '[core]\n\tbare = false\n'
          : `[remote "origin"]\n\turl = ${remote}\n`,
      );
      return repo;
    }

    /** The scope key of every row `g` recorded, in order (undefined for a row with none). */
    const keysOf = (g: ReturnType<typeof gatewayWith>): unknown[] =>
      g.recorded.map((e) => (e as { attributes: Record<string, unknown> }).attributes.scope_key);

    /** One `Agent` spawn of `model` from `cwd` over `gateway`, emits logged into `g.order`. */
    function spawn(
      g: ReturnType<typeof gatewayWith>,
      gateway: object,
      cwd: string | undefined,
      model = 'opus',
    ): Promise<boolean> {
      return handleSubagentSpawn(
        () => gateway as never,
        'Agent',
        { model },
        's1',
        cwd,
        async () => {
          g.order.push('emit');
          await Promise.resolve();
        },
      );
    }

    it('is refused in an enrolled repository, with the row keyed there', async () => {
      const g = gatewayWith(['claude-opus-5']);
      expect(await spawn(g, governed(g.gateway, [WORK_KEY]), checkout('work', WORK_REMOTE))).toBe(
        true,
      );
      expect(g.order).toEqual(['emit', 'close']);
      expect(keysOf(g)).toEqual([WORK_KEY]);
      expect((g.recorded[0] as { attributes: Record<string, unknown> }).attributes).toMatchObject({
        refusal_seam: 'spawn',
      });
    });

    it('is allowed in a personal repository: no output, no row, and the gateway closed', async () => {
      const g = gatewayWith(['claude-opus-5']);
      expect(
        await spawn(g, governed(g.gateway, [WORK_KEY]), checkout('mine', PERSONAL_REMOTE)),
      ).toBe(false);
      expect(g.order).toEqual(['close']);
      expect(g.recorded).toHaveLength(0);
    });

    it('is allowed in a checkout with no key, the gateway closed', async () => {
      const g = gatewayWith(['claude-opus-5']);
      expect(await spawn(g, governed(g.gateway, [WORK_KEY]), checkout('scratch', undefined))).toBe(
        false,
      );
      expect(g.order).toEqual(['close']);
      expect(g.recorded).toHaveLength(0);
    });

    it('is refused everywhere on a machine-wide attachment, a keyless checkout included', async () => {
      const g = gatewayWith(['claude-opus-5']);
      expect(await spawn(g, governed(g.gateway, 'every'), checkout('scratch', undefined))).toBe(
        true,
      );
      expect(g.order).toEqual(['emit', 'close']);
      expect(g.recorded).toHaveLength(1);
      expect(
        (g.recorded[0] as { attributes: Record<string, unknown> }).attributes,
      ).not.toHaveProperty('scope_key');
    });

    it('is refused in a personal repository by a gateway that does not answer', async () => {
      const g = gatewayWith(['claude-opus-5']);
      expect(await spawn(g, g.gateway, checkout('mine', PERSONAL_REMOTE))).toBe(true);
      expect(g.order).toEqual(['emit', 'close']);
      expect(keysOf(g)).toEqual([PERSONAL_KEY]);
    });

    it('with no cwd, is keyed from the process directory, as a capture is', async () => {
      const work = checkout('work', WORK_REMOTE);
      const mine = checkout('mine', PERSONAL_REMOTE);
      const from = async (processDir: string) => {
        const g = gatewayWith(['claude-opus-5']);
        const spy = vi.spyOn(process, 'cwd').mockReturnValue(processDir);
        try {
          const stop = await spawn(g, governed(g.gateway, [WORK_KEY]), undefined);
          return { stop, order: g.order, keys: keysOf(g) };
        } finally {
          spy.mockRestore();
        }
      };
      expect(await from(work)).toEqual({ stop: true, order: ['emit', 'close'], keys: [WORK_KEY] });
      expect(await from(mine)).toEqual({ stop: false, order: ['close'], keys: [] });
    });

    it('asks only once the list refuses, with the key the row carries', async () => {
      const ask = vi.fn<GovernanceScope['governanceAppliesTo']>(() => true);
      const work = checkout('work', WORK_REMOTE);
      const allowed = gatewayWith(['claude-opus-5']);
      // The allowed spawn names no cwd, so a key computed before the decision
      // would fall back to the process directory: the spy proves none was.
      // Asserted BEFORE the restore, which clears the spy's calls.
      const cwdRead = vi.spyOn(process, 'cwd').mockReturnValue(work);
      try {
        expect(
          await spawn(
            allowed,
            Object.assign(allowed.gateway, { governanceAppliesTo: ask }),
            undefined,
            'sonnet',
          ),
        ).toBe(false);
        expect(cwdRead).not.toHaveBeenCalled();
      } finally {
        cwdRead.mockRestore();
      }
      expect(ask).not.toHaveBeenCalled();
      const refused = gatewayWith(['claude-opus-5']);
      expect(
        await spawn(refused, Object.assign(refused.gateway, { governanceAppliesTo: ask }), work),
      ).toBe(true);
      expect(ask.mock.calls).toEqual([[WORK_KEY]]);
      expect(keysOf(refused)).toEqual([WORK_KEY]);
    });
  });
});

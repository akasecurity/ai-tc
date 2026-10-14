import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { GovernanceScope } from '@akasecurity/plugin-runtime';
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
      dir,
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
    const stop = await handleProhibitedTurn(
      gatewayWith([], close),
      dir,
      's1',
      undefined,
      dir,
      (o) => {
        emitted.push(o);
        return Promise.resolve();
      },
    );
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
    expect(
      await handleProhibitedTurn(broken, dir, 's1', undefined, dir, () => Promise.resolve()),
    ).toBe(false);
  });

  it('never resolves the model when the bundle prohibits nothing', async () => {
    // Ordering that keeps an unenforced tenant off the transcript entirely.
    recordSessionModel(dir, 's1', 'o3');
    expect(
      await handleProhibitedTurn(gatewayWith(undefined), dir, 's1', undefined, dir, () =>
        Promise.resolve(),
      ),
    ).toBe(false);
  });
});

describe('handleProhibitedTurn keys the refusal row', () => {
  /** A gateway that keeps what it is handed, so the row itself is asserted. */
  function recordingGateway(recorded: { attributes: Record<string, unknown> }[]) {
    return {
      getPolicyBundle: () => Promise.resolve({ prohibitedModels: ['o3'] }),
      recordAuditEvent: (event: { attributes: Record<string, unknown> }) => {
        recorded.push(event);
        return Promise.resolve();
      },
      close: vi.fn(() => Promise.resolve()),
    } as unknown as Parameters<typeof handleProhibitedTurn>[0];
  }

  /** A checkout under this test's directory whose origin is `remote`, or none. */
  function checkout(name: string, remote: string | undefined): string {
    const repo = join(dir, name);
    mkdirSync(join(repo, '.git'), { recursive: true });
    writeFileSync(
      join(repo, '.git', 'config'),
      remote === undefined ? '[core]\n\tbare = false\n' : `[remote "origin"]\n\turl = ${remote}\n`,
    );
    return repo;
  }

  it('stamps scope_key from the checkout the refused turn ran in', async () => {
    recordSessionModel(dir, 's1', 'o3');
    const recorded: { attributes: Record<string, unknown> }[] = [];
    const stop = await handleProhibitedTurn(
      recordingGateway(recorded),
      dir,
      's1',
      undefined,
      checkout('work', 'git@github.com:acme/work-repo.git'),
      () => Promise.resolve(),
    );
    expect(stop).toBe(true);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.attributes).toMatchObject({
      refusal_seam: 'turn',
      scope_key: 'github.com/acme/work-repo',
    });
  });

  it('records the refusal with no key for a checkout with no remote', async () => {
    recordSessionModel(dir, 's1', 'o3');
    const recorded: { attributes: Record<string, unknown> }[] = [];
    await handleProhibitedTurn(
      recordingGateway(recorded),
      dir,
      's1',
      undefined,
      checkout('scratch', undefined),
      () => Promise.resolve(),
    );
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.attributes).not.toHaveProperty('scope_key');
  });

  // ON A SCOPED ATTACHMENT the organization's model policy governs only the
  // repositories enrolled on this device. The turn is decided on the full list
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

    /**
     * `gateway`, offering the capability but unable to answer it: the question
     * throws. That reads as not governed, so a refusal the list would make is
     * allowed.
     */
    function unanswering<G extends object>(gateway: G): G & GovernanceScope {
      return Object.assign(gateway, {
        governanceAppliesTo(): boolean {
          throw new Error('the capability cannot answer');
        },
      });
    }

    /**
     * The refusal path's three members, refusing `o3`, with the rows and the close
     * in the test's hands (`recordingGateway` above keeps its close to itself).
     */
    function refusing(
      recorded: { attributes: Record<string, unknown> }[],
      close: () => Promise<void> = () => Promise.resolve(),
    ): Parameters<typeof handleProhibitedTurn>[0] {
      return {
        getPolicyBundle: () => Promise.resolve({ prohibitedModels: ['o3'] }),
        recordAuditEvent: (event: { attributes: Record<string, unknown> }) => {
          recorded.push(event);
          return Promise.resolve();
        },
        close,
      } as unknown as Parameters<typeof handleProhibitedTurn>[0];
    }

    /** One turn on the model the marker names, from `cwd`, and how many blocks it emitted. */
    async function turn(
      gateway: Parameters<typeof handleProhibitedTurn>[0],
      cwd: string | undefined,
    ): Promise<{ stop: boolean; emitted: number }> {
      let emitted = 0;
      const stop = await handleProhibitedTurn(gateway, dir, 's1', undefined, cwd, () => {
        emitted += 1;
        return Promise.resolve();
      });
      return { stop, emitted };
    }

    /**
     * A linked worktree of `main`, laid out the way `git worktree add` lays one
     * out: a `.git` FILE naming its gitdir under the main checkout's `.git`,
     * whose `commondir` leads back to the shared config, and so to the remote.
     */
    function linkedWorktree(main: string, name: string): string {
      const gitdir = join(main, '.git', 'worktrees', name);
      mkdirSync(gitdir, { recursive: true });
      writeFileSync(join(gitdir, 'commondir'), '../..\n');
      const tree = join(dir, name);
      mkdirSync(tree, { recursive: true });
      writeFileSync(join(tree, '.git'), `gitdir: ${gitdir}\n`);
      return tree;
    }

    /**
     * Where a turn can run, as [label, governed there, its cwd built from the
     * enrolled checkout]. The flag comes second so the case title prints it.
     */
    const SHAPES: [string, boolean, (work: string) => string][] = [
      [
        'a subdirectory of the enrolled checkout',
        true,
        (work) => {
          const sub = join(work, 'packages', 'api');
          mkdirSync(sub, { recursive: true });
          return sub;
        },
      ],
      [
        'a linked worktree of the enrolled checkout',
        true,
        (work) => linkedWorktree(work, 'feature'),
      ],
      // Only an absolute cwd is keyed: a relative one would be read against the
      // hook process's own directory, which need not be the session's.
      ['a relative cwd', false, () => join('relative', 'work')],
      [
        'a directory outside any repository',
        false,
        () => {
          const plain = join(dir, 'scratch');
          mkdirSync(plain, { recursive: true });
          return plain;
        },
      ],
    ];

    it('is refused in an enrolled repository, with the row keyed there', async () => {
      recordSessionModel(dir, 's1', 'o3');
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const close = vi.fn(() => Promise.resolve());
      const result = await turn(
        governed(refusing(recorded, close), [WORK_KEY]),
        checkout('work', WORK_REMOTE),
      );
      expect(result).toEqual({ stop: true, emitted: 1 });
      expect(close).toHaveBeenCalledTimes(1);
      expect(recorded.map((e) => e.attributes.scope_key)).toEqual([WORK_KEY]);
      expect(recorded[0]?.attributes).toMatchObject({ refusal_seam: 'turn' });
    });

    it('is allowed in a personal repository: no output, no row, and the gateway left OPEN', async () => {
      // The caller scans this turn over the same gateway and closes it in its
      // own `finally`; closing here would pull it out from under the scan.
      recordSessionModel(dir, 's1', 'o3');
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const close = vi.fn(() => Promise.resolve());
      const result = await turn(
        governed(refusing(recorded, close), [WORK_KEY]),
        checkout('mine', PERSONAL_REMOTE),
      );
      expect(result).toEqual({ stop: false, emitted: 0 });
      expect(close).not.toHaveBeenCalled();
      expect(recorded).toHaveLength(0);
    });

    it('is allowed in a checkout with no key, the gateway left OPEN', async () => {
      recordSessionModel(dir, 's1', 'o3');
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const close = vi.fn(() => Promise.resolve());
      const result = await turn(
        governed(refusing(recorded, close), [WORK_KEY]),
        checkout('scratch', undefined),
      );
      expect(result).toEqual({ stop: false, emitted: 0 });
      expect(close).not.toHaveBeenCalled();
      expect(recorded).toHaveLength(0);
    });

    it('is refused everywhere on a machine-wide attachment, a keyless checkout included', async () => {
      recordSessionModel(dir, 's1', 'o3');
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const close = vi.fn(() => Promise.resolve());
      const result = await turn(
        governed(refusing(recorded, close), 'every'),
        checkout('scratch', undefined),
      );
      expect(result).toEqual({ stop: true, emitted: 1 });
      expect(close).toHaveBeenCalledTimes(1);
      expect(recorded).toHaveLength(1);
      expect(recorded[0]?.attributes).not.toHaveProperty('scope_key');
    });

    it('is refused in a personal repository by a gateway that does not answer', async () => {
      recordSessionModel(dir, 's1', 'o3');
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const result = await turn(refusing(recorded), checkout('mine', PERSONAL_REMOTE));
      expect(result).toEqual({ stop: true, emitted: 1 });
      expect(recorded.map((e) => e.attributes.scope_key)).toEqual([PERSONAL_KEY]);
    });

    it('is allowed in an enrolled repository when the capability throws: no output, no row, and the gateway left OPEN', async () => {
      recordSessionModel(dir, 's1', 'o3');
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const close = vi.fn(() => Promise.resolve());
      const result = await turn(
        unanswering(refusing(recorded, close)),
        checkout('work', WORK_REMOTE),
      );
      expect(result).toEqual({ stop: false, emitted: 0 });
      expect(close).not.toHaveBeenCalled();
      expect(recorded).toHaveLength(0);
    });

    it('with no cwd, is keyed from the process directory, as its capture is', async () => {
      recordSessionModel(dir, 's1', 'o3');
      const work = checkout('work', WORK_REMOTE);
      const mine = checkout('mine', PERSONAL_REMOTE);
      const from = async (processDir: string) => {
        const recorded: { attributes: Record<string, unknown> }[] = [];
        const spy = vi.spyOn(process, 'cwd').mockReturnValue(processDir);
        try {
          const { stop } = await turn(governed(refusing(recorded), [WORK_KEY]), undefined);
          return { stop, keys: recorded.map((e) => e.attributes.scope_key) };
        } finally {
          spy.mockRestore();
        }
      };
      expect(await from(work)).toEqual({ stop: true, keys: [WORK_KEY] });
      expect(await from(mine)).toEqual({ stop: false, keys: [] });
    });

    it('asks only once the list refuses, with the key the row carries', async () => {
      const ask = vi.fn<GovernanceScope['governanceAppliesTo']>(() => true);
      const work = checkout('work', WORK_REMOTE);
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const gateway = () => Object.assign(refusing(recorded), { governanceAppliesTo: ask });
      recordSessionModel(dir, 's1', 'gpt-4o');
      // The allowed turn names no cwd, so a key computed before the decision
      // would fall back to the process directory: the spy proves none was.
      // Asserted BEFORE the restore, which clears the spy's calls.
      const cwdRead = vi.spyOn(process, 'cwd').mockReturnValue(work);
      try {
        expect((await turn(gateway(), undefined)).stop).toBe(false);
        expect(cwdRead).not.toHaveBeenCalled();
      } finally {
        cwdRead.mockRestore();
      }
      expect(ask).not.toHaveBeenCalled();
      recordSessionModel(dir, 's1', 'o3');
      expect((await turn(gateway(), work)).stop).toBe(true);
      expect(ask.mock.calls).toEqual([[WORK_KEY]]);
      expect(recorded.map((e) => e.attributes.scope_key)).toEqual([WORK_KEY]);
    });

    it.each(SHAPES)('from %s, governed: %s', async (_shape, governedHere, cwdOf) => {
      recordSessionModel(dir, 's1', 'o3');
      const recorded: { attributes: Record<string, unknown> }[] = [];
      const result = await turn(
        governed(refusing(recorded), [WORK_KEY]),
        cwdOf(checkout('work', WORK_REMOTE)),
      );
      expect(result.stop).toBe(governedHere);
      expect(recorded.map((e) => e.attributes.scope_key)).toEqual(governedHere ? [WORK_KEY] : []);
    });
  });
});

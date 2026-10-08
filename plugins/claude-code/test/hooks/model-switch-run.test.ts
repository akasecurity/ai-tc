import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { GovernanceScope } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { readSessionModel, recordSessionModel } from '@akasecurity/plugin-sdk';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { handleProhibitedTurn, refuseProhibitedTurn } from '../../src/hooks/model-guard.ts';
import { runPostModelSwitch, runPreModelSwitch } from '../../src/hooks/model-switch-run.ts';

// One temp root for the file, with a cheap subdirectory per test. These cases
// need an isolated marker file rather than an isolated filesystem, and a
// recursive remove per test is slow enough on Windows to be worth not paying.
let root: string;
let dir: string;
let n = 0;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-switch-run-'));
});

beforeEach(() => {
  n += 1;
  dir = join(root, `t${String(n)}`);
  mkdirSync(dir, { recursive: true });
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const config = (): PluginConfig => ({ dataDir: dir }) as unknown as PluginConfig;

/** A gateway stubbed down to the one read these paths perform. */
function gatewayWith(
  prohibited: string[] | undefined,
  onClose = vi.fn(),
  recordAuditEvent: (event: unknown) => Promise<void> = () => Promise.resolve(),
): DataGateway {
  return {
    getPolicyBundle: () =>
      Promise.resolve({ prohibitedModels: prohibited } as unknown as Awaited<
        ReturnType<DataGateway['getPolicyBundle']>
      >),
    recordAuditEvent,
    close: onClose,
  } as unknown as DataGateway;
}

/** One recorded audit row, in the shape these assertions read. */
interface RecordedEvent {
  eventType: string;
  attributes: Record<string, unknown>;
}

/**
 * The one row a refusal is expected to record.
 *
 * Narrows by construction rather than by an assertion — both `!` and `as` are
 * refused here — and states the cardinality while it is at it: two rows for one
 * refusal would be a defect these assertions would otherwise read straight past.
 */
function onlyEvent(events: readonly RecordedEvent[]): RecordedEvent {
  const [first, ...rest] = events;
  if (first === undefined || rest.length > 0) {
    throw new Error(`expected exactly one recorded event, got ${String(events.length)}`);
  }
  return first;
}

/** A recorder plus the rows it captured, typed so no mock tuple is indexed. */
function recorder(): {
  fn: (event: unknown) => Promise<void>;
  events: RecordedEvent[];
} {
  const events: RecordedEvent[] = [];
  return {
    fn: (event: unknown) => {
      events.push(event as RecordedEvent);
      return Promise.resolve();
    },
    events,
  };
}

describe('runPreModelSwitch', () => {
  it('refuses the switch and records NOTHING when the target is prohibited', () => {
    // A refused switch never happened, so recording its target would make the
    // next turn enforce against a model the session is not running.
    const emit = vi.fn(() => Promise.resolve());
    return runPreModelSwitch('claude-opus-5', 's1', dir, {
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
    const refused = await runPreModelSwitch('claude-sonnet-4-5', 's1', dir, {
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
    const refused = await runPreModelSwitch('claude-opus-5', 's1', dir, {
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
      await runPreModelSwitch(target, 's1', dir, {
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
    await runPreModelSwitch('claude-opus-5', 's1', dir, {
      config: config(),
      openGateway: () => gatewayWith([]),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: warn,
    });
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe('runPreModelSwitch records the refusal', () => {
  it('writes a model_refusal naming the model and the switch seam', async () => {
    const rec = recorder();
    await runPreModelSwitch('claude-opus-5', 's1', dir, {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: vi.fn(),
      newId: () => 'evt-1',
      now: () => new Date('2026-09-02T10:30:00.000Z'),
    });
    const event = onlyEvent(rec.events);
    expect(event.eventType).toBe('model_refusal');
    expect(event.attributes.model).toBe('claude-opus-5');
    expect(event.attributes.refusal_seam).toBe('switch');
  });

  it('records nothing when the switch is ALLOWED', async () => {
    const rec = recorder();
    await runPreModelSwitch('claude-sonnet-4-5', 's1', dir, {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: vi.fn(),
    });
    expect(rec.events).toHaveLength(0);
  });

  it('still refuses when the refusal cannot be recorded', async () => {
    // The failure this must never have: a write that throws reaching the entry's
    // outer catch would turn a deny into a fail-open allow, leaving the session
    // LESS governed than before the audit trail existed.
    const emit = vi.fn(() => Promise.resolve());
    const refused = await runPreModelSwitch('claude-opus-5', 's1', dir, {
      config: config(),
      openGateway: () =>
        gatewayWith(
          ['claude-opus-5'],
          vi.fn(),
          vi.fn(() => Promise.reject(new Error('store gone'))),
        ),
      emit,
      warnIfStoreRedirected: vi.fn(),
    });
    expect(refused).toBe(true);
    expect(emit).toHaveBeenCalledTimes(1);
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
    expect(out?.decision.decision).toBe('block');
    expect(out?.decision.reason).toContain('claude-opus-5');
    // The model rides back with the verdict so the audit row and the message
    // the user sees can never disagree about which model was refused.
    expect(out?.model).toBe('claude-opus-5');
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

describe('handleProhibitedTurn', () => {
  it('closes the gateway and emits the block, then tells the caller to stop', async () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const close = vi.fn(() => Promise.resolve());
    const emitted: { decision: 'block'; reason: string }[] = [];
    const emit = (output: { decision: 'block'; reason: string }): Promise<void> => {
      emitted.push(output);
      return Promise.resolve();
    };
    const stop = await handleProhibitedTurn(
      gatewayWith(['claude-opus-5'], close),
      dir,
      's1',
      undefined,
      dir,
      emit,
    );
    expect(stop).toBe(true);
    expect(close).toHaveBeenCalledTimes(1);
    expect(emitted).toHaveLength(1);
    expect(emitted[0]?.decision).toBe('block');
    expect(emitted[0]?.reason).toContain('claude-opus-5');
  });

  it('leaves the gateway OPEN and emits nothing when the turn is allowed', async () => {
    // The caller goes on to build a runtime over this gateway and closes it in
    // its own `finally`; closing here would pull it out from under the scan.
    const close = vi.fn(() => Promise.resolve());
    const emit = vi.fn(() => Promise.resolve());
    const stop = await handleProhibitedTurn(
      gatewayWith([], close),
      dir,
      's1',
      undefined,
      dir,
      emit,
    );
    expect(stop).toBe(false);
    expect(close).not.toHaveBeenCalled();
    expect(emit).not.toHaveBeenCalled();
  });
});

describe('handleProhibitedTurn records the refusal', () => {
  it('writes a model_refusal naming the TURN seam', async () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const rec = recorder();
    await handleProhibitedTurn(
      gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      dir,
      's1',
      undefined,
      dir,
      () => Promise.resolve(),
    );
    const event = onlyEvent(rec.events);
    expect(event.eventType).toBe('model_refusal');
    expect(event.attributes.model).toBe('claude-opus-5');
    // The seam is what separates this from the switch refusal in the same
    // session — an operator asking "was it prevented, or contained?" reads it.
    expect(event.attributes.refusal_seam).toBe('turn');
  });

  it('still refuses when the refusal cannot be recorded', async () => {
    // A write that throws must not reach the entry's outer catch, which would
    // turn the block into a fail-open allow.
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const emitted: unknown[] = [];
    const stop = await handleProhibitedTurn(
      gatewayWith(['claude-opus-5'], vi.fn(), () => Promise.reject(new Error('store gone'))),
      dir,
      's1',
      undefined,
      dir,
      (output) => {
        emitted.push(output);
        return Promise.resolve();
      },
    );
    expect(stop).toBe(true);
    expect(emitted).toHaveLength(1);
  });

  it('records nothing when the turn is allowed', async () => {
    const rec = recorder();
    await handleProhibitedTurn(gatewayWith([], vi.fn(), rec.fn), dir, 's1', undefined, dir, () =>
      Promise.resolve(),
    );
    expect(rec.events).toHaveLength(0);
  });
});

describe('the refusal row carries the scope key of the checkout it happened in', () => {
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

  it('stamps the switch refusal', async () => {
    const rec = recorder();
    await runPreModelSwitch(
      'claude-opus-5',
      's1',
      checkout('work', 'git@GitHub.com:acme/work-repo.git'),
      {
        config: config(),
        openGateway: () => gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
        emit: vi.fn(() => Promise.resolve()),
        warnIfStoreRedirected: vi.fn(),
      },
    );
    expect(onlyEvent(rec.events).attributes.scope_key).toBe('github.com/acme/work-repo');
  });

  it('stamps the turn refusal', async () => {
    recordSessionModel(dir, 's1', 'claude-opus-5');
    const rec = recorder();
    await handleProhibitedTurn(
      gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      dir,
      's1',
      undefined,
      checkout('work', 'https://github.com/acme/work-repo.git'),
      () => Promise.resolve(),
    );
    expect(onlyEvent(rec.events).attributes.scope_key).toBe('github.com/acme/work-repo');
  });

  it('records the refusal with no key for a checkout with no remote', async () => {
    const rec = recorder();
    await runPreModelSwitch('claude-opus-5', 's1', checkout('scratch', undefined), {
      config: config(),
      openGateway: () => gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
      emit: vi.fn(() => Promise.resolve()),
      warnIfStoreRedirected: vi.fn(),
    });
    const event = onlyEvent(rec.events);
    expect(event.attributes.refusal_seam).toBe('switch');
    expect(event.attributes).not.toHaveProperty('scope_key');
  });

  // ON A SCOPED ATTACHMENT the organization's model policy governs only the
  // repositories enrolled on this device. Each seam decides on the full list
  // first; only once the list refuses does it key the event from the payload
  // cwd and ask the gateway whether governance applies there, and the same key
  // stamps the row. Every gateway above answers nothing, and a gateway that
  // answers nothing is governed everywhere.
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
     * not governed, and the machine-wide cases would fail.
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

    describe('the switch', () => {
      it('is refused in an enrolled repository, with the row keyed there', async () => {
        const rec = recorder();
        const emit = vi.fn(() => Promise.resolve());
        const refused = await runPreModelSwitch(
          'claude-opus-5',
          's1',
          checkout('work', WORK_REMOTE),
          {
            config: config(),
            openGateway: () =>
              governed(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), [WORK_KEY]),
            emit,
            warnIfStoreRedirected: vi.fn(),
          },
        );
        expect(refused).toBe(true);
        expect(emit).toHaveBeenCalledTimes(1);
        expect(onlyEvent(rec.events).attributes.scope_key).toBe(WORK_KEY);
        expect(readSessionModel(dir, 's1')).toBeUndefined();
      });

      it('is allowed in a personal repository: no output, no row, closed, and the model recorded', async () => {
        const rec = recorder();
        const close = vi.fn(() => Promise.resolve());
        const emit = vi.fn(() => Promise.resolve());
        const refused = await runPreModelSwitch(
          'claude-opus-5',
          's1',
          checkout('mine', PERSONAL_REMOTE),
          {
            config: config(),
            openGateway: () => governed(gatewayWith(['claude-opus-5'], close, rec.fn), [WORK_KEY]),
            emit,
            warnIfStoreRedirected: vi.fn(),
          },
        );
        expect(refused).toBe(false);
        expect(emit).not.toHaveBeenCalled();
        expect(rec.events).toHaveLength(0);
        expect(close).toHaveBeenCalledTimes(1);
        // An allowed switch changes the model the session runs on, whatever
        // allowed it; the next turn reads this marker before the transcript.
        expect(readSessionModel(dir, 's1')).toBe('claude-opus-5');
      });

      it('is allowed in a checkout with no key', async () => {
        const rec = recorder();
        const emit = vi.fn(() => Promise.resolve());
        const refused = await runPreModelSwitch(
          'claude-opus-5',
          's1',
          checkout('scratch', undefined),
          {
            config: config(),
            openGateway: () =>
              governed(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), [WORK_KEY]),
            emit,
            warnIfStoreRedirected: vi.fn(),
          },
        );
        expect(refused).toBe(false);
        expect(emit).not.toHaveBeenCalled();
        expect(rec.events).toHaveLength(0);
        expect(readSessionModel(dir, 's1')).toBe('claude-opus-5');
      });

      it('is refused everywhere on a machine-wide attachment, a keyless checkout included', async () => {
        const rec = recorder();
        const refused = await runPreModelSwitch(
          'claude-opus-5',
          's1',
          checkout('scratch', undefined),
          {
            config: config(),
            openGateway: () => governed(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), 'every'),
            emit: vi.fn(() => Promise.resolve()),
            warnIfStoreRedirected: vi.fn(),
          },
        );
        expect(refused).toBe(true);
        expect(onlyEvent(rec.events).attributes).not.toHaveProperty('scope_key');
      });

      it('is refused in a personal repository by a gateway that does not answer', async () => {
        const rec = recorder();
        const refused = await runPreModelSwitch(
          'claude-opus-5',
          's1',
          checkout('mine', PERSONAL_REMOTE),
          {
            config: config(),
            openGateway: () => gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
            emit: vi.fn(() => Promise.resolve()),
            warnIfStoreRedirected: vi.fn(),
          },
        );
        expect(refused).toBe(true);
        expect(onlyEvent(rec.events).attributes.scope_key).toBe(PERSONAL_KEY);
      });

      it('with no cwd, is keyed from the process directory, as a capture is', async () => {
        const work = checkout('work', WORK_REMOTE);
        const mine = checkout('mine', PERSONAL_REMOTE);
        const from = async (processDir: string, sessionId: string) => {
          const rec = recorder();
          const spy = vi.spyOn(process, 'cwd').mockReturnValue(processDir);
          try {
            const refused = await runPreModelSwitch('claude-opus-5', sessionId, undefined, {
              config: config(),
              openGateway: () =>
                governed(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), [WORK_KEY]),
              emit: vi.fn(() => Promise.resolve()),
              warnIfStoreRedirected: vi.fn(),
            });
            return { refused, keys: rec.events.map((e) => e.attributes.scope_key) };
          } finally {
            spy.mockRestore();
          }
        };
        expect(await from(work, 's1')).toEqual({ refused: true, keys: [WORK_KEY] });
        expect(await from(mine, 's2')).toEqual({ refused: false, keys: [] });
      });

      it('asks only once the list refuses, with the key the row carries', async () => {
        const ask = vi.fn<GovernanceScope['governanceAppliesTo']>(() => true);
        const work = checkout('work', WORK_REMOTE);
        const rec = recorder();
        const deps = () => ({
          config: config(),
          openGateway: () =>
            Object.assign(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), {
              governanceAppliesTo: ask,
            }),
          emit: vi.fn(() => Promise.resolve()),
          warnIfStoreRedirected: vi.fn(),
        });
        // The allowed switch names no cwd, so a key computed before the decision
        // would fall back to the process directory: the spy proves none was.
        // Asserted BEFORE the restore, which clears the spy's calls.
        const cwdRead = vi.spyOn(process, 'cwd').mockReturnValue(work);
        try {
          expect(await runPreModelSwitch('claude-sonnet-4-5', 's1', undefined, deps())).toBe(false);
          expect(cwdRead).not.toHaveBeenCalled();
        } finally {
          cwdRead.mockRestore();
        }
        expect(ask).not.toHaveBeenCalled();
        expect(await runPreModelSwitch('claude-opus-5', 's1', work, deps())).toBe(true);
        expect(ask.mock.calls).toEqual([[WORK_KEY]]);
        expect(onlyEvent(rec.events).attributes.scope_key).toBe(WORK_KEY);
      });
    });

    describe('the turn', () => {
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

      it('is refused in an enrolled repository, with the row keyed there', async () => {
        recordSessionModel(dir, 's1', 'claude-opus-5');
        const rec = recorder();
        const close = vi.fn(() => Promise.resolve());
        const result = await turn(
          governed(gatewayWith(['claude-opus-5'], close, rec.fn), [WORK_KEY]),
          checkout('work', WORK_REMOTE),
        );
        expect(result).toEqual({ stop: true, emitted: 1 });
        expect(close).toHaveBeenCalledTimes(1);
        expect(onlyEvent(rec.events).attributes).toMatchObject({
          refusal_seam: 'turn',
          scope_key: WORK_KEY,
        });
      });

      it('is allowed in a personal repository: no output, no row, and the gateway left OPEN', async () => {
        // The caller scans this turn over the same gateway and closes it in its
        // own `finally`; closing here would pull it out from under the scan.
        recordSessionModel(dir, 's1', 'claude-opus-5');
        const rec = recorder();
        const close = vi.fn(() => Promise.resolve());
        const result = await turn(
          governed(gatewayWith(['claude-opus-5'], close, rec.fn), [WORK_KEY]),
          checkout('mine', PERSONAL_REMOTE),
        );
        expect(result).toEqual({ stop: false, emitted: 0 });
        expect(close).not.toHaveBeenCalled();
        expect(rec.events).toHaveLength(0);
      });

      it('is allowed in a checkout with no key, the gateway left OPEN', async () => {
        recordSessionModel(dir, 's1', 'claude-opus-5');
        const rec = recorder();
        const close = vi.fn(() => Promise.resolve());
        const result = await turn(
          governed(gatewayWith(['claude-opus-5'], close, rec.fn), [WORK_KEY]),
          checkout('scratch', undefined),
        );
        expect(result).toEqual({ stop: false, emitted: 0 });
        expect(close).not.toHaveBeenCalled();
        expect(rec.events).toHaveLength(0);
      });

      it('is refused everywhere on a machine-wide attachment, a keyless checkout included', async () => {
        recordSessionModel(dir, 's1', 'claude-opus-5');
        const rec = recorder();
        const close = vi.fn(() => Promise.resolve());
        const result = await turn(
          governed(gatewayWith(['claude-opus-5'], close, rec.fn), 'every'),
          checkout('scratch', undefined),
        );
        expect(result).toEqual({ stop: true, emitted: 1 });
        expect(close).toHaveBeenCalledTimes(1);
        expect(onlyEvent(rec.events).attributes).not.toHaveProperty('scope_key');
      });

      it('is refused in a personal repository by a gateway that does not answer', async () => {
        recordSessionModel(dir, 's1', 'claude-opus-5');
        const rec = recorder();
        const result = await turn(
          gatewayWith(['claude-opus-5'], vi.fn(), rec.fn),
          checkout('mine', PERSONAL_REMOTE),
        );
        expect(result).toEqual({ stop: true, emitted: 1 });
        expect(onlyEvent(rec.events).attributes.scope_key).toBe(PERSONAL_KEY);
      });

      it('with no cwd, is keyed from the process directory, as its capture is', async () => {
        recordSessionModel(dir, 's1', 'claude-opus-5');
        const work = checkout('work', WORK_REMOTE);
        const mine = checkout('mine', PERSONAL_REMOTE);
        const from = async (processDir: string) => {
          const rec = recorder();
          const spy = vi.spyOn(process, 'cwd').mockReturnValue(processDir);
          try {
            const { stop } = await turn(
              governed(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), [WORK_KEY]),
              undefined,
            );
            return { stop, keys: rec.events.map((e) => e.attributes.scope_key) };
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
        const rec = recorder();
        const gateway = () =>
          Object.assign(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), {
            governanceAppliesTo: ask,
          });
        recordSessionModel(dir, 's1', 'claude-sonnet-4-5');
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
        recordSessionModel(dir, 's1', 'claude-opus-5');
        expect((await turn(gateway(), work)).stop).toBe(true);
        expect(ask.mock.calls).toEqual([[WORK_KEY]]);
        expect(onlyEvent(rec.events).attributes.scope_key).toBe(WORK_KEY);
      });

      it.each(SHAPES)('from %s, governed: %s', async (_shape, governedHere, cwdOf) => {
        recordSessionModel(dir, 's1', 'claude-opus-5');
        const rec = recorder();
        const result = await turn(
          governed(gatewayWith(['claude-opus-5'], vi.fn(), rec.fn), [WORK_KEY]),
          cwdOf(checkout('work', WORK_REMOTE)),
        );
        expect(result.stop).toBe(governedHere);
        expect(rec.events.map((e) => e.attributes.scope_key)).toEqual(
          governedHere ? [WORK_KEY] : [],
        );
      });
    });

    it('allows a switch in a personal repository, then refuses the next turn in an enrolled one', async () => {
      const switchRows = recorder();
      const switched = await runPreModelSwitch(
        'claude-opus-5',
        's1',
        checkout('mine', PERSONAL_REMOTE),
        {
          config: config(),
          openGateway: () =>
            governed(gatewayWith(['claude-opus-5'], vi.fn(), switchRows.fn), [WORK_KEY]),
          emit: vi.fn(() => Promise.resolve()),
          warnIfStoreRedirected: vi.fn(),
        },
      );
      expect(switched).toBe(false);
      expect(switchRows.events).toHaveLength(0);

      // No transcript: the turn can know the model only from the marker the
      // allowed switch recorded, so this also proves the switch recorded it.
      const turnRows = recorder();
      const emitted: { decision: 'block'; reason: string }[] = [];
      const stop = await handleProhibitedTurn(
        governed(gatewayWith(['claude-opus-5'], vi.fn(), turnRows.fn), [WORK_KEY]),
        dir,
        's1',
        undefined,
        checkout('work', WORK_REMOTE),
        (output) => {
          emitted.push(output);
          return Promise.resolve();
        },
      );
      expect(stop).toBe(true);
      expect(emitted).toHaveLength(1);
      expect(emitted[0]?.reason).toContain('claude-opus-5');
      expect(onlyEvent(turnRows.events).attributes).toMatchObject({
        refusal_seam: 'turn',
        scope_key: WORK_KEY,
      });
    });
  });
});

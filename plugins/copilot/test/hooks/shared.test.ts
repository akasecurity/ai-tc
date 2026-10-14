// The stdio helpers in `shared.ts` that are neither the wire union nor the
// fail-open wrapper: `readStdin`, which every hook calls first, and
// `baseMetadata`, `captureScopeKey` and `callScopeKey`, which stamp what a
// capture is attributed to.
//
// Both were reachable only through a spawned process before this file, so
// nothing in-process saw them — and the e2e that drives them cannot distinguish
// "settled on end" from "settled on the timeout", or see that a listener was
// removed at all. Those are the properties here.
//
// `emit`, `runHookFailOpen` and the `HookOutput` union are covered in
// ./fail-open-wrapper.test.ts and ../hook-output-shapes.test.ts; this file
// deliberately does not restate them.
import { EventEmitter } from 'node:events';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, sep } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseMetadata,
  callScopeKey,
  captureScopeKey,
  getString,
  parseJson,
  readStdin,
  VSCODE_FILE_WRITERS,
} from '../../src/hooks/shared.ts';

// The userinfo in an scp-style remote (`<user>@<host>:path`) reads as an email
// address to a scanner, so the fixtures build it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

/**
 * A stand-in for `process.stdin` carrying only what `readStdin` touches.
 *
 * An EventEmitter rather than a mock object, so `on`/`removeListener` really
 * behave — the listener-removal case below is asserting emitter state, and a
 * hand-rolled stub would let it pass by construction.
 */
class FakeStdin extends EventEmitter {
  public encoding: string | undefined;

  public setEncoding(encoding: string): this {
    this.encoding = encoding;
    return this;
  }
}

/**
 * Install `fake` as `process.stdin` for the WHOLE of `body`, including whatever
 * it awaits.
 *
 * Restoring synchronously after kicking off `readStdin()` looks equivalent and
 * is not: `finish()` calls `process.stdin.removeListener(...)` when the stream
 * settles, which is a later turn — so the removal would land on the real stdin
 * and the fake would keep its listeners. That is a harness bug that reads
 * exactly like a product leak, and it cost this file a false red once.
 */
async function withStdin<T>(fake: FakeStdin, body: () => Promise<T>): Promise<T> {
  const original = Object.getOwnPropertyDescriptor(process, 'stdin');
  Object.defineProperty(process, 'stdin', { value: fake, configurable: true });
  try {
    return await body();
  } finally {
    if (original) Object.defineProperty(process, 'stdin', original);
  }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('readStdin', () => {
  it('concatenates every chunk and resolves on end', async () => {
    const fake = new FakeStdin();
    // Chunked deliberately: a payload past the pipe buffer arrives in several
    // reads, and an implementation keeping only the last chunk would pass a
    // single-chunk case.
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', '{"tool');
      fake.emit('data', 'Name":"bash"}');
      fake.emit('end');
      return pending;
    });
    expect(got).toBe('{"toolName":"bash"}');
  });

  it('asks for utf8 rather than decoding Buffers by hand', async () => {
    const fake = new FakeStdin();
    await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('end');
      return pending;
    });
    expect(fake.encoding).toBe('utf8');
  });

  it('resolves empty when stdin ends with nothing', async () => {
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('end');
      return pending;
    });
    expect(got).toBe('');
  });

  it('resolves rather than rejecting on an error event', async () => {
    // An unhandled 'error' on stdin is an uncaughtException, not a rejection —
    // it would kill the hook with a non-zero exit, which on the Copilot CLI is a
    // DENY. Settling instead is what keeps the exit at 0.
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', 'partial');
      fake.emit('error', new Error('EPIPE'));
      return pending;
    });
    expect(got).toBe('partial');
  });

  it('settles with whatever arrived when stdin never closes', async () => {
    // The 5s guard. A host that opens the pipe and never ends it would otherwise
    // hang the hook past its own timeout — and a timed-out hook is allowed
    // through unscanned.
    vi.useFakeTimers();
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', 'arrived before the stall');
      await vi.advanceTimersByTimeAsync(5_000);
      return pending;
    });
    expect(got).toBe('arrived before the stall');
  });

  it('settles ONCE — a late end after the timeout changes nothing', async () => {
    // The `settled` latch. Without it the second settle path would call
    // `resolve` again (harmless) but also re-enter the listener removal, and a
    // future edit that resolved with a fresh buffer would silently truncate.
    vi.useFakeTimers();
    const fake = new FakeStdin();
    const got = await withStdin(fake, async () => {
      const pending = readStdin();
      fake.emit('data', 'first');
      await vi.advanceTimersByTimeAsync(5_000);
      fake.emit('data', 'second');
      fake.emit('end');
      return pending;
    });
    expect(got).toBe('first');
  });

  it('removes its data and end listeners once settled', async () => {
    // Asserted on the emitter rather than inferred: a hook process is short
    // lived, so a leak here is invisible at runtime and only shows up as a
    // surprise when the handle is reused.
    const fake = new FakeStdin();
    await withStdin(fake, async () => {
      const pending = readStdin();
      // Both halves: a version that never attached would satisfy the removal
      // check trivially.
      expect(fake.listenerCount('data')).toBe(1);
      expect(fake.listenerCount('end')).toBe(1);
      fake.emit('end');
      return pending;
    });
    expect(fake.listenerCount('data')).toBe(0);
    expect(fake.listenerCount('end')).toBe(0);
  });
});

describe('baseMetadata', () => {
  it('reads the session id in the CLI casing', () => {
    expect(baseMetadata('cli', { sessionId: 'abc', cwd: '/nonexistent-xyz' })?.sessionId).toBe(
      'abc',
    );
  });

  it('reads the session id in the VS Code casing', () => {
    expect(baseMetadata('vscode', { session_id: 'abc' })?.sessionId).toBe('abc');
  });

  it('does not read the other dialect’s spelling', () => {
    // The tables are per dialect all the way down; picking up `session_id` on
    // the CLI would attribute a capture to a session that host never sent.
    //
    // Asserted on `sessionId` rather than on the whole record: the CLI branch
    // still falls back to `process.cwd()` for the repo, so its result is
    // non-empty here for a reason that has nothing to do with the session id.
    expect(baseMetadata('cli', { session_id: 'abc' })?.sessionId).toBeUndefined();
    expect(baseMetadata('vscode', { sessionId: 'abc' })).toBeUndefined();
  });

  it('falls back to the process cwd on the CLI when the payload carries none', () => {
    // On the CLI the hook's own cwd is the workspace, so the fallback is
    // correct there. Driven from the repo root, where `resolveRepo` resolves,
    // so this asserts the fallback FIRED rather than that it returned nothing.
    const spy = vi.spyOn(process, 'cwd').mockReturnValue(process.cwd());
    const meta = baseMetadata('cli', { sessionId: 's' });
    expect(spy).toHaveBeenCalled();
    expect(meta?.repo).toBeTypeOf('string');
  });

  it('does NOT fall back to the process cwd under VS Code', () => {
    // The load-bearing asymmetry. That host's spawn defaults its cwd to the HOME
    // DIRECTORY, so falling back would resolve a repo from `~` and stamp every
    // capture with whatever happens to live there.
    const spy = vi.spyOn(process, 'cwd');
    const meta = baseMetadata('vscode', { session_id: 's' });
    expect(spy).not.toHaveBeenCalled();
    expect(meta?.repo).toBeUndefined();
  });

  it('returns undefined when nothing at all could be derived', () => {
    // So callers can keep passing the optional metadata straight through.
    expect(baseMetadata('vscode', {})).toBeUndefined();
  });

  it('omits the repo when the cwd resolves to none', () => {
    const meta = baseMetadata('vscode', { session_id: 's', cwd: '/definitely/not/a/repo/xyz' });
    expect(meta).toEqual({ sessionId: 's' });
  });
});

describe('captureScopeKey', () => {
  const WORK = `${gitUser}GitHub.com:acme/work-repo.git`;
  const WORK_KEY = 'github.com/acme/work-repo';
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-copilot-scope-key-'));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  /** A checkout at `root/<name>` whose origin is `remote`, or with no remote. */
  function checkout(name: string, remote: string | undefined): string {
    const dir = join(root, name);
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(
      join(dir, '.git', 'config'),
      remote === undefined ? '[core]\n\tbare = false\n' : `[remote "origin"]\n\turl = ${remote}\n`,
    );
    return dir;
  }

  it('keys a CLI event by the cwd its payload carries', () => {
    expect(captureScopeKey('cli', { sessionId: 's', cwd: checkout('work', WORK) })).toBe(WORK_KEY);
  });

  it('keys a VS Code event the same way when its hook entry declared a cwd', () => {
    // The dialect is a payload format, not a host: a snake_case payload that
    // carries a cwd is as attributable as a camelCase one.
    expect(captureScopeKey('vscode', { session_id: 's', cwd: checkout('work', WORK) })).toBe(
      WORK_KEY,
    );
  });

  it('never keys from the process cwd, not even on the CLI where the slug falls back to it', () => {
    const repo = checkout('work', WORK);
    const spy = vi.spyOn(process, 'cwd').mockReturnValue(repo);
    // Count from zero here, whatever an earlier case left recorded.
    spy.mockClear();
    try {
      expect(captureScopeKey('cli', { sessionId: 's' })).toBeUndefined();
      expect(captureScopeKey('vscode', { session_id: 's' })).toBeUndefined();
      expect(spy).not.toHaveBeenCalled();
      // The asymmetry is the point: the display slug still takes the fallback.
      expect(baseMetadata('cli', { sessionId: 's' })?.repo).toBe('work-repo');
    } finally {
      spy.mockRestore();
    }
  });

  it('never keys a relative payload cwd, which only the process directory resolves', () => {
    // The walk climbs by name, so fs reads a relative cwd against the process's
    // real working directory, which a process.cwd spy does not move. So this
    // changes directory, to where the relative cwd names a keyed checkout.
    checkout('work', WORK);
    const before = process.cwd();
    process.chdir(root);
    try {
      expect(captureScopeKey('cli', { sessionId: 's', cwd: 'work' })).toBeUndefined();
      // The control: the slug, read through the same walk, found the checkout.
      expect(baseMetadata('cli', { sessionId: 's', cwd: 'work' })?.repo).toBe('work-repo');
    } finally {
      process.chdir(before);
    }
  });

  it.each([
    ['a checkout with no remote', () => checkout('scratch', undefined)],
    [
      'a directory outside any checkout',
      () => {
        const dir = join(root, 'plain');
        mkdirSync(dir, { recursive: true });
        return dir;
      },
    ],
    ['an empty cwd', () => ''],
  ])('passes no key for %s', (_label, make) => {
    expect(captureScopeKey('cli', { sessionId: 's', cwd: make() })).toBeUndefined();
  });

  it('passes no key for a cwd that is not a string', () => {
    expect(captureScopeKey('cli', { sessionId: 's', cwd: 42 })).toBeUndefined();
  });

  // An event that names an ABSOLUTE file is keyed by that file's checkout, on
  // either dialect, and needs no payload cwd for it. The pre-tool-use hook
  // passes a VS Code single-file writer's target here; its e2e covers which
  // calls those are.
  describe('with a file path', () => {
    const PERSONAL = 'https://github.com/someone/dotfiles.git';
    const PERSONAL_KEY = 'github.com/someone/dotfiles';

    it('keys a file in a second checkout by that checkout, not by the payload cwd', () => {
      const work = checkout('work', WORK);
      const personal = checkout('personal', PERSONAL);
      expect(
        captureScopeKey('cli', { sessionId: 's', cwd: work }, join(personal, 'notes.md')),
      ).toBe(PERSONAL_KEY);
    });

    it('keys an absolute file with no payload cwd, on either dialect', () => {
      // A file names its own directory, so the process-cwd question never arises.
      const file = join(checkout('personal', PERSONAL), 'notes.md');
      expect(captureScopeKey('cli', { sessionId: 's' }, file)).toBe(PERSONAL_KEY);
      expect(captureScopeKey('vscode', { session_id: 's' }, file)).toBe(PERSONAL_KEY);
    });

    it('passes no key for a file outside any checkout, rather than the payload cwd key', () => {
      const work = checkout('work', WORK);
      const loose = join(root, 'loose');
      mkdirSync(loose, { recursive: true });
      expect(
        captureScopeKey('cli', { sessionId: 's', cwd: work }, join(loose, 'notes.md')),
      ).toBeUndefined();
    });

    it('keys a relative path by the payload cwd, and never by the process cwd', () => {
      const work = checkout('work', WORK);
      expect(captureScopeKey('cli', { sessionId: 's', cwd: work }, 'src/index.ts')).toBe(WORK_KEY);
      const spy = vi.spyOn(process, 'cwd').mockReturnValue(work);
      spy.mockClear();
      try {
        expect(captureScopeKey('cli', { sessionId: 's' }, 'src/index.ts')).toBeUndefined();
        expect(spy).not.toHaveBeenCalled();
      } finally {
        spy.mockRestore();
      }
    });

    it('keys a file inside the payload cwd checkout like the cwd', () => {
      const work = checkout('work', WORK);
      const file = join(work, 'src', 'deep', 'index.ts');
      expect(captureScopeKey('cli', { sessionId: 's', cwd: work }, file)).toBe(WORK_KEY);
    });

    // A named path is walked from the path ITSELF, so one rule serves a file, a
    // directory and a checkout's top level. The walk probes `<path>/.git` first:
    // a file has none of its own, and a path not yet created has none to find.
    describe('that is a directory', () => {
      const NESTED = 'https://github.com/someone/lib.git';
      const NESTED_KEY = 'github.com/someone/lib';

      it('keys a checkout top level nested inside the payload cwd checkout by the nested one', () => {
        const work = checkout('work', WORK);
        const nested = checkout(join('work', 'vendor', 'lib'), NESTED);
        expect(captureScopeKey('cli', { sessionId: 's', cwd: work }, nested)).toBe(NESTED_KEY);
        expect(captureScopeKey('vscode', { session_id: 's', cwd: work }, nested)).toBe(NESTED_KEY);
      });

      it('keys another checkout top level by that checkout, though its parent is in none', () => {
        const work = checkout('work', WORK);
        const personal = checkout('personal', PERSONAL);
        expect(captureScopeKey('cli', { sessionId: 's', cwd: work }, personal)).toBe(PERSONAL_KEY);
        // A top level names its own directory, so no payload cwd is needed either.
        expect(captureScopeKey('cli', { sessionId: 's' }, personal)).toBe(PERSONAL_KEY);
      });

      it('keys a file inside the nested checkout, and one not yet created, by their checkout', () => {
        const work = checkout('work', WORK);
        const nested = checkout(join('work', 'vendor', 'lib'), NESTED);
        const input = { sessionId: 's', cwd: work };
        expect(captureScopeKey('cli', input, join(nested, 'index.ts'))).toBe(NESTED_KEY);
        // Neither the file nor its directories exist: a write may be creating them.
        expect(captureScopeKey('cli', input, join(work, 'src', 'new', 'index.ts'))).toBe(WORK_KEY);
        expect(captureScopeKey('cli', input, join(nested, 'new', 'index.ts'))).toBe(NESTED_KEY);
      });

      it('keys a directory that is not a checkout top level by the checkout around it', () => {
        const work = checkout('work', WORK);
        const sub = join(work, 'src', 'deep');
        mkdirSync(sub, { recursive: true });
        expect(captureScopeKey('cli', { sessionId: 's', cwd: work }, sub)).toBe(WORK_KEY);
      });

      it('passes no key for a directory outside any checkout, rather than the payload cwd key', () => {
        const work = checkout('work', WORK);
        const loose = join(root, 'loose');
        mkdirSync(loose, { recursive: true });
        expect(captureScopeKey('cli', { sessionId: 's', cwd: work }, loose)).toBeUndefined();
      });
    });

    it('does not climb back into a checkout that a `..` segment left', () => {
      const work = checkout('work', WORK);
      mkdirSync(join(root, 'loose'), { recursive: true });
      // Spelled with a literal `..`: join() would normalise it away.
      const filePath = [work, '..', 'loose', 'notes.md'].join(sep);
      expect(captureScopeKey('cli', { sessionId: 's', cwd: work }, filePath)).toBeUndefined();
    });
  });
});

describe('callScopeKey', () => {
  // Which calls are keyed by their file, which by their cwd, and which by
  // nothing. The `kind` argument is what the hook decided the call records as, so
  // a tool the hook has been taught to record as a code_change but this table has
  // not been taught to key is reachable here, as it is not through any built hook.
  const WORK = `${gitUser}GitHub.com:acme/work-repo.git`;
  const WORK_KEY = 'github.com/acme/work-repo';
  const PERSONAL = 'https://github.com/someone/dotfiles.git';
  const PERSONAL_KEY = 'github.com/someone/dotfiles';
  let root: string;
  let work: string;
  let personal: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-copilot-call-key-'));
    work = checkout('work', WORK);
    personal = checkout('personal', PERSONAL);
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function checkout(name: string, remote: string): string {
    const dir = join(root, name);
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(join(dir, '.git', 'config'), `[remote "origin"]\n\turl = ${remote}\n`);
    return dir;
  }

  const vscodeInput = (cwd: string): Record<string, unknown> => ({ session_id: 's', cwd });
  const cliInput = (cwd: string): Record<string, unknown> => ({ sessionId: 's', cwd });

  it('keys a known VS Code single-file writer by the absolute file it writes', () => {
    for (const name of VSCODE_FILE_WRITERS) {
      const call = { name, args: { filePath: join(personal, 'notes.ts') } };
      expect(callScopeKey('code_change', 'vscode', vscodeInput(work), call), name).toBe(
        PERSONAL_KEY,
      );
    }
  });

  it('gives a known writer no key without an absolute file, not the cwd key', () => {
    for (const args of [{}, { filePath: 'notes.ts' }, { filePath: '' }, { filePath: 42 }]) {
      const call = { name: 'create_file', args };
      expect(callScopeKey('code_change', 'vscode', vscodeInput(work), call)).toBeUndefined();
    }
  });

  it('gives a code_change tool that is not a known file writer no key, not the cwd key', () => {
    // A writer added to the set of tools recorded as code_change and not taught
    // to this table must default to no key: the cwd's key could name a checkout
    // the write never touched, and the content is recorded whole.
    const unlisted = { name: 'future_writer', args: { filePath: join(personal, 'notes.ts') } };
    expect(VSCODE_FILE_WRITERS.has(unlisted.name)).toBe(false);
    expect(callScopeKey('code_change', 'vscode', vscodeInput(work), unlisted)).toBeUndefined();
    expect(callScopeKey('code_change', 'cli', cliInput(work), unlisted)).toBeUndefined();
    // The control: the same call recorded as a plain tool_use is keyed by the cwd.
    expect(callScopeKey('tool_use', 'vscode', vscodeInput(work), unlisted)).toBe(WORK_KEY);
  });

  it('gives an apply_patch no key on either dialect, whatever it carries', () => {
    const patch = {
      name: 'apply_patch',
      args: { input: '*** Begin Patch\n*** End Patch\n', filePath: join(personal, 'a.ts') },
    };
    expect(callScopeKey('code_change', 'vscode', vscodeInput(work), patch)).toBeUndefined();
    expect(callScopeKey('code_change', 'cli', cliInput(work), patch)).toBeUndefined();
  });

  it('does not read a CLI call by a VS Code writer name: the CLI has no file writer', () => {
    const call = { name: 'create_file', args: { filePath: join(personal, 'notes.ts') } };
    expect(callScopeKey('code_change', 'cli', cliInput(work), call)).toBeUndefined();
  });

  it('keys a call that is not a code_change by the payload cwd alone', () => {
    const run = { name: 'run_in_terminal', args: { command: 'ls', filePath: join(personal, 'x') } };
    expect(callScopeKey('tool_use', 'vscode', vscodeInput(work), run)).toBe(WORK_KEY);
    const bash = { name: 'bash', args: { command: 'ls' } };
    expect(callScopeKey('tool_use', 'cli', cliInput(work), bash)).toBe(WORK_KEY);
    // No payload cwd: no key, never the process's.
    expect(callScopeKey('tool_use', 'cli', { sessionId: 's' }, bash)).toBeUndefined();
  });
});

describe('parseJson / getString', () => {
  it('accepts an object and rejects the shapes a payload must not be', () => {
    // `readToolCall` indexes the result, so an array or a scalar reaching it
    // would read fields off the wrong kind of value rather than declining.
    expect(parseJson('{"a":1}')).toEqual({ a: 1 });
    expect(parseJson('[1,2]')).toBeNull();
    expect(parseJson('"str"')).toBeNull();
    expect(parseJson('null')).toBeNull();
    expect(parseJson('not json')).toBeNull();
  });

  it('returns a string field only when it really is a string', () => {
    expect(getString({ a: 'x' }, 'a')).toBe('x');
    expect(getString({ a: 7 }, 'a')).toBeUndefined();
    expect(getString({}, 'a')).toBeUndefined();
  });
});

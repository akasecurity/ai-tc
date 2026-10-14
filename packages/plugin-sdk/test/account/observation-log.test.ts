import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { appendFileSync, constants, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { Worker } from 'node:worker_threads';

import type { SessionAccountObservation } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CLAUDE_ACCOUNT_ENV_NAMES } from '../../src/account/account-env.ts';
import { checkClaudeHook } from '../../src/account/claude-validate.ts';
import {
  appendObservation,
  latestBoundary,
  readObservations,
  readObservationTail,
  sessionAccountHash,
  sessionLogOpenFlags,
  sessionLogPath,
  sessionScanCachePath,
  sessionStateName,
} from '../../src/account/observation-log.ts';
import type { ClaudeMachine } from '../helpers/transcript-builder.ts';
import {
  claudeMachine,
  credentialOrgLine,
  SECOND,
  T0,
  workConfig,
  writeLines,
} from '../helpers/transcript-builder.ts';

let machine: ClaudeMachine;
let dir: string;
let sid: string;

beforeEach(() => {
  for (const name of CLAUDE_ACCOUNT_ENV_NAMES) vi.stubEnv(name, undefined);
  machine = claudeMachine();
  dir = machine.stateDir;
  sid = machine.sessionId;
});

afterEach(() => {
  vi.unstubAllEnvs();
  machine.dispose();
});

const view = (t: number, bd: string = machine.bindingHash): SessionAccountObservation => ({
  t,
  bd,
  k: 'n',
});
const lines = (): unknown[] =>
  readFileSync(sessionLogPath(dir, sid), 'utf8')
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line) as unknown);

describe('appendObservation', () => {
  it('appends one parseable line per observation, to an owner-only file', () => {
    expect(appendObservation(dir, sid, { t: T0, b: 'startup' })).toBe(true);
    expect(appendObservation(dir, sid, view(T0 + SECOND))).toBe(true);
    expect(lines()).toEqual([{ t: T0, b: 'startup' }, view(T0 + SECOND)]);
    if (process.platform !== 'win32') {
      expect(statSync(sessionLogPath(dir, sid)).mode & 0o777).toBe(0o600);
      expect(statSync(dir).mode & 0o777).toBe(0o700);
    }
  });

  it('refuses a line that is not a session-state shape, and writes nothing', () => {
    const bad = { t: 'yesterday', b: 'startup' } as unknown as SessionAccountObservation;
    expect(appendObservation(dir, sid, bad)).toBe(false);
    expect(readObservations(dir, sid).entries).toEqual([]);
  });

  it('stops appending at the cap', () => {
    const cap = 2 * (JSON.stringify(view(T0)).length + 1);
    expect(appendObservation(dir, sid, view(T0), cap)).toBe(true);
    expect(appendObservation(dir, sid, view(T0 + 1), cap)).toBe(true);
    expect(appendObservation(dir, sid, view(T0 + 2), cap)).toBe(false);
    expect(readObservations(dir, sid).entries).toHaveLength(2);
  });

  it('opens the log without O_NOFOLLOW where the platform has no such flag', () => {
    expect(sessionLogOpenFlags(undefined)).toBe(
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT,
    );
  });

  it.each([
    ['with O_NOFOLLOW', sessionLogOpenFlags((constants as { O_NOFOLLOW?: number }).O_NOFOLLOW)],
    ['without O_NOFOLLOW, as on win32', sessionLogOpenFlags(undefined)],
  ] as const)('keeps every line two concurrent appenders write, %s', async (_label, openFlags) => {
    const count = 200;
    const shared = new SharedArrayBuffer(8);
    const slots = new Int32Array(shared);
    const workers = [0, 1].map(
      () =>
        new Worker(new URL('../helpers/observation-append-worker.ts', import.meta.url), {
          workerData: {
            stateDir: dir,
            sessionId: sid,
            bindingHash: machine.bindingHash,
            count,
            shared,
            openFlags,
          },
        }),
    );
    const done = workers.map(
      (worker) =>
        new Promise<{ written: number }>((resolve, reject) => {
          worker.once('message', resolve);
          worker.once('error', reject);
        }),
    );
    while (Atomics.load(slots, 0) < workers.length)
      Atomics.wait(slots, 0, Atomics.load(slots, 0), 50);
    Atomics.store(slots, 1, 1);
    Atomics.notify(slots, 1);
    const results = await Promise.all(done);
    expect(results.map((r) => r.written)).toEqual([count, count]);
    expect(lines()).toHaveLength(2 * count);
    expect(readObservations(dir, sid).entries).toHaveLength(2 * count);
  });
});

describe('readObservations', () => {
  it('reads from an offset, skipping a malformed line and an unfinished one', () => {
    appendObservation(dir, sid, view(T0));
    const first = readObservations(dir, sid);
    appendFileSync(sessionLogPath(dir, sid), '{"t": "not a time"}\n');
    appendObservation(dir, sid, view(T0 + SECOND));
    const unfinished = '{"t": 1';
    appendFileSync(sessionLogPath(dir, sid), unfinished);
    const next = readObservations(dir, sid, first.size);
    expect(next.entries.map((entry) => entry.observation.t)).toEqual([T0 + SECOND]);
    expect(next.entries.at(-1)?.end).toBe(
      statSync(sessionLogPath(dir, sid)).size - unfinished.length,
    );
  });

  it('answers an empty read for a session with no log', () => {
    expect(readObservations(dir, randomUUID()).entries).toEqual([]);
  });

  it('reads the last window of a long log, whole lines only', () => {
    for (let i = 0; i < 50; i += 1) appendObservation(dir, sid, view(T0 + i));
    const tail = readObservationTail(dir, sid, 256);
    expect(tail.complete).toBe(false);
    expect(tail.entries.length).toBeGreaterThan(0);
    expect(tail.entries.at(-1)?.t).toBe(T0 + 49);
    expect(readObservationTail(dir, sid).complete).toBe(true);
  });
});

describe('latestBoundary', () => {
  it('finds the latest boundary, inherited only through a line of the current binding', () => {
    const entries: SessionAccountObservation[] = [
      { t: T0, b: 'startup' },
      view(T0 + 1),
      { t: T0 + 10, b: 'resume' },
      { t: T0 + 10, bd: randomBytes(8).toString('hex'), inh: true },
    ];
    expect(latestBoundary(entries, machine.bindingHash)).toEqual({
      t: T0 + 10,
      kind: 'resume',
      inherited: false,
    });
    entries.push({ t: T0 + 10, bd: machine.bindingHash, inh: true });
    expect(latestBoundary(entries, machine.bindingHash)).toEqual({
      t: T0 + 10,
      kind: 'resume',
      inherited: true,
    });
    expect(latestBoundary([view(T0)], machine.bindingHash)).toBeUndefined();
  });
});

describe('session state names and hashes', () => {
  it('names a session file by its id when it is a plain token, by its hash otherwise', () => {
    const id = randomUUID();
    expect(sessionStateName(id)).toBe(id);
    for (const hostile of ['../escape', '.', '..', 'a/b', '']) {
      expect(sessionStateName(hostile)).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(sessionLogPath(dir, id)).toBe(join(dir, `${id}.log`));
    expect(sessionScanCachePath(dir, id)).toBe(join(dir, `${id}.scan.json`));
  });

  it('hashes an account key under its own prefix', () => {
    const key = `claude:${randomUUID()}`;
    expect(sessionAccountHash(key)).toMatch(/^[0-9a-f]{64}$/);
    expect(sessionAccountHash(key)).not.toBe(createHash('sha256').update(key).digest('hex'));
  });
});

describe('privacy of the session state', () => {
  it('a personal session leaves no uuid, hash or email bytes in session-accounts', () => {
    const personal = randomUUID();
    const work = randomUUID();
    appendObservation(dir, sid, { t: T0, b: 'startup' });
    writeLines(machine.transcript, [credentialOrgLine(sid, personal, T0 + SECOND)]);
    const input = {
      dataDir: machine.dataDir,
      sessionId: sid,
      transcriptPath: machine.transcript,
      cwd: machine.cwd,
      ctx: machine.context(),
      paths: machine.paths,
    };
    machine.writeConfig(workConfig(personal, machine.email, { organizationType: 'claude_max' }));
    expect(checkClaudeHook({ ...input, now: () => T0 + 2 * SECOND }).check).toEqual({
      none: 'plan',
    });
    machine.writeConfig(workConfig(work, machine.email));
    expect(checkClaudeHook({ ...input, now: () => T0 + 3 * SECOND }).check).toEqual({
      none: 'login-changed',
    });
    const bytes = readdirSync(dir)
      .map((name) => readFileSync(join(dir, name), 'utf8'))
      .join('\n');
    expect(bytes.length).toBeGreaterThan(0);
    for (const needle of [
      personal,
      personal.replaceAll('-', ''),
      sessionAccountHash(`claude:${personal}`),
      machine.email,
      machine.email.split('@')[0] ?? machine.email,
    ]) {
      expect(bytes).not.toContain(needle);
    }
  });
});

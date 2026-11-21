// Tests the store-health module directly — NEVER via the hook entry files
// (src/hooks/*.ts run main() on import and hang vitest collection). The other
// plugins carry their own copy of the module and of these tests.
import { randomUUID } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { dataDir as dataDirOf, StoreAheadOfBuildError } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  claimStoreUnavailableWarning,
  openGateway,
  openGatewayOrNull,
  storeBusyMessage,
  storeDegradedMessage,
  storeOpenCause,
  storeRedirectedMessage,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from '../../src/hooks/store-health.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

function configFor(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 1,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
    },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: join(dataDir, 'settings'),
    onboarded: false,
    provider: { provider: 'openai' },
  };
}

describe('openGatewayOrNull — observable store-open failure', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-health-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns null when aka.db is not a database (corrupt bytes)', () => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'aka.db'), 'garbage bytes, definitely not sqlite');

    expect(openGatewayOrNull(configFor(dir))).toBeNull();
  });

  it('returns a working gateway for a healthy (fresh) data dir', async () => {
    const gateway = openGatewayOrNull(configFor(dir));
    expect(gateway).not.toBeNull();
    await gateway?.close();
  });
});

describe('claimStoreUnavailableWarning — once per session', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-warn-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('warns on the first claim of a session, then stays quiet for that session', () => {
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(false);
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(false);
  });

  it('a NEW session warns again', () => {
    expect(claimStoreUnavailableWarning(dir, 'sess-1')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'sess-2')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'sess-2')).toBe(false);
  });

  it('two sessions alternating claims each warn exactly once', () => {
    const warned = ['sess-1', 'sess-2', 'sess-1', 'sess-2', 'sess-1', 'sess-2'].filter((id) =>
      claimStoreUnavailableWarning(dir, id),
    );
    expect(warned).toEqual(['sess-1', 'sess-2']);
  });

  it('keeps a bounded id list, newest last, and evicts the oldest', () => {
    for (let i = 0; i < 100; i += 1) claimStoreUnavailableWarning(dir, `s${String(i)}`);
    const ids = readFileSync(join(dir, 'store-warning-last-session'), 'utf8').split('\n');
    expect(ids).toHaveLength(32);
    expect(ids.at(-1)).toBe('s99');
    expect(ids).not.toContain('s0');
    expect(claimStoreUnavailableWarning(dir, 's0')).toBe(true);
  });

  it('reads a marker written by an older build that held a single id', () => {
    writeFileSync(join(dir, 'store-warning-last-session'), 's1');
    expect(claimStoreUnavailableWarning(dir, 's1')).toBe(false);
    expect(claimStoreUnavailableWarning(dir, 's2')).toBe(true);
  });

  it('refuses an id carrying a newline: it always warns and is never recorded', () => {
    expect(claimStoreUnavailableWarning(dir, 'a\nb')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'a\nb')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'a')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'b')).toBe(true);
    expect(claimStoreUnavailableWarning(dir, 'a')).toBe(false);
  });

  it('with no session id it cannot dedupe and always warns', () => {
    expect(claimStoreUnavailableWarning(dir, undefined)).toBe(true);
    expect(claimStoreUnavailableWarning(dir, undefined)).toBe(true);
  });
});

describe('storeUnavailableMessage', () => {
  it('names the store path, says detection is off, and stays fail-open in tone', () => {
    const message = storeUnavailableMessage('/home/u/.aka/data/aka.db');
    expect(message).toContain('/home/u/.aka/data/aka.db');
    expect(message).toContain('OFF for this session');
    expect(message).toContain('fails open');
  });
});

// A symlinked store path is the OTHER way a session looks protected while it is
// not what the user thinks: everything is scanned and recorded, but into someone
// else's directory, under permissions AKA never applied. The store opens fine, so
// the unavailable-store warning above can never reach it.
describe('warnIfStoreRedirected — a symlinked store path is surfaced', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-redirect-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // The home is derived from `dataDir` because PluginConfig carries the leaves
  // and not the base. If the layout ever stops putting data/ directly under the
  // base, this is the assertion that says so — without it the derivation would
  // silently start reporting the wrong directory, i.e. no directory at all.
  it('derives the store home from dataDir exactly as the layout builds it', () => {
    const home = join(dir, 'somewhere');
    expect(dataDirOf(home)).toBe(join(home, 'data'));
  });

  it('two sessions alternating each get the redirect warning exactly once', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const victim = join(dir, 'victim-alt');
    mkdirSync(victim, { mode: 0o755 });
    const home = join(dir, 'linked-home-alt');
    symlinkSync(victim, home);
    mkdirSync(dataDirOf(home), { recursive: true });
    const config = configFor(dataDirOf(home));
    const written: string[] = [];
    for (const id of ['s1', 's2', 's1', 's2', 's1', 's2']) {
      warnIfStoreRedirected(config, id, (m) => written.push(m));
    }
    expect(written).toHaveLength(2);
  });

  it('a session id carrying a newline cannot dedupe: it warns every time and is never recorded', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const victim = join(dir, 'victim-newline');
    mkdirSync(victim, { mode: 0o755 });
    const home = join(dir, 'linked-home-newline');
    symlinkSync(victim, home);
    mkdirSync(dataDirOf(home), { recursive: true });
    const config = configFor(dataDirOf(home));
    const written: string[] = [];
    for (let i = 0; i < 3; i++) {
      warnIfStoreRedirected(config, 's1\ns2', (m) => written.push(m));
    }
    expect(written).toHaveLength(3);
    // The ids the newline would have split into are not recorded either, so a
    // genuine session of the same name still gets its own warning.
    warnIfStoreRedirected(config, 's1', (m) => written.push(m));
    warnIfStoreRedirected(config, 's2', (m) => written.push(m));
    expect(written).toHaveLength(5);
  });

  it('says nothing at all when no store path is a symlink', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const home = join(dir, 'real-home');
    mkdirSync(dataDirOf(home), { recursive: true });
    const written: string[] = [];
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    expect(written).toEqual([]);
  });

  it('warns once per session, naming the target and its non-owner-only mode', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    const victim = join(dir, 'victim');
    mkdirSync(victim, { mode: 0o755 });
    const home = join(dir, 'linked-home');
    symlinkSync(victim, home);
    mkdirSync(dataDirOf(home), { recursive: true });

    const written: string[] = [];
    const config = configFor(dataDirOf(home));
    warnIfStoreRedirected(config, 's1', (m) => written.push(m));

    expect(written).toHaveLength(1);
    const message = written[0] ?? '';
    // The link, where it really lands, and the permission the store inherits —
    // the three facts nothing else on the plugin path can tell the user.
    expect(message).toContain(home);
    expect(message).toContain(realpathSync(victim));
    expect(message).toContain('0755');
    expect(message).toContain('NOT owner-only');

    // Same session → silent. A per-hook warning would fire on every tool call.
    warnIfStoreRedirected(config, 's1', (m) => written.push(m));
    expect(written).toHaveLength(1);

    // A new session is told again: the condition is still true, and the marker
    // is one overwritten file rather than an accumulating set.
    warnIfStoreRedirected(config, 's2', (m) => written.push(m));
    expect(written).toHaveLength(2);
  });

  it('never throws on a hostile home — the warning is advisory, the hook is not', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('unprivileged symlink creation is not available on Windows');
      return;
    }
    // A store path whose link resolves NOWHERE: nothing to stat, nothing to
    // create through, and the marker write below it cannot land either.
    const home = join(dir, 'dangling-home');
    mkdirSync(home);
    symlinkSync(join(dir, 'no-such-volume'), join(home, 'data'));
    const written: string[] = [];
    expect(() => {
      warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    }).not.toThrow();
    // It is still REPORTED — a link that resolves nowhere is exactly the state a
    // user needs told about, and reporting nothing here would read as healthy.
    expect(written).toHaveLength(1);
    expect(written[0] ?? '').toContain('does not exist');

    // …and STILL only once. data/ is unwritable here, so the marker cannot land
    // in its natural home; without the fallback candidate the claim is never
    // recorded and every later hook fire in the session warns again — a fresh
    // multi-line warning on every tool call, in the very configuration this
    // feature exists to report. Driving it a second and third time is the whole
    // point: calling once cannot tell a working dedupe from an absent one.
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's1', (m) => written.push(m));
    expect(written).toHaveLength(1);

    // A different session is still told, so the fallback dedupes rather than
    // silences.
    warnIfStoreRedirected(configFor(dataDirOf(home)), 's2', (m) => written.push(m));
    expect(written).toHaveLength(2);
  });
});

describe('storeRedirectedMessage', () => {
  it('reports an owner-only target without the "NOT owner-only" claim', () => {
    const message = storeRedirectedMessage([
      {
        path: '/home/u/.aka',
        target: '/mnt/other',
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: 0o700,
      },
    ]);
    expect(message).toContain('0700');
    expect(message).not.toContain('NOT owner-only');
    // The redirection is still the story even when the mode is fine.
    expect(message).toContain('/mnt/other');
  });

  it('does not claim a write or an inherited mode when the link resolves NOWHERE', () => {
    // Nothing has been written and nothing inherited, so both of the framing
    // clauses would be false — the same three-shapes reasoning `symlinkWarnings`
    // records, applied to the one-line form.
    const message = storeRedirectedMessage([
      {
        path: '/home/u/.aka/keys',
        target: '/no/such/volume',
        holds: 'the vault key',
        missing: true,
        mode: undefined,
      },
    ]);
    expect(message).toContain('does not exist');
    expect(message).toContain('cannot write there');
    expect(message).not.toContain('writing into the target instead');
    expect(message).not.toContain('keeps whatever the target already had');
  });

  it('drops the permissions clause on Windows, where no mode is ever applied', () => {
    const path = {
      path: 'C:\\Users\\u\\.aka',
      target: 'D:\\elsewhere',
      holds: 'the store (including the prompt corpus in aka.db)',
      missing: false,
      mode: undefined,
    };
    // The redirection still stands on Windows — a junction needs no elevation —
    // but claiming the target's permissions are kept describes a control that
    // platform does not have.
    expect(storeRedirectedMessage([path], 'win32')).not.toContain(
      'keeps whatever the target already had',
    );
    expect(storeRedirectedMessage([path], 'win32')).toContain('writing into the target instead');
    // …and the POSIX branch still carries it.
    expect(storeRedirectedMessage([path], 'linux')).toContain(
      'keeps whatever the target already had',
    );
  });

  it('counts the paths it lists rather than always saying "a store path"', () => {
    const one = {
      path: '/home/u/.aka',
      target: '/mnt/a',
      holds: 'the store (including the prompt corpus in aka.db)',
      missing: false,
      mode: 0o700,
    };
    const two = { ...one, path: '/home/u/.aka/keys', target: '/mnt/b', holds: 'the vault key' };
    expect(storeRedirectedMessage([one], 'linux')).toContain('a store path is a symlink');
    const both = storeRedirectedMessage([one, two], 'linux');
    expect(both).toContain('2 store paths are symlinks');
    expect(both).toContain('/mnt/a');
    expect(both).toContain('/mnt/b');
  });

  it('reports no mode at all when there is none to inherit (Windows, or no target)', () => {
    const message = storeRedirectedMessage([
      {
        path: 'C:\\Users\\u\\.aka',
        target: 'D:\\elsewhere',
        holds: 'the store (including the prompt corpus in aka.db)',
        missing: false,
        mode: undefined,
      },
    ]);
    expect(message).toContain('D:\\elsewhere');
    // An absent mode must never be rendered as a safe one.
    expect(message).not.toContain('0700');
    expect(message).not.toContain('NOT owner-only');
  });
});

// Which message the user gets is decided by WHY the open failed, so the reason
// has to survive the open. It used to be swallowed by a bare catch, which made
// a store written by a newer AKA build read exactly like an unreadable one —
// and sent the user to move an intact corpus aside over a stale binary.
describe('openGateway — the reason survives the failure', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-reason-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('carries the failure out instead of collapsing it to null', () => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'aka.db'), 'garbage bytes, definitely not sqlite');

    const opened = openGateway(configFor(dir));

    expect(opened.gateway).toBeNull();
    expect(opened.error).toBeInstanceOf(Error);
  });

  it('reports no error at all when the store opens', async () => {
    const opened = openGateway(configFor(dir));

    expect(opened.gateway).not.toBeNull();
    expect(opened.error).toBeUndefined();
    await opened.gateway?.close();
  });
});

describe('storeDegradedMessage — one message per cause', () => {
  const DB = '/home/u/.aka/data/aka.db';
  const skew = new StoreAheadOfBuildError(
    { storeVersion: 42, buildVersion: 35, unknownTags: ['0035_from_a_newer_build'] },
    new Error('cannot UPSERT a view'),
  );

  it('names the version gap for a store written by a newer build', () => {
    const message = storeDegradedMessage(DB, skew, 'tool call');

    expect(message).toContain(DB);
    expect(message).toContain('0035_from_a_newer_build');
    expect(message).toContain('42');
    expect(message).toContain('35');
    expect(message).toContain('OFF for this session');
  });

  it('never tells the user to move an intact store aside', () => {
    expect(storeDegradedMessage(DB, skew, 'tool call')).not.toMatch(
      /aside|recreate|corrupt|permission/i,
    );
  });

  // The positive control for the assertion above: the GENERIC message really
  // does carry that advice, so the absence check is a property of the skew
  // branch rather than something both branches satisfy by accident.
  it('keeps the file-repair advice for a failure that is not skew', () => {
    const message = storeDegradedMessage(
      DB,
      new Error('database disk image is malformed'),
      'tool call',
    );

    expect(message).toBe(storeUnavailableMessage(DB));
    expect(message).toMatch(/aside/i);
  });

  it('falls back to the generic message when there is no error to read', () => {
    expect(storeDegradedMessage(DB, undefined, 'tool call')).toBe(storeUnavailableMessage(DB));
  });
});

// The generic warning used to hide WHICH failure it was, so a store that was
// merely locked by another process read exactly like a corrupt one. These cases
// drive real node:sqlite errors, never hand-built ones, so the fields read are
// the ones the engine actually sets.
describe('storeDegradedMessage — the failure is named', () => {
  const DB = '/home/u/.aka/data/aka.db';
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-store-cause-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  // A connection holding the file exclusively refuses another connection's
  // first statement at once when that connection set no busy timeout, which
  // yields a real SQLITE_BUSY without waiting.
  function busyError(): unknown {
    const file = join(dir, 'held.db');
    const holder = new DatabaseSync(file);
    const victim = new DatabaseSync(file);
    try {
      holder.exec('PRAGMA journal_mode = WAL');
      holder.exec('CREATE TABLE t (x INTEGER)');
      holder.exec('PRAGMA locking_mode = EXCLUSIVE');
      holder.exec('BEGIN EXCLUSIVE');
      holder.prepare('SELECT count(*) FROM t').get();
      try {
        victim.exec('PRAGMA journal_mode = WAL');
        return undefined;
      } catch (err) {
        return err;
      }
    } finally {
      victim.close();
      holder.exec('ROLLBACK');
      holder.close();
    }
  }

  it('names a lock held by another process and gives no repair advice', () => {
    const err = busyError();
    expect(err).toBeDefined();

    const message = storeDegradedMessage(DB, err, 'tool call');

    expect(message).toBe(
      storeBusyMessage(
        DB,
        { text: 'SQLite error 5: database is locked', lock: 'busy' },
        'tool call',
      ),
    );
    expect(message).toContain('another process held it locked');
    expect(message).toContain('skipped for this tool call');
    expect(message).toContain(DB);
    expect(message).toContain('fails open');
    expect(message).not.toMatch(/aside|recreate|corrupt/i);
  });

  it('names the SQLite code on the generic message for an unreadable store', () => {
    writeFileSync(join(dir, 'aka.db'), 'garbage bytes, definitely not sqlite');
    const opened = openGateway(configFor(dir));
    expect(opened.gateway).toBeNull();

    const message = storeDegradedMessage(DB, opened.error, 'tool call');

    expect(message).toContain('(SQLite error 26: file is not a database)');
    expect(message).toMatch(/aside/i);
    expect(message).toBe(storeUnavailableMessage(DB, 'SQLite error 26: file is not a database'));
  });

  it('names a filesystem code without the error message that came with it', () => {
    const secret = `k${randomUUID().replaceAll('-', '')}`;
    const err = Object.assign(new Error(`EACCES: permission denied, mkdir '/x/${secret}'`), {
      code: 'EACCES',
    });

    const message = storeDegradedMessage(DB, err, 'tool call');

    expect(message).toContain('(EACCES)');
    expectNoEchoOf(message, secret);
  });

  it("reads only the code and SQLite's own description, never the message", () => {
    const secret = `k${randomUUID().replaceAll('-', '')}`;
    const err = Object.assign(new Error(`near "${secret}": syntax error`), {
      errcode: 1,
      errstr: 'SQL logic error',
    });

    const message = storeDegradedMessage(DB, err, 'tool call');

    expect(message).toContain('(SQLite error 1: SQL logic error)');
    expectNoEchoOf(message, secret);
  });

  it("drops a description that is not shaped like SQLite's own", () => {
    const secret = `/Users/someone/${randomUUID()}`;
    expect(storeOpenCause({ errcode: 14, errstr: secret })).toEqual({
      text: 'SQLite error 14',
      lock: undefined,
    });
  });

  it('says nothing extra when the error carries no code', () => {
    expect(storeOpenCause(new Error('database disk image is malformed'))).toBeUndefined();
    expect(storeOpenCause(undefined)).toBeUndefined();
    expect(storeOpenCause({ code: 'not a code' })).toBeUndefined();
  });

  it('tells SQLITE_LOCKED apart from BUSY, and reads an extended BUSY code as BUSY', () => {
    expect(storeOpenCause({ errcode: 6, errstr: 'database table is locked' })?.lock).toBe('locked');
    expect(storeOpenCause({ errcode: 517, errstr: 'database is locked' })?.lock).toBe('busy');
    const corrupt = storeOpenCause({ errcode: 11, errstr: 'database disk image is malformed' });
    expect(corrupt?.lock).toBeUndefined();
  });

  it('names SQLITE_LOCKED by its code alone, without the other-process story', () => {
    const message = storeDegradedMessage(
      DB,
      { errcode: 6, errstr: 'database table is locked' },
      'tool call',
    );
    expect(message).toContain('because it was locked (SQLite error 6: database table is locked)');
    expect(message).not.toMatch(/another process|longer than AKA waits/);
    expect(message).not.toMatch(/aside|recreate|corrupt/i);
  });

  it('names the prompt, not a tool call, when a prompt hook hits the lock', () => {
    const message = storeDegradedMessage(
      DB,
      { errcode: 5, errstr: 'database is locked' },
      'prompt',
    );
    expect(message).toContain('skipped for this prompt');
    expect(message).not.toContain('tool call');
  });
});

describe('the event each hook names on a locked store', () => {
  it.each([
    ['pre-tool-use-run.ts', 'tool call', 'error'],
    ['post-tool-use-run.ts', 'tool result', 'error'],
    ['user-prompt-submit-run.ts', 'prompt', 'error'],
  ])('%s names a %s', (file: string, subject: string, errorArg: string) => {
    const source = readFileSync(new URL(`../../src/hooks/${file}`, import.meta.url), 'utf8');
    expect(source).toContain(`storeDegradedMessage(config.dbPath, ${errorArg}, '${subject}')`);
  });
});

describe('a lock met after the call ran', () => {
  it('says only the scan and recording of the tool result were skipped', () => {
    const message = storeDegradedMessage(
      '/home/u/.aka/data/aka.db',
      { errcode: 5, errstr: 'database is locked' },
      'tool result',
    );
    expect(message).toContain('Scanning and recording were skipped for this tool result');
    expect(message).not.toMatch(/enforcement|tool call/u);
  });
});

// The migration that re-keys a stored enrolment whose spelling this build no
// longer stamps.
//
// The assertion that MATTERS here is not what the record looks like — the
// editor's own suite covers that — but that the repository FORWARDS again. A
// scope key is matched against what a user enrolled by exact string, so an entry
// under a spelling the canonical form has moved away from reads as enrolled and
// matches nothing, with no error anywhere to say so. So every case ends at
// `resolveScope`, through the same `scopeVerdict` shape the forwarders use,
// rather than at the bytes on disk.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { resolveScope } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { respellStoredEnrolments } from '../src/enrolment-respell.ts';
import { enrollableRepoKey } from '../src/repo-key.ts';
import { readUserSettings } from '../src/settings.ts';
import { UNSAFE_TEST_ONLY_setSshHostAliases } from '../src/ssh-hosts.ts';

const ENDPOINT = 'https://plane.example.test';
const ISO = '2026-10-07T09:00:00.000Z';
// What a checkout of that repository stamps on its events today.
const STAMPED = 'github.com/acme/app';

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-respell-'));
});

afterEach(() => {
  UNSAFE_TEST_ONLY_setSshHostAliases(new Map());
  rmSync(base, { recursive: true, force: true });
});

function settingsFile(): string {
  return join(base, 'settings', 'settings.json');
}

function writeSettings(contents: unknown): void {
  mkdirSync(join(base, 'settings'), { recursive: true });
  writeFileSync(settingsFile(), JSON.stringify(contents, null, 2));
}

function attachedWith(entries: readonly unknown[], extra: Record<string, unknown> = {}): unknown {
  return {
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
    attachmentScope: {
      endpoint: ENDPOINT,
      tenantName: 'Acme Payments',
      userEmail: 'member-17',
      entries,
      ...extra,
    },
    onboardedAt: ISO,
  };
}

/** Whether a scoped attachment reading the file on disk would forward `key`. */
function forwards(key: string): boolean {
  return resolveScope({
    mode: 'scoped',
    scope: readUserSettings(base).attachmentScope,
    endpoint: ENDPOINT,
  }).keys.has(key);
}

function storedIdentities(): readonly unknown[] {
  const scope: unknown = readUserSettings(base).attachmentScope;
  const entries: unknown = (scope as { entries?: unknown }).entries;
  return (entries as readonly { identity?: unknown }[]).map((entry) => entry.identity);
}

describe('respellStoredEnrolments', () => {
  it('makes an entry stored under the pre-change spelling forward again', () => {
    // A capitalised path, enrolled when the canonical form kept path case. A
    // checkout on a case-insensitive forge stamps the folded key, so this
    // entry matched nothing.
    writeSettings(
      attachedWith([{ kind: 'repo', identity: 'github.com/Acme/App', enrolledAt: ISO }]),
    );
    expect(forwards(STAMPED)).toBe(false);

    expect(respellStoredEnrolments(base)).toBe('rewritten');

    expect(forwards(STAMPED)).toBe(true);
    expect(storedIdentities()).toStrictEqual([STAMPED]);
  });

  it('makes an entry stored under an SSH alias forward again', () => {
    // `gh-personal` is a host only because ~/.ssh/config says so. The machine
    // is the only place that mapping exists, which is why the rewrite happens
    // here and not on the deployment.
    UNSAFE_TEST_ONLY_setSshHostAliases(new Map([['gh-personal', 'github.com']]));
    writeSettings(
      attachedWith([{ kind: 'repo', identity: 'gh-personal/acme/app', enrolledAt: ISO }]),
    );
    expect(forwards(STAMPED)).toBe(false);

    expect(respellStoredEnrolments(base)).toBe('rewritten');

    expect(forwards(STAMPED)).toBe(true);
  });

  it('is a NO-OP on a record whose keys are already canonical', () => {
    // Byte-for-byte, not merely equivalent: this is the steady state, reached on
    // every sync pass, so the pass must not rewrite settings.json for ever.
    writeSettings(attachedWith([{ kind: 'repo', identity: STAMPED, enrolledAt: ISO }]));
    const before = readFileSync(settingsFile(), 'utf8');

    expect(respellStoredEnrolments(base)).toBe('skipped');

    expect(readFileSync(settingsFile(), 'utf8')).toBe(before);
    expect(forwards(STAMPED)).toBe(true);
  });

  it('does not stamp onboardedAt onto a machine that never onboarded', () => {
    // `applyOnboarding` stamps it on every write, so a pass that reached it
    // unconditionally would mark an un-onboarded machine as onboarded and kill
    // the first-run nudge. The gate ahead of the lock is what prevents that.
    writeSettings({ runMode: 'standalone' });

    expect(respellStoredEnrolments(base)).toBe('skipped');

    expect(readUserSettings(base).onboardedAt).toBeUndefined();
  });

  it('is idempotent: the second pass writes nothing', () => {
    writeSettings(
      attachedWith([{ kind: 'repo', identity: 'github.com/Acme/App', enrolledAt: ISO }]),
    );
    expect(respellStoredEnrolments(base)).toBe('rewritten');
    const after = readFileSync(settingsFile(), 'utf8');

    expect(respellStoredEnrolments(base)).toBe('skipped');
    expect(readFileSync(settingsFile(), 'utf8')).toBe(after);
  });

  it('keeps the binding, the opt-out and a key a newer build wrote', () => {
    writeSettings(
      attachedWith([{ kind: 'repo', identity: 'github.com/Acme/App', enrolledAt: ISO }], {
        workSubscriptions: 'off',
        somethingNewerBuildsWrite: { nested: true },
      }),
    );

    expect(respellStoredEnrolments(base)).toBe('rewritten');

    expect(readUserSettings(base).attachmentScope).toStrictEqual({
      endpoint: ENDPOINT,
      tenantName: 'Acme Payments',
      userEmail: 'member-17',
      workSubscriptions: 'off',
      somethingNewerBuildsWrite: { nested: true },
      entries: [{ kind: 'repo', identity: STAMPED, enrolledAt: ISO }],
    });
  });

  it('runs on a record for a deployment the machine has since left', () => {
    // No endpoint is consulted: a stale spelling matches nothing whichever
    // deployment the record names, and skipping would only re-key it the day
    // the machine attached back.
    writeSettings({
      runMode: 'standalone',
      attachmentScope: {
        endpoint: 'https://old.example.test',
        entries: [{ kind: 'repo', identity: 'github.com/Acme/App', enrolledAt: ISO }],
      },
      onboardedAt: ISO,
    });

    expect(respellStoredEnrolments(base)).toBe('rewritten');
    expect(storedIdentities()).toStrictEqual([STAMPED]);
  });

  it('leaves an entry no spelling can be worked out for, and says nothing changed', () => {
    // One path segment: an owner's page rather than a repository, so nothing
    // enrollable comes back. `aka status` names it; a guess cached here would
    // file the enrolment under a second key no checkout stamps either.
    const orphan = 'github.com/acme';
    expect(enrollableRepoKey(orphan)).toBeUndefined();
    writeSettings(attachedWith([{ kind: 'repo', identity: orphan, enrolledAt: ISO }]));
    const before = readFileSync(settingsFile(), 'utf8');

    expect(respellStoredEnrolments(base)).toBe('skipped');
    expect(readFileSync(settingsFile(), 'utf8')).toBe(before);
  });

  it('reports failure rather than throwing when the record cannot be written', () => {
    // A directory where settings.json belongs: the gate reads nothing, so there
    // is nothing to respell and the pass skips. What must not happen on any
    // unwritable home is a throw — this runs in a detached child with nothing
    // watching it.
    mkdirSync(settingsFile(), { recursive: true });

    expect(() => respellStoredEnrolments(base)).not.toThrow();
  });

  it('has nothing to do on a machine with no settings file at all', () => {
    expect(respellStoredEnrolments(base)).toBe('skipped');
    expect(() => readFileSync(settingsFile(), 'utf8')).toThrow();
  });
});

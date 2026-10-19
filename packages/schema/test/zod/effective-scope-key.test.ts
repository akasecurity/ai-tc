import { describe, expect, it } from 'vitest';

import { effectiveScopeKey } from '../../src/zod/agent-scope.ts';
import type { AttachmentMode } from '../../src/zod/control-plane.ts';
import type { ResolvedAttachmentScope } from '../../src/zod/local.ts';

// Which key a row is stamped with. Repository first: a row in an enrolled
// repository keeps that key whatever account its session runs under. Only then
// may an agent key, and only one the attachment's own scope holds, stand in for
// it. S enrolls a repository, an agent key and a bare account key (a web chat
// enrollment), so a wrong rule always has something in scope to pick.
const WORK = 'github.com/acme/payments-api';
const PERSONAL = 'github.com/someone/dotfiles';
const TAG = '0123456789abcdef';
const ACCOUNT = 'claude:2ef4cd3c-c23c-473a-96be-1275cfc79103';
const AGENT = `agent:${TAG}:${ACCOUNT}`;
const OTHER_AGENT = `agent:${TAG}:claude:f6793695-e29b-47e4-9473-c77e9ba752e9`;
const MALFORMED = `agent:${TAG}:claude:not-a-uuid`;

const S: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set([WORK, AGENT, ACCOUNT]) };
// A machine-wide scope's keys are never consulted. These are here so a rule
// that did consult them would find something.
const MACHINE: ResolvedAttachmentScope = {
  mode: 'machine',
  keys: new Set([WORK, AGENT, ACCOUNT]),
};

const ACCOUNTS = [
  ['no account', undefined],
  ['an enrolled agent key', AGENT],
  ['an agent key not enrolled', OTHER_AGENT],
  ['a malformed agent key', MALFORMED],
  ['an enrolled repository key passed as the account', WORK],
  ['an enrolled bare account key', ACCOUNT],
] as const;

describe('effectiveScopeKey', () => {
  it('an enrolled repository keeps its key whatever the account', () => {
    for (const [, account] of ACCOUNTS) expect(effectiveScopeKey(S, WORK, account)).toBe(WORK);
  });

  it('stamps an enrolled agent key outside an enrolled repository', () => {
    expect(effectiveScopeKey(S, PERSONAL, AGENT)).toBe(AGENT);
    expect(effectiveScopeKey(S, undefined, AGENT)).toBe(AGENT);
  });

  it('an agent key outside the resolved scope stamps the repository key', () => {
    expect(effectiveScopeKey(S, PERSONAL, OTHER_AGENT)).toBe(PERSONAL);
    expect(effectiveScopeKey(S, undefined, OTHER_AGENT)).toBeUndefined();
  });

  it('stamps an agent key only on a scoped attachment', () => {
    expect(effectiveScopeKey(MACHINE, PERSONAL, AGENT)).toBe(PERSONAL);
    expect(effectiveScopeKey(MACHINE, undefined, AGENT)).toBeUndefined();
    // A mode this build does not know is not a scoped attachment.
    const unknown = { mode: 'per-user' as unknown as AttachmentMode, keys: new Set([AGENT]) };
    expect(effectiveScopeKey(unknown, PERSONAL, AGENT)).toBe(PERSONAL);
  });

  it('a web key never stamps a coding row', () => {
    expect(effectiveScopeKey(S, PERSONAL, ACCOUNT)).toBe(PERSONAL);
    expect(effectiveScopeKey(S, undefined, ACCOUNT)).toBeUndefined();
  });

  it('a repository key passed as the account never stamps a row', () => {
    expect(effectiveScopeKey(S, PERSONAL, WORK)).toBe(PERSONAL);
    expect(effectiveScopeKey(S, undefined, WORK)).toBeUndefined();
  });

  it('stamps the repository key when the scope throws as it is read', () => {
    const throwingKeys = {
      mode: 'scoped',
      keys: {
        has: (): boolean => {
          throw new Error('unreadable scope');
        },
      },
    } as unknown as ResolvedAttachmentScope;
    expect(effectiveScopeKey(throwingKeys, PERSONAL, AGENT)).toBe(PERSONAL);
    const throwingMode = {
      get mode(): AttachmentMode {
        throw new Error('unreadable mode');
      },
      keys: new Set([AGENT]),
    } as ResolvedAttachmentScope;
    expect(effectiveScopeKey(throwingMode, undefined, AGENT)).toBeUndefined();
  });
});

describe('effectiveScopeKey — the truth table', () => {
  describe.each([
    ['no repository', undefined],
    ['an enrolled repository', WORK],
    ['a personal repository', PERSONAL],
  ] as const)('machine-wide, %s', (_repo, repo) => {
    it.each(ACCOUNTS)('with %s stamps the repository key', (_account, account) => {
      expect(effectiveScopeKey(MACHINE, repo, account)).toBe(repo);
    });
  });

  describe('scoped, an enrolled repository', () => {
    it.each(ACCOUNTS)('with %s stamps the repository key', (_account, account) => {
      expect(effectiveScopeKey(S, WORK, account)).toBe(WORK);
    });
  });

  describe.each([
    ['no repository', undefined],
    ['a personal repository', PERSONAL],
  ] as const)('scoped, %s', (_repo, repo) => {
    it.each(ACCOUNTS)('with %s', (label, account) => {
      expect(effectiveScopeKey(S, repo, account)).toBe(
        label === 'an enrolled agent key' ? AGENT : repo,
      );
    });
  });
});

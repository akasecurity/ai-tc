import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CredentialResolver } from '../../src/credentials/session-credentials.ts';
import {
  forgetSessionCredentials,
  injectedValues,
  MAX_REMEMBERED_SESSIONS,
  resolveForSession,
} from '../../src/credentials/session-credentials.ts';

afterEach(() => {
  forgetSessionCredentials();
});

const VALUE = 'value-0123456789';

describe('resolveForSession', () => {
  it('asks once per slug per session and answers later calls from memory', async () => {
    const resolve = vi.fn<CredentialResolver>((slugs) =>
      Promise.resolve({ resolved: slugs.map((slug) => ({ slug, value: VALUE })), refused: [] }),
    );
    await resolveForSession('s1', ['github'], resolve);
    const second = await resolveForSession('s1', ['github'], resolve);
    expect(second.values.get('github')).toBe(VALUE);
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(injectedValues('s1').get('github')).toBe(VALUE);
    expect(injectedValues('s2').size).toBe(0);
  });

  it('remembers nothing without a session id', async () => {
    const resolve = vi.fn<CredentialResolver>(() =>
      Promise.resolve({ resolved: [{ slug: 'github', value: VALUE }], refused: [] }),
    );
    await resolveForSession(undefined, ['github'], resolve);
    await resolveForSession(undefined, ['github'], resolve);
    expect(resolve).toHaveBeenCalledTimes(2);
  });

  it('does not remember a refusal, and reports what nothing answered for', async () => {
    const resolve = vi.fn<CredentialResolver>(() =>
      Promise.resolve({ resolved: [], refused: [{ slug: 'github', reason: 'no_grant' }] }),
    );
    const first = await resolveForSession('s1', ['github', 'stripe'], resolve);
    expect(first.refused).toEqual([{ slug: 'github', reason: 'no_grant' }]);
    expect(first.unanswered).toEqual(['stripe']);
    await resolveForSession('s1', ['github'], resolve);
    expect(resolve).toHaveBeenCalledTimes(2);

    const offline = await resolveForSession('s1', ['github'], () => Promise.resolve(undefined));
    expect(offline).toEqual({ values: new Map(), refused: [], unanswered: ['github'] });
  });

  it('ignores a value for a slug it did not ask for', async () => {
    const answer = await resolveForSession('s1', ['github'], () =>
      Promise.resolve({ resolved: [{ slug: 'other', value: VALUE }], refused: [] }),
    );
    expect(answer.values.size).toBe(0);
    expect(injectedValues('s1').size).toBe(0);
  });

  it('forgets the least recently used session past the bound', async () => {
    const resolve: CredentialResolver = () =>
      Promise.resolve({ resolved: [{ slug: 'github', value: VALUE }], refused: [] });
    for (let i = 0; i <= MAX_REMEMBERED_SESSIONS; i += 1) {
      await resolveForSession(`s${String(i)}`, ['github'], resolve);
    }
    expect(injectedValues('s0').size).toBe(0);
    expect(injectedValues(`s${String(MAX_REMEMBERED_SESSIONS)}`).size).toBe(1);
  });
});

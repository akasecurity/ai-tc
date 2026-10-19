import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  AccountBasis,
  AccountCheckReason,
  AGENT_KEY_PREFIX,
  agentKey,
  isAgentScopeKey,
  isRepoShapedScopeKey,
  parseAgentKey,
} from '../../src/zod/agent-scope.ts';
import type { SourceTool } from '../../src/zod/harness-map.ts';
import { SOURCE_TOOL } from '../../src/zod/harness-map.ts';
import type { WebAccountProvider } from '../../src/zod/web-account.ts';
import { AGENT_ACCOUNT_PROVIDER_OF, WEB_ACCOUNT_PROVIDER } from '../../src/zod/web-account.ts';

// The key a coding agent's row carries when it is attributed to a work account:
// `agent:<scope tag>:<account key>`. It is never a bare account key, which is
// what a claude.ai chat row carries, and never a repository key.
const ORG = '2ef4cd3c-c23c-473a-96be-1275cfc79103';
const ACCOUNT = `claude:${ORG}`;
const TAG = '0123456789abcdef';
const AGENT = `agent:${TAG}:${ACCOUNT}`;

describe('agentKey', () => {
  it('builds agent:<tag>:<account key>', () => {
    expect(AGENT_KEY_PREFIX).toBe('agent');
    expect(agentKey(TAG, ACCOUNT)).toBe(AGENT);
  });

  it('round-trips through parseAgentKey', () => {
    expect(parseAgentKey(agentKey(TAG, ACCOUNT))).toEqual({ scopeTag: TAG, accountKey: ACCOUNT });
  });

  it.each([
    ['a tag that is not sixteen hex digits', '0123456789abcde', ACCOUNT],
    ['an upper-case tag', '0123456789ABCDEF', ACCOUNT],
    ['an account key in no provider grammar', TAG, `example:${ORG}`],
    ['an account id that is not lower-case', TAG, `claude:${ORG.toUpperCase()}`],
    ['a repository key', TAG, 'github.com/acme/payments-api'],
    ['an agent key', TAG, AGENT],
  ])('makes no key from %s', (_label, tag, account) => {
    expect(agentKey(tag, account)).toBeUndefined();
  });
});

describe('parseAgentKey', () => {
  it('a bare account key is not an agent key', () => {
    expect(isAgentScopeKey(ACCOUNT)).toBe(false);
    expect(parseAgentKey(ACCOUNT)).toBeUndefined();
    expect(isAgentScopeKey(AGENT)).toBe(true);
  });

  it.each<[string, unknown]>([
    ['a repository key', 'github.com/acme/payments-api'],
    ['another prefix', `agents:${TAG}:${ACCOUNT}`],
    ['no tag', `agent::${ACCOUNT}`],
    ['a short tag', `agent:0123:${ACCOUNT}`],
    ['no account', `agent:${TAG}`],
    ['an account key in no provider grammar', `agent:${TAG}:example:${ORG}`],
    ['trailing text', `${AGENT}/x`],
    ['surrounding space', ` ${AGENT}`],
    ['a value that is not a string', 42],
    ['nothing', undefined],
  ])('reads %s as no agent key', (_label, key) => {
    expect(parseAgentKey(key)).toBeUndefined();
    expect(isAgentScopeKey(key)).toBe(false);
  });
});

describe('isRepoShapedScopeKey', () => {
  it.each([
    'github.com/acme/payments-api',
    'gitlab.com/group/sub/project',
    'example.org/org/re:po',
  ])('%s names a repository', (key) => {
    expect(isRepoShapedScopeKey(key)).toBe(true);
  });

  it.each<[string, unknown]>([
    ['a claude account key', ACCOUNT],
    ['a chatgpt account key', `chatgpt:${ORG}`],
    ['an agent key', AGENT],
    ['an unknown prefix', `example:${ORG}`],
    ['a colon before the first slash', `example:${ORG}/x`],
    ['no slash at all', 'payments-api'],
    ['an empty key', ''],
    ['a value that is not a string', undefined],
  ])('%s names no repository', (_label, key) => {
    expect(isRepoShapedScopeKey(key)).toBe(false);
  });
});

describe('AGENT_ACCOUNT_PROVIDER_OF', () => {
  it('names a provider for Claude Code alone', () => {
    const named = Object.entries(AGENT_ACCOUNT_PROVIDER_OF).filter(([, p]) => p !== undefined);
    expect(named).toEqual([[SOURCE_TOOL.ClaudeCode, WEB_ACCOUNT_PROVIDER.Claude]]);
  });

  // An account key on a web chat row is the chat's; a coding row never takes it.
  it('maps the web chat sites to no coding-agent provider', () => {
    expect(AGENT_ACCOUNT_PROVIDER_OF[SOURCE_TOOL.ClaudeAi]).toBeUndefined();
    expect(AGENT_ACCOUNT_PROVIDER_OF[SOURCE_TOOL.ChatGpt]).toBeUndefined();
  });

  it('has a row for every source tool', () => {
    expect(Object.keys(AGENT_ACCOUNT_PROVIDER_OF).sort()).toEqual(
      Object.values(SOURCE_TOOL).sort(),
    );
  });

  it('is typed over the whole source-tool vocabulary', () => {
    const exhaustive: Record<SourceTool, WebAccountProvider | undefined> =
      AGENT_ACCOUNT_PROVIDER_OF;
    // @ts-expect-error a table that leaves a source tool out does not compile
    const partial: Record<SourceTool, WebAccountProvider | undefined> = {
      [SOURCE_TOOL.ClaudeCode]: WEB_ACCOUNT_PROVIDER.Claude,
    };
    expect(exhaustive).toBe(AGENT_ACCOUNT_PROVIDER_OF);
    expect(partial).toBeDefined();
  });
});

describe('AccountCheckReason', () => {
  it('names every reason a check can give, opted-out included', () => {
    expect(AccountCheckReason.options).toEqual([
      'no-session-account',
      'veto',
      'unreadable',
      'env-mismatch',
      'login-changed',
      'org-changed',
      'email',
      'plan',
      'plan-unconfirmed',
      'plan-stale',
      'attached-user-unknown',
      'opted-out',
      'resumed',
      'provider',
      'absent',
      'mode',
      'malformed',
      'account-mismatch',
      'auth-changed',
      'cap-reached',
    ]);
  });

  it('names the three bases a work account is taken on', () => {
    expect(AccountBasis.options).toEqual(['validated', 'remembered', 'manual']);
  });

  it('registers no shape id for either', () => {
    expect(z.globalRegistry.get(AccountCheckReason)).toBeUndefined();
    expect(z.globalRegistry.get(AccountBasis)).toBeUndefined();
  });
});

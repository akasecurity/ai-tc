import { describe, expect, it } from 'vitest';

import { claudeBilling, codexBilling } from '../../src/account/billing.ts';
import type { ClaudeLogin, ClaudeLoginRead } from '../../src/account/claude-login.ts';
import type { CodexLogin, CodexLoginRead } from '../../src/account/codex-login.ts';

function claudeLogin(over: Partial<ClaudeLogin> = {}): ClaudeLoginRead {
  return {
    status: 'ok',
    mtimeMs: 0,
    size: 0,
    login: {
      hasOauthAccount: true,
      org: undefined,
      email: undefined,
      planState: 'other',
      plan: 'claude_max',
      primaryApiKey: false,
      hasSlots: false,
      newestSlotOrg: undefined,
      ...over,
    },
  };
}

function codexLogin(over: Partial<CodexLogin> = {}): CodexLoginRead {
  return {
    status: 'ok',
    login: {
      accountId: 'acct',
      emailMatchesAttached: false,
      planState: 'other',
      plan: 'plus',
      fingerprint: 'f',
      ...over,
    },
  };
}

const noKey = { keyEnv: false, tokenEnv: false };
const key = { keyEnv: true, tokenEnv: false };
const token = { keyEnv: false, tokenEnv: true };

describe('claudeBilling', () => {
  const base = { provider: 'anthropic', env: noKey, settingsVeto: false };

  it('reads a subscription sign-in with its plan', () => {
    expect(claudeBilling({ ...base, login: claudeLogin() })).toEqual({
      usageChannel: 'subscription',
      subscriptionPlan: 'claude_max',
    });
  });

  it('names a plan it does not know as other, and omits a missing one', () => {
    expect(claudeBilling({ ...base, login: claudeLogin({ plan: 'claude_mystery' }) })).toEqual({
      usageChannel: 'subscription',
      subscriptionPlan: 'other',
    });
    expect(claudeBilling({ ...base, login: claudeLogin({ plan: undefined }) })).toEqual({
      usageChannel: 'subscription',
    });
  });

  it('reads a Console sign-in, which stores a primary API key, as api_key', () => {
    const login = claudeLogin({ primaryApiKey: true, plan: 'claude_pro' });
    expect(claudeBilling({ ...base, login })).toEqual({ usageChannel: 'api_key' });
  });

  it('reads a key with no sign-in as api_key, and a key beside a sign-in as unknown', () => {
    expect(claudeBilling({ ...base, env: key, login: { status: 'absent' } })).toEqual({
      usageChannel: 'api_key',
    });
    expect(claudeBilling({ ...base, settingsVeto: true, login: claudeLogin() })).toEqual({
      usageChannel: 'unknown',
    });
  });

  it('reads the cloud and gateway providers before any login', () => {
    for (const provider of ['bedrock', 'vertex', 'foundry']) {
      expect(claudeBilling({ ...base, provider, login: claudeLogin() }).usageChannel).toBe('cloud');
    }
    expect(claudeBilling({ ...base, provider: 'gateway', login: claudeLogin() }).usageChannel).toBe(
      'gateway',
    );
  });

  it('reads a plan token with no sign-in as a subscription with no plan named', () => {
    expect(claudeBilling({ ...base, env: token, login: { status: 'absent' } })).toEqual({
      usageChannel: 'subscription',
    });
  });

  it('reads a key beside a plan token as unknown', () => {
    expect(
      claudeBilling({
        ...base,
        env: { keyEnv: true, tokenEnv: true },
        login: { status: 'absent' },
      }),
    ).toEqual({ usageChannel: 'unknown' });
  });

  it('is unknown with no login and no key', () => {
    expect(claudeBilling({ ...base, login: { status: 'unreadable' } })).toEqual({
      usageChannel: 'unknown',
    });
  });
});

describe('codexBilling', () => {
  const none = { keyEnv: false, accessTokenEnv: false };
  const codexKey = { keyEnv: true, accessTokenEnv: false };
  const access = { keyEnv: false, accessTokenEnv: true };
  const base = { provider: 'openai', env: none };

  it('reads a ChatGPT sign-in with its plan, folding workspace aliases', () => {
    expect(codexBilling({ ...base, login: codexLogin() })).toEqual({
      usageChannel: 'subscription',
      subscriptionPlan: 'chatgpt_plus',
    });
    expect(
      codexBilling({ ...base, login: codexLogin({ plan: 'self_serve_business_usage_based' }) }),
    ).toEqual({ usageChannel: 'subscription', subscriptionPlan: 'chatgpt_business' });
  });

  it('reads another login mode as api_key, or cloud for Bedrock credentials', () => {
    expect(codexBilling({ ...base, login: { status: 'mode' } }).usageChannel).toBe('api_key');
    expect(codexBilling({ ...base, login: { status: 'mode', cloud: true } }).usageChannel).toBe(
      'cloud',
    );
  });

  it('reads an access token as unknown whether it arrives in the environment or in auth.json', () => {
    const fromEnv = codexBilling({ ...base, env: access, login: { status: 'absent' } });
    const fromFile = codexBilling({ ...base, login: { status: 'mode', accessToken: true } });
    expect(fromEnv).toEqual({ usageChannel: 'unknown' });
    expect(fromFile).toEqual(fromEnv);
    expect(codexBilling({ ...base, env: access, login: codexLogin() }).usageChannel).toBe(
      'unknown',
    );
  });

  it('reads an API-key login in auth.json beside an environment access token as unknown', () => {
    expect(codexBilling({ ...base, env: access, login: { status: 'mode' } })).toEqual({
      usageChannel: 'unknown',
    });
    expect(codexBilling({ ...base, env: access, login: { status: 'mode', cloud: true } })).toEqual({
      usageChannel: 'cloud',
    });
  });

  it('reads a key beside an access token as unknown', () => {
    expect(
      codexBilling({
        ...base,
        env: { keyEnv: true, accessTokenEnv: true },
        login: { status: 'absent' },
      }),
    ).toEqual({ usageChannel: 'unknown' });
  });

  it('reads a key beside a ChatGPT sign-in as unknown, and a key alone as api_key', () => {
    expect(codexBilling({ ...base, env: codexKey, login: codexLogin() }).usageChannel).toBe(
      'unknown',
    );
    expect(codexBilling({ ...base, env: codexKey, login: { status: 'absent' } }).usageChannel).toBe(
      'api_key',
    );
  });

  it('reads an Azure provider as cloud before any login', () => {
    expect(codexBilling({ ...base, provider: 'azure', login: codexLogin() })).toEqual({
      usageChannel: 'cloud',
    });
    expect(
      codexBilling({ ...base, provider: 'azure', env: codexKey, login: { status: 'absent' } }),
    ).toEqual({ usageChannel: 'cloud' });
  });

  it('reads a gateway first, and a malformed or missing login as unknown', () => {
    expect(codexBilling({ ...base, provider: 'gateway', login: codexLogin() }).usageChannel).toBe(
      'gateway',
    );
    expect(codexBilling({ ...base, login: { status: 'malformed' } }).usageChannel).toBe('unknown');
    expect(codexBilling({ ...base, login: { status: 'absent' } }).usageChannel).toBe('unknown');
  });
});

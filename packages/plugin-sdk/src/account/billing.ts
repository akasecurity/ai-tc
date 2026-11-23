import type { SubscriptionPlan, UsageChannel } from '@akasecurity/schema';

import type { ClaudeAccountEnv, CodexAccountEnv } from './account-env.ts';
import { codexHomeDir, readClaudeAccountEnv, readCodexAccountEnv } from './account-env.ts';
import type { ClaudeLoginRead } from './claude-login.ts';
import {
  claudeConfigPath,
  claudeSettingsPaths,
  claudeSettingsVeto,
  readClaudeLogin,
} from './claude-login.ts';
import type { CodexLoginRead } from './codex-login.ts';
import { inspectCodexLogin } from './codex-login.ts';

/** How a session's calls are paid for, recorded on its root when it starts. */
export interface SessionBilling {
  readonly usageChannel: UsageChannel;
  readonly subscriptionPlan?: SubscriptionPlan;
}

const UNKNOWN: SessionBilling = { usageChannel: 'unknown' };
const API_KEY: SessionBilling = { usageChannel: 'api_key' };
const CLOUD: SessionBilling = { usageChannel: 'cloud' };
const GATEWAY: SessionBilling = { usageChannel: 'gateway' };

const CLAUDE_PLANS: Readonly<Record<string, SubscriptionPlan>> = {
  claude_pro: 'claude_pro',
  claude_max: 'claude_max',
  claude_team: 'claude_team',
  claude_enterprise: 'claude_enterprise',
};

const CHATGPT_PLANS: Readonly<Record<string, SubscriptionPlan>> = {
  plus: 'chatgpt_plus',
  pro: 'chatgpt_pro',
  team: 'chatgpt_business',
  business: 'chatgpt_business',
  self_serve_business_prolite: 'chatgpt_business',
  self_serve_business_usage_based: 'chatgpt_business',
  enterprise: 'chatgpt_enterprise',
  ent26: 'chatgpt_enterprise',
  enterprise_cbp_usage_based: 'chatgpt_enterprise',
  hc: 'chatgpt_enterprise',
  edu: 'chatgpt_edu',
  education: 'chatgpt_edu',
  edu_plus: 'chatgpt_edu',
  edu_pro: 'chatgpt_edu',
};

function subscription(
  plan: string | undefined,
  plans: Readonly<Record<string, SubscriptionPlan>>,
): SessionBilling {
  if (plan === undefined || plan === '') return { usageChannel: 'subscription' };
  return { usageChannel: 'subscription', subscriptionPlan: plans[plan] ?? 'other' };
}

export interface ClaudeBillingInput {
  readonly provider: string;
  readonly env: Pick<ClaudeAccountEnv, 'keyEnv' | 'tokenEnv'>;
  readonly login: ClaudeLoginRead;
  /** Any settings layer sets an API key helper or a billing env block. */
  readonly settingsVeto: boolean;
}

/**
 * Claude Code. A Console sign-in stores `primaryApiKey` next to its `oauthAccount`,
 * so that key, not the account, is what decides an API-key session; a key from the
 * environment or a settings helper beside a subscription sign-in or a plan token may
 * or may not be the one in use, so that pair is `unknown`. A plan token on its own
 * is a subscription whose plan the token does not name.
 */
export function claudeBilling(input: ClaudeBillingInput): SessionBilling {
  const { provider, env, login, settingsVeto } = input;
  if (provider === 'bedrock' || provider === 'vertex') return CLOUD;
  if (provider === 'gateway') return GATEWAY;
  const account = login.status === 'ok' ? login.login : undefined;
  if (account?.primaryApiKey === true) return API_KEY;
  const signedIn = account?.hasOauthAccount === true;
  if (env.keyEnv || settingsVeto) return signedIn || env.tokenEnv ? UNKNOWN : API_KEY;
  if (env.tokenEnv) return { usageChannel: 'subscription' };
  return signedIn ? subscription(account.plan, CLAUDE_PLANS) : UNKNOWN;
}

export interface CodexBillingInput {
  readonly provider: string;
  readonly env: Pick<CodexAccountEnv, 'keyEnv' | 'tokenEnv'>;
  readonly login: CodexLoginRead;
}

/**
 * Codex, read the same way as Claude Code. A key in the environment beside a ChatGPT sign-in or
 * an access token may or may not be the one in use, so that pair is `unknown`. An access token
 * is a ChatGPT sign-in, so on its own it is a subscription whose plan the token does not name.
 */
export function codexBilling(input: CodexBillingInput): SessionBilling {
  const { provider, env, login } = input;
  if (provider === 'gateway') return GATEWAY;
  switch (login.status) {
    case 'ok':
      if (env.keyEnv) return UNKNOWN;
      return env.tokenEnv
        ? { usageChannel: 'subscription' }
        : subscription(login.login.plan, CHATGPT_PLANS);
    case 'mode':
      return login.cloud === true ? CLOUD : API_KEY;
    case 'absent':
      if (env.keyEnv) return env.tokenEnv ? UNKNOWN : API_KEY;
      return env.tokenEnv ? { usageChannel: 'subscription' } : UNKNOWN;
    case 'malformed':
      return UNKNOWN;
  }
}

/** Reads Claude Code's login and settings; any failure is `unknown`. */
export function resolveClaudeBilling(provider: string, cwd: string): SessionBilling {
  try {
    const env = readClaudeAccountEnv();
    return claudeBilling({
      provider,
      env,
      login: readClaudeLogin(claudeConfigPath(env)),
      settingsVeto: claudeSettingsVeto(claudeSettingsPaths(env, cwd)),
    });
  } catch {
    return UNKNOWN;
  }
}

/** Reads Codex's `auth.json`; any failure is `unknown`. */
export function resolveCodexBilling(provider: string): SessionBilling {
  try {
    const env = readCodexAccountEnv();
    const home = codexHomeDir(env.codexHome);
    const login: CodexLoginRead =
      home === undefined ? { status: 'absent' } : inspectCodexLogin(home, undefined);
    return codexBilling({ provider, env, login });
  } catch {
    return UNKNOWN;
  }
}

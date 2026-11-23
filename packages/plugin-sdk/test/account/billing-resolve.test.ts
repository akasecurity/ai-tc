import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CLAUDE_ACCOUNT_ENV_NAMES,
  CODEX_ACCOUNT_ENV_NAMES,
} from '../../src/account/account-env.ts';
import { resolveClaudeBilling, resolveCodexBilling } from '../../src/account/billing.ts';
import type * as ClaudeLogin from '../../src/account/claude-login.ts';
import type * as CodexLogin from '../../src/account/codex-login.ts';
import type { CodexMachine } from '../helpers/fake-jwt.ts';
import { codexMachine } from '../helpers/fake-jwt.ts';
import type { ClaudeMachine } from '../helpers/transcript-builder.ts';
import { claudeMachine } from '../helpers/transcript-builder.ts';

const failing = vi.hoisted(() => ({ reads: false }));

const refuse = (): never => {
  throw new Error('read failed');
};

vi.mock('../../src/account/claude-login.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof ClaudeLogin>();
  return {
    ...actual,
    readClaudeLogin: (...args: Parameters<typeof actual.readClaudeLogin>) =>
      failing.reads ? refuse() : actual.readClaudeLogin(...args),
  };
});

vi.mock('../../src/account/codex-login.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof CodexLogin>();
  return {
    ...actual,
    inspectCodexLogin: (...args: Parameters<typeof actual.inspectCodexLogin>) =>
      failing.reads ? refuse() : actual.inspectCodexLogin(...args),
  };
});

afterEach(() => {
  failing.reads = false;
  vi.unstubAllEnvs();
});

describe('resolveClaudeBilling', () => {
  let machine: ClaudeMachine;

  beforeEach(() => {
    for (const name of CLAUDE_ACCOUNT_ENV_NAMES) vi.stubEnv(name, undefined);
    machine = claudeMachine();
    vi.stubEnv('CLAUDE_CONFIG_DIR', machine.home);
  });

  afterEach(() => {
    machine.dispose();
  });

  it('reads a plan login from the config file as a subscription', () => {
    machine.writeConfig({ oauthAccount: { organizationType: 'claude_max' } });
    expect(resolveClaudeBilling('anthropic', machine.cwd)).toEqual({
      usageChannel: 'subscription',
      subscriptionPlan: 'claude_max',
    });
  });

  it('reads an API key in the environment as per-token billing', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', 'fixture-key');
    expect(resolveClaudeBilling('anthropic', machine.cwd).usageChannel).toBe('api_key');
  });

  it('reads a plan token in the environment as a subscription', () => {
    vi.stubEnv('CLAUDE_CODE_OAUTH_TOKEN', 'fixture-token');
    expect(resolveClaudeBilling('anthropic', machine.cwd)).toEqual({
      usageChannel: 'subscription',
    });
  });

  it('answers unknown when reading the login throws', () => {
    machine.writeConfig({ oauthAccount: { organizationType: 'claude_max' } });
    failing.reads = true;
    expect(resolveClaudeBilling('anthropic', machine.cwd)).toEqual({ usageChannel: 'unknown' });
  });
});

describe('resolveCodexBilling', () => {
  let machine: CodexMachine;

  beforeEach(() => {
    for (const name of CODEX_ACCOUNT_ENV_NAMES) vi.stubEnv(name, undefined);
    machine = codexMachine();
    vi.stubEnv('CODEX_HOME', machine.codexHome);
  });

  afterEach(() => {
    machine.dispose();
  });

  it('reads a ChatGPT login from auth.json as a subscription', () => {
    machine.writeAuth({ plan: 'plus' });
    expect(resolveCodexBilling('openai')).toEqual({
      usageChannel: 'subscription',
      subscriptionPlan: 'chatgpt_plus',
    });
  });

  it('answers unknown when there is no login and no key', () => {
    expect(resolveCodexBilling('openai')).toEqual({ usageChannel: 'unknown' });
  });

  it('answers unknown when reading the login throws', () => {
    machine.writeAuth({ plan: 'plus' });
    failing.reads = true;
    expect(resolveCodexBilling('openai')).toEqual({ usageChannel: 'unknown' });
  });
});

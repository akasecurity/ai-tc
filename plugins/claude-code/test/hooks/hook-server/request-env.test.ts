import { CLAUDE_ACCOUNT_ENV_NAMES, CLAUDE_CREDENTIAL_ENV } from '@akasecurity/plugin-sdk/account';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  FORWARDED_ENV,
  PRESENCE_ONLY_ENV,
  REMOTE_CONTROL_ENV,
  VALUE_ENV,
} from '../../../src/hooks/hook-server/forwarded-env.ts';
import { applyRequestEnv, currentValue } from '../../../src/hooks/hook-server/request-env.ts';
import { isRemoteControlSession } from '../../../src/hooks/remote-session.ts';

describe('the forwarded environment', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('is exactly what the account checks read, plus the Remote Control marker', () => {
    expect([...FORWARDED_ENV].sort()).toEqual(
      [...CLAUDE_ACCOUNT_ENV_NAMES, REMOTE_CONTROL_ENV].sort(),
    );
    expect([...PRESENCE_ONLY_ENV].sort()).toEqual([...CLAUDE_CREDENTIAL_ENV].sort());
    expect(VALUE_ENV).not.toEqual(expect.arrayContaining([...PRESENCE_ONLY_ENV]));
  });

  it('names the variable the Remote Control check reads', () => {
    vi.stubEnv(REMOTE_CONTROL_ENV, '');
    expect(isRemoteControlSession()).toBe(false);
    vi.stubEnv(REMOTE_CONTROL_ENV, 'session_x');
    expect(isRemoteControlSession()).toBe(true);
  });

  it('sets the request value, unsets what the request lacks, and restores both', () => {
    vi.stubEnv('CLAUDE_CONFIG_DIR', '/server');
    vi.stubEnv('CLAUDE_CODE_USER_EMAIL', 'server@example.com');
    vi.stubEnv('UNRELATED_SERVER_VARIABLE', 'kept');
    const restore = applyRequestEnv({ CLAUDE_CONFIG_DIR: '/request', ANTHROPIC_API_KEY: '1' });
    expect(currentValue('CLAUDE_CONFIG_DIR')).toBe('/request');
    expect(currentValue('CLAUDE_CODE_USER_EMAIL')).toBeUndefined();
    expect(currentValue('ANTHROPIC_API_KEY')).toBe('1');
    expect(currentValue('UNRELATED_SERVER_VARIABLE')).toBe('kept');
    restore();
    expect(currentValue('CLAUDE_CONFIG_DIR')).toBe('/server');
    expect(currentValue('CLAUDE_CODE_USER_EMAIL')).toBe('server@example.com');
    expect(currentValue('ANTHROPIC_API_KEY')).toBeUndefined();
  });

  it('ignores a name outside the list, whatever the request carries', () => {
    vi.stubEnv('PATH_LIKE', 'before');
    const restore = applyRequestEnv({ PATH_LIKE: 'injected', NODE_OPTIONS: '--inspect' });
    expect(currentValue('PATH_LIKE')).toBe('before');
    expect(currentValue('NODE_OPTIONS')).not.toBe('--inspect');
    restore();
  });
});

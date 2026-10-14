import { randomUUID } from 'node:crypto';
import { mkdirSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CLAUDE_ACCOUNT_ENV_NAMES,
  CLAUDE_CREDENTIAL_ENV,
  CLAUDE_PROVIDER_FLAG_ENV,
  isNonDefaultBaseUrl,
  readClaudeAccountEnv,
} from '../../src/account/account-env.ts';
import {
  CLAUDE_CONFIG_MAX_BYTES,
  claudeConfigPath,
  claudePlanState,
  claudeSettingsPaths,
  claudeSettingsVeto,
  readClaudeLogin,
} from '../../src/account/claude-login.ts';
import type { ClaudeMachine, SettingsLayer } from '../helpers/transcript-builder.ts';
import { claudeMachine, otherHost, T0, workConfig } from '../helpers/transcript-builder.ts';

let machine: ClaudeMachine;

beforeEach(() => {
  for (const name of CLAUDE_ACCOUNT_ENV_NAMES) vi.stubEnv(name, undefined);
  machine = claudeMachine();
});

afterEach(() => {
  vi.unstubAllEnvs();
  machine.dispose();
});

const configPath = (): string => join(machine.home, '.claude.json');
const settingsPaths = (): readonly string[] =>
  claudeSettingsPaths(readClaudeAccountEnv(), machine.cwd, machine.paths);

describe('readClaudeAccountEnv', () => {
  it.each(CLAUDE_CREDENTIAL_ENV)(
    'reads a non-empty %s as a credential and keeps no value',
    (name) => {
      const value = randomUUID();
      vi.stubEnv(name, value);
      const env = readClaudeAccountEnv();
      expect(env.credentialEnv).toBe(true);
      expect(JSON.stringify(env)).not.toContain(value);
    },
  );

  it.each(CLAUDE_CREDENTIAL_ENV)('reads an empty %s as unset', (name) => {
    vi.stubEnv(name, '');
    expect(readClaudeAccountEnv().credentialEnv).toBe(false);
  });

  const truthy = ['1', 'true', 'yes', 'on', 'TRUE', ' On '];
  const falsy = ['', '0', 'false', 'off', 'no', 'enabled'];

  it.each(
    CLAUDE_PROVIDER_FLAG_ENV.flatMap((name) => truthy.map((value) => [name, value] as const)),
  )('turns %s on for %j, the way the host reads its flags', (name, value) => {
    vi.stubEnv(name, value);
    expect(readClaudeAccountEnv().providerFlag).toBe(true);
  });

  it.each(CLAUDE_PROVIDER_FLAG_ENV.flatMap((name) => falsy.map((value) => [name, value] as const)))(
    'leaves %s off for %j',
    (name, value) => {
      vi.stubEnv(name, value);
      expect(readClaudeAccountEnv().providerFlag).toBe(false);
    },
  );

  it('reads the default API URL the desktop host sets as no veto', () => {
    expect(isNonDefaultBaseUrl('https://api.anthropic.com')).toBe(false);
    expect(isNonDefaultBaseUrl('https://api.anthropic.com/')).toBe(false);
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com');
    expect(readClaudeAccountEnv().baseUrlVeto).toBe(false);
  });

  it('vetoes a base URL that is not https, names another host or port, or carries a path', () => {
    const host = otherHost();
    for (const url of [
      'http://api.anthropic.com',
      `https://${host}`,
      'https://api.anthropic.com:8443',
      'https://api.anthropic.com/v1',
      'https://api.anthropic.com/?region=1',
      `${host}:4000`,
      'not a url',
    ]) {
      expect(isNonDefaultBaseUrl(url), url).toBe(true);
    }
  });

  it('lower-cases the env org and normalises the env email, in memory only', () => {
    const org = randomUUID();
    vi.stubEnv('CLAUDE_CODE_ORGANIZATION_UUID', org.toUpperCase());
    vi.stubEnv('CLAUDE_CODE_USER_EMAIL', ` ${machine.email.toUpperCase()} `);
    expect(readClaudeAccountEnv()).toMatchObject({
      orgPresent: true,
      org,
      emailPresent: true,
      email: machine.email,
    });
  });

  it('reads the subprocess env scrub as a flag', () => {
    vi.stubEnv('CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', '1');
    expect(readClaudeAccountEnv().envScrub).toBe(true);
    vi.stubEnv('CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', '');
    expect(readClaudeAccountEnv().envScrub).toBe(false);
  });

  it('honours CLAUDE_CONFIG_DIR for the login file and the user settings layer', () => {
    const dir = join(machine.root, 'config-home');
    vi.stubEnv('CLAUDE_CONFIG_DIR', dir);
    const env = readClaudeAccountEnv();
    expect(claudeConfigPath(env, machine.home)).toBe(join(dir, '.claude.json'));
    expect(claudeSettingsPaths(env, machine.cwd, machine.paths)[0]).toBe(
      join(dir, 'settings.json'),
    );
    vi.stubEnv('CLAUDE_CONFIG_DIR', '');
    expect(claudeConfigPath(readClaudeAccountEnv(), machine.home)).toBe(configPath());
  });

  it('takes a Windows-style CLAUDE_CONFIG_DIR as given, drive letter and backslashes included', () => {
    const dir = ['C:', 'Users', 'dev', 'claude-work'].join('\\');
    vi.stubEnv('CLAUDE_CONFIG_DIR', dir);
    const env = readClaudeAccountEnv();
    expect(env.configDir).toBe(dir);
    expect(claudeConfigPath(env, machine.home)).toBe(join(dir, '.claude.json'));
    expect(claudeSettingsPaths(env, machine.cwd, machine.paths)[0]).toBe(
      join(dir, 'settings.json'),
    );
  });

  it.runIf(process.platform === 'win32')(
    'reads the login file under a drive-letter config dir',
    () => {
      const dir = join(machine.root, 'config-home');
      expect(dir).toMatch(/^[A-Za-z]:\\/);
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, '.claude.json'),
        JSON.stringify(workConfig(randomUUID(), machine.email)),
      );
      vi.stubEnv('CLAUDE_CONFIG_DIR', dir);
      expect(readClaudeLogin(claudeConfigPath(readClaudeAccountEnv(), machine.home)).status).toBe(
        'ok',
      );
    },
  );
});

describe('readClaudeLogin', () => {
  it('reads the org, the normalised email, the plan, the API-key marker and the newest slot', () => {
    const org = randomUUID();
    machine.writeConfig({
      oauthAccount: {
        organizationUuid: org.toUpperCase(),
        emailAddress: machine.email.toUpperCase(),
        organizationType: 'claude_enterprise',
      },
      primaryApiKey: randomUUID(),
      clientDataCacheSlots: {
        older: { data: null, at: T0, org: randomUUID() },
        newer: { data: null, at: T0 + 1, org: org.toUpperCase() },
        unstamped: { data: null },
      },
    });
    expect(readClaudeLogin(configPath())).toMatchObject({
      status: 'ok',
      login: {
        hasOauthAccount: true,
        org,
        email: machine.email,
        planState: 'company',
        primaryApiKey: true,
        hasSlots: true,
        newestSlotOrg: org,
      },
    });
  });

  it.each([
    ['claude_team', 'company'],
    ['claude_enterprise', 'company'],
    ['claude_max', 'other'],
    ['claude_pro', 'other'],
    ['Claude_Team', 'other'],
    [42, 'other'],
    [null, 'absent'],
    [undefined, 'absent'],
  ] as const)('reads organizationType %j as %s', (type, state) => {
    expect(claudePlanState(type)).toBe(state);
  });

  it('answers absent for a missing file, unreadable for a torn, non-object or oversized one', () => {
    expect(readClaudeLogin(configPath()).status).toBe('absent');
    writeFileSync(configPath(), '{"oauthAccount": {');
    expect(readClaudeLogin(configPath()).status).toBe('unreadable');
    writeFileSync(configPath(), '[]');
    expect(readClaudeLogin(configPath()).status).toBe('unreadable');
    writeFileSync(configPath(), `{"pad":"${'x'.repeat(CLAUDE_CONFIG_MAX_BYTES)}"}`);
    expect(readClaudeLogin(configPath()).status).toBe('unreadable');
  });

  it('memoises a good read on mtime and size, and never memoises an unreadable one', () => {
    writeFileSync(configPath(), '{"oauthAccount": {');
    expect(readClaudeLogin(configPath()).status).toBe('unreadable');
    machine.writeConfig(workConfig(randomUUID(), machine.email));
    const first = readClaudeLogin(configPath());
    expect(first.status).toBe('ok');
    expect(readClaudeLogin(configPath())).toBe(first);
    machine.writeConfig(workConfig(randomUUID(), machine.email));
    utimesSync(configPath(), new Date(T0 + 60_000), new Date(T0 + 60_000));
    expect(readClaudeLogin(configPath())).not.toBe(first);
  });
});

describe('claudeSettingsVeto', () => {
  const layers: readonly SettingsLayer[] = ['user', 'project', 'local', 'managed'];

  it('finds no veto when no layer exists', () => {
    expect(claudeSettingsVeto(settingsPaths())).toBe(false);
  });

  it.each(layers)('vetoes an apiKeyHelper in the %s layer', (layer) => {
    machine.writeSettings(layer, { apiKeyHelper: '/usr/local/bin/key-helper' });
    expect(claudeSettingsVeto(settingsPaths())).toBe(true);
  });

  it.each(layers.flatMap((layer) => CLAUDE_CREDENTIAL_ENV.map((name) => [layer, name] as const)))(
    'vetoes an env block in the %s layer that sets %s',
    (layer, name) => {
      machine.writeSettings(layer, { env: { [name]: randomUUID() } });
      expect(claudeSettingsVeto(settingsPaths())).toBe(true);
    },
  );

  it.each(CLAUDE_PROVIDER_FLAG_ENV)(
    'vetoes a truthy %s in an env block, and not an empty one',
    (name) => {
      machine.writeSettings('project', { env: { [name]: '' } });
      expect(claudeSettingsVeto(settingsPaths())).toBe(false);
      machine.writeSettings('project', { env: { [name]: '1' } });
      expect(claudeSettingsVeto(settingsPaths())).toBe(true);
    },
  );

  it('vetoes a non-default base URL in an env block, and not the default one', () => {
    machine.writeSettings('user', { env: { ANTHROPIC_BASE_URL: 'https://api.anthropic.com' } });
    expect(claudeSettingsVeto(settingsPaths())).toBe(false);
    machine.writeSettings('user', { env: { ANTHROPIC_BASE_URL: `https://${otherHost()}` } });
    expect(claudeSettingsVeto(settingsPaths())).toBe(true);
  });

  it('vetoes a layer it cannot parse, since it cannot rule out a key there', () => {
    machine.writeSettings('local', '{"apiKeyHelper": ');
    expect(claudeSettingsVeto(settingsPaths())).toBe(true);
  });
});

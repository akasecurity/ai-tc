// The pre-tool-use handler the hook server runs, driven in-process on a real
// store in a temp home: what it returns is what the node hook would have
// written to stdout, and it leaves the process as it found it.
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, loadConfig, shippedRegexMatchers } from '@akasecurity/plugin-sdk';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../../test/helpers/remove-tree.ts';
import { FORWARDED_ENV, REMOTE_CONTROL_ENV } from '../../../src/hooks/hook-server/forwarded-env.ts';
import { postToolUseHandler, preToolUseHandler } from '../../../src/hooks/hook-server/handlers.ts';
import { currentValue } from '../../../src/hooks/hook-server/request-env.ts';
import {
  closingGateways,
  dropHeldGateway,
  openGateway,
  reuseGateways,
} from '../../../src/hooks/store-health.ts';

const REMOTE = REMOTE_CONTROL_ENV;
const LEAF = 'ledger-q4-9f3a1c7d2b.txt';
const pack = bundledDetections().find((p) =>
  p.rules.some((r) => r.id === 'command-risk/protected-path-access'),
);

describe('the pre-tool-use hook server handler', () => {
  let home: string;
  let docs: string;
  let proj: string;

  beforeEach(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), 'aka-hs-handler-')));
    docs = join(home, 'Documents');
    proj = join(home, 'proj');
    mkdirSync(docs, { recursive: true });
    mkdirSync(proj, { recursive: true });
    writeFileSync(join(docs, LEAF), 'x');
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    for (const name of FORWARDED_ENV) vi.stubEnv(name, '');
    applyOnboarding({ protectedPaths: ['~/Documents'] }, join(home, '.aka'));
    const db = openLocalDatabase(join(home, '.aka', 'data'), {
      shippedRegexMatchers: shippedRegexMatchers(),
    });
    try {
      db.installedPacks.recordInventory(bundledDetections());
      if (pack) db.installedPacks.setPolicy(pack.namespace, pack.packId, 'warn');
    } finally {
      db.close();
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    removeTree(home);
  });

  const payload = (command: Record<string, unknown>): string =>
    JSON.stringify({
      tool_name: 'Read',
      tool_input: command,
      session_id: 'hs-test',
      cwd: proj,
      hook_event_name: 'PreToolUse',
    });

  const handleRaw = (
    body: string,
    env: Record<string, string> = {},
    cwd?: string,
  ): Promise<string | null> =>
    preToolUseHandler(() => undefined)({ hook: 'pre-tool-use', cwd, env, payload: body });

  // The output of a call the handler took; a decline fails the case.
  const handle = async (
    body: string,
    env: Record<string, string> = {},
    cwd?: string,
  ): Promise<string> => {
    const out = await handleRaw(body, env, cwd);
    if (out === null) throw new Error('the handler declined the request');
    return out;
  };

  const protectedRead = (): string => payload({ file_path: join(docs, LEAF) });

  it('returns the JSON the hook would have written, and nothing for a call it has no view on', async () => {
    expect(await handle(payload({ file_path: join(proj, 'a.txt') }))).toBe('');
    const warned = await handle(protectedRead());
    expect((JSON.parse(warned) as { systemMessage: string }).systemMessage).toContain(
      'command-risk/protected-path-access',
    );
  });

  it('applies the environment the request carries, and only for that request', async () => {
    const denied = await handle(protectedRead(), { [REMOTE]: 'session_x' });
    expect(JSON.parse(denied)).toMatchObject({
      hookSpecificOutput: { permissionDecision: 'deny' },
    });
    expect(currentValue(REMOTE)).toBe('');
    // The next request carries none, so it is a local session again.
    expect(JSON.parse(await handle(protectedRead()))).not.toHaveProperty('hookSpecificOutput');
  });

  it('puts back a variable the server itself had, and leaves unforwarded ones alone', async () => {
    vi.stubEnv('CLAUDE_CONFIG_DIR', '/server/own');
    vi.stubEnv('HOME_MARKER_NOT_FORWARDED', 'kept');
    await handle(protectedRead(), { CLAUDE_CONFIG_DIR: '/request/own' });
    expect(currentValue('CLAUDE_CONFIG_DIR')).toBe('/server/own');
    expect(currentValue('HOME_MARKER_NOT_FORWARDED')).toBe('kept');
  });

  it('runs in the request working directory and goes back to its own', async () => {
    const before = process.cwd();
    await handle(protectedRead(), {}, proj);
    expect(process.cwd()).toBe(before);
    // A directory that is gone costs nothing but the directory.
    expect(await handle(payload({ file_path: join(proj, 'a.txt') }), {}, join(home, 'gone'))).toBe(
      '',
    );
    expect(process.cwd()).toBe(before);
  });

  it('runs the PostToolUse pipeline on a tool response', async () => {
    const run = (stdout: string): Promise<string | null> =>
      postToolUseHandler(() => undefined)({
        hook: 'post-tool-use',
        cwd: proj,
        env: {},
        payload: JSON.stringify({
          tool_name: 'Bash',
          tool_input: { command: 'env' },
          tool_response: { stdout, stderr: '', interrupted: false },
          session_id: 'hs-test',
          cwd: proj,
          hook_event_name: 'PostToolUse',
        }),
      });
    expect(await run('nothing sensitive here')).toBe('');
    expect(await run('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE')).toContain('secrets/aws-access-key');
  });

  it('declines when the vault is turned on, so the node hook runs it', async () => {
    applyOnboarding(
      {
        protectedPaths: ['~/Documents'],
        vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
      },
      join(home, '.aka'),
    );
    const settingsFile = join(home, '.aka', 'settings', 'settings.json');
    const settings = JSON.parse(readFileSync(settingsFile, 'utf8')) as Record<string, unknown>;
    expect(settings.vaultConsent).toBeDefined();
    expect(await handleRaw(protectedRead())).toBeNull();
  });

  it('answers empty for input that is not a hook payload', async () => {
    expect(await handle('not json')).toBe('');
    expect(await handle('[]')).toBe('');
  });

  it('captures what the hook writes to standard error instead of printing it', async () => {
    const lines: string[] = [];
    const write = vi.spyOn(process.stderr, 'write');
    // Settings this build cannot read make the pipeline report on stderr.
    writeFileSync(join(home, '.aka', 'settings', 'settings.json'), '{"protectedPaths":[1,');
    await preToolUseHandler((text) => lines.push(text))({
      hook: 'pre-tool-use',
      cwd: undefined,
      env: {},
      payload: protectedRead(),
    });
    expect(write.mock.calls.filter(([chunk]) => String(chunk).startsWith('[aka]'))).toEqual([]);
  });
});

describe('closingGateways', () => {
  let home: string;
  beforeEach(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), 'aka-hs-gw-')));
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    removeTree(home);
  });

  it('closes every gateway opened inside it, even when the work throws', async () => {
    const closed: string[] = [];
    await expect(
      closingGateways(() => {
        for (const label of ['a', 'b']) {
          const opened = openGateway(loadConfig());
          if (opened.gateway === null) throw new Error('store did not open');
          const close = opened.gateway.close.bind(opened.gateway);
          opened.gateway.close = () => {
            closed.push(label);
            return close();
          };
        }
        return Promise.reject(new Error('work failed'));
      }),
    ).rejects.toThrow('work failed');
    expect(closed).toEqual(['a', 'b']);
  });

  it('does not track gateways opened outside it', async () => {
    const opened = openGateway(loadConfig());
    if (opened.gateway === null) throw new Error('store did not open');
    const close = vi.spyOn(opened.gateway, 'close');
    await closingGateways(() => Promise.resolve());
    expect(close).not.toHaveBeenCalled();
    await opened.gateway.close();
  });
});

describe('a held gateway', () => {
  let home: string;
  beforeEach(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), 'aka-hs-held-')));
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
  });
  afterEach(async () => {
    await reuseGateways(false);
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    removeTree(home);
  });

  it('is the same gateway for every open, and survives closingGateways', async () => {
    await reuseGateways(true);
    const first = openGateway(loadConfig()).gateway;
    const second = await closingGateways(() => Promise.resolve(openGateway(loadConfig()).gateway));
    expect(first).not.toBeNull();
    expect(second === first).toBe(true);
    expect(openGateway(loadConfig()).gateway === first).toBe(true);
  });

  it('ignores the close a hook runtime makes, so the next hook finds it open', async () => {
    await reuseGateways(true);
    const lent = openGateway(loadConfig()).gateway;
    if (lent === null) throw new Error('store did not open');
    await lent.close();
    const again = openGateway(loadConfig()).gateway;
    expect(again === lent).toBe(true);
    // Still usable: a closed handle would throw here.
    await expect(again?.getPolicyBundle()).resolves.toMatchObject({ version: 'local' });
  });

  it('is replaced when the store file is not the one it opened', async () => {
    await reuseGateways(true);
    const config = loadConfig();
    const first = openGateway(config).gateway;
    await dropHeldGateway();
    rmSync(config.dbPath, { force: true });
    rmSync(`${config.dbPath}-wal`, { force: true });
    rmSync(`${config.dbPath}-shm`, { force: true });
    const second = openGateway(config).gateway;
    expect(second).not.toBeNull();
    // Compared by identity, not with toBe: a failed toBe prints the closed gateway.
    expect(second === first).toBe(false);
  });

  it('is replaced when the file is removed and recreated underneath it', async () => {
    await reuseGateways(true);
    const config = loadConfig();
    const first = openGateway(config).gateway;
    rmSync(config.dbPath, { force: true });
    writeFileSync(config.dbPath, '');
    const second = openGateway(config).gateway;
    // Compared by identity, not with toBe: a failed toBe prints the closed gateway.
    expect(second === first).toBe(false);
  });

  it('is closed when reuse is turned off, and opens are tracked again', async () => {
    await reuseGateways(true);
    const held = openGateway(loadConfig()).gateway;
    await reuseGateways(false);
    const close = held === null ? undefined : vi.spyOn(held, 'close');
    const closed: string[] = [];
    await closingGateways(() => {
      const opened = openGateway(loadConfig()).gateway;
      if (opened === null) throw new Error('store did not open');
      const original = opened.close.bind(opened);
      opened.close = () => {
        closed.push('tracked');
        return original();
      };
      return Promise.resolve();
    });
    expect(closed).toEqual(['tracked']);
    expect(close).toBeDefined();
  });
});

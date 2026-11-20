import { chmodSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { CURSOR_EVENTS } from '../src/hooks/event-name.ts';
import {
  HOOK_SCRIPTS,
  hookCommand,
  isOwnEntry,
  mergeOwnHooks,
  OWNER_MARKER,
  parseHooksFile,
  removeOwnHooks,
} from '../src/install.ts';
import { applyInstall, cursorHooksPath } from '../src/install-cli.ts';
import tsupConfig from '../tsup.config.ts';

const NODE = '/opt/node/bin/node';
const SCRIPTS = '/home/someone/aka cursor/package/scripts';
const USER_HOOK = { command: './audit.sh', timeout: 5 };

describe('hook commands', () => {
  it('quote both paths and end with the owner marker', () => {
    const command = hookCommand(NODE, SCRIPTS, 'preToolUse');
    expect(command).toBe(
      `"${NODE}" "${join(SCRIPTS, 'pre-tool-use.js')}" preToolUse ${OWNER_MARKER}`,
    );
    expect(isOwnEntry({ command })).toBe(true);
    expect(isOwnEntry(USER_HOOK)).toBe(false);
    expect(isOwnEntry({})).toBe(false);
  });

  it('register only events Cursor documents', () => {
    for (const event of Object.keys(HOOK_SCRIPTS)) expect(CURSOR_EVENTS).toContain(event);
  });

  it('name scripts the build emits', () => {
    const entries = Object.keys((tsupConfig as { entry: Record<string, string> }).entry).map(
      (name) => `${name}.js`,
    );
    for (const script of Object.values(HOOK_SCRIPTS)) expect(entries).toContain(script);
  });
});

describe('merging into hooks.json', () => {
  it('reads an absent file as empty', () => {
    expect(parseHooksFile(undefined)).toEqual({ version: 1, hooks: {} });
  });

  it('refuses a shape it cannot merge into', () => {
    expect(() => parseHooksFile([])).toThrow();
    expect(() => parseHooksFile({ version: '1' })).toThrow();
    expect(() => parseHooksFile({ hooks: [] })).toThrow();
    expect(() => parseHooksFile({ hooks: { preToolUse: {} } })).toThrow();
    expect(() => parseHooksFile({ hooks: { preToolUse: ['x'] } })).toThrow();
  });

  it('keeps the user’s own hooks and other keys, and adds one entry per event', () => {
    const file = parseHooksFile({ version: 1, extra: true, hooks: { preToolUse: [USER_HOOK] } });
    const merged = mergeOwnHooks(file, NODE, SCRIPTS);
    expect(merged.extra).toBe(true);
    expect(merged.hooks.preToolUse?.[0]).toEqual(USER_HOOK);
    for (const event of Object.keys(HOOK_SCRIPTS)) {
      expect(merged.hooks[event]?.filter(isOwnEntry)).toHaveLength(1);
    }
  });

  it('replaces its own entries on a second install rather than adding more', () => {
    const once = mergeOwnHooks(parseHooksFile(undefined), NODE, '/old/scripts');
    const twice = mergeOwnHooks(once, NODE, SCRIPTS);
    expect(twice.hooks.preToolUse).toHaveLength(1);
    expect(twice.hooks.preToolUse?.[0]?.command).toContain(SCRIPTS);
  });

  it('removes only its own entries, and drops events left empty', () => {
    const merged = mergeOwnHooks(
      parseHooksFile({ hooks: { preToolUse: [USER_HOOK] } }),
      NODE,
      SCRIPTS,
    );
    expect(removeOwnHooks(merged).hooks).toEqual({ preToolUse: [USER_HOOK] });
  });
});

describe('applyInstall', () => {
  let home: string;
  let path: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-cursor-install-'));
    path = cursorHooksPath(home);
  });

  afterEach(() => {
    removeTrees([home]);
  });

  it('creates the file, then removes its entries again', () => {
    applyInstall(path, 'install', NODE, SCRIPTS);
    const installed = JSON.parse(readFileSync(path, 'utf8')) as { hooks: object };
    expect(Object.keys(installed.hooks).sort()).toEqual(Object.keys(HOOK_SCRIPTS).sort());
    applyInstall(path, 'uninstall', NODE, SCRIPTS);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ version: 1, hooks: {} });
  });

  it('leaves a file it cannot parse untouched', () => {
    mkdirSync(join(home, '.cursor'));
    writeFileSync(path, '{ not json');
    expect(() => {
      applyInstall(path, 'install', NODE, SCRIPTS);
    }).toThrow();
    expect(readFileSync(path, 'utf8')).toBe('{ not json');
  });
});

describe('applyInstall keeps the file’s permission bits', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-cursor-install-mode-'));
  });

  afterEach(() => {
    removeTrees([home]);
  });

  it.skipIf(process.platform === 'win32')('on a rewrite', () => {
    const path = cursorHooksPath(home);
    mkdirSync(join(home, '.cursor'));
    writeFileSync(path, '{"version":1,"hooks":{}}', { mode: 0o600 });
    chmodSync(path, 0o600);
    applyInstall(path, 'install', NODE, SCRIPTS);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });
});

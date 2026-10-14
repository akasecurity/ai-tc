import type * as Fs from 'node:fs';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { TestContext } from 'vitest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CLAUDE_CONFIG_MAX_BYTES, claudeSettingsVeto } from '../../src/account/claude-login.ts';
import type { ClaudeMachine } from '../helpers/transcript-builder.ts';
import { claudeMachine } from '../helpers/transcript-builder.ts';

// A layer listed here reports a size of 0 from stat and fstat, whatever it
// holds: what a special file, or a file that grew after it was measured, does.
const understated = vi.hoisted(() => ({ paths: new Set<string>(), fds: new Set<number>() }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof Fs>();
  const understate = (stat: Fs.Stats): Fs.Stats =>
    Object.create(stat, { size: { value: 0 } }) as Fs.Stats;
  return {
    ...actual,
    openSync: ((...args: Parameters<typeof actual.openSync>) => {
      const fd = actual.openSync(...args);
      if (understated.paths.has(String(args[0]))) understated.fds.add(fd);
      return fd;
    }) as typeof actual.openSync,
    closeSync: (fd: number) => {
      understated.fds.delete(fd);
      actual.closeSync(fd);
    },
    fstatSync: ((fd: number) => {
      const stat = actual.fstatSync(fd);
      return understated.fds.has(fd) ? understate(stat) : stat;
    }) as typeof actual.fstatSync,
    statSync: ((path: Fs.PathLike) => {
      const stat = actual.statSync(path);
      return understated.paths.has(String(path)) ? understate(stat) : stat;
    }) as typeof actual.statSync,
  };
});

let machine: ClaudeMachine;
let layer: string;

beforeEach(() => {
  machine = claudeMachine();
  mkdirSync(join(machine.root, 'layers'));
  layer = join(machine.root, 'layers', 'settings.json');
  understated.paths.clear();
  understated.fds.clear();
});

afterEach(() => {
  machine.dispose();
});

const link = (ctx: TestContext, target: string, path: string): void => {
  try {
    symlinkSync(target, path);
  } catch {
    ctx.skip('symbolic links cannot be created here');
  }
};

const sized = (bytes: number): string => {
  const head = '{"pad":"';
  const tail = '"}';
  return head + 'x'.repeat(bytes - head.length - tail.length) + tail;
};

describe('a settings layer read for a veto', () => {
  it('leaves an ordinary small layer alone, and vetoes one that sets an API key helper', () => {
    writeFileSync(layer, '{"theme":"dark"}');
    expect(claudeSettingsVeto([layer])).toBe(false);
    writeFileSync(layer, '{"apiKeyHelper":"/usr/local/bin/key-helper"}');
    expect(claudeSettingsVeto([layer])).toBe(true);
  });

  it('leaves a missing layer, and a layer that is a directory, alone', () => {
    expect(claudeSettingsVeto([layer])).toBe(false);
    mkdirSync(layer);
    expect(claudeSettingsVeto([layer])).toBe(false);
  });

  it('reads a layer of exactly the size cap, and vetoes one a byte over it', () => {
    writeFileSync(layer, sized(CLAUDE_CONFIG_MAX_BYTES));
    expect(claudeSettingsVeto([layer])).toBe(false);
    writeFileSync(layer, sized(CLAUDE_CONFIG_MAX_BYTES + 1));
    expect(claudeSettingsVeto([layer])).toBe(true);
  });

  it('vetoes a layer that holds more than the cap although it reports a size of 0', () => {
    writeFileSync(layer, sized(CLAUDE_CONFIG_MAX_BYTES + 1));
    understated.paths.add(layer);
    expect(claudeSettingsVeto([layer])).toBe(true);
  });

  it('reads a layer that is a symbolic link to an ordinary file', (ctx) => {
    const target = join(machine.root, 'layers', 'target.json');
    writeFileSync(target, '{"theme":"dark"}');
    link(ctx, target, layer);
    expect(claudeSettingsVeto([layer])).toBe(false);
    writeFileSync(target, '{"apiKeyHelper":"/usr/local/bin/key-helper"}');
    expect(claudeSettingsVeto([layer])).toBe(true);
  });

  it('vetoes a layer that is a link to a file over the cap', (ctx) => {
    const target = join(machine.root, 'layers', 'target.json');
    writeFileSync(target, sized(CLAUDE_CONFIG_MAX_BYTES + 1));
    link(ctx, target, layer);
    expect(claudeSettingsVeto([layer])).toBe(true);
  });

  it('leaves a link to a directory, and a link to a device, alone', (ctx) => {
    const directory = join(machine.root, 'layers', 'directory');
    mkdirSync(directory);
    link(ctx, directory, layer);
    expect(claudeSettingsVeto([layer])).toBe(false);
    const device = join(machine.root, 'layers', 'device.json');
    link(ctx, '/dev/zero', device);
    expect(claudeSettingsVeto([device])).toBe(false);
  });
});

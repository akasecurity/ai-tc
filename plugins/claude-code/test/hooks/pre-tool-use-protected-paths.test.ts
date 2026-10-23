/**
 * A user's protected paths, driven through the PreToolUse pipeline IN-PROCESS on
 * a real store in a temp home. The list is written the way a user's save writes
 * it (applyOnboarding), the command-risk pack is given each action in turn, and
 * the emitted decision is read beside the action the ledger recorded: both come
 * from the one resolution, so they must agree.
 */
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, shippedRegexMatchers } from '@akasecurity/plugin-sdk';
import type { WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type * as PathFieldsModule from '../../src/hooks/protected-path-fields.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// Lets one case make the matcher throw; every other case calls straight through.
const matcherFault = vi.hoisted(() => ({ on: false }));
vi.mock('../../src/hooks/protected-path-fields.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof PathFieldsModule>();
  return {
    ...actual,
    protectedPathFields: (...args: Parameters<typeof actual.protectedPathFields>) => {
      if (matcherFault.on) throw new Error('matcher fault');
      return actual.protectedPathFields(...args);
    },
  };
});

const RULE_ID = 'command-risk/protected-path-access';
const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));

// A name no ordinary output repeats, so a leak of the path is findable.
const LEAF = 'ledger-q4-9f3a1c7d2b.txt';

type Action = 'monitor' | 'warn' | 'redact' | 'block';

describe('protected paths in a PreToolUse call', () => {
  let home: string;
  let dataDir: string;
  let docs: string;
  let proj: string;

  beforeEach(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), 'aka-protected-run-')));
    dataDir = join(home, '.aka', 'data');
    docs = join(home, 'Documents');
    proj = join(home, 'proj');
    mkdirSync(docs, { recursive: true });
    mkdirSync(proj, { recursive: true });
    writeFileSync(join(docs, LEAF), 'x');
    // Both variables, so no platform resolves the developer's own ~/.aka.
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    expect(pack, 'the rule ships in a bundled pack').toBeDefined();
  });

  afterEach(() => {
    matcherFault.on = false;
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    removeTree(home);
  });

  function configure(action: Action, settings: Partial<WorkspaceSettings>): void {
    applyOnboarding(settings, join(home, '.aka'));
    const db = openLocalDatabase(dataDir, { shippedRegexMatchers: shippedRegexMatchers() });
    try {
      db.installedPacks.recordInventory(bundledDetections());
      if (pack) db.installedPacks.setPolicy(pack.namespace, pack.packId, action);
    } finally {
      db.close();
    }
  }

  async function run(tool: string, toolInput: Record<string, unknown>): Promise<HookOutput[]> {
    const out: HookOutput[] = [];
    await runPreToolUse(
      { tool_name: tool, tool_input: toolInput, session_id: 'protected-test', cwd: proj },
      (output) => {
        out.push(output);
        return Promise.resolve();
      },
      { mode: 'hook' },
    );
    return out;
  }

  const decisionOf = (outputs: readonly HookOutput[]): string | undefined => {
    const first = outputs[0] as
      { hookSpecificOutput?: { permissionDecision?: string } } | undefined;
    return first?.hookSpecificOutput?.permissionDecision;
  };

  async function recordedActions(): Promise<string[]> {
    const db = openLocalDatabase(dataDir, { shippedRegexMatchers: shippedRegexMatchers() });
    try {
      const recent = await db.findings.recentFindings({ limit: 50 });
      return recent.filter((f) => f.ruleId === RULE_ID).map((f) => f.actionTaken);
    } finally {
      db.close();
    }
  }

  const protectedRead = (): Record<string, unknown> => ({ file_path: join(docs, LEAF) });

  it('control: with no list a Read of the same file is not flagged', async () => {
    configure('block', {});
    expect(await run('Read', protectedRead())).toEqual([]);
    expect(await recordedActions()).toEqual([]);
  });

  it('control: with a list, a Read outside it is not flagged', async () => {
    configure('block', { protectedPaths: ['~/Documents'] });
    expect(await run('Read', { file_path: join(proj, 'a.txt') })).toEqual([]);
  });

  it('blocks a Read inside a protected folder under a block policy, and records the block', async () => {
    configure('block', { protectedPaths: ['~/Documents'] });
    const out = await run('Read', protectedRead());
    expect(decisionOf(out)).toBe('deny');
    expect(JSON.stringify(out)).toContain(RULE_ID);
    expect(await recordedActions()).toEqual(['block']);
  });

  it('does not echo the protected path in what it tells the model', async () => {
    configure('block', { protectedPaths: ['~/Documents'] });
    const out = await run('Read', protectedRead());
    expect(decisionOf(out)).toBe('deny');
    expectNoEchoOf(JSON.stringify(out), LEAF);
  });

  it('warns without denying under a warn policy', async () => {
    configure('warn', { protectedPaths: ['~/Documents'] });
    const out = await run('Read', protectedRead());
    expect(decisionOf(out)).toBeUndefined();
    expect(JSON.stringify(out)).toContain(RULE_ID);
    expect(await recordedActions()).toEqual(['warn']);
  });

  it('says nothing under monitor, but still records the access', async () => {
    configure('monitor', { protectedPaths: ['~/Documents'] });
    expect(await run('Read', protectedRead())).toEqual([]);
    expect(await recordedActions()).toHaveLength(1);
  });

  it('degrades a redact to the redact fallback and never rewrites the input', async () => {
    configure('redact', { protectedPaths: ['~/Documents'], redactFallback: 'block' });
    const denied = await run('Read', protectedRead());
    expect(decisionOf(denied)).toBe('deny');
    expect(JSON.stringify(denied)).not.toContain('updatedInput');
    expect(await recordedActions()).toEqual(['block']);
  });

  it('lets a redact through with a warning when the fallback is warn', async () => {
    configure('redact', { protectedPaths: ['~/Documents'], redactFallback: 'warn' });
    const out = await run('Read', protectedRead());
    expect(decisionOf(out)).toBeUndefined();
    expect(JSON.stringify(out)).not.toContain('updatedInput');
    expect(JSON.stringify(out)).toContain(RULE_ID);
    expect(await recordedActions()).toEqual(['warn']);
  });

  it('applies to Grep, Glob and Bash as it does to Read', async () => {
    configure('block', { protectedPaths: ['~/Documents'] });
    expect(decisionOf(await run('Grep', { pattern: 'x', path: docs }))).toBe('deny');
    expect(decisionOf(await run('Glob', { pattern: '**/*.txt', path: docs }))).toBe('deny');
    expect(decisionOf(await run('Bash', { command: `cat ~/Documents/${LEAF}` }))).toBe('deny');
    expect(decisionOf(await run('Bash', { command: `cp "${join(docs, LEAF)}" /tmp/x` }))).toBe(
      'deny',
    );
    expect(decisionOf(await run('Bash', { command: 'ls -la /tmp' }))).toBeUndefined();
    expect(await run('Grep', { pattern: 'x', path: proj })).toEqual([]);
  });

  it('applies a file name glob wherever the file sits', async () => {
    configure('block', { protectedPaths: ['**/ledger-q4-*.txt'] });
    expect(decisionOf(await run('Read', protectedRead()))).toBe('deny');
    expect(await run('Read', { file_path: join(proj, 'notes.txt') })).toEqual([]);
  });

  it('catches a path that reaches the folder through a symlink', async (ctx) => {
    configure('block', { protectedPaths: ['~/Documents'] });
    const link = join(proj, 'inbox');
    try {
      symlinkSync(docs, link, 'dir');
    } catch {
      return ctx.skip('symlinks need a privilege on this platform');
    }
    expect(decisionOf(await run('Read', { file_path: join(link, LEAF) }))).toBe('deny');
  });

  it('fails open when the settings carry a list this build cannot read', async () => {
    configure('block', {});
    writeFileSync(
      join(home, '.aka', 'settings', 'settings.json'),
      JSON.stringify({ protectedPaths: 'not-a-list', policy: 'block' }),
    );
    expect(await run('Read', protectedRead())).toEqual([]);
  });

  it('fails open when settings.json is not JSON at all', async () => {
    configure('block', { protectedPaths: ['~/Documents'] });
    writeFileSync(join(home, '.aka', 'settings', 'settings.json'), '{ not json');
    expect(await run('Read', protectedRead())).toEqual([]);
  });

  it('writes no evaluation notice when the list is evaluated normally', async () => {
    configure('block', { protectedPaths: ['~/Documents'] });
    const stderr: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderr.push(String(chunk));
      return true;
    });
    expect(decisionOf(await run('Read', protectedRead()))).toBe('deny');
    expect(await run('Read', { file_path: join(proj, 'a.txt') })).toEqual([]);
    expect(stderr.join('')).not.toContain('[aka] protected paths');
  });

  it('fails open and says so on stderr when the list cannot be evaluated', async () => {
    configure('block', { protectedPaths: ['~/Documents'] });
    const stderr: string[] = [];
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
      stderr.push(String(chunk));
      return true;
    });
    matcherFault.on = true;
    const out = await run('Read', protectedRead());
    expect(out).toEqual([]);
    const notice = stderr.join('');
    expect(notice).toContain('[aka] protected paths could not be evaluated');
    expect(notice).toContain('The call proceeds.');
    expect(JSON.stringify(out)).not.toContain('[aka]');
  });
});

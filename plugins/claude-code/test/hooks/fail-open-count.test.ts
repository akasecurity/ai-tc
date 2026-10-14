import { randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type * as Account from '@akasecurity/plugin-sdk/account';
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type * as Shared from '../../src/hooks/shared.ts';
import type { Device } from '../helpers/account-fixture.ts';
import { device, PERSONAL_KEY } from '../helpers/account-fixture.ts';
import type { Sent } from '../helpers/recording-client.ts';

// The fail-open path, run in-process: every entry's main() starts by reading
// stdin, so a read that rejects sends each entry straight into its top-level
// catch. countFailOpen is replaced by a spy so the case can see the call.
const failOpen = vi.hoisted(() => ({ count: vi.fn() }));
vi.mock('../../src/hooks/shared.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof Shared>()),
  readStdin: () => Promise.reject(new Error('stdin unavailable')),
  countFailOpen: failOpen.count,
}));

// The account cases open the gateway the plugin's factory builds; only its
// transport is replaced, by one that records what it is handed and sends nothing.
const sent = vi.hoisted((): Sent => ({ captures: [], audit: [], inventory: [] }));
vi.mock('../../../../packages/remote/src/index.ts', async (importOriginal) => {
  const { recordingClient } = await import('../helpers/recording-client.ts');
  return {
    ...(await importOriginal<typeof Remote>()),
    createRemoteClient: () => recordingClient(sent),
  };
});

// The session check, made to fault on demand, the way the readers report one:
// the hook must answer it with the repository key and count the exit like any
// other fail-open.
const accountFault = vi.hoisted(() => ({ on: false }));
vi.mock('@akasecurity/plugin-sdk/account', async (importOriginal) => {
  const real = await importOriginal<typeof Account>();
  return {
    ...real,
    checkClaudeHook: (...args: Parameters<typeof real.checkClaudeHook>) =>
      accountFault.on
        ? { check: { none: 'unreadable' as const }, mayAdmit: false, threw: true }
        : real.checkClaudeHook(...args),
  };
});

// test/hooks -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOKS_DIR = join(PLUGIN_ROOT, 'src', 'hooks');

/**
 * Every hook entry tsup builds, DERIVED from the build config rather than
 * listed here: a ninth hook lands in `entry` first, and this suite has to
 * reach it without anyone remembering to add it below. The pattern accepts any
 * file name, so a digit or an underscore in a new entry's name cannot hide it.
 */
function hookEntries(): string[] {
  const config = readFileSync(join(PLUGIN_ROOT, 'tsup.config.ts'), 'utf8');
  return [...config.matchAll(/'src\/hooks\/([^'/]+)\.ts'/g)]
    .map((match) => match[1])
    .filter((name): name is string => name !== undefined);
}

/**
 * Every file in `src/hooks` shaped like an entry — one that ends by exiting —
 * read from the directory rather than from the build config, so the two
 * derivations check each other.
 */
function entryShapedFiles(): string[] {
  return readdirSync(HOOKS_DIR)
    .filter((file) => file.endsWith('.ts'))
    .filter((file) => /\nprocess\.exit\(0\);\n?$/.test(readFileSync(join(HOOKS_DIR, file), 'utf8')))
    .map((file) => file.slice(0, -'.ts'.length));
}

// The top-level fail-open guard every entry ends in, capturing the catch body.
const FAIL_OPEN_GUARD =
  /\ntry \{\n {2}await main\(\);\n\} catch \{\n([\s\S]*?)\n\}\nprocess\.exit\(0\);\n?$/;

describe('every hook entry counts its fail-open exit', () => {
  // Failing open is the ABSENCE of output, so nothing a built hook prints can
  // show whether this call is wired — the e2e fail-open matrix asserts an
  // empty stdout either way. The shape is pinned at the source instead: the
  // catch that swallows the throw is also the only place that can count it.
  const entries = hookEntries();

  it('derives EXACTLY the entry-shaped files in src/hooks from tsup.config.ts', () => {
    // An exact set, not a floor: an entry the config pattern misses, or a hook
    // wired some other way, fails here instead of generating no case below.
    // The named member keeps two empty derivations from agreeing vacuously.
    expect(entries).toContain('session-start');
    expect(new Set(entries)).toEqual(new Set(entryShapedFiles()));
  });

  it.each(entries)('%s calls countFailOpen() inside its top-level catch', (name) => {
    const source = readFileSync(join(HOOKS_DIR, `${name}.ts`), 'utf8');
    const guard = FAIL_OPEN_GUARD.exec(source);
    expect(guard, `${name}.ts must end in the try { await main() } catch guard`).not.toBeNull();
    expect(guard?.[1]).toMatch(/\bcountFailOpen\(\);/);
  });
});

describe('every hook entry counts its fail-open exit when main() throws', () => {
  // The source-shape cases above pin WHERE the call sits; these run it. Each
  // entry is imported once, which executes its top-level try/catch with a stdin
  // read that rejects, so the only way to satisfy the spy is the real catch body.
  const entries = hookEntries();
  let exit: MockInstance<typeof process.exit>;

  beforeEach(() => {
    failOpen.count.mockClear();
    exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as typeof process.exit);
  });

  afterEach(() => {
    exit.mockRestore();
  });

  it.each(entries)('%s counts one exit and still exits 0', async (name) => {
    await import(`../../src/hooks/${name}.ts`);
    expect(failOpen.count).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(0);
  });
});

describe('a session check that faults', () => {
  let dev: Device;
  beforeEach(() => {
    failOpen.count.mockClear();
    dev = device(sent);
    dev.attach();
    dev.login({ org: dev.workOrg });
  });
  afterEach(() => {
    accountFault.on = false;
    dev.dispose();
  });

  it('lets the call through on its repository key, sends nothing and counts one fail-open', async () => {
    const t = dev.transcript(randomUUID());
    dev.boundary(t);
    const later = (n: number): string => new Date(Date.now() + (n + 1) * 1_000).toISOString();
    t.prompt(later(1));
    t.org(dev.workOrg, later(2));
    t.reply(later(3));
    accountFault.on = true;
    const emitted: unknown[] = [];
    await runPreToolUse(
      {
        session_id: t.sessionId,
        transcript_path: t.path,
        cwd: dev.personal,
        hook_event_name: 'PreToolUse',
        tool_name: 'Write',
        tool_input: { file_path: join(dev.personal, 'notes.md'), content: 'hello' },
      },
      (output) => {
        emitted.push(output);
        return Promise.resolve();
      },
      { mode: 'hook' },
    );
    expect(emitted).toEqual([]);
    expect(
      dev
        .storedRows()
        .filter((row) => row.eventType === 'code_change')
        .map((row) => row.scopeKey),
    ).toEqual([PERSONAL_KEY]);
    expect(dev.sent.captures).toEqual([]);
    expect(failOpen.count).toHaveBeenCalledTimes(1);
  });
});

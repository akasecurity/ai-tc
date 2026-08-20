// Drives ALL FOUR real built Antigravity hooks against hostile stdin.
//
// The Claude Code sibling of this file (`fail-open.e2e.test.ts` there) asserts
// the opposite bytes: on that host a faulting hook must print NOTHING, and its
// checks are absence checks. Here every one of those same faults must instead
// produce a valid JSON object, because Antigravity reads a non-zero exit, a
// schema-rejected payload, and empty stdout alike as a `deny` on the tool call.
// A regression that merely stopped printing would block every tool call the
// user makes, and no absence assertion anywhere could see it.
//
// So the shape of every case here is: exit 0, stdout parses, and it parses to
// the payload that hook's own "carry on unchanged" is spelled as. Silence fails
// loudly rather than passing quietly.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/e2e -> plugins/antigravity
const PLUGIN_ROOT = join(HERE, '..', '..');
const script = (name: string): string => join(PLUGIN_ROOT, 'scripts', `${name}.js`);

/**
 * The four hooks that delegate to `runHookFailOpen`, each with the payload the
 * host must receive when the body cannot decide. `pre-invocation` is the one
 * that takes an argument (its own manifest path), so the argv is carried here
 * rather than assumed.
 */
const HOOKS = [
  { name: 'pre-tool-use', argv: [] as string[], failOpen: { decision: 'allow' } },
  { name: 'post-tool-use', argv: [] as string[], failOpen: {} },
  { name: 'stop', argv: [] as string[], failOpen: {} },
  {
    name: 'pre-invocation',
    argv: [join(PLUGIN_ROOT, 'plugin.json')],
    failOpen: {},
  },
] as const;

/**
 * Hostile stdin, one entry per way a payload can arrive broken.
 *
 * `oversized` exercises the READ direction — a payload far past the pipe buffer
 * that the hook must consume without stalling or truncating its own answer. It
 * is deliberately NOT a test of the write-direction flush hazard: what a hook
 * emits here is `{"decision":"allow"}` or `{}`, twenty bytes at most, so no
 * amount of oversized stdin can push its stdout past the buffer. That property
 * belongs to `emit` and is driven directly in
 * `test/hooks/fail-open-wrapper.test.ts`.
 */
const FAULTS: { label: string; input: string | Buffer }[] = [
  { label: 'empty stdin', input: '' },
  { label: 'malformed JSON', input: '{not json at all' },
  { label: 'truncated JSON', input: '{"toolCall":{"name":"run_command","args":{"CommandLine":"ec' },
  { label: 'a JSON scalar rather than an object', input: '"just-a-string"' },
  { label: 'JSON null', input: 'null' },
  { label: 'binary', input: Buffer.from([0x00, 0xff, 0xfe, 0x01, 0x02, 0x7f, 0x00]) },
  {
    label: 'oversized payload past the pipe buffer',
    input: JSON.stringify({
      toolCall: { name: 'run_command', args: { CommandLine: 'echo ' + 'A'.repeat(1024 * 1024) } },
      conversationId: 'conv-oversized',
      workspacePaths: ['/tmp'],
    }),
  },
];

interface HookRun {
  stdout: string;
  status: number;
}

function runHook(hookName: string, argv: readonly string[], home: string, input: string | Buffer) {
  try {
    const stdout = execFileSync(process.execPath, [script(hookName), ...argv], {
      env: { HOME: home, USERPROFILE: home },
      input,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
    });
    return { stdout, status: 0 } satisfies HookRun;
  } catch (err) {
    const e = err as { stdout?: string; status?: number };
    return { stdout: e.stdout ?? '', status: e.status ?? 1 } satisfies HookRun;
  }
}

/**
 * Assert the three things the host requires, in the order that makes a failure
 * readable: it exited 0, it said something, and what it said is exactly one
 * JSON object. `JSON.parse` over the WHOLE stdout is what forbids a second
 * object — two concatenated objects do not parse.
 */
function soleObject(run: HookRun): unknown {
  expect(run.status).toBe(0);
  expect(run.stdout).not.toBe('');
  return JSON.parse(run.stdout) as unknown;
}

// Each case gets its own throwaway home so a store one hook creates cannot
// change how the next one behaves.
function withHome<T>(label: string, fn: (home: string) => T): T {
  const home = mkdtempSync(join(tmpdir(), `aka-agy-failopen-${label}-`));
  try {
    return fn(home);
  } finally {
    removeTree(home);
  }
}

describe.each(HOOKS)(
  '$name built hook — fails open by PRINTING, on every fault',
  (hook) => {
    it.each(FAULTS)('emits its carry-on payload on $label', (fault) => {
      const run = withHome(hook.name, (home) => runHook(hook.name, hook.argv, home, fault.input));
      expect(soleObject(run)).toEqual(hook.failOpen);
    });

    it('emits its carry-on payload over a store that cannot be opened', () => {
      // The fault that is not about stdin: the hook's own dependency is broken.
      // Not the "SQLite format 3\0" header, so the first PRAGMA fails
      // SQLITE_NOTADB.
      //
      // Note what this does and does not reach. `openGatewayOrNull` catches the
      // open failure and returns null by design, so the body still returns a
      // normal decision — this proves the degraded path answers, NOT that the
      // wrapper's catch works. No fault available here makes a body throw after
      // the store opens, so the wrapper's throw branch is covered by
      // `test/hooks/fail-open-wrapper.test.ts` and by nothing at this tier.
      const run = withHome(`${hook.name}-corrupt`, (home) => {
        const dataDir = join(home, '.aka', 'data');
        mkdirSync(dataDir, { recursive: true });
        writeFileSync(
          join(dataDir, 'aka.db'),
          'AKA corrupt-store fixture — not a database\n'.repeat(64),
        );
        return runHook(
          hook.name,
          hook.argv,
          home,
          JSON.stringify({
            toolCall: { name: 'run_command', args: { CommandLine: 'echo hello' } },
            stepIdx: 0,
            conversationId: 'conv-corrupt',
            workspacePaths: ['/tmp'],
          }),
        );
      });
      expect(soleObject(run)).toEqual(hook.failOpen);
    });
  },
  60_000,
);

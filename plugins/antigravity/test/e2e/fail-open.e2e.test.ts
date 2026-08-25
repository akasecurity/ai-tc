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
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { withTempHome } from '../helpers/run-hook.ts';

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
  stderr: string;
  status: number;
}

// spawnSync rather than execFileSync: execFileSync returns stdout ALONE and
// lets the child's stderr through to the parent, so a hook that exits 0 while
// writing a warning reads as having written nothing. On THIS host stdout is the
// decision channel and must stay exactly one JSON object, so a once-per-session
// notice has nowhere else to go — leaving stderr uncaptured would make it
// unassertable.
function runHook(hookName: string, argv: readonly string[], home: string, input: string | Buffer) {
  const result = spawnSync(process.execPath, [script(hookName), ...argv], {
    env: { HOME: home, USERPROFILE: home },
    input,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const { error, status, stdout, stderr } = result as unknown as {
    error?: Error;
    status: number | null;
    stdout: string | null;
    stderr: string | null;
  };
  if (error && stdout === null && stderr === null) {
    return { stdout: '', stderr: error.message, status: 1 } satisfies HookRun;
  }
  return { stdout: stdout ?? '', stderr: stderr ?? '', status: status ?? 1 } satisfies HookRun;
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

describe.each(HOOKS)(
  '$name built hook — fails open by PRINTING, on every fault',
  (hook) => {
    it.each(FAULTS)('emits its carry-on payload on $label', (fault) => {
      // Each case gets its own throwaway home so a store one hook creates
      // cannot change how the next one behaves.
      const run = withTempHome(
        (home) => runHook(hook.name, hook.argv, home, fault.input),
        `aka-agy-failopen-${hook.name}-`,
      );
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
      const run = withTempHome((home) => {
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
      }, `aka-agy-failopen-${hook.name}-corrupt-`);
      expect(soleObject(run)).toEqual(hook.failOpen);
    });

    // A hostile home is the fault class the corrupt-store case cannot reach: the
    // store opens PERFECTLY, so nothing is degraded — the corpus simply lands
    // somewhere the user did not choose. On THIS host that makes silence doubly
    // dangerous: an empty stdout is read as a DENY, so the hook must still print
    // its decision AND say where the store went, on a channel that cannot
    // disturb it.
    it('still prints its decision on a symlinked home, and says the store moved', (ctx) => {
      if (process.platform === 'win32') {
        ctx.skip('unprivileged symlink creation is not available on Windows');
        return;
      }
      let victim = '';
      const run = withTempHome((home) => {
        // Inside `home` so withTempHome's teardown removes it, and RESOLVED
        // because linkTarget() realpaths what it reports.
        const target = join(home, 'victim');
        mkdirSync(target, { recursive: true });
        chmodSync(target, 0o755);
        symlinkSync(target, join(home, '.aka'));
        victim = realpathSync(target);
        return runHook(
          hook.name,
          hook.argv,
          home,
          // `transcriptPath` is what makes this a valid reconcile trigger, which
          // `post-tool-use` and `stop` need before they load config at all —
          // without it they return early and never reach the warning. Pointed at
          // a path that does not exist, the way the pre-tool-use e2e already
          // does: the reconcile spawn is throttled, detached and best-effort, so
          // it finds nothing and this row never waits on it.
          JSON.stringify({
            toolCall: { name: 'run_command', args: { CommandLine: 'echo hello' } },
            stepIdx: 0,
            conversationId: 'conv-symlinked',
            transcriptPath: '/tmp/does-not-exist/transcript.jsonl',
            workspacePaths: ['/tmp'],
          }),
        );
      }, `aka-agy-failopen-${hook.name}-symlink-`);

      // The decision first: on a deny-by-default host this is the assertion that
      // matters, and a warning that cost the user their tool call would be worse
      // than the silence it replaced.
      expect(soleObject(run)).toEqual(hook.failOpen);
      // …and the redirection is really surfaced, on stderr.
      expect(run.stderr).toContain('is a symlink');
      expect(run.stderr).toContain(victim);
      expect(run.stderr).toContain('NOT owner-only');
    });
  },
  60_000,
);

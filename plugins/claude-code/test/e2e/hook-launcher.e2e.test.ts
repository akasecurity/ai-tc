/**
 * The launcher every hook command runs (src/hooks/launch.ts): it turns on
 * Node's compile cache and then loads `<name>.body.js`, the hook itself. It
 * sits in front of every hook, so it inherits the first principle — it must
 * never break a session — and a fault that happens BEFORE the body has loaded
 * is outside every catch the body has. These cases drive the built launcher
 * against copies of `scripts/` with the body removed or broken, and against
 * homes where the cache cannot be made.
 *
 * Every refusal case is paired with the same payload through an intact build,
 * which must emit: that is the positive control without which "printed
 * nothing" would pass for a launcher that never ran the hook at all.
 */
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { DATA_DIR_MODE } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  BODY_LOAD_FAILED,
  bodyScriptFor,
  CACHE_DIR_MODE,
  compileCacheDir,
} from '../../src/hooks/launch-paths.ts';
import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const PLUGIN_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');
const RULE_ID = 'secrets/twilio-key';
const PLUGIN_VERSION = (
  JSON.parse(readFileSync(join(PLUGIN_ROOT, 'package.json'), 'utf8')) as { version: string }
).version;

// The value comes from a bundled rule's own `examples`, so no secret-shaped
// literal lives in this file.
const SECRET = bundledDetections()
  .flatMap((pack) => pack.rules)
  .find((rule) => rule.id === RULE_ID)?.examples?.[0];
if (SECRET === undefined) throw new Error(`bundled rule ${RULE_ID} has no example to drive`);

function payload(home: string): string {
  return JSON.stringify({
    session_id: 'launcher-e2e-session',
    transcript_path: join(home, 'transcript.jsonl'),
    cwd: home,
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command: `echo ${String(SECRET)}` },
  });
}

/** A copy of the built scripts, for a case that breaks one of them. */
function scriptsCopy(home: string): string {
  const dir = join(home, 'scripts-copy');
  cpSync(SCRIPTS_DIR, dir, { recursive: true });
  return dir;
}

interface HooksManifest {
  hooks: Record<string, { hooks: { command: string }[] }[]>;
}

const manifestScripts = [
  ...new Set(
    Object.values(
      (JSON.parse(readFileSync(join(PLUGIN_ROOT, 'hooks', 'hooks.json'), 'utf8')) as HooksManifest)
        .hooks,
    )
      .flat()
      .flatMap((entry) => entry.hooks)
      .flatMap(({ command }) => [
        ...[...command.matchAll(/scripts\/([\w-]+)\.js/g)].map((m) => m[1]),
        // A hook run through the shell client is named after the client.
        ...[...command.matchAll(/hook-client\.sh" ([\w-]+)/g)].map((m) => m[1]),
      ]),
  ),
].filter((name): name is string => name !== undefined);

describe('the launcher paths', () => {
  it('names the body beside the launcher', () => {
    expect(bodyScriptFor(join('a', 'scripts', 'pre-tool-use.js'))).toBe(
      join('a', 'scripts', 'pre-tool-use.body.js'),
    );
  });

  it('keeps the cache under ~/.aka, per plugin version, owner-only like the rest of it', () => {
    expect(compileCacheDir(join('h'), '1.2.3')).toBe(
      join('h', '.aka', 'cache', 'compile', '1.2.3'),
    );
    expect(CACHE_DIR_MODE).toBe(DATA_DIR_MODE);
  });
});

describe('every hook the manifest runs goes through the launcher', () => {
  it('finds the manifest scripts', () => {
    expect(manifestScripts).toEqual(
      expect.arrayContaining(['pre-tool-use', 'post-tool-use', 'stop']),
    );
  });

  it.each(manifestScripts)('%s is a launcher with its body beside it', (name) => {
    const launcher = readFileSync(join(SCRIPTS_DIR, `${name}.js`), 'utf8');
    // The launcher bundles nothing but itself: anything more is compiled
    // before the cache is on, which is the cost it exists to avoid.
    expect(launcher).toContain('enableCompileCache');
    expect(launcher.length).toBeLessThan(4096);
    expect(existsSync(join(SCRIPTS_DIR, `${name}.body.js`)), `${name}.body.js`).toBe(true);
  });
});

describe('the launcher fails open', () => {
  it('runs the hook through an intact build (the positive control)', () => {
    withTempHome((home) => {
      const run = runHook('pre-tool-use', payload(home), { env: tempHomeEnv(home) });
      expect(run.status).toBe(0);
      expect(run.stdout).not.toBe('');
      expect(() => JSON.parse(run.stdout) as unknown).not.toThrow();
      expect(run.stderr).not.toContain(BODY_LOAD_FAILED);
    });
  });

  it('exits 0, prints nothing on stdout and says so on stderr when the body is missing', () => {
    withTempHome((home) => {
      const dir = scriptsCopy(home);
      rmSync(join(dir, 'pre-tool-use.body.js'));
      const run = runHook('pre-tool-use', payload(home), {
        env: tempHomeEnv(home),
        scriptsDir: dir,
      });
      expect(run.status).toBe(0);
      expect(run.stdout).toBe('');
      // One fixed line and nothing else: no path, nothing from the payload.
      expect(run.stderr).toBe(`${BODY_LOAD_FAILED}\n`);
    });
  });

  it.each([
    ['throws while it loads', "throw new Error('body failed to load');\n"],
    ['does not parse', 'export const = ;\n'],
  ])('exits 0, prints nothing on stdout and says so on stderr when the body %s', (_label, body) => {
    withTempHome((home) => {
      const dir = scriptsCopy(home);
      writeFileSync(join(dir, 'pre-tool-use.body.js'), body);
      const run = runHook('pre-tool-use', payload(home), {
        env: tempHomeEnv(home),
        scriptsDir: dir,
      });
      expect(run.status).toBe(0);
      expect(run.stdout).toBe('');
      // One fixed line and nothing else: no path, nothing from the payload.
      expect(run.stderr).toBe(`${BODY_LOAD_FAILED}\n`);
    });
  });

  it('still runs the hook when the cache directory cannot be made', () => {
    withTempHome((home) => {
      // A FILE where the cache directory's parent belongs: the create fails on
      // every platform, whoever runs the suite.
      mkdirSync(join(home, '.aka'), { recursive: true });
      writeFileSync(join(home, '.aka', 'cache'), 'not a directory');
      const run = runHook('pre-tool-use', payload(home), { env: tempHomeEnv(home) });
      expect(run.status).toBe(0);
      expect(run.stdout).not.toBe('');
      expect(() => JSON.parse(run.stdout) as unknown).not.toThrow();
    });
  });

  it('still runs the hook when the cache directory cannot be written', (ctx) => {
    if (process.platform === 'win32')
      ctx.skip('POSIX permission bits do not deny writes on Windows');
    withTempHome((home) => {
      const cache = compileCacheDir(home, PLUGIN_VERSION);
      mkdirSync(cache, { recursive: true });
      chmodSync(cache, 0o500);
      try {
        const run = runHook('pre-tool-use', payload(home), { env: tempHomeEnv(home) });
        expect(run.status).toBe(0);
        expect(run.stdout).not.toBe('');
      } finally {
        chmodSync(cache, 0o700);
      }
    });
  });
});

describe('the compile cache', () => {
  it('is written under the home the hook ran against', () => {
    withTempHome((home) => {
      const run = runHook(
        'stop',
        JSON.stringify({ session_id: 's', transcript_path: join(home, 't.jsonl') }),
        {
          env: tempHomeEnv(home),
        },
      );
      expect(run.status).toBe(0);
      const cache = compileCacheDir(home, PLUGIN_VERSION);
      expect(existsSync(cache)).toBe(true);
      // Node keeps one subdirectory per runtime version, holding the entries.
      const entries = readdirSync(cache, { recursive: true });
      expect(entries.length).toBeGreaterThan(1);
      if (process.platform !== 'win32') {
        // Created owner-only, including ~/.aka itself on a home that had none.
        expect(statSync(join(home, '.aka')).mode & 0o777).toBe(0o700);
        expect(statSync(join(home, '.aka', 'cache')).mode & 0o777).toBe(0o700);
        expect(statSync(join(home, '.aka', 'cache', 'compile')).mode & 0o777).toBe(0o700);
        expect(statSync(cache).mode & 0o777).toBe(0o700);
      }
    });
  });
});

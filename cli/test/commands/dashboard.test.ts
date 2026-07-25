import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import {
  BIND_HOST,
  refreshUpdateMirror,
  runDashboardServer,
} from '../../src/commands/dashboard.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-dashboard-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

it('pre-launch mirror refresh is fail-open: an unusable store never throws, and names the cause', () => {
  // A FILE where the data dir should be — openLocalDatabase cannot create or
  // open the store here. The refresh must swallow it (launch proceeds) and
  // surface the cause on stderr rather than a bare "(store busy?)" guess.
  const blocked = join(dir, 'blocker');
  writeFileSync(blocked, 'x');
  const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

  expect(() => {
    refreshUpdateMirror(blocked);
  }).not.toThrow();

  const message = stderr.mock.calls.map((c) => String(c[0])).join('');
  expect(message).toContain('could not refresh the detection-update mirror');
  expect(message).toContain('launching anyway');
  expect(message).toMatch(/mirror: \S/); // a concrete cause, not the bare label
});

it('pre-launch mirror refresh records the bundled inventory on a healthy store', () => {
  refreshUpdateMirror(dir);

  const raw = new DatabaseSync(join(dir, 'aka.db'));
  const packs = (raw.prepare('SELECT count(*) AS n FROM available_packs').get() as { n: number }).n;
  raw.close();
  expect(packs).toBeGreaterThan(0); // the bundled packs landed in the mirror
});

// The `__dashboard-server` subcommand boots the standalone server IN-PROCESS via a
// dynamic import — the mechanism a SEA binary relies on (it cannot exec an external
// script). Next's real server.js is ESM with no `require.main` guard, so importing it
// evaluates its top level and starts the server; the stand-in mirrors that shape.
// Plain-node CI exercising this is what retires that risk before any binary exists.
it('__dashboard-server imports the given server-js in-process (ESM, no entry guard)', async () => {
  const serverJs = join(dir, 'server.mjs');
  // Mirrors Next's standalone entry: ESM, __dirname via import.meta.url, boots on load.
  writeFileSync(
    serverJs,
    "import { writeFileSync } from 'node:fs';\n" +
      "import { fileURLToPath } from 'node:url';\n" +
      "import { dirname, join } from 'node:path';\n" +
      'const __dirname = dirname(fileURLToPath(import.meta.url));\n' +
      "writeFileSync(join(__dirname, 'booted.txt'), 'ok');\n",
  );

  await runDashboardServer(['--server-js', serverJs]);

  expect(existsSync(join(dir, 'booted.txt'))).toBe(true);
});

it('__dashboard-server without --server-js fails with a message, does not throw', async () => {
  const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  const prevExit = process.exitCode;

  await expect(runDashboardServer([])).resolves.toBeUndefined();

  expect(stderr.mock.calls.map((c) => String(c[0])).join('')).toContain('--server-js');
  expect(process.exitCode).toBe(1);
  process.exitCode = prevExit; // don't leak a failing exit code into the runner
});

// The pre-flight port probe (isPortFree's probe.listen) and both server spawns
// (the dev `next start --hostname` and the standalone HOSTNAME env) must bind the
// SAME loopback address. If they drift — e.g. the bind moves to `::1` but the probe
// still checks `127.0.0.1` — isPortFree reports a busy port free, the friendly
// "port in use" message is skipped, and Next dies on the raw EADDRINUSE the probe
// exists to prevent. Pin that they share one source of truth (BIND_HOST) by proving
// the literal appears exactly once in the source: the const declaration. Every bind
// site must reference the constant, so a second hard-coded literal fails this test.
it('probe and both binds share one loopback source of truth (no drift)', () => {
  expect(BIND_HOST).toBe('127.0.0.1');

  const src = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '../../src/commands/dashboard.ts'),
    'utf8',
  );
  const literals = src.match(/127\.0\.0\.1/g) ?? [];
  expect(literals).toHaveLength(1); // only the BIND_HOST declaration hard-codes it
  expect(src).toMatch(/const BIND_HOST = '127\.0\.0\.1'/);
});

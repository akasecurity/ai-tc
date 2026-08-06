// Post-package smoke for the dashboard boot path. A SEA binary cannot exec a script, so
// `aka dashboard` serves the Next standalone server IN-PROCESS via the hidden
// `__dashboard-server` subcommand (dynamic import of the bundled server.js). `--version`
// only evaluates the module graph — it never starts the server — so this drives the
// PACKAGED binary through that subcommand against its own web-ui sidecar and asserts the
// dashboard actually serves HTTP 200. Run after `package:sea`.
//
// It runs the binary from a COPY of the staged archive placed outside this repo, which is
// the only reason the check means anything. server.js does `require('next')`, resolved by
// Node's upward node_modules walk — so run in place, from cli/sea-dist/aka-<triple>/, that
// walk climbs out of the archive into the workspace's own cli/node_modules and finds the
// `next` the CLI declares as a runtime dep. An archive shipping no node_modules at all
// therefore serves 200 here and dies with "Cannot find module 'next'" the moment a user
// extracts it anywhere else. That is not hypothetical: it is what shipped, green, until
// package-sea grew the step that installs those deps into the staged web-ui.
//
// Copying to a temp dir removes the workspace from the walk; assertNoAncestorNodeModules
// then proves it, because a smoke that silently regained an ancestor node_modules would
// go back to passing on a broken archive without changing a line of this file.
//
// It also drives TWO routes. `/security` alone shows the server boots; a second Server
// Component page shows it renders, which is the claim that actually covers the runtime
// module graph rather than just its entrypoint.
import { execFileSync, spawn } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cliDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const { platform, arch } = process;
const exeName = platform === 'win32' ? 'aka.exe' : 'aka';
const stagedDir = join(cliDir, 'sea-dist', `aka-${platform}-${arch}`);
if (!existsSync(join(stagedDir, exeName)))
  throw new Error(`missing ${join(stagedDir, exeName)} — run \`pnpm package:sea\` first`);
if (!existsSync(join(stagedDir, 'web-ui', 'web-ui', 'server.js')))
  throw new Error(`missing the web-ui sidecar — run \`pnpm bundle:web-ui\` then \`package:sea\``);

const PORT = 41847;
const HOST = '127.0.0.1';

// Two routes, not one. The first proves the server BOOTS; the second proves a Server
// Component page RENDERS, which is what actually walks the runtime module graph rather than
// just its entrypoint. Both go through web-ui/middleware.ts.
const ROUTES = ['/security', '/findings'];

// Throw if any node_modules sits on the walk from `startDir` to the filesystem root. The
// archive's own (web-ui/node_modules) sits BELOW the root passed in and is deliberately not
// counted — it is the thing under test.
//
// Walks the REAL path: Node resolves a module's realpath before starting its upward walk, so
// on macOS — where tmpdir() is /var/…, a symlink to /private/var — the resolver's chain
// includes /private/node_modules and a walk over the symlinked path never looks there.
const assertNoAncestorNodeModules = (startDir) => {
  const hits = [];
  for (let dir = realpathSync(startDir); ;) {
    if (existsSync(join(dir, 'node_modules'))) hits.push(join(dir, 'node_modules'));
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  if (hits.length > 0) {
    throw new Error(
      `the smoke root ${startDir} has node_modules above it (${hits.join(', ')}) — server.js ` +
        `would resolve \`next\` from there, so this check could not tell a self-contained ` +
        `archive from a broken one`,
    );
  }
};

const get = (path) =>
  new Promise((resolve) => {
    const req = http.get({ host: HOST, port: PORT, path }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', () => resolve(null));
  });

// Isolate the ~/.aka store in a temp home so the smoke never touches a real one and
// runs deterministically on a clean CI runner. homedir() honors HOME / USERPROFILE.
const home = mkdtempSync(join(tmpdir(), 'aka-dash-smoke-'));
const stage = mkdtempSync(join(tmpdir(), 'aka-dash-stage-'));
const env = { ...process.env, HOME: home, USERPROFILE: home, PORT: String(PORT), HOSTNAME: HOST };

let child;
try {
  // Run from a copy outside the repo — see the header. cpSync preserves modes, so the
  // binary stays executable and its ad-hoc macOS signature (embedded in the Mach-O)
  // survives.
  const runDir = join(stage, `aka-${platform}-${arch}`);
  cpSync(stagedDir, runDir, { recursive: true });

  assertNoAncestorNodeModules(stage);

  const exe = join(runDir, exeName);
  const serverJs = join(runDir, 'web-ui', 'web-ui', 'server.js');

  // Seed the store the dashboard reads (init resolves the same homedir()/.aka).
  execFileSync(exe, ['init', '--yes'], { env, stdio: 'ignore' });

  child = spawn(exe, ['__dashboard-server', '--server-js', serverJs], {
    cwd: dirname(serverJs),
    env,
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  child.on('error', (err) => {
    process.stderr.write(`sea-dashboard-smoke: spawn failed — ${err.message}\n`);
    process.exitCode = 1;
  });

  // The retry loop is the BOOT probe and belongs to the first route only. Retrying the rest
  // would let a route that never renders read as merely slow.
  let status = null;
  for (let i = 0; i < 120 && child.exitCode === null; i++) {
    status = await get(ROUTES[0]);
    if (status) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  if (status !== 200) {
    throw new Error(`dashboard ${ROUTES[0]} returned ${status ?? 'no response'}`);
  }

  const served = [`${ROUTES[0]} -> ${status}`];
  for (const route of ROUTES.slice(1)) {
    const code = await get(route);
    if (code !== 200) throw new Error(`dashboard ${route} returned ${code ?? 'no response'}`);
    served.push(`${route} -> ${code}`);
  }
  process.stdout.write(`sea-dashboard-smoke: OK (${served.join(', ')})\n`);
} catch (err) {
  process.stderr.write(
    `sea-dashboard-smoke: FAIL — ${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exitCode = 1;
} finally {
  if (child) child.kill('SIGKILL');
  // Best-effort teardown: on Windows the just-killed server can still hold handles
  // on the temp store for a moment, so retry — and never let a cleanup EPERM mask the
  // smoke result (the OS temp dir is reclaimed by the runner regardless).
  for (const dir of [home, stage]) {
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    } catch {
      // ignore — temp dir, reclaimed by the OS/runner
    }
  }
}

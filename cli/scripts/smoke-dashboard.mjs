// Post-package smoke for the dashboard boot path. A SEA binary cannot exec a script, so
// `aka dashboard` serves the Next standalone server IN-PROCESS via the hidden
// `__dashboard-server` subcommand (dynamic import of the bundled server.js). `--version`
// only evaluates the module graph — it never starts the server — so this drives the
// PACKAGED binary through that subcommand against its own web-ui sidecar and asserts the
// dashboard actually serves HTTP 200. Run after `package:sea`.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const cliDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const { platform, arch } = process;
const outDir = join(cliDir, 'sea-dist', `aka-${platform}-${arch}`);
const exe = join(outDir, platform === 'win32' ? 'aka.exe' : 'aka');
const serverJs = join(outDir, 'web-ui', 'web-ui', 'server.js');
if (!existsSync(exe)) throw new Error(`missing ${exe} — run \`pnpm package:sea\` first`);
if (!existsSync(serverJs))
  throw new Error(`missing ${serverJs} — run \`pnpm bundle:web-ui\` then \`package:sea\``);

const PORT = 41847;
const HOST = '127.0.0.1';

// Isolate the ~/.aka store in a temp home so the smoke never touches a real one and
// runs deterministically on a clean CI runner. homedir() honors HOME / USERPROFILE.
const home = mkdtempSync(join(tmpdir(), 'aka-dash-smoke-'));
const env = { ...process.env, HOME: home, USERPROFILE: home, PORT: String(PORT), HOSTNAME: HOST };

const get = (path) =>
  new Promise((resolve) => {
    const req = http.get({ host: HOST, port: PORT, path }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', () => resolve(null));
  });

let child;
try {
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

  let status = null;
  for (let i = 0; i < 120 && child.exitCode === null; i++) {
    status = await get('/security');
    if (status) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  if (status !== 200) throw new Error(`dashboard /security returned ${status ?? 'no response'}`);
  process.stdout.write(`sea-dashboard-smoke: OK (/security -> ${status})\n`);
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
  try {
    rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // ignore — temp dir, reclaimed by the OS/runner
  }
}

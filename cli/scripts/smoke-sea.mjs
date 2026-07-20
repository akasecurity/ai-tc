// Post-build smoke for the SEA bundle: runs the built dist-sea/cli.mjs through core
// commands and exits non-zero on any failure. CI runs this after `build:sea` (and, in
// the packaging PR, against the compiled binary). Exercises the full module graph —
// including ink/yoga's top-level-await wasm load, which happens at import — plus the
// SQLite store path.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const bundle = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist-sea', 'cli.mjs');
const home = mkdtempSync(join(tmpdir(), 'aka-sea-smoke-'));
const run = (...args) => execFileSync(process.execPath, [bundle, ...args], { encoding: 'utf8' });

try {
  const version = run('--version').trim();
  if (!/^\d+\.\d+\.\d+/.test(version)) throw new Error(`--version returned "${version}"`);
  if (!run('--help').includes('Usage: aka')) throw new Error('--help missing usage');

  run('init', '--home', home, '--yes');
  if (!run('stats', '--home', home).includes('Findings:')) throw new Error('stats missing output');

  process.stdout.write(`sea-smoke: OK (v${version})\n`);
} catch (err) {
  process.stderr.write(`sea-smoke: FAIL — ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
} finally {
  rmSync(home, { recursive: true, force: true });
}

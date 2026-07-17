// Package the CLI as a Node Single Executable Application for the current OS/arch.
// Prereqs (run first): `build:sea` (dist-sea/cli.mjs) and `bundle:web-ui` (cli/web-ui).
// Produces sea-dist/aka-<platform>-<arch>/ containing the `aka` binary plus its sidecars:
//   boot.cjs, cli.mjs, package.json (for cliVersion), web-ui/ (the Next standalone).
// The binary embeds Node + entry.cjs; entry.cjs requires boot.cjs, which imports cli.mjs.
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { inject } from 'postject';

const cliDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const { platform, arch } = process;
const isWin = platform === 'win32';
const isMac = platform === 'darwin';

const bundle = join(cliDir, 'dist-sea', 'cli.mjs');
const webUiSrc = join(cliDir, 'web-ui');
if (!existsSync(bundle)) throw new Error('missing dist-sea/cli.mjs — run `pnpm build:sea` first');
if (!existsSync(join(webUiSrc, 'web-ui', 'server.js'))) {
  throw new Error('missing cli/web-ui — run `pnpm bundle:web-ui` first');
}

const outDir = join(cliDir, 'sea-dist', `aka-${platform}-${arch}`);
const exePath = join(outDir, isWin ? 'aka.exe' : 'aka');

// 1. Stage the binary's sidecars.
rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });
copyFileSync(bundle, join(outDir, 'cli.mjs'));
copyFileSync(join(cliDir, 'scripts', 'sea', 'boot.cjs'), join(outDir, 'boot.cjs'));
const pkg = JSON.parse(readFileSync(join(cliDir, 'package.json'), 'utf8'));
// Minimal manifest so the bundled cliVersion() (which walks up for @akasecurity/cli)
// resolves the version next to cli.mjs — a SEA has no package.json otherwise.
writeFileSync(
  join(outDir, 'package.json'),
  `${JSON.stringify({ name: pkg.name, version: pkg.version, private: true }, null, 2)}\n`,
);
cpSync(webUiSrc, join(outDir, 'web-ui'), { recursive: true });

// 2. Generate the SEA preparation blob from entry.cjs.
const blobPath = join(cliDir, 'sea-prep.blob');
execFileSync(process.execPath, ['--experimental-sea-config', join(cliDir, 'sea-config.json')], {
  cwd: cliDir,
  stdio: 'inherit',
});

// 3. Copy the running node binary and strip its signature (macOS) before injecting.
const nodeBin = realpathSync(process.execPath);
copyFileSync(nodeBin, exePath);
chmodSync(exePath, 0o755);
if (isMac) execFileSync('codesign', ['--remove-signature', exePath], { stdio: 'inherit' });

// 4. Inject the blob. The SEA fuse sentinel changed between Node releases, so read it
// from the target binary rather than hard-coding it.
const fuse = extractFuse(nodeBin);
await inject(exePath, 'NODE_SEA_BLOB', readFileSync(blobPath), {
  sentinelFuse: fuse,
  ...(isMac ? { machoSegmentName: 'NODE_SEA' } : {}),
});

// 5. Re-sign ad-hoc on macOS (injection invalidates the signature; unsigned is fine but
// the binary must carry a valid ad-hoc signature to run on Apple Silicon).
if (isMac) execFileSync('codesign', ['--sign', '-', exePath], { stdio: 'inherit' });

rmSync(blobPath, { force: true });

// 6. Self-check: the binary boots through entry.cjs → boot.cjs → cli.mjs and reports its
// version, which also evaluates the full module graph (including ink/yoga's top-level-await
// wasm load). Fail the build loudly if the packaged binary can't run.
const version = execFileSync(exePath, ['--version'], { encoding: 'utf8' }).trim();
if (!/^\d+\.\d+\.\d+/.test(version)) {
  throw new Error(`packaged binary --version returned "${version}"`);
}
process.stdout.write(`packaged: ${exePath} (verified v${version})\n`);

// Read the "NODE_SEA_FUSE_<hex>" sentinel embedded in a node binary.
function extractFuse(nodeBinPath) {
  const buf = readFileSync(nodeBinPath);
  const needle = Buffer.from('NODE_SEA_FUSE_');
  const start = buf.indexOf(needle);
  if (start === -1) throw new Error('SEA fuse sentinel not found in the node binary');
  let end = start + needle.length;
  const isHex = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66);
  while (end < buf.length && isHex(buf[end])) end++;
  return buf.toString('latin1', start, end);
}

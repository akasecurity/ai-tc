// Package the CLI as a Node Single Executable Application for the current OS/arch.
// Prereqs (run first): `build:sea` (dist-sea/cli.mjs) and `bundle:web-ui` (cli/web-ui).
// Produces sea-dist/aka-<platform>-<arch>/ containing the `aka` binary plus its sidecars:
//   boot.cjs, cli.mjs, package.json (for cliVersion), web-ui/ (the Next standalone plus
//   the node_modules that standalone needs — see step 1b).
// The binary embeds Node + entry.cjs; entry.cjs requires boot.cjs, which imports cli.mjs.
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
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

// 1b. Install the standalone server's runtime dependencies INTO the staged web-ui.
//
// bundle-web-ui strips node_modules out of the Next standalone copy on purpose, and the
// npm channel re-supplies them a different way: `@akasecurity/cli` declares next/react/
// react-dom as runtime deps, so `npm i -g` puts them ABOVE web-ui/web-ui/server.js and
// Node's upward node_modules walk finds them from there.
//
// A SEA has no npm install anywhere and nothing above the extracted archive, so that walk
// finds nothing — `aka dashboard` dies with "Cannot find module 'next'" on every binary
// install. Nothing in-repo notices, because the build tree answers the same walk: from
// cli/sea-dist/aka-<triple>/web-ui/web-ui/ it climbs to cli/node_modules/next, which the
// workspace install already put there. That is why smoke-dashboard runs from a copy
// outside this tree — a smoke rooted here passes on an archive that cannot work anywhere
// else.
//
// Installed at the standalone ROOT (web-ui/), which is both where Next expects them and
// the first node_modules the walk from web-ui/web-ui/server.js reaches.
const seaWebUi = join(outDir, 'web-ui');
// Pin to the versions the workspace lockfile already resolved, so the binary channel
// serves the same Next the npm channel does instead of whatever the range floats to.
const runtimeDeps = ['next', 'react', 'react-dom'].map((name) => {
  const manifest = join(cliDir, 'node_modules', name, 'package.json');
  if (!existsSync(manifest)) {
    throw new Error(`cannot pin ${name} for the web-ui sidecar — missing ${manifest}`);
  }
  return `${name}@${JSON.parse(readFileSync(manifest, 'utf8')).version}`;
});
// Into a temp prefix, then copied in: installing directly over the staged web-ui would
// have npm rewrite its package.json — which is the REPO ROOT manifest that Next's
// outputFileTracingRoot puts there, devDependencies and all — rather than a manifest this
// step owns. `--ignore-scripts` keeps release packaging free of dependency install hooks;
// the deps here ship prebuilt binaries via optional deps and need no build step.
const depStage = mkdtempSync(join(tmpdir(), 'aka-sea-deps-'));
try {
  execFileSync(
    'npm',
    [
      'install',
      '--prefix',
      depStage,
      '--no-package-lock',
      '--no-audit',
      '--no-fund',
      '--omit=dev',
      '--ignore-scripts',
      ...runtimeDeps,
    ],
    // `shell` on Windows: npm is npm.cmd there, and Node refuses to execFile a .cmd
    // without a shell. No-op elsewhere. (Same reason bundle-web-ui.mjs does it for pnpm.)
    { stdio: 'inherit', shell: isWin },
  );
  cpSync(join(depStage, 'node_modules'), join(seaWebUi, 'node_modules'), { recursive: true });
} finally {
  rmSync(depStage, { recursive: true, force: true });
}
// Assert the module whose absence is the whole failure mode actually landed. `npm install`
// exits 0 on plenty of outcomes that leave a tree the server cannot boot from.
if (!existsSync(join(seaWebUi, 'node_modules', 'next', 'package.json'))) {
  throw new Error(`next missing from the staged web-ui at ${join(seaWebUi, 'node_modules')}`);
}

// The browser extension + its native-messaging host, staged next to the binary
// the same way (aka extension install resolves them via dirname(process.execPath)
// under a SEA — see cli/src/commands/extension.ts).
const extensionSrc = join(cliDir, 'extension');
const nativeHostSrc = join(cliDir, 'native-host');
if (!existsSync(join(extensionSrc, 'manifest.json'))) {
  throw new Error('missing cli/extension — run `pnpm bundle:extension` first');
}
if (!existsSync(join(nativeHostSrc, 'host.js'))) {
  throw new Error('missing cli/native-host — run `pnpm bundle:extension` first');
}
cpSync(extensionSrc, join(outDir, 'extension'), { recursive: true });
cpSync(nativeHostSrc, join(outDir, 'native-host'), { recursive: true });

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

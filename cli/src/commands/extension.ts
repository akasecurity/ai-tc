import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { isSea } from '@akasecurity/local-ops';
import { DATA_FILE_MODE } from '@akasecurity/persistence';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

// Where the CLI's bundled assets live. Under the SEA binary the compiled code
// runs from inside the executable, so bundled dirs sit NEXT TO the binary
// (package-sea.mjs stages them there) — same resolution dashboard.ts uses for
// the bundled web-ui.
function cliRoot(): string {
  return isSea() ? dirname(process.execPath) : join(here, '..');
}

// Mirrors plugins/browser-extension/src/constants.ts — the extension id is
// derived from the "key" field committed in plugins/browser-extension/
// manifest.json (a public key, not a secret), which pins it across every
// machine that builds the extension from source. Duplicated here rather than
// imported: cli and plugins/* are sibling leaf packages (see CLAUDE.md's
// package dependency rules — neither depends on the other), and the CLI
// already hardcodes small per-plugin facts this way (see AGENT_PLUGINS in
// packages/local-ops/src/registry.ts). If the extension's signing key ever
// changes, both copies need updating together.
const EXTENSION_ID = 'mdoiaiemcnjnaokmcmgbikcdhgiemdof';
const NATIVE_HOST_NAME = 'com.akasecurity.aka';

function nativeHostManifest(hostPath: string): Record<string, unknown> {
  return {
    name: NATIVE_HOST_NAME,
    description:
      'AI Traffic Control native messaging host — bridges the browser extension to the local ~/.aka SQLite store.',
    path: hostPath,
    type: 'stdio',
    allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
  };
}

// A published CLI ships the native host under <package>/native-host/host.js
// (mirrors dashboard.ts's web-ui bundling story — see cli/scripts/
// bundle-extension.mjs); a dev checkout resolves the sibling workspace
// package's own build output instead, if it's been built.
export function resolveHostScript(root: string = cliRoot()): string | null {
  const bundled = join(root, 'native-host', 'host.js');
  if (existsSync(bundled)) return bundled;
  try {
    const pkgJson = require.resolve('@akasecurity/plugin-browser-extension/package.json');
    const devBuilt = join(dirname(pkgJson), 'native-host', 'host.js');
    if (existsSync(devBuilt)) return devBuilt;
  } catch {
    // Not resolvable outside a workspace checkout — the bundled path above
    // was already tried.
  }
  return null;
}

// Same dual-candidate story for the built extension directory Chrome's
// "Load unpacked" needs (manifest.json + background/content/popup output).
export function resolveExtensionDist(root: string = cliRoot()): string | null {
  const bundled = join(root, 'extension');
  if (existsSync(bundled)) return bundled;
  try {
    const pkgJson = require.resolve('@akasecurity/plugin-browser-extension/package.json');
    const devDist = join(dirname(pkgJson), 'dist');
    if (existsSync(devDist)) return devDist;
  } catch {
    // Not resolvable outside a workspace checkout.
  }
  return null;
}

// Chrome's own per-OS convention for where a native-messaging-host manifest
// must live to be discovered. Chrome only for now — Edge/Brave/Chromium share
// the mechanism but use different manifest paths and are not yet supported.
export function chromeManifestDir(platform: NodeJS.Platform = process.platform): string {
  if (platform === 'darwin') {
    return join(
      homedir(),
      'Library',
      'Application Support',
      'Google',
      'Chrome',
      'NativeMessagingHosts',
    );
  }
  if (platform === 'win32') {
    // Windows has no NativeMessagingHosts directory — Chrome discovers the
    // host via a registry key instead (registerWindowsHost below). The
    // manifest file itself still needs a real path on disk; ~/.aka is as
    // good as any, since nothing else reads it there.
    return join(homedir(), '.aka', 'native-messaging');
  }
  // Linux (and other freedesktop-ish platforms) — Chrome's own convention.
  return join(homedir(), '.config', 'google-chrome', 'NativeMessagingHosts');
}

// Chrome spawns the manifest's `path` as an executable — a bare .js file is
// not one on any platform, so the manifest points at a small launcher written
// at install time that execs the Node runtime over the bundled host script.
// The Node path is resolved at install time: the npm CLI runs under Node, so
// process.execPath IS the runtime; the SEA binary is not a Node runtime, so
// there `node` must resolve on PATH or the install fails loudly rather than
// registering a host Chrome can never start.
export function resolveNodeForLauncher(): string | null {
  if (!isSea()) return process.execPath;
  try {
    const probe = process.platform === 'win32' ? 'where' : 'which';
    const out = execFileSync(probe, ['node'], { encoding: 'utf8' }).split(/\r?\n/)[0]?.trim();
    if (out === undefined || out === '') return null;
    return out;
  } catch {
    return null;
  }
}

export function launcherPath(manifestDir: string, platform: NodeJS.Platform): string {
  return join(
    manifestDir,
    platform === 'win32' ? `${NATIVE_HOST_NAME}.cmd` : `${NATIVE_HOST_NAME}.sh`,
  );
}

// Both interpolated paths are attacker-free but not syntax-free: they come from
// process.execPath and the install location, either of which can hold characters
// the launcher's interpreter would act on. Wrapping in double quotes is not
// enough on either platform.
//
// POSIX sh still expands $, `…` and \ inside double quotes. Single quotes
// suppress all three, and the one character they cannot hold is escaped by
// closing the quote, emitting \' and reopening ('\'').
function posixQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

// cmd.exe expands %VAR% inside double quotes, and % is legal in a Windows path
// (a directory literally named `100%`), so a quoted path can still be rewritten
// before node ever sees it. `%%` is the batch-file escape for a literal %.
// A Windows path cannot contain " at all, so that case needs no handling.
function cmdQuote(value: string): string {
  return `"${value.replaceAll('%', '%%')}"`;
}

function writeLauncher(
  manifestDir: string,
  hostScript: string,
  nodePath: string,
  platform: NodeJS.Platform,
): string {
  const path = launcherPath(manifestDir, platform);
  const tmp = `${path}.tmp`;
  if (platform === 'win32') {
    writeFileSync(tmp, `@echo off\r\n${cmdQuote(nodePath)} ${cmdQuote(hostScript)} %*\r\n`);
  } else {
    writeFileSync(tmp, `#!/bin/sh\nexec ${posixQuote(nodePath)} ${posixQuote(hostScript)} "$@"\n`, {
      mode: 0o755,
    });
  }
  renameSync(tmp, path);
  return path;
}

function windowsRegistryKey(): string {
  return `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${NATIVE_HOST_NAME}`;
}

function registerWindowsHost(manifestPath: string): void {
  execFileSync('reg', [
    'add',
    windowsRegistryKey(),
    '/ve',
    '/t',
    'REG_SZ',
    '/d',
    manifestPath,
    '/f',
  ]);
}

export function runExtension(argv: string[]): void {
  const sub = argv[0];
  if (sub === 'install') {
    runInstall(chromeManifestDir());
    return;
  }
  if (sub === 'status') {
    runStatus(chromeManifestDir());
    return;
  }
  process.stderr.write(
    `aka extension: unknown subcommand '${sub ?? ''}'\nUsage: aka extension <install|status>\n`,
  );
  process.exitCode = 1;
}

// `manifestDir` is injectable so tests can point this at a scratch directory
// instead of the real per-OS Chrome path; `hostScript`/`extensionDist`
// likewise so tests don't depend on a real plugin-browser-extension build
// existing on disk — runExtension's own call site is the only one that
// defaults all three to their real resolvers.
export function runInstall(
  manifestDir: string,
  hostScript: string | null = resolveHostScript(),
  extensionDist: string | null = resolveExtensionDist(),
  nodePath: string | null = resolveNodeForLauncher(),
): void {
  if (!hostScript) {
    process.stderr.write(
      'aka extension install: could not find the native-messaging host script.\n' +
        '  In a workspace checkout, build it first: pnpm --filter @akasecurity/plugin-browser-extension build\n',
    );
    process.exitCode = 1;
    return;
  }
  if (!nodePath) {
    process.stderr.write(
      'aka extension install: no Node.js runtime found to run the native-messaging host.\n' +
        '  The host runs under Node; install Node.js (so `node` resolves on PATH) and re-run.\n',
    );
    process.exitCode = 1;
    return;
  }

  mkdirSync(manifestDir, { recursive: true });
  // Chrome executes the manifest's `path` — write a launcher that execs the
  // Node runtime over the host script, and point the manifest at the launcher.
  const launcher = writeLauncher(manifestDir, hostScript, nodePath, process.platform);
  const manifestPath = join(manifestDir, `${NATIVE_HOST_NAME}.json`);
  // Owner-only (0600) + atomic tmp+rename, matching every other writer under
  // ~/.aka (see cli/src/commands/init.ts) — this manifest lives outside
  // ~/.aka on macOS/Linux, but the same crash-safety concern applies.
  const tmp = `${manifestPath}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(nativeHostManifest(launcher), null, 2)}\n`, {
    mode: DATA_FILE_MODE,
  });
  renameSync(tmp, manifestPath);

  if (process.platform === 'win32') {
    try {
      registerWindowsHost(manifestPath);
    } catch (err) {
      process.stderr.write(
        `aka extension install: could not register the Windows registry key (${
          err instanceof Error ? err.message : String(err)
        }) — the native host won't be discoverable by Chrome until this is fixed.\n`,
      );
      process.exitCode = 1;
      return;
    }
  }

  process.stdout.write(
    `✓ Installed the AKA native-messaging host\n` +
      `  host script: ${hostScript}\n` +
      `  launcher:    ${launcher}\n` +
      `  manifest:    ${manifestPath}\n` +
      (process.platform === 'win32' ? `  registry:    ${windowsRegistryKey()}\n` : '') +
      `\nNext: load the extension in Chrome —\n` +
      `  1. Open chrome://extensions\n` +
      `  2. Enable "Developer mode" (top right)\n` +
      `  3. Click "Load unpacked" and select:\n` +
      `     ${extensionDist ?? '<run: pnpm --filter @akasecurity/plugin-browser-extension build>'}\n`,
  );
}

export function runStatus(manifestDir: string): void {
  const manifestPath = join(manifestDir, `${NATIVE_HOST_NAME}.json`);
  const installed = existsSync(manifestPath);
  process.stdout.write(
    `native-messaging host: ${installed ? 'installed' : 'not installed'}\n` +
      `  manifest: ${manifestPath}\n` +
      (installed ? '' : '  run `aka extension install` to set it up\n'),
  );
}

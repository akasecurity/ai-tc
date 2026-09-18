import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

import { WEB_CAPTURE_DRIFT_RULE, webCaptureReport } from '@akasecurity/detections';
import { isSea } from '@akasecurity/local-ops';
import {
  DATA_FILE_MODE,
  dataDir,
  openLocalDatabase,
  readEffectiveSettings,
} from '@akasecurity/persistence';
import { isWebChatCaptureConsentValid, webChatCaptureOf } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import { launcherScript, parseLauncher } from '../lib/native-host-launcher.ts';
import type { Realpath } from '../lib/stable-path.ts';
import { isVersionPinned, realpathOrNull, stablePath } from '../lib/stable-path.ts';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

// Where the CLI's bundled assets live. Under the SEA binary the compiled code
// runs from inside the executable, so bundled dirs sit NEXT TO the binary
// (package-sea.mjs stages them there) — same resolution dashboard.ts uses for
// the bundled web-ui.
function cliRoot(): string {
  return isSea() ? dirname(process.execPath) : join(here, '..');
}

// Mirrors plugins/browser-extension/src/constants.ts — an extension id is
// derived from the "key" field committed in plugins/browser-extension/
// manifest.json (a public key, not a secret), which pins it across every
// machine that builds the extension from source. Duplicated here rather than
// imported: cli and plugins/* are sibling leaf packages (see CLAUDE.md's
// package dependency rules — neither depends on the other), and the CLI
// already hardcodes small per-plugin facts this way (see AGENT_PLUGINS in
// packages/local-ops/src/registry.ts).
//
// A LIST rather than one id: the Chrome Web Store signs a listing with a key
// it holds and ignores the committed one, so a store build and an unpacked
// from-source build have DIFFERENT ids. Granting both is what lets an already
// installed unpacked build keep reaching the native host across that switch —
// an id missing here is not a build error but a silent runtime one, since
// Chrome refuses connectNative for an origin the host manifest omits.
//
// Every entry is a live grant: an extension whose id is listed may talk to the
// native host, so add one deliberately and drop a legacy id once it is dead.
// plugins/browser-extension/test/manifest.test.ts derives the committed key's
// id and fails if this list omits it.
//
// Adding an id here means updating cli/test/commands/extension.test.ts too: it
// deep-equals the whole written manifest, so a new entry reddens it on an
// allowed_origins mismatch. That literal is spelled out rather than derived on
// purpose — widening a grant should have to be confirmed somewhere, the way the
// host_permissions guard works — so the second edit is the point, not friction.
const EXTENSION_IDS = [
  // Derived from the "key" in plugins/browser-extension/manifest.json.
  'mdoiaiemcnjnaokmcmgbikcdhgiemdof',
];
const NATIVE_HOST_NAME = 'com.akasecurity.aka';

function nativeHostManifest(hostPath: string): Record<string, unknown> {
  return {
    name: NATIVE_HOST_NAME,
    description:
      'AI Traffic Control native messaging host — bridges the browser extension to the local ~/.aka SQLite store.',
    path: hostPath,
    type: 'stdio',
    allowed_origins: EXTENSION_IDS.map((id) => `chrome-extension://${id}/`),
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

// The hidden subcommand under which the standalone binary runs the host.
export const NATIVE_HOST_COMMAND = '__native-host';

export interface LauncherRuntime {
  sea: boolean;
  execPath: string;
  realpath: Realpath;
}

function currentRuntime(): LauncherRuntime {
  return { sea: isSea(), execPath: process.execPath, realpath: realpathOrNull };
}

// Chrome spawns the manifest's `path` as an executable — a bare .js file is not
// one on any platform, so the manifest points at a small launcher that execs
// this argv. The launcher is written once and read on every connection, so
// every path in it is spelled through the link a package manager re-points on
// upgrade (see stable-path.ts).
//
// The standalone binary embeds the Node runtime the host is built for, so it
// runs the host itself (`__native-host`) and the launcher names no host script:
// the binary finds its own beside it at run time. The npm CLI runs under a Node
// runtime, so there process.execPath IS the runtime and the launcher names the
// host script directly.
export function launcherCommand(
  hostScript: string,
  runtime: LauncherRuntime = currentRuntime(),
): string[] {
  const executable = stablePath(runtime.execPath, runtime.realpath);
  if (runtime.sea) return [executable, NATIVE_HOST_COMMAND];
  return [executable, stablePath(hostScript, runtime.realpath)];
}

export function launcherPath(manifestDir: string, platform: NodeJS.Platform): string {
  return join(
    manifestDir,
    platform === 'win32' ? `${NATIVE_HOST_NAME}.cmd` : `${NATIVE_HOST_NAME}.sh`,
  );
}

function writeLauncher(
  manifestDir: string,
  command: readonly string[],
  platform: NodeJS.Platform,
): string {
  const path = launcherPath(manifestDir, platform);
  const tmp = `${path}.tmp`;
  writeFileSync(
    tmp,
    launcherScript(command, platform),
    platform === 'win32' ? {} : { mode: 0o755 },
  );
  renameSync(tmp, path);
  return path;
}

// The hidden `__native-host` command: runs the bundled host script IN-PROCESS,
// the way `__dashboard-server` runs the dashboard. Chrome reads this process's
// stdout as the native-messaging channel, so nothing is written there before
// the host takes it over; a missing script is reported on stderr.
export async function runNativeHost(
  hostScript: string | null = resolveHostScript(),
): Promise<void> {
  if (hostScript === null) {
    process.stderr.write(
      'aka __native-host: this install carries no native-messaging host script\n',
    );
    process.exitCode = 1;
    return;
  }
  await import(pathToFileURL(hostScript).href);
}

// Under the standalone binary the host's detached children — spawned as
// `<process.execPath> <script>`, with a script that sits beside the host —
// arrive as `aka <script>`, since the binary is not a Node runtime that would
// run it. Returns the script when `command` is one of those, else null: an
// existing `.js` file in this install's own native-host directory, and only
// under the standalone binary.
export function hostChildScript(
  command: string,
  sea: boolean = isSea(),
  root: string = cliRoot(),
): string | null {
  if (!sea || !isAbsolute(command) || !command.endsWith('.js')) return null;
  if (resolve(dirname(command)) !== resolve(root, 'native-host')) return null;
  return existsSync(command) ? command : null;
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
  // Parsed first, THEN read the subcommand from the positionals — the same
  // rule `aka detections` follows, so a flag-first invocation (`--home <dir>
  // status`) still resolves the subcommand.
  const { values, positionals } = parseArgs({
    args: argv,
    options: HOME_OPTION,
    allowPositionals: true,
  });
  const sub = positionals[0];
  if (sub === 'install') {
    runInstall(chromeManifestDir());
    return;
  }
  if (sub === 'status') {
    runStatus(chromeManifestDir(), homeBase(values.home));
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
// existing on disk, and `command` so they can name what the launcher runs —
// runExtension's own call site is the only one that defaults all four.
export function runInstall(
  manifestDir: string,
  hostScript: string | null = resolveHostScript(),
  extensionDist: string | null = resolveExtensionDist(),
  command?: readonly string[],
): void {
  if (!hostScript) {
    process.stderr.write(
      'aka extension install: could not find the native-messaging host script.\n' +
        '  In a workspace checkout, build it first: pnpm --filter @akasecurity/plugin-browser-extension build\n',
    );
    process.exitCode = 1;
    return;
  }
  const argv = command ?? launcherCommand(hostScript);

  mkdirSync(manifestDir, { recursive: true });
  // Chrome executes the manifest's `path` — write a launcher that execs the
  // host, and point the manifest at the launcher.
  const launcher = writeLauncher(manifestDir, argv, process.platform);
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
      `  runs:        ${argv.join(' ')}\n` +
      `  manifest:    ${manifestPath}\n` +
      (process.platform === 'win32' ? `  registry:    ${windowsRegistryKey()}\n` : '') +
      `\nNext: load the extension in Chrome —\n` +
      `  1. Open chrome://extensions\n` +
      `  2. Enable "Developer mode" (top right)\n` +
      `  3. Click "Load unpacked" and select:\n` +
      `     ${extensionDist ?? '<run: pnpm --filter @akasecurity/plugin-browser-extension build>'}\n`,
  );
}

// What an existence check cannot see. `install` runs only when the user types
// it, and nothing re-runs it on upgrade — so a manifest written before an id
// joined EXTENSION_IDS keeps granting the shorter list. Chrome refuses
// connectNative for an origin the manifest omits, so that extension installs
// cleanly and silently cannot reach the host: the same failure the CLI-side
// guard prevents, reached from the on-disk side instead of the source side.
// Reported rather than repaired, because rewriting a manifest is what the
// explicit `install` subcommand is for.
function originFault(parsed: unknown): string | null {
  const granted = (parsed as { allowed_origins?: unknown } | null)?.allowed_origins;
  if (!Array.isArray(granted)) return 'has no allowed_origins list';
  const missing = EXTENSION_IDS.filter((id) => !granted.includes(`chrome-extension://${id}/`));
  if (missing.length === 0) return null;
  return `does not grant ${missing.length === 1 ? 'the extension id' : 'the extension ids'} ${missing.join(', ')}`;
}

const ORIGIN_REMEDY = [
  'Chrome refuses a connection from any origin the manifest omits —',
  're-run `aka extension install` to rewrite it',
];

// The same blind spot on the launcher side. An upgrade or uninstall removes
// the directory an older launcher names, and Chrome's spawn then fails with
// nothing reported anywhere; a launcher that names a version directory directly
// works until the next upgrade removes it. Reported rather than repaired, for
// the reason `originFault` gives.
function launcherFaults(parsed: unknown): string[] {
  const launcher = (parsed as { path?: unknown } | null)?.path;
  if (typeof launcher !== 'string' || launcher === '') {
    return ['this manifest names no launcher'];
  }
  let script: string;
  try {
    script = readFileSync(launcher, 'utf8');
  } catch {
    return [`the launcher ${launcher} does not exist or cannot be read`];
  }
  const argv = parseLauncher(script);
  if (argv === null) {
    return [`the launcher ${launcher} is not one \`aka extension install\` writes`];
  }
  const faults: string[] = [];
  for (const arg of argv.filter((value) => isAbsolute(value))) {
    if (realpathOrNull(arg) === null) {
      faults.push(`the launcher runs ${arg}, which does not exist`);
    } else if (isVersionPinned(arg)) {
      faults.push(`the launcher runs ${arg}, a versioned path the next upgrade removes`);
    }
  }
  return faults;
}

const LAUNCHER_REMEDY = [
  'Chrome starts the host through the launcher on every connection —',
  're-run `aka extension install` to point it at this install',
];

// The network-capture block `runStatus` appends when `home` is given. Reads
// the reported `capture_status` rows through the same store the extension's
// native host writes into (SqliteCaptureStatusRepository), and derives each
// site's word with the SAME deriver the drift rule fires on, so the CLI can
// never print a state the rule disagrees with.
//
// Never touches process.exitCode: a drifting site is a real fault but not a
// CLI misconfiguration, and `aka extension status` runs in scripts that must
// not start failing on a state the user cannot fix from the CLI.
function captureBlock(home: string): string {
  try {
    const effective = readEffectiveSettings(home);
    const webChat = webChatCaptureOf(effective.settings);
    if (!isWebChatCaptureConsentValid(webChat.consent)) {
      return (
        '\nnetwork capture: not enabled\n' +
        '  no web-chat capture consent is recorded, so nothing is observed or stored\n' +
        '  enable it under Settings in `aka dashboard`\n'
      );
    }

    const db = openLocalDatabase(dataDir(home));
    let records;
    try {
      records = db.captureStatus.latest(Date.now());
    } finally {
      db.close();
    }

    const lines = webCaptureReport(records).map((site) => {
      let line = `  ${site.tool.padEnd(10)} ${site.state.padEnd(10)} ${site.headline}\n`;
      if (site.drift && site.remediation !== undefined) {
        line += `    ${WEB_CAPTURE_DRIFT_RULE.ruleId} (${WEB_CAPTURE_DRIFT_RULE.severity}) — ${site.remediation}\n`;
      }
      return line;
    });
    return `\nnetwork capture\n${lines.join('')}`;
  } catch (err) {
    return (
      '\nnetwork capture: unavailable\n' +
      `  the local store could not be read (${err instanceof Error ? err.message : String(err)})\n`
    );
  }
}

// The lines that follow `manifest:` in the status block — empty for a
// registration with nothing wrong with it.
function registrationFaults(manifestPath: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    return [
      `this manifest could not be read (${err instanceof Error ? err.message : String(err)})`,
      ...ORIGIN_REMEDY,
    ];
  }
  const lines: string[] = [];
  const origin = originFault(parsed);
  if (origin !== null) lines.push(`this manifest ${origin}`, ...ORIGIN_REMEDY);
  const launcher = launcherFaults(parsed);
  if (launcher.length > 0) lines.push(...launcher, ...LAUNCHER_REMEDY);
  return lines;
}

export function runStatus(manifestDir: string, home?: string): void {
  const manifestPath = join(manifestDir, `${NATIVE_HOST_NAME}.json`);
  if (!existsSync(manifestPath)) {
    process.stdout.write(
      'native-messaging host: not installed\n' +
        `  manifest: ${manifestPath}\n` +
        '  run `aka extension install` to set it up\n',
    );
  } else {
    const faults = registrationFaults(manifestPath);
    process.stdout.write(
      `native-messaging host: ${faults.length > 0 ? 'installed (out of date)' : 'installed'}\n` +
        `  manifest: ${manifestPath}\n` +
        faults.map((line) => `  ${line}\n`).join(''),
    );
    if (faults.length > 0) process.exitCode = 1;
  }

  // Omitted entirely when no home was resolved (the unit-test call shape) —
  // the capture block must never depend on the developer's real ~/.aka.
  if (home !== undefined) {
    process.stdout.write(captureBlock(home));
  }
}

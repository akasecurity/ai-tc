import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { dataDir, openLocalDatabase, settingsDir } from '@akasecurity/persistence';
import type { WebCaptureStatus } from '@akasecurity/schema';
import { toCaptureStatusAttributes, WEB_CHAT_CAPTURE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import {
  chromeManifestDir,
  hostChildScript,
  launcherCommand,
  launcherPath,
  NATIVE_HOST_COMMAND,
  resolveExtensionDist,
  resolveHostScript,
  runInstall,
  runNativeHost,
  runStatus,
} from '../../src/commands/extension.ts';
import { launcherScript, parseLauncher } from '../../src/lib/native-host-launcher.ts';
import { realpathOrNull } from '../../src/lib/stable-path.ts';

describe('chromeManifestDir', () => {
  it('resolves the macOS Chrome NativeMessagingHosts path', () => {
    expect(chromeManifestDir('darwin')).toContain(
      join('Library', 'Application Support', 'Google', 'Chrome', 'NativeMessagingHosts'),
    );
  });

  it('resolves the Linux Chrome NativeMessagingHosts path', () => {
    expect(chromeManifestDir('linux')).toContain(
      join('.config', 'google-chrome', 'NativeMessagingHosts'),
    );
  });

  it('resolves a manifest path under ~/.aka on Windows (no NativeMessagingHosts dir exists there)', () => {
    expect(chromeManifestDir('win32')).toContain(join('.aka', 'native-messaging'));
  });
});

describe('resolveHostScript / resolveExtensionDist', () => {
  let cliRoot: string;

  beforeEach(() => {
    cliRoot = mkdtempSync(join(tmpdir(), 'aka-cli-root-'));
  });

  afterEach(() => {
    rmSync(cliRoot, { recursive: true, force: true });
  });

  it('finds the bundled native host script under <cliRoot>/native-host/host.js', () => {
    const hostDir = join(cliRoot, 'native-host');
    mkdirSync(hostDir, { recursive: true });
    writeFileSync(join(hostDir, 'host.js'), '// stub');

    expect(resolveHostScript(cliRoot)).toBe(join(hostDir, 'host.js'));
  });

  it('finds the bundled extension dist under <cliRoot>/extension', () => {
    const extDir = join(cliRoot, 'extension');
    mkdirSync(extDir, { recursive: true });
    writeFileSync(join(extDir, 'manifest.json'), '{}');

    expect(resolveExtensionDist(cliRoot)).toBe(extDir);
  });
});

describe('runInstall / runStatus', () => {
  let manifestDir: string;

  beforeEach(() => {
    manifestDir = mkdtempSync(join(tmpdir(), 'aka-native-messaging-'));
  });

  afterEach(() => {
    rmSync(manifestDir, { recursive: true, force: true });
    vi.restoreAllMocks();
    process.exitCode = 0;
  });

  it('status reports "not installed" before install has run', () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir);
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toContain('not installed');
    expect(out).toContain('aka extension install');
  });

  // `install` runs only when the user types it, and nothing re-runs it on
  // upgrade — so appending an id to EXTENSION_IDS leaves every existing user's
  // manifest granting the old list. Chrome refuses connectNative for an origin
  // the manifest omits, so that extension installs cleanly and silently cannot
  // reach the host. An existence check reports exactly that as "installed".
  const writeManifest = (body: string): void => {
    writeFileSync(join(manifestDir, 'com.akasecurity.aka.json'), body);
  };
  const status = (): string => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir);
    return stdout.mock.calls.map((c) => String(c[0])).join('');
  };

  it('status reports a manifest that does not grant every current extension id', () => {
    writeManifest(
      JSON.stringify({
        name: 'com.akasecurity.aka',
        path: '/fake/launcher',
        type: 'stdio',
        allowed_origins: ['chrome-extension://aaaabbbbccccddddeeeeffffgggghhhh/'],
      }),
    );

    const out = status();
    expect(out).toContain('installed (out of date)');
    // Names the id that is missing, so the reader can tell which grant lapsed
    // rather than being sent to re-run install on a hunch.
    expect(out).toContain('mdoiaiemcnjnaokmcmgbikcdhgiemdof');
    expect(out).toContain('aka extension install');
    expect(process.exitCode).toBe(1);
  });

  it('status reports a manifest carrying no allowed_origins at all', () => {
    writeManifest(JSON.stringify({ name: 'com.akasecurity.aka', type: 'stdio' }));

    const out = status();
    expect(out).toContain('installed (out of date)');
    expect(out).toContain('no allowed_origins list');
    // No `path` either, so Chrome has nothing to start.
    expect(out).toContain('this manifest names no launcher');
    expect(process.exitCode).toBe(1);
  });

  it('status reports a manifest it cannot parse rather than calling it installed', () => {
    writeManifest('{ this is not json');

    const out = status();
    expect(out).toContain('installed (out of date)');
    expect(out).toContain('could not be read');
    expect(process.exitCode).toBe(1);
  });

  it('declines to install (no manifest written) when no host script can be found', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    runInstall(manifestDir, null, null);
    expect(process.exitCode).toBe(1);
    expect(stderr.mock.calls.map((c) => String(c[0])).join('')).toContain(
      'could not find the native-messaging host script',
    );
    expect(existsSync(join(manifestDir, 'com.akasecurity.aka.json'))).toBe(false);
  });

  it('writes the manifest pointing at an executable launcher (never the bare .js), then status reports it', () => {
    // A real file: status now checks that what the launcher runs exists, so a
    // fake path here would read as the broken registration it would be.
    const hostDir = join(manifestDir, 'install', 'native-host');
    mkdirSync(hostDir, { recursive: true });
    const hostScript = join(hostDir, 'host.js');
    writeFileSync(hostScript, '');

    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runInstall(manifestDir, hostScript, '/fake/extension');

    const manifestPath = join(manifestDir, 'com.akasecurity.aka.json');
    expect(existsSync(manifestPath)).toBe(true);
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, unknown>;
    const launcher = launcherPath(manifestDir, process.platform);
    expect(manifest).toEqual({
      name: 'com.akasecurity.aka',
      description:
        'AI Traffic Control native messaging host — bridges the browser extension to the local ~/.aka SQLite store.',
      path: launcher,
      type: 'stdio',
      // Spelled out rather than derived from EXTENSION_IDS: every origin here
      // is a live grant to talk to the native host, so widening the list should
      // have to be confirmed in a second place. If this reddened after you
      // appended an id there, that is this assertion doing its job — add the
      // matching origin. It is not an unrelated manifest regression.
      allowed_origins: ['chrome-extension://mdoiaiemcnjnaokmcmgbikcdhgiemdof/'],
    });

    // Chrome executes manifest.path directly, so the launcher must exist, be
    // executable, and exec the Node runtime over the host script — a manifest
    // naming the .js itself would make Chrome's spawn fail silently forever.
    // Compared by what each path REACHES: the launcher spells both through
    // whatever link follows upgrades, which is a different string wherever
    // the runtime came from a package manager.
    expect(existsSync(launcher)).toBe(true);
    const launcherSrc = readFileSync(launcher, 'utf8');
    const runs = parseLauncher(launcherSrc);
    expect(runs).toHaveLength(2);
    expect(realpathSync(runs?.[0] ?? '')).toBe(realpathSync(process.execPath));
    expect(realpathSync(runs?.[1] ?? '')).toBe(realpathSync(hostScript));
    if (process.platform !== 'win32') {
      expect(launcherSrc.startsWith('#!/bin/sh\n')).toBe(true);
      expect(statSync(launcher).mode & 0o111).not.toBe(0);
    }

    const written = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(written).toContain('Installed the AKA native-messaging host');
    expect(written).toContain('/fake/extension');

    const statusStdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir);
    // The whole line, not `toContain('installed')` — that substring is in
    // "not installed" and in "installed (out of date)" too, so it cannot tell
    // a working install from either way of being broken.
    expect(statusStdout.mock.calls.map((c) => String(c[0])).join('')).toContain(
      'native-messaging host: installed\n',
    );
    expect(process.exitCode).toBe(0);
  });

  // Runs the launcher for real rather than pattern-matching its source: the
  // question is what /bin/sh does with those paths, which only sh can answer.
  // The fake runtime prints the argument it was handed, so an expansion that
  // rewrote the path shows up as a mismatch instead of passing unnoticed.
  it.skipIf(process.platform === 'win32')(
    'quotes the launcher paths so shell metacharacters in them survive to the host script',
    () => {
      const scratch = mkdtempSync(join(tmpdir(), 'aka-launcher-quoting-'));
      try {
        const fakeNode = join(scratch, 'fake-node.sh');
        writeFileSync(fakeNode, '#!/bin/sh\nprintf %s "$1"\n', { mode: 0o755 });

        // Every character sh still acts on inside DOUBLE quotes ($ and `),
        // plus the single quote the new quoting has to escape by hand.
        const trickyDir = join(scratch, "we$IRD `dir` 'q'");
        mkdirSync(trickyDir, { recursive: true });
        const hostScript = join(trickyDir, 'host.js');
        writeFileSync(hostScript, '');

        vi.spyOn(process.stdout, 'write').mockReturnValue(true);
        runInstall(manifestDir, hostScript, '/fake/extension', [fakeNode, hostScript]);

        const launcher = launcherPath(manifestDir, process.platform);
        const handedToNode = execFileSync('/bin/sh', [launcher], { encoding: 'utf8' });
        expect(handedToNode).toBe(hostScript);
      } finally {
        rmSync(scratch, { recursive: true, force: true });
      }
    },
  );

  it('prints instructions to build the extension when its dist could not be resolved', () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runInstall(manifestDir, '/fake/native-host/host.js', null);
    const written = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(written).toContain('pnpm --filter @akasecurity/plugin-browser-extension build');
  });
});

// A Homebrew prefix built on disk: every version is its own keg under
// Cellar/aka/<version>/libexec, holding the binary and its native-host sidecar,
// and opt/aka is the link `brew upgrade` re-points before removing the old keg.
// Real links, so every assertion reads what realpath reports.
describe('the native-messaging registration across an upgrade', () => {
  let root: string;
  let manifestDir: string;

  beforeEach(() => {
    // Resolved up front, so the only links under it are the layout's own.
    root = realpathSync(mkdtempSync(join(tmpdir(), 'aka-brew-prefix-')));
    manifestDir = join(root, 'NativeMessagingHosts');
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
    vi.restoreAllMocks();
    process.exitCode = 0;
  });

  const keg = (version: string): string => join(root, 'Cellar', 'aka', version);
  const optAka = (): string => join(root, 'opt', 'aka');

  function linkDir(target: string, path: string): void {
    mkdirSync(dirname(path), { recursive: true });
    symlinkSync(target, path, process.platform === 'win32' ? 'junction' : 'dir');
  }

  // Returns the keg's binary.
  function pourKeg(version: string): string {
    const libexec = join(keg(version), 'libexec');
    mkdirSync(join(libexec, 'native-host'), { recursive: true });
    writeFileSync(join(libexec, 'aka'), '');
    writeFileSync(join(libexec, 'native-host', 'host.js'), '');
    return join(libexec, 'aka');
  }

  // What `brew upgrade` does to the tree: pour the new keg, re-point opt at it,
  // then remove the old keg.
  function brewUpgrade(from: string, to: string): void {
    pourKeg(to);
    rmSync(optAka(), { force: true });
    linkDir(keg(to), optAka());
    rmSync(keg(from), { recursive: true, force: true });
  }

  const standalone = (execPath: string) => ({ sea: true, execPath, realpath: realpathOrNull });

  function status(): string {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir);
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    stdout.mockRestore();
    return out;
  }

  function install(command: readonly string[]): void {
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runInstall(manifestDir, join(root, 'unused-host.js'), '/fake/extension', command);
    vi.restoreAllMocks();
  }

  it('has the standalone binary run the host itself, named through opt', () => {
    const exe = pourKeg('1.0.0');
    linkDir(keg('1.0.0'), optAka());

    // No host script in the command: the binary finds its own beside it when it
    // starts, so nothing versioned is written down at all.
    expect(launcherCommand(join(dirname(exe), 'native-host', 'host.js'), standalone(exe))).toEqual([
      join(optAka(), 'libexec', 'aka'),
      NATIVE_HOST_COMMAND,
    ]);
  });

  it('names both the Node runtime and the host script through opt under the npm CLI', () => {
    const node = join(root, 'Cellar', 'node', '24.18.0', 'bin', 'node');
    mkdirSync(dirname(node), { recursive: true });
    writeFileSync(node, '');
    linkDir(join(root, 'Cellar', 'node', '24.18.0'), join(root, 'opt', 'node'));
    const exe = pourKeg('1.0.0');
    linkDir(keg('1.0.0'), optAka());

    const hostScript = join(dirname(exe), 'native-host', 'host.js');
    expect(
      launcherCommand(hostScript, { sea: false, execPath: node, realpath: realpathOrNull }),
    ).toEqual([
      join(root, 'opt', 'node', 'bin', 'node'),
      join(optAka(), 'libexec', 'native-host', 'host.js'),
    ]);
  });

  it('stays installed across `brew upgrade`', () => {
    const exe = pourKeg('1.0.0');
    linkDir(keg('1.0.0'), optAka());
    install(launcherCommand(join(dirname(exe), 'native-host', 'host.js'), standalone(exe)));
    expect(status()).toContain('native-messaging host: installed\n');

    brewUpgrade('1.0.0', '1.0.1');

    expect(existsSync(keg('1.0.0'))).toBe(false);
    const out = status();
    expect(out).toContain('native-messaging host: installed\n');
    expect(process.exitCode).toBe(0);
    // And what it names is the NEW keg's binary, not merely something that exists.
    const runs = parseLauncher(readFileSync(launcherPath(manifestDir, process.platform), 'utf8'));
    expect(realpathSync(runs?.[0] ?? '')).toBe(join(keg('1.0.1'), 'libexec', 'aka'));
  });

  it('reports a launcher that names a keg, before and after the upgrade removes it', () => {
    // The shape a standalone-binary registration used to take: a Node runtime
    // over the keg's own host script. Working until the upgrade, then gone
    // with nothing said anywhere.
    const node = join(root, 'tools', 'node');
    mkdirSync(dirname(node), { recursive: true });
    writeFileSync(node, '');
    const exe = pourKeg('1.0.0');
    linkDir(keg('1.0.0'), optAka());
    const kegHost = join(dirname(exe), 'native-host', 'host.js');
    install([node, kegHost]);

    const before = status();
    expect(before).toContain('installed (out of date)');
    expect(before).toContain(
      `the launcher runs ${kegHost}, a versioned path the next upgrade removes`,
    );
    expect(before).toContain('re-run `aka extension install`');
    // A runtime no layout links to is named as it is, and is not a fault.
    expect(before).not.toContain(`the launcher runs ${node}`);
    expect(process.exitCode).toBe(1);

    process.exitCode = 0;
    brewUpgrade('1.0.0', '1.0.1');

    const after = status();
    expect(after).toContain('installed (out of date)');
    expect(after).toContain(`the launcher runs ${kegHost}, which does not exist`);
    expect(process.exitCode).toBe(1);

    // And the remedy it names works.
    process.exitCode = 0;
    const current = join(optAka(), 'libexec', 'aka');
    install(launcherCommand(join(dirname(current), 'native-host', 'host.js'), standalone(current)));
    expect(status()).toContain('native-messaging host: installed\n');
    expect(process.exitCode).toBe(0);
  });

  it('reports a launcher still running an older installer version after `current` moves on', () => {
    // The layout install.sh leaves after an upgrade: it removes only the
    // version it is installing over, so the old binroot stays on disk and a
    // launcher naming it keeps working, on the old host, against a store the
    // new build migrates. `does not exist` never fires for it.
    const binroot = (version: string): string => join(root, 'aka', version, 'aka-darwin-arm64');
    for (const version of ['0.9.1', '0.9.2']) {
      mkdirSync(join(binroot(version), 'native-host'), { recursive: true });
      writeFileSync(join(binroot(version), 'aka'), '');
      writeFileSync(join(binroot(version), 'native-host', 'host.js'), '');
    }
    const current = join(root, 'aka', 'current');
    linkDir(binroot('0.9.2'), current);
    const old = join(binroot('0.9.1'), 'aka');
    install([old, NATIVE_HOST_COMMAND]);

    const out = status();
    expect(out).toContain('installed (out of date)');
    expect(out).toContain(`the launcher runs ${old}, but ${current} points at another version`);
    expect(out).toContain('re-run `aka extension install`');
    expect(process.exitCode).toBe(1);

    // And the remedy it names works, from the version `current` now names.
    process.exitCode = 0;
    install(launcherCommand('', standalone(join(binroot('0.9.2'), 'aka'))));
    expect(status()).toContain('native-messaging host: installed\n');
    expect(process.exitCode).toBe(0);
  });

  it('reports a manifest whose launcher is gone', () => {
    install([pourKeg('1.0.0'), NATIVE_HOST_COMMAND]);
    rmSync(launcherPath(manifestDir, process.platform));

    const out = status();
    expect(out).toContain('installed (out of date)');
    expect(out).toContain('does not exist or cannot be read');
    expect(process.exitCode).toBe(1);
  });

  it('reports a launcher that is not in the form install writes', () => {
    install([pourKeg('1.0.0'), NATIVE_HOST_COMMAND]);
    writeFileSync(launcherPath(manifestDir, process.platform), 'echo something else\n');

    const out = status();
    expect(out).toContain('installed (out of date)');
    expect(out).toContain('is not one `aka extension install` writes');
    expect(process.exitCode).toBe(1);
  });

  it('checks a launcher of the other platform by its own form', () => {
    // parseLauncher recognises a launcher by its header, so a cmd launcher is
    // checked on a POSIX run and the reverse — the missing-target case has to
    // be reachable on every leg, not only on the one that writes that form.
    const missing = join(root, 'Cellar', 'aka', '0.9.0', 'libexec', 'aka');
    install([missing, NATIVE_HOST_COMMAND]);
    const other = process.platform === 'win32' ? 'darwin' : 'win32';
    writeFileSync(
      launcherPath(manifestDir, process.platform),
      launcherScript([missing, NATIVE_HOST_COMMAND], other),
    );

    expect(status()).toContain(`the launcher runs ${missing}, which does not exist`);
    expect(process.exitCode).toBe(1);
  });
});

describe('runNativeHost', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-native-host-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    vi.restoreAllMocks();
    process.exitCode = 0;
  });

  it('runs the host script in-process, writing nothing to stdout itself', async () => {
    // Stands in for host.js: ESM that does its work at load, as the real one
    // starts reading stdin at load.
    const hostScript = join(dir, 'host.mjs');
    writeFileSync(
      hostScript,
      "import { writeFileSync } from 'node:fs';\n" +
        "writeFileSync(new URL('./started.txt', import.meta.url), 'ok');\n",
    );
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);

    await runNativeHost(hostScript);

    expect(existsSync(join(dir, 'started.txt'))).toBe(true);
    // Chrome reads this process's stdout as framed messages.
    expect(stdout).not.toHaveBeenCalled();
  });

  it('reports a missing host script on stderr, not stdout', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

    await runNativeHost(null);

    expect(stderr.mock.calls.map((c) => String(c[0])).join('')).toContain(
      'no native-messaging host script',
    );
    expect(stdout).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
});

describe('hostChildScript', () => {
  let root: string;
  let child: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-host-child-'));
    mkdirSync(join(root, 'native-host'));
    child = join(root, 'native-host', 'sync.js');
    writeFileSync(child, '');
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('names a script beside the host under the standalone binary', () => {
    expect(hostChildScript(child, true, root)).toBe(child);
  });

  it('names nothing outside the standalone binary, which is a Node runtime already', () => {
    expect(hostChildScript(child, false, root)).toBeNull();
  });

  it('names nothing outside this install’s own native-host directory', () => {
    const elsewhere = join(root, 'elsewhere.js');
    writeFileSync(elsewhere, '');
    mkdirSync(join(root, 'native-host-other'));
    const sibling = join(root, 'native-host-other', 'sync.js');
    writeFileSync(sibling, '');

    expect(hostChildScript(elsewhere, true, root)).toBeNull();
    expect(hostChildScript(sibling, true, root)).toBeNull();
  });

  it('names nothing for a relative path, a non-script, or a script that is not there', () => {
    const data = join(root, 'native-host', 'host.json');
    writeFileSync(data, '{}');

    expect(hostChildScript(join('native-host', 'sync.js'), true, root)).toBeNull();
    expect(hostChildScript(data, true, root)).toBeNull();
    expect(hostChildScript(join(root, 'native-host', 'gone.js'), true, root)).toBeNull();
  });

  it('is what a detached child of the in-process host is spawned as', () => {
    // plugin-runtime spawns `<process.execPath> <script>` with the script
    // resolved against host.js's own URL — the shape reproduced here, so a
    // change to how either side spells the path fails on this line.
    const hostUrl = pathToFileURL(join(root, 'native-host', 'host.js'));
    const spawned = fileURLToPath(new URL('sync.js', hostUrl));
    expect(hostChildScript(spawned, true, root)).toBe(child);
  });
});

describe('runStatus — the network-capture block', () => {
  let home: string;
  let manifestDir: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-extension-status-home-'));
    manifestDir = mkdtempSync(join(tmpdir(), 'aka-extension-status-manifest-'));
  });

  afterEach(() => {
    // `home` is opened with openLocalDatabase (via seedStatus/runStatus), so a
    // bare rmSync can meet a WAL/SHM sidecar that outlives close() by a
    // moment on Windows — removeTree tolerates that the way every other
    // store-touched teardown in this repo does.
    removeTree(home);
    rmSync(manifestDir, { recursive: true, force: true });
    vi.restoreAllMocks();
    process.exitCode = 0;
  });

  function writeSettings(webChatCapture?: unknown): void {
    const dir = settingsDir(home);
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, 'settings.json'),
      JSON.stringify({
        specVersion: 3,
        runMode: 'standalone',
        policy: 'redact',
        historicalAccess: 'session-only',
        dataSharesInPlace: true,
        vaultKeyCustody: 'file',
        vaultInlineReveal: 'masked',
        redactFallback: 'warn',
        bodyRetention: { enabled: false, retainDays: 30 },
        ...(webChatCapture !== undefined ? { webChatCapture } : {}),
      }),
    );
  }

  function consentedSettings(): unknown {
    return {
      responses: 'with-findings',
      account: false,
      consent: {
        acknowledgedAt: '2026-01-01T00:00:00.000Z',
        version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
      },
    };
  }

  function seedStatus(
    tool: 'chatgpt' | 'claude-ai',
    status: WebCaptureStatus,
    agoMs = 0,
    rootSessionId?: string,
  ): void {
    const db = openLocalDatabase(dataDir(home));
    // Stamped NOW rather than at a fixed date: `captureStatus.latest` bounds
    // its read to the last CAPTURE_STATUS_RECENCY_MS, so a literal calendar
    // date ages out of the window once the wall clock passes it and every
    // case below would then assert against an empty read.
    const startedAt = new Date(Date.now() - agoMs).toISOString();
    try {
      // `root_session_id` groups a site's rows into documents, so a case about
      // two tabs names it and every other case leaves it unset — which reads
      // as the one document those cases mean. It is a self-FK, so the root row
      // has to exist first; its `session` row carries no attributes and so no
      // `source_tool`, which keeps it out of this read.
      if (rootSessionId !== undefined) db.auditEvents.ensureSessionRoot(rootSessionId, startedAt);
      db.auditEvents.insertAuditEvent({
        id: `${tool}-status-${String(Math.random())}`,
        eventType: 'capture_status',
        startedAt,
        ...(rootSessionId === undefined ? {} : { rootSessionId }),
        attributes: toCaptureStatusAttributes(status, tool),
      });
    } finally {
      db.close();
    }
  }

  const BASE_STATUS: WebCaptureStatus = {
    patched: true,
    live: false,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    conversationEndpoints: 0,
    closed: false,
    enforcement: 'watching',
  };

  function run(): string {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir, home);
    return stdout.mock.calls.map((c) => String(c[0])).join('');
  }

  it('prints standby for a site whose build declares no endpoints', () => {
    writeSettings(consentedSettings());
    // The shape every machine reports today: the extension DID report, and it
    // declared zero conversation endpoints (the traffic survey has not run).
    seedStatus('chatgpt', BASE_STATUS);
    const out = run();
    expect(out).toContain('standby');
    expect(out).toContain('declares no endpoints');
    expect(out).not.toContain('web-capture-drift');
  });

  it('prints the drift rule and its remediation for a degraded site', () => {
    writeSettings(consentedSettings());
    seedStatus('claude-ai', {
      ...BASE_STATUS,
      conversationEndpoints: 1,
      closed: false,
      live: true,
      shapeMisses: ['message.id'],
    });
    const out = run();
    expect(out).toContain('degraded');
    expect(out).toContain('web-capture-drift (medium)');
    expect(out).toContain('chrome://extensions');
  });

  it('prints the working state for a site whose capture is working', () => {
    // `active` used to be the one state whose headline was built rather than
    // looked up, because it quoted the turn count. It no longer does: the
    // stored count is only as current as the report that carried it, and the
    // bridge relays on a transition rather than per turn, so the number went
    // stale the moment a tab settled.
    writeSettings(consentedSettings());
    seedStatus('chatgpt', {
      ...BASE_STATUS,
      conversationEndpoints: 1,
      closed: false,
      live: true,
      exchangesSeenNet: 1,
      sendsSeenDom: 1,
    });
    const out = run();
    expect(out).toContain('active');
    expect(out).toContain('observed');
    // No count: it would be the count as of the last report, not the session's.
    expect(out).not.toContain('1 turn observed');
    expect(out).not.toContain('web-capture-drift');
  });

  it('prints one tab-s drift while another tab is capturing fine', () => {
    // Two documents on one site, which is an ordinary browser. The newest of
    // them reporting healthy used to be the whole answer, so this surface said
    // `active` while a tab was swallowing the user's messages.
    writeSettings(consentedSettings());
    seedStatus(
      'claude-ai',
      { ...BASE_STATUS, conversationEndpoints: 1, blind: true, sendsSeenDom: 3 },
      60_000,
      'doc-blind',
    );
    seedStatus(
      'claude-ai',
      { ...BASE_STATUS, conversationEndpoints: 1, live: true, exchangesSeenNet: 4 },
      0,
      'doc-healthy',
    );
    const out = run();
    expect(out).toContain('blind');
    expect(out).toContain('the network capture never saw');
  });

  it('prints the blind headline and its own remediation, not the degraded one', () => {
    // The two drift states share a rule id and a severity, so the headline and
    // the remediation are all that separate them on this surface.
    writeSettings(consentedSettings());
    seedStatus('claude-ai', {
      ...BASE_STATUS,
      conversationEndpoints: 1,
      closed: false,
      blind: true,
      sendsSeenDom: 3,
    });
    const out = run();
    expect(out).toContain('blind');
    expect(out).toContain('the network capture never saw');
    expect(out).toContain('reload the tab');
    expect(out).not.toContain('no longer carry the fields');
  });

  it('a drifting site does not change the exit code', () => {
    writeSettings(consentedSettings());
    seedStatus('claude-ai', {
      ...BASE_STATUS,
      conversationEndpoints: 1,
      closed: false,
      live: true,
      shapeMisses: ['message.id'],
    });
    run();
    expect(process.exitCode).toBe(0);
  });

  it('a manifest fault still sets the exit code, with the capture block present', () => {
    // The positive control for the case above: an UNRELATED fault (the
    // manifest, not the capture block) must still be reported.
    writeFileSync(join(manifestDir, 'com.akasecurity.aka.json'), JSON.stringify({ type: 'stdio' }));
    writeSettings(consentedSettings());
    const out = run();
    expect(out).toContain('installed (out of date)');
    expect(out).toContain('network capture');
    expect(process.exitCode).toBe(1);
  });

  it('prints the not-enabled block and no site lines without consent', () => {
    writeSettings();
    const out = run();
    expect(out).toContain('network capture: not enabled');
    expect(out).not.toContain('chatgpt');
    expect(out).not.toContain('claude-ai');
  });

  it('gives every known site a line even with an empty store', () => {
    writeSettings(consentedSettings());
    const out = run();
    expect(out).toContain('chatgpt');
    expect(out).toContain('claude-ai');
    expect((out.match(/unreported/g) ?? []).length).toBe(2);
  });

  it('prints unavailable for an unreadable store and leaves the exit code alone', () => {
    // A --home with valid, CONSENTED settings (so the fault below is reached
    // rather than short-circuited by the consent check) whose data directory
    // cannot be created: a regular FILE sits where the store's parent
    // directory needs to go.
    const blockedHome = mkdtempSync(join(tmpdir(), 'aka-extension-status-blocked-'));
    mkdirSync(settingsDir(blockedHome), { recursive: true });
    writeFileSync(
      join(settingsDir(blockedHome), 'settings.json'),
      JSON.stringify({
        specVersion: 3,
        runMode: 'standalone',
        policy: 'redact',
        historicalAccess: 'session-only',
        dataSharesInPlace: true,
        vaultKeyCustody: 'file',
        vaultInlineReveal: 'masked',
        redactFallback: 'warn',
        bodyRetention: { enabled: false, retainDays: 30 },
        webChatCapture: consentedSettings(),
      }),
    );
    writeFileSync(join(blockedHome, 'data'), 'not a directory');
    try {
      const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
      runStatus(manifestDir, blockedHome);
      const out = stdout.mock.calls.map((c) => String(c[0])).join('');
      expect(out).toContain('network capture: unavailable');
      expect(out).toContain('could not be read');
      expect(process.exitCode).toBe(0);
    } finally {
      rmSync(blockedHome, { recursive: true, force: true });
    }
  });

  it('leaves the existing host-manifest output unchanged when home is omitted', () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir);
    const out = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(out).toBe(
      'native-messaging host: not installed\n' +
        `  manifest: ${join(manifestDir, 'com.akasecurity.aka.json')}\n` +
        '  run `aka extension install` to set it up\n',
    );
    expect(out).not.toContain('network capture');
  });
});

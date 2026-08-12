import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  chromeManifestDir,
  launcherPath,
  resolveExtensionDist,
  resolveHostScript,
  runInstall,
  runStatus,
} from '../../src/commands/extension.ts';

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
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runInstall(manifestDir, '/fake/native-host/host.js', '/fake/extension');

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
    expect(existsSync(launcher)).toBe(true);
    const launcherSrc = readFileSync(launcher, 'utf8');
    expect(launcherSrc).toContain('/fake/native-host/host.js');
    if (process.platform !== 'win32') {
      expect(launcherSrc.startsWith('#!/bin/sh\n')).toBe(true);
      expect(launcherSrc).toContain(`exec '${process.execPath}'`);
      expect(statSync(launcher).mode & 0o111).not.toBe(0);
    }

    const written = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(written).toContain('Installed the AKA native-messaging host');
    expect(written).toContain('/fake/extension');

    const statusStdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir);
    expect(statusStdout.mock.calls.map((c) => String(c[0])).join('')).toContain('installed');
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
        runInstall(manifestDir, hostScript, '/fake/extension', fakeNode);

        const launcher = launcherPath(manifestDir, process.platform);
        const handedToNode = execFileSync('/bin/sh', [launcher], { encoding: 'utf8' });
        expect(handedToNode).toBe(hostScript);
      } finally {
        rmSync(scratch, { recursive: true, force: true });
      }
    },
  );

  it('declines to install when no Node runtime can be resolved for the launcher', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    runInstall(manifestDir, '/fake/native-host/host.js', '/fake/extension', null);
    expect(process.exitCode).toBe(1);
    expect(stderr.mock.calls.map((c) => String(c[0])).join('')).toContain(
      'no Node.js runtime found',
    );
    expect(existsSync(join(manifestDir, 'com.akasecurity.aka.json'))).toBe(false);
  });

  it('prints instructions to build the extension when its dist could not be resolved', () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runInstall(manifestDir, '/fake/native-host/host.js', null);
    const written = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(written).toContain('pnpm --filter @akasecurity/plugin-browser-extension build');
  });
});

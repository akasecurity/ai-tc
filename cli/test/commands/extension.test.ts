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
      expect(launcherSrc).toContain(`exec "${process.execPath}"`);
      expect(statSync(launcher).mode & 0o111).not.toBe(0);
    }

    const written = stdout.mock.calls.map((c) => String(c[0])).join('');
    expect(written).toContain('Installed the AKA native-messaging host');
    expect(written).toContain('/fake/extension');

    const statusStdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    runStatus(manifestDir);
    expect(statusStdout.mock.calls.map((c) => String(c[0])).join('')).toContain('installed');
  });

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

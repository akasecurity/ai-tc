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

import { dataDir, openLocalDatabase, settingsDir } from '@akasecurity/persistence';
import type { WebCaptureStatus } from '@akasecurity/schema';
import { toCaptureStatusAttributes, WEB_CHAT_CAPTURE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
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

  function seedStatus(tool: 'chatgpt' | 'claude-ai', status: WebCaptureStatus): void {
    const db = openLocalDatabase(dataDir(home));
    try {
      db.auditEvents.insertAuditEvent({
        id: `${tool}-status-${String(Math.random())}`,
        eventType: 'capture_status',
        // Stamped NOW rather than at a fixed date: `captureStatus.latest`
        // bounds its read to the last CAPTURE_STATUS_RECENCY_MS, so a literal
        // calendar date ages out of the window once the wall clock passes it
        // and every case below would then assert against an empty read.
        startedAt: new Date().toISOString(),
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
      live: true,
      shapeMisses: ['message.id'],
    });
    const out = run();
    expect(out).toContain('degraded');
    expect(out).toContain('web-capture-drift (medium)');
    expect(out).toContain('chrome://extensions');
  });

  it('prints the turn count for a site whose capture is working', () => {
    // The one state whose headline is built rather than looked up, so it is
    // the one nothing else in the tree renders.
    writeSettings(consentedSettings());
    seedStatus('chatgpt', {
      ...BASE_STATUS,
      conversationEndpoints: 1,
      live: true,
      exchangesSeenNet: 1,
      sendsSeenDom: 1,
    });
    const out = run();
    expect(out).toContain('active');
    expect(out).toContain('1 turn observed');
    expect(out).not.toContain('web-capture-drift');
  });

  it('prints the blind headline and its own remediation, not the degraded one', () => {
    // The two drift states share a rule id and a severity, so the headline and
    // the remediation are all that separate them on this surface.
    writeSettings(consentedSettings());
    seedStatus('claude-ai', {
      ...BASE_STATUS,
      conversationEndpoints: 1,
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

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type { TriageHit } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { BackfillDeps, BackfillIo } from './backfill.ts';
import { runBackfill, triageSentinel } from './backfill.ts';
import type { ScanSummary } from './history/scan.ts';

// --triage mode mints a real fingerprint key file via
// @akasecurity/plugin-sdk's loadOrCreateFingerprintKey, so each test gets its
// own scratch directory removed afterward rather than a fixed shared path.
let dataDir: string;

beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'aka-backfill-test-'));
});

afterEach(() => {
  rmSync(dataDir, { recursive: true, force: true });
});

function fakeIo(): { io: BackfillIo; stdout: string[]; stderr: string[]; failed: () => boolean } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  let didFail = false;
  return {
    io: {
      stdout: (chunk) => stdout.push(chunk),
      stderr: (chunk) => stderr.push(chunk),
      fail: () => {
        didFail = true;
      },
    },
    stdout,
    stderr,
    failed: () => didFail,
  };
}

function zeroSummary(): ScanSummary {
  return { consented: true, scanned: 0, skipped: 0, findings: 0, bySeverity: {}, windowDays: 30 };
}

function baseDeps(overrides: Partial<BackfillDeps> = {}): BackfillDeps {
  const { io } = fakeIo();
  const config: PluginConfig = {
    settings: { specVersion: 2, runMode: 'standalone', policy: 'redact', historicalAccess: 'full' },
    dataDir,
    dbPath: join(dataDir, 'aka.db'),
    settingsDir: dataDir,
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
  return {
    triage: false,
    io,
    loadConfig: () => config,
    scanHistory: vi.fn(() => Promise.resolve(zeroSummary())),
    reconcileHistory: vi.fn(() => Promise.resolve(undefined)),
    ...overrides,
  };
}

function fixtureHit(rawMatch: string): TriageHit {
  return {
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    maskedMatch: '****',
    rawMatch,
    context: `leaked ${rawMatch} here`,
    confidence: 0.9,
  };
}

describe('triageSentinel', () => {
  it('serializes done/count/status as a single trailing JSON line', () => {
    expect(triageSentinel(3, 'complete')).toBe('{"done":true,"count":3,"status":"complete"}\n');
  });
});

describe('runBackfill — triage mode', () => {
  it('streams exactly N JSONL lines then a matching complete sentinel with nothing to stderr', async () => {
    const { io, stdout, stderr } = fakeIo();
    const hits = [fixtureHit('AKIAEXAMPLE1'), fixtureHit('AKIAEXAMPLE2')];
    const scanHistory = vi.fn((_config, _opts, onHit?: (hit: TriageHit) => void) => {
      for (const hit of hits) onHit?.(hit);
      return Promise.resolve(zeroSummary());
    });
    const deps = baseDeps({ triage: true, io, scanHistory });

    await runBackfill(deps);

    expect(stdout).toHaveLength(3);
    const [first, second, third] = stdout;
    expect((JSON.parse(first ?? '') as TriageHit).rawMatch).toBe('AKIAEXAMPLE1');
    expect((JSON.parse(second ?? '') as TriageHit).rawMatch).toBe('AKIAEXAMPLE2');
    expect(third).toBe(triageSentinel(2, 'complete'));
    expect(stderr).toEqual([]);
  });

  it('emits only the skipped:no-consent sentinel when consent is not full', async () => {
    const { io, stdout } = fakeIo();
    const config: PluginConfig = {
      settings: {
        specVersion: 2,
        runMode: 'standalone',
        policy: 'redact',
        historicalAccess: 'session-only',
      },
      dataDir,
      dbPath: join(dataDir, 'aka.db'),
      settingsDir: dataDir,
      onboarded: true,
      provider: { provider: 'anthropic' },
    };
    const deps = baseDeps({ triage: true, io, loadConfig: () => config });

    await runBackfill(deps);

    expect(stdout).toEqual([triageSentinel(0, 'skipped:no-consent')]);
  });

  it('never writes a success sentinel on a mid-stream rejection, fails loud instead', async () => {
    const { io, stdout, stderr, failed } = fakeIo();
    const scanHistory = vi.fn(() => Promise.reject(new Error('boom: transcript read failed')));
    const deps = baseDeps({ triage: true, io, scanHistory });

    await runBackfill(deps);

    expect(stdout.some((line) => line.includes('"status":"complete"'))).toBe(false);
    expect(failed()).toBe(true);
    expect(stderr.some((line) => line.includes('boom: transcript read failed'))).toBe(true);
  });

  it(
    'never writes a success sentinel when an onHit write throws mid-stream, even though the ' +
      'real scanHistory isolates and swallows that throw itself',
    async () => {
      const { io, stdout, stderr, failed } = fakeIo();
      const hits = [
        fixtureHit('AKIAEXAMPLE1'),
        fixtureHit('AKIAEXAMPLE2'),
        fixtureHit('AKIAEXAMPLE3'),
      ];
      // Mirrors scanHistory's own onHit isolation (history/scan.ts): a
      // synchronous throw from onHit is caught right here and the sweep keeps
      // going, so scanHistory still resolves normally afterward.
      const scanHistory = vi.fn((_config, _opts, onHit?: (hit: TriageHit) => void) => {
        for (const hit of hits) {
          try {
            onHit?.(hit);
          } catch {
            // scanHistory's real isolation: a misbehaving sink must not abort the sweep.
          }
        }
        return Promise.resolve(zeroSummary());
      });
      let writes = 0;
      const throwingIo: BackfillIo = {
        ...io,
        stdout: (chunk) => {
          writes += 1;
          if (writes === 2) throw new Error('EPIPE: downstream judge closed the pipe');
          io.stdout(chunk);
        },
      };
      const deps = baseDeps({ triage: true, io: throwingIo, scanHistory });

      await runBackfill(deps);

      expect(stdout.some((line) => line.includes('"status":"complete"'))).toBe(false);
      expect(failed()).toBe(true);
      expect(stderr.some((line) => line.includes('EPIPE'))).toBe(true);
    },
  );

  it('forwards the self-contamination guard (beforeMs + excludeSessionId) into scanHistory', async () => {
    const { io } = fakeIo();
    const scanHistory = vi.fn(() => Promise.resolve(zeroSummary()));
    const guard = { beforeMs: 1_700_000_000_000, excludeSessionId: 'session_abc' };
    const deps = baseDeps({ triage: true, io, scanHistory, guard });

    await runBackfill(deps);

    // The scan must actually RECEIVE the guard — the whole point of the finding is
    // that runBackfill used to pass {} and the guard did nothing in production.
    expect(scanHistory).toHaveBeenCalledWith(expect.anything(), guard, expect.any(Function));
  });

  it('defaults the scan opts to {} when no guard is provided', async () => {
    const { io } = fakeIo();
    const scanHistory = vi.fn(() => Promise.resolve(zeroSummary()));
    const deps = baseDeps({ triage: true, io, scanHistory });

    await runBackfill(deps);

    expect(scanHistory).toHaveBeenCalledWith(expect.anything(), {}, expect.any(Function));
  });

  it('never leaks a raw value to stderr when an enriched hit fails validation', async () => {
    const { io, stderr, failed } = fakeIo();
    const raw = 'AKIAIOSFODNN7EXAMPLE';
    // A hit that is invalid AFTER enrichment (bad severity) but still carries raw
    // in context: TriageHit validation fails, and the error must not echo the raw.
    const badHit = { ...fixtureHit(raw), severity: 'NOT_A_SEVERITY' } as unknown as TriageHit;
    const scanHistory = vi.fn((_config, _opts, onHit?: (hit: TriageHit) => void) => {
      try {
        onHit?.(badHit);
      } catch {
        // scanHistory's real isolation
      }
      return Promise.resolve(zeroSummary());
    });
    const deps = baseDeps({ triage: true, io, scanHistory });

    await runBackfill(deps);

    expect(failed()).toBe(true);
    expect(stderr.join('')).not.toContain(raw);
    expect(stderr.some((l) => l.includes('history scan failed'))).toBe(true);
  });
});

describe('runBackfill — human mode (unchanged)', () => {
  it('stays fail-open on a scanHistory rejection: friendly stdout message, no fail() call', async () => {
    const { io, stdout, failed } = fakeIo();
    const scanHistory = vi.fn(() => Promise.reject(new Error('boom')));
    const deps = baseDeps({ triage: false, io, scanHistory });

    await runBackfill(deps);

    expect(stdout).toEqual([
      'AKA could not scan your history right now. It will still protect everything from here on.\n',
    ]);
    expect(failed()).toBe(false);
  });
});

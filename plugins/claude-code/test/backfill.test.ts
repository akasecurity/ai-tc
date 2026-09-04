import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { setDefaultGatewayFactory } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import type { TriageHit } from '@akasecurity/schema';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { BackfillDeps, BackfillIo } from '../src/backfill.ts';
import { runBackfill, triageSentinel } from '../src/backfill.ts';
import type { ScanSummary } from '../src/history/scan.ts';

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
  return {
    consented: true,
    scanned: 0,
    skipped: 0,
    findings: 0,
    bySeverity: {},
    windowDays: 30,
    visitedFiles: [],
  };
}

function baseDeps(overrides: Partial<BackfillDeps> = {}): BackfillDeps {
  const { io } = fakeIo();
  const config: PluginConfig = {
    settings: {
      specVersion: 2,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'full',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
    },
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
      return Promise.resolve({ ...zeroSummary(), scanned: hits.length });
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

  it('emits a complete:no-history sentinel when the history set was genuinely empty (scanned === 0)', async () => {
    const { io, stdout, stderr } = fakeIo();
    // A completed, non-truncated scan that examined zero messages — a fresh
    // machine with no Claude history to calibrate from.
    const scanHistory = vi.fn(() => Promise.resolve({ ...zeroSummary(), scanned: 0 }));
    const deps = baseDeps({ triage: true, io, scanHistory });

    await runBackfill(deps);

    expect(stdout).toEqual([triageSentinel(0, 'complete:no-history')]);
    expect(stderr).toEqual([]);
  });

  it('emits a plain complete sentinel when history WAS scanned but nothing surfaced (scanned > 0)', async () => {
    const { io, stdout } = fakeIo();
    // Messages were examined but none leaked — scan-clean, not no-history.
    const scanHistory = vi.fn(() => Promise.resolve({ ...zeroSummary(), scanned: 5 }));
    const deps = baseDeps({ triage: true, io, scanHistory });

    await runBackfill(deps);

    expect(stdout).toEqual([triageSentinel(0, 'complete')]);
  });

  it('emits a plain complete sentinel on a fully-deduped rescan of real history (scanned === 0, skipped > 0)', async () => {
    const { io, stdout } = fakeIo();
    // A re-run over history already recorded on a prior scan: every message is
    // deduped (skipped), none newly examined. History exists — this is NOT
    // no-history, even though scanned is 0.
    const scanHistory = vi.fn(() => Promise.resolve({ ...zeroSummary(), scanned: 0, skipped: 7 }));
    const deps = baseDeps({ triage: true, io, scanHistory });

    await runBackfill(deps);

    expect(stdout).toEqual([triageSentinel(0, 'complete')]);
  });

  it('emits only the skipped:no-consent sentinel when consent is not full', async () => {
    const { io, stdout } = fakeIo();
    const config: PluginConfig = {
      settings: {
        specVersion: 2,
        runMode: 'standalone',
        policy: 'redact',
        historicalAccess: 'session-only',
        dataSharesInPlace: true,
        vaultKeyCustody: 'file',
        vaultInlineReveal: 'masked',
        redactFallback: 'warn',
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

describe('runBackfill — at-rest scrub of visited transcripts', () => {
  const consent = { acknowledgedAt: '2026-07-30T00:00:00.000Z', version: VAULT_CONSENT_VERSION };

  function summaryWithFiles(files: string[]): ScanSummary {
    return { ...zeroSummary(), scanned: files.length, visitedFiles: files };
  }

  function depsWithConsent(
    overrides: Partial<BackfillDeps>,
    consented: boolean,
  ): { deps: BackfillDeps; out: () => string } {
    const { io, stdout } = fakeIo();
    const base = baseDeps({ io, ...overrides });
    const config = base.loadConfig();
    if (consented) config.settings.vaultConsent = consent;
    return { deps: { ...base, loadConfig: () => config }, out: () => stdout.join('') };
  }

  it('scrubs every visited file when vault consent is granted, and says so', async () => {
    const scrubFile = vi.fn().mockResolvedValue({ rewritten: 2 });
    const { deps, out } = depsWithConsent(
      {
        scanHistory: () => Promise.resolve(summaryWithFiles(['/h/a.jsonl', '/h/b.jsonl'])),
        scrubFile,
      },
      true,
    );
    await runBackfill(deps);
    expect(scrubFile.mock.calls.map((c): unknown => c[0])).toEqual(['/h/a.jsonl', '/h/b.jsonl']);
    expect(out()).toContain('Rewrote secrets in 2 transcript files to recoverable vault pointers');
  });

  // Reading history was consented; KEEPING recoverable copies was not — the
  // scrub must not run on the historical grant alone.
  it('never scrubs without vault consent', async () => {
    const scrubFile = vi.fn();
    const { deps, out } = depsWithConsent(
      { scanHistory: () => Promise.resolve(summaryWithFiles(['/h/a.jsonl'])), scrubFile },
      false,
    );
    await runBackfill(deps);
    expect(scrubFile).not.toHaveBeenCalled();
    expect(out()).not.toContain('Rewrote');
  });

  it('a scrub fault fails nothing and claims nothing', async () => {
    const scrubFile = vi
      .fn()
      .mockRejectedValueOnce(new Error('locked'))
      .mockResolvedValueOnce(null);
    const { deps, out } = depsWithConsent(
      {
        scanHistory: () => Promise.resolve(summaryWithFiles(['/h/a.jsonl', '/h/b.jsonl'])),
        scrubFile,
      },
      true,
    );
    await runBackfill(deps);
    expect(out()).toContain('Historical scan complete');
    expect(out()).not.toContain('Rewrote');
  });

  it('clean files (rewritten: 0) are not counted as scrubbed', async () => {
    const scrubFile = vi.fn().mockResolvedValue({ rewritten: 0 });
    const { deps, out } = depsWithConsent(
      { scanHistory: () => Promise.resolve(summaryWithFiles(['/h/a.jsonl'])), scrubFile },
      true,
    );
    await runBackfill(deps);
    expect(out()).not.toContain('Rewrote');
  });

  // The fault posture of the REAL scrubber (no injected scrubFile), which the
  // cases above all bypass. The scrub self-scans, so the machine's pack policy
  // is what decides which spans it may rewrite at all; with no readable policy
  // the only honest answer is to rewrite nothing. Falling back to a policy-blind
  // scrub would put values whose detection is set to Monitor into the vault,
  // and unlike a skipped scrub — which the next run simply repeats — a rewrite
  // of the user's own transcripts is not undoable.
  //
  // The positive control is the first case in this block: with a scrubber in
  // hand the same run reports 'Rewrote secrets in …'. Here it must not, and the
  // spy proves the run got as far as asking for policy rather than bailing out
  // somewhere earlier.
  it('scrubs nothing when the pack policy cannot be read', async () => {
    const getPolicyBundle = vi.fn(() => Promise.reject(new Error('bundle unreadable')));
    const restore = setDefaultGatewayFactory(
      () =>
        ({
          getPolicyBundle,
          close: () => Promise.resolve(),
        }) as unknown as DataGateway,
    );
    try {
      const { deps, out } = depsWithConsent(
        { scanHistory: () => Promise.resolve(summaryWithFiles(['/h/a.jsonl'])) },
        true,
      );
      await runBackfill(deps);
      expect(getPolicyBundle).toHaveBeenCalledTimes(1);
      expect(out()).toContain('Historical scan complete');
      expect(out()).not.toContain('Rewrote');
    } finally {
      restore();
    }
  });

  // The --triage stdout stream is a machine protocol (hits + sentinel); the
  // scrub still runs under both grants but must add nothing to that stream.
  it('triage mode scrubs silently', async () => {
    const scrubFile = vi.fn().mockResolvedValue({ rewritten: 1 });
    const { deps, out } = depsWithConsent(
      {
        triage: true,
        scanHistory: () => Promise.resolve(summaryWithFiles(['/h/a.jsonl'])),
        scrubFile,
      },
      true,
    );
    await runBackfill(deps);
    expect(scrubFile).toHaveBeenCalledTimes(1);
    expect(out()).toBe(triageSentinel(0, 'complete'));
  });
});

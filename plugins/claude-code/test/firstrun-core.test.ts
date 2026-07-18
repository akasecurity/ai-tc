import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { handleCapture, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { SetupHandoffOffer } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { parseSurfacedCount, runFirstRun, runFirstRunFailOpen } from '../src/firstrun-core.ts';
import { readPostureBlock } from '../src/posture.ts';
import { readFrameJsonBlock } from '../src/setup-frame-json.ts';

// Composed at runtime so the repo's own secret scanning doesn't flag this file.
const AWS_EXAMPLE_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
// Composed for the same reason — a literal address would be redacted on write.
const PII_EMAIL = ['jane.doe', 'example.com'].join('@');

function config(dataDir: string): PluginConfig {
  return {
    settings: {
      specVersion: 1,
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
}

describe('parseSurfacedCount', () => {
  it('reads a non-negative integer from --surfaced', () => {
    expect(parseSurfacedCount(['--surfaced', '3'])).toBe(3);
    expect(parseSurfacedCount(['--surfaced', '0'])).toBe(0);
  });

  it('returns undefined when the flag is absent or malformed — never a fabricated count', () => {
    expect(parseSurfacedCount([])).toBeUndefined();
    expect(parseSurfacedCount(['--surfaced'])).toBeUndefined();
    expect(parseSurfacedCount(['--surfaced', 'lots'])).toBeUndefined();
    expect(parseSurfacedCount(['--surfaced', '-1'])).toBeUndefined();
    expect(parseSurfacedCount(['--surfaced', '2.5'])).toBeUndefined();
  });
});

describe('runFirstRun — emits the handoff-offer payload alongside the card', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-firstrun-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function seedAndRun(argv: readonly string[]): Promise<string> {
    const cfg = config(dir);
    // Seed through the real write path so the card's stats trace to real data.
    await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: `here is a key ${AWS_EXAMPLE_KEY}` },
      cfg,
    );
    const gateway = resolveDataGateway(cfg);
    const out: string[] = [];
    try {
      await runFirstRun({
        argv,
        gateway,
        readPosture: () => readPostureBlock(() => openLocalDatabase(cfg.dataDir)),
        stdout: (s) => out.push(s),
      });
    } finally {
      await gateway.close();
    }
    return out.join('');
  }

  it('emits a valid SetupHandoffOffer whose worthALook is the passed --surfaced count', async () => {
    const blob = await seedAndRun(['--surfaced', '2']);

    // Additive: the human-readable install card is still present (not replaced).
    expect(blob).toContain('installed');
    expect(blob).toContain('First scan complete');

    const payload = readFrameJsonBlock(blob);
    const parsed = SetupHandoffOffer.safeParse(payload);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;

    // 'M worth a look' is the surfaced/important count threaded in from the
    // calibration preview — NOT the whole-store finding total (1 finding was seeded).
    expect(parsed.data.worthALook).toBe(2);
    expect(parsed.data.options).toEqual([
      { id: 'open-dashboard', label: 'Open dashboard' },
      { id: 'not-now', label: 'Not now' },
    ]);
  });

  it('omits the handoff payload (never fabricates one) when no surfaced count is supplied', async () => {
    const blob = await seedAndRun([]);

    // The card still renders — only the machine-readable payload is withheld.
    expect(blob).toContain('installed');
    expect(readFrameJsonBlock(blob)).toBeUndefined();
  });

  it('degrades honestly over an empty store (no scanned findings) — omits the handoff payload, no fabricated count', async () => {
    // No capture seeded: the store holds no scanned findings (the no-scan /
    // found-nothing state). Running with no --surfaced must degrade honestly.
    const cfg = config(dir);
    const gateway = resolveDataGateway(cfg);
    const out: string[] = [];
    try {
      await runFirstRun({
        argv: [],
        gateway,
        readPosture: () => readPostureBlock(() => openLocalDatabase(cfg.dataDir)),
        stdout: (s) => out.push(s),
      });
    } finally {
      await gateway.close();
    }
    const blob = out.join('');

    // The install card still renders as a tidy success state…
    expect(blob).toContain('installed');
    // …with an honest empty-state stats line, never a fabricated scan tally…
    expect(blob).toContain("you're starting clean");
    expect(blob).not.toContain('worth a look');
    // …and the machine-readable handoff payload is withheld, never fabricated.
    expect(readFrameJsonBlock(blob)).toBeUndefined();
  });

  it('omits only the Posture section (rest of the card renders) when opening the posture store throws', async () => {
    const cfg = config(dir);
    await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: `here is a key ${AWS_EXAMPLE_KEY}` },
      cfg,
    );
    const gateway = resolveDataGateway(cfg);
    const out: string[] = [];
    try {
      await runFirstRun({
        argv: ['--surfaced', '2'],
        gateway,
        // The posture opener throws (unopenable store). It degrades identically
        // to a read fault: only the Posture section is hidden.
        readPosture: () =>
          readPostureBlock(() => {
            throw new Error('cannot open database');
          }),
        stdout: (s) => out.push(s),
      });
    } finally {
      await gateway.close();
    }
    const blob = out.join('');

    // The rest of the install card still renders over the live gateway…
    expect(blob).toContain('installed');
    expect(blob).toContain('First scan complete');
    expect(blob).toContain('Findings');
    // …and the handoff payload is still emitted.
    expect(SetupHandoffOffer.safeParse(readFrameJsonBlock(blob)).success).toBe(true);
    // …but the Posture section is omitted, not collapsed into the fail-open note.
    expect(blob).not.toContain('Posture');
    expect(blob).not.toContain("I couldn't read the local store");
  });

  it('carries no raw detected value into the emitted frame block', async () => {
    const blob = await seedAndRun(['--surfaced', '2']);
    expect(blob).toContain('<<<AKA_FRAME_JSON');
    expect(JSON.stringify(readFrameJsonBlock(blob))).not.toContain(AWS_EXAMPLE_KEY);
    // The card masks matches, so the raw key never appears anywhere on stdout.
    expect(blob).not.toContain(AWS_EXAMPLE_KEY);
  });

  it('card stats trace to the seeded store, never a fixed literal', async () => {
    const cfg = config(dir);
    // Two distinct sensitive findings through the real write path: a critical
    // secret and a medium PII match — two categories, two findings.
    await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: `here is a key ${AWS_EXAMPLE_KEY}` },
      cfg,
    );
    await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: `contact ${PII_EMAIL}` },
      cfg,
    );

    const gateway = resolveDataGateway(cfg);
    const out: string[] = [];
    let summaryFindings: number;
    try {
      // Read back what the store actually holds so the assertion is a genuine
      // trace (card number === store number), not a hardcoded expectation.
      summaryFindings = (await gateway.healthSummary()).findings;
      await runFirstRun({
        argv: [],
        gateway,
        readPosture: () => readPostureBlock(() => openLocalDatabase(cfg.dataDir)),
        stdout: (s) => out.push(s),
      });
    } finally {
      await gateway.close();
    }
    const blob = out.join('');

    // The 'Findings N' stat is the real whole-store total, not the render-unit
    // fixture's literal.
    expect(summaryFindings).toBe(2);
    expect(blob).toContain(`Findings ${String(summaryFindings)}`);
    expect(blob).not.toContain('Findings 142');
    // 'Recommendations' mirrors /recommend over the real findings: one per
    // category (secret + pii) → 2.
    expect(blob).toContain('Recommendations 2');
    // 'Health' is the derived score over the real summary, rendered out of 100 —
    // never a fixed 82/100 sample.
    expect(blob).toMatch(/Health \d+\/100/);
    expect(blob).not.toContain('82/100');
    // The Try line names only commands the shipped plugin registers — never the
    // not-yet-shipped rename targets.
    expect(blob).toContain('Try:');
    expect(blob).not.toContain('/aka:secretscan');
    expect(blob).not.toContain('/aka:codescan');
  });
});

describe('runFirstRunFailOpen — degrades to the store-unavailable note on a store-read failure', () => {
  it('writes the honest note instead of throwing when the gateway read fails', async () => {
    const out: string[] = [];
    // A gateway whose store reads fail (missing / corrupt / locked db). runFirstRun
    // throws on a read failure; the fail-open wrapper must catch it and substitute
    // the honest note so no error escapes to break the Claude session.
    const failingGateway = {
      healthSummary: () =>
        Promise.reject(new Error('SQLITE_CORRUPT: database disk image is malformed')),
      recentFindings: () => Promise.reject(new Error('SQLITE_CORRUPT')),
      close: () => Promise.resolve(),
    } as unknown as DataGateway;

    let threw: unknown;
    try {
      await runFirstRunFailOpen({
        argv: ['--surfaced', '2'],
        gateway: failingGateway,
        readPosture: () => Promise.resolve(''),
        stdout: (s) => out.push(s),
      });
    } catch (e) {
      threw = e;
    }
    const blob = out.join('');

    // Fail-open: no throw escaped, and the honest store-unavailable note stands in.
    expect(threw).toBeUndefined();
    expect(blob).toContain("I couldn't read the local store");
    // No fabricated card: the install card's stats never rendered over a dead store.
    expect(blob).not.toContain('installed');
  });
});

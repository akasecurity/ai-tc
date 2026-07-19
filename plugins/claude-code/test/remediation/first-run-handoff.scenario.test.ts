import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { handleCapture, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type {
  CalibrationPreview,
  MaskedSecretFinding,
  SetupHandoffOffer,
} from '@akasecurity/schema';
import { SetupHandoffOffer as SetupHandoffOfferSchema } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { frameCalibration } from '../../src/calibration.ts';
import { runFirstRun } from '../../src/firstrun-core.ts';
import { readPostureBlock } from '../../src/posture.ts';
import { presentBatchedRemediation } from '../../src/remediation/chain.ts';
import { loadSecretLeakFindings } from '../../src/remediation/findings.ts';
import { frameJsonBlock, readFrameJsonBlock } from '../../src/setup-frame-json.ts';

// The first-run handoff seam, driven at the APP-LEVEL: the real frame-0.6
// handoff-offer payload (runFirstRun → buildHandoffOffer) composed with the real
// chain entry (loadSecretLeakFindings → presentBatchedRemediation), both surfaces
// reading the SAME persisted calibration frame the wizard emitted at frame 0.4. It
// proves the calibration and remediation boundaries meet: remediation is entered
// exactly when the calibration scan surfaced live-key secret findings and never
// otherwise, the frame-0.6 dashboard handoff is retained (composed, not replaced)
// on the live-key branch, and the count the remediation decision presents agrees with the
// surfaced live-key count frame 0.4 counted. The prompt-authored AskUserQuestion
// issuance is covered by the manual walkthrough; this is its automated app-level
// companion.

// Composed at runtime so the repo's own secret scan does not flag this file.
const AWS_EXAMPLE_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const MASKED_TOKEN = 'AKIA****************';

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

// One masked per-secret summary the calibration frame carries for a surfaced
// live-key finding — raw-free by construction (only the masked token, never the
// raw key), the shape the finding table renders from.
function secretFinding(i: number): MaskedSecretFinding {
  return {
    provider: 'aws',
    maskedToken: MASKED_TOKEN,
    where: { filePath: `/tmp/session-${String(i)}.jsonl` },
    // Validity is unverifiable offline, so the honest default is 'unknown'.
    state: 'unknown',
  };
}

describe('first-run handoff seam: calibration findings trigger (or skip) remediation (app-level)', () => {
  const dirs: string[] = [];

  beforeEach(() => {
    dirs.length = 0;
  });
  afterEach(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  // Frame 0.4: build the calibration frame the wizard emits for a preview + its
  // masked secret findings, persist it exactly as the wizard writes it, and read
  // back the surfaced secret findings the remediation loader sees. This one persisted
  // frame is the SINGLE source both the 0.6 handoff gate and the remediation decision
  // read, so their agreement below is genuine, not two hand-set literals.
  function calibrate(preview: CalibrationPreview, masked: readonly MaskedSecretFinding[]) {
    const frame = frameCalibration(preview, masked).frame;
    const persisted = frameJsonBlock(frame);
    const surfacedSecrets = loadSecretLeakFindings(() => persisted) ?? [];
    return { frame, persisted, surfacedSecrets };
  }

  // Frame 0.6: run the REAL install-complete core over a real seeded store and
  // return the structured handoff-offer payload it emits. `surfaced` is frame
  // 0.4's all-category important count; `liveKeys` is the narrower surfaced
  // live-key secret count — both derived from the persisted frame by the caller,
  // never invented here (the wizard threads the same preview values in product).
  async function frameSixHandoff(
    surfaced: number,
    liveKeys: number,
  ): Promise<{
    blob: string;
    offer: SetupHandoffOffer;
  }> {
    const dir = mkdtempSync(join(tmpdir(), 'aka-first-run-handoff-'));
    dirs.push(dir);
    const cfg = config(dir);
    // Seed through the real capture path so the card's stats trace to real data.
    await handleCapture(
      { kind: 'prompt', sourceTool: 'claude-code', text: `here is a key ${AWS_EXAMPLE_KEY}` },
      cfg,
    );
    const gateway = resolveDataGateway(cfg);
    const out: string[] = [];
    try {
      await runFirstRun({
        argv: ['--surfaced', String(surfaced), '--live-keys', String(liveKeys)],
        gateway,
        readPosture: () => readPostureBlock(() => openLocalDatabase(cfg.dataDir)),
        stdout: (s) => out.push(s),
      });
    } finally {
      await gateway.close();
    }
    const blob = out.join('');
    const parsed = SetupHandoffOfferSchema.parse(readFrameJsonBlock(blob));
    return { blob, offer: parsed };
  }

  // The 0.6→remediation entry the prompt layer performs: it routes on the offer's
  // structured `enter-remediation` option (present exactly when live keys
  // surfaced) and, when present, invokes the real chain over the findings loaded
  // from the SAME persisted frame. Composition of real seams only — no mock.
  function enterRemediation(offer: SetupHandoffOffer, persisted: string) {
    const offersRemediation = offer.options.some((o) => o.id === 'enter-remediation');
    if (!offersRemediation) return { entered: false as const };
    const findings = loadSecretLeakFindings(() => persisted) ?? [];
    return {
      entered: true as const,
      decision: presentBatchedRemediation(findings, { entrySource: 'first-run' }),
    };
  }

  it('live-key branch: frame 0.6 composes the chain entry with the retained dashboard handoff, and the remediation decision agrees on N with frame 0.4', async () => {
    // The calibration surfaced 3 live-key secrets AND one non-secret (pii) finding,
    // so the all-category surfaced count (4) is strictly larger than the live-key
    // count (3) — the gate below is the live-key subset, not the display count.
    const preview: CalibrationPreview = {
      categories: [
        { category: 'secret', genuineCount: 3, fpCount: 10, egress: false },
        { category: 'pii', genuineCount: 1, fpCount: 5, egress: false },
      ],
      posture: {
        secret: 'warn',
        pii: 'warn',
        financial: 'warn',
        phi: 'warn',
        code_flaw: 'warn',
        custom: 'warn',
        code_context: 'monitor',
        config: 'monitor',
      },
    };
    const masked = [secretFinding(0), secretFinding(1), secretFinding(2)];
    const { frame, persisted, surfacedSecrets } = calibrate(preview, masked);

    // Frame 0.4 counted 3 surfaced secret findings ('M that matter (live keys)'),
    // and the loader both surfaces read reproduces that count off the one frame.
    const surfacedLiveKeys = surfacedSecrets.length;
    expect(surfacedLiveKeys).toBe(3);

    // Frame 0.6 runs with the counts derived from that same frame: the broader
    // all-category important count and the narrower live-key subset.
    const { blob, offer } = await frameSixHandoff(frame.counts.important, surfacedLiveKeys);

    // The all-category display count (4) is larger than the live-key count (3):
    // the two are genuinely distinct, so the gate cannot be the display count.
    expect(offer.worthALook).toBe(4);
    expect(offer.liveKeys).toBe(3);

    // The chain entry composes with, and never replaces, the frame-0.6
    // dashboard handoff: Open dashboard / Not now stay reachable exactly as on the
    // no-findings branch (the dashboard handoff does not regress).
    expect(offer.options).toEqual([
      { id: 'enter-remediation', label: 'Review leaked keys' },
      { id: 'open-dashboard', label: 'Open dashboard' },
      { id: 'not-now', label: 'Not now' },
    ]);
    // The rendered install card itself still carries the dashboard handoff line.
    expect(blob).toContain('Open dashboard');

    // Completing frame 0.6 hands off into the batched remediation decision, so
    // calibration and the remediation tail form one continuous first-run flow.
    const entry = enterRemediation(offer, persisted);
    expect(entry.entered).toBe(true);
    if (!entry.entered) return;
    expect(entry.decision.kind).toBe('decision');
    if (entry.decision.kind !== 'decision') return;

    // The findings the remediation decision presents are the same surfaced secret findings
    // frame 0.4 counted: the two surfaces agree on N, and the count presented at
    // the remediation decision equals the surfaced live-key count (3) — NOT the broader display count (4).
    expect(entry.decision.secretCount).toBe(surfacedLiveKeys);
    expect(entry.decision.secretCount).toBe(offer.liveKeys);
    expect(entry.decision.prompt).toContain('3 live keys are sitting in old transcripts');
  });

  it('no-findings branch — only non-secret findings surfaced: no remediation offered; dashboard handoff only', async () => {
    // A surfaced pii finding but no secret: the display count is positive while the
    // live-key count is zero, so the gate (the live-key subset) stays shut.
    const preview: CalibrationPreview = {
      categories: [{ category: 'pii', genuineCount: 1, fpCount: 5, egress: false }],
      posture: {
        secret: 'warn',
        pii: 'warn',
        financial: 'warn',
        phi: 'warn',
        code_flaw: 'warn',
        custom: 'warn',
        code_context: 'monitor',
        config: 'monitor',
      },
    };
    // No secret surfaced ⇒ the frame carries no maskedFindings.
    const { frame, persisted, surfacedSecrets } = calibrate(preview, []);
    expect(surfacedSecrets).toHaveLength(0);

    const { offer } = await frameSixHandoff(frame.counts.important, surfacedSecrets.length);

    // worthALook is positive (something surfaced) but no chain entry is offered:
    // the gate is the live-key count, never the all-category display count.
    expect(offer.worthALook).toBe(1);
    expect(offer.options).toEqual([
      { id: 'open-dashboard', label: 'Open dashboard' },
      { id: 'not-now', label: 'Not now' },
    ]);

    // The journey ends at the installed summary with the dashboard handoff only —
    // no remediation decision, and even a forced load degrades honestly to no-decision.
    const entry = enterRemediation(offer, persisted);
    expect(entry.entered).toBe(false);
    expect(
      presentBatchedRemediation(loadSecretLeakFindings(() => persisted) ?? [], {
        entrySource: 'first-run',
      }),
    ).toEqual({ kind: 'no-decision' });
  });

  it('no-findings branch — empty scan surfaced nothing: no remediation offered; dashboard handoff only', async () => {
    // The scan ran and surfaced nothing (all suppressed): zero surfaced findings.
    const preview: CalibrationPreview = {
      categories: [{ category: 'secret', genuineCount: 0, fpCount: 10, egress: false }],
      posture: {
        secret: 'warn',
        pii: 'warn',
        financial: 'warn',
        phi: 'warn',
        code_flaw: 'warn',
        custom: 'warn',
        code_context: 'monitor',
        config: 'monitor',
      },
    };
    const { frame, persisted, surfacedSecrets } = calibrate(preview, []);
    expect(surfacedSecrets).toHaveLength(0);

    const { offer } = await frameSixHandoff(frame.counts.important, surfacedSecrets.length);

    expect(offer.worthALook).toBe(0);
    expect(offer.options).toEqual([
      { id: 'open-dashboard', label: 'Open dashboard' },
      { id: 'not-now', label: 'Not now' },
    ]);

    const entry = enterRemediation(offer, persisted);
    expect(entry.entered).toBe(false);
  });

  it('the remediation flow is entered exactly when the calibration surfaced secret-leak findings, and never otherwise', async () => {
    const posture = {
      secret: 'warn',
      pii: 'warn',
      financial: 'warn',
      phi: 'warn',
      code_flaw: 'warn',
      custom: 'warn',
      code_context: 'monitor',
      config: 'monitor',
    } as const;

    // Three branches over one shared seam: live-key secrets surfaced, only
    // non-secret findings surfaced, and an empty scan. Only the first enters.
    const branches: { name: string; preview: CalibrationPreview; masked: MaskedSecretFinding[] }[] =
      [
        {
          name: 'live-key secrets surfaced',
          preview: {
            categories: [{ category: 'secret', genuineCount: 2, fpCount: 4, egress: false }],
            posture,
          },
          masked: [secretFinding(0), secretFinding(1)],
        },
        {
          name: 'only non-secret findings surfaced',
          preview: {
            categories: [{ category: 'pii', genuineCount: 2, fpCount: 4, egress: false }],
            posture,
          },
          masked: [],
        },
        {
          name: 'empty scan',
          preview: {
            categories: [{ category: 'secret', genuineCount: 0, fpCount: 6, egress: false }],
            posture,
          },
          masked: [],
        },
      ];

    const entered: boolean[] = [];
    for (const branch of branches) {
      const { frame, persisted, surfacedSecrets } = calibrate(branch.preview, branch.masked);
      const { offer } = await frameSixHandoff(frame.counts.important, surfacedSecrets.length);
      entered.push(enterRemediation(offer, persisted).entered);
    }

    // Entered exactly when secret-leak findings surfaced, and never otherwise.
    expect(entered).toEqual([true, false, false]);
  });
});

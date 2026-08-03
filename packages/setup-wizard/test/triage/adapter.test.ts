import type {
  CalibrationFrame,
  CalibrationPreview,
  FalsePositivePatternGroup,
  MaskedSecretFinding,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';
import { severityFloorPosture } from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

import {
  type AdapterDb,
  type AdapterDeps,
  type AdapterPresenter,
  runApply,
} from '../../src/triage/adapter.ts';
import { type PersistedPlan, PLAN_FILE_VERSION } from '../../src/triage/plan-file.ts';

const RAW = 'AKIAIOSFODNN7EXAMPLE';
const FP = 'ab'.repeat(32);
const PLAN_PATH = '/sentinel/plan/setup-plan.json';

const hit = (over: Partial<TriageHit> = {}): TriageHit => ({
  ruleId: 'core-secret/aws',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A***E',
  rawMatch: RAW,
  context: `export KEY=${RAW} # prod`,
  confidence: 0.9,
  id: '0',
  valueFingerprint: FP,
  keyVersion: 1,
  ...over,
});

const streamText = () =>
  JSON.stringify(hit()) +
  '\n' +
  JSON.stringify({ done: true, count: 1, status: 'complete' }) +
  '\n';

const sentinelStream = (status: string) => `${JSON.stringify({ done: true, count: 0, status })}\n`;

const verdict = (): TriageRecommendation => ({
  perCategory: [
    {
      category: 'secret',
      action: 'warn',
      reasoning: 'canonical fake AWS example key',
      genuineCount: 0,
      fpCount: 1,
      fpIds: ['0'],
    },
  ],
  notes: 'looks routine',
});

// Every member returns a distinguishable sentinel: host-branded copy can reach
// stdout ONLY through this injected surface, so any un-sentineled host copy in
// the output would have to originate in the shared core — the exact leak this
// suite exists to rule out. Frame payloads are unique object sentinels so the
// pass-through into frameJsonBlock is provable by identity, not by shape.
function sentinelPresenter() {
  // Unique object sentinels asserted by IDENTITY (toBe) — the cast to the
  // schema frame type is safe because no case reads frame fields, only that
  // the exact object the presenter returned is the one relayed.
  const emptyFrame = { sentinel: 'empty-frame' } as unknown as CalibrationFrame;
  const zeroFrame = { sentinel: 'zero-count-frame' } as unknown as CalibrationFrame;
  const calibrationFrame = { sentinel: 'calibration-frame' } as unknown as CalibrationFrame;
  const frameJsonBlockReceived: unknown[] = [];
  const frameEmptyStateCalls: {
    cause: 'scan-clean' | 'no-history';
    posture: CalibrationPreview['posture'];
  }[] = [];
  const frameCalibrationCalls: {
    preview: CalibrationPreview;
    maskedFindings: readonly MaskedSecretFinding[];
    falsePositivePatterns: readonly FalsePositivePatternGroup[];
  }[] = [];
  const zeroCountFrameCalls: CalibrationPreview['posture'][] = [];
  const present: AdapterPresenter = {
    show: (body) => `<<SHOW:${body}>>`,
    fenced: (body) => `<<FENCED:${body}>>`,
    frameJsonBlock: (payload) => {
      frameJsonBlockReceived.push(payload);
      return `<<JSON:${JSON.stringify(payload)}>>`;
    },
    frameEmptyState: (cause, posture) => {
      frameEmptyStateCalls.push({ cause, posture });
      return { copy: `<<EMPTY:${cause}>>`, frame: emptyFrame };
    },
    frameCalibration: (preview, maskedFindings, falsePositivePatterns) => {
      frameCalibrationCalls.push({ preview, maskedFindings, falsePositivePatterns });
      return { copy: '<<CALIBRATION-COPY>>', frame: calibrationFrame };
    },
    renderRecommendedPosture: () => '<<RECOMMENDED-POSTURE>>',
    zeroCountFrame: (posture) => {
      zeroCountFrameCalls.push(posture);
      return zeroFrame;
    },
    renderApplied: (categoriesTuned, dismissed) =>
      `<<APPLIED:${String(categoriesTuned)}:${String(dismissed)}>>`,
    storeUnavailableNote: '<<STORE-UNAVAILABLE>>',
    rerunHint: '<<RERUN-HINT>>',
  };
  return {
    present,
    emptyFrame,
    zeroFrame,
    calibrationFrame,
    frameJsonBlockReceived,
    frameEmptyStateCalls,
    frameCalibrationCalls,
    zeroCountFrameCalls,
  };
}

const openFakeDb = (): AdapterDb => ({
  policies: {
    getCategoryAction: () => undefined,
    upsertCategoryAction: vi.fn(),
  },
  exceptions: {
    create: () => Promise.resolve(),
  },
  close: vi.fn(),
});

// The preview never reads a plan file; write returns a fixed path so the
// untagged status lines are byte-deterministic.
const fakePlanIO = () => ({
  write: () => PLAN_PATH,
  read: (): never => {
    throw new Error('preview must not read a plan file');
  },
  delete: vi.fn(),
});

// Drive runApply's preview path with the sentinel presenter over faked IO.
async function drive(opts: { stream?: string; consent?: boolean; openDb?: AdapterDeps['openDb'] }) {
  const p = sentinelPresenter();
  const out: string[] = [];
  const runJudge = vi.fn(() => verdict());
  const code = await runApply({
    present: p.present,
    argv: [],
    readStream: () => opts.stream ?? streamText(),
    runJudge,
    modelJudgeConsent: () => opts.consent ?? true,
    openDb: opts.openDb ?? openFakeDb,
    now: () => 0,
    createdBy: () => 'tester',
    stdout: (s) => out.push(s),
    stderr: vi.fn(),
    planIO: fakePlanIO(),
  });
  return { code, out, p, runJudge };
}

const SENTINEL_WRAPPED = /^<<(?:SHOW|JSON):/;
// The plan path + re-run hint are the preview's only untagged status lines —
// machine plumbing the wizard consumes, never relayed human copy.
const PLAN_STATUS = /^\nPlan saved to: |^Re-run with: /;

function expectSentinelOnly(out: readonly string[], opts: { planStatus?: boolean } = {}): void {
  for (const chunk of out) {
    if (opts.planStatus === true && PLAN_STATUS.test(chunk)) continue;
    expect(chunk).toMatch(SENTINEL_WRAPPED);
  }
}

// Host-branded copy lives only in each plugin's own presenter. The sentinel
// presenter emits none of it, so a hit here means the shared core printed a
// host surface itself.
const HOST_COPY = [
  'Claude',
  'Codex',
  'nothing needs your attention',
  'Nothing to learn from yet',
  'I went through',
  "I couldn't check my records",
];

function expectHostFree(out: readonly string[]): void {
  const blob = out.join('');
  for (const phrase of HOST_COPY) expect(blob).not.toContain(phrase);
}

describe('runApply — the no-history empty state rides the presenter seam', () => {
  it('emits only the sentinel-wrapped empty copy and its frame, over the severity floor', async () => {
    const { code, out, p } = await drive({ stream: sentinelStream('complete:no-history') });
    expect(code).toBe(0);
    // Exactly the presenter's output, wrapped by the presenter's own relay
    // framing — nothing else reaches stdout on this path.
    expect(out).toEqual([
      '<<SHOW:<<FENCED:<<EMPTY:no-history>>>>>>',
      `<<JSON:${JSON.stringify(p.emptyFrame)}>>`,
    ]);
    expect(p.frameEmptyStateCalls).toEqual([
      { cause: 'no-history', posture: severityFloorPosture() },
    ]);
    // The frame handed to frameJsonBlock is frameEmptyState's return, verbatim.
    expect(p.frameJsonBlockReceived).toHaveLength(1);
    expect(p.frameJsonBlockReceived[0]).toBe(p.emptyFrame);
  });
});

describe('runApply — the scan-clean empty state rides the presenter seam', () => {
  it('emits only the sentinel-wrapped empty copy and its frame, tagged scan-clean', async () => {
    const { code, out, p } = await drive({ stream: sentinelStream('complete') });
    expect(code).toBe(0);
    expect(out).toEqual([
      '<<SHOW:<<FENCED:<<EMPTY:scan-clean>>>>>>',
      `<<JSON:${JSON.stringify(p.emptyFrame)}>>`,
    ]);
    expect(p.frameEmptyStateCalls).toEqual([
      { cause: 'scan-clean', posture: severityFloorPosture() },
    ]);
    expect(p.frameJsonBlockReceived[0]).toBe(p.emptyFrame);
  });
});

describe('runApply — the consent skip rides the presenter seam', () => {
  it('sends the skip line through present.show and exactly zeroCountFrame through frameJsonBlock', async () => {
    const { code, out, p, runJudge } = await drive({ consent: false });
    expect(code).toBe(0);
    expect(runJudge).not.toHaveBeenCalled();
    // The skip line is shared-core copy, but its relay framing is the host's:
    // it rides present.show, never a bare stdout write.
    expect(out).toEqual([
      "<<SHOW:I didn't send anything to the model — model-judge consent wasn't granted.>>",
      `<<JSON:${JSON.stringify(p.zeroFrame)}>>`,
    ]);
    // frameJsonBlock received EXACTLY zeroCountFrame's return — the same object,
    // not a re-derived lookalike.
    expect(p.frameJsonBlockReceived).toHaveLength(1);
    expect(p.frameJsonBlockReceived[0]).toBe(p.zeroFrame);
    expect(p.zeroCountFrameCalls).toEqual([severityFloorPosture()]);
    expectHostFree(out);
  });
});

describe('runApply — the calibration gate + frame ride the presenter seam', () => {
  it('fences the gate through show/fenced, ends it with the presenter card, and frames calibration.frame verbatim', async () => {
    const { code, out, p } = await drive({});
    expect(code).toBe(0);
    expect(out).toHaveLength(4);
    const [gate, frame, planLine, rerunLine] = out;
    if (gate === undefined) throw new Error('no gate emitted');

    // The whole human gate is one presenter-wrapped relay region, closing with
    // the presenter's calibrated card and condensed posture render.
    expect(gate).toMatch(/^<<SHOW:<<FENCED:/);
    expect(gate).toContain('<<CALIBRATION-COPY>>');
    expect(gate.endsWith('<<RECOMMENDED-POSTURE>>>>>>')).toBe(true);
    expect(gate).not.toContain('<<STORE-UNAVAILABLE>>');

    // The machine frame is frameCalibration's frame, passed through verbatim.
    expect(frame).toBe(`<<JSON:${JSON.stringify(p.calibrationFrame)}>>`);
    expect(p.frameJsonBlockReceived).toHaveLength(1);
    expect(p.frameJsonBlockReceived[0]).toBe(p.calibrationFrame);

    // The only untagged stdout is the plan-file plumbing.
    expect(planLine).toBe(`\nPlan saved to: ${PLAN_PATH}\n`);
    expect(rerunLine).toMatch(/^Re-run with: /);
    expectSentinelOnly(out, { planStatus: true });
    expectHostFree(out);

    // The seam hands the presenter this run's real derivations, not literals:
    // the plan's genuine/suppressed split and the recommended posture.
    const [cal] = p.frameCalibrationCalls;
    if (cal === undefined) throw new Error('frameCalibration was not called');
    expect(cal.preview.categories).toEqual([
      { category: 'secret', genuineCount: 0, fpCount: 1, egress: false },
    ]);
    expect(cal.preview.posture.secret).toBe('warn');
    // All-suppressed run: nothing surfaced, one FP pattern group derived.
    expect(cal.maskedFindings).toEqual([]);
    expect(cal.falsePositivePatterns).toHaveLength(1);
  });
});

describe('runApply — the confirm drift refusal rides the presenter seam', () => {
  it("names the presenter's rerun hint in the stale-plan refusal and writes nothing", async () => {
    const p = sentinelPresenter();
    const out: string[] = [];
    const err: string[] = [];
    const upsertCategoryAction = vi.fn();
    const db: AdapterDb = {
      policies: { getCategoryAction: () => undefined, upsertCategoryAction },
      exceptions: { create: () => Promise.resolve() },
      close: vi.fn(),
    };
    // Previewed against `current: { secret: 'log' }`; the fake store now
    // answers undefined for every category — the plan is stale, so confirm
    // must refuse and route the user back to the wizard.
    const plan: PersistedPlan = {
      version: PLAN_FILE_VERSION,
      posture: { secret: 'warn' },
      entries: [],
      showcase: [],
      join: [],
      notes: '',
      current: { secret: 'log' },
    };
    const code = await runApply({
      present: p.present,
      argv: ['--confirmed', '--plan', PLAN_PATH],
      readStream: (): never => {
        throw new Error('confirm must not read the stream');
      },
      runJudge: (): never => {
        throw new Error('confirm must not run the judge');
      },
      modelJudgeConsent: () => true,
      openDb: () => db,
      now: () => 0,
      createdBy: () => 'tester',
      stdout: (s) => out.push(s),
      stderr: (s) => err.push(s),
      planIO: { write: () => PLAN_PATH, read: () => plan, delete: vi.fn() },
    });

    expect(code).toBe(1);
    expect(out).toEqual([]);
    expect(upsertCategoryAction).not.toHaveBeenCalled();
    // The refusal names the drifted category and tells the user what to type —
    // via the presenter's hint, never a host command owned by the shared core.
    const refusal = err.join('');
    expect(refusal).toContain('(secret)');
    expect(refusal).toContain('re-run <<RERUN-HINT>> to review against the current store');
    expectHostFree(err);
  });
});

describe('runApply — the store-unavailable note rides the presenter seam', () => {
  it('leads the gate with the presenter note when the store cannot be opened, still exit 0', async () => {
    const { code, out } = await drive({
      openDb: () => {
        throw new Error('SQLITE_CANTOPEN: unable to open database file');
      },
    });
    expect(code).toBe(0);
    const [gate] = out;
    if (gate === undefined) throw new Error('no gate emitted');
    // The note is the presenter's, and it opens the consolidated gate region.
    expect(gate.startsWith('<<SHOW:<<FENCED:<<STORE-UNAVAILABLE>>')).toBe(true);
    // The rest of the gate still renders — degrading the store read never
    // replaces the calibration card.
    expect(gate).toContain('<<CALIBRATION-COPY>>');
    expectSentinelOnly(out, { planStatus: true });
    expectHostFree(out);
  });
});

/**
 * scripts/start-light.js — the 0.3b start-light frame emitter of the /aka:setup
 * Not-now branch. Runs the BUILT script the wizard actually shells out to and
 * asserts it prints the default-posture start-light card, fenced, doing no I/O beyond
 * writing to stdout (mirrors how the intro/firstrun scripts emit their cards).
 */
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { fenced } from '../src/present.ts';
import {
  RE_TUNE_HINT,
  renderAdjustConfirm,
  renderPostureGrid,
  renderStartLight,
} from '../src/render.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test -> plugins/claude-code
const SCRIPT = join(HERE, '..', 'scripts', 'start-light.js');

interface Run {
  stdout: string;
  stderr: string;
  status: number;
}

function runStartLight(args: string[] = []): Run {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

describe('scripts/start-light.js', () => {
  const result = runStartLight();

  it('prints the default-posture start-light card fenced, with no I/O beyond stdout', () => {
    // Clean exit and empty stderr: the script reads no store and takes no consent,
    // so nothing but the card reaches stdout.
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    // The whole card wrapped in the shared code fence, rendered from the severity floor.
    expect(result.stdout.trim()).toBe(fenced(renderStartLight(severityFloorPosture())));
  });

  it('the fenced card carries the heading, the 8×4 default posture grid, and the re-tune hint', () => {
    expect(result.stdout).toContain('Start light — set your packs');
    expect(result.stdout).toContain(renderPostureGrid(severityFloorPosture()));
    expect(result.stdout).toContain(RE_TUNE_HINT);
  });
});

describe('scripts/start-light.js --adjust-confirm', () => {
  const recommended = severityFloorPosture();
  // The user's adjusted posture: the recommended base with two packs overridden.
  const chosen: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
    ...recommended,
    secret: 'redact',
    config: 'warn',
  };
  const result = runStartLight(['--adjust-confirm', '--posture', JSON.stringify(chosen)]);

  it('prints the 0.4b adjust-confirm card fenced, with no I/O beyond stdout', () => {
    // Clean exit, empty stderr: the emitter reads no store and takes no consent,
    // so nothing but the confirm card reaches stdout.
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    // The whole card wrapped in the shared fence, rendered from the recommended
    // posture against the adjusted --posture map it was handed.
    expect(result.stdout.trim()).toBe(fenced(renderAdjustConfirm(recommended, chosen)));
  });

  it("carries the 'category │ recommended │ yours' columns, the changed pack, and the re-tune hint", () => {
    expect(result.stdout).toContain('CATEGORY');
    expect(result.stdout).toContain('RECOMMENDED');
    expect(result.stdout).toContain('YOURS');
    // The overridden pack shows a different 'yours' value than recommended.
    expect(result.stdout).toMatch(/secret\s+warn\s+redact/);
    expect(result.stdout).toContain("I'll keep the rest as recommended");
    expect(result.stdout).toContain(RE_TUNE_HINT);
  });

  it('fails loudly when --adjust-confirm is given without a --posture map', () => {
    const missing = runStartLight(['--adjust-confirm']);
    expect(missing.status).not.toBe(0);
  });

  it('keys the recommended column on --recommended, not the severity floor', () => {
    // A calibration that escalated the 'secret' pack above the floor: the
    // recommended base carries the calibrated level.
    const calibrated: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
      ...recommended,
      secret: 'block',
    };
    // The user leaves 'secret' untouched but changes 'config'.
    const merged: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
      ...calibrated,
      config: 'warn',
    };
    const withRec = runStartLight([
      '--adjust-confirm',
      '--recommended',
      JSON.stringify(calibrated),
      '--posture',
      JSON.stringify(merged),
    ]);
    expect(withRec.status).toBe(0);
    expect(withRec.stdout.trim()).toBe(fenced(renderAdjustConfirm(calibrated, merged)));
    // The untouched escalated pack repeats its calibrated level in both columns —
    // it does not render as a spurious change against the floor.
    expect(withRec.stdout).toMatch(/secret\s+block\s+block/);
  });
});

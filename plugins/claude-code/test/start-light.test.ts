/**
 * scripts/start-light.js — the 0.3b start-light frame emitter of the /aka:setup
 * Not-now branch. Runs the BUILT script the wizard actually shells out to and
 * asserts it prints the default-posture start-light card, fenced, doing no I/O beyond
 * writing to stdout (mirrors how the intro/firstrun scripts emit their cards).
 *
 * --adjust-confirm also does a best-effort read of the policies store for the
 * downgrade comparison (see src/start-light.ts, test/start-light-adjust-downgrade.test.ts
 * for that guard's own coverage). Every invocation here runs against a throwaway,
 * always-empty ~/.aka home so this suite's assertions stay independent of
 * whatever the real machine's store happens to hold.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
  // A fresh, empty home per call: no ~/.aka store exists, so --adjust-confirm's
  // store read (readExistingPosture) always takes its no-store branch and every
  // assertion below stays independent of the real machine's store.
  const home = mkdtempSync(join(tmpdir(), 'aka-start-light-test-'));
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
      env: { HOME: home, USERPROFILE: home },
      encoding: 'utf8',
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  } finally {
    rmSync(home, { recursive: true, force: true });
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
    expect(result.stdout).toContain('Starting light — your detection categories');
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
    // A malformed invocation prints the clean one-line reason, not a raw stack.
    expect(missing.stdout).toContain('AKA setup failed:');
    expect(missing.stderr).toBe('');
  });

  it('fails cleanly on malformed --posture JSON, with no raw stack trace', () => {
    const badJson = runStartLight(['--adjust-confirm', '--posture', '{not valid json']);
    expect(badJson.status).not.toBe(0);
    // The parse error is caught and reported as the clean setup-failure line; a
    // raw uncaught throw would spill a stack to stderr instead.
    expect(badJson.stdout).toContain('AKA setup failed:');
    expect(badJson.stdout).not.toMatch(/\n\s+at\s/);
    expect(badJson.stderr).toBe('');
  });

  // Bad input reaches the user as a plain line, never a stack trace — the same
  // failure form onboard.js prints.
  it.each([
    ['a missing --posture map', ['--adjust-confirm']],
    ['malformed --posture JSON', ['--adjust-confirm', '--posture', '{not json']],
    ['an unknown category', ['--adjust-confirm', '--posture', '{"nope":"warn"}']],
    [
      'malformed --current JSON',
      ['--adjust-confirm', '--posture', '{"secret":"warn"}', '--current', '{oops'],
    ],
  ])('reports %s as a friendly failure line and a non-zero exit', (_label, args) => {
    const failed = runStartLight(args);
    expect(failed.status).not.toBe(0);
    expect(failed.stdout).toContain('AKA setup failed: ');
    // A stack trace would name the throwing frame; the friendly path prints none.
    expect(failed.stdout).not.toContain('    at ');
    expect(failed.stderr).toBe('');
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

  // The adjust fork can lower a pack the user hardened out of band, so the card
  // must carry the same downgrade WARNING the confirm gate prints.
  describe('--current downgrade guard', () => {
    // 'secret' hardened to block in the store before the wizard ran.
    const hardened = JSON.stringify({ secret: 'block' });

    it('warns when the chosen level lowers enforcement below the stored action', () => {
      // The user picks 'warn' for a pack the store holds at 'block'.
      const lowered: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
        ...recommended,
        secret: 'warn',
      };
      const run = runStartLight([
        '--adjust-confirm',
        '--posture',
        JSON.stringify(lowered),
        '--current',
        hardened,
      ]);
      expect(run.status).toBe(0);
      expect(run.stdout).toContain('Heads up — this would lower 1 detection level (secret) below');
      expect(run.stdout).toContain('Confirm you mean to lower it before I apply');
    });

    it('stays silent when the chosen level is the same or higher than the stored action', () => {
      // The user picks 'block' — matching what the store already holds.
      const kept: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
        ...recommended,
        secret: 'block',
      };
      const run = runStartLight([
        '--adjust-confirm',
        '--posture',
        JSON.stringify(kept),
        '--current',
        hardened,
      ]);
      expect(run.status).toBe(0);
      expect(run.stdout).not.toContain('WARNING');
      expect(run.stdout).not.toContain('LOWERED');
    });

    it('has no baseline to warn against when --current is omitted', () => {
      const lowered: Partial<Record<DetectionCategory, BuiltinPolicyId>> = {
        ...recommended,
        secret: 'warn',
      };
      const run = runStartLight(['--adjust-confirm', '--posture', JSON.stringify(lowered)]);
      expect(run.status).toBe(0);
      expect(run.stdout).not.toContain('WARNING');
    });
  });
});

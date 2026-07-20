import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { ONBOARDING_NUDGE } from '../../src/hooks/onboarding-nudge.ts';

const CANONICAL_NUDGE =
  'AKA Security is installed but not calibrated — run /aka:setup to tune notifications to this machine (about a minute).';
const STALE_INSTALL_NUDGE = 'choose your installation type';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/hooks -> plugins/claude-code
const PLUGIN_ROOT = join(HERE, '..', '..');
const HOOK_SOURCE = join(PLUGIN_ROOT, 'src', 'hooks', 'user-prompt-submit.ts');
// The built entry the suite's global setup compiles (test/journey/global-setup.ts).
// Driving it proves the emit SITE, not just the exported constant.
const HOOK_SCRIPT = join(PLUGIN_ROOT, 'scripts', 'user-prompt-submit.js');

interface HookRun {
  stdout: string;
  stderr: string;
  status: number;
}

// Drive the real built hook against a throwaway ~/.aka home, feeding a Claude
// Code UserPromptSubmit payload on stdin. process.execPath is an absolute node
// path, so the child needs no host PATH and inherits no ambient environment.
function runHook(home: string, payload: unknown): HookRun {
  try {
    const stdout = execFileSync(process.execPath, [HOOK_SCRIPT], {
      env: { HOME: home, USERPROFILE: home },
      input: JSON.stringify(payload),
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

describe('ONBOARDING_NUDGE', () => {
  it('is the canonical calibration-wizard copy', () => {
    expect(ONBOARDING_NUDGE).toBe(CANONICAL_NUDGE);
  });

  it('drops the stale installation-type framing', () => {
    expect(ONBOARDING_NUDGE).not.toContain(STALE_INSTALL_NUDGE);
  });
});

describe('user-prompt-submit hook source', () => {
  it('no longer references the stale installation-type string', () => {
    // The stale installation-type string no longer exists in the hook source.
    expect(readFileSync(HOOK_SOURCE, 'utf8')).not.toContain(STALE_INSTALL_NUDGE);
  });
});

describe('user-prompt-submit hook — driven end-to-end', () => {
  it('emits the calibration nudge (not the stale copy) on a clean prompt from an un-calibrated machine', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-ups-nudge-'));
    try {
      const run = runHook(home, {
        prompt: 'what does this function do?',
        session_id: 'sess-nudge',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
      });
      expect(run.status).toBe(0);
      expect(run.stderr).toBe('');
      const payload = JSON.parse(run.stdout) as { systemMessage?: string };
      // Proves the emit SITE carries the constant: a regression to any other copy
      // at the emit call fails here, which the constant-equality check cannot catch.
      expect(payload.systemMessage).toBe(ONBOARDING_NUDGE);
      expect(run.stdout).not.toContain(STALE_INSTALL_NUDGE);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('falls back to allow and never throws when a store fault is injected (fail-open)', () => {
    const home = mkdtempSync(join(tmpdir(), 'aka-ups-failopen-'));
    try {
      // Injected fault: an unreadable store (not the SQLite header) so enforcement
      // cannot complete before the nudge. The hook must still resolve to allow.
      const dataDir = join(home, '.aka', 'data');
      mkdirSync(dataDir, { recursive: true });
      writeFileSync(join(dataDir, 'aka.db'), 'not a database\n'.repeat(64));

      const run = runHook(home, {
        prompt: 'what does this function do?',
        session_id: 'sess-failopen',
        cwd: '/tmp',
        hook_event_name: 'UserPromptSubmit',
      });
      // Allow = exit 0, no exception escaped (empty stderr), and never a block.
      expect(run.status).toBe(0);
      expect(run.stderr).toBe('');
      expect(run.stdout).not.toContain('"decision":"block"');
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});

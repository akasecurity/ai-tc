/**
 * The host-floor notice through the BUILT hook, which is the only layer that
 * tests what ships. The unit suites drive the module directly; this drives
 * `scripts/stop.js` the way Claude Code does, so a notice that works in-process
 * and never reaches a real hook's stderr fails here.
 *
 * Both halves are required and neither is decoration. The PRESENCE row proves
 * the warning arrives; the paired ABSENCE row proves it is conditional. Without
 * the second, a notice printed unconditionally passes the first — and on this
 * path "exit 0, nothing on stderr" is also what a silently-missing protection
 * looks like, which is the defect the feature exists to report.
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

/** Older than every floor AKA declares. */
const ANCIENT = '2.0.0';
/** Newer than any floor, so the notice must stay silent. */
const CURRENT = '99.0.0';

function transcriptIn(home: string, version: string): string {
  const path = join(home, `transcript-${version}.jsonl`);
  writeFileSync(path, `${JSON.stringify({ type: 'user', version })}\n`, 'utf8');
  return path;
}

function stopPayload(home: string, version: string): string {
  return JSON.stringify({
    session_id: `s-${version}`,
    transcript_path: transcriptIn(home, version),
    cwd: home,
    hook_event_name: 'Stop',
    stop_hook_active: false,
  });
}

describe('the host-floor notice reaches a real hook’s stderr', () => {
  it('warns on a host older than a floor, without touching the stdout contract', () => {
    withTempHome((home) => {
      const result = runHook('stop', stopPayload(home, ANCIENT), { env: tempHomeEnv(home) });

      // Fail-open first: a warning must never cost the user their session, and
      // Stop's stdout contract stays empty whatever the hook has to say.
      expect(result.status).toBe(0);
      expect(result.stdout).toBe('');

      expect(result.stderr).toContain('[aka]');
      expect(result.stderr).toContain(ANCIENT);
      expect(result.stderr).toContain('Update Claude Code');
    });
  });

  it('says nothing on a current host — the control that makes the row above mean something', () => {
    withTempHome((home) => {
      const result = runHook('stop', stopPayload(home, CURRENT), { env: tempHomeEnv(home) });

      expect(result.status).toBe(0);
      expect(result.stdout).toBe('');
      // The whole bytes, not `not.toContain`: every `not.toContain` passes on
      // '', and '' is exactly what this hook writes on a clean run — so the
      // weaker form would stay green against a hook that says nothing at all,
      // which is the state this feature exists to distinguish.
      expect(result.stderr).toBe('');
    });
  });

  it('says nothing when the transcript names no version', () => {
    withTempHome((home) => {
      const path = join(home, 'bookkeeping.jsonl');
      writeFileSync(path, `${JSON.stringify({ type: 'queue-operation' })}\n`, 'utf8');
      const result = runHook(
        'stop',
        JSON.stringify({
          session_id: 's-unknown',
          transcript_path: path,
          cwd: home,
          hook_event_name: 'Stop',
        }),
        { env: tempHomeEnv(home) },
      );

      expect(result.status).toBe(0);
      expect(result.stderr).toBe('');
    });
  });
});

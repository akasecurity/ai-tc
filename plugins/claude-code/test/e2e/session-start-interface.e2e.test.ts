// SessionStart records WHICH SURFACE of Claude Code is running — the terminal,
// the VS Code panel, the desktop app — from the value the host stamps on its
// own subprocess environment. Drives the REAL built script, because the read is
// of `process.env` inside that process and nothing an in-process test does can
// stand in for it.
//
// Why not the transcript, which also carries an `entrypoint`: that field sits on
// the first user/assistant record (measured as record 3 or 4 across sixty
// transcripts on a reference machine), so a session that has just STARTED has no
// record carrying it — which is every `source: startup` session at the moment
// this hook runs. The transcript stays the backfill's source, where the records
// do exist by the time it reads them.
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { describe, expect, it } from 'vitest';

import { runHook, tempHomeEnv, withTempHome } from '../helpers/run-hook.ts';

const SESSION_ID = 'session-start-interface-e2e';

function payload(home: string): string {
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  return JSON.stringify({
    session_id: SESSION_ID,
    cwd,
    hook_event_name: 'SessionStart',
    source: 'startup',
  });
}

/**
 * The session root's attribute bag, read back out of the store the hook wrote.
 *
 * Read with `node:sqlite` directly (the pattern the history suites already use)
 * because nothing in `@akasecurity/persistence` surfaces `harness_interface`
 * yet: it is written by the capture path and rendered by no read surface. That
 * gap is not this file's to close, but it does mean the value has to be
 * asserted where it lands rather than through an API.
 */
function sessionRootAttributes(home: string): Record<string, unknown> {
  const db = new DatabaseSync(join(home, '.aka', 'data', 'aka.db'), { readOnly: true });
  try {
    const row = db
      .prepare("SELECT attributes FROM audit_events WHERE id = ? AND event_type = 'session'")
      .get(SESSION_ID) as { attributes: string } | undefined;
    expect(row, 'the hook wrote no session root').toBeDefined();
    return JSON.parse(row?.attributes ?? '{}') as Record<string, unknown>;
  } finally {
    db.close();
  }
}

describe('session-start records the harness interface the host stamps', () => {
  it('records the VS Code panel as its own interface', () => {
    withTempHome((home) => {
      const result = runHook('session-start', payload(home), {
        env: { ...tempHomeEnv(home), CLAUDE_CODE_ENTRYPOINT: 'claude-vscode' },
      });
      expect(result.status).toBe(0);

      const attributes = sessionRootAttributes(home);
      expect(attributes.harness_interface).toBe('claude-vscode');
      // Opaque, and NOT folded into the harness id: the surface is recorded
      // beside the tool, never in place of it.
      expect(attributes.harness).toBe('claudecode');
    });
  });

  it('carries the value through verbatim, whatever the host says', () => {
    // The set of spellings is the host's, not this plugin's — `sdk-ts`,
    // `claude-desktop`, `remote*` and others exist — so nothing here may
    // validate against a list this plugin would have to keep in step.
    withTempHome((home) => {
      runHook('session-start', payload(home), {
        env: { ...tempHomeEnv(home), CLAUDE_CODE_ENTRYPOINT: 'sdk-ts' },
      });
      expect(sessionRootAttributes(home).harness_interface).toBe('sdk-ts');
    });
  });

  it('omits the fact when the host stamps nothing, rather than guessing a terminal', () => {
    // Empty rather than deleted: `runHook` layers its env over the host's, and
    // this process is itself a Claude Code session carrying the variable — so a
    // test that merely left it unset would inherit whatever ran the suite. The
    // hook treats empty and absent alike, which is what makes that substitution
    // sound; a reader who needs the truly-unset case has the same code path.
    withTempHome((home) => {
      const result = runHook('session-start', payload(home), {
        env: { ...tempHomeEnv(home), CLAUDE_CODE_ENTRYPOINT: '' },
      });
      expect(result.status).toBe(0);

      const attributes = sessionRootAttributes(home);
      expect(attributes).not.toHaveProperty('harness_interface');
      // The positive control: the root was written and IS populated, so the
      // absence above is a missing key rather than a missing row.
      expect(attributes.harness).toBe('claudecode');
    });
  });
});

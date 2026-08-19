import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isBareCommandUnsupported, planBareCommand } from '@akasecurity/plugin-sdk/bare-command';
import type { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { runJudge } from '../../src/triage/judge.ts';
import { judgeArgvUnsupported } from './judge-argv-unsupported.ts';

// `judgeArgvUnsupported` is a gate, and a gate is the one shape a green run
// cannot vouch for. Its consumer spends it through `describe.skipIf`, so setting
// it to `true` deletes the whole wizard-journey suite on EVERY platform and
// vitest reports each removed case as a success. Nothing asserts a floor on the
// executed count, so the run stays green and the diff is the only thing standing
// in the way.
//
// That is the same argument CLAUDE.md makes for `no-echo.ts`: a helper whose
// weakening is invisible from its callers carries its own suite.
//
// What this can and cannot catch is worth stating, because the value is
// platform-dependent and so is the coverage:
//
//   `= true`                       caught on every non-win32 leg
//   `= false`                      caught on the win32 leg
//   `=== 'linux'` / other platform caught wherever the two disagree
//
// No single leg catches all three, which is why it matters on a workspace that
// runs ubuntu, macOS and Windows rather than one that runs only Linux.
describe('judgeArgvUnsupported', () => {
  it('is exactly the win32 predicate, not a hardcoded constant', () => {
    expect(judgeArgvUnsupported).toBe(process.platform === 'win32');
  });

  it('is a boolean, so `skipIf` reads it as a gate rather than as truthiness', () => {
    // `skipIf` takes any value and coerces it. A non-empty string would gate the
    // suite on every platform and satisfy the case above under `==`.
    expect(typeof judgeArgvUnsupported).toBe('boolean');
  });

  it('leaves the journey RUNNING on a host that can spawn the stub', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('win32 is the platform the gate exists to exclude');
      return;
    }

    // The property the consumer actually depends on, stated as the consumer sees
    // it: off win32 the gate must be open. Asserting the flag's value alone
    // leaves this implicit, and it is the half whose failure is silent.
    expect(judgeArgvUnsupported).toBe(false);
  });

  // Nothing about a skip expires on its own: give this host a stdin or
  // prompt-file input, move the prompt off argv, and the suite would stay
  // skipped on Windows for ever — green and silent, because a skip that is no
  // longer needed looks exactly like one that is.
  //
  // So pin the JUSTIFICATION, behaviourally, against the REAL planner and the
  // REAL argv `runJudge` builds. A restatement of the rule in prose would go on
  // passing after the rule stopped applying; this cannot.
  it('still describes a real refusal — when this fails, the win32 skip is stale', () => {
    const hit: TriageHit = {
      ruleId: 'core-secret/aws',
      category: 'secret',
      severity: 'high',
      maskedMatch: 'A***Z',
      rawMatch: 'AKIAIOSFODNN7EXAMPLE',
      context: 'export KEY=AKIAIOSFODNN7EXAMPLE # prod',
      confidence: 0.9,
    };
    const verdict = [
      '```json',
      '{"perCategory":[{"category":"secret","action":"warn","reasoning":"r","genuineCount":1,"fpCount":0,"fpIds":[]}],"notes":""}',
      '```',
    ].join('\n');
    // Pointed at a throwaway home: runJudge removes the conversation its own run
    // created, and an unset `home` resolves to the REAL ~/.gemini brain store.
    const home = mkdtempSync(join(tmpdir(), 'aka-judge-gate-home-'));
    let argv: readonly string[] = [];
    try {
      runJudge([hit], {
        spawn: (seen) => {
          argv = seen;
          return JSON.stringify({ conversation_id: 'conv-gate', response: verdict });
        },
        // A short rubric on purpose: the refusal under test must come from the
        // PROMPT's own shape, not from a 6 KiB asset overrunning the ceiling.
        loadRubric: () => 'RUBRIC',
        home,
      });
    } finally {
      rmSync(home, { recursive: true, force: true });
    }

    // The positive control: the prompt is still an argv element at all. Move it
    // to stdin and this goes red before the refusal check below does.
    expect(argv).toContain('-p');
    expect(argv[argv.indexOf('-p') + 1]).toContain('AKIAIOSFODNN7EXAMPLE');

    const refusal = errorFrom(() =>
      planBareCommand('agy', argv, {
        platform: 'win32',
        home: '/anchor/home',
        resolve: () => String.raw`C:\Users\dev\AppData\Roaming\npm\agy.cmd`,
      }),
    );

    expect(
      isBareCommandUnsupported(refusal),
      'the judge argv now crosses cmd.exe intact, so the Antigravity wizard-journey ' +
        'suite is no longer blocked on Windows. Re-run it on the Windows leg; if it ' +
        'passes, delete judge-argv-unsupported.ts, the `describeJudgeArgv` gate built ' +
        'from it, and this file.',
    ).toBe(true);
  });
});

// The error a thunk threw, captured OUTSIDE its own catch — a `try { fn();
// throw new Error('expected') } catch` asserts on the test's own guard error
// whenever the subject stops throwing.
function errorFrom(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return undefined;
}

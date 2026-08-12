import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { shimUnsupported } from './shim-unsupported.ts';

const JUDGE = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'src',
  'triage',
  'judge.ts',
);

// `shimUnsupported` is a gate, and a gate is the one shape a green run cannot
// vouch for. Every consumer spends it through `describe.skipIf`/`it.skipIf`, so
// setting it to `true` deletes the whole wizard-journey tier on EVERY platform,
// and vitest reports each removed case as a success. Nothing asserts a floor on
// the executed count, so the run stays green and the diff is the only thing
// standing in the way.
//
// That is the same argument CLAUDE.md makes for `no-echo.ts`: a helper whose
// weakening is invisible from its callers carries its own suite, and a copy
// takes that suite with it. This file is that suite for this copy.
//
// What it can and cannot catch is worth stating, because the value is
// platform-dependent and so is the coverage:
//
//   `= true`                        caught on every non-win32 leg
//   `= false`                       caught on the win32 leg
//   `=== 'linux'` / other platform   caught wherever the two disagree
//
// No single leg catches all three, which is why this matters on a workspace
// that runs ubuntu, macOS and Windows rather than one that runs only Linux.
describe('shimUnsupported', () => {
  it('is exactly the win32 predicate, not a hardcoded constant', () => {
    expect(shimUnsupported).toBe(process.platform === 'win32');
  });

  it('is a boolean, so `skipIf` reads it as a gate rather than as truthiness', () => {
    // `skipIf` takes any value and coerces it. A non-empty string would gate
    // every suite on every platform and satisfy the case above under `==`.
    expect(typeof shimUnsupported).toBe('boolean');
  });

  it('leaves the shimmed suites RUNNING on a host that can spawn a shim', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('win32 is the platform the gate exists to exclude');
      return;
    }

    // The property the consumers actually depend on, stated as the consumers see
    // it: off win32 the gate must be open. Asserting the flag's value alone
    // leaves this implicit, and it is the half whose failure is silent.
    expect(shimUnsupported).toBe(false);
  });

  // This gate is only honest while the thing it models is still broken, and
  // nothing about a skip expires on its own: fix the spawn and these suites stay
  // skipped on Windows for ever, green and silent, because a skip that is no
  // longer needed looks exactly like one that is.
  //
  // So pin the JUSTIFICATION rather than the symptom. The suites are skipped
  // because `spawnClaude` reaches its CLI through a shell-free `execFileSync`,
  // and Node has refused to spawn a `.cmd` without a shell since the
  // CVE-2024-27980 fix — so `assertShimResolves` is right to refuse, and a probe
  // that disagreed with its subject would let the chain reach the developer's
  // real installed CLI with seeded fixtures on stdin.
  //
  // The moment someone gives that spawn a `shell` option, this case goes red and
  // names what to do next. Deliberately a source assertion rather than a win32
  // behavioural one: the fix has to be noticed on the leg the fixer is actually
  // running, which is not usually Windows.
  it('still models a shell-free spawn — when this fails, the win32 skips are stale', () => {
    const judge = readFileSync(JUDGE, 'utf8');

    expect(
      /\bshell\s*:/.test(judge),
      'judge.ts now passes a `shell` option, so a `.cmd` is reachable and the ' +
        'CVE-2024-27980 refusal no longer applies. Re-run the wizard journey ' +
        'suites on Windows; if they pass, delete shim-unsupported.ts and every ' +
        '`describeShimmed`/`itShimmed` gate built from it, and this case with them.',
    ).toBe(false);
  });
});

import { expect, test } from 'claude-code/testing';

import cases from './cases.generated.js';
import * as engine from './engine.js';

// Runs inside the real mod runtime (no Node). The expected values were
// produced by the Node engine in prepare.mjs; any difference in rule ids,
// spans or redacted text fails.
test('the built engine agrees with the Node engine on every rule fixture', () => {
  const t0 = performance.now();
  engine.registerBundledPacks();
  const registerMs = performance.now() - t0;
  console.log(`registered ${engine.getLoadedRules().length} rules in ${registerMs.toFixed(1)} ms`);

  const diffs: string[] = [];
  for (const c of cases) {
    const findings = engine.scan(c.text, undefined, c.context);
    const got = findings
      .map((f) => ({ ruleId: f.ruleId, span: f.span }))
      .sort(
        (a, b) =>
          a.span.start - b.span.start || a.span.end - b.span.end || (a.ruleId < b.ruleId ? -1 : 1),
      );
    const want = [...c.findings].sort(
      (a, b) =>
        a.span.start - b.span.start || a.span.end - b.span.end || (a.ruleId < b.ruleId ? -1 : 1),
    );
    if (
      JSON.stringify(got) !== JSON.stringify(want) ||
      engine.redact(c.text, findings) !== c.redacted
    ) {
      diffs.push(c.id);
    }
  }
  expect(cases.length).toBeGreaterThan(700);
  expect(diffs).toEqual([]);
});

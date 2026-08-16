import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Rule as RuleSchema, RuleFixture as RuleFixtureSchema } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { discoverBundledRuleFiles, fixturePath, onDiskRuleCount } from './helpers/rules.ts';

// The strict-schema gate for the shipped rule tree, deliberately in its OWN
// file rather than beside the fixture suite in `engine.test.ts`.
//
// That suite parses every rule at MODULE scope (`loadRule` throws), so a rule
// with a bad key takes the whole file down before any test runs: vitest reports
// "no tests" and a stack trace pointing at the walk, naming neither the rule nor
// the key. This file parses nothing at module scope, so it still runs when the
// tree is broken — which is the only condition under which it has anything to
// say. Both halves use safeParse for the same reason: the failure has to name
// every offender at once instead of aborting at the first.
//
// A rule that fails here has a latent typo. Before the schema was strict, that
// key was stripped and the rule shipped with whatever it configured absent.

// Walked once for the file rather than once per test — safe here precisely
// because this module parses nothing at load, which is why it is its own file.
// `onDiskRuleCount` counts straight off disk so the manifest walk cannot vouch
// for itself; `engine.test.ts` separately pins that the two agree.
const RULE_FILES = discoverBundledRuleFiles();
const ON_DISK_RULE_COUNT = onDiskRuleCount();

// `path` is Zod's `PropertyKey[]`, so a segment may be a symbol — and
// `Array.prototype.join` stringifies its elements, which THROWS on one. Mapping
// through String() first keeps the formatter total, so a malformed rule still
// gets named instead of being replaced by a TypeError from the reporting code.
function describeIssues(issues: { path: PropertyKey[]; message: string }[]): string {
  return issues.map((i) => `${i.path.map(String).join('.') || '<root>'}: ${i.message}`).join('; ');
}

describe('bundled rule tree parses under the strict schema', () => {
  it('parses every bundled rule', () => {
    const failures: string[] = [];
    for (const { packDir, packDirAbs, ruleFile } of RULE_FILES) {
      const raw: unknown = JSON.parse(
        readFileSync(resolve(packDirAbs, `${ruleFile}.json`), 'utf-8'),
      );
      const parsed = RuleSchema.safeParse(raw);
      if (!parsed.success) {
        failures.push(`rules/${packDir}/${ruleFile}.json — ${describeIssues(parsed.error.issues)}`);
      }
    }
    expect(failures).toEqual([]);
    // Non-vacuous: an empty or truncated walk satisfies the line above exactly
    // as well as a clean tree does, and would report success having checked
    // nothing.
    expect(RULE_FILES.length).toBe(ON_DISK_RULE_COUNT);
    expect(RULE_FILES.length).toBeGreaterThan(0);
  });

  it('parses every bundled fixture', () => {
    // `expectedSpans` is a guard like any other — the singular spelling used to
    // vanish, taking the span assertion with it — so fixtures get the same
    // treatment as the rules they pin.
    const failures: string[] = [];
    let fixtureCount = 0;
    for (const { packDir, packDirAbs, ruleFile } of RULE_FILES) {
      const path = fixturePath(packDirAbs, ruleFile);
      // A bare readFileSync would surface a missing fixture as an ENOENT naming
      // an absolute path; `engine.test.ts` states the rule, so state it here too
      // rather than degrading the message in the file that runs when the tree is
      // broken.
      if (!existsSync(path)) {
        failures.push(
          `rules/${packDir}/fixtures/${ruleFile}.json — missing. Every rule must have a fixture file per skills/write-detection-rule/SKILL.md.`,
        );
        continue;
      }
      const raw = JSON.parse(readFileSync(path, 'utf-8')) as unknown[];
      for (const [index, entry] of raw.entries()) {
        fixtureCount += 1;
        const parsed = RuleFixtureSchema.safeParse(entry);
        if (!parsed.success) {
          failures.push(
            `rules/${packDir}/fixtures/${ruleFile}.json[${String(index)}] — ${describeIssues(parsed.error.issues)}`,
          );
        }
      }
    }
    expect(failures).toEqual([]);
    // Every rule carries fixtures, so the count must exceed the rule count —
    // which also catches a walk that quietly found nothing.
    expect(fixtureCount).toBeGreaterThan(ON_DISK_RULE_COUNT);
  });
});

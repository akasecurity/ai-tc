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

// A fixture label opening with one of these marks a DOCUMENTED RESIDUAL: a case
// the rule is known to get wrong, carried as a fixture so the behaviour is on
// the record instead of being rediscovered. Matched case-insensitively — the
// capitalization is the label author's, and a contract that a different
// spelling walks out of is not one.
const RESIDUAL_PREFIXES = ['known false positive:', 'known gap:'] as const;

/**
 * Every documented residual the shipped tree carries, keyed `<pack>/<rule>`.
 *
 * Exact label sets, not per-rule counts: a count cannot tell a deleted residual
 * from one swapped for another, and both change what the tree claims about
 * itself. A rule absent from this table must carry none, so a new residual gets
 * declared here or the walk names it.
 *
 * This is not the fixture bar in `test/helpers/fixture-bar.ts` and does not
 * duplicate it. That bar is a minimum each rule must clear and says nothing
 * about WHICH cases clear it, so deleting a residual leaves it satisfied while
 * the documented behaviour quietly stops being pinned.
 */
const DOCUMENTED_RESIDUALS: Record<string, readonly string[]> = {
  'code-flaws/sql-inject-concat': [
    'known false positive: a literal opening "where <word> between" satisfies the WHERE..BETWEEN arm',
    'known false positive: a literal opening "where <word> in (" satisfies the WHERE..IN arm',
    'known false positive: a literal opening "where <word> LIKE \'" satisfies the WHERE..LIKE arm',
  ],
  'code-flaws/sql-inject-format': [
    'known false positive: prose "where <word> < {n}" satisfies the WHERE..compare arm',
    'known false positive: prose "where <word> <> {n}" satisfies the WHERE..compare arm',
    'known false positive: prose "where <word> > {n}" satisfies the WHERE..compare arm',
    'known false positive: prose "where <word> between" satisfies the WHERE..BETWEEN arm',
    'known false positive: prose "where <word> in (" satisfies the WHERE..IN arm',
    'known false positive: prose "where <word> LIKE \'<quoted>\'" satisfies the WHERE..LIKE arm',
    'known false positive: the same prose compare shape in the % spelling',
    'known false positive: the same prose shape in the % spelling',
    'known gap: a prose line after the first that starts with a sql phrase and carries ${} still matches',
    'known gap: heredoc statement split across lines with a #{} placeholder is not matched by this rule (sql-inject-interp covers it)',
    'known gap: heredoc statement split across lines with a %s placeholder is not matched',
    'known gap: interpolation-first statement is not matched',
    'known gap: unquoted parenthesized statement is not matched',
    'known gap: UPDATE of two tables is not matched (same cap)',
    'known gap: UPDATE ONLY is not matched (the widened UPDATE arm does not fit the pattern-length cap)',
    'known gap: UPDATE with an AS alias is not matched (same cap)',
  ],
  'code-flaws/sql-inject-interp': [
    'known gap: @variable as the WHERE operand is not matched',
    'known gap: DELETE with STRAIGHT_JOIN is not matched',
    'known gap: DELETE with an interpolated target before FROM is not matched',
    'known gap: FROM more than three lines after SELECT is not matched',
    'known gap: INSERT without INTO is not matched',
    'known gap: MySQL multi-table UPDATE with JOIN ... ON before SET is not matched',
    'known gap: SELECT with no FROM is not matched',
    'known gap: UPDATE with INNER JOIN before SET is not matched',
    'known gap: UPDATE with LEFT JOIN before SET is not matched',
    'known gap: a SELECT column list longer than 1000 characters before FROM is not matched',
    'known gap: a literal backslash-n between the table and SET is not matched',
    'known gap: comma-joined multi-table DELETE is not matched',
    'known gap: interpolation on a later line than SELECT in a heredoc is not matched',
    'known gap: interpolation-first statement is not matched',
    'known gap: jq select on a field named from, directly after the quote, still matches',
    'known gap: named placeholder as the WHERE operand is not matched',
    'known gap: positional placeholder as the WHERE operand is not matched',
    'known gap: prose statement shaped like DELETE FROM with interpolation still matches',
    'known gap: prose statement shaped like SELECT ... FROM with interpolation still matches',
    'known gap: tuple SET is not matched',
    'known gap: two bare PHP variables after WHERE are not matched',
    'known gap: unquoted parenthesized statement is not matched',
  ],
  'code-flaws/sql-inject-interp-multiline': [
    'known gap: @variable as the WHERE operand is not matched (line-start form)',
    'known gap: DELETE with STRAIGHT_JOIN is not matched (line-start form)',
    'known gap: DELETE with an interpolated target before FROM is not matched (line-start form)',
    'known gap: FROM more than three lines after SELECT is not matched',
    'known gap: INSERT without INTO is not matched (line-start form)',
    'known gap: MySQL multi-table UPDATE with JOIN ... ON before SET is not matched (line-start form)',
    'known gap: SELECT with no FROM is not matched (line-start form)',
    'known gap: UPDATE with INNER JOIN before SET is not matched (line-start form)',
    'known gap: UPDATE with LEFT JOIN before SET is not matched (line-start form)',
    'known gap: a literal backslash-n between the table and SET is not matched (line-start form)',
    'known gap: a prose line after the first that starts with a sql word and carries interpolation still matches',
    'known gap: comma-joined multi-table DELETE is not matched (line-start form)',
    'known gap: interpolation on a later line than SELECT in a heredoc is not matched',
    'known gap: named placeholder as the WHERE operand is not matched (line-start form)',
    'known gap: positional placeholder as the WHERE operand is not matched (line-start form)',
    'known gap: tuple SET is not matched (line-start form)',
    'known gap: two bare PHP variables after WHERE are not matched (line-start form)',
  ],
  'secrets-infra/env-key-value': [
    'KNOWN GAP: bare code identifier on the right still matches; the pattern cannot tell it from a short literal',
    'KNOWN GAP: dot-separated id/secret pair (Twilio-style) — same, stays undetected by design',
    'KNOWN GAP: dotted sk.live key — same property-chain indistinguishability, stays undetected by design',
    'KNOWN GAP: pure dotted literal — the pattern cannot tell it from a property chain, so it stays undetected by design',
  ],
  'secrets/vault-token': [
    'known gap: a 24-character member access with a digit and a capital still matches',
  ],
};

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
  it('pins every documented residual', () => {
    const failures: string[] = [];
    let residualCount = 0;
    for (const { packDir, packDirAbs, ruleFile } of RULE_FILES) {
      const path = fixturePath(packDirAbs, ruleFile);
      // A missing fixture file is the previous test's finding, not this one's.
      if (!existsSync(path)) continue;
      const raw = JSON.parse(readFileSync(path, 'utf-8')) as { label?: unknown }[];
      const found = raw
        .map((entry) => (typeof entry.label === 'string' ? entry.label : ''))
        .filter((label) =>
          RESIDUAL_PREFIXES.some((prefix) => label.toLowerCase().startsWith(prefix)),
        )
        .sort();
      residualCount += found.length;
      // Both sides sorted by the same comparator here, so the table above may
      // be written in any order.
      const declared = [...(DOCUMENTED_RESIDUALS[`${packDir}/${ruleFile}`] ?? [])].sort();
      if (found.length !== declared.length || found.some((label, i) => label !== declared[i])) {
        failures.push(
          `rules/${packDir}/fixtures/${ruleFile}.json — documented residuals differ from the ` +
            `DOCUMENTED_RESIDUALS inventory in this file.\n` +
            `  on disk:  ${JSON.stringify(found)}\n` +
            `  declared: ${JSON.stringify(declared)}`,
        );
      }
    }
    expect(failures).toEqual([]);
    // Non-vacuous: an empty walk, or a table nobody filled in, satisfies the
    // line above exactly as well as an inventory that matches.
    expect(residualCount).toBe(
      Object.values(DOCUMENTED_RESIDUALS).reduce((n, labels) => n + labels.length, 0),
    );
    expect(residualCount).toBeGreaterThan(0);
  });
});

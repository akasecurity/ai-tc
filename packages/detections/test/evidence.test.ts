import { readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { bundledCodeEvidenceIds, ruleEvidence } from '../src/evidence.ts';

const RULES_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../../rules');

// The bundled code-flaw rules whose match contains a real secret value. Each is
// a decision, not an oversight: their excerpts must redact the match.
const VALUE_CODE_FLAWS = new Set([
  'code-flaws/hardcoded-password',
  'code-flaws/hardcoded-secret-key',
  'code-flaws/dev-placeholder-secret',
]);

interface Manifest {
  id: string;
  rules: string[];
}

function manifest(pack: string): Manifest {
  return JSON.parse(readFileSync(resolve(RULES_DIR, pack, 'manifest.json'), 'utf-8')) as Manifest;
}

describe('the bundled code-evidence map', () => {
  const codeFlaws = manifest('code-flaws').rules.map((name) => `code-flaws/${name}`);
  const mapped = new Set(bundledCodeEvidenceIds());

  it('classifies every code-flaws rule, as code or as one of the named value rules', () => {
    // Control: the pack is really there to compare against.
    expect(codeFlaws.length).toBeGreaterThan(20);
    const unclassified = codeFlaws.filter((id) => !mapped.has(id) && !VALUE_CODE_FLAWS.has(id));
    expect(unclassified).toEqual([]);
  });

  it('never classifies a rule whose match carries a secret value as code', () => {
    for (const id of VALUE_CODE_FLAWS) {
      expect(codeFlaws).toContain(id);
      expect(mapped.has(id)).toBe(false);
    }
  });

  it('names only rules the bundled packs ship', () => {
    const shipped = new Set(
      readdirSync(RULES_DIR, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .flatMap((entry) => manifest(entry.name).rules.map((name) => `${entry.name}/${name}`)),
    );
    expect([...mapped].filter((id) => !shipped.has(id))).toEqual([]);
  });
});

describe('ruleEvidence', () => {
  it("prefers the rule's own field", () => {
    expect(ruleEvidence({ id: 'code-flaws/xss-inner-html', evidence: 'value' })).toBe('value');
    expect(ruleEvidence({ id: 'custom/pattern', evidence: 'code' })).toBe('code');
  });

  it('never treats a rule in a value category as code, whatever it declares', () => {
    for (const category of ['secret', 'pii', 'financial', 'phi'] as const) {
      expect(ruleEvidence({ id: 'pulled/token', category, evidence: 'code' })).toBe('value');
    }
    // Control: the same declaration on a code-flaw rule is honoured.
    expect(ruleEvidence({ id: 'pulled/token', category: 'code_flaw', evidence: 'code' })).toBe(
      'code',
    );
  });

  it('falls back to the bundled map, and to value for anything unmapped', () => {
    expect(ruleEvidence({ id: 'code-flaws/xss-inner-html' })).toBe('code');
    expect(ruleEvidence({ id: 'code-flaws/hardcoded-password' })).toBe('value');
    expect(ruleEvidence({ id: 'secrets/aws-access-key' })).toBe('value');
  });
});

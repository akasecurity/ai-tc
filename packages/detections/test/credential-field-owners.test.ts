import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../src/engine.ts';
import { bundledPackDirs, RULES_DIR } from './helpers/rules.ts';

// The whole bundled ruleset, as the hooks run it.
const ruleset: Rule[] = bundledPackDirs().flatMap((packDir) => {
  const dir = resolve(RULES_DIR, packDir);
  if (!readdirSync(dir).includes('manifest.json')) return [];
  const manifest = JSON.parse(readFileSync(resolve(dir, 'manifest.json'), 'utf-8')) as {
    rules: string[];
  };
  return manifest.rules.map((name) =>
    Rule.parse(JSON.parse(readFileSync(resolve(dir, `${name}.json`), 'utf-8'))),
  );
});

const VALUE = 'a3f9c27d81b4e605d9f2a7c13e8b4056f1d7a29c8e3b60f4d5a1c97e2b8f3d60';
const OWNER = 'secrets-infra/secret-config-value';

function findingsFor(text: string): { ruleId: string; value: string }[] {
  return scan(text, ruleset).map((f) => ({ ruleId: f.ruleId, value: f.rawMatch }));
}

describe('a secret under a credential-named field', () => {
  it.each([
    ['nested JSON', `{\n  "auth": {\n    "secret_key": "${VALUE}"\n  }\n}\n`],
    ['the value the hook hands over for a bare jq -r output', `auth.secret_key: "${VALUE}"\n`],
  ])('is reported once, by the config-value rule: %s', (_label, text) => {
    const findings = findingsFor(text);
    // One finding, over the value alone: redaction replaces one span and the
    // key stays readable.
    expect(findings).toEqual([{ ruleId: OWNER, value: VALUE }]);
  });

  it.each([
    ['bearer', `{"bearer": "${VALUE}"}`],
    ['session_key', `{"session": {"session_key": "${VALUE}"}}`],
    ['sessionKey', '{"sessionKey": "pZ4kQ9wE2rT7yU1iOa3S"}'],
    ['a short bearer value', 'bearer: 4gH7jK1lZ5xC8vB2nM6a'],
  ])(
    'is reported by exactly one rule when only the config-value rule knows the key: %s',
    (_label, text) => {
      expect(findingsFor(text).map((f) => f.ruleId)).toEqual([OWNER]);
    },
  );
});

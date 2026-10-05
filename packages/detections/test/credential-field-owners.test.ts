import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../src/engine.ts';
import { bundledPackDirs, RULES_DIR } from './helpers/rules.ts';

// The whole bundled ruleset, as the hooks run it. A value may get more than one
// finding (coverage over de-duplication); redaction folds overlapping spans.
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
const SLASH_B64 = '/9j4AAQSkZJRgABAQEASABIAADQk1xuAbCdEfGhIjKlMnOpQrStUvWxYz0123456789+uA=';
const LONG = 'aB3dE6gH9jK2mN5pQ8sT1vX4yZ7'.repeat(11);
const OWNER = 'secrets-infra/secret-config-value';

function findingsFor(text: string): { ruleId: string; value: string }[] {
  return scan(text, ruleset).map((f) => ({ ruleId: f.ruleId, value: f.rawMatch }));
}

describe('the issue cases', () => {
  it.each([
    ['nested JSON', `{\n  "auth": {\n    "secret_key": "${VALUE}"\n  }\n}\n`],
    ['the value the hook hands over for a bare jq -r output', `secret_key: "${VALUE}"\n`],
  ])('the config-value rule reports the value: %s', (_label, text) => {
    expect(findingsFor(text)).toContainEqual({ ruleId: OWNER, value: VALUE });
  });

  it('reports a bearer value', () => {
    expect(findingsFor(`{"bearer": "${VALUE}"}`)).toContainEqual({ ruleId: OWNER, value: VALUE });
  });
});

// Forms the config-value rule does not read (unquoted keys, flow maps, a log
// prefix, a value starting with "/", one over 256 characters, a key path of
// four or more segments). Another rule must still report the value.
describe('a secret_key or session_key value in a form the config-value rule skips', () => {
  it.each([
    ['JS object', `const cfg = { secret_key: '${VALUE}' };`, VALUE],
    ['Python dict', `cfg = {'secret_key': '${VALUE}'}`, VALUE],
    ['log line', `2026-10-05 INFO loaded secret_key: ${VALUE}`, VALUE],
    ['YAML flow map', `auth: {secret_key: ${VALUE}}`, VALUE],
    ['base64 starting with a slash', `{"secret_key": "${SLASH_B64}"}`, SLASH_B64],
    ['value over 256 characters', `{"secret_key": "${LONG}"}`, LONG],
    ['four-segment key path', `services.prod.auth_config.secret_key: "${VALUE}"`, VALUE],
    ['session_key in a JS object', `const s = { session_key: '${VALUE}' };`, VALUE],
    ['session_key in a log line', `DEBUG session_key: ${VALUE}`, VALUE],
  ])('is reported: %s', (_label, text, value) => {
    // The fallback reads at most 200 characters, so a longer value is reported
    // by its leading part.
    expect(findingsFor(text).some((f) => f.value !== '' && value.startsWith(f.value))).toBe(true);
  });
});

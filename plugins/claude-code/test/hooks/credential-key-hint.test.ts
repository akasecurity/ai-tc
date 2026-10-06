import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { scanText } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  annotateBareValue,
  annotatedText,
  credentialKeyFromInput,
  unannotatedText,
} from '../../src/hooks/credential-key-hint.ts';
import type { FieldTokenizer } from '../../src/hooks/pre-tool-use-decision.ts';
import { scanResponseFields } from '../../src/hooks/scan-response.ts';
import { scannableResponseFields } from '../../src/hooks/tool-response.ts';

// Fake values only: random-looking, belonging to no real system.
const HEX = 'a3f9c27d81b4e605d9f2a7c13e8b4056f1d7a29c8e3b60f4d5a1c97e2b8f3d60';
const BASE64 = 'Zq81mVtR0aLp44XsYb2NcE7kWd9HfU3oQx5Tg';

const bash = (command: string): unknown => ({ command });

describe('credentialKeyFromInput', () => {
  it.each([
    ['jq path', 'jq -r .auth.secret_key settings.json', 'secret_key'],
    ['jq bracket path', `jq -r '.auth["secret_key"]' settings.json`, 'secret_key'],
    ['env expansion', 'echo "$API_TOKEN"', 'API_TOKEN'],
    ['printenv', 'printenv GITHUB_TOKEN', 'GITHUB_TOKEN'],
    ['yq', 'yq .db.password config.yml', 'password'],
    ['camelCase', 'node -p "require(\'./c.json\').accessKey"', 'accessKey'],
    ['upper-case with a dash', 'cat conf | grep -i X-Auth-Token', 'X-Auth-Token'],
    ['braced expansion', 'echo "${API_TOKEN}"', 'API_TOKEN'],
    ['master_key path', 'cat /run/secrets/master_key', 'master_key'],
    ['jq master_key', 'jq -r .master_key config.json', 'master_key'],
    ['passphrase expansion', 'echo $PASSPHRASE', 'PASSPHRASE'],
    ['license_key path', 'cat /run/secrets/license_key', 'license_key'],
    ['passcode path', 'cat /run/secrets/passcode', 'passcode'],
    ['pairing code lookup', 'jq -r .pairing_code c.json', 'pairing_code'],
    ['pwd lookup', 'jq -r .db.pwd c.json', 'pwd'],
  ] as const)('reads the key from a Bash command: %s', (_label, command, key) => {
    expect(credentialKeyFromInput('Bash', bash(command))).toBe(key);
  });

  it('uses only the last component of a deep lookup path', () => {
    expect(
      credentialKeyFromInput('Bash', bash('jq -r .models.local.auth_cfg.server.secret_key c.json')),
    ).toBe('secret_key');
    expect(credentialKeyFromInput('Bash', bash('jq -r .a.b.c.d.bearer c.json'))).toBe('bearer');
  });

  it('attributes a Bearer header to the variable, not the scheme', () => {
    expect(
      credentialKeyFromInput(
        'Bash',
        bash('curl -H "Authorization: Bearer $TOKEN" https://x.invalid'),
      ),
    ).toBe('TOKEN');
    expect(
      credentialKeyFromInput('Bash', bash('curl -H "Authorization: Bearer abc" https://x.invalid')),
    ).toBeUndefined();
  });

  it('reads the last path component only for a command that prints a file', () => {
    expect(credentialKeyFromInput('Bash', bash('cat /run/secrets/api_token'))).toBe('api_token');
    expect(credentialKeyFromInput('Bash', bash('ls /run/secrets/api_token'))).toBeUndefined();
  });

  it('reads the key from a Read path', () => {
    expect(credentialKeyFromInput('Read', { file_path: '/srv/app/secret_key' })).toBe('secret_key');
  });

  it.each([
    'jq -r .max_tokens settings.json',
    'jq -r .token_count settings.json',
    'jq -r .secret_name settings.json',
    'jq -r .token.id settings.json',
    'jq -r .token.value settings.json',
    'jq -r .client_secret_id settings.json',
    'cd ~/src/token && git rev-parse HEAD',
    'git log -1 --format=%H -- src/auth/token',
    'npm view jsonwebtoken dist.shasum',
    'cat notes.txt',
    'ls -la',
    'git log --grep=secret_key --format=%H',
    'git commit -m "add token"',
    'npm view my-token dist.shasum',
    'gh issue list --label=api_key',
    'echo spin compass bypass',
  ])('names no key for %s', (command) => {
    expect(credentialKeyFromInput('Bash', bash(command))).toBeUndefined();
  });

  it('ignores tools whose input does not say where the output came from', () => {
    expect(credentialKeyFromInput('WebFetch', { url: 'https://example.invalid/token' })).toBe(
      undefined,
    );
    expect(credentialKeyFromInput('Bash', undefined)).toBeUndefined();
    expect(credentialKeyFromInput('Bash', { command: 42 })).toBeUndefined();
  });

  it('skips a very long command', () => {
    expect(credentialKeyFromInput('Bash', bash(`echo ${'a '.repeat(3000)} $API_TOKEN`))).toBe(
      undefined,
    );
  });
});

describe('annotateBareValue', () => {
  it('wraps one high-entropy token, keeping the newline', () => {
    const annotation = annotateBareValue('auth.secret_key', `${HEX}\n`);
    expect(annotation).toBeDefined();
    if (!annotation) return;
    const wrapped = annotatedText(`${HEX}\n`, annotation);
    expect(wrapped).toBe(`auth.secret_key: "${HEX}"\n`);
    expect(unannotatedText(wrapped, annotation)).toBe(`${HEX}\n`);
  });

  it.each([
    ['a low-entropy token', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
    ['a short token', 'a3f9c27d81b4e605'],
    ['two lines', `${HEX}\n${HEX}\n`],
    ['a sentence', 'the quick brown fox jumps over the lazy dog'],
    ['a path', '/usr/local/lib/python3.12/site-packages/pkg'],
    ['empty output', ''],
  ])('leaves %s alone', (_label, output) => {
    expect(annotateBareValue('secret_key', output)).toBeUndefined();
  });

  it('leaves a token longer than the rule reads alone', () => {
    expect(annotateBareValue('secret_key', `${'0123456789abcdef'.repeat(16)}0`)).toBeUndefined();
    expect(annotateBareValue('secret_key', '0123456789abcdef'.repeat(16))).toBeDefined();
  });

  it('does nothing without a key', () => {
    expect(annotateBareValue(undefined, HEX)).toBeUndefined();
  });

  it('keeps a rewrite that lost the wrapper', () => {
    const annotation = annotateBareValue('token', `${HEX}\n`);
    if (!annotation) throw new Error('expected an annotation');
    expect(unannotatedText('[REDACTED:SECRET]', annotation)).toBe('[REDACTED:SECRET]');
  });
});

describe('scannableResponseFields with a tool input', () => {
  it('annotates a stdout that is one bare value under a named key', () => {
    const fields = scannableResponseFields(
      'Bash',
      { stdout: `${HEX}\n`, stderr: '' },
      bash('jq -r .auth.secret_key settings.json'),
    );
    expect(fields).toHaveLength(1);
    expect(fields[0]?.annotation?.prefix).toBe('secret_key: "');
  });

  it('leaves a field alone when the command names no key', () => {
    const [field] = scannableResponseFields(
      'Bash',
      { stdout: `${HEX}\n`, stderr: '' },
      bash('sha256sum build.tar'),
    );
    expect(field?.annotation).toBeUndefined();
  });

  it('leaves multi-line output alone', () => {
    const [field] = scannableResponseFields(
      'Bash',
      { stdout: `${HEX}\n${HEX}\n`, stderr: '' },
      bash('jq -r .auth.secret_key settings.json'),
    );
    expect(field?.annotation).toBeUndefined();
  });
});

// The capture stand-in runs the real bundled packs: a Redact policy rewrites
// every finding, a Warn policy reports them and rewrites nothing.
function capture(policy: 'redact' | 'warn'): (text: string) => Promise<CaptureResult> {
  return (text) => {
    const { masked, findings } = scanText(text);
    const matches: CaptureResult['findings'] = findings.map((f) => ({
      ruleId: f.ruleId,
      category: f.category,
      severity: f.severity,
      span: f.span,
      rawMatch: text.slice(f.span.start, f.span.end),
      confidence: f.confidence,
    }));
    if (matches.length === 0) return Promise.resolve({ action: 'log', text: null, findings: [] });
    return Promise.resolve(
      policy === 'redact'
        ? { action: 'redact', text: masked, findings: matches, enforcedFindings: matches }
        : { action: 'warn', text: null, findings: matches },
    );
  };
}

async function runBash(
  command: string,
  stdout: string,
  policy: 'redact' | 'warn',
): ReturnType<typeof scanResponseFields> {
  const response = { stdout, stderr: '' };
  const fields = scannableResponseFields('Bash', response, bash(command));
  return scanResponseFields('Bash', response, fields, capture(policy));
}

describe('a tokenized annotated field', () => {
  const POINTER = '[[aka:secret:abc.def]]';

  it('puts the pointer where the bare value was and leaks no wrapper', async () => {
    const seen: string[] = [];
    // A tokenizer stand-in: replaces the union of the enforced spans in the text
    // it is given (the annotated scan text) with a pointer.
    const tokenizeField: FieldTokenizer = (text, findings) => {
      seen.push(text);
      const start = Math.min(...findings.map((f) => f.span.start));
      const end = Math.max(...findings.map((f) => f.span.end));
      return Promise.resolve({
        text: `${text.slice(0, start)}${POINTER}${text.slice(end)}`,
        pointers: [POINTER],
        degraded: [],
      });
    };
    const response = { stdout: `${HEX}\n`, stderr: '' };
    const fields = scannableResponseFields(
      'Bash',
      response,
      bash('jq -r .auth.secret_key settings.json'),
    );
    expect(fields[0]?.annotation).toBeDefined();
    const outcome = await scanResponseFields(
      'Bash',
      response,
      fields,
      capture('redact'),
      tokenizeField,
    );
    expect(seen).toEqual([`secret_key: "${HEX}"\n`]);
    const { stdout } = outcome.updated as { stdout: string };
    expect(stdout).toBe(`${POINTER}\n`);
    expect(stdout).not.toContain('secret_key');
    expect(stdout).not.toContain(HEX);
    expect(outcome.realized?.pointers.map((p) => p.token)).toEqual([POINTER]);
  });
});

describe('the issue case, end to end through the response scan', () => {
  const json = `{\n  "auth": {\n    "secret_key": "${HEX}"\n  }\n}\n`;

  it('masks the nested JSON value under Redact', async () => {
    const outcome = await runBash('jq . settings.json', json, 'redact');
    const { stdout } = outcome.updated as { stdout: string };
    expect(stdout).not.toContain(HEX);
    expect(stdout).toContain('"secret_key"');
    expect(outcome.redactedFindings.length).toBeGreaterThan(0);
  });

  it('flags the nested JSON value under Warn', async () => {
    const outcome = await runBash('jq . settings.json', json, 'warn');
    expect(outcome.warnedFindings.map((f) => f.ruleId)).toContain(
      'secrets-infra/secret-config-value',
    );
  });

  it('masks the bare jq -r value under Redact, keeping the newline', async () => {
    const outcome = await runBash('jq -r .auth.secret_key settings.json', `${HEX}\n`, 'redact');
    const { stdout } = outcome.updated as { stdout: string };
    expect(stdout).not.toContain(HEX);
    expect(stdout).toBe('[REDACTED:SECRET]\n');
  });

  it('flags the bare jq -r value under Warn', async () => {
    const outcome = await runBash('jq -r .auth.secret_key settings.json', `${HEX}\n`, 'warn');
    expect(outcome.warnedFindings.map((f) => f.ruleId)).toContain(
      'secrets-infra/secret-config-value',
    );
  });

  it('masks a bare base64 value read from an environment variable', async () => {
    const outcome = await runBash('echo "$SERVICE_API_KEY"', `${BASE64}\n`, 'redact');
    expect((outcome.updated as { stdout: string }).stdout).toBe('[REDACTED:SECRET]\n');
  });

  it('does not touch the same bare value when the command names no key', async () => {
    const outcome = await runBash('sha256sum release.tar', `${HEX}\n`, 'redact');
    expect(outcome.redactedFindings).toEqual([]);
    expect((outcome.updated as { stdout: string }).stdout).toBe(`${HEX}\n`);
  });

  it('masks a bare value read through a deep jq path, with the two rules that read it', async () => {
    const outcome = await runBash(
      'jq -r .models.local.auth_cfg.server.secret_key settings.json',
      `${HEX}\n`,
      'redact',
    );
    expect((outcome.updated as { stdout: string }).stdout).toBe('[REDACTED:SECRET]\n');
    // Two rules read this value (coverage over de-duplication); redaction folds
    // their identical spans into one, which the exact output above shows.
    expect(outcome.redactedFindings.map((f) => f.ruleId).sort()).toEqual([
      'secrets-infra/generic-high-entropy-secret',
      'secrets-infra/secret-config-value',
    ]);
  });

  it('does not mask a commit hash printed after a command that merely mentions a token path', async () => {
    for (const command of [
      'cd ~/src/token && git rev-parse HEAD',
      'git log -1 --format=%H -- src/auth/token',
      'npm view jsonwebtoken dist.shasum',
      'git log --grep=secret_key --format=%H',
      'git commit -m "add token"',
      'npm view my-token dist.shasum',
      'gh pr list --label=api_key',
    ]) {
      const outcome = await runBash(command, `${HEX}\n`, 'redact');
      expect(outcome.redactedFindings, command).toEqual([]);
      expect((outcome.updated as { stdout: string }).stdout).toBe(`${HEX}\n`);
    }
  });

  it.each([
    'cat /run/secrets/master_key',
    'jq -r .master_key config.json',
    'echo $PASSPHRASE',
    'cat /run/secrets/license_key',
    'cat /run/secrets/passcode',
  ])('masks a bare value printed by %s', async (command) => {
    const outcome = await runBash(command, `${HEX}\n`, 'redact');
    expect((outcome.updated as { stdout: string }).stdout).toBe('[REDACTED:SECRET]\n');
  });

  it('does not touch a bare count under a look-alike key', async () => {
    const outcome = await runBash('jq -r .max_tokens settings.json', '4096\n', 'redact');
    expect(outcome.redactedFindings).toEqual([]);
  });
});

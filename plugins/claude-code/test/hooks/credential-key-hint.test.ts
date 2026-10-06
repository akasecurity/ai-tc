import { scanText } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  annotateBareValue,
  annotatedText,
  credentialKeyFromInput,
  unannotatedText,
} from '../../src/hooks/credential-key-hint.ts';

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
    ['aws secret id flag', 'aws secretsmanager get-secret-value --secret-id api_key', 'api_key'],
    ['aws secret id equals', 'aws secretsmanager get-secret-value --secret-id=api_key', 'api_key'],
    ['aws ssm name', 'aws ssm get-parameter --name api_key --with-decryption', 'api_key'],
    ['aws ssm path name', 'aws ssm get-parameter --name=/prod/api_key', 'api_key'],
    ['vault -field', 'vault kv get -field=api_key secret/app', 'api_key'],
    ['vault -field space', 'vault kv get -field api_key secret/app', 'api_key'],
    ['op --field', 'op item get web --field api_token', 'api_token'],
    ['generic -p', 'op item get web -p token', 'token'],
    ['terraform output', 'terraform output api_key', 'api_key'],
    ['terraform output raw', 'terraform output -raw api_key', 'api_key'],
    ['vault kv get path', 'vault kv get secret/api_key', 'api_key'],
    ['op read', 'op read op://vault/api_token', 'api_token'],
    ['cd then cat', 'cd /run/secrets && cat api_key', 'api_key'],
    ['newline then cat', 'cd /run/secrets\nls\ncat api_key', 'api_key'],
    ['sudo cat', 'sudo cat /run/secrets/api_key', 'api_key'],
    ['piped xargs cat', 'ls | xargs cat api_key', 'api_key'],
    ['subshell cat', 'echo $(cat /run/secrets/api_key)', 'api_key'],
    ['head with count', 'head -c 40 /run/secrets/api_key', 'api_key'],
    ['grep long regexp', 'grep --regexp=secret_key file', 'secret_key'],
    ['grep long regexp space', 'grep --regexp secret_key file', 'secret_key'],
    ['grep -e', 'grep -e secret_key file', 'secret_key'],
    ['jq bracket with spaces', `jq -r '.auth["my secret_key"]' settings.json`, 'secret_key'],
    [
      'python index',
      `python3 -c "import json;print(json.load(open('c.json'))['secret_key'])"`,
      'secret_key',
    ],
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
    'less -p api_key file.txt',
    'head -c api_key file',
    'tail --lines api_key file',
    'tail -n api_key file',
    'grep -f secret_key file',
    'grep --file=secret_key file',
    'grep -e other --file secret_key file',
    'gh issue list --label api_key',
    'docker run --name api_key image',
    'aws ssm get-parameter --label=api_key',
    'docker run -v .env.token:/app image',
    'make .secret_key',
    "printf '%s' .token",
    'git checkout .token',
    'curl -H "X-Field: .api_key" https://x',
    `jq -r '.auth["my name"]' settings.json`,
    'terraform output region',
    'terraform apply api_key',
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

describe('the annotated text, scanned with the shipped rules', () => {
  it('a bare value is not found, and the same value under its key name is', () => {
    expect(scanText(`${HEX}\n`).findings).toHaveLength(0);
    const annotation = annotateBareValue('secret_key', `${HEX}\n`);
    if (!annotation) throw new Error('expected an annotation');
    expect(scanText(annotatedText(`${HEX}\n`, annotation)).findings.length).toBeGreaterThan(0);
  });
});

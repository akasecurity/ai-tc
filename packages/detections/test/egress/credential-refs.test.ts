import { CREDENTIAL_REFS_PER_CALL_SITE_MAX, MAX_VARIABLE_NAME_LENGTH } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  enclosingCall,
  enclosingCalls,
  variableReadsIn,
  variableRefsOf,
  withLiteralCredentialRefs,
} from '../../src/egress/credential-refs.ts';
import { extractEgress } from '../../src/egress/extract.ts';

const URL = 'https://api.stripe.com/v1/charges';
const TOKEN = (n: number): string => `[[aka:fp:v1.${String(n).padStart(43, 'A')}]]`;

function onlyHit(text: string) {
  const hits = extractEgress(text);
  expect(hits).toHaveLength(1);
  return hits[0];
}

function variableNames(text: string): string[] {
  return (onlyHit(text)?.credentialRefs ?? []).map((ref) =>
    ref.kind === 'variable' ? ref.variableName : ref.token,
  );
}

describe('extractEgress credential references', () => {
  it.each([
    ['process.env.X', `fetch('${URL}', { headers: { a: process.env.STRIPE_KEY } })`],
    ['process.env["X"]', `fetch('${URL}', { headers: { a: process.env["STRIPE_KEY"] } })`],
    ["process.env['X']", `fetch('${URL}', { headers: { a: process.env['STRIPE_KEY'] } })`],
    ['import.meta.env.X', `fetch('${URL}', { headers: { a: import.meta.env.STRIPE_KEY } })`],
    ['Bun.env.X', `fetch('${URL}', { headers: { a: Bun.env.STRIPE_KEY } })`],
    ['Deno.env.get', `fetch('${URL}', { headers: { a: Deno.env.get("STRIPE_KEY") } })`],
    ['os.environ[]', `requests.post("${URL}", headers={"a": os.environ["STRIPE_KEY"]})`],
    ['os.environ.get', `requests.post("${URL}", headers={"a": os.environ.get("STRIPE_KEY")})`],
    ['os.getenv', `requests.post("${URL}", headers={"a": os.getenv("STRIPE_KEY")})`],
    ['Go os.Getenv', `client.Do(newReq("${URL}", os.Getenv("STRIPE_KEY")))`],
    ['Go os.LookupEnv', `post("${URL}", os.LookupEnv("STRIPE_KEY"))`],
    ['Ruby ENV[]', `Faraday.new("${URL}", headers: { "a" => ENV["STRIPE_KEY"] })`],
    ['Ruby ENV.fetch', `Faraday.new("${URL}", headers: { "a" => ENV.fetch("STRIPE_KEY") })`],
    ['PHP getenv', `$client->post('${URL}', ['a' => getenv('STRIPE_KEY')])`],
    ['PHP $_ENV', `$client->post('${URL}', ['a' => $_ENV['STRIPE_KEY']])`],
    ['Java System.getenv', `post("${URL}", System.getenv("STRIPE_KEY"))`],
    [
      'C# Environment.GetEnvironmentVariable',
      `post("${URL}", Environment.GetEnvironmentVariable("STRIPE_KEY"))`,
    ],
    ['Rust env::var', `client.post("${URL}", env::var("STRIPE_KEY"))`],
    ['Rust std::env::var', `post("${URL}", std::env::var("STRIPE_KEY"))`],
  ])('finds a variable read inside the call: %s', (_label, text) => {
    expect(variableNames(text)).toEqual(['STRIPE_KEY']);
  });

  it('finds a read in a client constructor whose options carry the URL', () => {
    const read = ['process', 'env', 'STRIPE_KEY'].join('.');
    const field = ['api', 'Key'].join('');
    const text = `const client = new Stripe({ baseURL: '${URL}', ${field}: ${read} });`;
    expect(variableNames(text)).toEqual(['STRIPE_KEY']);
  });

  it('finds reads across a multi-line call', () => {
    const text = [
      `const res = await fetch('${URL}', {`,
      `  method: 'POST',`,
      `  headers: {`,
      `    Authorization: \`Bearer \${process.env.STRIPE_KEY}\`,`,
      `    'X-Account': process.env.STRIPE_ACCOUNT,`,
      `  },`,
      `});`,
    ].join('\n');
    expect(variableNames(text)).toEqual(['STRIPE_KEY', 'STRIPE_ACCOUNT']);
  });

  it('records each variable once per call site', () => {
    const text = `fetch('${URL}', { a: process.env.K, b: process.env.K })`;
    expect(variableNames(text)).toEqual(['K']);
  });

  it('does not attach a read outside the call', () => {
    const text = [
      `const key = process.env.STRIPE_KEY;`,
      `fetch('${URL}', { headers: { a: key } });`,
      `const other = process.env.OTHER;`,
    ].join('\n');
    expect(onlyHit(text)?.credentialRefs).toBeUndefined();
  });

  it('does not attach a read in a sibling call on the same line', () => {
    const text = `send(process.env.BEFORE); fetch('${URL}'); send(process.env.AFTER);`;
    expect(onlyHit(text)?.credentialRefs).toBeUndefined();
  });

  it('attaches nothing to a URL that sits in no call', () => {
    const text = `const BASE = '${URL}';\nconst key = process.env.STRIPE_KEY;`;
    expect(onlyHit(text)?.credentialRefs).toBeUndefined();
    expect(onlyHit(text)?.call).toBeUndefined();
  });

  it('does not reach through a block into the call around it', () => {
    const text = `describe('x', () => {\n  const u = '${URL}';\n  use(process.env.K);\n});`;
    expect(onlyHit(text)?.call).toBeUndefined();
  });

  it('does not take a control-flow parenthesis for a call', () => {
    const text = `if (process.env.K && url === '${URL}') go();`;
    expect(onlyHit(text)?.call).toBeUndefined();
  });

  it('looks past a URL constructor to the call that sends it', () => {
    const text = `fetch(new URL('${URL}'), { headers: { a: process.env.K } })`;
    expect(variableNames(text)).toEqual(['K']);
  });

  it('ignores a name longer than the variable-name cap', () => {
    const long = `V${'x'.repeat(MAX_VARIABLE_NAME_LENGTH)}`;
    const text = `fetch('${URL}', { a: process.env.${long}, b: process.env.OK })`;
    expect(variableNames(text)).toEqual(['OK']);
  });

  it('caps the references on one call site', () => {
    const reads = Array.from({ length: 12 }, (_, i) => `process.env.K${String(i)}`).join(', ');
    const text = `fetch('${URL}', [${reads}])`;
    expect(variableNames(text)).toHaveLength(CREDENTIAL_REFS_PER_CALL_SITE_MAX);
    expect(variableNames(text)[0]).toBe('K0');
  });

  it('gives the call span as offsets into the text', () => {
    const text = `x();\nfetch('${URL}', process.env.K);\ny();`;
    const call = onlyHit(text)?.call;
    expect(call).toBeDefined();
    expect(text.slice(call?.start, call?.end)).toBe(`fetch('${URL}', process.env.K)`.slice(5));
  });

  it('gives up on a call that does not close within its bound', () => {
    const text = `fetch('${URL}', process.env.K${' '.repeat(10_000)}`;
    expect(onlyHit(text)?.call).toBeUndefined();
  });

  it('skips parentheses inside strings when matching the call', () => {
    const text = `fetch('${URL}', { note: ')(', a: process.env.K })`;
    expect(variableNames(text)).toEqual(['K']);
  });

  it('finds the call around a URL that sits mid-string', () => {
    const text = `request("GET ${URL}", { a: process.env.K })`;
    expect(variableNames(text)).toEqual(['K']);
  });
});

describe('enclosingCall', () => {
  it('stops at a statement boundary', () => {
    const text = `open(a; '${URL}')`;
    expect(enclosingCall(text, text.indexOf('https'), text.indexOf(')'))).toBeUndefined();
  });

  it('gives up past its lookback', () => {
    const text = `fetch(${' '.repeat(1_500)}'${URL}')`;
    const start = text.indexOf('https');
    expect(enclosingCall(text, start, start + URL.length)).toBeUndefined();
  });

  it('balances nested brackets before the URL', () => {
    const text = `fetch(a(b), [c], { d: e }, '${URL}')`;
    const start = text.indexOf('https');
    expect(enclosingCall(text, start, start + URL.length)).toEqual({
      start: 5,
      end: text.length,
    });
  });

  it('reads an unclosed quote, such as an apostrophe in a comment, as a plain character', () => {
    const text = `// don't\nfetch('${URL}', process.env.K)`;
    const start = text.indexOf('https');
    expect(enclosingCall(text, start, start + URL.length)).toEqual({
      start: text.indexOf('('),
      end: text.length,
    });
  });

  it('skips an escaped quote inside a string', () => {
    const text = `fetch('${URL}', 'it\\'s )', process.env.K)`;
    const start = text.indexOf('https');
    expect(enclosingCall(text, start, start + URL.length)?.end).toBe(text.length);
  });

  it('places many offsets in one pass, each in its own call', () => {
    const text = `a('${URL}'); b(c('${URL}'), 1);`;
    const first = text.indexOf('https');
    const second = text.indexOf('https', first + 1);
    expect(enclosingCalls(text, [second, first])).toEqual([
      { start: text.indexOf('c(') + 1, end: text.indexOf(')', second) + 1 },
      { start: 1, end: text.indexOf(')') + 1 },
    ]);
  });

  it('keeps matching brackets nested past its depth cap', () => {
    const deep = '['.repeat(1_050) + ']'.repeat(1_050);
    const text = `fetch('${URL}', ${deep})`;
    const start = text.indexOf('https');
    expect(enclosingCall(text, start, start + URL.length)).toEqual({ start: 5, end: text.length });
  });
});

describe('variableRefsOf', () => {
  it('reads nothing once the file budget cannot cover the call', () => {
    const text = `fetch('${URL}', process.env.K)`;
    const call = { start: 5, end: text.length };
    expect(variableRefsOf(text, call, { chars: 1_000 })).toEqual([
      { kind: 'variable', variableName: 'K' },
    ]);
    const spent = { chars: 3 };
    expect(variableRefsOf(text, call, spent)).toEqual([]);
    expect(spent.chars).toBe(3);
  });
});

describe('variableReadsIn', () => {
  it('reads names in text order', () => {
    expect(variableReadsIn('os.getenv("B") + process.env.A')).toEqual(['B', 'A']);
  });
});

describe('withLiteralCredentialRefs', () => {
  const text = `const pre = 'SECRET-A';\nfetch('${URL}', { headers: { a: 'SECRET-B' }, b: process.env.K });\nconst post = 'SECRET-C';`;
  const spanOf = (value: string, token: string) => ({
    start: text.indexOf(value),
    end: text.indexOf(value) + value.length,
    ruleId: 'test-rule',
    token,
  });

  it('attaches only the secrets whose span lies inside the call, before the variables', () => {
    const [hit] = withLiteralCredentialRefs(extractEgress(text), [
      spanOf('SECRET-A', TOKEN(1)),
      spanOf('SECRET-B', TOKEN(2)),
      spanOf('SECRET-C', TOKEN(3)),
    ]);
    expect(hit?.credentialRefs).toEqual([
      { kind: 'literal', token: TOKEN(2), ruleId: 'test-rule' },
      { kind: 'variable', variableName: 'K' },
    ]);
  });

  it('does not attach a secret that straddles the call boundary', () => {
    const start = text.indexOf('fetch') - 2;
    const [hit] = withLiteralCredentialRefs(extractEgress(text), [
      { start, end: start + 10, ruleId: 'test-rule', token: TOKEN(4) },
    ]);
    expect(hit?.credentialRefs).toEqual([{ kind: 'variable', variableName: 'K' }]);
  });

  it('records one token once per call site', () => {
    const second = text.indexOf('process');
    const [hit] = withLiteralCredentialRefs(extractEgress(text), [
      spanOf('SECRET-B', TOKEN(2)),
      { start: second, end: second + 3, ruleId: 'test-rule', token: TOKEN(2) },
    ]);
    expect(hit?.credentialRefs?.filter((ref) => ref.kind === 'literal')).toHaveLength(1);
  });

  it('keeps the cap with literals first', () => {
    const many = Array.from({ length: 10 }, (_, i) => spanOf('SECRET-B', TOKEN(i)));
    const [hit] = withLiteralCredentialRefs(extractEgress(text), many);
    expect(hit?.credentialRefs).toHaveLength(CREDENTIAL_REFS_PER_CALL_SITE_MAX);
    expect(hit?.credentialRefs?.every((ref) => ref.kind === 'literal')).toBe(true);
  });

  it('leaves a hit outside any call untouched', () => {
    const bare = `const BASE = '${URL}';`;
    const hits = extractEgress(bare);
    expect(withLiteralCredentialRefs(hits, [spanOf('SECRET-B', TOKEN(1))])).toEqual(hits);
  });

  it('leaves the hits unchanged with no secrets', () => {
    const hits = extractEgress(text);
    expect(withLiteralCredentialRefs(hits, [])).toBe(hits);
  });
});

// Drives the built CLI shim as a real child process. Each case gets its own
// mkdtempSync directory so no test can see another's files.
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { claudeAdapter } from '../../src/providers/claude.ts';
import { resolveProtocolTokens } from '../../src/sanitize/index.ts';
import { sanitizeCapture } from '../../src/sanitize/sanitize-capture.ts';
import { errorFrom, expectNoEchoOf } from '../helpers/no-echo.ts';

const PACKAGE_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const CLI_SCRIPT = join(PACKAGE_ROOT, 'scripts', 'sanitize-capture.mjs');

const RAW = 'qZ7hLm2XvB9tRw4sKcN6pJ1dGf3yUa8e';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-sanitize-cli-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
}

function run(args: readonly string[], input = ''): RunResult {
  const proc = spawnSync(process.execPath, [CLI_SCRIPT, ...args], {
    encoding: 'utf8',
    input,
  });
  return { status: proc.status ?? 1, stdout: proc.stdout, stderr: proc.stderr };
}

function runWithStdin(args: readonly string[], input: string): RunResult {
  return run(args, input);
}

function baseArgs(overrides: Partial<Record<string, string>> = {}): string[] {
  const merged: Record<string, string> = {
    site: 'chatgpt',
    kind: 'conversation',
    direction: 'request',
    url: 'https://chatgpt.com/backend-api/x',
    format: 'json',
    ...overrides,
  };
  return Object.entries(merged).flatMap(([k, v]) => [`--${k}`, v]);
}

describe('sanitize-capture CLI', () => {
  it('K1: --survey writes the two list files and no fixture', () => {
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, JSON.stringify({ a: RAW }));
    const outBase = join(dir, 'out');
    const result = run([...baseArgs(), '--in', inPath, '--out', outBase, '--survey']);
    expect(result.status).toBe(0);
    expect(existsSync(`${outBase}.keys.txt`)).toBe(true);
    expect(existsSync(`${outBase}.values.txt`)).toBe(true);
    expect(existsSync(outBase)).toBe(false);
  });

  it('K1b: a REFUSED run still writes the survey, so the approvals can be bootstrapped', () => {
    // A survey that only works once the run already succeeds cannot produce
    // the approvals the run needs — which is the position an operator was in
    // for every refusal.
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, JSON.stringify({ model: 'gpt-4o', n: 1e21 }));
    const outBase = join(dir, 'out');
    const result = run([...baseArgs(), '--in', inPath, '--out', outBase, '--survey']);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('refused (unrepresentable-number)');
    expect(existsSync(`${outBase}.values.txt`)).toBe(true);
    expect(readFileSync(`${outBase}.values.txt`, 'utf8')).toContain('gpt-4o');
  });

  it('K1c: the survey file says in the file that it carries raw capture content', () => {
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, JSON.stringify({ model: 'gpt-4o' }));
    const outBase = join(dir, 'out');
    const result = run([...baseArgs(), '--in', inPath, '--out', outBase, '--survey']);
    expect(result.status).toBe(0);
    expect(readFileSync(`${outBase}.values.txt`, 'utf8')).toContain('RAW CAPTURE CONTENT');
    expect(result.stderr).toContain('RAW capture content');
  });

  it('K1d: --survey refuses an --out inside test/fixtures/', () => {
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, '{}');
    const outBase = join(PACKAGE_ROOT, 'test', 'fixtures', 'chatgpt', 'approved');
    const result = run([...baseArgs(), '--in', inPath, '--out', outBase, '--survey']);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('test/fixtures');
    expect(existsSync(`${outBase}.keys.txt`)).toBe(false);
  });

  it('K2: a full run writes bytes identical to sanitizeCapture computed in-test', () => {
    const raw = JSON.stringify({ a: RAW, b: 'gpt-4o' });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const outPath = join(dir, 'out.json');
    const result = run([...baseArgs(), '--in', inPath, '--out', outPath]);
    expect(result.status).toBe(0);

    const expected = sanitizeCapture({
      raw,
      url: 'https://chatgpt.com/backend-api/x',
      site: 'chatgpt',
      kind: 'conversation',
      direction: 'request',
      format: 'json',
      allowedHosts: ['chatgpt.com', 'chat.openai.com'],
      approvedKeys: new Set(),
      approvedValues: new Set(),
      protocolTokens: new Set(),
      detect: () => [],
    });
    if (!expected.ok) throw new Error(`expected ok:true, got ${expected.refusal}`);
    expect(readFileSync(outPath, 'utf8')).toBe(expected.text);
  });

  it('K3: --out exists without --force refuses (exit 2) and leaves the file untouched', () => {
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, '{}');
    const outPath = join(dir, 'out.json');
    writeFileSync(outPath, 'PREEXISTING');
    const result = run([...baseArgs(), '--in', inPath, '--out', outPath]);
    expect(result.status).toBe(2);
    expect(readFileSync(outPath, 'utf8')).toBe('PREEXISTING');
  });

  it('K4: a HAR input refuses (exit 1), writes nothing, and does not echo the raw value', () => {
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, JSON.stringify({ log: { entries: [{ request: { url: RAW } }] } }));
    const outPath = join(dir, 'out.json');
    const result = run([...baseArgs(), '--in', inPath, '--out', outPath]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('HAR');
    expect(existsSync(outPath)).toBe(false);
    expectNoEchoOf(result.stderr, RAW);
  });

  it('K5: with no approval files, nothing preservable survives verbatim', () => {
    const raw = JSON.stringify({ note: 'gpt-4o', tag: 'assistant-mode' });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const outPath = join(dir, 'out.json');
    const result = run([...baseArgs(), '--in', inPath, '--out', outPath]);
    expect(result.status).toBe(0);
    const fixture = JSON.parse(readFileSync(outPath, 'utf8')) as { chunks: string[] };
    expect(fixture.chunks[0]).not.toContain('gpt-4o');
    expect(fixture.chunks[0]).not.toContain('assistant-mode');
    expect(fixture.chunks[0]).not.toContain('"note"');
    expect(fixture.chunks[0]).not.toContain('"tag"');
  });

  it('K6: the happy path prints a summary line and never echoes the raw value', () => {
    const raw = JSON.stringify({ body: RAW });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const outPath = join(dir, 'out.json');
    const result = run([...baseArgs(), '--in', inPath, '--out', outPath]);
    expect(result.status).toBe(0);
    // Positive control: stderr does carry something (the summary line) — an
    // empty-string check would satisfy every "does not echo" assertion below
    // vacuously.
    expect(result.stderr.length).toBeGreaterThan(0);
    expect(result.stderr).toContain('sanitized fixture written');
    expectNoEchoOf(result.stdout, RAW);
    expectNoEchoOf(result.stderr, RAW);
  });

  // A real bundled rule's own fixture value (core-pii/mac-address), chosen
  // because it is a VOCABULARY-class candidate (short, low-entropy, colon
  // allowed by the vocabulary charset) — the only class the approval
  // mechanism and the detector gate ever apply to. A base64ish- or hex-class
  // secret (an AWS key, say) is unconditionally replaced regardless of
  // approval or detection, so it would pass this test even against a fake
  // no-op detector and prove nothing about the wiring.
  const MAC_EXAMPLE = 'AA:BB:CC:DD:EE:FF';

  it('K7: the real detection engine is wired — a rule example is replaced even when approved', () => {
    const raw = JSON.stringify({ credential: MAC_EXAMPLE });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const approvedKeysPath = join(dir, 'approved-keys.txt');
    writeFileSync(approvedKeysPath, 'credential\n');
    const approvedValuesPath = join(dir, 'approved-values.txt');
    writeFileSync(approvedValuesPath, `${MAC_EXAMPLE}\n`);
    const outPath = join(dir, 'out.json');
    const result = run([
      ...baseArgs(),
      '--in',
      inPath,
      '--out',
      outPath,
      '--approved-keys',
      approvedKeysPath,
      '--approved-values',
      approvedValuesPath,
    ]);
    expect(result.status).toBe(0);
    const fixture = JSON.parse(readFileSync(outPath, 'utf8')) as { chunks: string[] };
    expect(fixture.chunks[0]).not.toContain(MAC_EXAMPLE);
  });

  it('K7b: the summary reports an approval the detector overrode', () => {
    // K7 proves such a value is REPLACED. This proves the operator is told. On
    // the normal path only the survey printed the flag counts, so an approvals
    // file carrying a live credential was silently ignored while the run
    // reported a clean success — the one outcome that reads as "my approvals
    // were applied".
    const raw = JSON.stringify({ credential: MAC_EXAMPLE });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const approvedKeysPath = join(dir, 'approved-keys.txt');
    writeFileSync(approvedKeysPath, 'credential\n');
    const approvedValuesPath = join(dir, 'approved-values.txt');
    writeFileSync(approvedValuesPath, `${MAC_EXAMPLE}\n`);
    const outPath = join(dir, 'out.json');
    const result = run([
      ...baseArgs(),
      '--in',
      inPath,
      '--out',
      outPath,
      '--approved-keys',
      approvedKeysPath,
      '--approved-values',
      approvedValuesPath,
    ]);
    expect(result.status).toBe(0);
    expect(result.stderr).toContain('1 approval(s)/declaration(s) overridden by the detector');
    expectNoEchoOf(result.stderr, MAC_EXAMPLE);
  });

  it('K8: a detector-flagged survey candidate withholds the value', () => {
    const raw = JSON.stringify({ credential: MAC_EXAMPLE, harmless: 'gpt-4o' });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const outBase = join(dir, 'out');
    const result = run([...baseArgs(), '--in', inPath, '--out', outBase, '--survey']);
    expect(result.status).toBe(0);
    const valuesFile = readFileSync(`${outBase}.values.txt`, 'utf8');
    // Positive control: the file carries an ordinary (non-flagged) candidate
    // line too, so an empty file is not what makes the absence check below
    // pass.
    expect(valuesFile).toContain('gpt-4o');
    expect(valuesFile).toContain('[detected:');
    expect(valuesFile).toContain('<withheld>');
    expectNoEchoOf(valuesFile, MAC_EXAMPLE);
  });

  it('K9: the CLI passes exactly what the resolver returns (byte-identity, the K2 shape)', () => {
    // The point of the resolver split (mirroring toTapEndpoints) is that the
    // CLI is wired to WHATEVER protocolTokensForSite returns rather than to a
    // constant. The stand-in below therefore carries the adapter's OWN
    // declaration, read from the adapter: hardcoding a list here would make
    // this pass only while that list happened to match, which is exactly the
    // coupling the case exists to prove.
    const raw = JSON.stringify({ a: RAW });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const outPath = join(dir, 'out.json');
    const result = run([
      ...baseArgs({ site: 'claude-ai', url: 'https://claude.ai/api/x' }),
      '--in',
      inPath,
      '--out',
      outPath,
    ]);
    expect(result.status).toBe(0);

    const expected = sanitizeCapture({
      raw,
      url: 'https://claude.ai/api/x',
      site: 'claude-ai',
      kind: 'conversation',
      direction: 'request',
      format: 'json',
      allowedHosts: ['claude.ai'],
      approvedKeys: new Set(),
      approvedValues: new Set(),
      protocolTokens: resolveProtocolTokens(
        // A single-adapter registry stand-in, mirroring what the shim
        // resolves through the real one — this is the assertion that the
        // wiring uses the SITE'S OWN declaration rather than a constant.
        [
          {
            id: 'claude-ai',
            hostnames: ['claude.ai'],
            protocolTokens: claudeAdapter.protocolTokens,
          },
        ] as never,
        'claude-ai',
      ),
      detect: () => [],
    });
    if (!expected.ok) throw new Error(`expected ok:true, got ${expected.refusal}`);
    expect(readFileSync(outPath, 'utf8')).toBe(expected.text);
  });

  it('K10: an invalid declaration refuses loudly, naming the site/index/clause and never the token', () => {
    const badToken = 'a b'; // whitespace — index 1's offense
    const syntheticAdapters = [
      {
        id: 'chatgpt',
        hostnames: ['chatgpt.com'],
        protocolTokens: ['content_block_delta', badToken],
      },
    ] as never;
    const err = errorFrom(() => resolveProtocolTokens(syntheticAdapters, 'chatgpt'));
    expect(err).toBeDefined();
    expect(err?.message).toContain('chatgpt');
    expect(err?.message).toContain('index 1');
    expectNoEchoOf(err?.message, badToken);

    // A 41-character run and the stripe rule's own example, each their own
    // adapter so each is independently the FIRST (and only) offender.
    const longRun = 'a'.repeat(41);
    const longErr = errorFrom(() =>
      resolveProtocolTokens(
        [{ id: 'chatgpt', hostnames: ['chatgpt.com'], protocolTokens: [longRun] }] as never,
        'chatgpt',
      ),
    );
    expect(longErr?.message).toContain('index 0');
    expectNoEchoOf(longErr?.message, longRun);

    const uuid = '123e4567-e89b-12d3-a456-426614174000';
    const uuidErr = errorFrom(() =>
      resolveProtocolTokens(
        [{ id: 'chatgpt', hostnames: ['chatgpt.com'], protocolTokens: [uuid] }] as never,
        'chatgpt',
      ),
    );
    expect(uuidErr?.message).toContain('index 0');
    expectNoEchoOf(uuidErr?.message, uuid);
  });

  it('K11: the summary line reports declared preservations and detector overrides, and echoes no token', () => {
    const raw = JSON.stringify({ credential: MAC_EXAMPLE, note: RAW });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, raw);
    const approvedKeysPath = join(dir, 'approved-keys.txt');
    writeFileSync(approvedKeysPath, 'credential\n');
    const approvedValuesPath = join(dir, 'approved-values.txt');
    writeFileSync(approvedValuesPath, `${MAC_EXAMPLE}\n`);
    const outPath = join(dir, 'out.json');
    const result = run([
      ...baseArgs(),
      '--in',
      inPath,
      '--out',
      outPath,
      '--approved-keys',
      approvedKeysPath,
      '--approved-values',
      approvedValuesPath,
    ]);
    expect(result.status).toBe(0);
    // Positive control: the wording is present at all, so the absence checks
    // below are not vacuous.
    expect(result.stderr).toContain('declared protocol token(s) preserved');
    expect(result.stderr).toContain('approval(s)/declaration(s) overridden by the detector');
    expectNoEchoOf(result.stderr, MAC_EXAMPLE);
    expectNoEchoOf(result.stderr, RAW);
  });

  it('never echoes the --in file path (leak surface 13: an operator filename can itself disclose something)', () => {
    // The path itself carries something a raw-value check cannot name — a
    // project name — so this is asserted directly rather than through
    // expectNoEchoOf, which is built for a captured secret value.
    const missingPath = join(dir, 'a-real-project-name-nobody-should-see.json');
    const outPath = join(dir, 'out.json');
    const result = run([...baseArgs(), '--in', missingPath, '--out', outPath]);
    expect(result.status).toBe(1);
    expect(result.stderr).not.toContain('a-real-project-name-nobody-should-see');
    expect(result.stdout).not.toContain('a-real-project-name-nobody-should-see');
    expect(result.stderr).toContain('could not read --in');
  });

  it('reads from stdin when --in is -', () => {
    const outPath = join(dir, 'out.json');
    const result = runWithStdin(
      [...baseArgs(), '--in', '-', '--out', outPath],
      JSON.stringify({ x: 'hello' }),
    );
    expect(result.status).toBe(0);
    expect(existsSync(outPath)).toBe(true);
  });

  it('a missing required flag is a usage error (exit 2)', () => {
    const result = run(['--site', 'chatgpt']);
    expect(result.status).toBe(2);
  });

  it('an unknown flag is a usage error (exit 2)', () => {
    const result = run([...baseArgs(), '--bogus', 'x']);
    expect(result.status).toBe(2);
  });
});

// The resolver's SITE keying, and the shim's wiring to it. Both are unreachable
// from the real registry today — every adapter declares an empty array — so
// each is driven against a declaration built for the case.
describe('protocol-token resolution is keyed by site', () => {
  it('K12: two adapters, each declaring its own token, resolve to their own sets', () => {
    // Every other case in this file builds a ONE-adapter array, which cannot
    // tell `find(a => a.id === site)` from `adapters[0]`, from a union of all
    // adapters, or from a constant. Two adapters declaring DIFFERENT tokens
    // separates all four.
    const adapters = [
      { id: 'chatgpt', hostnames: ['chatgpt.com'], protocolTokens: ['conversation_ready'] },
      { id: 'claude-ai', hostnames: ['claude.ai'], protocolTokens: ['content_block_delta'] },
    ] as never;

    const chatgpt = resolveProtocolTokens(adapters, 'chatgpt');
    const claude = resolveProtocolTokens(adapters, 'claude-ai');

    expect([...chatgpt]).toEqual(['conversation_ready']);
    expect([...claude]).toEqual(['content_block_delta']);
    // Neither carries the other's — this is what a union would fail.
    expect(chatgpt.has('content_block_delta')).toBe(false);
    expect(claude.has('conversation_ready')).toBe(false);
    // A site no adapter drives resolves to nothing, rather than to the first
    // adapter's declaration.
    expect([...resolveProtocolTokens(adapters, 'nosuchsite')]).toEqual([]);
  });
});

// Drives the REAL shim against a DECLARING adapter. The registry declares
// nothing today, so the shim's own wiring — protocolTokensForSite -> the
// sanitiser's protocolTokens — is otherwise satisfied by a constant empty
// set and by the wrong site alike. The package is copied to a temp directory
// and its adapter patched there; `node_modules` is symlinked back so esbuild
// resolves the bundle exactly as it does in place, and nothing under the
// repository is written.
describe('the CLI is wired to the declaring adapter (K13)', () => {
  const DECLARED = 'content_block_delta';
  const SEGMENT = 'organizations';
  // Verbatim from rules/secrets/stripe-live-key.json's own `examples`.
  const FLAGGED_DECLARATION = 'pk_live_wDlmi91dAAKCRu1JBy89Xaq3RZ';

  let pkgDir: string | undefined;

  function buildPackage(declaration: string): string {
    const root = mkdtempSync(join(tmpdir(), 'aka-sanitize-pkg-'));
    cpSync(join(PACKAGE_ROOT, 'src'), join(root, 'src'), { recursive: true });
    cpSync(join(PACKAGE_ROOT, 'scripts'), join(root, 'scripts'), { recursive: true });
    symlinkSync(join(PACKAGE_ROOT, 'node_modules'), join(root, 'node_modules'), 'dir');
    const adapterPath = join(root, 'src', 'providers', 'claude.ts');
    const source = readFileSync(adapterPath, 'utf8');
    // Matches the WHOLE declaration rather than an empty-array literal: the
    // adapter declares real tokens now, so a marker spelled `[]` would find
    // nothing. The class excludes `]`, which the array's own entries and
    // comments never contain.
    const marker = /^ {2}protocolTokens: \[[^\]]*\],$/m;
    // Fails loudly rather than silently patching nothing: a copy whose
    // adapter was never patched declares its own tokens, and every assertion
    // below would then be asserting the state this case exists to move away
    // from.
    if (!marker.test(source)) {
      throw new Error('claude.ts no longer carries a protocolTokens declaration to patch');
    }
    writeFileSync(adapterPath, source.replace(marker, `  protocolTokens: [${declaration}],`));
    return root;
  }

  function runIn(root: string, args: readonly string[]): RunResult {
    const proc = spawnSync(
      process.execPath,
      [join(root, 'scripts', 'sanitize-capture.mjs'), ...args],
      {
        encoding: 'utf8',
      },
    );
    return { status: proc.status ?? 1, stdout: proc.stdout, stderr: proc.stderr };
  }

  afterEach(() => {
    if (pkgDir !== undefined) rmSync(pkgDir, { recursive: true, force: true });
    pkgDir = undefined;
  });

  it('K13: a declared token survives the real CLI, only for its own site and only whole', () => {
    pkgDir = buildPackage(`'${DECLARED}', '${SEGMENT}'`);
    // `${DECLARED}_extra` is the exact-match control: it CONTAINS a declared
    // token and must not survive, so a prefix or substring match reds here.
    const body = JSON.stringify({ type: DECLARED, longer: `${DECLARED}_extra` });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, body);

    const outPath = join(dir, 'out.json');
    const declared = runIn(pkgDir, [
      ...baseArgs({ site: 'claude-ai', url: `https://claude.ai/api/${SEGMENT}` }),
      '--in',
      inPath,
      '--out',
      outPath,
    ]);
    expect(declared.status).toBe(0);
    const text = readFileSync(outPath, 'utf8');
    expect(text).toContain(DECLARED);
    expect(text).not.toContain(`${DECLARED}_extra`);
    // The URL path segment took the same branch, which is what makes an
    // endpoint declarable at all.
    expect(text).toContain(`/${SEGMENT}"`);
    // Two: the body value and the path segment. `${DECLARED}_extra` is the
    // third leaf and is not among them.
    expect(declared.stderr).toContain('2 declared protocol token(s) preserved');

    // The SAME body under a site whose adapter declares nothing keeps none of
    // it — this is what a site-blind resolver or a constant would fail.
    const otherPath = join(dir, 'other.json');
    const other = runIn(pkgDir, [
      ...baseArgs({ site: 'chatgpt', url: `https://chatgpt.com/backend-api/${SEGMENT}` }),
      '--in',
      inPath,
      '--out',
      otherPath,
    ]);
    expect(other.status).toBe(0);
    expect(other.stderr).toContain('0 declared protocol token(s) preserved');
    expect(readFileSync(otherPath, 'utf8')).not.toContain(DECLARED);
  });

  it('K14: an unusable declaration refuses at exit 1, naming the index and never the token', () => {
    const badToken = 'a b';
    pkgDir = buildPackage(`'${DECLARED}', '${badToken}'`);
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, JSON.stringify({ type: DECLARED }));
    const result = runIn(pkgDir, [
      ...baseArgs({ site: 'claude-ai', url: 'https://claude.ai/api/x' }),
      '--in',
      inPath,
      '--out',
      join(dir, 'out.json'),
    ]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('claude-ai');
    expect(result.stderr).toContain('index 1');
    expect(result.stderr).toContain('contains whitespace');
    expectNoEchoOf(result.stderr, badToken);
    // A REFUSAL, not an unhandled throw. Without the shim's own catch the
    // outer handler prints the stack, which carries the same three strings
    // above plus absolute paths from the operator's machine — the leak
    // surface this file already guards for --in. A stack frame is the one
    // thing that separates the two outcomes.
    expect(result.stderr).not.toContain('    at ');
    expect(result.stderr.trimEnd().split('\n')).toHaveLength(1);
  });

  it('K15: a declaration the detector overrode is reported on the --survey path too', () => {
    // A declared token is neither a candidate nor a preserved value, so it
    // appears in no survey list. Counting only keys and values reported a
    // clean run for a body whose normal run reports the override.
    pkgDir = buildPackage(`'${DECLARED}', '${FLAGGED_DECLARATION}'`);
    const body = JSON.stringify({ type: DECLARED, cred: FLAGGED_DECLARATION, plain: 'gpt-4o' });
    const inPath = join(dir, 'in.json');
    writeFileSync(inPath, body);

    const outBase = join(dir, 'survey');
    const survey = runIn(pkgDir, [
      ...baseArgs({ site: 'claude-ai', url: 'https://claude.ai/api/x' }),
      '--in',
      inPath,
      '--out',
      outBase,
      '--survey',
    ]);
    expect(survey.status).toBe(0);
    // Positive control: the run really did survey something, so the count
    // below is not the empty-input reading.
    expect(survey.stderr).toContain('candidate value(s)');
    expect(survey.stderr).toContain('1 approval(s)/declaration(s) overridden by the detector');
    expectNoEchoOf(survey.stderr, FLAGGED_DECLARATION);
    expectNoEchoOf(readFileSync(`${outBase}.values.txt`, 'utf8'), FLAGGED_DECLARATION);

    // The normal run for the same body agrees, which is the disagreement
    // this case exists to prevent.
    const normal = runIn(pkgDir, [
      ...baseArgs({ site: 'claude-ai', url: 'https://claude.ai/api/x' }),
      '--in',
      inPath,
      '--out',
      join(dir, 'out.json'),
    ]);
    expect(normal.status).toBe(0);
    expect(normal.stderr).toContain('1 approval(s)/declaration(s) overridden by the detector');
    expect(normal.stderr).toContain('1 declared protocol token(s) preserved');
    expectNoEchoOf(normal.stderr, FLAGGED_DECLARATION);
  });
});

// Drives the built CLI shim as a real child process. Each case gets its own
// mkdtempSync directory so no test can see another's files.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { sanitizeCapture } from '../../src/sanitize/sanitize-capture.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

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

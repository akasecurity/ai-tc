import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  assetName,
  DESC,
  type ManifestInput,
  ManifestInputError,
  MAX_DESC_LENGTH,
  parseSums,
  renderFormula,
  renderScoopManifest,
  renderVersionFile,
  type Triple,
  TRIPLES,
} from '../src/lib.ts';
import { defaultIo, type EntryIo, isEntry, main, OUTPUT_NAMES } from '../src/render-manifests.ts';

const FIXTURE_PATH = join(import.meta.dirname, 'fixtures', 'SHA256SUMS');
const FIXTURE = readFileSync(FIXTURE_PATH, 'utf8');
const VERSION = '9.9.9';
const REPO = 'akasecurity/ai-tc';
const VERSIONED_TAG = `/releases/download/bin-v${VERSION}/`;
const ROLLING_TAG = '/releases/download/bin-latest/';

const input = (over: Partial<ManifestInput> = {}): ManifestInput => ({
  version: VERSION,
  repo: REPO,
  sums: parseSums(FIXTURE),
  ...over,
});

/** The hash the fixture gives one triple's archive. */
function fixtureHash(triple: Triple): string {
  const hash = parseSums(FIXTURE).get(assetName(VERSION, triple));
  expect(hash, `the fixture lists no ${assetName(VERSION, triple)}`).toBeDefined();
  return hash ?? '';
}

/** A sums file with some archives removed. */
function sumsWithout(...triples: readonly Triple[]): string {
  const dropped = triples.map((triple) => assetName(VERSION, triple));
  const kept = FIXTURE.split('\n').filter(
    (line) => line !== '' && !dropped.some((name) => line.endsWith(name)),
  );
  expect(kept, 'dropping archives left no lines at all').toHaveLength(4 - triples.length);
  return `${kept.join('\n')}\n`;
}

/** The error a thunk threw, captured outside its own catch. */
function errorFrom(run: () => unknown): Error | undefined {
  try {
    run();
    return undefined;
  } catch (err) {
    return err as Error;
  }
}

const opensRubyBlock = (trimmed: string): boolean =>
  /^class\s/.test(trimmed) || /^def\s/.test(trimmed) || /\bdo$/.test(trimmed);

/** The lines strictly inside the Ruby block whose opening line is `header`. */
function rubyBlock(source: string, header: string): string[] {
  const lines = source.split('\n');
  const start = lines.findIndex((line) => line.trim() === header);
  expect(start, `the formula has no "${header}" line`).toBeGreaterThan(-1);
  const body: string[] = [];
  let depth = 1;
  for (const line of lines.slice(start + 1)) {
    const trimmed = line.trim();
    if (trimmed === 'end') {
      depth -= 1;
      if (depth === 0) return body;
      body.push(line);
      continue;
    }
    body.push(line);
    if (opensRubyBlock(trimmed)) depth += 1;
  }
  throw new Error(`"${header}" is never closed`);
}

/** The quoted arguments of every `<name> "…"` line in a block. */
function directive(block: readonly string[], name: string): string[] {
  const out: string[] = [];
  for (const line of block) {
    const matched = new RegExp(`^${name} "(.*)"$`).exec(line.trim());
    if (matched !== null) out.push(matched[1] ?? '');
  }
  return out;
}

/** The one quoted argument of a `<name> "…"` line, refusing zero or many. */
function onlyDirective(block: readonly string[], name: string): string {
  const found = directive(block, name);
  expect(found, `expected exactly one ${name} line`).toHaveLength(1);
  return found[0] ?? '';
}

interface ScoopManifest {
  version: string;
  description: string;
  homepage: string;
  license: string;
  architecture: { '64bit': { url: string; hash: string; extract_dir: string } };
  bin: string;
  notes: string;
  checkver: { url: string; regex: string };
  autoupdate: {
    architecture: { '64bit': { url: string } };
    hash: { url: string; regex: string };
  };
}

const scoop = (text: string): ScoopManifest => JSON.parse(text) as ScoopManifest;

describe('the fixture', () => {
  it('gives four pairwise distinct hashes', () => {
    // Load-bearing for the pairing case below: with two hashes equal, swapping
    // one platform's hash onto another platform's url renders identically.
    const hashes = TRIPLES.map((triple) => fixtureHash(triple));
    expect(hashes).toHaveLength(4);
    expect(new Set(hashes).size).toBe(4);
    for (const hash of hashes) expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('the Homebrew formula', () => {
  const formula = renderFormula(input());

  it('names the class and carries version, license and a homepage built from --repo', () => {
    const head = formula.split('\n');
    expect(head[0]).toBe('class Aka < Formula');
    expect(head).toContain(`  version "${VERSION}"`);
    expect(head).toContain('  license "Apache-2.0"');
    expect(head).toContain(`  homepage "https://github.com/${REPO}"`);
    expect(head.at(-2)).toBe('end');
  });

  it('sets a url and a sha256 on every macOS, and refuses a machine that is not arm64', () => {
    const block = rubyBlock(formula, 'on_macos do');
    // Nested in an `on_arm`, this url resolves to nothing on an Intel Mac and
    // the whole formula fails to load before it can say why.
    expect(block.join('\n')).not.toMatch(/\bon_(?:arm|intel)\b/);
    expect(block.map((line) => line.trim())).toContain('depends_on arch: :arm64');
    expect(onlyDirective(block, 'url')).toContain(assetName(VERSION, 'darwin-arm64'));
    expect(onlyDirective(block, 'sha256')).toBe(fixtureHash('darwin-arm64'));
  });

  it('refuses 32-bit ARM on both the macOS and the Linux ARM block', () => {
    // Homebrew's `on_arm` fires on ARM32 too, so without the dependency a
    // 32-bit machine is handed an arm64 binary it cannot exec.
    const linux = rubyBlock(formula, 'on_linux do').join('\n');
    const blocks: readonly (readonly [string, string[]])[] = [
      ['on_macos do', rubyBlock(formula, 'on_macos do')],
      ['on_linux > on_arm do', rubyBlock(linux, 'on_arm do')],
    ];
    expect(blocks).toHaveLength(2);
    for (const [name, block] of blocks) {
      expect(
        block.map((line) => line.trim()),
        name,
      ).toContain('depends_on arch: :arm64');
    }
    // The Intel blocks must not carry it, or no x86_64 machine can install.
    expect(rubyBlock(linux, 'on_intel do').join('\n')).not.toContain('depends_on arch:');
  });

  it('pairs each platform with the hash the sums file gives that platform archive', () => {
    const macos = rubyBlock(formula, 'on_macos do');
    const linux = rubyBlock(formula, 'on_linux do').join('\n');
    const arm = rubyBlock(linux, 'on_arm do');
    const intel = rubyBlock(linux, 'on_intel do');

    const pairs: readonly (readonly [Triple, string[]])[] = [
      ['darwin-arm64', macos],
      ['linux-arm64', arm],
      ['linux-x64', intel],
    ];
    for (const [triple, block] of pairs) {
      expect(onlyDirective(block, 'url'), triple).toBe(
        `https://github.com/${REPO}${VERSIONED_TAG}${assetName(VERSION, triple)}`,
      );
      expect(onlyDirective(block, 'sha256'), triple).toBe(fixtureHash(triple));
    }
  });

  it('tracks new versions through the rolling tag', () => {
    const block = rubyBlock(formula, 'livecheck do');
    expect(onlyDirective(block, 'url')).toBe(`https://github.com/${REPO}${ROLLING_TAG}VERSION`);
    const trimmed = block.map((line) => line.trim());
    expect(trimmed).toContain('strategy :page_match');
    expect(trimmed.some((line) => line.startsWith('regex('))).toBe(true);
  });

  it('installs the whole tree into libexec and links the binary out of it', () => {
    // The binary resolves its sidecars from its own directory, so copying it out
    // on its own leaves it unable to find them.
    const block = rubyBlock(formula, 'def install').map((line) => line.trim());
    expect(block).toContain('libexec.install Dir["*"]');
    expect(block).toContain('bin.install_symlink libexec/"aka"');
  });

  it('tells the reader what to run next', () => {
    const block = rubyBlock(formula, 'def caveats').join('\n');
    expect(block).toContain('aka init');
  });

  it('runs the installed binary in its own test block', () => {
    const block = rubyBlock(formula, 'test do').join('\n');
    expect(block).toContain('--version');
    expect(block).toContain('#{bin}/aka');
  });

  it("orders its top-level components the way Homebrew's style check requires", () => {
    const top = formula
      .split('\n')
      .filter((line) => /^ {2}\S/.test(line))
      .map((line) => line.trim().split(' ')[0] ?? '')
      .filter((word) => word !== 'end');
    const order = ['desc', 'homepage', 'version', 'license', 'livecheck', 'on_macos', 'on_linux'];
    const tail = ['def', 'def', 'test'];
    const positions = order.map((name) => top.indexOf(name));
    for (const [index, name] of order.entries()) {
      expect(positions[index], `the formula carries no top-level ${name}`).toBeGreaterThan(-1);
    }
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
    expect(top.slice(-tail.length)).toEqual(tail);
    expect(rubyBlock(formula, 'def install').length).toBeGreaterThan(0);
    expect(formula.indexOf('  def install')).toBeLessThan(formula.indexOf('  def caveats'));
  });

  it('keeps desc inside the length Homebrew allows, capitalized', () => {
    const desc = onlyDirective(formula.split('\n'), 'desc');
    expect(desc).toBe(DESC);
    expect(desc.length).toBeLessThanOrEqual(MAX_DESC_LENGTH);
    expect(desc.slice(0, 1)).toBe(desc.slice(0, 1).toUpperCase());
    expect(desc.slice(0, 1)).toMatch(/[A-Z]/);
  });
});

describe('the Scoop manifest', () => {
  const text = renderScoopManifest(input());
  const manifest = scoop(text);

  it('is JSON, pretty-printed, with a trailing newline', () => {
    expect(text.endsWith('}\n')).toBe(true);
    expect(text).toContain('\n  "version"');
  });

  it('carries the same description, the homepage from --repo and the licence', () => {
    expect(manifest.version).toBe(VERSION);
    expect(manifest.description).toBe(DESC);
    expect(manifest.homepage).toBe(`https://github.com/${REPO}`);
    expect(manifest.license).toBe('Apache-2.0');
  });

  it('points one 64-bit architecture at the versioned zip and its own hash', () => {
    const arch = manifest.architecture['64bit'];
    expect(arch.url).toBe(
      `https://github.com/${REPO}${VERSIONED_TAG}${assetName(VERSION, 'win32-x64')}`,
    );
    expect(arch.hash).toBe(fixtureHash('win32-x64'));
  });

  it('names the archive top-level directory and the shim target', () => {
    // Without extract_dir the exe sits one level down and the shim points at
    // nothing. A literal, not the renderer's own helper: the value has to match
    // the directory cli/scripts/archive-sea.mjs stages the archive under, and a
    // comparison against the helper under test agrees with it whatever it says.
    expect(manifest.architecture['64bit'].extract_dir).toBe('aka-win32-x64');
    expect(manifest.bin).toBe('aka.exe');
  });

  it('checks for new versions against the rolling tag', () => {
    expect(manifest.checkver.url).toBe(`https://github.com/${REPO}${ROLLING_TAG}VERSION`);
    expect(new RegExp(manifest.checkver.regex).exec(VERSION)?.[1]).toBe(VERSION);
  });

  it('keeps $version a literal token in both autoupdate URLs', () => {
    const archive = manifest.autoupdate.architecture['64bit'].url;
    const hashSource = manifest.autoupdate.hash.url;
    // Twice: once in the tag, once in the filename. A concrete version in
    // either republishes this same release for ever.
    expect(archive.split('$version')).toHaveLength(3);
    expect(archive).not.toContain(VERSION);
    expect(hashSource).toContain('bin-v$version/SHA256SUMS');
    expect(hashSource).not.toContain(VERSION);
  });

  it('reads the autoupdate hash out of SHA256SUMS with its own group-1 regex', () => {
    const { regex } = manifest.autoupdate.hash;
    expect(regex, 'the autoupdate hash regex was left to the default').toBeTruthy();
    // Scoop substitutes $version regex-escaped and matches ONCE against the
    // whole file, with no multiline option — which a JavaScript RegExp built
    // with no flags reproduces. The fixture carries the Windows line last, as
    // the release's sorted aggregate does, so a bare `^` cannot reach it.
    const escaped = VERSION.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const compiled = new RegExp(regex.split('$version').join(escaped));
    expect(compiled.flags).toBe('');
    const lines = FIXTURE.split('\n').filter((line) => line !== '');
    expect(lines.length, 'the fixture holds fewer than four lines').toBe(4);
    expect(lines.at(-1)?.endsWith(assetName(VERSION, 'win32-x64'))).toBe(true);

    const orders = [lines, [...lines].reverse(), [lines[1], lines[3], lines[0], lines[2]]];
    for (const order of orders) {
      const file = `${order.join('\n')}\n`;
      expect(compiled.exec(file)?.[1], file).toBe(fixtureHash('win32-x64'));
    }
    // With the Windows line gone, no other line answers for the Windows zip.
    expect(compiled.exec(sumsWithout('win32-x64'))).toBeNull();
    // Nor does the same line under another version.
    expect(compiled.exec(FIXTURE.split(VERSION).join('9.9.10'))).toBeNull();
  });

  it('tells the reader what to run next', () => {
    // Named before it is searched: an absent `notes` reaches `toContain` as
    // undefined, which reports an argument-type complaint rather than the
    // missing field.
    expect(typeof manifest.notes, 'the manifest carries no notes field').toBe('string');
    expect(manifest.notes).toContain('aka init');
  });
});

describe('which tag each URL names', () => {
  const formula = renderFormula(input());
  const manifest = scoop(renderScoopManifest(input()));

  it('names the immutable versioned tag on every archive URL', () => {
    // The bytes behind a bin-latest URL change at the next release while a
    // published sha256 does not.
    const linux = rubyBlock(formula, 'on_linux do').join('\n');
    const archiveUrls = [
      onlyDirective(rubyBlock(formula, 'on_macos do'), 'url'),
      onlyDirective(rubyBlock(linux, 'on_arm do'), 'url'),
      onlyDirective(rubyBlock(linux, 'on_intel do'), 'url'),
      manifest.architecture['64bit'].url,
    ];
    expect(archiveUrls).toHaveLength(4);
    for (const url of archiveUrls) {
      expect(url, url).toContain(VERSIONED_TAG);
      expect(url, url).not.toContain('bin-latest');
    }
  });

  it('names the rolling tag in exactly the two version probes', () => {
    const rolling = [
      onlyDirective(rubyBlock(formula, 'livecheck do'), 'url'),
      manifest.checkver.url,
    ];
    expect(new Set(rolling).size).toBe(1);
    for (const url of rolling) expect(url.endsWith(`${ROLLING_TAG}VERSION`)).toBe(true);

    const rollingLines = formula.split('\n').filter((line) => line.includes('bin-latest'));
    expect(rollingLines).toHaveLength(1);
  });

  it('leaves the $version template in exactly the two autoupdate URLs', () => {
    const update = manifest.autoupdate;
    const urls = [update.architecture['64bit'].url, update.hash.url];
    expect(urls).toHaveLength(2);
    const templated = urls.filter((url) => url.includes('bin-v$version'));
    expect(templated).toHaveLength(2);
    // Nothing reads the token in the formula, so nothing there may carry it.
    expect(renderFormula(input())).not.toContain('$version');
  });
});

describe('VERSION', () => {
  it('is the bare version and a trailing newline', () => {
    expect(renderVersionFile(VERSION)).toBe(`${VERSION}\n`);
  });

  it('is matched by both version probes', () => {
    // A shape control over JavaScript approximations of a Ruby and a .NET
    // engine, not a proof about either of them.
    const formula = renderFormula(input());
    const rubyRegex = /regex\(\/(.*)\/i\)/.exec(formula)?.[1] ?? '';
    expect(rubyRegex, 'the livecheck block carries no regex').not.toBe('');
    const { checkver } = scoop(renderScoopManifest(input()));
    for (const source of [rubyRegex, checkver.regex]) {
      expect(new RegExp(source).exec(renderVersionFile(VERSION).trim())?.[1], source).toBe(VERSION);
    }
  });
});

describe('refusals', () => {
  it('refuses a version that is not bare X.Y.Z', () => {
    for (const version of ['0.9', '0.9.11-beta.1', 'v0.9.11', '', '9.9.9 ']) {
      const err = errorFrom(() => renderFormula(input({ version })));
      expect(err, version).toBeInstanceOf(ManifestInputError);
      expect(err?.message, version).toContain('bare X.Y.Z');
    }
  });

  it('refuses a repo that is not owner/name', () => {
    for (const repo of ['akasecurity', 'https://github.com/akasecurity/ai-tc', 'a/b/c', '']) {
      const err = errorFrom(() => renderFormula(input({ repo })));
      expect(err, repo).toBeInstanceOf(ManifestInputError);
      expect(err?.message, repo).toContain('<owner>/<name>');
    }
  });

  it('names every missing archive, not only the first', () => {
    const err = errorFrom(() =>
      renderFormula(input({ sums: parseSums(sumsWithout('linux-x64', 'win32-x64')) })),
    );
    expect(err).toBeInstanceOf(ManifestInputError);
    const message = err?.message ?? '';
    const first = assetName(VERSION, 'linux-x64');
    const second = assetName(VERSION, 'win32-x64');
    expect(first.includes(second) || second.includes(first)).toBe(false);
    expect(message).toContain(first);
    expect(message).toContain(second);
  });

  it('names the one missing archive when only one is absent', () => {
    const err = errorFrom(() =>
      renderScoopManifest(input({ sums: parseSums(sumsWithout('darwin-arm64')) })),
    );
    expect(err).toBeInstanceOf(ManifestInputError);
    expect(err?.message).toContain(assetName(VERSION, 'darwin-arm64'));
  });

  it('refuses a hash that is not 64 lowercase hex, naming the file it belongs to', () => {
    const good = fixtureHash('win32-x64');
    const name = assetName(VERSION, 'win32-x64');
    for (const hash of [good.slice(0, 63), good.toUpperCase(), `${good}ab`]) {
      const err = errorFrom(() => parseSums(`${hash}  ${name}\n`));
      expect(err, hash).toBeInstanceOf(ManifestInputError);
      expect(err?.message, hash).toContain(name);
      expect(err?.message, hash).toContain('64 lowercase hex');
    }
  });

  it('refuses a line it cannot read, naming the line number', () => {
    // A non-hex hash never reaches the length test: the line shape is what
    // fails, so the refusal names a line rather than a file.
    for (const text of [`${'z'.repeat(64)}  aka.zip\n`, 'aka-9.9.9-win32-x64.zip\n', '   x\n']) {
      const err = errorFrom(() => parseSums(text));
      expect(err, text).toBeInstanceOf(ManifestInputError);
      expect(err?.message, text).toContain('line 1');
      expect(err?.message, text).toContain('<sha256>  <filename>');
    }
  });

  it('refuses a filename listed twice', () => {
    const name = assetName(VERSION, 'win32-x64');
    const err = errorFrom(() =>
      parseSums(`${'a'.repeat(64)}  ${name}\n${'b'.repeat(64)}  ${name}\n`),
    );
    expect(err).toBeInstanceOf(ManifestInputError);
    expect(err?.message).toContain(name);
    expect(err?.message).toContain('twice');
  });
});

describe('the entry', () => {
  let out = '';
  let errors: string[] = [];
  const io = (over: Partial<EntryIo> = {}): EntryIo => ({
    ...defaultIo,
    writeErr: (text) => errors.push(text),
    ...over,
  });
  const argv = (): string[] => [
    '--version',
    VERSION,
    '--repo',
    REPO,
    '--sums',
    FIXTURE_PATH,
    '--out',
    out,
  ];

  beforeEach(() => {
    out = mkdtempSync(join(tmpdir(), 'aka-package-manifests-'));
    errors = [];
  });

  afterEach(() => {
    rmSync(out, { recursive: true, force: true });
  });

  it('writes exactly the three files on a complete sums file', () => {
    expect(main(argv(), io())).toBe(0);
    expect(errors).toEqual([]);
    expect(readdirSync(out).sort()).toEqual([...OUTPUT_NAMES].sort());
    expect(readFileSync(join(out, 'VERSION'), 'utf8')).toBe(`${VERSION}\n`);
    expect(readFileSync(join(out, 'aka.rb'), 'utf8')).toContain('class Aka < Formula');
    expect(scoop(readFileSync(join(out, 'aka.json'), 'utf8')).bin).toBe('aka.exe');
  });

  it('writes nothing at all when a later renderer refuses', () => {
    const sentinel = join(out, 'sentinel.txt');
    writeFileSync(sentinel, 'untouched');
    const boom = io({
      renderers: {
        ...defaultIo.renderers,
        scoop: () => {
          throw new ManifestInputError('the second renderer refused');
        },
      },
    });

    expect(main(argv(), boom)).toBe(1);
    expect(errors.join('')).toContain('the second renderer refused');
    expect(readdirSync(out)).toEqual(['sentinel.txt']);
    expect(readFileSync(sentinel, 'utf8')).toBe('untouched');
  });

  it('refuses an absent --repo rather than assuming one', () => {
    const without = argv().filter((token, index, all) => {
      const previous = all.at(index - 1);
      return token !== '--repo' && previous !== '--repo';
    });
    expect(main(without, io())).toBe(1);
    expect(errors.join('')).toContain('--repo is required');
    expect(readdirSync(out)).toEqual([]);
  });

  it('refuses a flag whose value is missing or is the next flag', () => {
    expect(main(['--version', '--repo', REPO], io())).toBe(1);
    expect(errors.join('')).toContain('--version is required');
  });

  it('accepts the --name=value form', () => {
    expect(
      main(
        [`--version=${VERSION}`, `--repo=${REPO}`, `--sums=${FIXTURE_PATH}`, `--out=${out}`],
        io(),
      ),
    ).toBe(0);
    expect(readdirSync(out).sort()).toEqual([...OUTPUT_NAMES].sort());
  });

  it('refuses --name= carrying nothing after the equals sign', () => {
    // An empty value reaching the renderer renders a homepage of
    // `https://github.com/` and archive urls under a tag that cannot exist.
    const empty = ['--version=', `--repo=${REPO}`, `--sums=${FIXTURE_PATH}`, `--out=${out}`];
    expect(main(empty, io())).toBe(1);
    expect(errors.join('')).toContain('--version is required');
    expect(readdirSync(out)).toEqual([]);
  });

  it('reports a bad sums file and writes nothing', () => {
    const bad = join(out, 'broken');
    writeFileSync(bad, 'not a sums line\n');
    const withBad = argv().map((token) => (token === FIXTURE_PATH ? bad : token));
    expect(main(withBad, io())).toBe(1);
    expect(errors.join('')).toContain('package-manifests: ');
    expect(readdirSync(out)).toEqual(['broken']);
  });
});

describe('the entry as the release job runs it', () => {
  const SRC = join(import.meta.dirname, '..', 'src');
  const ENTRY = join(SRC, 'render-manifests.ts');
  let scratch = '';

  beforeEach(() => {
    scratch = mkdtempSync(join(tmpdir(), 'aka-package-manifests-run-'));
  });

  afterEach(() => {
    rmSync(scratch, { recursive: true, force: true });
  });

  const run = (args: readonly string[]) =>
    spawnSync(process.execPath, [...args], { encoding: 'utf8', timeout: 20_000 });
  const fullArgs = (entry: string, out: string): string[] => [
    entry,
    '--version',
    VERSION,
    '--repo',
    REPO,
    '--sums',
    FIXTURE_PATH,
    '--out',
    out,
  ];

  it('renders all three files under plain node, with nothing but type stripping', (ctx) => {
    if (!process.features.typescript) ctx.skip('this node cannot strip types');
    const out = join(scratch, 'out');
    const result = run(fullArgs(ENTRY, out));
    expect(result.stderr).toBe('');
    expect(result.status).toBe(0);
    expect(readdirSync(out).sort()).toEqual([...OUTPUT_NAMES].sort());
    expect(readFileSync(join(out, 'aka.rb'), 'utf8')).toBe(renderFormula(input()));
  });

  it('still runs when reached through a symlinked path', (ctx) => {
    if (!process.features.typescript) ctx.skip('this node cannot strip types');
    const link = join(scratch, 'src-link');
    try {
      symlinkSync(SRC, link, 'dir');
    } catch (err) {
      ctx.skip(`this platform refused a directory symlink: ${String(err)}`);
    }
    const out = join(scratch, 'out');
    const result = run(fullArgs(join(link, 'render-manifests.ts'), out));
    expect(result.status).toBe(0);
    expect(readdirSync(out).sort()).toEqual([...OUTPUT_NAMES].sort());
  });

  it('exits non-zero and writes nothing on a refusal', (ctx) => {
    if (!process.features.typescript) ctx.skip('this node cannot strip types');
    const out = join(scratch, 'out');
    const result = run([ENTRY, '--version', VERSION, '--out', out]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('--repo is required');
    expect(existsSync(out)).toBe(false);
  });

  it('recognises only its own module as the entry', () => {
    const self = pathToFileURL(ENTRY).href;
    expect(isEntry(ENTRY, self)).toBe(true);
    expect(isEntry(undefined, self)).toBe(false);
    expect(isEntry(join(SRC, 'lib.ts'), self)).toBe(false);
    expect(isEntry(join(scratch, 'absent.ts'), self)).toBe(false);
  });

  it('imports nothing but node builtins and its sibling, since the job installs nothing', () => {
    const files = readdirSync(SRC).filter((name) => name.endsWith('.ts'));
    expect(files.sort()).toEqual(['lib.ts', 'render-manifests.ts']);
    const specifiers: string[] = [];
    for (const name of files) {
      const source = readFileSync(join(SRC, name), 'utf8');
      for (const matched of source.matchAll(/\bfrom\s+'([^']+)'|\bimport\s*\(\s*'([^']+)'/g)) {
        specifiers.push(matched[1] ?? matched[2] ?? '');
      }
    }
    expect(specifiers.length, 'no import was found at all').toBeGreaterThan(0);
    for (const specifier of specifiers) {
      expect(specifier.startsWith('node:') || /^\.\/[\w-]+\.ts$/.test(specifier), specifier).toBe(
        true,
      );
    }
  });
});

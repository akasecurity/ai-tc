// The fixture bar: what a declaring adapter must carry before its network
// half is trusted, and the hard pin that keeps today's emptiness VISIBLE
// rather than a green check nobody is reading. See
// test/helpers/fixture-bar.ts for why EXPECTED_DECLARING_ADAPTERS is an
// exact-set assertion rather than a reported count.
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SOURCE_TOOL } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { CompiledEndpoint } from '../../src/bridge.ts';
import { classifyCompiled, compileEndpoints, resolveField } from '../../src/bridge.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';
import { ADAPTERS } from '../../src/providers/registry.ts';
import type {
  ParsedRequest,
  ProviderAdapter,
  ProviderEndpoint,
  WebExchangeSummary,
} from '../../src/providers/types.ts';
import { assertDeclarableTokens } from '../../src/sanitize/classify.ts';
import { createDetector } from '../../src/sanitize/detector.ts';
import type { FixtureBarOptions } from '../helpers/fixture-bar.ts';
import {
  ACCOUNT_FIXTURE,
  adapterSource,
  APPROVED_KEYS_FILE,
  APPROVED_VALUES_FILE,
  assertApprovalsAreApprovable,
  assertDeclarationsAppearInSource,
  assertDeclarationsAreDetectorClean,
  assertFixtureFullySanitised,
  assertStreamFixtureIsMultiChunk,
  assertValidFixture,
  belowFixtureBar,
  EXPECTED_DECLARING_ADAPTERS,
  EXPECTED_PROTOCOL_TOKENS,
  fixtureDir,
  loadApprovals,
  loadFixture,
  missingFixtures,
  REQUEST_FIXTURE,
  STREAM_FIXTURE,
} from '../helpers/fixture-bar.ts';
import { matchedExchangeFor } from '../helpers/matched-exchange.ts';
import { errorFrom, expectNoEchoOf } from '../helpers/no-echo.ts';

// The REAL engine, not a stub: the bar's whole point is to re-judge a
// committed fixture against the packs as they stand now, and a fake detector
// would make that check report clean for ever.
const detect = createDetector();

const declaring = ADAPTERS.filter((a) => a.endpoints.length > 0);
const nonDeclaring = ADAPTERS.filter((a) => a.endpoints.length === 0);

describe('registry partition (anti-vacuity)', () => {
  it('B1: the registry is non-empty and the declaring/non-declaring partition is exhaustive', () => {
    expect(ADAPTERS.length).toBeGreaterThanOrEqual(2);
    expect(declaring.length + nonDeclaring.length).toBe(ADAPTERS.length);
    expect(nonDeclaring.length).toBeGreaterThanOrEqual(1);
  });
});

describe('the declaring set is pinned', () => {
  it('B2: matches EXPECTED_DECLARING_ADAPTERS exactly', () => {
    expect(declaring.map((a) => a.id)).toEqual([...EXPECTED_DECLARING_ADAPTERS]);
  });
});

describe('a declaring adapter must observe a conversation', () => {
  it('B3: every declaring adapter declares at least one conversation endpoint', () => {
    for (const adapter of declaring) {
      const conversationCount = adapter.endpoints.filter((e) => e.kind === 'conversation').length;
      expect(
        conversationCount,
        `adapter "${adapter.id}" declares an endpoint but no conversation kind`,
      ).toBeGreaterThan(0);
    }
  });
});

describe('non-declaring adapters (runs today)', () => {
  for (const adapter of nonDeclaring) {
    describe(adapter.id, () => {
      it('carries no fixtures directory', () => {
        expect(fixtureExistsAny(adapter.id)).toBe(false);
      });

      it('parseStream() does not throw and end() reports null', () => {
        const assembler = adapter.parseStream(matchedExchangeFor(adapter));
        expect(() => assembler.end()).not.toThrow();
        expect(assembler.end()).toBeNull();
      });

      it("parseRequest('{}') does not throw and reports requiredPathsSeen: false", () => {
        let parsed: ParsedRequest | undefined;
        expect(() => {
          parsed = adapter.parseRequest('{}');
        }).not.toThrow();
        expect(parsed?.requiredPathsSeen).toBe(false);
      });
    });
  }
});

function fixtureExistsAny(site: WebSourceTool): boolean {
  try {
    return statSync(fixtureDir(site)).isDirectory();
  } catch {
    return false;
  }
}

// Not wrapped in an outer describe(): with `declaring` empty today, a
// wrapping describe would have no children at all, and vitest treats an
// empty describe as an error rather than a vacuous pass — exactly the
// silent-green shape this whole file exists to avoid. Each per-adapter
// describe below is created only when there is an adapter to describe, so
// zero adapters means zero describes, not one empty one.
for (const adapter of declaring) {
  describe(`declaring adapter: ${adapter.id}`, () => {
    const conversationEndpointCount = adapter.endpoints.filter(
      (e) => e.kind === 'conversation',
    ).length;
    const accountEndpointCount = adapter.endpoints.filter((e) => e.kind === 'account').length;

    it('carries the fixtures its declared endpoint kinds require', () => {
      const missing = missingFixtures(adapter.id, conversationEndpointCount, accountEndpointCount);
      expect(missing, belowFixtureBar(adapter.id, adapter.endpoints.length, missing)).toEqual([]);
    });

    const compiled = compileEndpoints(adapter);
    const approvals = loadApprovals(adapter.id);
    const barOptions: FixtureBarOptions = {
      allowedHosts: adapter.hostnames,
      detect,
      protocolTokens: new Set(adapter.protocolTokens),
    };

    it('every approvals entry is one the sanitiser would have preserved', () => {
      assertApprovalsAreApprovable(adapter.id, approvals, detect);
    });

    if (conversationEndpointCount > 0) {
      it('request.json is a valid, fully sanitised, conversation/request fixture matching this adapter', () => {
        const fixture = loadFixture(adapter.id, REQUEST_FIXTURE);
        assertValidFixture(`${adapter.id}/${REQUEST_FIXTURE}`, fixture);
        assertFixtureFullySanitised(
          `${adapter.id}/${REQUEST_FIXTURE}`,
          fixture,
          approvals,
          barOptions,
        );
        expect(fixture.site).toBe(adapter.id);
        expect(fixture.kind).toBe('conversation');
        expect(fixture.direction).toBe('request');
        expect(['json', 'urlencoded']).toContain(fixture.format);
        expect(classifyCompiled(compiled, fixture.url)).toBe('conversation');
      });

      it('stream.json is a valid, fully sanitised, conversation/response fixture matching this adapter', () => {
        const fixture = loadFixture(adapter.id, STREAM_FIXTURE);
        assertValidFixture(`${adapter.id}/${STREAM_FIXTURE}`, fixture);
        assertFixtureFullySanitised(
          `${adapter.id}/${STREAM_FIXTURE}`,
          fixture,
          approvals,
          barOptions,
        );
        assertStreamFixtureIsMultiChunk(`${adapter.id}/${STREAM_FIXTURE}`, fixture);
        expect(fixture.site).toBe(adapter.id);
        expect(fixture.kind).toBe('conversation');
        expect(fixture.direction).toBe('response');
        expect(classifyCompiled(compiled, fixture.url)).toBe('conversation');
      });

      it('adapter.parseRequest() satisfies its own required request paths', () => {
        const fixture = loadFixture(adapter.id, REQUEST_FIXTURE);
        const body = fixture.chunks.join('');
        const parsed = adapter.parseRequest(body);
        expect(parsed.requiredPathsSeen).toBe(true);
        const decoded: unknown =
          fixture.format === 'urlencoded'
            ? Object.fromEntries(new URLSearchParams(body))
            : JSON.parse(body);
        for (const path of adapter.requiredPaths.request) {
          expect(resolveField(decoded, path), `request path "${path}"`).not.toBeUndefined();
        }
      });

      it('replaying stream.json yields a summary satisfying its own required response paths', () => {
        const fixture = loadFixture(adapter.id, STREAM_FIXTURE);
        const assembler = adapter.parseStream(matchedExchangeFor(adapter, fixture.url));
        for (const chunk of fixture.chunks) assembler.push(chunk);
        const summary = assembler.end();
        expect(summary).not.toBeNull();
        expect(summary?.messageId.trim()).not.toBe('');
        for (const path of adapter.requiredPaths.response) {
          expect(resolveField(summary, path), `response path "${path}"`).not.toBeUndefined();
        }
      });

      it('the parser survives every robustness shape', () => {
        const fixture = loadFixture(adapter.id, STREAM_FIXTURE);
        const joined = fixture.chunks.join('');

        function expectSurvives(chunks: readonly string[]): void {
          const assembler = adapter.parseStream(matchedExchangeFor(adapter, fixture.url));
          expect(() => {
            for (const c of chunks) assembler.push(c);
          }).not.toThrow();
          let summary: WebExchangeSummary | null | undefined;
          expect(() => {
            summary = assembler.end();
          }).not.toThrow();
          if (summary !== null && summary !== undefined) {
            expect(summary.messageId.trim()).not.toBe('');
          }
        }

        // (a) truncated at 1/4, 1/2, 3/4
        for (const frac of [0.25, 0.5, 0.75]) {
          expectSurvives([joined.slice(0, Math.floor(joined.length * frac))]);
        }
        // (b) reverse order
        expectSurvives([...fixture.chunks].reverse());
        // (c) re-split into 1-character pieces
        expectSurvives(joined.split(''));
        // (d) synthetic unknown event inserted
        const unknownEvent = 'event: __aka_unknown__\ndata: {"__aka":1}\n\n';
        if (fixture.format === 'sse') {
          expectSurvives([...fixture.chunks, unknownEvent]);
        } else {
          expectSurvives([...fixture.chunks, '{"__aka_unknown__":1}']);
        }
        // (e) garbage
        for (const garbage of ['', ' ￿{{{', '['.repeat(4096), 'a'.repeat(64 * 1024)]) {
          expectSurvives([garbage]);
        }
        // (f) end() called twice
        {
          const assembler = adapter.parseStream(matchedExchangeFor(adapter, fixture.url));
          for (const c of fixture.chunks) assembler.push(c);
          assembler.end();
          expect(() => assembler.end()).not.toThrow();
        }
        // (g) end() with no push at all
        {
          const assembler = adapter.parseStream(matchedExchangeFor(adapter, fixture.url));
          expect(() => assembler.end()).not.toThrow();
        }
      });
    }

    if (accountEndpointCount > 0) {
      it('account.json is a valid, fully sanitised, account/response fixture matching this adapter', () => {
        const fixture = loadFixture(adapter.id, ACCOUNT_FIXTURE);
        assertValidFixture(`${adapter.id}/${ACCOUNT_FIXTURE}`, fixture);
        assertFixtureFullySanitised(
          `${adapter.id}/${ACCOUNT_FIXTURE}`,
          fixture,
          approvals,
          barOptions,
        );
        expect(fixture.site).toBe(adapter.id);
        expect(fixture.kind).toBe('account');
        expect(fixture.direction).toBe('response');
        expect(classifyCompiled(compiled, fixture.url)).toBe('account');
      });
    }
  });
}

describe('the bar FIRES (non-vacuous today: driven against a site with no fixtures)', () => {
  // With EXPECTED_DECLARING_ADAPTERS empty, the per-adapter block above
  // generates no test at all — so nothing would ever have observed this bar
  // rejecting anything, and the day somebody declares a guessed endpoint the
  // reviewer sees the same green tick. These drive the SAME missingFixtures
  // the block above calls, against a site whose fixtures directory does not
  // exist, which is the state every site is in today.
  const site = ADAPTERS[0]?.id;

  it('B4: a declared conversation endpoint with no fixtures names every artifact it owes', () => {
    expect(site).toBeDefined();
    if (site === undefined) return;
    expect(fixtureExistsAny(site)).toBe(false);
    const missing = missingFixtures(site, 1, 0);
    expect(missing).toEqual([
      `${site}/${REQUEST_FIXTURE}`,
      `${site}/${STREAM_FIXTURE}`,
      `${site}/${APPROVED_KEYS_FILE}`,
      `${site}/${APPROVED_VALUES_FILE}`,
    ]);
  });

  it('B5: a declared account endpoint additionally owes account.json', () => {
    expect(site).toBeDefined();
    if (site === undefined) return;
    expect(missingFixtures(site, 1, 1)).toContain(`${site}/${ACCOUNT_FIXTURE}`);
  });

  it('B6: the message a reviewer reads names the site, the shortfall and the remedy', () => {
    expect(site).toBeDefined();
    if (site === undefined) return;
    const missing = missingFixtures(site, 1, 0);
    const message = belowFixtureBar(site, 1, missing);
    expect(message).toContain(site);
    expect(message).toContain(`${site}/${REQUEST_FIXTURE}`);
    expect(message).toContain('EXPECTED_DECLARING_ADAPTERS');
    expect(message).toContain('Do not hand-write a fixture');
  });
});

describe('classifyCompiled (non-vacuous today: a synthetic adapter, not a registry one)', () => {
  const table: CompiledEndpoint[] = [
    {
      host: 'chatgpt.com',
      path: /^\/backend-api\/conversation(?:\/|$)/,
      kind: 'conversation',
      source: {
        host: 'chatgpt.com',
        path: /^\/backend-api\/conversation(?:\/|$)/,
        kind: 'conversation',
      },
    },
    {
      host: 'chatgpt.com',
      path: /^\/backend-api\/accounts(?:\/|$)/,
      kind: 'account',
      source: { host: 'chatgpt.com', path: /^\/backend-api\/accounts(?:\/|$)/, kind: 'account' },
    },
  ];

  it('B7: exact host match is required', () => {
    expect(classifyCompiled(table, 'https://chatgpt.com/backend-api/conversation/x')).toBe(
      'conversation',
    );
    expect(
      classifyCompiled(table, 'https://evil-chatgpt.com/backend-api/conversation/x'),
    ).toBeNull();
    expect(
      classifyCompiled(table, 'https://not-chatgpt.com/backend-api/conversation/x'),
    ).toBeNull();
  });

  it('B7: the path is anchored at the start', () => {
    expect(classifyCompiled(table, 'https://chatgpt.com/x/backend-api/conversation')).toBeNull();
  });

  it('B7: a pattern written for one site does not match another origin whose URL merely contains its text', () => {
    const url = 'https://attacker.example/?redirect=https://chatgpt.com/backend-api/conversation/x';
    expect(classifyCompiled(table, url)).toBeNull();
  });

  it('B7: an unparseable URL classifies to null rather than throwing', () => {
    expect(classifyCompiled(table, 'not a url at all')).toBeNull();
  });

  it('B7: an endpoint whose pattern fails to compile is dropped, not matched', () => {
    const hostileEndpoint = {
      host: 'chatgpt.com',
      get path(): RegExp {
        throw new Error('boom');
      },
      kind: 'conversation',
    } as unknown as ProviderEndpoint;
    const hostileAdapter = {
      id: 'chatgpt',
      endpoints: [hostileEndpoint],
    } as unknown as ProviderAdapter;
    const compiled = compileEndpoints(hostileAdapter);
    expect(compiled).toEqual([]);
    expect(classifyCompiled(compiled, 'https://chatgpt.com/backend-api/conversation/x')).toBeNull();
  });
});

// The one reading of an import B8 applies: every specifier in `source` that
// resolves into src/sanitize/ from `importer`, a package-relative posix path as
// `git ls-files` prints it. The specimens and the tree scan below both call it,
// so each form a specimen proves is a form the scan reads.
//
// It matches the SHAPE of an import and does not parse code: `from '…'` (a
// static import, or an `export … from`), a side-effect `import '…'`, a dynamic
// `import(…)` and `require(…)`. Whitespace, newlines, and block and line
// comments may sit between the keyword, a parenthesis and the specifier, in any
// number and order. The specifier is in either quote or a backtick and is read
// no further than its own line. Only literal text is read, so a specifier whose
// directory is computed at runtime is invisible to it. A comment shaped like an
// import counts as one: telling it apart from code means finding where comments
// start, which strings and regex literals make a pattern get wrong, and deleting
// a dead import is the cheaper fix. Prose that names the directory without that
// shape does not count.
//
// The whole shape sits in a lookahead, so a match consumes no text and every
// keyword is tried where it stands. A keyword in prose or at the end of a string
// opens a false match at the quote or backtick after it, and that false match
// cannot carry the scan past a real import. Two keywords reach one specifier
// when a line comment ending in one sits before it, so a specifier is counted
// once per offset. No gap can be split into whitespace and comments two ways, so
// a try costs what it reads.
//
// A relative specifier is resolved against its importer rather than matched as
// text, so `./sanitizer/` or a same-named directory elsewhere is not a hit and
// `./sanitize`, naming the directory itself, is. A bare specifier is skipped:
// this package declares no `exports`, and neither tsconfig nor either build maps
// an alias onto src/, so one cannot reach the directory.
function sanitiserImportsIn(importer: string, source: string): string[] {
  const gap = String.raw`(?:\s|/\*[^*]*\*+(?:[^/*][^*]*\*+)*/|//[^\n]*\n)*`;
  const keyword = String.raw`\bfrom|\bimport(?:${gap}\()?|\brequire${gap}\(`;
  const quoted = String.raw`'([^'\n]*)'|"([^"\n]*)"|\`([^\`\n]*)\``;
  const importShape = new RegExp(`(?=((?:${keyword})${gap})(?:${quoted}))`, 'g');
  const counted = new Set<number>();
  const found: string[] = [];
  for (const match of source.matchAll(importShape)) {
    const specifier = match[2] ?? match[3] ?? match[4] ?? '';
    const offset = match.index + (match[1] ?? '').length;
    if (counted.has(offset) || !specifier.startsWith('.')) continue;
    counted.add(offset);
    const segments = importer.split('/').slice(0, -1);
    for (const part of specifier.split('/')) {
      if (part === '..') segments.pop();
      else if (part !== '.' && part !== '') segments.push(part);
    }
    const resolved = segments.join('/');
    if (resolved === 'src/sanitize' || resolved.startsWith('src/sanitize/')) {
      found.push(specifier);
    }
  }
  return found;
}

const packageRoot = fileURLToPath(new URL('../..', import.meta.url));

// The tree scan's read of one file: what sanitiserImportsIn finds in the file at
// `relPath`, or null when the working tree no longer has it. The one path both
// locates the file and is the importer the matcher resolves against, and the
// matcher reports a hit only for an importer spelled from the package root
// ('src/…'). A control drives this function on a real file, so a read that
// handed the matcher any other spelling would empty the scan and be seen to.
function sanitiserImportsInFile(relPath: string): string[] | null {
  let contents: string;
  try {
    contents = readFileSync(join(packageRoot, relPath), 'utf8');
  } catch (error) {
    // A tracked file deleted from the working tree imports nothing. Any other
    // failed read would drop a file out of the scan unseen.
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
  return sanitiserImportsIn(relPath, contents);
}

describe('the sanitiser stays a dev tool (B8)', () => {
  // The positive controls for the tree scan: its empty offender list means
  // nothing unless the same matcher is seen to flag every form it claims to
  // read. Each importer is one the specifier really resolves into src/sanitize/
  // from.
  const flagged = [
    {
      form: 'a static import',
      importer: 'src/providers/chatgpt.ts',
      source: "import { createDetector } from '../sanitize/detector.ts';",
      specifier: '../sanitize/detector.ts',
    },
    {
      form: 'a type import split across lines',
      importer: 'src/providers/chatgpt.ts',
      source: 'import type {\n  Detector,\n} from "../sanitize/detector.ts";',
      specifier: '../sanitize/detector.ts',
    },
    {
      form: 'an export-from',
      importer: 'src/providers/registry.ts',
      source: "export { classify } from '../sanitize/classify.ts';",
      specifier: '../sanitize/classify.ts',
    },
    {
      form: 'a side-effect import',
      importer: 'src/background.ts',
      source: "import './sanitize/index.ts';",
      specifier: './sanitize/index.ts',
    },
    {
      form: 'a dynamic import',
      importer: 'src/content.ts',
      source: "const engine = await import('./sanitize/detector.ts');",
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a dynamic import with whitespace and a newline before the specifier',
      importer: 'src/content.ts',
      source: 'void import (\n  "./sanitize/detector.ts"\n);',
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a dynamic import of a template literal',
      importer: 'src/content.ts',
      source: 'void import(`./sanitize/detector.ts`);',
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a dynamic import of the directory itself',
      importer: 'src/content.ts',
      source: "void import('./sanitize');",
      specifier: './sanitize',
    },
    {
      form: 'a require',
      importer: 'src/native-host/host.ts',
      source: "const { createDetector } = require('../sanitize/detector.ts');",
      specifier: '../sanitize/detector.ts',
    },
    {
      form: 'a commented-out import',
      importer: 'src/content.ts',
      source: "// import { createDetector } from './sanitize/detector.ts';",
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a dynamic import with a block comment before the specifier',
      importer: 'src/content.ts',
      source: 'void import(/* lazy */ "./sanitize/detector.ts");',
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a dynamic import with a line comment before the specifier',
      importer: 'src/content.ts',
      source: "const engine = await import(\n  // lazy\n  './sanitize/detector.ts'\n);",
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a static import with comments and whitespace interleaved before the specifier',
      importer: 'src/providers/chatgpt.ts',
      source:
        "import { createDetector } from /* engine */\n  // eager\n  '../sanitize/detector.ts';",
      specifier: '../sanitize/detector.ts',
    },
    {
      form: 'a dynamic import with a comment before its parenthesis',
      importer: 'src/content.ts',
      source: "void import /* lazy */ ('./sanitize/detector.ts');",
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a require with a comment before its parenthesis',
      importer: 'src/native-host/host.ts',
      source: "const { createDetector } = require /* sync */ ('../sanitize/detector.ts');",
      specifier: '../sanitize/detector.ts',
    },
    {
      // The comment's last word is a keyword whose own match reaches the same
      // specifier as the dynamic import's.
      form: 'a specifier two keywords reach, once',
      importer: 'src/content.ts',
      source:
        "void import(\n  // loaded here, not by a static import\n  './sanitize/detector.ts'\n);",
      specifier: './sanitize/detector.ts',
    },
    // A keyword the matcher tries before each real import below is followed by
    // a closing quote or backtick. After a quote, the next quote on the same
    // line closes a false match that runs over the real import; after a
    // backtick, the specifier's line bound stops one before the backtick further
    // down can close it. Either would hide the import if a match consumed text.
    {
      form: 'a dynamic import below a comment naming import in backticks',
      importer: 'src/content.ts',
      source:
        '// loaded by a dynamic `import`\nconst engine = await import("./sanitize/detector.ts");\nconst label = `engine`;',
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a static import below a comment naming from in backticks',
      importer: 'src/content.ts',
      source:
        "// values are read `from` the page\nimport { createDetector } from './sanitize/detector.ts';\nconst label = `detector`;",
      specifier: './sanitize/detector.ts',
    },
    {
      form: 'a dynamic import after a string that ends in a keyword on its line',
      importer: 'src/content.ts',
      source: "const label = 'read from '; void import('./sanitize/detector.ts');",
      specifier: './sanitize/detector.ts',
    },
  ];
  for (const { form, importer, source, specifier } of flagged) {
    it(`B8 (anti-vacuity): the matcher flags ${form}`, () => {
      expect(sanitiserImportsIn(importer, source)).toEqual([specifier]);
    });
  }

  // Paths that only resemble the directory. Each sits beside a real import of
  // it, so one assertion shows the lookalike is skipped while the matcher was
  // still reading that source.
  const realImport = "import { createDetector } from './sanitize/detector.ts';";
  const resembling = [
    {
      what: 'a sibling directory whose name extends it',
      line: "import { a } from './sanitizer/index.ts';",
    },
    {
      what: 'a sibling directory whose name starts with it',
      line: "import './sanitize-notes/index.ts';",
    },
    {
      what: 'a same-named directory elsewhere under src/',
      line: "import { a } from './providers/sanitize/index.ts';",
    },
    {
      // Read as relative from src/content.ts, this would land in the directory.
      what: 'a bare specifier',
      line: "import { a } from 'sanitize/detector.ts';",
    },
    {
      what: 'prose naming a relative path into it',
      line: '// the engine loads through ./sanitize/classify.ts',
    },
  ];
  for (const { what, line } of resembling) {
    it(`B8 (anti-vacuity): the matcher skips ${what}`, () => {
      expect(sanitiserImportsIn('src/content.ts', `${line}\n${realImport}`)).toEqual([
        './sanitize/detector.ts',
      ]);
    });
  }

  it('B8 (anti-vacuity): the per-file read flags src/sanitize/index.ts importing its siblings', () => {
    // index.ts re-exports its siblings through './' specifiers, which resolve
    // into src/sanitize/ only from the path spelled the way the scan spells it.
    expect(sanitiserImportsInFile('src/sanitize/index.ts')).toContain('./detector.ts');
  });

  it('no file under src/ outside src/sanitize/ imports src/sanitize/**', () => {
    // Untracked files too: the bundler follows imports rather than the index,
    // so a new importer reds a local run before it is ever committed. -z keeps
    // a name with non-ASCII bytes unquoted, so the extension filter reads it.
    const candidates = execFileSync(
      'git',
      ['ls-files', '-z', '--cached', '--others', '--exclude-standard', 'src'],
      { cwd: packageRoot, encoding: 'utf8' },
    )
      .split('\0')
      .filter((f) => f.length > 0 && !f.startsWith('src/sanitize/'))
      .filter((f) => /\.[cm]?[jt]sx?$/.test(f));

    const scanned: string[] = [];
    const offenders: string[] = [];
    for (const relPath of candidates) {
      const found = sanitiserImportsInFile(relPath);
      if (found === null) continue;
      scanned.push(relPath);
      if (found.length > 0) {
        offenders.push(`${relPath}: ${found.join(', ')}`);
      }
    }
    // content.ts is the script injected into every chat page, so a walk that
    // never read it would report the tree clean without having looked.
    expect(scanned).toContain('src/content.ts');
    expect(offenders).toEqual([]);
  });
});

// The declared protocol token vocabulary: what an adapter's parser may name
// verbatim to the sanitiser. See test/helpers/fixture-bar.ts's
// EXPECTED_PROTOCOL_TOKENS doc comment for why it is a ratchet, and
// src/sanitize/classify.ts's isDeclarableToken for the bound itself.
describe('declared protocol tokens', () => {
  it('PT1: EXPECTED_PROTOCOL_TOKENS matches the registry exactly, per site, in both directions', () => {
    for (const adapter of ADAPTERS) {
      expect([...adapter.protocolTokens].sort(), `adapter "${adapter.id}"`).toEqual(
        [...EXPECTED_PROTOCOL_TOKENS[adapter.id]].sort(),
      );
      // Distinct, because PT6 requires a SECOND quoted occurrence of each
      // token in the adapter's source and a duplicate entry in this very
      // array would supply one without the parser ever naming it.
      expect(new Set(adapter.protocolTokens).size, `adapter "${adapter.id}"`).toBe(
        adapter.protocolTokens.length,
      );
    }
    const registryIds = new Set(ADAPTERS.map((a) => a.id));
    for (const site of Object.keys(EXPECTED_PROTOCOL_TOKENS)) {
      expect(registryIds.has(site as WebSourceTool), `pinned site "${site}"`).toBe(true);
    }
  });

  it('PT2: every adapter in the registry declares only tokens that clear assertDeclarableTokens', () => {
    // Over ALL adapters, declaring or not — a token declared before its
    // endpoints are is still bounded.
    for (const adapter of ADAPTERS) {
      expect(() => {
        assertDeclarableTokens(adapter.id, adapter.protocolTokens);
      }, adapter.id).not.toThrow();
    }
  });

  it('PT3: every declared token in the registry is detector-clean under the real engine', () => {
    for (const adapter of ADAPTERS) {
      expect(() => {
        assertDeclarationsAreDetectorClean(adapter.id, adapter.protocolTokens, detect);
      }, adapter.id).not.toThrow();
    }
  });

  it('PT4 (anti-vacuity): PT2 and PT3 both actually FIRE, driven against a synthetic adapter array', () => {
    // With every real adapter declaring nothing, PT2/PT3 pass over an empty
    // loop body for every adapter — which proves nothing about whether the
    // checks work. This drives assertDeclarableTokens and
    // assertDeclarationsAreDetectorClean directly against a hand-built
    // hostile declaration, so a weakened check (a warning instead of a
    // throw) is caught here even while the registry stays empty.
    const longRun = 'a'.repeat(41);
    expect(() => {
      assertDeclarableTokens('chatgpt', [longRun]);
    }).toThrow(/index 0/);
    expectNoEchoOf(
      errorFrom(() => {
        assertDeclarableTokens('chatgpt', [longRun]);
      })?.message,
      longRun,
    );

    // The whitespace clause and the charset clause are asserted through
    // their DISTINCT messages, not through the shared `index N` wording.
    // VOCABULARY_PATTERN admits no character in `\s`, so a whitespace input
    // reaches the charset clause too — checking only `index 1` passes with
    // the whitespace branch deleted, and then the guarantee the branch names
    // is pinned by nothing.
    const whitespaceToken = 'a b';
    const whitespaceErr = errorFrom(() => {
      assertDeclarableTokens('chatgpt', ['organizations', whitespaceToken]);
    });
    expect(whitespaceErr?.message).toContain('index 1');
    expect(whitespaceErr?.message).toContain('contains whitespace');

    const charsetToken = 'a,b';
    const charsetErr = errorFrom(() => {
      assertDeclarableTokens('chatgpt', ['organizations', charsetToken]);
    });
    expect(charsetErr?.message).toContain('index 1');
    expect(charsetErr?.message).toContain('outside the declarable charset');

    // Verbatim from rules/secrets/stripe-live-key.json's own `examples`.
    const flaggedToken = 'pk_live_wDlmi91dAAKCRu1JBy89Xaq3RZ';
    expect(() => {
      assertDeclarationsAreDetectorClean('chatgpt', [flaggedToken], detect);
    }).toThrow(/secrets\/stripe-live-key/);
    expectNoEchoOf(
      errorFrom(() => {
        assertDeclarationsAreDetectorClean('chatgpt', [flaggedToken], detect);
      })?.message,
      flaggedToken,
    );
  });

  it('PT5: a declaring adapter is judged with its own declared tokens via FixtureBarOptions', () => {
    // Generated over every adapter (not only declaring ones, since none are
    // today) to prove the wiring — `barOptions.protocolTokens` inside the
    // per-adapter loop above is built the same way — is non-vacuous now
    // rather than only once the first adapter declares.
    for (const adapter of ADAPTERS) {
      const options: FixtureBarOptions = {
        allowedHosts: adapter.hostnames,
        detect,
        protocolTokens: new Set(adapter.protocolTokens),
      };
      expect([...options.protocolTokens].sort(), adapter.id).toEqual(
        [...adapter.protocolTokens].sort(),
      );
    }
  });

  it('PT6: every declared token appears in its OWN adapter source, twice', () => {
    for (const adapter of ADAPTERS) {
      const source = adapterSource(adapter.id);
      expect(() => {
        assertDeclarationsAppearInSource(adapter.id, adapter.protocolTokens, source);
      }, adapter.id).not.toThrow();
    }
  });

  it('PT6 (anti-vacuity): the source check FIRES, and reads each adapter its own file', () => {
    // Both adapters declare nothing today, so PT6's loop body never runs for
    // a real token. These drive the check directly.
    const declaredOnly = "  protocolTokens: ['content_block_delta'],";
    const err = errorFrom(() => {
      assertDeclarationsAppearInSource('claude-ai', ['content_block_delta'], declaredOnly);
    });
    expect(err?.message).toContain('appears 1 time(s)');

    const declaredAndUsed = `${declaredOnly}\n    case 'content_block_delta':`;
    expect(() => {
      assertDeclarationsAppearInSource('claude-ai', ['content_block_delta'], declaredAndUsed);
    }).not.toThrow();

    // A backtick code span in a doc comment is NOT a use — claude.ai's own
    // NETWORK HALF note names these tokens that way, so counting backticks
    // would let the prose above a declaration stand in for the dispatch
    // below it.
    const mentionedInProse = `${declaredOnly}\n// see \`content_block_delta\` above`;
    expect(() => {
      assertDeclarationsAppearInSource('claude-ai', ['content_block_delta'], mentionedInProse);
    }).toThrow(/appears 1 time\(s\)/);

    // Each adapter is read its OWN file: a token used only in the other
    // adapter's source must not satisfy this one.
    const chatgptSource = adapterSource(SOURCE_TOOL.ChatGpt);
    expect(() => {
      assertDeclarationsAppearInSource(
        SOURCE_TOOL.ChatGpt,
        ['createClaudeStreamAssembler'],
        chatgptSource,
      );
    }).toThrow(/appears 0 time\(s\)/);
  });
});

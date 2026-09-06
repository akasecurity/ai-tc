// The fixture bar: what a declaring adapter must carry before its network
// half is trusted, and the hard pin that keeps today's emptiness VISIBLE
// rather than a green check nobody is reading. See
// test/helpers/fixture-bar.ts for why EXPECTED_DECLARING_ADAPTERS is an
// exact-set assertion rather than a reported count.
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

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
import { createDetector } from '../../src/sanitize/detector.ts';
import type { FixtureBarOptions } from '../helpers/fixture-bar.ts';
import {
  ACCOUNT_FIXTURE,
  APPROVED_KEYS_FILE,
  APPROVED_VALUES_FILE,
  assertApprovalsAreApprovable,
  assertFixtureFullySanitised,
  assertStreamFixtureIsMultiChunk,
  assertValidFixture,
  belowFixtureBar,
  EXPECTED_DECLARING_ADAPTERS,
  fixtureDir,
  loadApprovals,
  loadFixture,
  missingFixtures,
  REQUEST_FIXTURE,
  STREAM_FIXTURE,
} from '../helpers/fixture-bar.ts';

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
        const assembler = adapter.parseStream();
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
    const barOptions: FixtureBarOptions = { allowedHosts: adapter.hostnames, detect };

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
        const assembler = adapter.parseStream();
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
          const assembler = adapter.parseStream();
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
          const assembler = adapter.parseStream();
          for (const c of fixture.chunks) assembler.push(c);
          assembler.end();
          expect(() => assembler.end()).not.toThrow();
        }
        // (g) end() with no push at all
        {
          const assembler = adapter.parseStream();
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
    { host: 'chatgpt.com', path: /^\/backend-api\/conversation(?:\/|$)/, kind: 'conversation' },
    { host: 'chatgpt.com', path: /^\/backend-api\/accounts(?:\/|$)/, kind: 'account' },
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

describe('the sanitiser stays a dev tool (B8)', () => {
  it('no file under src/ outside src/sanitize/ imports src/sanitize/**', () => {
    const srcRoot = fileURLToPath(new URL('../../src', import.meta.url));
    const tracked = execFileSync('git', ['ls-files', 'src'], {
      cwd: fileURLToPath(new URL('../..', import.meta.url)),
      encoding: 'utf8',
    })
      .split('\n')
      .filter((f) => f.length > 0 && !f.startsWith('src/sanitize/'))
      .filter((f) => f.endsWith('.ts') || f.endsWith('.tsx'));

    const offenders: string[] = [];
    for (const relPath of tracked) {
      const absPath = join(srcRoot, relPath.slice('src/'.length));
      let contents: string;
      try {
        contents = readFileSync(absPath, 'utf8');
      } catch {
        continue;
      }
      if (
        /from\s+['"][^'"]*\/sanitize\//.test(contents) ||
        /import\s+['"][^'"]*\/sanitize\//.test(contents)
      ) {
        offenders.push(relPath);
      }
    }
    expect(offenders).toEqual([]);
  });
});

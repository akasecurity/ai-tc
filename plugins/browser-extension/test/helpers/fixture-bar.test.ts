import { describe, expect, it } from 'vitest';

import type { Detect, SimpleValueClass } from '../../src/sanitize/index.ts';
import {
  FIXTURE_SCHEMA_ID,
  looksLikeSurrogateNumber,
  looksLikeSurrogateString,
  numberSurrogate,
  surrogateFor,
} from '../../src/sanitize/sanitize-capture.ts';
import type { Approvals, FixtureBarOptions } from './fixture-bar.ts';
import {
  assertApprovalsAreApprovable,
  assertFixtureFullySanitised,
  assertStreamFixtureIsMultiChunk,
  assertValidFixture,
  belowFixtureBar,
} from './fixture-bar.ts';

/** A detector that finds nothing — the neutral default for shape-only cases. */
const quiet: Detect = () => [];

function options(overrides: Partial<FixtureBarOptions> = {}): FixtureBarOptions {
  return {
    allowedHosts: ['chatgpt.com'],
    detect: quiet,
    protocolTokens: new Set(),
    ...overrides,
  };
}

function approvals(keys: string[] = [], values: string[] = []): Approvals {
  return { keys: new Set(keys), values: new Set(values) };
}

// A well-formed synthetic fixture — the positive control every malformation
// case below is a one-field mutation of.
function wellFormedFixture(): Record<string, unknown> {
  return {
    $schema: FIXTURE_SCHEMA_ID,
    site: 'chatgpt',
    kind: 'conversation',
    direction: 'request',
    url: 'https://chatgpt.com/TOKEN_4',
    format: 'json',
    chunks: ['{"TOKEN_2":"TOKEN_1","TOKEN_3":7}'],
    surrogates: { strings: ['TOKEN_1', 'TOKEN_2', 'TOKEN_3', 'TOKEN_4'], numbers: [] },
  };
}

/** The error a thunk threw, captured OUTSIDE its own catch. */
function errorFrom(fn: () => void): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (e) {
    return e as Error;
  }
}

describe('assertValidFixture', () => {
  it('F1: passes a well-formed fixture (positive control)', () => {
    expect(() => {
      assertValidFixture('t', wellFormedFixture());
    }).not.toThrow();
  });

  it('F2: throws on a missing $schema', () => {
    const bad = wellFormedFixture();
    delete bad.$schema;
    expect(() => {
      assertValidFixture('t', bad);
    }).toThrow(/\$schema/);
  });

  it('F3: throws on a wrong $schema value', () => {
    const bad = { ...wellFormedFixture(), $schema: 'something-else/1' };
    expect(() => {
      assertValidFixture('t', bad);
    }).toThrow(/\$schema/);
  });

  it('F4: throws on missing, empty, or non-string-element chunks', () => {
    const missing = wellFormedFixture();
    delete missing.chunks;
    expect(() => {
      assertValidFixture('t', missing);
    }).toThrow(/chunks/);

    const empty = { ...wellFormedFixture(), chunks: [] };
    expect(() => {
      assertValidFixture('t', empty);
    }).toThrow(/chunks/);

    const nonString = { ...wellFormedFixture(), chunks: [42] };
    expect(() => {
      assertValidFixture('t', nonString);
    }).toThrow(/chunks/);
  });

  it('F5: throws on missing surrogates', () => {
    const bad = wellFormedFixture();
    delete bad.surrogates;
    expect(() => {
      assertValidFixture('t', bad);
    }).toThrow(/surrogates/);
  });

  it('rejects unsorted or duplicate surrogates.strings', () => {
    const unsorted = {
      ...wellFormedFixture(),
      chunks: ['{}'],
      url: 'https://chatgpt.com/',
      surrogates: { strings: ['b', 'a'], numbers: [] },
    };
    expect(() => {
      assertValidFixture('t', unsorted);
    }).toThrow(/sorted/);

    const dup = {
      ...wellFormedFixture(),
      chunks: ['{}'],
      url: 'https://chatgpt.com/',
      surrogates: { strings: ['a', 'a'], numbers: [] },
    };
    expect(() => {
      assertValidFixture('t', dup);
    }).toThrow(/distinct/);
  });

  it('throws on a non-parseable url', () => {
    const bad = { ...wellFormedFixture(), url: 'not-a-url' };
    expect(() => {
      assertValidFixture('t', bad);
    }).toThrow(/url/);
  });

  it('throws on an invalid kind/direction/format', () => {
    expect(() => {
      assertValidFixture('t', { ...wellFormedFixture(), kind: 'bogus' });
    }).toThrow(/kind/);
    expect(() => {
      assertValidFixture('t', { ...wellFormedFixture(), direction: 'bogus' });
    }).toThrow(/direction/);
    expect(() => {
      assertValidFixture('t', { ...wellFormedFixture(), format: 'bogus' });
    }).toThrow(/format/);
  });
});

describe('surrogates must have the SHAPE the sanitiser emits', () => {
  it('F12: every surrogate the sanitiser really emits is recognised (derived control)', () => {
    const originals: Record<SimpleValueClass, string> = {
      text: 'a whole sentence of prose that is far too long to be a token',
      vocabulary: 'gpt-4o',
      uuid: '123e4567-e89b-12d3-a456-426614174000',
      jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u',
      'iso-datetime': '2026-09-04T11:22:33.000Z',
      email: 'someone@example.com',
      hex: 'deadbeefcafe0123456789ab',
      base64ish: 'QmVhcmVyVG9rZW5MaXZlU2VjcmV0Rm9yUmV2aWV3==',
      'numeric-string': '8837462091',
    };
    for (const [cls, original] of Object.entries(originals)) {
      for (const ordinal of [1, 2, 7, 41]) {
        const surrogate = surrogateFor(cls as SimpleValueClass, ordinal, original);
        expect(looksLikeSurrogateString(surrogate), `${cls} #${String(ordinal)}`).toBe(true);
      }
    }
    // The two forms surrogateFor does not own.
    expect(looksLikeSurrogateString('KEY_12')).toBe(true);
    expect(looksLikeSurrogateString('host-3.invalid')).toBe(true);
  });

  it('F12b: every number surrogate the sanitiser really emits is recognised (derived control)', () => {
    for (const value of [12345, -8837462091, 0.735, 1000000, 3.5, -0.25, 205, 99]) {
      for (const ordinal of [1, 2, 7, 41, 97]) {
        expect(
          looksLikeSurrogateNumber(numberSurrogate(value, ordinal)),
          `${String(value)} #${String(ordinal)}`,
        ).toBe(true);
      }
    }
  });

  it('F13: a fixture cannot declare its own raw values as surrogates', () => {
    // The self-certification attack: list the secret in surrogates.strings and
    // the membership check that draws its allowed set from the same file has
    // nothing to object to.
    const bad = {
      ...wellFormedFixture(),
      chunks: ['{"a":"sk-proj-QmVhcmVyVG9rZW5MaXZlU2VjcmV0Rm9yUmV2aWV3"}'],
      url: 'https://chatgpt.com/',
      surrogates: { strings: ['sk-proj-QmVhcmVyVG9rZW5MaXZlU2VjcmV0Rm9yUmV2aWV3'], numbers: [] },
    };
    expect(() => {
      assertValidFixture('t', bad);
    }).toThrow(/would never emit/);

    const prose = {
      ...bad,
      chunks: ['{"a":"I told my therapist about it"}'],
      surrogates: { strings: ['I told my therapist about it'], numbers: [] },
    };
    expect(() => {
      assertValidFixture('t', prose);
    }).toThrow(/would never emit/);
  });

  it('F13b: a fixture cannot declare a real identifier as a surrogate NUMBER', () => {
    const bad = {
      ...wellFormedFixture(),
      chunks: ['{"user_id":8675309}'],
      url: 'https://chatgpt.com/',
      surrogates: { strings: [], numbers: [8675309] },
    };
    expect(() => {
      assertValidFixture('t', bad);
    }).toThrow(/would never emit/);
  });
});

describe('assertApprovalsAreApprovable', () => {
  it('F14: accepts entries the sanitiser would preserve (positive control)', () => {
    expect(() => {
      assertApprovalsAreApprovable(
        't',
        approvals(['conversation_id', 'parent_message_id'], ['gpt-4o', 'backend-api']),
        quiet,
      );
    }).not.toThrow();
  });

  it('F15: refuses an unpruned survey value pasted in wholesale', () => {
    // Exactly what `--survey` writes: raw candidate strings lifted out of a
    // real capture. None of these clears isVocabularyCandidate, so none of
    // them could ever have been preserved by the tool that produced them.
    for (const value of [
      'Draft the layoff memo for the Thunderbird team by Friday.',
      'alice.smith@acme-internal.example',
      'proj-thunderbird-2026-layoffs',
    ]) {
      expect(() => {
        assertApprovalsAreApprovable('t', approvals([], [value]), quiet);
      }).toThrow(/would never preserve/);
    }
  });

  it('F15b: refuses a key the sanitiser would never preserve, and one the detector flags', () => {
    expect(() => {
      assertApprovalsAreApprovable('t', approvals(['not a key at all']), quiet);
    }).toThrow(/would never preserve/);

    expect(() => {
      assertApprovalsAreApprovable('t', approvals(['session_token'], []), () => ['fake-rule']);
    }).toThrow(/fake-rule/);
    expect(() => {
      assertApprovalsAreApprovable('t', approvals([], ['gpt-4o']), () => ['fake-rule']);
    }).toThrow(/fake-rule/);
  });

  it('PT-F2: an operator cannot widen their own approvals file into the protocol vocabulary', () => {
    // content_block_delta classifies base64ish (not a vocabulary candidate at
    // all) and organizations clears entropy 3.085 >= ENTROPY_THRESHOLD — both
    // measured in src/sanitize/classify.ts's own doc comment. An adapter's
    // `protocolTokens` declaration is judged by the wider isDeclarableToken;
    // an operator's approvals file must stay judged by isVocabularyCandidate,
    // or the operator's local file reaches exactly the vocabulary this whole
    // mechanism exists to keep behind a source-code review.
    for (const value of ['content_block_delta', 'organizations']) {
      expect(() => {
        assertApprovalsAreApprovable('t', approvals([], [value]), quiet);
      }, value).toThrow(/would never preserve/);
    }
  });
});

describe('assertFixtureFullySanitised', () => {
  it('F1: passes a well-formed fixture (positive control)', () => {
    const fixture = wellFormedFixture();
    assertValidFixture('t', fixture);
    expect(() => {
      assertFixtureFullySanitised('t', fixture, approvals(), options());
    }).not.toThrow();
  });

  it('F6: throws on a string leaf that is in neither surrogates nor approvals, and names the path', () => {
    const fixture = {
      ...wellFormedFixture(),
      chunks: ['{"id":"LEAKED_RAW_VALUE"}'],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', fixture);
    const err = errorFrom(() => {
      assertFixtureFullySanitised('t', fixture, approvals(['id']), options());
    });
    expect(err).toBeDefined();
    expect(err?.message).toContain('chunks[0]');
    expect(err?.message).toContain('LEAKED_RAW_VALUE');
  });

  it('an approved value is accepted as a leaf', () => {
    const fixture = {
      ...wellFormedFixture(),
      chunks: ['{"id":"gpt-4o"}'],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', fixture);
    expect(() => {
      assertFixtureFullySanitised('t', fixture, approvals(['id'], ['gpt-4o']), options());
    }).not.toThrow();
  });

  it('F16: keys and values are judged against their OWN approvals file', () => {
    const fixture = {
      ...wellFormedFixture(),
      chunks: ['{"id":"gpt-4o"}'],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', fixture);
    // 'gpt-4o' approved as a KEY does not make it legal as a VALUE.
    expect(() => {
      assertFixtureFullySanitised('t', fixture, approvals(['id', 'gpt-4o']), options());
    }).toThrow(/approved value/);
    // ...and 'id' approved as a VALUE does not make it legal as a KEY.
    expect(() => {
      assertFixtureFullySanitised('t', fixture, approvals([], ['id', 'gpt-4o']), options());
    }).toThrow(/approved key/);
  });

  it('F7: throws on an object key that is in neither surrogates nor approvals', () => {
    const fixture = {
      ...wellFormedFixture(),
      chunks: ['{"leaked_key_name":""}'],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', fixture);
    expect(() => {
      assertFixtureFullySanitised('t', fixture, approvals(), options());
    }).toThrow(/leaked_key_name/);
  });

  it('F8: throws on a number that is not a small integer and not in surrogates.numbers; 7 passes', () => {
    const withBigNumber = {
      ...wellFormedFixture(),
      chunks: ['{"n":12345}'],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', withBigNumber);
    expect(() => {
      assertFixtureFullySanitised('t', withBigNumber, approvals(['n']), options());
    }).toThrow(/12345/);

    const withSmallNumber = { ...withBigNumber, chunks: ['{"n":7}'] };
    assertValidFixture('t', withSmallNumber);
    expect(() => {
      assertFixtureFullySanitised('t', withSmallNumber, approvals(['n']), options());
    }).not.toThrow();
  });

  it('F9: validates a leaf nested inside a JSON-parseable string too', () => {
    const legitimatelyNested = {
      ...wellFormedFixture(),
      chunks: [JSON.stringify({ payload: JSON.stringify({ note: 'hello' }) })],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', legitimatelyNested);
    // Passes only because the nested leaves ('note', 'hello') are approved —
    // proving the walker actually descended into the nested JSON string
    // rather than only checking its raw (never-approved) container text.
    expect(() => {
      assertFixtureFullySanitised(
        't',
        legitimatelyNested,
        approvals(['payload', 'note'], ['hello']),
        options(),
      );
    }).not.toThrow();

    const leakedNested = {
      ...wellFormedFixture(),
      chunks: [JSON.stringify({ payload: JSON.stringify({ note: 'LEAKED_INNER_VALUE' }) })],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', leakedNested);
    expect(() => {
      assertFixtureFullySanitised('t', leakedNested, approvals(['payload', 'note']), options());
    }).toThrow(/LEAKED_INNER_VALUE/);
  });

  it('F10: validates the url as a leaf', () => {
    const fixture = {
      ...wellFormedFixture(),
      chunks: ['{}'],
      surrogates: { strings: [], numbers: [] },
      url: 'https://chatgpt.com/LEAKED_PATH_SEGMENT?q=LEAKED_QUERY_VALUE#LEAKED_FRAGMENT',
    };
    assertValidFixture('t', fixture);
    expect(() => {
      assertFixtureFullySanitised('t', fixture, approvals(), options());
    }).toThrow(/url/);
  });

  it('F17: a URL-shaped leaf has its HOST checked, even with no other components', () => {
    // A URL with empty path, query and fragment used to be decomposed into
    // nothing at all and returned without checkString ever running.
    const inHost = {
      ...wellFormedFixture(),
      chunks: ['{"TOKEN_1":"https://I-told-my-therapist-about-the-affair.example"}'],
      surrogates: { strings: ['TOKEN_1'], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', inHost);
    expect(() => {
      assertFixtureFullySanitised('t', inHost, approvals(), options());
    }).toThrow(/host/);

    // ...and the form the sanitiser really emits is accepted.
    const surrogateHost = {
      ...inHost,
      chunks: ['{"TOKEN_1":"https://host-1.invalid/TOKEN_2"}'],
      surrogates: { strings: ['TOKEN_1', 'TOKEN_2', 'host-1.invalid'], numbers: [] },
    };
    assertValidFixture('t', surrogateHost);
    expect(() => {
      assertFixtureFullySanitised('t', surrogateHost, approvals(), options());
    }).not.toThrow();
  });

  it('F17b: the top-level url host must be one the adapter drives', () => {
    const fixture = { ...wellFormedFixture(), chunks: ['{}'], url: 'https://elsewhere.example/' };
    assertValidFixture('t', fixture);
    expect(() => {
      assertFixtureFullySanitised(
        't',
        fixture,
        approvals(),
        options({ allowedHosts: ['chatgpt.com'] }),
      );
    }).toThrow(/host/);
  });

  it('F18: SSE metadata lines are checked, not only `data:` bodies', () => {
    function sseFixture(chunk: string): Record<string, unknown> {
      return {
        ...wellFormedFixture(),
        format: 'sse',
        direction: 'response',
        url: 'https://chatgpt.com/',
        chunks: [chunk, 'data: {"TOKEN_2":"TOKEN_1"}\n\n'],
        surrogates: { strings: ['TOKEN_1', 'TOKEN_2'], numbers: [] },
      };
    }
    const leaks = [
      'id: sk-live-9f3a2b7c4e1d8a05-REALSECRET\ndata: {"TOKEN_2":"TOKEN_1"}\n\n',
      'event: alice.smith@acme-internal.example\ndata: {"TOKEN_2":"TOKEN_1"}\n\n',
      ': internal-project-codename-thunderbird\ndata: {"TOKEN_2":"TOKEN_1"}\n\n',
    ];
    for (const chunk of leaks) {
      const fixture = sseFixture(chunk);
      assertValidFixture('t', fixture);
      expect(() => {
        assertFixtureFullySanitised('t', fixture, approvals(), options());
      }, chunk).toThrow(/not a surrogate/);
    }

    // Control: the same value inside a `data:` body was always caught, and a
    // fixture whose metadata IS sanitised still passes.
    const clean = sseFixture('event: TOKEN_1\nid: TOKEN_2\ndata: {"TOKEN_2":"TOKEN_1"}\n\n');
    assertValidFixture('t', clean);
    expect(() => {
      assertFixtureFullySanitised('t', clean, approvals(), options());
    }).not.toThrow();
  });

  it('F19: the detector is re-run over the committed fixture', () => {
    const fixture = wellFormedFixture();
    assertValidFixture('t', fixture);
    const err = errorFrom(() => {
      assertFixtureFullySanitised(
        't',
        fixture,
        approvals(),
        options({ detect: (text) => (text.includes('TOKEN_1') ? ['fake-rule'] : []) }),
      );
    });
    expect(err).toBeDefined();
    expect(err?.message).toContain('fake-rule');
  });

  it('PT-F1: a declared protocol token is accepted as a VALUE and refused as a KEY', () => {
    const token = 'content_block_delta';
    const asValue = {
      ...wellFormedFixture(),
      chunks: [`{"TOKEN_1":"${token}"}`],
      surrogates: { strings: ['TOKEN_1'], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', asValue);
    expect(() => {
      assertFixtureFullySanitised(
        't',
        asValue,
        approvals(),
        options({ protocolTokens: new Set([token]) }),
      );
    }).not.toThrow();

    // Never widened into keys — the same string, as a KEY this time, is still
    // refused even though it is declared.
    const asKey = {
      ...wellFormedFixture(),
      chunks: [`{"${token}":"TOKEN_1"}`],
      surrogates: { strings: ['TOKEN_1'], numbers: [] },
      url: 'https://chatgpt.com/',
    };
    assertValidFixture('t', asKey);
    expect(() => {
      assertFixtureFullySanitised(
        't',
        asKey,
        approvals(),
        options({ protocolTokens: new Set([token]) }),
      );
    }).toThrow(/not a surrogate or an approved key/);
  });
});

describe('assertStreamFixtureIsMultiChunk', () => {
  it('F20: refuses a single-chunk stream fixture, and accepts two distinct events', () => {
    const single = {
      ...wellFormedFixture(),
      format: 'sse',
      direction: 'response',
      chunks: ['data: {"TOKEN_2":"TOKEN_1"}\n\n'],
    };
    assertValidFixture('t', single);
    expect(() => {
      assertStreamFixtureIsMultiChunk('t', single);
    }).toThrow(/at least 2 chunks/);

    const repeated = {
      ...single,
      chunks: ['data: {"TOKEN_2":"TOKEN_1"}\n\n', 'data: {"TOKEN_2":"TOKEN_1"}\n\n'],
    };
    assertValidFixture('t', repeated);
    expect(() => {
      assertStreamFixtureIsMultiChunk('t', repeated);
    }).toThrow(/DISTINCT/);

    const twoEvents = {
      ...single,
      chunks: ['data: {"TOKEN_2":"TOKEN_1"}\n\n', 'data: {"TOKEN_2":"TOKEN_3"}\n\n'],
      surrogates: { strings: ['TOKEN_1', 'TOKEN_2', 'TOKEN_3'], numbers: [] },
    };
    assertValidFixture('t', twoEvents);
    expect(() => {
      assertStreamFixtureIsMultiChunk('t', twoEvents);
    }).not.toThrow();
  });
});

describe('belowFixtureBar', () => {
  it('F11: names the site, the endpoint count, and the missing files', () => {
    const message = belowFixtureBar('chatgpt', 1, ['test/fixtures/chatgpt/request.json']);
    expect(message).toContain('chatgpt');
    expect(message).toContain('1');
    expect(message).toContain('test/fixtures/chatgpt/request.json');
    expect(message).toContain('EXPECTED_DECLARING_ADAPTERS');
  });

  it('F11b: the remediation names what is missing rather than a fixed pair', () => {
    const message = belowFixtureBar('chatgpt', 2, ['chatgpt/account.json']);
    expect(message).toContain('chatgpt/account.json');
    expect(message).not.toContain('{request,stream}.json');
    expect(message).toContain('declares 2 endpoints');
  });
});

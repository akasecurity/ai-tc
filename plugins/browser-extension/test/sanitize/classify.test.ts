import { describe, expect, it } from 'vitest';

import {
  assertDeclarableTokens,
  classifyString,
  DECLARABLE_CLASSES,
  isDeclarableToken,
  isPreservableKey,
  isVocabularyCandidate,
  shannonEntropy,
  VOCABULARY_MAX_LENGTH,
} from '../../src/sanitize/classify.ts';
import { errorFrom, expectNoEchoOf } from '../helpers/no-echo.ts';

// Random-looking, high-entropy, and matches no bundled detection rule.
const RAW = 'qZ7hLm2XvB9tRw4sKcN6pJ1dGf3yUa8e';

// A vocabulary-eligible run built from a repeated low-entropy character plus
// periodic dots, which keep it OUT of base64ish's charset (so classification
// does not eat it before length is what's being tested).
function dotted(length: number): string {
  return Array.from({ length }, (_, i) => (i % 5 === 4 ? '.' : 'a')).join('');
}

describe('classifyString', () => {
  it.each([
    ['', 'empty'],
    ['123e4567-e89b-12d3-a456-426614174000', 'uuid'],
    [
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      'jwt',
    ],
    ['2026-09-04T10:00:00.000Z', 'iso-datetime'],
    ['https://chatgpt.com/backend-api/x', 'url'],
    ['user@example.com', 'email'],
    ['deadbeefcafe', 'hex'],
    ['YWJjZGVmZ2hpamtsbW5vcA==', 'base64ish'],
    ['12345678', 'numeric-string'],
    ['gpt-4o', 'vocabulary'],
    ['hello world', 'text'],
  ] as const)('classifies %j as %s', (value, expected) => {
    expect(classifyString(value)).toBe(expected);
  });

  it('resolves precedence: uuid and jwt win over base64ish, numeric-string wins over hex', () => {
    expect(classifyString('123e4567-e89b-12d3-a456-426614174000')).toBe('uuid');
    expect(
      classifyString(
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      ),
    ).toBe('jwt');
    expect(classifyString('12345678')).toBe('numeric-string');
  });
});

describe('isVocabularyCandidate', () => {
  it('rejects whitespace and accepts a hyphenated token', () => {
    expect(isVocabularyCandidate('gpt 4o')).toBe(false);
    expect(isVocabularyCandidate('gpt-4o')).toBe(true);
  });

  it('enforces the length ceiling exactly at VOCABULARY_MAX_LENGTH', () => {
    expect(VOCABULARY_MAX_LENGTH).toBe(40);
    expect(isVocabularyCandidate(dotted(40))).toBe(true);
    expect(isVocabularyCandidate(dotted(41))).toBe(false);
  });

  it('rejects raw high-entropy runs and accepts an ordinary structural word', () => {
    // A random run at base64ish's own floor (16 chars) is excluded on TWO
    // independent grounds — its classification (base64ish) and its entropy —
    // so this alone says nothing about the entropy gate specifically.
    expect(isVocabularyCandidate(RAW.slice(0, 16))).toBe(false);
    // A slice one short of that floor (13 chars) structurally classifies as
    // 'vocabulary' and is rejected on entropy alone — this is what isolates
    // the gate.
    expect(isVocabularyCandidate(RAW.slice(0, 13))).toBe(false);
    // Long enough that its per-character entropy reads "high", short enough
    // that the entropy gate does not apply to it at all.
    expect(isVocabularyCandidate('conversation')).toBe(true);
  });

  it('requires the vocabulary charset', () => {
    expect(isVocabularyCandidate('a b')).toBe(false);
    expect(isVocabularyCandidate('a==b')).toBe(false);
  });
});

describe('isPreservableKey', () => {
  it('accepts a snake_case identifier and rejects a spaced, oversized or uuid-shaped one', () => {
    expect(isPreservableKey('message_id')).toBe(true);
    expect(isPreservableKey('my note')).toBe(false);
    expect(isPreservableKey('a'.repeat(65))).toBe(false);
    expect(isPreservableKey('123e4567-e89b-12d3-a456-426614174000')).toBe(false);
  });

  it('rejects a key starting with a digit', () => {
    expect(isPreservableKey('9lives')).toBe(false);
  });

  it('C1: the ordinary structural field names a request body carries are approvable', () => {
    // Measured over a whole-identifier entropy gate, every one of these
    // computes above ENTROPY_THRESHOLD (3.14-3.72) purely because it is made
    // of several dictionary words — and a refused key cannot be rescued by an
    // approval file, so a fixture could not carry the paths an adapter's
    // requiredPaths are written against.
    for (const key of [
      'conversation_id',
      'conversation_mode',
      'parent_message_id',
      'client_message_id',
      'websocket_request_id',
      'timezone_offset_min',
      'completion_tokens',
      'prompt_tokens',
      'stream_response',
      'finish_details',
      'is_completion',
      'history_and_training_disabled',
    ]) {
      expect(isPreservableKey(key), key).toBe(true);
    }
  });

  it('C2: a genuinely random run used as a key is still refused', () => {
    // The gate's own job, which the per-word measure must not give away.
    expect(isPreservableKey('Xk9fQ2mW7pL4vB1n')).toBe(false);
    expect(isPreservableKey(RAW)).toBe(false);
    // Long enough that the whole-identifier floor catches a run broken up by
    // separators, which the per-word measure alone cannot see.
    expect(isPreservableKey('Xk9f-Q2mW-7pL4-vB1n-Zc6T-Rj8H-Ka3D-Ye5S')).toBe(false);
  });
});

describe('shannonEntropy', () => {
  it('is zero for a single repeated character and two bits for four distinct ones', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBe(2);
  });

  it('is zero for the empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });
});

// The declaration bound: a blast-radius limit on what an adapter's parser may
// name verbatim, not a recogniser of what is safe. See classify.ts's own doc
// comment on isDeclarableToken for the full reasoning; these cases pin the
// four clauses and the classes each one excludes.
describe('isDeclarableToken', () => {
  it('C1: the four blocking protocol tokens all clear the bound', () => {
    // Mutation: drop 'base64ish' from DECLARABLE_CLASSES kills the first
    // three (all base64ish-classed); re-apply an entropy gate kills
    // 'organizations' (vocabulary-classed, entropy 3.085 at length 13 — above
    // isVocabularyCandidate's own ENTROPY_THRESHOLD).
    for (const token of [
      'content_block_delta',
      'conversation_ready',
      'chat_conversations',
      'organizations',
    ]) {
      expect(isDeclarableToken(token), token).toBe(true);
    }
  });

  it('C2: whitespace is refused', () => {
    expect(isDeclarableToken('content block delta')).toBe(false);
  });

  it('C3: the length ceiling is VOCABULARY_MAX_LENGTH exactly, shared with the approvals gate', () => {
    // A dotted low-entropy run (see the shared `dotted` helper above) stays
    // vocabulary-classed at both lengths, isolating the ceiling from the
    // class check.
    expect(isDeclarableToken(dotted(40))).toBe(true);
    expect(isDeclarableToken(dotted(41))).toBe(false);
  });

  it('C4: every refused class is excluded, each asserted by class first', () => {
    const cases: readonly [string, ReturnType<typeof classifyString>][] = [
      ['123e4567-e89b-12d3-a456-426614174000', 'uuid'],
      ['aaa.bbb.ccc', 'jwt'],
      ['user@example.com', 'email'],
      ['deadbeefdeadbeefdeadbeef', 'hex'],
      ['12345678901234567890', 'numeric-string'],
      ['2024-01-01T00:00:00Z', 'iso-datetime'],
      // Charset-legal (VOCABULARY_PATTERN admits ':' and '/'), the sharp one:
      // a URL survives the charset clause and is excluded only by class.
      ['https://claude.ai/api', 'url'],
    ];
    for (const [value, expectedClass] of cases) {
      expect(classifyString(value), value).toBe(expectedClass);
      expect(isDeclarableToken(value), value).toBe(false);
    }
  });

  it('DECLARABLE_CLASSES is exactly vocabulary and base64ish', () => {
    expect([...DECLARABLE_CLASSES].sort()).toEqual(['base64ish', 'vocabulary']);
  });
});

describe('assertDeclarableTokens', () => {
  it('C5: throws naming the site and the offending index, never the token', () => {
    const token = 'a b'; // whitespace-bearing — index 1 is the offender
    const err = errorFrom(() => {
      assertDeclarableTokens('claude-ai', ['content_block_delta', token]);
    });
    expect(err).toBeDefined();
    expect(err?.message).toContain('claude-ai');
    expect(err?.message).toContain('index 1');
    expectNoEchoOf(err?.message, token);
  });

  it('C6 (anti-vacuity): a well-formed array validates without throwing', () => {
    expect(() => {
      assertDeclarableTokens('claude-ai', ['content_block_delta', 'organizations']);
    }).not.toThrow();
  });
});

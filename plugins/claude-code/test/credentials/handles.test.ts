import { describe, expect, it } from 'vitest';

import {
  handleSlugsIn,
  MIN_SCRUBBED_VALUE_LENGTH,
  scrubValues,
  substituteHandles,
  valueScrubber,
  valueSpellings,
} from '../../src/credentials/handles.ts';

const GITHUB = 'ghp_value"with\\quote-0123456789';
const STRIPE = 'sk_test_value_abcdefghijk';

describe('handleSlugsIn', () => {
  it('finds each slug once across nested string leaves, never in keys', () => {
    const input = {
      command: 'curl -H "Authorization: Bearer [[aka:cred:github]]" https://api.example',
      nested: { list: ['x [[aka:cred:stripe]]', 3, null, '[[aka:cred:github]]'] },
      '[[aka:cred:in-a-key]]': 'plain',
    };
    expect(handleSlugsIn(input)).toEqual(['github', 'stripe']);
  });

  it('ignores lookalikes that break the slug grammar', () => {
    expect(handleSlugsIn({ a: '[[aka:cred:Upper]] [[aka:cred:-dash]] [[aka:tok:x]]' })).toEqual([]);
  });
});

describe('substituteHandles', () => {
  it('replaces every handle with a value and keeps the rest as written', () => {
    const input = {
      command: 'A=[[aka:cred:github]] B=[[aka:cred:github]] C=[[aka:cred:missing]]',
      deep: { args: ['--key', '[[aka:cred:stripe]]'], count: 2 },
      untouched: { text: 'nothing here' },
    };
    const { value, substituted } = substituteHandles(
      input,
      new Map([
        ['github', GITHUB],
        ['stripe', STRIPE],
      ]),
    );
    expect(value).toEqual({
      command: `A=${GITHUB} B=${GITHUB} C=[[aka:cred:missing]]`,
      deep: { args: ['--key', STRIPE], count: 2 },
      untouched: { text: 'nothing here' },
    });
    expect(substituted.sort()).toEqual(['github', 'stripe']);
    expect((value as typeof input).untouched).toBe(input.untouched);
    expect(input.command).toContain('[[aka:cred:github]]');
  });

  it('treats a replacement value literally, including dollar signs', () => {
    const { value } = substituteHandles('x=[[aka:cred:a]]', new Map([['a', "$&$1$'"]]));
    expect(value).toBe("x=$&$1$'");
  });
});

describe('value scrubbing', () => {
  it('replaces the raw and JSON-escaped spellings with the handle', () => {
    const scrubber = valueScrubber(new Map([['github', GITHUB]]));
    const line = JSON.stringify({ updatedInput: { command: `curl -H "x: ${GITHUB}"` } });
    const twice = JSON.stringify({ text: line });
    expect(scrubber.scrub(line).text).toBe(
      JSON.stringify({ updatedInput: { command: 'curl -H "x: [[aka:cred:github]]"' } }),
    );
    expect(scrubber.scrub(twice).text).not.toContain('ghp_value');
    expect(scrubber.scrub(`raw ${GITHUB} end`)).toEqual({
      text: 'raw [[aka:cred:github]] end',
      slugs: ['github'],
    });
  });

  it('leaves a value too short to match safely alone', () => {
    const short = 'a'.repeat(MIN_SCRUBBED_VALUE_LENGTH - 1);
    expect(valueSpellings(short)).toEqual([]);
    expect(valueScrubber(new Map([['s', short]])).scrub(`x ${short} y`).slugs).toEqual([]);
  });

  it('scrubs every string leaf of a tool response and keeps its shape', () => {
    const response = {
      stdout: `token ${STRIPE}\n`,
      stderr: '',
      interrupted: false,
      isImage: false,
    };
    const { value, slugs } = scrubValues(response, valueScrubber(new Map([['stripe', STRIPE]])));
    expect(value).toEqual({
      stdout: 'token [[aka:cred:stripe]]\n',
      stderr: '',
      interrupted: false,
      isImage: false,
    });
    expect(slugs).toEqual(['stripe']);
  });
});

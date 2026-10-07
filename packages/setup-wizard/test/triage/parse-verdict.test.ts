import type { TriageRecommendation } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { parseRecommendation } from '../../src/triage/parse-verdict.ts';

const VERDICT: TriageRecommendation = { perCategory: [], notes: 'the real verdict' };
const SHAPE: TriageRecommendation = { perCategory: [], notes: 'an illustrative shape' };

function json(value: TriageRecommendation): string {
  return JSON.stringify(value);
}

describe('parseRecommendation', () => {
  it('parses the one json fence a reply carries', () => {
    const reply = `Here it is:\n\`\`\`json\n${json(VERDICT)}\n\`\`\`\n`;
    expect(parseRecommendation(reply)).toEqual(VERDICT);
  });

  it('takes the LAST json fence when an earlier one is illustrative', () => {
    const reply = ['```json', json(SHAPE), '```', 'The verdict:', '```json', json(VERDICT), '```'];
    expect(parseRecommendation(reply.join('\n'))).toEqual(VERDICT);
  });

  it('reads a fence with no whitespace between the markers and the body', () => {
    expect(parseRecommendation(`\`\`\`json${json(VERDICT)}\`\`\``)).toEqual(VERDICT);
  });

  it('ignores a json fence left open after a closed one', () => {
    const reply = `\`\`\`json\n${json(VERDICT)}\n\`\`\`\nthen \`\`\`json\n${json(SHAPE)}`;
    expect(parseRecommendation(reply)).toEqual(VERDICT);
  });

  it('closes a fence at the first ``` after it, even one that opens another fence', () => {
    // The second opener's backticks close the first fence, and what is left of
    // that opener ("json …") no longer opens one, so this reply holds one fence.
    const reply = `\`\`\`json ${json(VERDICT)} \`\`\`json ${json(SHAPE)} \`\`\``;
    expect(parseRecommendation(reply)).toEqual(VERDICT);
  });

  it('parses the whole reply as JSON when it carries no fence', () => {
    expect(parseRecommendation(`  ${json(VERDICT)}\n`)).toEqual(VERDICT);
  });

  it('reads a lone open fence as no fence, so the whole reply is parsed and refused', () => {
    expect(() => parseRecommendation(`\`\`\`json\n${json(VERDICT)}`)).toThrow(SyntaxError);
  });

  it(
    'takes one pass over an open fence followed by a long run of whitespace',
    { timeout: 5000 },
    () => {
      // A whitespace run followed by a lazy any-character body lets a pattern try
      // every split of the run between the two before it gives up on a fence that
      // never closes, which costs the square of the run's length. The fence sits
      // inside a bare verdict's notes, so the fallback still parses the reply.
      const verdict: TriageRecommendation = {
        perCategory: [],
        notes: `\`\`\`json${' '.repeat(500_000)}`,
      };
      expect(parseRecommendation(json(verdict))).toEqual(verdict);
    },
  );
});

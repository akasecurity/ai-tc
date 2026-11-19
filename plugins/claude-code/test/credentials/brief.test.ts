import { describe, expect, it } from 'vitest';

import { credentialBrief, MAX_BRIEFED_CREDENTIALS } from '../../src/credentials/brief.ts';

describe('credentialBrief', () => {
  it('is undefined when nothing is granted', () => {
    expect(credentialBrief([])).toBeUndefined();
  });

  it('lists each handle with its description and how to use one', () => {
    const brief =
      credentialBrief([
        { slug: 'github', description: 'GitHub API token\nfor the demo org' },
        { slug: 'stripe', description: '' },
      ]) ?? '';
    expect(brief).toContain('- [[aka:cred:github]]: GitHub API token for the demo org');
    expect(brief).toContain('- [[aka:cred:stripe]]\n');
    expect(brief).toContain('Authorization: Bearer [[aka:cred:github]]');
    expect(brief).toContain('Never ask the user for these values');
  });

  it('stays small', () => {
    const many = Array.from({ length: MAX_BRIEFED_CREDENTIALS + 5 }, (_, i) => ({
      slug: `cred-${String(i)}`,
      description: 'x'.repeat(500),
    }));
    const brief = credentialBrief(many) ?? '';
    expect(brief.split('\n').filter((line) => line.startsWith('- '))).toHaveLength(
      MAX_BRIEFED_CREDENTIALS,
    );
    expect(brief.length).toBeLessThan(5_000);
  });
});

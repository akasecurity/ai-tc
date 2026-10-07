// An encoded secret (a base64 run, an xxd dump) is reported with the DECODED
// value as its match, so every preview and identity built from a finding is
// built from the secret itself, never from the dump text around it.
import { describe, expect, it } from 'vitest';

import { scanText } from '../src/mask.ts';

// Assembled from parts so no credential-shaped literal sits in this file.
const TOKEN = ['gh', 'p_', 'Q7mK2xV9pL4sT8wR1zY6bN3cF5hJ0dG2aE7u'].join('');

function xxd(s: string): string {
  const bytes = Buffer.from(s, 'utf8');
  const lines: string[] = [];
  for (let at = 0; at < bytes.length; at += 16) {
    const row = bytes.subarray(at, at + 16);
    const groups: string[] = [];
    for (let g = 0; g < row.length; g += 2) groups.push(row.subarray(g, g + 2).toString('hex'));
    const ascii = [...row].map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'));
    lines.push(
      `${at.toString(16).padStart(8, '0')}: ${groups.join(' ').padEnd(39)}  ${ascii.join('')}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

describe('the masked preview of an encoded secret', () => {
  const plain = scanText(`token ${TOKEN}\n`).findings.filter(
    (f) => f.ruleId === 'secrets/github-pat',
  );

  it('is the preview of the plain secret, for base64 and for xxd', () => {
    expect(plain).toHaveLength(1);
    for (const text of [
      Buffer.from(`token ${TOKEN}\n`).toString('base64'),
      xxd(`mail=a@b.com ${TOKEN}\n`),
    ]) {
      const encoded = scanText(text).findings.filter((f) => f.ruleId === 'secrets/github-pat');
      expect(encoded.map((f) => f.maskedMatch)).toEqual(plain.map((f) => f.maskedMatch));
    }
  });

  it('never reveals a run of the secret through an email on the same dump line', () => {
    for (const finding of scanText(xxd(`mail=a@b.com ${TOKEN}\n`)).findings) {
      for (let k = 0; k + 6 <= TOKEN.length; k++) {
        expect(finding.maskedMatch).not.toContain(TOKEN.slice(k, k + 6));
      }
      expect(finding.maskedMatch).not.toContain(Buffer.from(TOKEN.slice(0, 6)).toString('hex'));
    }
  });
});

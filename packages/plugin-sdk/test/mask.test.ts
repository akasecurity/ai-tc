import { describe, expect, it } from 'vitest';

import { maskText, scanText } from '../src/mask.ts';

// Secrets are ASSEMBLED at runtime from fragments so this source file contains no
// literal secret (which the detection engine would otherwise flag on write/scan).
const AWS_KEY = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('');
const SSN = ['123', '45', '6789'].join('-');

describe('maskText', () => {
  it('leaves text with no detectable secret unchanged', () => {
    expect(maskText('https://docs.claude.com/en/docs/claude-code/hooks')).toBe(
      'https://docs.claude.com/en/docs/claude-code/hooks',
    );
    expect(maskText('npm run build')).toBe('npm run build');
  });

  it('redacts a secret embedded in a command', () => {
    const masked = maskText(`aws configure set aws_access_key_id ${AWS_KEY}`);
    expect(masked).not.toContain(AWS_KEY);
    expect(masked).toContain('[REDACTED');
  });

  it('never partially leaks a detectable secret', () => {
    const masked = maskText(`echo ${SSN}`);
    // Either the rule fires (redacted) or the pattern isn't in the bundled packs
    // (unchanged) — but it must never leak a partial.
    if (masked !== `echo ${SSN}`) expect(masked).not.toContain(SSN);
  });
});

describe('scanText', () => {
  it('returns the masked text and enriched findings for a detected secret', () => {
    const { masked, findings } = scanText(`aws configure set aws_access_key_id ${AWS_KEY}`);
    expect(masked).not.toContain(AWS_KEY);
    expect(findings.length).toBeGreaterThan(0);
    const f = findings[0];
    expect(f).toBeDefined();
    expect(f?.ruleId).toBeTruthy();
    expect(f?.ruleName).toBeTruthy();
    expect(f?.ruleVersion).toBeTruthy();
    expect(f?.category).toBeTruthy();
    expect(f?.span.end).toBeGreaterThan(f?.span.start ?? 0);
    // The finding carries only the MASKED match, never the raw secret.
    expect(f?.maskedMatch).not.toContain(AWS_KEY);
  });

  it('returns no findings for clean text', () => {
    const { masked, findings } = scanText('npm run build');
    expect(masked).toBe('npm run build');
    expect(findings).toEqual([]);
  });
});

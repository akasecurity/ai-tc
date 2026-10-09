import { readFileSync } from 'node:fs';

import { MODEL_ENTRIES } from '@akasecurity/schema';
import { TONE_SOFT } from '@akasecurity/ui-kit';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';

import * as root from '../../src/index.ts';
import { MODEL_FAMILY_MARKS, ModelMark, modelMarkFor } from '../../src/shared/ModelMark.tsx';

describe('modelMarkFor', () => {
  it('draws a known family from its family id', () => {
    expect(modelMarkFor({ familyId: 'claude', label: 'Claude Opus 5' })).toEqual({
      letter: 'C',
      tone: 'violet',
    });
    expect(modelMarkFor({ familyId: 'gpt', label: 'GPT-4o' })).toEqual({
      letter: 'O',
      tone: 'teal',
    });
  });

  it('falls back to the vendor when the family is not known', () => {
    expect(modelMarkFor({ familyId: 'unlisted', vendor: 'google', label: 'Some model' })).toEqual(
      MODEL_FAMILY_MARKS.gemini,
    );
    expect(modelMarkFor({ vendor: 'openai', label: 'text-embedding-3-small' })).toEqual(
      MODEL_FAMILY_MARKS.gpt,
    );
  });

  it('prefers the family over the vendor', () => {
    expect(modelMarkFor({ familyId: 'qwen', vendor: 'openai', label: 'x' })).toEqual(
      MODEL_FAMILY_MARKS.qwen,
    );
  });

  it('falls back to the first letter of the label on the neutral tone', () => {
    expect(modelMarkFor({ label: 'phi-4' })).toEqual({ letter: 'P', tone: 'neutral' });
    expect(modelMarkFor({ vendor: 'unknown', label: '  42-model' })).toEqual({
      letter: '4',
      tone: 'neutral',
    });
    expect(modelMarkFor({ label: '' })).toEqual({ letter: '?', tone: 'neutral' });
    expect(modelMarkFor({ label: '---' })).toEqual({ letter: '?', tone: 'neutral' });
  });

  it('does not resolve Object.prototype keys as families or vendors', () => {
    for (const hostile of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
      expect(modelMarkFor({ familyId: hostile, vendor: hostile, label: 'zeta' })).toEqual({
        letter: 'Z',
        tone: 'neutral',
      });
    }
  });

  it('gives every catalog family a known mark', () => {
    const families = new Set(MODEL_ENTRIES.map((e) => e.familyId));
    for (const family of families) {
      expect(Object.hasOwn(MODEL_FAMILY_MARKS, family), family).toBe(true);
    }
  });

  it('resolves every catalog vendor to a known mark through its vendor alone', () => {
    for (const entry of MODEL_ENTRIES) {
      expect(
        modelMarkFor({ vendor: entry.vendor, label: '' }).letter,
        `${entry.id} via ${entry.vendor}`,
      ).not.toBe('?');
    }
  });

  it('never uses a severity tone', () => {
    for (const glyph of Object.values(MODEL_FAMILY_MARKS)) {
      expect(['teal', 'violet', 'primary', 'neutral']).toContain(glyph.tone);
    }
  });
});

describe('ModelMark', () => {
  it('names the model for assistive technology and hides the letter', () => {
    const html = renderToStaticMarkup(<ModelMark familyId="claude" label="Claude Opus 5" />);
    expect(html).toContain('role="img"');
    expect(html).toContain('aria-label="Claude Opus 5"');
    expect(html).toContain('<span aria-hidden="true">C</span>');
  });

  it('hides the whole tile when it is decorative', () => {
    const html = renderToStaticMarkup(
      <ModelMark familyId="claude" label="Claude Opus 5" decorative />,
    );
    expect(html).not.toContain('role="img"');
    expect(html).not.toContain('aria-label');
    expect(html).toMatch(/^<span[^>]*aria-hidden="true"/);
  });

  it('paints the tile with the tonal pair for its family', () => {
    const html = renderToStaticMarkup(<ModelMark familyId="gpt" label="GPT-4o" />);
    for (const cls of TONE_SOFT.teal.split(' ')) expect(html).toContain(cls);
    expect(html).toContain('data-tone="teal"');
  });

  it('paints an unknown model on the neutral pair with its first letter', () => {
    const html = renderToStaticMarkup(<ModelMark label="phi-4" />);
    for (const cls of TONE_SOFT.neutral.split(' ')) expect(html).toContain(cls);
    expect(html).toContain('<span aria-hidden="true">P</span>');
  });

  it('renders the two sizes and defaults to md', () => {
    expect(renderToStaticMarkup(<ModelMark label="x" size="sm" />)).toContain('size-5');
    expect(renderToStaticMarkup(<ModelMark label="x" />)).toContain('size-7');
  });

  it('merges a caller className', () => {
    expect(renderToStaticMarkup(<ModelMark label="x" className="ml-2" />)).toContain('ml-2');
  });

  it('carries no inline colour and no hex literal', () => {
    const html = renderToStaticMarkup(<ModelMark familyId="claude" label="Claude" />);
    expect(html).not.toContain('style=');
    const source = readFileSync(new URL('../../src/shared/ModelMark.tsx', import.meta.url), 'utf8');
    expect(source).not.toMatch(/#[0-9a-f]{3,8}\b/iu);
  });

  it('is exported from the package root', () => {
    expect(root.ModelMark).toBe(ModelMark);
    expect(root.modelMarkFor).toBe(modelMarkFor);
    expect(root.MODEL_FAMILY_MARKS).toBe(MODEL_FAMILY_MARKS);
  });
});

import { describe, expect, it } from 'vitest';

import { DEFAULT_LOCALE, resolveLocale } from '../../src/lib/locale.ts';

describe('resolveLocale', () => {
  it('falls back to en-US when the request names no locale', () => {
    expect(DEFAULT_LOCALE).toBe('en-US');
    expect(resolveLocale(null)).toBe('en-US');
    expect(resolveLocale(undefined)).toBe('en-US');
    expect(resolveLocale('')).toBe('en-US');
    expect(resolveLocale('*')).toBe('en-US');
  });

  it('takes the first tag of a plain header', () => {
    expect(resolveLocale('de-DE')).toBe('de-DE');
    expect(resolveLocale('fr-CH, fr;q=0.9, en;q=0.8')).toBe('fr-CH');
  });

  it('orders by weight, not by position', () => {
    // A real browser lists highest first, but the header's meaning is its
    // weights: a resolver that took the first entry would answer `en` here.
    expect(resolveLocale('en;q=0.5, de-DE;q=0.9, fr;q=0.7')).toBe('de-DE');
  });

  it('keeps header order between equal weights', () => {
    expect(resolveLocale('fr;q=0.8, de;q=0.8')).toBe('fr');
  });

  it('skips a refused tag and a malformed weight', () => {
    // q=0 means "not acceptable"; a weight that does not parse is not a weight.
    expect(resolveLocale('de;q=0, fr')).toBe('fr');
    expect(resolveLocale('de;q=abc, fr')).toBe('fr');
    expect(resolveLocale('de;q=1.5, fr')).toBe('fr');
  });

  it('skips a tag this runtime cannot format and a tag that is not a tag', () => {
    expect(resolveLocale('zz-ZZ, de')).toBe('de');
    expect(resolveLocale('not a locale!, de')).toBe('de');
    expect(resolveLocale('zz, qq')).toBe('en-US');
  });

  it('canonicalizes the tag it returns', () => {
    expect(resolveLocale('DE-de')).toBe('de-DE');
    expect(resolveLocale('en-us')).toBe('en-US');
  });

  it('drops Unicode extensions, which a browser never sends', () => {
    // Kept, an extension would make the set of locales a formatter cache can be
    // asked for as large as the header space rather than the locale space.
    expect(resolveLocale('de-DE-u-nu-arab')).toBe('de-DE');
  });

  it('reads a bounded prefix of a hostile header', () => {
    // Every entry before the supported one is unsupported, and it sits past the
    // entry bound — so the header resolves to the default rather than doing the
    // work of reaching it.
    const header = `${Array.from({ length: 40 }, () => 'zz').join(',')},de`;
    expect(resolveLocale(header)).toBe('en-US');
    // The control: the same supported tag inside the bound is found.
    expect(resolveLocale('zz,zz,de')).toBe('de');
  });
});

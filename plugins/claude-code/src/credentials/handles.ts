// Credential handles in tool payloads: finding them, swapping in values, and
// swapping values back to their handles. Pure, so it unit-tests without a hook.
import type { CredentialSlug } from '@akasecurity/schema';
import { credentialHandleScanner, formatCredentialHandle } from '@akasecurity/schema';

/** A value shorter than this is never scrubbed: it would match unrelated text. */
export const MIN_SCRUBBED_VALUE_LENGTH = 8;

/** Copy of `value` with `transform` applied to every string leaf; object keys are left alone. */
function mapStrings(value: unknown, transform: (text: string) => string): unknown {
  if (typeof value === 'string') return transform(value);
  if (Array.isArray(value)) {
    const items: unknown[] = value;
    const out = items.map((item) => mapStrings(item, transform));
    return out.some((next, i) => next !== items[i]) ? out : value;
  }
  if (typeof value === 'object' && value !== null) {
    let changed = false;
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      const next = mapStrings(item, transform);
      if (next !== item) changed = true;
      out[key] = next;
    }
    return changed ? out : value;
  }
  return value;
}

function eachString(value: unknown, visit: (text: string) => void): void {
  if (typeof value === 'string') visit(value);
  else if (Array.isArray(value)) for (const item of value) eachString(item, visit);
  else if (typeof value === 'object' && value !== null) {
    for (const item of Object.values(value)) eachString(item, visit);
  }
}

/** The distinct slugs named by a handle in any string leaf of `value`, in first-seen order. */
export function handleSlugsIn(value: unknown): CredentialSlug[] {
  const slugs = new Set<CredentialSlug>();
  eachString(value, (text) => {
    if (!text.includes('[[aka:cred:')) return;
    for (const match of text.matchAll(credentialHandleScanner())) {
      if (match[1] !== undefined) slugs.add(match[1]);
    }
  });
  return [...slugs];
}

/**
 * Copy of `value` with every handle whose slug has a value replaced by that
 * value. A handle without a value stays as written.
 */
export function substituteHandles(
  value: unknown,
  values: ReadonlyMap<CredentialSlug, string>,
): { value: unknown; substituted: CredentialSlug[] } {
  const substituted = new Set<CredentialSlug>();
  const out = mapStrings(value, (text) =>
    text.includes('[[aka:cred:')
      ? text.replace(credentialHandleScanner(), (handle, slug: string) => {
          const resolved = values.get(slug);
          if (resolved === undefined) return handle;
          substituted.add(slug);
          return resolved;
        })
      : text,
  );
  return { value: out, substituted: [...substituted] };
}

/**
 * The spellings of `value` worth looking for: as written, and JSON-escaped once
 * and twice, which is how it appears inside a JSONL record and inside JSON text
 * carried in one. Longest first, so a longer spelling is replaced before a
 * shorter one inside it.
 */
export function valueSpellings(value: string): string[] {
  if (value.length < MIN_SCRUBBED_VALUE_LENGTH) return [];
  const once = JSON.stringify(value).slice(1, -1);
  const twice = JSON.stringify(once).slice(1, -1);
  return [...new Set([value, once, twice])].sort((a, b) => b.length - a.length);
}

export interface ValueScrubber {
  /** `text` with every injected value replaced by its handle, and the slugs replaced. */
  scrub(text: string): { text: string; slugs: CredentialSlug[] };
}

/** A scrubber over `injected` (slug → value). Values too short to scrub safely are skipped. */
export function valueScrubber(injected: ReadonlyMap<CredentialSlug, string>): ValueScrubber {
  const pairs: { spelling: string; slug: CredentialSlug }[] = [];
  for (const [slug, value] of injected) {
    for (const spelling of valueSpellings(value)) pairs.push({ spelling, slug });
  }
  pairs.sort((a, b) => b.spelling.length - a.spelling.length);
  return {
    scrub(text) {
      const slugs = new Set<CredentialSlug>();
      let out = text;
      for (const { spelling, slug } of pairs) {
        if (!out.includes(spelling)) continue;
        out = out.split(spelling).join(formatCredentialHandle(slug));
        slugs.add(slug);
      }
      return { text: out, slugs: [...slugs] };
    },
  };
}

/** Copy of `value` with every injected value in its string leaves replaced by its handle. */
export function scrubValues(
  value: unknown,
  scrubber: ValueScrubber,
): { value: unknown; slugs: CredentialSlug[] } {
  const slugs = new Set<CredentialSlug>();
  const out = mapStrings(value, (text) => {
    const result = scrubber.scrub(text);
    for (const slug of result.slugs) slugs.add(slug);
    return result.text;
  });
  return { value: out, slugs: [...slugs] };
}

/** The handles of `slugs`, for a message: `[[aka:cred:a]], [[aka:cred:b]]`. */
export function handleList(slugs: readonly CredentialSlug[]): string {
  return slugs.map((slug) => formatCredentialHandle(slug)).join(', ');
}

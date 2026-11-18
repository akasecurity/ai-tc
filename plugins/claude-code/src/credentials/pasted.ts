// A credential the organization vaulted, pasted by the user: recognised by its
// sighting token and replaced with its handle before the model reads it.
import { readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';

import type { SightingKeys } from '@akasecurity/persistence';
import { readSightingKeys, sightingTokens, writeOwnerOnlyFileSync } from '@akasecurity/persistence';
import type { AvailableCredential } from '@akasecurity/schema';
import { CredentialSlug, formatCredentialHandle } from '@akasecurity/schema';
import * as z from 'zod';

import { MIN_SCRUBBED_VALUE_LENGTH } from './handles.ts';

export const CREDENTIAL_LOOKUPS_FILENAME = 'credential-lookups.json';

const StoredLookups = z.object({
  v: z.literal(1),
  credentials: z.array(z.object({ slug: CredentialSlug, lookups: z.array(z.string()) })),
});

/** A sighting token, mapped to the slug of the credential whose value it hashes. */
export type CredentialLookups = ReadonlyMap<string, CredentialSlug>;

export interface PastedCredential {
  slug: CredentialSlug;
  rawMatch: string;
}

/**
 * Keep the lookup tokens of the credentials granted to this machine, for the
 * prompt hooks of every later process. The file holds HMACs, never a value; it
 * is removed when no credential carries one.
 */
export function saveCredentialLookups(
  dataDir: string,
  credentials: readonly AvailableCredential[],
): void {
  const file = join(dataDir, CREDENTIAL_LOOKUPS_FILENAME);
  const entries = credentials.flatMap(({ slug, lookups }) =>
    lookups === undefined || lookups.length === 0 ? [] : [{ slug, lookups }],
  );
  if (entries.length === 0) {
    rmSync(file, { force: true });
    return;
  }
  writeOwnerOnlyFileSync(file, JSON.stringify({ v: 1, credentials: entries }));
}

/** The saved lookups; empty when there are none or the file does not parse. */
export function readCredentialLookups(dataDir: string): CredentialLookups {
  let raw: string;
  try {
    raw = readFileSync(join(dataDir, CREDENTIAL_LOOKUPS_FILENAME), 'utf8');
  } catch {
    return new Map();
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return new Map();
  }
  const parsed = StoredLookups.safeParse(json);
  if (!parsed.success) return new Map();
  const lookups = new Map<string, CredentialSlug>();
  for (const { slug, lookups: tokens } of parsed.data.credentials) {
    for (const token of tokens) lookups.set(token, slug);
  }
  return lookups;
}

/**
 * `text` with each secret finding whose value hashes to a lookup token replaced,
 * at every occurrence, by that credential's handle.
 */
export function swapPastedCredentials(
  text: string,
  findings: readonly { category: string; rawMatch: string }[],
  lookups: CredentialLookups,
  keys: SightingKeys,
): { text: string; swapped: PastedCredential[] } {
  const swapped = new Map<string, CredentialSlug>();
  for (const { category, rawMatch } of findings) {
    if (category !== 'secret' || rawMatch.length < MIN_SCRUBBED_VALUE_LENGTH) continue;
    if (swapped.has(rawMatch)) continue;
    const tokens = sightingTokens(keys, rawMatch);
    const slug = [tokens.token, ...(tokens.aliases ?? [])]
      .map((token) => lookups.get(token))
      .find((found) => found !== undefined);
    if (slug !== undefined) swapped.set(rawMatch, slug);
  }
  let out = text;
  const longestFirst = [...swapped].sort(([a], [b]) => b.length - a.length);
  for (const [rawMatch, slug] of longestFirst) {
    out = out.split(rawMatch).join(formatCredentialHandle(slug));
  }
  return { text: out, swapped: longestFirst.map(([rawMatch, slug]) => ({ slug, rawMatch })) };
}

/**
 * {@link swapPastedCredentials} with this machine's saved lookups and sighting
 * keys, or null when it has neither or nothing matched.
 */
export function swapPastedCredentialsOnMachine(
  dataDir: string,
  text: string,
  findings: readonly { category: string; rawMatch: string }[],
): { text: string; swapped: PastedCredential[] } | null {
  if (!findings.some((finding) => finding.category === 'secret')) return null;
  const lookups = readCredentialLookups(dataDir);
  if (lookups.size === 0) return null;
  const keys = readSightingKeys(dirname(dataDir));
  if (keys === undefined) return null;
  const result = swapPastedCredentials(text, findings, lookups, keys);
  return result.swapped.length === 0 ? null : result;
}

/** What the model is told about the handles that replaced pasted values. */
export function pastedCredentialNote(swapped: readonly PastedCredential[]): string {
  const handles = [...new Set(swapped.map(({ slug }) => formatCredentialHandle(slug)))];
  return `AKA replaced a credential the user pasted with its handle (${handles.join(', ')}). Use the handle exactly as written; AKA supplies the real value when a tool runs. Do not ask the user for the value.`;
}

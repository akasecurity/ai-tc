import type { MatchResult, TokenizedSecretSpan } from '@akasecurity/detections';
import type { ScanSighting, SightingKeys } from '@akasecurity/persistence';
import { sightingTokens } from '@akasecurity/persistence';

/** One file's secrets as sighting tokens, each computed once. */
export interface SecretSightings {
  /** What the scan sends for the file. */
  sightings: ScanSighting[];
  /** Where each token sits in the file, for the call sites that use it. */
  spans: TokenizedSecretSpan[];
}

/**
 * The secret matches in one file reduced to sighting tokens under `keys`, with
 * aliases under its previous versions. A value that cannot be reduced to a token
 * is left out; the scan goes on.
 */
export function secretSightingsOf(
  keys: SightingKeys,
  matches: readonly MatchResult[],
  file: string,
  scopeKey?: string,
): SecretSightings {
  const found: SecretSightings = { sightings: [], spans: [] };
  for (const match of matches) {
    if (match.category !== 'secret') continue;
    let tokens: { token: string; aliases?: string[] };
    try {
      tokens = sightingTokens(keys, match.rawMatch);
    } catch {
      continue;
    }
    found.sightings.push({
      ...tokens,
      ruleId: match.ruleId,
      ...(match.variableName === undefined ? {} : { variableName: match.variableName }),
      file,
      ...(scopeKey === undefined ? {} : { scopeKey }),
    });
    found.spans.push({ ...match.span, ruleId: match.ruleId, ...tokens });
  }
  return found;
}

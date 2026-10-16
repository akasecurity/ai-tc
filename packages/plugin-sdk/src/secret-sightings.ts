import type { MatchResult, TokenizedSecretSpan } from '@akasecurity/detections';
import type { ScanSighting, SightingKey } from '@akasecurity/persistence';
import { sightingToken } from '@akasecurity/persistence';

/** One file's secrets as sighting tokens, each computed once. */
export interface SecretSightings {
  /** What the scan sends for the file. */
  sightings: ScanSighting[];
  /** Where each token sits in the file, for the call sites that use it. */
  spans: TokenizedSecretSpan[];
}

/**
 * The secret matches in one file reduced to sighting tokens under `key`. A
 * value that cannot be reduced to a token is left out; the scan goes on.
 */
export function secretSightingsOf(
  key: SightingKey,
  matches: readonly MatchResult[],
  file: string,
  scopeKey?: string,
): SecretSightings {
  const found: SecretSightings = { sightings: [], spans: [] };
  for (const match of matches) {
    if (match.category !== 'secret') continue;
    let token: string;
    try {
      token = sightingToken(key, match.rawMatch);
    } catch {
      continue;
    }
    found.sightings.push({
      token,
      ruleId: match.ruleId,
      ...(match.variableName === undefined ? {} : { variableName: match.variableName }),
      file,
      ...(scopeKey === undefined ? {} : { scopeKey }),
    });
    found.spans.push({ ...match.span, ruleId: match.ruleId, token });
  }
  return found;
}

import type { CredentialSightingsRequest, RemoteFailureKind } from '@akasecurity/schema';

import { createRemoteClient } from './client.ts';
import { classifyRemoteFailure } from './failure-kind.ts';

/** The deadline on each credential-sightings request a scan makes. */
export const CREDENTIAL_SIGHTINGS_TIMEOUT_MS = 15_000;

/** Where to send: the attached endpoint and the credential minted for it. */
export interface CredentialSightingsSenderConnection {
  endpoint: string;
  apiKey: string;
}

/** What one send did. A failure is named, never thrown. */
export type CredentialSightingsSendResult =
  { ok: true; accepted: number } | { ok: false; kind: RemoteFailureKind };

export type CredentialSightingsSender = (
  connection: CredentialSightingsSenderConnection,
  request: CredentialSightingsRequest,
) => Promise<CredentialSightingsSendResult>;

/**
 * The sender for a scan's credential sightings: one client and one request per
 * call, every failure read through `classifyRemoteFailure`. Never throws.
 */
export function createCredentialSightingsSender(
  timeoutMs = CREDENTIAL_SIGHTINGS_TIMEOUT_MS,
): CredentialSightingsSender {
  return async (connection, request) => {
    try {
      const ack = await createRemoteClient({
        ...connection,
        timeoutMs,
      }).recordCredentialSightings(request);
      return { ok: true, accepted: ack.accepted };
    } catch (err) {
      return { ok: false, kind: classifyRemoteFailure(err) };
    }
  };
}

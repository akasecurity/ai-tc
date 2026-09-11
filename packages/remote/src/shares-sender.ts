import type { EgressIngestRequest, RemoteFailureKind } from '@akasecurity/schema';

import { createRemoteClient } from './client.ts';
import { classifyRemoteFailure } from './failure-kind.ts';

// The one transport adapter for forwarding a Data Shares register, shared by
// every surface that records one and then sends it. It is declared over schema
// types only — the caller that decides WHETHER to send keeps its own shape for
// the sender and this satisfies it structurally, so that caller never needs to
// import this package to describe what it expects.

/**
 * The deadline on the one forward a scan makes.
 *
 * One request, one deadline, no retry: a full 5,000-call-site body is around
 * 2 MB, which 15 seconds covers on a slow link, and the next scan of the same
 * project replaces its register outright — so the retry already exists and
 * costs the person at the prompt nothing to wait for.
 */
export const SHARES_FORWARD_TIMEOUT_MS = 15_000;

/** Where to send: the attached endpoint and the credential minted for it. */
export interface SharesSenderConnection {
  endpoint: string;
  apiKey: string;
}

/** What one send did. A failure is named, never thrown. */
export type SharesSendResult = { ok: true } | { ok: false; kind: RemoteFailureKind };

export type SharesSender = (
  connection: SharesSenderConnection,
  request: EgressIngestRequest,
) => Promise<SharesSendResult>;

/**
 * Build the sender: one client per call, one request, and every failure read
 * through `classifyRemoteFailure` so each surface renders the same verdict for
 * the same failure. Never throws — the caller is a fail-open path that has
 * already done the work that matters.
 */
export function createSharesSender(timeoutMs = SHARES_FORWARD_TIMEOUT_MS): SharesSender {
  return async (connection, request) => {
    try {
      await createRemoteClient({ ...connection, timeoutMs }).recordProjectEgress(request);
      return { ok: true };
    } catch (err) {
      return { ok: false, kind: classifyRemoteFailure(err) };
    }
  };
}

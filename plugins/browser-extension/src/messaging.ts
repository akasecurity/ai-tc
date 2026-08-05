// The one contract content.ts and background.ts share: a content
// script asks for a session_start/capture/ping by omitting requestId
// (background.ts owns request-id assignment and native-port correlation) and
// gets back the native host's response verbatim. Kept as its own module so
// neither side needs to import the other.
import type { HostRequest, HostResponse } from './native-host/protocol.ts';

// Plain `Omit<HostRequest, 'requestId'>` would NOT distribute over
// HostRequest's union — Omit is defined via keyof, and keyof a union
// collapses to the properties common to every member (just `type` here),
// silently erasing sessionId/tool/hostname/kind/text from the result. This
// conditional forces per-member distribution instead.
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type BackgroundRequest = DistributiveOmit<HostRequest, 'requestId'>;
export type BackgroundResponse = HostResponse;

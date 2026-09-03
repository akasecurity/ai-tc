// The control-plane transport: the one OSS package that reaches a network, and
// only the network a machine's own settings name.
//
// It is deliberately narrow. `createRemoteClient` speaks the eight routes an
// attached machine is scoped to and cannot express anything else; `send` is the
// single module underneath that opens a socket. Nothing here decides WHETHER a
// machine is attached, reads the credential, or holds a policy — those belong to
// the settings, the credential store and the runtime respectively.
//
// `createAttachClient` is the one credential-LESS surface, and it is a separate
// client for a reason rather than a flag on the one above. Its two routes are
// how a machine obtains a credential in the first place, so it necessarily has
// none while calling them — and being a distinct object means a caller cannot
// reach any other route without one, because this client does not know how to
// build one. An optional key on the main client would instead have made a
// forgotten credential a silent unauthenticated call on every route.
export type {
  AttachClient,
  ConditionalBundle,
  RemoteClient,
  RemoteClientOptions,
} from './client.ts';
export { createAttachClient, createRemoteClient } from './client.ts';
// `send` and its option/response types are deliberately NOT re-exported.
//
// Every guarantee `http.ts` makes is held by construction inside that module —
// no redirects, a deadline on every request, a body cap, an upgrade refused —
// with ONE exception: that plain `http:` only ever names a loopback host. That
// one is established by `isSafeEndpoint` before an endpoint is ever written to
// disk, and `send` cannot re-check it (the predicate lives in
// @akasecurity/persistence, which this package must not depend on, and a second
// copy here is exactly the drift the switch's own comment warns about).
//
// While `send` was exported, that made the weakest guarantee in the file the
// only one a caller could step around: anything in the workspace could build a
// `SendOptions.url` from a less-trusted source and put the credential on a
// cleartext socket, with nothing here to refuse it. Narrowing the barrel closes
// it by construction instead — the package's whole public surface is now eight
// named routes against one endpoint, and there is no exported way to hand this
// module an arbitrary URL. Nothing outside the package used `send`.
export {
  DEFAULT_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  RemoteRequestError,
  RemoteRequestInvalid,
  RemoteResponseInvalid,
  RemoteRouteAbsent,
  RemoteTransportError,
} from './http.ts';

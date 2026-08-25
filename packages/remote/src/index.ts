// The control-plane transport: the one OSS package that reaches a network, and
// only the network a machine's own settings name.
//
// It is deliberately narrow. `createRemoteClient` speaks the six routes an
// attached machine is scoped to and cannot express anything else; `send` is the
// single module underneath that opens a socket. Nothing here decides WHETHER a
// machine is attached, reads the credential, or holds a policy — those belong to
// the settings, the credential store and the runtime respectively.
export type { ConditionalBundle, RemoteClient, RemoteClientOptions } from './client.ts';
export { createRemoteClient } from './client.ts';
export type { RemoteResponse, SendOptions } from './http.ts';
export {
  DEFAULT_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  RemoteRequestError,
  RemoteRequestInvalid,
  RemoteResponseInvalid,
  RemoteTransportError,
  send,
} from './http.ts';

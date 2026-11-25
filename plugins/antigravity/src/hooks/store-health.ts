// This plugin's store-health seam. The module lives in
// @akasecurity/plugin-runtime and is shared by every plugin; hooks import it
// from here so each plugin has one place to reach it.
export type { GatewayOpen, StoreEventSubject, StoreLock } from '@akasecurity/plugin-runtime';
export {
  claimStoreDegradedWarning,
  claimStoreUnavailableWarning,
  isSessionMarked,
  markSession,
  openGateway,
  openGatewayOrNull,
  storeAheadMessage,
  storeBusyMessage,
  storeDegradedMessage,
  storeOpenCause,
  storeRedirectedMessage,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from '@akasecurity/plugin-runtime';

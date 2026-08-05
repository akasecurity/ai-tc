// The native-messaging host name background.ts hands to
// chrome.runtime.connectNative — must match the manifest `aka extension
// install` writes (cli/src/commands/extension.ts). The extension's own id is
// pinned by the public key committed in manifest.json's "key" field (public
// keys aren't secret), so the CLI's allowed_origins writer can hardcode the
// derived id and every from-source build keeps the same identity.
export const NATIVE_HOST_NAME = 'com.akasecurity.aka';

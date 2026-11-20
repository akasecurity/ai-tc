import { accessSync, constants } from 'node:fs';
import { delimiter, join } from 'node:path';

import type { VaultConsent } from '@akasecurity/schema';
import { isVaultConsentValid } from '@akasecurity/schema';

interface ConsentSettings {
  readonly vaultConsent?: VaultConsent | undefined;
}

/** Whether the hook server takes tool calls: it declines every one while the local vault is on. */
export function hookServerTakesToolCalls(settings: ConsentSettings): boolean {
  return !isVaultConsentValid(settings.vaultConsent);
}

function onPath(command: string, path: string | undefined): boolean {
  return (path ?? '').split(delimiter).some((dir) => {
    if (dir === '') return false;
    try {
      accessSync(join(dir, command), constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

/**
 * Whether this machine's tool calls reach the hook server, the one process that can supply a
 * credential and replace it in the output. The hook client falls back to a one-shot hook with
 * `AKA_HOOK_SERVER=0`, without `perl`, or when the server declines the call.
 */
export function credentialHandlesCanBeSupplied(
  settings: ConsentSettings,
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  if (!hookServerTakesToolCalls(settings)) return false;
  if (env.AKA_HOOK_SERVER === '0') return false;
  return onPath('perl', env.PATH);
}

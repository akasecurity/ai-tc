import type { CredentialListItem, CredentialStatus } from './types.ts';

/** `exposed` exactly when the credential was seen in a live LLM session, else `ok`. */
export function credentialStatus(item: Pick<CredentialListItem, 'exposedAt'>): CredentialStatus {
  return item.exposedAt === null ? 'ok' : 'exposed';
}

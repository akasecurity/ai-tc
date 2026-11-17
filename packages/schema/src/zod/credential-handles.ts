// Handles an agent writes in place of a stored credential, and the two attached
// routes that list and resolve them. The model only ever holds the handle; the
// plugin swaps in the value immediately before a tool runs.
import * as z from 'zod';

export const CREDENTIAL_SLUG_SOURCE = '[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?';

export const CredentialSlug = z
  .string()
  .regex(
    new RegExp(`^${CREDENTIAL_SLUG_SOURCE}$`),
    'must be lower-case letters, digits and dashes',
  );
export type CredentialSlug = z.infer<typeof CredentialSlug>;

const HANDLE_SOURCE = `\\[\\[aka:cred:(${CREDENTIAL_SLUG_SOURCE})\\]\\]`;

/** Returns a new global scanner for credential handles; group 1 is the slug. */
export function credentialHandleScanner(): RegExp {
  return new RegExp(HANDLE_SOURCE, 'g');
}

export function formatCredentialHandle(slug: CredentialSlug): string {
  return `[[aka:cred:${slug}]]`;
}

export const CREDENTIAL_RESOLVE_BATCH_MAX = 20;
export const CREDENTIAL_VALUE_MAX_LENGTH = 65_536;

export const AvailableCredential = z
  .object({
    slug: CredentialSlug,
    description: z.string().max(500),
  })
  .strict();
export type AvailableCredential = z.infer<typeof AvailableCredential>;

/** `GET /v1/vault/available`: the credentials granted to the calling machine. */
export const AvailableCredentialsResponse = z
  .object({ credentials: z.array(AvailableCredential) })
  .strict();
export type AvailableCredentialsResponse = z.infer<typeof AvailableCredentialsResponse>;

/** `POST /v1/vault/resolve`. The machine comes from the credential, never the body. */
export const ResolveCredentialsRequest = z
  .object({
    slugs: z
      .array(CredentialSlug)
      .min(1)
      .max(CREDENTIAL_RESOLVE_BATCH_MAX)
      .refine((slugs) => new Set(slugs).size === slugs.length, 'slugs must be unique'),
    sessionId: z.string().min(1).max(128).nullable(),
  })
  .strict();
export type ResolveCredentialsRequest = z.infer<typeof ResolveCredentialsRequest>;

export const CredentialRefusalReason = z.enum([
  'no_grant',
  'credential_not_found',
  'store_unavailable',
]);
export type CredentialRefusalReason = z.infer<typeof CredentialRefusalReason>;

export const ResolveCredentialsResponse = z
  .object({
    resolved: z.array(
      z
        .object({ slug: CredentialSlug, value: z.string().max(CREDENTIAL_VALUE_MAX_LENGTH) })
        .strict(),
    ),
    refused: z.array(z.object({ slug: CredentialSlug, reason: CredentialRefusalReason }).strict()),
  })
  .strict();
export type ResolveCredentialsResponse = z.infer<typeof ResolveCredentialsResponse>;

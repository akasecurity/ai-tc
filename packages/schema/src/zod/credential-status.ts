import * as z from 'zod';

/**
 * The statuses a credential can carry. A credential carries any number of them,
 * and one carrying none needs no attention, so there is no "OK" member.
 *
 * - `rotation_overdue`: a rotation policy is set and its interval has passed
 *   since the credential was last rotated, or since it was first seen when no
 *   rotation date is known.
 * - `exposed`: the value was seen in a live LLM session.
 */
export const CredentialStatus = z
  .enum(['rotation_overdue', 'exposed'])
  .meta({ id: 'CredentialStatus' });
export type CredentialStatus = z.infer<typeof CredentialStatus>;

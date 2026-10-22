import * as z from 'zod';

/**
 * A status a credential can carry. `rotation_overdue`: a rotation policy is set
 * and its interval has passed since the credential was last rotated, or since
 * it was first seen when no rotation date is known. A credential carrying no
 * status needs no attention.
 */
export const CredentialStatus = z.enum(['rotation_overdue']).meta({ id: 'CredentialStatus' });
export type CredentialStatus = z.infer<typeof CredentialStatus>;

// The longest owner a credential may carry, measured after trimming.
export const CREDENTIAL_OWNER_MAX_LENGTH = 120;

// A rotation policy is a whole number of days in this range.
export const ROTATION_POLICY_MIN_DAYS = 1;
export const ROTATION_POLICY_MAX_DAYS = 3650;

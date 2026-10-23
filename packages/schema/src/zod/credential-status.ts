import * as z from 'zod';

/**
 * A status a credential carries. `exposed`: the value was seen in a live LLM
 * session. `ok`: it carries none of the other statuses. A credential carries
 * `ok` alone or one or more of the others, never both.
 */
export const CredentialStatus = z.enum(['exposed', 'ok']).meta({ id: 'CredentialStatus' });
export type CredentialStatus = z.infer<typeof CredentialStatus>;

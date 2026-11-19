// The SessionStart note that tells the model which credential handles it may use.
import type { AvailableCredential } from '@akasecurity/schema';
import { formatCredentialHandle } from '@akasecurity/schema';

/** Credentials listed at most; the rest are left out of the note. */
export const MAX_BRIEFED_CREDENTIALS = 20;
const MAX_DESCRIPTION_CHARS = 160;

function oneLine(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > MAX_DESCRIPTION_CHARS
    ? `${flat.slice(0, MAX_DESCRIPTION_CHARS - 1)}…`
    : flat;
}

/** The note for `credentials`, or undefined when there are none. */
export function credentialBrief(credentials: readonly AvailableCredential[]): string | undefined {
  if (credentials.length === 0) return undefined;
  const listed = credentials.slice(0, MAX_BRIEFED_CREDENTIALS).map(({ slug, description }) => {
    const about = oneLine(description);
    return about === ''
      ? `- ${formatCredentialHandle(slug)}`
      : `- ${formatCredentialHandle(slug)}: ${about}`;
  });
  const example = formatCredentialHandle(credentials[0]?.slug ?? 'name');
  return [
    'Credentials your organization has granted to this machine through AKA:',
    ...listed,
    `To use one, write its handle literally where the secret goes in a Bash command, for example \`curl -H "Authorization: Bearer ${example}" …\` or \`TOKEN=${example} ./script.sh\`. AKA puts the real value in just before the command runs and turns it back into the handle where the output shows it as written.`,
    'Never ask the user for these values, and do not print, encode, transform or store them: a value that is base64-encoded, reversed or split in the output is not recognised and reaches you as it is.',
  ].join('\n');
}

import { printableForTerminal } from '@akasecurity/plugin-runtime';
import type { ConnectionRefusal } from '@akasecurity/schema';
import { connectionRefusalMessage } from '@akasecurity/schema';

/**
 * A connection refusal's sentence, with each string in it that someone else
 * wrote stripped for the terminal.
 *
 * Two members of a refusal come from an administrator's file: the
 * organization's name and the endpoint it pins or holds. The schema keeps
 * control characters out of neither, so printed as they are, an escape sequence
 * in either one could repaint or hide the lines around the refusal. `aka
 * attach`, `aka detach`, `aka enroll` and `aka unenroll` print every connection
 * refusal through this one function, and a test fails when any other source file
 * (TypeScript or TSX) under cli/src names `connectionRefusalMessage`.
 *
 * The bound is the one the other echoes of an organization or an endpoint use.
 */
export function refusalLine(refusal: ConnectionRefusal): string {
  const shown = (text: string): string => printableForTerminal(text, 200);
  return connectionRefusalMessage({
    ...refusal,
    ...(refusal.organization === undefined ? {} : { organization: shown(refusal.organization) }),
    ...('endpoint' in refusal ? { endpoint: shown(refusal.endpoint) } : {}),
  });
}

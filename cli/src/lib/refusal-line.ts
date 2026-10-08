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
 * in either one could repaint or hide the lines around the refusal. Every
 * command that prints a refusal goes through this one function, so no echo can
 * be left unstripped by being written separately.
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

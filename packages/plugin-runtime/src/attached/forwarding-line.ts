import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { controlPlaneName, scopeVerdict } from '@akasecurity/schema';

import { resolveAttachmentForConfig } from './factory.ts';
import { printableForTerminal } from './status.ts';

/**
 * The one line a session start shows about where this session's activity goes,
 * or null on a machine that forwards nothing.
 *
 * Three states, from the attachment the gateway is built from and the key the
 * session root is stamped with:
 *
 *   machine         `AKA: forwarding everything to <name> (machine-wide)`
 *   scoped, in      `AKA: forwarding to <name> (<enrolled repository>)`
 *   scoped, out     `AKA: local-only (not enrolled); work in an enrolled repository is still forwarded`
 *
 * A standalone machine, a half attachment, and an attachment whose credential
 * cannot be used print nothing: the gateway is local for all of them, so no
 * line means nothing is forwarded. A scoped machine always prints one, so the
 * local-only state is said rather than left to silence.
 *
 * The scoped verdict is the session ROOT's, which is what decides whether the
 * session's own records (its token usage and tool-call records) are sent. A
 * capture is decided by the key it carries, so a local-only session that edits
 * a file in an enrolled repository still sends that capture, which is why the
 * local-only line says so.
 *
 * Never throws: a fault prints nothing, the same answer as a local gateway.
 */
export function forwardingLine(
  config: PluginConfig,
  rootScopeKey: string | undefined,
): string | null {
  try {
    const configured = resolveAttachmentForConfig(config);
    if (configured === null) return null;
    const name = printableForTerminal(controlPlaneName(configured.connection), 200);
    if (configured.attachment.mode === 'machine') {
      return `AKA: forwarding everything to ${name} (machine-wide)`;
    }
    if (
      rootScopeKey !== undefined &&
      scopeVerdict(configured.attachment, rootScopeKey) === 'forward'
    ) {
      return `AKA: forwarding to ${name} (${printableForTerminal(rootScopeKey, 200)})`;
    }
    return 'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';
  } catch {
    return null;
  }
}

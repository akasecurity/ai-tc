/**
 * A bundled rule's first example, with the pack that carries it.
 *
 * Taken from the rule's own examples rather than written in a test: this
 * repository is public, and a credential-shaped literal does not belong in it.
 * Throws when the rule is absent or has no example, so a renamed rule fails
 * setup loudly instead of handing a case an `undefined` to scan.
 */
import { bundledDetections } from '@akasecurity/plugin-sdk';

export interface RuleExample {
  namespace: string;
  packId: string;
  example: string;
}

export function ruleExample(ruleId: string): RuleExample {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === ruleId));
  const example = pack?.rules.find((r) => r.id === ruleId)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${ruleId} is missing from the pack registry or has no example`);
  }
  return { namespace: pack.namespace, packId: pack.packId, example };
}

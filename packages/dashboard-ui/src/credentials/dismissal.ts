import type { DismissMethod } from '@akasecurity/schema';

import type { Choice } from '../shared/ChoiceGroup.tsx';

/** The reasons a credential can be dismissed for, worded for a credential. */
export const CREDENTIAL_DISMISS_REASONS: readonly Choice<DismissMethod>[] = [
  {
    value: 'acknowledged',
    label: 'Accepted risk',
    description: 'The value is a real credential, and you are choosing to accept where it is used.',
  },
  {
    value: 'false-positive',
    label: 'Not a credential',
    description: 'The value only looks like a credential: it grants no access to anything.',
  },
  {
    value: 'test-or-example',
    label: 'Test or example data',
    description: 'The value is a test fixture or an example, not a live credential.',
  },
];

/** The label of a dismissal reason; the reason itself when no label names it. */
export function credentialDismissReasonLabel(reason: DismissMethod): string {
  return CREDENTIAL_DISMISS_REASONS.find((r) => r.value === reason)?.label ?? reason;
}

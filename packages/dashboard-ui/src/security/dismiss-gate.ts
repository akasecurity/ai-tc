// The Dismiss dialog's decisions, as pure functions.
//
// They live outside the view because the view is only server-rendered in this
// package's suite (see vitest.config.ts — `node`, with a per-file jsdom
// opt-in), so a gate expressed only as a `disabled={…}` expression inside JSX
// is reachable by no assertion here. Pulling them out keeps them testable
// without a DOM, and keeps the JSX below a rendering of decisions rather than
// the place they are made.
//
// NONE of this is the control. The dialog gate is UX; the Server Action
// re-checks the confirmation word and the method against the schema before it
// writes, exactly as `rotateKey` and `purgeVault` do. A caller that posts
// straight to the action never renders any of this.
import type { DismissMethod } from '@akasecurity/schema';
import { DISMISS_CONFIRMATION } from '@akasecurity/schema';

import type { Choice } from '../shared/ChoiceGroup.tsx';

/**
 * The two dispositions the dialog offers, in the order it renders them.
 *
 * Typed as `Choice` so it can be handed straight to `ChoiceGroup`, which
 * renders every option's description at once. A type-only import, so this
 * module stays free of React and can be unit-tested with no DOM.
 *
 * The descriptions are load-bearing rather than decorative: the two answers
 * differ in what they CLAIM, not merely in how a report groups them later.
 * 'Accepted risk' says the finding is real and this team has chosen to live
 * with it; 'Not a real finding' says the rule is wrong. A reader who cannot see
 * both descriptions while choosing has no way to tell them apart from the
 * labels alone.
 */
export const DISMISS_METHODS: readonly Choice<DismissMethod>[] = [
  {
    value: 'acknowledged',
    label: 'Accepted risk',
    description: 'The finding is real, and this team has decided not to act on it.',
  },
  {
    value: 'false-positive',
    label: 'Not a real finding',
    description: 'The rule matched something that is not actually sensitive.',
  },
];

/**
 * Whether the confirm button may fire.
 *
 * The confirmation is compared EXACTLY — not trimmed, not lower-cased. A
 * confirmation exists to be deliberate, and every forgiving comparison makes it
 * a little less so; the two sibling surfaces on this dashboard (`rotate`,
 * `purge`) compare exactly for the same reason, and the action re-checks it the
 * same way, so accepting ` Dismiss ` here would produce a dialog that arms a
 * button the server then refuses.
 */
export function canConfirmDismiss(state: {
  confirmation: string;
  method: DismissMethod | null;
  isMutating: boolean;
}): boolean {
  if (state.isMutating) return false;
  if (state.method === null) return false;
  return state.confirmation === DISMISS_CONFIRMATION;
}

/**
 * What the dialog tells the reader will happen, in one sentence per consequence.
 *
 * Kept here rather than inline so the claims are assertable: each is a fact
 * about the write this button performs, and the third is the one a reader
 * cannot discover anywhere else in the product — a dismissed finding is not
 * reopened by a later scan that detects the same value again, because the
 * scanner's redetect pass reopens only `resolved` keys.
 */
export function dismissConsequences(ruleId: string): readonly string[] {
  return [
    `Closes every open finding for ${ruleId}, across every file and session.`,
    'The findings stay in the store and keep their history — they are closed, not deleted.',
    'A later scan that finds the same value again will NOT reopen them.',
    'There is no undo in the dashboard.',
  ];
}

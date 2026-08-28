'use client';
// The enforcement-policy picker: a segmented control over the built-in
// archetypes, in display order.
//
// Three states, not two, and the third is the reason this takes a prop rather
// than a boolean:
//
//   `onChange` given            — live; the host persists the choice.
//   `onChange` omitted          — read-only; a host with no per-detection write
//                                 keeps the UI without implying a write path.
//   `unavailable[id]` given     — with `onChange`: the host CAN write, but not
//                                 this value (ignored entirely without it), and
//                                 says why. Offered `aria-disabled` with the
//                                 reason rather than dropped from the list —
//                                 aria rather than native, so the option keeps
//                                 its place in the tab order and the reason
//                                 reaches a keyboard user at the control.
//
// The third state exists because an archetype the product documents can be
// unassignable through one particular host — Redact & Vault through a control
// plane whose devices will not accept a remote custody instruction — and the
// alternative to saying so here was a live-looking button that takes a click,
// fails on the server, and snaps back under an error banner.
import { toneColors } from '@akasecurity/ui-kit';
import { useId } from 'react';

import { BUILTIN_POLICY_IDS, policyMeta } from './meta.ts';

export function PolicyPicker({
  value,
  onChange,
  unavailable,
}: {
  // The assigned policy id; falls back to the visual default when unset.
  value: string | undefined;
  onChange?: ((policyId: string) => void) | undefined;
  /**
   * Policy ids this host can render but not assign, each mapped to WHY.
   *
   * Offered-and-disabled rather than hidden, deliberately. Hiding an archetype
   * the product documents turns "you cannot pick this here, because X" into
   * "this does not exist", and the reader's next move is to go looking for it.
   * A disabled control with its reason answers the question in place.
   *
   * Optional, and empty by default: a host that knows of no restriction — the
   * OSS dashboard, which assigns against its own local store — passes nothing
   * and gets exactly the control it had before.
   */
  unavailable?: Readonly<Record<string, string>> | undefined;
}) {
  const disabled = !onChange;
  // Distinct from `disabled` above, which is about the HOST having no write path
  // at all. This is per-option: the host can write, and this one value is the one
  // it cannot deliver.
  // Ignored outright when there is NO write path, which is the combination the
  // two designed states do not cover between them. `unavailable` means "the host
  // can write, but not this value" — a statement that does not exist when the
  // host cannot write anything, and rendering it there is actively wrong twice
  // over: the reason line implies the OTHER archetypes are assignable when none
  // of them is, and the button would carry `aria-describedby` while natively
  // disabled, so the description never reaches the keyboard user it exists for.
  // Read-only wins, and the whole third state collapses.
  const reasonFor = (id: string): string | undefined => (disabled ? undefined : unavailable?.[id]);
  const reasons = [...new Set(BUILTIN_POLICY_IDS.map(reasonFor).filter((r) => r !== undefined))];
  // Keyed on the REASON rather than the policy id, because the lines below are
  // deduped by string — two unavailable archetypes sharing a sentence render one
  // <p>, and both buttons must point at it. useId keeps two pickers on one page
  // from minting the same ids.
  const base = useId();
  const reasonId = (reason: string): string =>
    `${base}-unavailable-${String(reasons.indexOf(reason))}`;
  return (
    <div className="flex flex-col items-start gap-1.5">
      <div
        className={
          'inline-flex gap-1 self-start rounded-lg border border-border bg-surface-2 p-0.5' +
          (disabled ? ' opacity-70' : '')
        }
        aria-disabled={disabled || undefined}
      >
        {BUILTIN_POLICY_IDS.map((k) => {
          const m = policyMeta(k);
          const on = value === k;
          const [fg, bg] = toneColors(m.tone);
          // The neutral tone's tint (surface-3) barely contrasts with this control's
          // surface-2 track, so a selected "Monitor" looks unselected. Fall back to a
          // white pill for it — the shadow then makes the selection read clearly.
          const selBg = m.tone === 'neutral' ? 'var(--color-surface)' : bg;
          const Icon = m.icon;
          const reason = reasonFor(k);
          return (
            <button
              key={k}
              type="button"
              // NATIVE `disabled` only for the whole-control case. For a
              // per-option restriction the control stays focusable and carries
              // `aria-disabled`, because the entire point of this state is that
              // the REASON reaches the person who wanted that archetype — and a
              // natively disabled button leaves the tab order, so a keyboard or
              // screen-reader user never lands on it and never hears why.
              // Focusable is safe here: `onClick` below is undefined whenever
              // `reason` is set, so activation is already inert, and this
              // control's styling keys on `reason` rather than on `:disabled`,
              // so nothing visual is lost by dropping the attribute.
              disabled={disabled}
              aria-disabled={disabled || reason !== undefined || undefined}
              // Points at the line below, so the reason is announced AT the
              // control rather than as prose the user has to go and find.
              aria-describedby={reason === undefined ? undefined : reasonId(reason)}
              // The reason travels with the control, not only in the line below,
              // so a pointer user gets it without reading ahead.
              title={reason}
              onClick={
                onChange && reason === undefined
                  ? () => {
                      onChange(k);
                    }
                  : undefined
              }
              aria-pressed={on}
              data-unavailable={reason === undefined ? undefined : ''}
              className={
                'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-semibold ' +
                (disabled || reason !== undefined ? 'cursor-not-allowed ' : 'cursor-pointer ') +
                (reason === undefined ? '' : 'opacity-50 ') +
                (on ? 'shadow-sm' : 'text-text-3')
              }
              style={on ? { color: fg, background: selBg } : undefined}
            >
              <Icon aria-hidden focusable={false} className="size-4" />
              {m.label}
            </button>
          );
        })}
      </div>
      {reasons.map((reason) => (
        // Below the control rather than only in `title`, because a tooltip is
        // invisible on touch and unreliable for assistive tech. This line is the
        // accessible copy of the same sentence, and `aria-describedby` above
        // points the unavailable buttons at it — so it is both visible prose and
        // the announced description, rather than something to encounter
        // separately.
        <p
          key={reason}
          id={reasonId(reason)}
          className="text-xs text-text-3"
          data-slot="policy-unavailable-reason"
        >
          {reason}
        </p>
      ))}
    </div>
  );
}

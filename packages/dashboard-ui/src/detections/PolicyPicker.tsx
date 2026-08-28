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
//   `unavailable[id]` given     — the host CAN write, but not this value, and
//                                 says why. Rendered disabled with the reason
//                                 rather than dropped from the list.
//
// The third state exists because an archetype the product documents can be
// unassignable through one particular host — Redact & Vault through a control
// plane whose devices will not accept a remote custody instruction — and the
// alternative to saying so here was a live-looking button that takes a click,
// fails on the server, and snaps back under an error banner.
import { BUILTIN_POLICY_IDS, policyMeta, toneColors } from './meta.ts';

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
  const reasonFor = (id: string): string | undefined => unavailable?.[id];
  const reasons = [...new Set(BUILTIN_POLICY_IDS.map(reasonFor).filter((r) => r !== undefined))];
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
          // The gray tone's tint (surface-3) barely contrasts with this control's
          // surface-2 track, so a selected "Monitor" looks unselected. Fall back to a
          // white pill for gray — the shadow then makes the selection read clearly.
          const selBg = m.tone === 'gray' ? 'var(--color-surface)' : bg;
          const Icon = m.icon;
          const reason = reasonFor(k);
          return (
            <button
              key={k}
              type="button"
              disabled={disabled || reason !== undefined}
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
        // Below the control rather than only in `title`: a disabled button is
        // not focusable, so a tooltip is unreachable by keyboard and invisible
        // on touch. This line is the accessible copy of the same sentence.
        <p key={reason} className="text-xs text-text-3" data-slot="policy-unavailable-reason">
          {reason}
        </p>
      ))}
    </div>
  );
}

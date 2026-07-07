'use client';
// The enforcement-policy picker: a segmented control over the built-in actions
// (monitor / warn / redact / block). Controllable — when `onChange` is provided
// (a host that persists the choice) the buttons are live; when it is
// omitted (a host with no per-detection policy write) the control renders
// read-only, preserving the UI without implying a write path.
import { BUILTIN_POLICY_IDS, policyMeta, toneColors } from './meta.ts';

export function PolicyPicker({
  value,
  onChange,
}: {
  // The assigned policy id; falls back to the visual default when unset.
  value: string | undefined;
  onChange?: ((policyId: string) => void) | undefined;
}) {
  const disabled = !onChange;
  return (
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
        return (
          <button
            key={k}
            type="button"
            disabled={disabled}
            onClick={
              onChange
                ? () => {
                    onChange(k);
                  }
                : undefined
            }
            aria-pressed={on}
            className={
              'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-semibold ' +
              (disabled ? 'cursor-not-allowed ' : 'cursor-pointer ') +
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
  );
}

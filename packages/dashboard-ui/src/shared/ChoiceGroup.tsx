'use client';

import { cn } from '@akasecurity/ui-kit';

/**
 * One option in a {@link ChoiceGroup}: what it is worth, what it is called, and
 * what choosing it means. The description is not decoration — it is the only
 * place the consequence of an option is stated, so every choice carries one.
 */
export interface Choice<T extends string> {
  value: T;
  label: string;
  description: string;
}

/**
 * A vertical list of radio cards, each showing its own label AND its own
 * description at once.
 *
 * Native `<input type="radio">` rather than a Radix primitive, which is not the
 * usual rule in this package — but the concerns that rule exists for
 * (outside-click, focus traps, anchored positioning) are none of them a radio
 * group's, and the browser already gives roving focus, arrow-key movement,
 * label association and a grouped announcement for free. A `<label>` wrapping
 * the input is what makes the whole card a hit target without an `htmlFor`/`id`
 * pair to keep unique across two groups on one page.
 *
 * Every description is rendered, never only the selected one's. A single line
 * that swaps as the selection moves makes the reader choose in order to find out
 * what they are choosing, which on a consent or a disposition control is the one
 * thing the description is there to prevent.
 *
 * `labelledBy` points at the group's own visible heading. Falling back to the
 * field NAME announced storage keys to a screen reader — "vaultConsent",
 * "historicalAccess" — which name the setting to nobody but us.
 */
export function ChoiceGroup<T extends string>({
  name,
  labelledBy,
  choices,
  value,
  onChange,
  disabled,
}: {
  name: string;
  labelledBy?: string;
  /**
   * Readonly, so a module-level constant can be passed without a defensive
   * copy at every call site — this renders its input and never reorders or
   * mutates it.
   */
  choices: readonly Choice<T>[];
  /** The current selection, or null where nothing has been chosen yet. */
  value: T | null;
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex flex-col gap-2" role="radiogroup" aria-labelledby={labelledBy}>
      {choices.map((c) => (
        <label
          key={c.value}
          className={cn(
            'flex items-start gap-3 rounded-lg border p-3 transition-colors',
            disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
            value === c.value
              ? 'border-primary bg-primary-tint'
              : cn('border-border bg-surface', !disabled && 'hover:bg-surface-2'),
          )}
        >
          <input
            type="radio"
            name={name}
            checked={value === c.value}
            disabled={disabled}
            onChange={() => {
              onChange(c.value);
            }}
            className="mt-1 accent-primary"
          />
          <span>
            <span className="block text-sm font-medium text-text">{c.label}</span>
            <span className="mt-0.5 block text-xs text-text-2">{c.description}</span>
          </span>
        </label>
      ))}
    </div>
  );
}

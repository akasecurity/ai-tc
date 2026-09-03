'use client';
import type { ExceptionDescriptor } from '@akasecurity/schema';
import { Badge, SegmentedControl, SegmentedControlItem } from '@akasecurity/ui-kit';

import type { ExceptionState, ScopeAnswer } from './meta.ts';
import {
  CAPABILITY_LABEL,
  exceptionState,
  SCOPE_ANSWER_LABEL,
  SCOPE_ANSWERS,
  STATE_TONE,
} from './meta.ts';

/** Lifecycle state chip (derived, never stored). */
export function StateTag({ state }: { state: ExceptionState }) {
  return <Badge variant={STATE_TONE[state]}>{state}</Badge>;
}

/**
 * Lifecycle chip for a grant, derived at `now`. `now` is required for the reason
 * {@link exceptionState}'s is — a chip that picks its own instant reads `active`
 * on the server and `expired` in the browser whenever the two straddle
 * `expiresAt`.
 */
export function StateTagFor({ exception, now }: { exception: ExceptionDescriptor; now: number }) {
  return <StateTag state={exceptionState(exception, now)} />;
}

/**
 * Capability chip. Rendered ONLY for reveal-to-model grants — while such a
 * grant is active the model can receive the value's raw form at tool
 * boundaries, so the register flags it on every surface. Suppression (the
 * default) stays unlabelled: repeating "suppress" on every row would bury the
 * one capability that matters.
 */
export function CapabilityTagFor({ exception }: { exception: ExceptionDescriptor }) {
  if (exception.capability !== 'reveal_to_model') return null;
  return <Badge variant="critical">{CAPABILITY_LABEL.reveal_to_model}</Badge>;
}

/**
 * The scope choice every grant form requires — once / 30m / 1h / 24h /
 * permanent. Emits the raw answer string; the server action resolves it via
 * the schema's scopeFromAnswer (scope is an explicit choice, never defaulted).
 */
export function ScopePicker({
  value,
  onChange,
}: {
  value: ScopeAnswer | null;
  onChange: (scope: ScopeAnswer) => void;
}) {
  return (
    <SegmentedControl
      value={value ?? ''}
      onValueChange={(next: string) => {
        if (next) onChange(next as ScopeAnswer);
      }}
    >
      {SCOPE_ANSWERS.map((answer) => (
        <SegmentedControlItem key={answer} value={answer}>
          {SCOPE_ANSWER_LABEL[answer]}
        </SegmentedControlItem>
      ))}
    </SegmentedControl>
  );
}

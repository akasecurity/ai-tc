'use client';
import type { DetectionException } from '@akasecurity/schema';
import { Badge, SegmentedControl, SegmentedControlItem } from '@akasecurity/ui-kit';

import type { ExceptionState, ScopeAnswer } from './meta.ts';
import { exceptionState, SCOPE_ANSWER_LABEL, SCOPE_ANSWERS, STATE_TONE } from './meta.ts';

/** Lifecycle state chip (derived, never stored). */
export function StateTag({ state }: { state: ExceptionState }) {
  return <Badge variant={STATE_TONE[state]}>{state}</Badge>;
}

export function StateTagFor({ exception, now }: { exception: DetectionException; now?: number }) {
  return <StateTag state={exceptionState(exception, now)} />;
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

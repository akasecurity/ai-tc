'use client';
import {
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@akasecurity/ui-kit';

import { BLOCKED_WINDOWS, type BlockedWindow } from '../lib/timeRanges.ts';
import { CalendarIcon, ChevronDownIcon } from '../shared/icons.tsx';

/** Lookback-window filter for the "Recently blocked" ledger: a chip trigger + dropdown. */
export function BlockedWindowSelect({
  value,
  onChange,
}: {
  value: BlockedWindow;
  onChange: (value: BlockedWindow) => void;
}) {
  const currentLabel = BLOCKED_WINDOWS.find((w) => w.value === value)?.label ?? value;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" tone="neutral" size="sm">
          <CalendarIcon aria-hidden focusable={false} className="size-3.5 text-text-3" />
          {currentLabel}
          <ChevronDownIcon aria-hidden focusable={false} className="size-3.5 text-text-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        <DropdownMenuRadioGroup
          value={value}
          onValueChange={(v) => {
            onChange(v as BlockedWindow);
          }}
        >
          {BLOCKED_WINDOWS.map((w) => (
            <DropdownMenuRadioItem key={w.value} value={w.value}>
              {w.label}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

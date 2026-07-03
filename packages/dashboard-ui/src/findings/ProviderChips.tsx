import type { FindingProvider } from '@akasecurity/schema';

import { Provider, PROVIDERS } from '../shared/Provider.tsx';

/** Overlapping avatar stack of the distinct providers for a finding. */
export function ProviderChips({ ids }: { ids: FindingProvider[] }) {
  return (
    <div className="flex items-center -space-x-1.5">
      {ids.map((id) => (
        <span
          key={id}
          title={PROVIDERS[id].label}
          className="inline-flex rounded-lg ring-2 ring-surface"
        >
          <Provider id={id} />
        </span>
      ))}
    </div>
  );
}

/** A single provider chip with its label — used in instance (location) rows. */
export function ProviderTag({ provider }: { provider: FindingProvider }) {
  return (
    <span className="inline-flex items-center gap-2 font-display text-xs text-text">
      <Provider id={provider} />
      {PROVIDERS[provider].label}
    </span>
  );
}

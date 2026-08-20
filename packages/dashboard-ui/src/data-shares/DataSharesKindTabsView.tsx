'use client';
// Kind-tab strip for the Data Shares register — one tab per destination kind
// (providers / internal / external / raw IPs), each carrying its count and a
// review-recommended flag for external/raw-IP groups. Rendered by the app as
// a sibling of the table (see DataSharesTableView), inside a shared ui-kit
// `Tabs` root the app owns — that's what lets the tab strip sit outside the
// table's scroll container while still driving which group the table shows.
// No margin of its own: the app places this beside its search box in one
// row, so the row (not this list) owns the spacing below it.
import type { ShareDestinationGroup } from '@akasecurity/schema';
import { TabsList, TabsTrigger } from '@akasecurity/ui-kit';

import { AlertIcon } from '../shared/icons.tsx';
import { KIND_LABEL } from './meta.ts';

function KindTabLabel({ group }: { group: ShareDestinationGroup }) {
  return (
    <>
      {KIND_LABEL[group.kind]}
      <span className="rounded-full border border-border bg-surface-2 px-1.5 text-label py-0.5 font-semibold text-text-2">
        {group.total}
      </span>
      {(group.kind === 'ip' || group.kind === 'external') && (
        <AlertIcon
          aria-hidden
          focusable={false}
          className={group.kind === 'ip' ? 'text-sev-critical-ink' : 'text-sev-high-ink'}
        />
      )}
    </>
  );
}

export interface DataSharesKindTabsViewProps {
  groups: ShareDestinationGroup[];
}

export function DataSharesKindTabsView({ groups }: DataSharesKindTabsViewProps) {
  return (
    <TabsList className="shrink-0">
      {groups.map((g) => (
        <TabsTrigger key={g.kind} value={g.kind}>
          <KindTabLabel group={g} />
        </TabsTrigger>
      ))}
    </TabsList>
  );
}

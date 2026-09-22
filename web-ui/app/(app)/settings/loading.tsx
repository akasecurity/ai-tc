import { Skeleton } from '@akasecurity/ui-kit';

import { CardSkeleton, PageHeadSkeleton } from '../../components/skeletons';

// One section per group the page renders, in its order, each a LABEL plus a
// card — the same `<h2>` + card pair SettingGroup emits. Mirroring the pair
// matters as much as the heights do: five omitted labels is a systematic ~105px
// that no card size absorbs.
//
// The structure mirrors page.tsx as well. PageHeadSkeleton carries its own
// `pb-6`, exactly as the real PageHead does, so it sits OUTSIDE the `gap-7`
// column; inside it, that 24px and the column's 28px would both apply and every
// card below would start 28px low.
//
// The heights are the real cards, measured with every row collapsed — what the
// page renders on load — at the 768px the `max-w-3xl` column settles to on a
// desktop viewport. Measure at that width or not at all: read at a 713px column
// the same page reports Connection and Enforcement 16px taller apiece, because
// one notice paragraph in each takes an extra line.
//
// Four are stable — Enforcement is fixed copy, and Data access, Display and
// Storage are a fixed row count. Connection is the one that moves with machine
// state: an attached machine renders credential and forwarding notices where a
// standalone one renders the attach form, so this is a stand-in for both rather
// than a match for either.
//
// Nothing stands in for the Sync panel below the form: readSyncPanel returns
// null unless the machine is attached, so a card here would be a phantom on
// every standalone one.
const SECTIONS = [
  { group: 'connection', height: 'h-58' },
  { group: 'enforcement', height: 'h-54' },
  { group: 'data-access', height: 'h-87' },
  { group: 'display', height: 'h-20' },
  { group: 'storage', height: 'h-16' },
] as const;

export default function Loading() {
  return (
    <div aria-busy className="box-content max-w-3xl p-6">
      <PageHeadSkeleton />
      <div className="flex flex-col gap-7">
        {SECTIONS.map(({ group, height }) => (
          // Keyed on the group, never the height: two groups may measure the
          // same and duplicate keys would collide.
          <div key={group}>
            {/* `text-label` (11px) over `mb-2`, matching SettingGroup's h2. */}
            <Skeleton className="mb-2 h-3 w-24" />
            <CardSkeleton className={`${height} rounded-xl`} />
          </div>
        ))}
      </div>
    </div>
  );
}

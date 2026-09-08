import { CardSkeleton, PageHeadSkeleton } from '../../components/skeletons';

// Four groups, four skeletons — Connection, Enforcement, Data access, Display.
// They are short because the rows they stand in for are collapsed: a tall
// skeleton followed by a compact page is a layout jump, not a loading state.
export default function Loading() {
  return (
    <div aria-busy className="flex max-w-4xl flex-col gap-7 p-6">
      <PageHeadSkeleton />
      <CardSkeleton className="h-28 rounded-xl" />
      <CardSkeleton className="h-16 rounded-xl" />
      <CardSkeleton className="h-36 rounded-xl" />
      <CardSkeleton className="h-16 rounded-xl" />
    </div>
  );
}

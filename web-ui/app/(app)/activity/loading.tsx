import {
  CompactStatStripSkeleton,
  MasterDetailSkeleton,
  PageHeadSkeleton,
} from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex h-full min-h-0 flex-col p-6">
      <PageHeadSkeleton actions />
      {/* Token usage is a chip inside the PageHead actions, not a card of its
          own — so the strip is the only band above the session master/detail. */}
      <CompactStatStripSkeleton />
      <MasterDetailSkeleton />
    </div>
  );
}

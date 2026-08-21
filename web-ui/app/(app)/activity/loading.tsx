import {
  CompactStatStripSkeleton,
  MasterDetailSkeleton,
  PageHeadSkeleton,
} from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHeadSkeleton actions />
      {/* Token usage is a chip inside the PageHead actions, not a card of its
          own — so the strip is the only band above the session master/detail,
          and ActivityClient's root carries no top margin. */}
      <CompactStatStripSkeleton className="mb-3" />
      <MasterDetailSkeleton className="mt-0" />
    </div>
  );
}

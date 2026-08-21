import {
  CompactStatStripSkeleton,
  MasterDetailSkeleton,
  PageHeadSkeleton,
} from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHeadSkeleton />
      {/* No margin here and `mt-4` below: the real page's strip carries none and
          DetectionsClient's grid carries the gap. */}
      <CompactStatStripSkeleton />
      <MasterDetailSkeleton />
    </div>
  );
}

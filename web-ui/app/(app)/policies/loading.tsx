import {
  CompactStatStripSkeleton,
  MasterDetailSkeleton,
  PageHeadSkeleton,
} from '../../components/skeletons';

export default function Loading() {
  return (
    // Mirrors page.tsx's wrapper, including the lg-gated height cap.
    <div aria-busy className="flex min-h-full flex-col px-8 pb-8 pt-7 lg:h-full lg:min-h-0">
      <PageHeadSkeleton />
      <CompactStatStripSkeleton className="mb-3" />
      <MasterDetailSkeleton stacksBelowLg listWidth="lg:w-80" />
    </div>
  );
}

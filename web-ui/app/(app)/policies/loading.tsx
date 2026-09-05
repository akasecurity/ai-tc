import {
  CompactStatStripSkeleton,
  MasterDetailSkeleton,
  PageHeadSkeleton,
} from '../../components/skeletons';

export default function Loading() {
  return (
    // Mirrors page.tsx's wrapper, including the lg-gated height cap.
    <div aria-busy className="flex min-h-full flex-col p-6 lg:h-full lg:min-h-0">
      <PageHeadSkeleton />
      <CompactStatStripSkeleton />
      <MasterDetailSkeleton stacksBelowLg listWidth="w-80" />
    </div>
  );
}

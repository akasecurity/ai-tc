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
      {/* The real page spends its gap on the strip's own wrapper (`mb-4`) and
          PoliciesClient's grid carries no top margin — so the pair is mb-4/mt-0. */}
      <CompactStatStripSkeleton className="mb-4" />
      <MasterDetailSkeleton className="mt-0" />
    </div>
  );
}

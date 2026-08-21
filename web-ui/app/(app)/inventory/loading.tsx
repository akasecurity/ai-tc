import { MasterDetailSkeleton, PageHeadSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHeadSkeleton />
      {/* InventoryClient's root carries no top margin. */}
      <MasterDetailSkeleton className="mt-0" />
    </div>
  );
}

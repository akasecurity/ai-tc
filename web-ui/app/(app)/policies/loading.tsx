import { MasterDetailSkeleton, PageHeadSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex min-h-full flex-col px-8 pb-10 pt-7">
      <PageHeadSkeleton />
      <MasterDetailSkeleton />
    </div>
  );
}

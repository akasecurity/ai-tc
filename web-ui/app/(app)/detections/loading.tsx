import {
  CompactStatStripSkeleton,
  MasterDetailSkeleton,
  PageHeadSkeleton,
} from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex h-full min-h-0 flex-col p-6">
      <PageHeadSkeleton />
      <CompactStatStripSkeleton />
      <MasterDetailSkeleton listWidth="w-88" />
    </div>
  );
}

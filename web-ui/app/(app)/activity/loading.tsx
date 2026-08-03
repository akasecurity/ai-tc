import {
  CardSkeleton,
  MasterDetailSkeleton,
  PageHeadSkeleton,
  StatStripSkeleton,
} from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex h-full min-h-0 flex-col px-8 pb-8 pt-7">
      <PageHeadSkeleton actions />
      <StatStripSkeleton />
      <CardSkeleton className="h-24" />
      <MasterDetailSkeleton />
    </div>
  );
}

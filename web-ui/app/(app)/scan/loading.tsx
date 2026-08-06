import { CardSkeleton, PageHeadSkeleton, StatStripSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex max-w-3xl flex-col gap-6 px-8 pb-10 pt-7">
      <PageHeadSkeleton />
      <StatStripSkeleton tiles={4} />
      <CardSkeleton className="h-50 rounded-xl" />
    </div>
  );
}

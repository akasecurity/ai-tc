import { CardGridSkeleton, PageHeadSkeleton, StatStripSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="px-8 pb-10 pt-7">
      <PageHeadSkeleton actions />
      <StatStripSkeleton tiles={4} />
      <CardGridSkeleton cards={3} />
      <CardGridSkeleton cards={2} className="mt-4 lg:grid-cols-2 xl:mt-5" />
    </div>
  );
}

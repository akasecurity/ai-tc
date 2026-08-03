import { CardSkeleton, PageHeadSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex flex-col gap-4 px-8 pb-10 pt-7">
      <PageHeadSkeleton />
      <CardSkeleton />
      <CardSkeleton className="h-40" />
    </div>
  );
}

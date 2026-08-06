import { CardSkeleton, PageHeadSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex max-w-4xl flex-col gap-6 px-8 pb-10 pt-7">
      <PageHeadSkeleton />
      <CardSkeleton className="h-50 rounded-xl" />
      <CardSkeleton className="h-50 rounded-xl" />
      <CardSkeleton className="h-50 rounded-xl" />
      <CardSkeleton className="h-50 rounded-xl" />
    </div>
  );
}

import { CardSkeleton, PageHeadSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex max-w-3xl flex-col gap-6 p-6">
      <PageHeadSkeleton />
      <CardSkeleton className="h-50 rounded-xl" />
    </div>
  );
}

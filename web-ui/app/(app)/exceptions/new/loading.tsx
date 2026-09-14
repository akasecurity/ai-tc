import { CardSkeleton, PageHeadSkeleton } from '../../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="p-6">
      <PageHeadSkeleton />
      <CardSkeleton />
    </div>
  );
}

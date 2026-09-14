import { PageHeadSkeleton, TableSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="p-6">
      <PageHeadSkeleton />
      <TableSkeleton />
    </div>
  );
}

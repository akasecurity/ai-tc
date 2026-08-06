import { PageHeadSkeleton, TableSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="px-8 pb-10 pt-7">
      <PageHeadSkeleton />
      <TableSkeleton />
    </div>
  );
}

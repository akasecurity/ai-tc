import { PageHeadSkeleton, TableSkeleton, ToolbarSkeleton } from '../../components/skeletons';

export default function Loading() {
  return (
    <div aria-busy className="flex h-full min-h-0 flex-col p-6">
      <PageHeadSkeleton actions />
      <ToolbarSkeleton />
      <TableSkeleton />
    </div>
  );
}

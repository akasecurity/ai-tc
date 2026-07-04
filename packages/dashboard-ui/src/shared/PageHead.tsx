import { type ReactNode } from 'react';

/** Page header: title + subtitle on the left, action controls on the right. */
export function PageHead({
  title,
  sub,
  actions,
}: {
  title: string;
  sub?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-4 pb-6">
      <div>
        <h1 className="font-display text-2xl font-semibold text-text">{title}</h1>
        {sub && <p className="mt-1 text-sm text-text-3">{sub}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

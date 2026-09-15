import type { FindingDelivery } from '@akasecurity/schema';
import { Badge } from '@akasecurity/ui-kit';

import { MetaItem } from '../shared/DetailFields.tsx';
import { deliveryDetail, type DeploymentDisplay, findingDeliveryMeta } from './meta.ts';

/**
 * The detail drawer's Deployment row: a finding's delivery state and what it
 * means. Spans both columns of the drawer's field grid, because the sentence
 * under the badge does not fit one.
 */
export function DeploymentMetaItem({
  delivery,
  deployment,
  renderedAt,
}: {
  delivery: FindingDelivery;
  deployment: DeploymentDisplay;
  /** The instant relative times are measured against, in epoch milliseconds. */
  renderedAt: number;
}) {
  const meta = findingDeliveryMeta(delivery.state);
  return (
    <div className="col-span-2">
      <MetaItem label="Deployment">
        <div className="flex flex-col items-start gap-1">
          <Badge variant={meta.badge} className="h-6">
            {meta.label}
          </Badge>
          <span className="text-xs font-normal text-text-2">
            {deliveryDetail(delivery, deployment, renderedAt)}
          </span>
          <span className="text-xs font-normal text-text-3">Based on its latest detection.</span>
        </div>
      </MetaItem>
    </div>
  );
}

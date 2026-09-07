import type { Severity, WebSourceTool } from '@akasecurity/schema';
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardHeading,
  CardIcon,
  CardTitle,
  Skeleton,
} from '@akasecurity/ui-kit';

import { GlobeIcon } from '../shared/icons.tsx';
import { WidgetError } from './widget-shared.tsx';

const SITE_LABELS = {
  chatgpt: 'ChatGPT',
  'claude-ai': 'Claude.ai',
} satisfies Record<WebSourceTool, string>;

/**
 * One site's row, as this card renders it. A presentation descriptor: `stateLabel`
 * is the display word the caller already chose, not a vocabulary this package owns
 * (the state enum lives in @akasecurity/detections, which dashboard-ui may not import).
 */
export interface WebCaptureSiteRow {
  tool: WebSourceTool;
  stateLabel: string;
  headline: string;
  remediation?: string;
  drift: boolean;
}

export interface WebCaptureCardViewProps {
  sites: WebCaptureSiteRow[];
  /** The posture rule a drifting row cites. */
  ruleId: string;
  severity: Severity;
  isLoading: boolean;
  error: string | null;
}

/** Per-site web chat capture posture: which sites the browser extension is
 * reading cleanly, and which have drifted. */
export function WebCaptureCardView({
  sites,
  ruleId,
  severity,
  isLoading,
  error,
}: WebCaptureCardViewProps) {
  return (
    <Card className="flex flex-col shadow-sm">
      <CardHeader>
        <CardIcon tone="teal">
          <GlobeIcon aria-hidden focusable={false} className="size-4" />
        </CardIcon>
        <CardHeading>
          <CardTitle>Web chat capture</CardTitle>
          <CardDescription>Browser extension · per site</CardDescription>
        </CardHeading>
      </CardHeader>
      <CardContent aria-busy={isLoading} className="flex flex-col gap-3">
        {error ? (
          <WidgetError message={error} />
        ) : isLoading ? (
          [0, 1].map((i) => <Skeleton key={i} className="h-10 w-full" />)
        ) : (
          sites.map((site) => (
            <div key={site.tool} className="flex flex-col gap-1">
              <div className="flex items-center gap-2">
                <span className="w-20 shrink-0 text-ui font-medium text-text">
                  {SITE_LABELS[site.tool]}
                </span>
                <span className="text-xs font-semibold uppercase tracking-wide text-text-3">
                  {site.stateLabel}
                </span>
              </div>
              <p className="text-xs text-text-2">{site.headline}</p>
              {site.drift && (
                // `data-severity` is the severity as DATA. A test that reads it
                // off the rendered markup is asserting what the card was told,
                // where matching the word inside the class list `variant`
                // expands to would be asserting a Tailwind token — satisfied by
                // any utility that happens to contain the same substring, and
                // broken by any that starts to.
                <div
                  className="mt-1 flex flex-wrap items-center gap-2"
                  data-slot="web-capture-drift"
                  data-severity={severity}
                >
                  <Badge variant={severity}>
                    <span className="font-mono">{ruleId}</span>
                  </Badge>
                  {site.remediation !== undefined && (
                    <span className="text-xs text-text-3">{site.remediation}</span>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}

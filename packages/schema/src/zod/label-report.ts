// What an attached machine reports about the human labels it holds: the
// exceptions a person granted and the findings they dismissed, each with the
// reason they picked. Sent under the history-sync grant (payload v4).
//
// LABELS ONLY. Nothing a person typed crosses: not a grant's justification or
// revoke reason, not a dismissal's evidence. Nor does anything naming the local
// account (createdBy, revokedBy) — the deployment knows who the credential
// belongs to — or the grant's keyed fingerprint, which is a correlation key
// for this machine alone. Every object is `.strict()`, so a sender that adds
// one of those fields is refused rather than having it quietly stripped.
import * as z from 'zod';

import { DetectionException } from './exception.ts';
import { DetectionCategory } from './finding.ts';
import { ConfirmedBy, DismissMethod } from './recommendation-action.ts';

export const LABEL_REPORT_BATCH_MAX = 500;

/** One exception grant, as the deployment may know it. Keyed by the grant's own id. */
export const ReportedGrant = z
  .object({
    id: z.guid(),
    ruleId: z.string().min(1).max(200),
    category: DetectionCategory,
    keyVersion: z.number().int().positive(),
    maskedValue: z.string().max(200),
    capability: DetectionException.shape.capability.unwrap(),
    scope: DetectionException.shape.scope,
    expiresAt: z.iso.datetime().nullable(),
    maxUses: z.number().int().positive().nullable(),
    useCount: z.number().int().nonnegative(),
    lastUsedAt: z.iso.datetime().nullable(),
    method: DismissMethod.nullable(),
    confirmedBy: ConfirmedBy,
    createdVia: DetectionException.shape.createdVia,
    createdAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
    revokedAt: z.iso.datetime().nullable(),
  })
  .strict();
export type ReportedGrant = z.infer<typeof ReportedGrant>;

/**
 * One dismissal of one finding, keyed by the local resolution row's id. The
 * finding key is the one the finding itself was forwarded under.
 */
export const ReportedDismissal = z
  .object({
    id: z.guid(),
    findingKey: z.string().min(1).max(200),
    method: DismissMethod,
    confirmedBy: ConfirmedBy,
    resolvedAt: z.number().int().nonnegative(),
  })
  .strict();
export type ReportedDismissal = z.infer<typeof ReportedDismissal>;

/** `POST /v1/plugin/labels`. No device id: the deployment takes it from the credential. */
export const LabelReportRequest = z
  .object({
    grants: z.array(ReportedGrant).max(LABEL_REPORT_BATCH_MAX),
    dismissals: z.array(ReportedDismissal).max(LABEL_REPORT_BATCH_MAX),
  })
  .strict()
  .refine((r) => r.grants.length + r.dismissals.length > 0, {
    message: 'a label report carries at least one label',
  });
export type LabelReportRequest = z.infer<typeof LabelReportRequest>;

/** How many of each the deployment recorded. A replayed label counts again. */
export const LabelReportAck = z
  .object({
    grants: z.number().int().nonnegative(),
    dismissals: z.number().int().nonnegative(),
  })
  .strict();
export type LabelReportAck = z.infer<typeof LabelReportAck>;

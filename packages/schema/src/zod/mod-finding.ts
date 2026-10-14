import * as z from 'zod';

import { DetectionCategory, Severity } from './finding.ts';
import { POINTER_TOKEN_ANCHORED } from './vault.ts';

export const MOD_FINDINGS_DIR = 'mod-findings';
export const MOD_FINDINGS_MAX_BYTES = 4 * 1024 * 1024;

export const ModFindingAction = z
  .enum(['redacted', 'vaulted', 'blocked', 'warned', 'logged'])
  .meta({ id: 'ModFindingAction' });
export type ModFindingAction = z.infer<typeof ModFindingAction>;

export const ModFindingWhere = z
  .enum(['prompt', 'attachment', 'tool-input', 'tool-output', 'memory', 'subagent'])
  .meta({ id: 'ModFindingWhere' });
export type ModFindingWhere = z.infer<typeof ModFindingWhere>;

// One finding AKA acted on in a Claude Code session, as the mod's widgets draw
// it. It names the rule and what was done, never the matched value or where in
// the text it sat.
export const ModFinding = z
  .strictObject({
    v: z.literal(1),
    id: z.string().regex(/^[0-9a-f]{16}$/),
    at: z.iso.datetime(),
    ruleId: z.string().min(1),
    shortName: z.string().min(1).max(64).optional(),
    category: DetectionCategory,
    severity: Severity,
    action: ModFindingAction,
    where: ModFindingWhere,
    pointer: z.string().regex(POINTER_TOKEN_ANCHORED).optional(),
  })
  .refine((f) => (f.action === 'vaulted') === (f.pointer !== undefined), {
    path: ['pointer'],
    message: 'pointer is present only for a vaulted finding, and a vaulted finding has one',
  })
  .meta({ id: 'ModFinding' });
export type ModFinding = z.infer<typeof ModFinding>;

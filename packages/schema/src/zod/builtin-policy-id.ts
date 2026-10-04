import { z } from 'zod';

// Single source of truth for the built-in policy ids, declared in display order
// (monitor → warn → redact → vault → block, least → most restrictive). This one runtime
// array feeds the Zod enum (BuiltinPolicyId), PATCH membership validation, the
// catalog display order (BUILTIN_ORDER), and the catalog keys (BUILTIN_POLICIES) —
// so the literal set is declared exactly once here.
//
// Its own module, re-exported from policy.ts, because rule.ts needs the enum for
// PackManifest.defaultPolicy and policy.ts already imports rule.ts: declaring it
// in policy.ts would make that a load-order cycle.
export const KNOWN_BUILTIN_IDS = ['monitor', 'warn', 'redact', 'vault', 'block'] as const;

export const BuiltinPolicyId = z.enum(KNOWN_BUILTIN_IDS).meta({ id: 'BuiltinPolicyId' });
export type BuiltinPolicyId = z.infer<typeof BuiltinPolicyId>;

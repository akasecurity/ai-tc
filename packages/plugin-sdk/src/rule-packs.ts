import { registerPack } from '@aka/detections';
import { Rule } from '@aka/schema';

/**
 * Validate raw rule-file JSON (as bundled from `rules/<pack>/`) against the
 * versioned Rule schema and register it with the engine. Throws on invalid
 * rules — callers on the hook path wrap in their fail-open guard.
 */
export function registerRulePack(packId: string, rawRules: unknown[]): void {
  const rules = rawRules.map((raw) => Rule.parse(raw));
  registerPack({ id: packId, rules });
}

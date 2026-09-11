// Host-compatibility DTOs: whether the agent harness running a session is new
// enough for the hook events AKA's manifest registers. Plain TS interfaces (no
// Zod, no .meta) — these cross no route, so an id here would produce a named
// OpenAPI component nothing references. `updates.ts` is the same decision, and
// likewise holds the DTO for a JSON file persisted under ~/.aka.

/**
 * One protection AKA cannot enforce because the host predates the hook events
 * it needs.
 *
 * `label` is ordinary language on purpose, and reaches only the on-demand
 * surfaces (`aka status`, /aka:health). The in-session notice stays generic: it
 * names no hook event, so it cannot suggest — or be read as suggesting — that
 * the fix is to delete something from the plugin manifest.
 */
export interface HostFeatureGap {
  feature: string;
  label: string;
  since: string;
}

/**
 * The newest host version observed on this machine, cached at
 * ~/.aka/data/host-version.json.
 *
 * Written only from a hook whose own semantics guarantee the newest transcript
 * record was written by the RUNNING host, and read only by the on-demand
 * surfaces — never by the notice. That split is what stops a stale reading from
 * ever becoming a wrong "update Claude Code".
 */
export interface HostVersionCache {
  version: string;
  observedAt: number;
}

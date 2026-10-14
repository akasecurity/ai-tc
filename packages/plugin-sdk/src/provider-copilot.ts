/**
 * Provider resolution for GitHub Copilot sessions.
 *
 * This one is deliberately UNLIKE its three siblings, and the difference is the
 * whole content of the module: `provider.ts`, `provider-codex.ts` and
 * `provider-antigravity.ts` each read a documented host env var that names the
 * backend a session talks to (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`,
 * `GOOGLE_GEMINI_BASE_URL`). **Copilot publishes no such variable.** A Copilot
 * session reaches whichever model the user's subscription and the host's own
 * model picker selected, over GitHub's endpoint, and nothing in the hook
 * process's environment says which.
 *
 * So this resolver reads NO environment at all — which is why this file carries
 * no `n/no-process-env` opt-out and is absent from CLAUDE.md §3's table. It
 * answers `'unknown'`, unconditionally, and that is an honest answer rather
 * than a stub: recording `'github'` or `'openai'` here would be a fabricated
 * per-session fact that the cost attribution would then trust.
 *
 * The model ID is recorded separately, off the session's own event stream
 * (`session.shutdown.modelMetrics` and the per-turn records), so a usage row
 * still names the model even while the backend behind it stays unresolved.
 *
 * THERE IS DELIBERATELY NO `copilotProviderFromModelId` HERE, and its absence
 * is the point rather than an omission. The three siblings each carry one — a
 * pure heuristic mapping a model id onto a backend, used where the env is stale
 * (backfill, a pre-SessionStart root). On this host the model family says
 * nothing about the backend: a Copilot session can run Claude, GPT or Gemini
 * through GitHub's own endpoint, so a `claude-sonnet-…` id under Copilot is NOT
 * an Anthropic-direct call, and classifying it as one would attribute the cost
 * to the wrong provider — the exact failure the per-session provider fact
 * exists to prevent. A heuristic that answered 'unknown' for every id would
 * read like a gap somebody forgot to fill; this paragraph is the alternative.
 *
 * When a payload-derived provider seam exists, `resolveCopilotProvider` is the
 * call site that stops being constant.
 */

/** Provider backend a Copilot session talks to, as far as this build can tell. */
export type CopilotProvider = 'unknown';

/**
 * Whatever a Copilot hook can say about its backend, which today is nothing.
 *
 * Shaped like `ResolvedCodexProvider` — the same `{ provider, gatewayHost? }`
 * pair — so it slots into `PluginConfig['provider']` and into the session
 * root's attribute writer without either of them branching on the host.
 */
export interface ResolvedCopilotProvider {
  provider: CopilotProvider;
  /** Never set today; present so the shape matches its three siblings. */
  gatewayHost?: string;
}

/**
 * The provider a Copilot session talks to: unresolved.
 *
 * Called once, from the hook that snapshots the provider onto the session root
 * (`plugins/copilot/src/hooks/session-start.ts`). Constant by design — see the
 * module comment. Kept as a function rather than a constant so the call site is
 * identical to the other three hosts' and so widening it later moves no caller.
 */
export function resolveCopilotProvider(): ResolvedCopilotProvider {
  return { provider: 'unknown' };
}

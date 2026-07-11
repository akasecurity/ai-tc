// Read-time token rollups.
//
// Turns the flat `llm_call` leaf bags written by the reconciler into per-session
// `SessionTokenReport`s: grouped by `(provider, model)`, with cost derived HERE,
// at read time, from each leaf — never stored. Cost is computed PER LEAF (not by
// pricing the summed tokens) because the price map charges the 1h/5m ephemeral
// cache split and the service tier per call, neither of which survives a merged
// rollup total. Pure: no I/O, deterministic.
import type {
  LlmCallAttributes,
  ModelTokenUsage,
  SessionTokenReport,
  TokenRollup,
  TokenUsageSummary,
} from '../zod/meta.ts';
import type { CostModel, CostUsage } from './cost-model.ts';

// One reconciler-written `llm_call` leaf: its session and the parsed attribute bag.
export interface LlmCallLeaf {
  sessionId: string;
  attributes: LlmCallAttributes;
}

interface RollupAcc {
  provider: string;
  model: string;
  input: number;
  output: number;
  cacheCreation: number;
  cacheRead: number;
  costUsd: number;
  // A known `(provider, model)` price was found for at least one leaf. A rollup is
  // single-(provider, model), so in practice this is all-or-nothing across its
  // leaves; `false` means the pair is unknown → cost renders as null, never a guess.
  priced: boolean;
}

const num = (value: number | undefined): number => value ?? 0;

// Map a leaf's stored attribute names onto the cost model's `CostUsage` shape.
function costUsageOf(a: LlmCallAttributes): CostUsage {
  const usage: CostUsage = {
    inputTokens: num(a.input_tokens),
    outputTokens: num(a.output_tokens),
    cacheWrite1hTokens: num(a.ephemeral_1h_input_tokens),
    cacheWrite5mTokens: num(a.ephemeral_5m_input_tokens),
    cacheReadTokens: num(a.cache_read_input_tokens),
    webSearchRequests: num(a.web_search_requests),
  };
  // `?: string` under exactOptionalPropertyTypes — only set when present.
  if (a.service_tier !== undefined) usage.serviceTier = a.service_tier;
  return usage;
}

// Group `llm_call` leaves into per-session token reports, deriving USD cost at read
// time via `costModel`. Sessions and their rollups are ordered by total tokens
// (largest first) so the read surface shows the heaviest spend up top.
export function buildTokenReports(
  leaves: readonly LlmCallLeaf[],
  costModel: CostModel,
): SessionTokenReport[] {
  const bySession = new Map<string, Map<string, RollupAcc>>();

  for (const { sessionId, attributes } of leaves) {
    const provider = attributes.provider ?? 'unknown';
    const model = attributes.model ?? 'unknown';
    const key = `${provider} ${model}`;

    let rollups = bySession.get(sessionId);
    if (rollups === undefined) {
      rollups = new Map();
      bySession.set(sessionId, rollups);
    }
    let acc = rollups.get(key);
    if (acc === undefined) {
      acc = {
        provider,
        model,
        input: 0,
        output: 0,
        cacheCreation: 0,
        cacheRead: 0,
        costUsd: 0,
        priced: false,
      };
      rollups.set(key, acc);
    }

    acc.input += num(attributes.input_tokens);
    acc.output += num(attributes.output_tokens);
    acc.cacheCreation += num(attributes.cache_creation_input_tokens);
    acc.cacheRead += num(attributes.cache_read_input_tokens);

    const leafCost = costModel.costFor({ provider, model, usage: costUsageOf(attributes) });
    if (leafCost !== null) {
      acc.costUsd += leafCost;
      acc.priced = true;
    }
  }

  const reports: SessionTokenReport[] = [];
  for (const [sessionId, rollupMap] of bySession) {
    const rollups: TokenRollup[] = [];
    let totalTokens = 0;
    let costUsd = 0;
    let anyPriced = false;
    let anyUnpriced = false;

    for (const acc of rollupMap.values()) {
      const rollupTotal = acc.input + acc.output + acc.cacheCreation + acc.cacheRead;
      totalTokens += rollupTotal;
      const estimatedCostUsd = acc.priced ? acc.costUsd : null;
      if (estimatedCostUsd === null) {
        anyUnpriced = true;
      } else {
        anyPriced = true;
        costUsd += estimatedCostUsd;
      }
      rollups.push({
        sessionId,
        model: acc.model,
        provider: acc.provider,
        inputTokens: acc.input,
        outputTokens: acc.output,
        cacheCreation: acc.cacheCreation,
        cacheRead: acc.cacheRead,
        totalTokens: rollupTotal,
        estimatedCostUsd,
      });
    }
    rollups.sort((a, b) => b.totalTokens - a.totalTokens);

    reports.push({
      sessionId,
      rollups,
      totalTokens,
      // Σ of the PRICED rollups; null when none had a known price.
      estimatedCostUsd: anyPriced ? costUsd : null,
      // Any unknown (provider, model) means the total understates real spend.
      costIsPartial: anyUnpriced,
    });
  }
  reports.sort((a, b) => b.totalTokens - a.totalTokens);
  return reports;
}

// Roll a set of per-session token reports UP into one cross-session summary,
// collapsing every rollup onto its `(provider, model)` so the read surfaces (the
// Activity page's usage panel, the CLI `aka stats` block, the TUI health screen)
// render one "usage by model" table with grand totals. Same aggregation the
// plugin's `/aka:tokens` renderer does inline — centralized here so every surface
// agrees on the numbers.
//
// Cost handling mirrors `buildTokenReports`: an unpriced rollup (unknown
// (provider, model)) contributes tokens but NO cost and flips `costIsPartial`,
// so the total is a lower bound (`≥ $X`) the UI renders honestly rather than a
// silently understated figure. `estimatedCostUsd` on a model row is null when
// NONE of its rollups were priced; a number (the Σ of the priced ones) otherwise.
export function aggregateTokenUsage(reports: readonly SessionTokenReport[]): TokenUsageSummary {
  interface Agg {
    provider: string;
    model: string;
    inputTokens: number;
    outputTokens: number;
    cacheTokens: number;
    totalTokens: number;
    costUsd: number;
    priced: boolean;
  }
  const byModel = new Map<string, Agg>();
  let totalTokens = 0;
  let estimatedCostUsd = 0;
  let costIsPartial = false;

  for (const report of reports) {
    for (const roll of report.rollups) {
      const key = `${roll.provider} ${roll.model}`;
      let agg = byModel.get(key);
      if (agg === undefined) {
        agg = {
          provider: roll.provider,
          model: roll.model,
          inputTokens: 0,
          outputTokens: 0,
          cacheTokens: 0,
          totalTokens: 0,
          costUsd: 0,
          priced: false,
        };
        byModel.set(key, agg);
      }
      agg.inputTokens += roll.inputTokens;
      agg.outputTokens += roll.outputTokens;
      agg.cacheTokens += roll.cacheCreation + roll.cacheRead;
      agg.totalTokens += roll.totalTokens;
      if (roll.estimatedCostUsd === null) {
        costIsPartial = true;
      } else {
        agg.costUsd += roll.estimatedCostUsd;
        agg.priced = true;
      }
    }
    totalTokens += report.totalTokens;
    if (report.estimatedCostUsd !== null) estimatedCostUsd += report.estimatedCostUsd;
    if (report.costIsPartial) costIsPartial = true;
  }

  const models: ModelTokenUsage[] = [...byModel.values()]
    .sort((a, b) => b.totalTokens - a.totalTokens)
    .map((m) => ({
      provider: m.provider,
      model: m.model,
      inputTokens: m.inputTokens,
      outputTokens: m.outputTokens,
      cacheTokens: m.cacheTokens,
      totalTokens: m.totalTokens,
      estimatedCostUsd: m.priced ? m.costUsd : null,
    }));

  return {
    models,
    sessionCount: reports.length,
    totalTokens,
    estimatedCostUsd,
    costIsPartial,
  };
}

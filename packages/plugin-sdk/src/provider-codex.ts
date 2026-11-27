/**
 * Provider resolution for Codex CLI sessions.
 *
 * Codex CLI talks to OpenAI-direct by default, or to Azure OpenAI / any
 * OpenAI-compatible gateway (LiteLLM, OpenRouter, a self-hosted shim, …) when
 * `OPENAI_BASE_URL` or a named `model_providers` entry in `config.toml` points
 * elsewhere. The same `model` id costs a different amount per provider, so
 * token-usage cost attribution needs the provider as a per-session fact.
 *
 * A session is 'azure' when its base URL's host is under `.openai.azure.com` or
 * `.services.ai.azure.com`, whether that URL is the `base_url` of the provider
 * `config.toml` selects (under `CODEX_HOME`, default `~/.codex`) or
 * `OPENAI_BASE_URL`. Any other non-default `OPENAI_BASE_URL` is a 'gateway'.
 *
 * Two resolvers live here, mirroring provider.ts:
 *   - `resolveCodexProvider()` — reads the host env and `config.toml` once at
 *     SessionStart, where they are contemporaneous, and snapshots the result
 *     onto the session root. Never call it from the reconciler.
 *   - `codexProviderFromModelId()` — a PURE heuristic (no env) used as the
 *     fallback when env is silent or stale (backfill / pre-SessionStart roots).
 */

import { homedir } from 'node:os';
import { join } from 'node:path';

import { readCodexActiveProviderBaseUrl } from './codex-config.ts';
import { CodexProviderEnvSchema, DEFAULT_OPENAI_HOST } from './provider-env-codex.ts';

/** Provider backend a Codex CLI session talks to. */
export type CodexProvider = 'openai' | 'azure' | 'gateway';

/** `codexProviderFromModelId` adds 'unknown' for ids it cannot classify. */
export type CodexProviderOrUnknown = CodexProvider | 'unknown';

export interface ResolvedCodexProvider {
  provider: CodexProvider;
  /** Host of `OPENAI_BASE_URL` when the provider is a 'gateway'; else absent. */
  gatewayHost?: string;
}

/** Host suffixes of Azure OpenAI and Azure AI Foundry endpoints. */
export const AZURE_OPENAI_HOST_SUFFIXES: readonly string[] = [
  '.openai.azure.com',
  '.services.ai.azure.com',
];

/**
 * Parse a base URL; tolerate a bare host (no scheme) by retrying with one.
 * Identical logic to provider.ts's hostOf().
 */
function parseBaseUrl(url: string): URL | undefined {
  try {
    const parsed = new URL(url);
    if (parsed.host !== '') return parsed;
  } catch {
    // fall through to the scheme-prefixed retry
  }
  try {
    const parsed = new URL(`https://${url}`);
    return parsed.host !== '' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** True when the URL's host name sits under one of the Azure suffixes. */
export function isAzureOpenAiUrl(url: string): boolean {
  const parsed = parseBaseUrl(url);
  if (parsed === undefined) return false;
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  return AZURE_OPENAI_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

/** True when the provider `config.toml` selects has an Azure `base_url`. */
function configSelectsAzure(codexHome: string | undefined): boolean {
  try {
    const baseUrl = readCodexActiveProviderBaseUrl(codexHome ?? join(homedir(), '.codex'));
    return baseUrl !== undefined && isAzureOpenAiUrl(baseUrl);
  } catch {
    return false;
  }
}

/**
 * Resolve the provider from `config.toml` and the host process env. Called once
 * at SessionStart, where both are contemporaneous, to snapshot the provider onto
 * the session root.
 *
 * Priority cascade:
 *   1. the provider `config.toml` selects has an Azure `base_url` → 'azure'
 *   2. else `OPENAI_BASE_URL` has an Azure host → 'azure'
 *   3. else `OPENAI_BASE_URL` set AND its host ≠ api.openai.com → 'gateway' (+ `gatewayHost`)
 *   4. else → 'openai'
 */
export function resolveCodexProvider(): ResolvedCodexProvider {
  // Lenient parse — every field is optional and total (`.catch(undefined)`), so a
  // malformed value degrades to undefined instead of throwing in a hook path.
  // Fall back to a parse of {} on the unexpected failure rather than throwing.
  const parsed = CodexProviderEnvSchema.safeParse(process.env);
  const env = parsed.success ? parsed.data : CodexProviderEnvSchema.parse({});

  if (configSelectsAzure(env.CODEX_HOME)) return { provider: 'azure' };

  const baseUrl = env.OPENAI_BASE_URL;
  if (baseUrl !== undefined && baseUrl !== '') {
    if (isAzureOpenAiUrl(baseUrl)) return { provider: 'azure' };
    const host = parseBaseUrl(baseUrl)?.host;
    if (host !== undefined && host !== DEFAULT_OPENAI_HOST) {
      return { provider: 'gateway', gatewayHost: host };
    }
  }

  return { provider: 'openai' };
}

/**
 * PURE heuristic mapping a Codex `model` id to a provider — no env access.
 * Used as the fallback when env is silent/stale (the reconciler resolving a
 * backfilled or pre-SessionStart root). Best-effort → 'unknown'.
 *
 *   - plain OpenAI ids (`gpt-…`, `o1…`/`o3…`/`o4…`, `codex-…`) → openai
 *   - `<vendor>/…` (e.g. `azure/…`, `openrouter/…`)            → gateway
 *   - `…:<tag>` (e.g. gateway-routed aliases)                  → gateway
 *   - anything else                                            → unknown
 */
export function codexProviderFromModelId(modelId: string): CodexProviderOrUnknown {
  const id = modelId.trim();
  if (id === '') return 'unknown';

  // Gateway/router ids namespace the vendor with a slash, e.g. `azure/gpt-5-codex`.
  if (id.includes('/')) return 'gateway';

  // Gateway-routed `name:tag` aliases (e.g. LiteLLM/OpenRouter style).
  if (id.includes(':')) return 'gateway';

  // Plain OpenAI-direct model families.
  if (/^(gpt-|o[134](-|$)|codex-)/.test(id)) return 'openai';

  return 'unknown';
}

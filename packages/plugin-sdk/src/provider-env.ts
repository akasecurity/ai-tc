import { z } from 'zod';

// Default Anthropic-direct API host. ANTHROPIC_BASE_URL pointing anywhere else
// means a gateway/proxy is in front of the model (LiteLLM, OpenRouter, an Ollama
// shim, …). Kept here so resolveProvider() and the schema agree on the baseline.
export const DEFAULT_ANTHROPIC_HOST = 'api.anthropic.com';

// Claude Code provider/backend selection, inherited from the host process env.
// These are NOT the backend service's own config — Claude Code sets them to pick
// AWS Bedrock / Google Vertex / an Anthropic-compatible gateway as the model
// backend. They are read here so resolveProvider() can classify the provider for
// per-session cost attribution.
//
// `CLAUDE_CODE_USE_BEDROCK` / `CLAUDE_CODE_USE_VERTEX` are boolean-ish: Claude
// Code sets them to a truthy string (e.g. "1" or "true") when active and leaves
// them unset otherwise, so any non-empty, non-"false"/"0" value reads as true.
// All optional — absent on a plain Anthropic-direct session.
// `.catch(undefined)` makes the field total: should an unexpected input ever
// trip the transform, it degrades to undefined rather than throwing, so a single
// bad flag can never fail the whole ProviderEnvSchema parse (and silently mislabel
// the provider). Flag-based detection must resolve independently of the URL field.
const booleanish = z
  .string()
  .optional()
  .transform((v) => {
    if (v === undefined) return undefined;
    const t = v.trim().toLowerCase();
    if (t === '' || t === 'false' || t === '0') return false;
    return true;
  })
  .catch(undefined);

// ANTHROPIC_BASE_URL is parsed leniently as a non-empty string, NOT a strict URL:
// it is only used to extract a host for gateway classification, and a scheme-less
// host like `localhost:11434` (Ollama) or `my-gateway:4000` (LiteLLM) is a
// legitimate value that `hostOf()` normalizes before extracting the host. An empty
// or whitespace-only string is coerced to undefined ("unset" — no gateway), so a
// shell that exports ANTHROPIC_BASE_URL="" must not fail the parse. `.catch(undefined)`
// makes the field total so one malformed value can never poison the whole parse.
const optionalBaseUrl = z
  .preprocess((v) => {
    if (typeof v === 'string' && v.trim() === '') return undefined;
    return v;
  }, z.string().optional())
  .catch(undefined);

export const providerEnvShape = {
  CLAUDE_CODE_USE_BEDROCK: booleanish,
  CLAUDE_CODE_USE_VERTEX: booleanish,
  ANTHROPIC_BASE_URL: optionalBaseUrl,
};

// Lenient provider-only schema parsed against the host env by resolveProvider().
// Every field is optional, so it parses cleanly on a default Anthropic-direct
// session where none of these are set.
export const ProviderEnvSchema = z.object(providerEnvShape);
export type ProviderEnv = z.infer<typeof ProviderEnvSchema>;

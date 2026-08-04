import { z } from 'zod';

// Default OpenAI-direct API host. OPENAI_BASE_URL pointing anywhere else means a
// gateway/proxy is in front of the model (Azure OpenAI, LiteLLM, OpenRouter, a
// self-hosted shim, …). Kept here so resolveCodexProvider() and the schema
// agree on the baseline.
export const DEFAULT_OPENAI_HOST = 'api.openai.com';

// Codex CLI provider/backend selection, inherited from the host process env.
// Unlike Claude Code (CLAUDE_CODE_USE_BEDROCK / CLAUDE_CODE_USE_VERTEX booleans),
// Codex has no fixed env-var flags for named providers — Azure OpenAI and other
// `model_providers` entries are selected via ~/.codex/config.toml, which this
// resolver deliberately does NOT read (same scope as the Claude Code resolver:
// host env only, read once at SessionStart where it is contemporaneous). The one
// fixed env var Codex itself reads is OPENAI_BASE_URL, so that is the only
// signal available for gateway classification without a config-file read.
//
// OPENAI_BASE_URL is parsed leniently as a non-empty string, NOT a strict URL:
// it is only used to extract a host for gateway classification, and a
// scheme-less host like `localhost:11434` (a local proxy) is a legitimate
// value that `hostOf()` normalizes before extracting the host. An empty or
// whitespace-only string is coerced to undefined ("unset" — no gateway), so a
// shell that exports OPENAI_BASE_URL="" must not fail the parse. `.catch(undefined)`
// makes the field total so one malformed value can never poison the whole parse.
const optionalBaseUrl = z
  .preprocess((v) => {
    if (typeof v === 'string' && v.trim() === '') return undefined;
    return v;
  }, z.string().optional())
  .catch(undefined);

export const codexProviderEnvShape = {
  OPENAI_BASE_URL: optionalBaseUrl,
};

// Lenient provider-only schema parsed against the host env by resolveCodexProvider().
// Every field is optional, so it parses cleanly on a default OpenAI-direct
// session where OPENAI_BASE_URL isn't set.
export const CodexProviderEnvSchema = z.object(codexProviderEnvShape);
export type CodexProviderEnv = z.infer<typeof CodexProviderEnvSchema>;

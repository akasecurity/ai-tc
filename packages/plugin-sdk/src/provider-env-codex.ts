import * as z from 'zod';

// Default OpenAI-direct API host. OPENAI_BASE_URL pointing anywhere else means
// Azure OpenAI or a gateway/proxy is in front of the model (LiteLLM, OpenRouter,
// a self-hosted shim, …).
export const DEFAULT_OPENAI_HOST = 'api.openai.com';

// Codex CLI provider/backend selection, inherited from the host process env.
// Codex has no env-var flags for named providers: Azure OpenAI and other
// `model_providers` entries are selected in `config.toml` under CODEX_HOME
// (default `~/.codex`), which resolveCodexProvider() reads from that directory.
// OPENAI_BASE_URL is the one env var that overrides the default provider's URL.
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

// CODEX_HOME names the directory holding `config.toml`; empty reads as unset.
const optionalDir = z
  .preprocess((v) => (v === '' ? undefined : v), z.string().optional())
  .catch(undefined);

export const codexProviderEnvShape = {
  OPENAI_BASE_URL: optionalBaseUrl,
  CODEX_HOME: optionalDir,
};

// Lenient provider-only schema parsed against the host env by resolveCodexProvider().
// Every field is optional, so it parses cleanly on a default OpenAI-direct
// session where neither is set.
export const CodexProviderEnvSchema = z.object(codexProviderEnvShape);
export type CodexProviderEnv = z.infer<typeof CodexProviderEnvSchema>;

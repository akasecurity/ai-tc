import { z } from 'zod';

// Default Gemini API host. GOOGLE_GEMINI_BASE_URL pointing anywhere else means
// a gateway/proxy is in front of the model (LiteLLM, OpenRouter, a self-hosted
// shim, …). Kept here so resolveAntigravityProvider() and the schema agree on
// the baseline.
export const DEFAULT_GEMINI_HOST = 'generativelanguage.googleapis.com';

// Antigravity provider/backend selection, inherited from the host process env.
// Antigravity talks to Gemini either through the public Generative Language
// API or through Vertex AI, and the choice is a boolean env flag
// (GOOGLE_GENAI_USE_VERTEXAI) rather than a config-file entry — closer to
// Claude Code's CLAUDE_CODE_USE_VERTEX than to Codex, which has no fixed flag
// at all. Antigravity's own settings.json can also select a backend; this
// resolver deliberately does NOT read it (same scope as both siblings: host
// env only, read once at the first invocation where it is contemporaneous).
//
// GOOGLE_GEMINI_BASE_URL is parsed leniently as a non-empty string, NOT a
// strict URL: it is only used to extract a host for gateway classification, and
// a scheme-less host like `localhost:11434` (a local proxy) is a legitimate
// value that `hostOf()` normalizes before extracting the host. An empty or
// whitespace-only string is coerced to undefined ("unset" — no gateway), so a
// shell that exports GOOGLE_GEMINI_BASE_URL="" must not fail the parse.
// `.catch(undefined)` makes the field total so one malformed value can never
// poison the whole parse.
const optionalBaseUrl = z
  .preprocess((v) => {
    if (typeof v === 'string' && v.trim() === '') return undefined;
    return v;
  }, z.string().optional())
  .catch(undefined);

// Truthy-flag parse matching the Claude Code resolver's treatment of
// CLAUDE_CODE_USE_VERTEX: any non-empty value other than '0'/'false' counts as
// on, since shells commonly export `=1`. Total via `.catch(false)`.
const optionalFlag = z
  .preprocess((v) => {
    if (typeof v !== 'string') return false;
    const normalized = v.trim().toLowerCase();
    return normalized !== '' && normalized !== '0' && normalized !== 'false';
  }, z.boolean())
  .catch(false);

export const antigravityProviderEnvShape = {
  GOOGLE_GENAI_USE_VERTEXAI: optionalFlag,
  GOOGLE_GEMINI_BASE_URL: optionalBaseUrl,
};

// Lenient provider-only schema parsed against the host env by
// resolveAntigravityProvider(). Every field is optional/total, so it parses
// cleanly on a default Gemini-direct session where neither var is set.
export const AntigravityProviderEnvSchema = z.object(antigravityProviderEnvShape);
export type AntigravityProviderEnv = z.infer<typeof AntigravityProviderEnvSchema>;

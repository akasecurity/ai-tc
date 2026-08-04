import { chatgptAdapter } from './chatgpt.ts';
import { claudeAdapter } from './claude.ts';
import type { ProviderAdapter } from './types.ts';

// Every provider this extension knows about — content.ts resolves ONE of
// these for the current page via resolveAdapter(location.hostname). Adding a
// new web provider (Gemini, DeepSeek, T3 Chat, …) is: implement
// ProviderAdapter in a new file here, add it to this array, and add its
// origin to manifest.json's content_scripts matches — no other file in this
// package changes. Do NOT also add a host_permissions entry: content-script
// injection needs only `matches`, and manifest.test.ts asserts the grant
// stays absent (it would additionally allow cross-origin fetch into the
// user's chat sessions, which nothing here does).
const ADAPTERS: ProviderAdapter[] = [chatgptAdapter, claudeAdapter];

// Every hostname the registry drives, derived from the adapters themselves so
// a new adapter cannot be added without the manifest guard seeing it.
export const ADAPTER_HOSTNAMES: readonly string[] = ADAPTERS.flatMap(
  (adapter) => adapter.hostnames,
);

export function resolveAdapter(hostname: string): ProviderAdapter | null {
  return ADAPTERS.find((adapter) => adapter.hostnames.includes(hostname)) ?? null;
}

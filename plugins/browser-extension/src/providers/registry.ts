import { chatgptAdapter } from './chatgpt.ts';
import { claudeAdapter } from './claude.ts';
import type { ProviderAdapter } from './types.ts';

// Every provider this extension knows about — content.ts resolves ONE of
// these for the current page via resolveAdapter(location.hostname). Adding a
// new web provider (Gemini, DeepSeek, T3 Chat, …) is: implement
// ProviderAdapter in a new file here, add it to this array, and add its
// origin to manifest.json's content_scripts/host_permissions matches — no
// other file in this package changes.
const ADAPTERS: ProviderAdapter[] = [chatgptAdapter, claudeAdapter];

export function resolveAdapter(hostname: string): ProviderAdapter | null {
  return ADAPTERS.find((adapter) => adapter.matches(hostname)) ?? null;
}

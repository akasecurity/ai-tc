'use server';

import {
  applyCliUpdate,
  applyPluginUpdate,
  clearCache,
  installAgentPlugin,
  refreshCache,
} from '@akasecurity/local-ops';
import { defaultDataDir } from '@akasecurity/persistence';
import { revalidatePath } from 'next/cache';

// The web twins of `aka check-updates` / `aka update` / `aka plugins install`.
// SECURITY: the actions accept only component/agent IDS — every child-process
// argument is a constant resolved from the static registry inside
// @akasecurity/local-ops (an unknown id fails closed with no spawn). Network rides
// `npm`/`claude` child processes, exactly like the CLI — never fetch().

export interface ApplyActionResult {
  ok: boolean;
  output: string;
  // True after a successful CLI self-update: the running `aka dashboard`
  // standalone server still serves the OLD version until restarted.
  restartRequired: boolean;
}

/** Refresh the update cache from npm (the web twin of `aka check-updates`). */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function checkNow(): Promise<{ ok: boolean }> {
  refreshCache(defaultDataDir());
  revalidatePath('/updates');
  return { ok: true };
}

/** Apply one component's update: `cli` → npm self-update; else a plugin update. */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function applyUpdate(id: string): Promise<ApplyActionResult> {
  const result = id === 'cli' ? applyCliUpdate() : applyPluginUpdate(id);
  // The still-running process reflects the pre-update versions — a cache kept
  // now would falsely re-nag. Mirrors `aka update`.
  clearCache(defaultDataDir());
  revalidatePath('/updates');
  return { ...result, restartRequired: id === 'cli' && result.ok };
}

/** Install an agent plugin via the `claude` plugin manager. */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function installPlugin(id: string): Promise<ApplyActionResult> {
  const result = installAgentPlugin(id);
  clearCache(defaultDataDir());
  revalidatePath('/updates');
  return { ...result, restartRequired: false };
}

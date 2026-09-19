'use server';

import {
  applyCliUpdate,
  applyPluginUpdate,
  clearCache,
  detectInstallChannel,
  installAgentPlugin,
  readCache,
  refreshCache,
} from '@akasecurity/local-ops';
import { defaultDataDir } from '@akasecurity/persistence';
import { revalidatePath } from 'next/cache';

import { dashboardInstallOrigin } from '../../lib/install-origin';
import { cliUpdateTarget, updatesReport } from './report';

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
  const result =
    id === 'cli'
      ? // The channel AND the resolved version come from ./report.ts, the same
        // module ./page.tsx built the line the dialog showed from — so the spec
        // this runs names the version that line named. A default here would
        // install stable while the dialog promised another channel, and a
        // channel with no version would install whatever that channel's
        // dist-tag serves, which on a graduating prerelease is a different
        // release from the one the page offered.
        //
        // Derived here rather than passed in: an action's parameters arrive as
        // JSON over a POST, so a version taken from the caller would be
        // attacker-supplied text on its way to a child process's argv.
        //
        // `hasBin` stays at its default PATH probe.
        applyCliUpdate(
          detectInstallChannel(dashboardInstallOrigin()),
          'capture',
          undefined,
          cliUpdateTarget(updatesReport(readCache(defaultDataDir()))),
        )
      : applyPluginUpdate(id);
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

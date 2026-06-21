import type { CaptureInput, CaptureResult, PluginConfig } from '@akasecurity/plugin-sdk';
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';

import { resolveDataGateway } from './resolve.ts';

/**
 * The one entry every adapter calls per captured text: resolve the gateway from
 * config → detect → record → return a tool-agnostic decision. This wiring lives
 * in `@akasecurity/plugin-runtime` (not the SDK) because it depends on the
 * resolver; the SDK stays free of a runtime dependency, so there is no package
 * cycle.
 *
 * Fully fail-open: any error (config, gateway, scan) yields `log` + the original
 * text so a hook can never break the host session. `config` is injectable for
 * tests/adapters that already loaded it; otherwise it is read fresh per call.
 */
export async function handleCapture(
  input: CaptureInput,
  config: PluginConfig = loadConfig(),
): Promise<CaptureResult> {
  try {
    const gateway = resolveDataGateway(config);
    const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
    let result: CaptureResult;
    try {
      result = await runtime.capture(input);
    } finally {
      await runtime.close();
    }
    return result;
  } catch {
    return { action: 'log', text: input.text, findings: [] };
  }
}

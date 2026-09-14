import type {
  CaptureInput,
  CaptureOptions,
  CaptureResult,
  PluginConfig,
} from '@akasecurity/plugin-sdk';
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';

import { resolveDataGateway } from './resolve.ts';

/**
 * The one entry every adapter calls per captured text: resolve the gateway from
 * config → detect → record → return a tool-agnostic decision. This wiring lives
 * in `@akasecurity/plugin-runtime` (not the SDK) because it depends on the
 * resolver; the SDK stays free of a runtime dependency, so there is no package
 * cycle.
 *
 * `opts` reaches `runtime.capture` whole, never key by key. Omitted it is `{}`,
 * which is capture's own default: every capture is persisted and a resolved
 * `redact` is carried out. A caller narrows that per field — `persist:
 * 'with-findings'` records only a capture that detected something, `rewritable:
 * false` degrades a resolved `redact` to `settings.redactFallback` for a field
 * the caller has no way to rewrite.
 *
 * Forwarding the whole object is the guarantee, and it is what makes a field
 * added to `CaptureOptions` reach `capture` here without an edit. Only two of
 * those fields change anything observable through this seam — `persist` moves a
 * row, `rewritable` moves the resolved action — so this function's suite pins
 * those two and nothing else. `dedupe` and `preAuthorizedGrantIds` are covered
 * by the whole-shape forward rather than by a case: narrowing this call to name
 * a subset of the keys would keep every test green, so it is a deliberate
 * change to argue for rather than one a red suite will catch.
 *
 * Fully fail-open: any error (config, gateway, scan) yields `log` + the original
 * text so a hook can never break the host session. `config` is injectable for
 * tests/adapters that already loaded it; otherwise it is read fresh per call.
 */
export async function handleCapture(
  input: CaptureInput,
  config: PluginConfig = loadConfig(),
  opts: CaptureOptions = {},
): Promise<CaptureResult> {
  try {
    const gateway = resolveDataGateway(config);
    const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
    let result: CaptureResult;
    try {
      result = await runtime.capture(input, opts);
    } finally {
      await runtime.close();
    }
    return result;
  } catch {
    return { action: 'log', text: input.text, findings: [] };
  }
}

// The one place a Codex hook records a capture, asks whether the organization's
// model policy governs an event, or builds a model-refusal row. Each function
// takes the event's key as a StampedScopeKey: the key the gateway's account scope
// stamped (see account-stamp.ts), never a bare repository key. This plugin's
// eslint.config.mjs refuses those calls anywhere else under src/hooks.
import type { StampedScopeKey } from '@akasecurity/plugin-runtime';
import { governanceApplies, stampScopeKey } from '@akasecurity/plugin-runtime';
import type {
  CaptureInput,
  CaptureOptions,
  CaptureResult,
  PluginRuntime,
} from '@akasecurity/plugin-sdk';
import { buildModelRefusalEvent } from '@akasecurity/plugin-sdk';

/** A capture's input with its key left to the stamp. */
export type UnstampedCapture = Omit<CaptureInput, 'scopeKey'>;

/** A model-refusal row's input with its key left to the stamp. */
export type UnstampedRefusal = Omit<Parameters<typeof buildModelRefusalEvent>[0], 'scopeKey'>;

/**
 * The key an event is stored under: the repository key of where it happened,
 * or the thread's agent key where the gateway's account scope chooses it (an
 * enrolled repository keeps its own key). A gateway with no account scope, and
 * any fault, give the repository key.
 */
export function stampFor(
  gateway: object,
  repoKey: string | undefined,
  accountKey: string | undefined,
): StampedScopeKey | undefined {
  return stampScopeKey(gateway, repoKey, accountKey);
}

/** `runtime.capture`, keyed `key`. */
export function captureStamped(
  runtime: Pick<PluginRuntime, 'capture'>,
  input: UnstampedCapture,
  key: StampedScopeKey | undefined,
  options?: CaptureOptions,
): Promise<CaptureResult> {
  return runtime.capture({ ...input, scopeKey: key }, options);
}

/** Whether the organization's model policy governs an event keyed `key`. */
export function governedAt(gateway: object, key: StampedScopeKey | undefined): boolean {
  return governanceApplies(gateway, key);
}

/** The model-refusal row, keyed `key`. */
export function modelRefusalAt(
  input: UnstampedRefusal,
  key: StampedScopeKey | undefined,
): ReturnType<typeof buildModelRefusalEvent> {
  return buildModelRefusalEvent({ ...input, scopeKey: key });
}

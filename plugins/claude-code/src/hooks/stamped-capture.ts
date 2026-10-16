// The one place a Claude Code hook or mod helper records a capture, asks whether
// the organization's model policy governs an event, or builds a model-refusal
// row. Each function takes the event's key as a StampedScopeKey: what `stampFor`
// (account-stamp.ts) returns, which is the repository key itself where no
// account key applies. This plugin's eslint.config.mjs refuses those calls
// anywhere else under src/hooks and src/mod.
import type { StampedScopeKey } from '@akasecurity/plugin-runtime';
import { governanceApplies } from '@akasecurity/plugin-runtime';
import type {
  CaptureInput,
  CaptureOptions,
  CaptureResult,
  DeferredCapture,
  PluginRuntime,
} from '@akasecurity/plugin-sdk';
import { buildModelRefusalEvent } from '@akasecurity/plugin-sdk';

/** A capture's input with its key left to the stamp. */
export type UnstampedCapture = Omit<CaptureInput, 'scopeKey'>;

/** A model-refusal row's input with its key left to the stamp. */
export type UnstampedRefusal = Omit<Parameters<typeof buildModelRefusalEvent>[0], 'scopeKey'>;

/** `runtime.capture`, keyed `key`. */
export function captureStamped(
  runtime: Pick<PluginRuntime, 'capture'>,
  input: UnstampedCapture,
  key: StampedScopeKey | undefined,
  opts?: CaptureOptions,
): Promise<CaptureResult> {
  return runtime.capture({ ...input, scopeKey: key }, opts);
}

/** `runtime.captureDeferred`, keyed `key`. */
export function captureDeferredStamped(
  runtime: Pick<PluginRuntime, 'captureDeferred'>,
  input: UnstampedCapture,
  key: StampedScopeKey | undefined,
  opts?: CaptureOptions,
): Promise<DeferredCapture> {
  return runtime.captureDeferred({ ...input, scopeKey: key }, opts);
}

/** Whether the organization's model policy governs an event keyed `key` (governanceApplies). */
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

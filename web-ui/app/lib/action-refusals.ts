import type { ActionInputFailure, ManagedSettingKey } from '@akasecurity/schema';

// The refusal wording the settings Server Actions return.
//
// It lives HERE rather than inside the `'use server'` module for one reason:
// every export of a `'use server'` file must be an async Server Action, so a
// message formatter defined there is reachable only by performing the whole
// write it describes — and the administrative-lock branch needs a managed file
// at an absolute OS path no test can redirect. Moving the formatting out makes
// both branches ordinary pure functions with ordinary tests, and leaves the
// actions holding only the decision about WHICH one applies.

/**
 * A payload that did not arrive in the shape the action's schema declares.
 *
 * The message names the SCHEMA'S key, never the payload. A field arriving as
 * the wrong type is still whatever the caller sent — which on this surface can
 * be a credential the user pasted into the wrong box — so nothing derived from
 * it may reach the message describing its rejection. Zod's own issue messages
 * are excluded for the same reason.
 *
 * It branches on `wrongType` rather than always naming the type, because the
 * parse is generic over any schema: a `.min()` added to one of these fields
 * would reject a value that IS the right type, and "did not arrive as expected"
 * would then be a false diagnosis pointing at the wrong fix.
 */
export function malformedInput(failure: ActionInputFailure): string {
  if (failure.field === null) {
    return 'The request did not arrive in the expected shape — reload the page and try again.';
  }
  return failure.wrongType
    ? `The '${failure.field}' field did not arrive as expected — reload the page and try again.`
    : `The '${failure.field}' field was not in the expected form — reload the page and try again.`;
}

/**
 * An administrator has pinned one of the fields this write touches.
 *
 * Worded as a decision rather than a failure: retrying will not help, and the
 * user has done nothing wrong. The field names come from the schema's own
 * `ManagedSettingKey` enum — the caller cannot influence them, because a key
 * only reaches this list by being present in BOTH the administrator's locked
 * set and the writer's own derived key list.
 */
export function managedRefusal(fields: readonly ManagedSettingKey[]): string {
  return `Your organization manages ${fields.join(', ')} on this machine, so the change was not saved.`;
}

/** The store could not be written at all — a fault, unlike the two above. */
export const SETTINGS_WRITE_ERROR = 'Could not write settings.json.';

/**
 * The three refusals `attachToControlPlane` adds.
 *
 * None of them interpolates anything the caller supplied. That is the point:
 * this action is the one on this surface that handles a credential, and every
 * string here is rendered straight into the page. "Help the user spot their
 * typo" is the well-meaning change that would put a run of the key on screen,
 * so the wording carries no value at all — the field, never its contents.
 */
export const ATTACH_KEY_MISSING = 'Enter the access key to attach.';

/**
 * Worded as a refusal to send rather than a failed send, because nothing has
 * been sent yet — this is checked before the key reaches the wire.
 */
export const ATTACH_ENDPOINT_INSECURE =
  'That endpoint is not secure, so the access key was not sent. Use an https:// address (http:// is accepted only for a deployment on this machine).';

/**
 * One string for every verification failure, and the ambiguity is deliberate.
 *
 * A wrong key, a revoked key, a key of the wrong KIND, a typo'd host, a DNS
 * failure and a timeout are not distinguishable to this surface without either
 * forwarding the cause — which can carry the endpoint or a response body into
 * the page — or probing further on the user's behalf. It names the three things
 * a user can actually check instead.
 *
 * The kind is named because it is the one cause a user cannot otherwise guess:
 * an `ingest` key authenticates but carries no policy read, so it fails here
 * looking exactly like a bad key.
 */
export const ATTACH_VERIFY_FAILED =
  'That key was not accepted by the deployment, so nothing was changed. Check the address, that the key has not been revoked, and that it is a plugin key rather than an ingest key.';

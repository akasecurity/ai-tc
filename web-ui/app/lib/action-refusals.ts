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

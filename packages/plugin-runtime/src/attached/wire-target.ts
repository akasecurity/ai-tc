/**
 * `event` with its `attributes.target` passed through `redact`. When `redact`
 * cannot answer, the target is left off and the rest of the event is kept. An
 * event with no string target is returned unchanged.
 */
export async function withRedactedTarget<
  T extends { attributes?: Record<string, unknown> | undefined },
>(event: T, redact: (text: string) => Promise<string | undefined>): Promise<T> {
  const target = event.attributes?.target;
  if (typeof target !== 'string') return event;
  let redacted: string | undefined;
  try {
    redacted = await redact(target);
  } catch {
    redacted = undefined;
  }
  if (redacted === target) return event;
  const attributes: Record<string, unknown> = { ...event.attributes };
  if (redacted === undefined) delete attributes.target;
  else attributes.target = redacted;
  return { ...event, attributes };
}

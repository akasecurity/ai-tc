// The framing between the hook client (a shell script) and the hook server. Pure:
// no sockets, so it tests without one.
//
// A request is a few text lines and then the payload, sized by a byte count so
// the client need not reshape the JSON the host handed it:
//
//   AKA-HOOK 1 <hook>\n
//   C <working directory>\n        (optional)
//   E <NAME> <value>\n             (zero or more; one line each)
//   P <payload byte length>\n
//   <payload bytes>
//
// A response is a status line and then, for `OK`, exactly the bytes the hook
// would have written to stdout:
//
//   OK\n<stdout>          the hook ran; empty stdout means "no opinion"
//   FALLBACK\n            the hook did not run; the client runs the node hook itself

/** A request larger than this goes to a node process of its own, so one large payload cannot hold the queue. */
export const MAX_REQUEST_BYTES = 256 * 1024;

const MAGIC = 'AKA-HOOK 1 ';

export interface HookRequest {
  readonly hook: string;
  readonly cwd: string | undefined;
  readonly env: Readonly<Record<string, string>>;
  readonly payload: string;
}

export type ParsedRequest =
  | { readonly kind: 'incomplete' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'request'; readonly request: HookRequest };

const NEWLINE = 0x0a;
const HOOK_NAME = /^[a-z][a-z-]{0,40}$/;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;

/** Parses what has arrived so far; `incomplete` means more bytes may complete it. */
export function parseRequest(data: Buffer): ParsedRequest {
  let offset = 0;
  const nextLine = (): string | null => {
    const end = data.indexOf(NEWLINE, offset);
    if (end === -1) return null;
    const line = data.toString('utf8', offset, end);
    offset = end + 1;
    return line;
  };

  const first = nextLine();
  if (first === null) return data.length > 256 ? { kind: 'invalid' } : { kind: 'incomplete' };
  if (!first.startsWith(MAGIC)) return { kind: 'invalid' };
  const hook = first.slice(MAGIC.length);
  if (!HOOK_NAME.test(hook)) return { kind: 'invalid' };

  let cwd: string | undefined;
  const env: Record<string, string> = {};
  for (;;) {
    const line = nextLine();
    if (line === null) return { kind: 'incomplete' };
    if (line.startsWith('C ')) {
      cwd = line.slice(2);
    } else if (line.startsWith('E ')) {
      const space = line.indexOf(' ', 2);
      if (space === -1) return { kind: 'invalid' };
      const name = line.slice(2, space);
      if (!ENV_NAME.test(name)) return { kind: 'invalid' };
      env[name] = line.slice(space + 1);
    } else if (line.startsWith('P ')) {
      const length = Number(line.slice(2));
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_REQUEST_BYTES) {
        return { kind: 'invalid' };
      }
      if (data.length - offset < length) return { kind: 'incomplete' };
      const payload = data.toString('utf8', offset, offset + length);
      return { kind: 'request', request: { hook, cwd, env, payload } };
    } else {
      return { kind: 'invalid' };
    }
  }
}

export function okResponse(stdout: string): string {
  return `OK\n${stdout}`;
}

export const FALLBACK_RESPONSE = 'FALLBACK\n';

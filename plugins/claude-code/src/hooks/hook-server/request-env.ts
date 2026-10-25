// The environment a hook reads, set for the length of one request.
//
// A hook run by the server shares the server's environment, not the one the
// host gave the hook, so the variables the hook's account and session checks
// read are carried in the request and put in place before the hook runs. They
// are the only ones carried; the server's own environment is otherwise left
// alone. The server runs one request at a time, which is what makes setting
// process-wide state per request safe.
//
// A credential variable is read for presence only, so the client sends a marker
// for those rather than the value, and the value never crosses.
import { FORWARDED_ENV, PRESENCE_ONLY_ENV } from './forwarded-env.ts';

function setVariable(name: string, value: string | undefined): void {
  if (value === undefined) Reflect.deleteProperty(process.env, name);
  else process.env[name] = value;
}

/** Replaces the forwarded variables with the request's, and returns a function that restores them. */
export function applyRequestEnv(forwarded: Readonly<Record<string, string>>): () => void {
  const saved = new Map<string, string | undefined>();
  for (const name of FORWARDED_ENV) {
    saved.set(name, process.env[name]);
    setVariable(name, forwarded[name]);
  }
  return () => {
    for (const [name, value] of saved) setVariable(name, value);
  };
}

/** The current value of a variable; what a suite reads to see the request's state come and go. */
export function currentValue(name: string): string | undefined {
  return process.env[name];
}

/** Drops the credential variables the server inherited from the hook that started it. */
export function scrubPresenceOnlyEnv(): void {
  for (const name of PRESENCE_ONLY_ENV) Reflect.deleteProperty(process.env, name);
}

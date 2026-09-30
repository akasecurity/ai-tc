// Pure sessionStart-payload reading, split out of the `session-start.ts` entry
// script so it can be unit-tested WITHOUT importing the entry (whose top-level
// `runHookFailOpen(main)` reads stdin and would block test collection forever).
// Hooks stay thin glue; their logic is tested here. Same split as
// `pre-tool-use-decision.ts`.
//
// Every reader below takes the DIALECT FIRST, matching ./dialect.ts. Both
// parameters are consumed as values in some call shapes, so a flipped call can
// typecheck while resolving nothing — which lands every capture with no session
// id at all. The order is stated here because that failure is silent.

import type { Dialect } from './dialect.ts';
import { detectDialect, readCwd, readSessionId } from './dialect.ts';

/** What the sessionStart hook needs off its stdin payload. */
export interface SessionStartFacts {
  /** The dialect the payload was recognised as, or undefined when neither. */
  dialect: Dialect | undefined;
  sessionId: string | undefined;
  /** The workspace dir, or undefined when the payload carries none. */
  cwd: string | undefined;
  /** The opaque surface string, or undefined when the dialect is unknown. */
  harnessInterface: string | undefined;
}

/**
 * Which SURFACE a session runs on, as an opaque descriptive string.
 *
 * It rides in the harness attribute bag and NEVER forks the harness or
 * sourceTool dimension: a Copilot session is a Copilot session whether it ran
 * in a terminal or in VS Code. Same role as the Codex sibling's
 * `session_meta.originator`, derived from a different place — the payload
 * dialect, because the two hosts this package covers are told apart by their
 * wire shape and by nothing else (see ./dialect.ts).
 *
 * THE CLI DIALECT COVERS TWO SURFACES, and this function deliberately reports
 * only one of them. A terminal `copilot` and the cloud coding agent speak the
 * same wire, so nothing in the payload separates them; answering `cli` for both
 * is honest, and answering `cloud` for a terminal session would be a fabricated
 * fact on a durable per-session row. The cloud runner names itself through its
 * own installed launcher instead, which is something the installer knows and
 * this hook does not.
 *
 * `undefined` for an unrecognised dialect, for the same reason: no surface is
 * better than the wrong one.
 */
export function harnessInterfaceFor(dialect: Dialect | undefined): string | undefined {
  if (dialect === undefined) return undefined;
  return dialect === 'vscode' ? 'vscode' : 'cli';
}

/**
 * Read the session facts off a parsed payload.
 *
 * A payload whose dialect cannot be told still yields a session id where one is
 * spelled the CLI's way: that is the host whose hooks matter most here, and a
 * root opened under the right id is worth more than a strict refusal. What it
 * does NOT do is invent a `harnessInterface` — see above.
 *
 * `cwd` is read the same way and is deliberately NOT defaulted here. Under VS
 * Code the spawn's own cwd is the HOME DIRECTORY unless the hook entry declared
 * one, so a session-start entry with no `cwd` must decline rather than resolve
 * a repo from `~` — the same rule `baseMetadata` in ./shared.ts keeps, for the
 * same reason. This module reports the absence; the entry decides what to do
 * about it.
 */
export function readSessionStartFacts(input: Record<string, unknown> | null): SessionStartFacts {
  if (input === null) {
    return {
      dialect: undefined,
      sessionId: undefined,
      cwd: undefined,
      harnessInterface: undefined,
    };
  }
  const dialect = detectDialect(input);
  return {
    dialect,
    sessionId: readSessionId(dialect ?? 'cli', input),
    cwd: readCwd(dialect ?? 'cli', input),
    harnessInterface: harnessInterfaceFor(dialect),
  };
}

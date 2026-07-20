// The installed command registry and the per-surface selection over it. The
// registry is the source of truth for command EXISTENCE — the shipped
// `commands/*.md` set — not for which commands a given surface suggests. Each
// surface declares its own curated subset and validates it here, so no rendered
// line can name a command the installed plugin does not register.
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// The slash-command namespace the plugin registers commands under: a command
// file `foo.md` is invoked as `/aka:foo`, the only form that resolves when typed.
const COMMAND_NAMESPACE = 'aka';

// The shipped command files — one `foo.md` per registered `/aka:foo` command.
const COMMANDS_DIR = fileURLToPath(new URL('../commands', import.meta.url));

// The commands the installed plugin registers, read from the `commands/*.md` set
// and mapped to their invokable `/aka:<command>` form. This is the registry of
// command existence a suggested command is validated against, read from disk so
// a renamed or removed command is reflected rather than drifting from a copy.
export function readRegisteredCommands(): string[] {
  return readdirSync(COMMANDS_DIR)
    .filter((f) => f.endsWith('.md'))
    .map((f) => `/${COMMAND_NAMESPACE}:${f.replace(/\.md$/, '')}`);
}

// Resolve a surface's curated command set against the installed registry: every
// curated command must be a registered command, or this throws so an absent name
// fails loud rather than shipping a call-to-action the user cannot invoke.
// Returns the curated set unchanged (order preserved) once every entry validates.
export function selectRegisteredCommands(
  curated: readonly string[],
  registry: readonly string[],
): string[] {
  const registered = new Set(registry);
  const missing = curated.filter((c) => !registered.has(c));
  if (missing.length > 0) {
    throw new Error(
      `Curated command(s) not registered in the installed plugin: ${missing.join(', ')}`,
    );
  }
  return [...curated];
}

// The chaining line names a single secret-scan continuation command. It is
// registered under one of two names — `/aka:secretscan` where the dedicated
// secret-scan command exists, or `/aka:scan` otherwise — so the curated
// candidates list both, most-specific first, and the selection resolves to
// whichever name the installed plugin registers.
const SECRET_SCAN_CONTINUATION = ['/aka:secretscan', '/aka:scan'] as const;

// Select the chaining line's single secret-scan continuation command: resolve the
// curated candidates against the installed registry, then validate the one that
// resolves through selectRegisteredCommands so the line names a registered command
// in either ship order. Throws when none is registered, so an absent continuation
// fails the build rather than shipping a call-to-action the user cannot invoke.
export function selectSecretScanContinuation(
  registry: readonly string[] = readRegisteredCommands(),
): string {
  const curated = SECRET_SCAN_CONTINUATION.find((c) => registry.includes(c));
  if (curated === undefined) {
    throw new Error(
      `No secret-scan continuation command registered in the installed plugin (looked for ${SECRET_SCAN_CONTINUATION.join(', ')})`,
    );
  }
  const [selected = curated] = selectRegisteredCommands([curated], registry);
  return selected;
}

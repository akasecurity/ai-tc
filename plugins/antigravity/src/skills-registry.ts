// The installed skill registry and the per-surface selection over it. The
// registry is the source of truth for skill EXISTENCE — the shipped
// `skills/<dir>/SKILL.md` set — not for which skills a given surface suggests.
// Each surface declares its own curated subset and validates it here, so no
// rendered line can name a skill the installed plugin does not register.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// The shipped skill directories — one `skills/<dir>/SKILL.md` per registered
// skill, invoked by the `name:` its frontmatter declares.
const SKILLS_DIR = fileURLToPath(new URL('../skills', import.meta.url));

// Extract the `name:` field from a SKILL.md's leading frontmatter block, or
// undefined when the file has no frontmatter or no name entry.
function frontmatterName(content: string): string | undefined {
  const block = /^---\n([\s\S]*?)\n---/.exec(content);
  if (block === null) return undefined;
  const name = /^name:\s*(.+?)\s*$/m.exec(block[1] ?? '');
  return name?.[1];
}

// The skills the installed plugin registers, read from the shipped
// `skills/<dir>/SKILL.md` set and mapped to the invokable name each file's
// frontmatter declares. This is the registry of skill existence a suggested
// skill is validated against, read from disk so a renamed or removed skill is
// reflected rather than drifting from a copy. A directory without a readable
// SKILL.md name registers nothing.
export function readRegisteredSkills(): string[] {
  return readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .flatMap((entry) => {
      let content: string;
      try {
        content = readFileSync(join(SKILLS_DIR, entry.name, 'SKILL.md'), 'utf8');
      } catch {
        return [];
      }
      const name = frontmatterName(content);
      return name === undefined ? [] : [name];
    });
}

// Resolve a surface's curated skill set against the installed registry: every
// curated skill must be a registered skill, or this throws so an absent name
// fails loud rather than shipping a call-to-action the user cannot invoke.
// Returns the curated set unchanged (order preserved) once every entry validates.
export function selectRegisteredSkills(
  curated: readonly string[],
  registry: readonly string[],
): string[] {
  const registered = new Set(registry);
  const missing = curated.filter((c) => !registered.has(c));
  if (missing.length > 0) {
    throw new Error(
      `Curated skill(s) not registered in the installed plugin: ${missing.join(', ')}`,
    );
  }
  return [...curated];
}

// The chaining line names a single secret-scan continuation skill. It is
// registered under one of two names — `aka-secretscan` where the dedicated
// secret-scan skill exists, or `aka-scan` otherwise — so the curated
// candidates list both, most-specific first, and the selection resolves to
// whichever name the installed plugin registers.
const SECRET_SCAN_CONTINUATION = ['aka-secretscan', 'aka-scan'] as const;

// Select the chaining line's single secret-scan continuation skill: resolve the
// curated candidates against the installed registry, then validate the one that
// resolves through selectRegisteredSkills so the line names a registered skill
// in either ship order. Throws when none is registered, so an absent continuation
// fails the build rather than shipping a call-to-action the user cannot invoke.
export function selectSecretScanContinuation(
  registry: readonly string[] = readRegisteredSkills(),
): string {
  const curated = SECRET_SCAN_CONTINUATION.find((c) => registry.includes(c));
  if (curated === undefined) {
    throw new Error(
      `No secret-scan continuation skill registered in the installed plugin (looked for ${SECRET_SCAN_CONTINUATION.join(', ')})`,
    );
  }
  const [selected = curated] = selectRegisteredSkills([curated], registry);
  return selected;
}

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

export interface SourceFile {
  /** Forward-slash path relative to the scanned directory. */
  path: string;
  text: string;
}

// Name-based: a module is found by the word "sighting" in its source, so a sender
// that never uses that word is not detected and stays enforced by review alone.
const MENTIONS_SIGHTINGS = /sighting/i;

const IMPORTS_GATE =
  /import\s*\{[^}]*\b(?:readSightingSharing|resolveSightingSharing)\b[^}]*\}\s*from\s*'@akasecurity\/(?:persistence|schema)'/;

const CALLS_GATE = /\b(?:readSightingSharing|resolveSightingSharing)\s*\(/;

// What a module that sends credential sightings references: the sightings route, a
// sighting token, or the function that computes one.
const SENDS_SIGHTINGS = /credential-sightings|credentialSightings|\[\[aka:fp:|\bsightingToken\s*\(/;

/** Every non-test TypeScript source under `dir`, recursively. */
export function readSources(dir: string): SourceFile[] {
  const out: SourceFile[] = [];
  const walk = (at: string): void => {
    for (const entry of readdirSync(at, { withFileTypes: true })) {
      const full = join(at, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
        out.push({
          path: relative(dir, full).split(sep).join('/'),
          text: readFileSync(full, 'utf8'),
        });
      }
    }
  };
  walk(dir);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Sources that mention credential sightings but are on neither the sender list nor
 * the key-reader list.
 */
export function unlistedSightingSenders(
  sources: readonly SourceFile[],
  senders: readonly string[],
  keyReaders: readonly string[] = [],
): string[] {
  return sources
    .filter(
      (s) =>
        MENTIONS_SIGHTINGS.test(s.text) &&
        !senders.includes(s.path) &&
        !keyReaders.includes(s.path),
    )
    .map((s) => s.path);
}

/** Listed senders that are missing, or do not both import and call the gate. */
export function ungatedSightingSenders(
  sources: readonly SourceFile[],
  senders: readonly string[],
): string[] {
  return senders.filter((path) => {
    const source = sources.find((s) => s.path === path);
    return source === undefined || !IMPORTS_GATE.test(source.text) || !CALLS_GATE.test(source.text);
  });
}

/**
 * Listed key readers (modules that fetch or store the sighting key and send no
 * sightings) that are missing, or that reference sending sightings.
 */
export function keyReadersThatSend(
  sources: readonly SourceFile[],
  keyReaders: readonly string[],
): string[] {
  return keyReaders.filter((path) => {
    const source = sources.find((s) => s.path === path);
    return source === undefined || SENDS_SIGHTINGS.test(source.text);
  });
}

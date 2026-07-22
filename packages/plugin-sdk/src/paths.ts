import { sep } from 'node:path';

// Shared by every writer that stores or compares repo-relative paths (the
// CLI/web-ui scan pipeline and the plugin scan pipeline both key stored rows
// on paths built this way), so the two pipelines produce byte-identical path
// keys for the same file instead of drifting apart under two hand-written
// copies of the same one-liner.

/** Normalize a filesystem path to posix-style forward slashes. A no-op outside win32. */
export function toPosix(path: string): string {
  return path.split(sep).join('/');
}

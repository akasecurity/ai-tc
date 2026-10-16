import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { readClaudeAccountEnv } from '@akasecurity/plugin-sdk/account';

import { transcriptsDir } from '../history/transcripts.ts';

const SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;

// The host writes a session to `<projects>/<project>/<sessionId>.jsonl`, under
// CLAUDE_CONFIG_DIR when that is set and under ~/.claude otherwise; with the
// variable set, both directories are searched.
function projectsDirs(): string[] {
  const { configDir } = readClaudeAccountEnv();
  return configDir === undefined
    ? [transcriptsDir()]
    : [join(configDir, 'projects'), transcriptsDir()];
}

/**
 * The transcript the host wrote for `sessionId`, for a caller the host handed no
 * path. When several projects hold a file for the session (a resumed one), the
 * most recently written. Undefined when there is none, or when `sessionId` could
 * not be a file name.
 */
export function findSessionTranscript(sessionId: string | undefined): string | undefined {
  if (sessionId === undefined || !SESSION_ID.test(sessionId)) return undefined;
  let newest: { readonly path: string; readonly writtenAt: number } | undefined;
  for (const root of projectsDirs()) {
    let projects: string[];
    try {
      projects = readdirSync(root);
    } catch {
      continue;
    }
    for (const project of projects) {
      const path = join(root, project, `${sessionId}.jsonl`);
      try {
        const stat = statSync(path);
        if (stat.isFile() && (newest === undefined || stat.mtimeMs > newest.writtenAt)) {
          newest = { path, writtenAt: stat.mtimeMs };
        }
      } catch {
        // This project holds no file for the session.
      }
    }
  }
  return newest?.path;
}

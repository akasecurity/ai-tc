/**
 * User-facing SHOW regions the /aka:setup wizard scripts emit. A script wraps
 * everything the user should see — fenced cards and plain confirmation lines —
 * in these markers; the wizard's global relay contract pastes the content
 * between the markers verbatim. The markers are delimiters, never shown. This is
 * the human-facing twin of setup-frame-json.ts's machine-frame markers: same
 * delimiter style, opposite disposition (show vs hide).
 */
import { FRAME_JSON_BEGIN, FRAME_JSON_END } from './setup-frame-json.ts';

export const SHOW_BEGIN = '<<<AKA_SHOW';
export const SHOW_END = 'AKA_SHOW>>>';

// Wrap a body in a SHOW region a script writes to stdout. The trailing newline
// keeps the region on its own lines even when callers concatenate emissions.
export function showBlock(body: string): string {
  return `${SHOW_BEGIN}\n${body}\n${SHOW_END}\n`;
}

// Extract every SHOW region's content, in order. A region missing its end marker
// is skipped rather than throwing, so a reader treats malformed output as "no
// further show content" uniformly.
export function readShowBlocks(stdout: string): string[] {
  const blocks: string[] = [];
  let from = 0;
  for (;;) {
    const begin = stdout.indexOf(SHOW_BEGIN, from);
    if (begin === -1) break;
    const contentStart = begin + SHOW_BEGIN.length;
    const end = stdout.indexOf(SHOW_END, contentStart);
    if (end === -1) break;
    blocks.push(stdout.slice(contentStart, end).replace(/^\n/, '').replace(/\n$/, ''));
    from = end + SHOW_END.length;
  }
  return blocks;
}

export interface Surface {
  shows: string[];
  frames: unknown[];
  status: string;
}

// Partition a script's stdout into the three wizard output regions in a single
// left-to-right walk, so every byte lands in exactly one of them: `shows` is
// what the model relays verbatim; `frames` is machine-only parsed JSON (malformed
// blocks are dropped); `status` is the untagged remainder (paths, errors) with
// every show and frame region removed. A region missing its end marker stops the
// walk but still appends everything from that marker onward — including any
// trailing untagged text — to `status`, rather than dropping it.
export function parseSurface(stdout: string): Surface {
  const shows: string[] = [];
  const frames: unknown[] = [];
  let status = '';
  let cursor = 0;
  while (cursor < stdout.length) {
    const nextShow = stdout.indexOf(SHOW_BEGIN, cursor);
    const nextFrame = stdout.indexOf(FRAME_JSON_BEGIN, cursor);
    const candidates = [nextShow, nextFrame].filter((i) => i !== -1);
    if (candidates.length === 0) {
      status += stdout.slice(cursor);
      break;
    }
    const next = Math.min(...candidates);
    status += stdout.slice(cursor, next);
    if (next === nextShow) {
      const contentStart = next + SHOW_BEGIN.length;
      const end = stdout.indexOf(SHOW_END, contentStart);
      if (end === -1) {
        status += stdout.slice(next);
        break;
      }
      shows.push(stdout.slice(contentStart, end).replace(/^\n/, '').replace(/\n$/, ''));
      cursor = end + SHOW_END.length;
    } else {
      const from = next + FRAME_JSON_BEGIN.length;
      const end = stdout.indexOf(FRAME_JSON_END, from);
      if (end === -1) {
        status += stdout.slice(next);
        break;
      }
      try {
        frames.push(JSON.parse(stdout.slice(from, end).trim()));
      } catch {
        // Malformed frame: drop it, mirroring readFrameJsonBlock's fail-soft.
      }
      cursor = end + FRAME_JSON_END.length;
    }
  }
  return { shows, frames, status };
}

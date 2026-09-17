/**
 * The plugin’s own package name — the identity its posture reports carry.
 *
 * It lives in its own module rather than in `build-info.ts` because
 * `packages/eslint-config/test/package-walls.test.js` pins this path as the
 * package’s import probe, and a probe file has to export something.
 */
export const PLUGIN_PACKAGE = '@akasecurity/ai-tc-copilot';

export type { ApplyMode, ApplyResult } from './apply.ts';
export { applyCliUpdate, applyPluginUpdate, installAgentPlugin } from './apply.ts';
export {
  claudeAvailable,
  ensureMarketplace,
  installClaudePlugin,
  updateClaudePlugin,
} from './claude-plugin.ts';
export type { RunResult } from './exec.ts';
export { binExists, runCapture, runInherit } from './exec.ts';
export type {
  CollectedFile,
  ScannedFileFindings,
  ScanPathOptions,
  ScanPathResult,
} from './fs-scan.ts';
export { collectFiles, scanPathIntoStore } from './fs-scan.ts';
export type { AgentPlugin } from './registry.ts';
export { AGENT_PLUGINS, findAgent, pluginRef } from './registry.ts';
export { compareSemver, isNewer } from './semver.ts';
export {
  cachePath,
  CHECK_TTL_MS,
  clearCache,
  isStale,
  notifyFromCache,
  readCache,
  refreshCache,
  writeCache,
} from './update-cache.ts';
export { outdated, renderReport } from './update-render.ts';
export type { ReportDeps } from './updates.ts';
export {
  CLI_PACKAGE,
  cliRecordedBy,
  cliVersion,
  gatherReport,
  gatherReportLive,
  installedPluginVersions,
  npmViewVersion,
} from './updates.ts';

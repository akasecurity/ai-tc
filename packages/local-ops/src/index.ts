export type { ApplyMode, ApplyResult } from './apply.ts';
export { applyCliUpdate, applyPluginUpdate, installAgentPlugin } from './apply.ts';
export type { BackgroundScheduleDeps } from './background-schedule.ts';
export {
  BACKGROUND_SYNC_INTERVAL_SECONDS,
  BACKGROUND_SYNC_LABEL,
  backgroundSyncLabel,
  installBackgroundSync,
  renderPlist,
  uninstallBackgroundSync,
} from './background-schedule.ts';
export { claudeAvailable, installClaudePlugin, updateClaudePlugin } from './claude-plugin.ts';
export type { CliPluginBin, CliPluginManager } from './cli-plugin-manager.ts';
export { createCliPluginManager } from './cli-plugin-manager.ts';
export { codexAvailable, installCodexPlugin, updateCodexPlugin } from './codex-plugin.ts';
export type { EgressRecordResult } from './egress-record.ts';
export { recordProjectEgress } from './egress-record.ts';
export type { RunResult } from './exec.ts';
export { binExists, runCapture, runInherit } from './exec.ts';
export type {
  CollectedFile,
  ScannedFileFindings,
  ScanPathOptions,
  ScanPathResult,
} from './fs-scan.ts';
export { collectFiles, scanPathIntoStore } from './fs-scan.ts';
export type {
  DroppedRules,
  GuardedFileScanner,
  GuardedFileScannerOptions,
} from './guarded-scan.ts';
export { createGuardedFileScanner } from './guarded-scan.ts';
export type {
  ChannelProbe,
  InstallChannel,
  InstallManager,
  InstallOrigin,
  UpdatePlan,
} from './install-channel.ts';
export {
  classifyInstall,
  describeChannel,
  detectInstallChannel,
  planCliUpdate,
} from './install-channel.ts';
export type { ProjectInventoryResult } from './project-inventory.ts';
export { recordProjectInventory } from './project-inventory.ts';
export type { AgentPlugin } from './registry.ts';
export { AGENT_PLUGINS, findAgent, pluginRef } from './registry.ts';
export type { Reinvocation } from './self-exec.ts';
export { isSea, reinvokeArgv } from './self-exec.ts';
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
  installedAgentPluginVersions,
  installedCodexPluginVersions,
  installedPluginVersions,
  npmViewVersion,
} from './updates.ts';

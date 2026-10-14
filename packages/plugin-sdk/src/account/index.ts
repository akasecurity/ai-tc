export type {
  AccountCheck,
  AccountContext,
  AccountContextInput,
  AccountPlanState,
  AccountScopeView,
  BasisInput,
} from './account-check.ts';
export {
  accountContextFor,
  accountContextOf,
  accountGateOpen,
  CHATGPT_ACCOUNT_PREFIX,
  chatgptKey,
  CLAUDE_ACCOUNT_PREFIX,
  claudeKey,
  decideBasis,
  emailMatchesAttached,
  hasManualKey,
  isAccountMatch,
  isLearned,
  isManual,
} from './account-check.ts';
export type { ClaudeAccountEnv } from './account-env.ts';
export {
  CLAUDE_ACCOUNT_ENV_NAMES,
  CLAUDE_BASE_URL_ENV,
  CLAUDE_CREDENTIAL_ENV,
  CLAUDE_PROVIDER_FLAG_ENV,
  isNonDefaultBaseUrl,
  isPresent,
  isTruthyFlag,
  readClaudeAccountEnv,
} from './account-env.ts';
export type {
  AttributionCarry,
  AttributionInput,
  AttributionResult,
  AttributionView,
  PendingHold,
  RecordAttribution,
  TranscriptMark,
} from './attribution.ts';
export {
  attributeRecords,
  ATTRIBUTION_HOLD_MAX_AGE_MS,
  ATTRIBUTION_HOLD_MAX_PASSES,
  holdDecision,
  NO_ATTRIBUTION_CARRY,
} from './attribution.ts';
export type { ClaudeLogin, ClaudeLoginPaths, ClaudeLoginRead } from './claude-login.ts';
export {
  CLAUDE_CONFIG_MAX_BYTES,
  claudeConfigPath,
  claudeManagedSettingsPath,
  claudePlanState,
  claudeSettingsPaths,
  claudeSettingsVeto,
  readClaudeLogin,
} from './claude-login.ts';
export type {
  AnchorOutcome,
  AnchorState,
  ClaudeVerdictMemo,
  CredentialOrgSighting,
  ResolvedAnchor,
  SessionAnchor,
  TranscriptDelta,
} from './claude-session.ts';
export {
  anchorOf,
  credentialOrgAt,
  credentialOrgOf,
  readScanCache,
  resolveSessionAnchor,
  scanCredentialOrgs,
  TRANSCRIPT_SCAN_CAP_BYTES,
  TranscriptScanCache,
  writeScanCache,
} from './claude-session.ts';
export type {
  ClaudeHookInput,
  ClaudeHookResult,
  ClaudeLoginReport,
  ClaudeSessionInput,
  ClaudeSessionSource,
} from './claude-validate.ts';
export {
  checkClaudeHook,
  claudeEnvFingerprint,
  claudeLoginCheck,
  claudeLoginView,
  claudeVetoed,
  loginViewObservation,
  startClaudeSession,
  validateClaudeSession,
} from './claude-validate.ts';
export type {
  LoggedObservation,
  ObservationKind,
  ObservationRead,
  SessionBoundary,
} from './observation-log.ts';
export {
  appendObservation,
  classifyObservation,
  latestBoundary,
  readObservations,
  readObservationTail,
  SESSION_LOG_CAP_BYTES,
  SESSION_LOG_TAIL_BYTES,
  sessionAccountHash,
  sessionLogOpenFlags,
  sessionLogPath,
  sessionScanCachePath,
  sessionStateName,
} from './observation-log.ts';

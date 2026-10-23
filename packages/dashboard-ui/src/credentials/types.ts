// The shapes the credential views render. A host maps its own credential
// records onto these; the views never see a value or its fingerprint.
import type { CredentialStatus, Severity } from '@akasecurity/schema';

export interface CredentialListItem {
  id: string;
  /** The variable the value was last seen assigned to, when a scan named one. */
  variableName: string | null;
  /** The name an administrator gave it; null when it has none. An empty string counts as none. */
  label: string | null;
  /**
   * The name to show: the label, else the variable name, else the kind and
   * where it was seen. Read it through `credentialName`, which falls back
   * when it is empty.
   */
  displayName: string;
  /** The detecting rule's short label, such as "GitHub token". */
  kind: string;
  provider: string | null;
  /** Who answers for it; null when nobody has said. */
  owner: string | null;
  projectCount: number;
  teamCount: number;
  endpointCount: number;
  /**
   * ISO date or time it was last rotated; null when nobody has said. The
   * rotation editor saves it as a date, so a time it carries is dropped on save.
   */
  lastRotated: string | null;
  /** ISO time it was last seen. */
  lastSeen: string;
  /** Whole days between rotations; null when no policy is set. */
  rotationPolicyDays: number | null;
  /** What needs attention; empty when nothing does. */
  statuses: CredentialStatus[];
}

/** How many credentials each status chip covers under the current search, whatever chip is on. */
export interface CredentialStatusCounts {
  all: number;
  byStatus: Record<CredentialStatus, number>;
}

/** What an administrator enters about a credential. Null clears a field. */
export interface CredentialRotationInput {
  owner: string | null;
  /** ISO date, `YYYY-MM-DD`. */
  lastRotated: string | null;
  rotationPolicyDays: number | null;
}

export interface CredentialTeamUsage {
  /** The group tag, or null for the users with none. */
  name: string | null;
  userCount: number;
}

export interface CredentialLinkedFinding {
  id: string;
  name: string;
  severity: Severity;
  /** ISO time the capture that raised it happened. */
  detectedAt: string;
}

export interface CredentialDetailModel extends CredentialListItem {
  ruleId: string;
  /** ISO time it was first seen. */
  firstSeen: string;
  sightingCount: number;
  /** The secrets-manager reference; null marks a credential as detected only. */
  reference: string | null;
  /** ISO time the policy next falls due; null when no policy is set. */
  rotationDueAt: string | null;
  projects: string[];
  teams: CredentialTeamUsage[];
  /** Source tool ids, such as "claude-code"; an id the registry does not know is shown as sent. */
  harnesses: string[];
  findings: CredentialLinkedFinding[];
}

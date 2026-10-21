// The shapes the credential views render. A host maps its own credential
// records onto these; the views never see a value or its fingerprint.
import type { Severity } from '@akasecurity/schema';

export interface CredentialListItem {
  id: string;
  /** The variable the value was last seen assigned to, when a scan named one. */
  variableName: string | null;
  /** The name an administrator gave it. */
  label: string | null;
  /** The name to show: the label, else the variable name, else the kind and where it was seen. */
  displayName: string;
  /** The detecting rule's short label, such as "GitHub token". */
  kind: string;
  provider: string | null;
  /** Null until a secrets manager supplies one. */
  owner: string | null;
  projectCount: number;
  teamCount: number;
  endpointCount: number;
  /** ISO time; null until a secrets manager supplies one. */
  lastRotated: string | null;
  /** ISO time it was last seen. */
  lastSeen: string;
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
  projects: string[];
  teams: CredentialTeamUsage[];
  /** Source tool ids, such as "claude-code"; an id the registry does not know is shown as sent. */
  harnesses: string[];
  findings: CredentialLinkedFinding[];
}

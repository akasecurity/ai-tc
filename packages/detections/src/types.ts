import type { DetectionCategory, Rule, Severity, Span } from '@akasecurity/schema';

export interface MatchResult {
  ruleId: string;
  category: DetectionCategory;
  severity: Severity;
  span: Span;
  rawMatch: string;
  confidence: number;
  // For a secret assigned on its line (`NAME=value`, `name: value`), the name
  // it is assigned to. Never contains the value.
  variableName?: string;
}

export interface ScanResult {
  findings: MatchResult[];
  redactedText: string;
}

export interface Matcher {
  match(text: string, rule: Rule): Span[];
}

export interface RulePack {
  id: string;
  rules: Rule[];
}

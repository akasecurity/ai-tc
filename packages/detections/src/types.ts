import type { DetectionCategory, Rule, Severity, Span } from '@aka/schema';

export interface MatchResult {
  ruleId: string;
  category: DetectionCategory;
  severity: Severity;
  span: Span;
  rawMatch: string;
  confidence: number;
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

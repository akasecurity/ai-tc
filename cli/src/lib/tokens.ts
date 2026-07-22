// Token/cost formatting for the CLI's read surfaces — the `aka stats` block and
// the TUI health screen. All three are the SHARED @akasecurity/schema
// formatters (re-exported under the CLI's local names) so the CLI, the plugin's
// `/aka:tokens`, and the web-ui print the same token magnitude (K/M/B/T) AND the
// same cost figure/qualifier convention.
export {
  formatTokenCount as compactTokens,
  formatCostTotal as totalCostLabel,
  formatUsd as usdCost,
} from '@akasecurity/schema';

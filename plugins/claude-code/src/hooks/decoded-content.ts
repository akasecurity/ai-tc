// A session in which an MCP tool has returned text is marked, and a later call to
// something that sends data out (an MCP tool that sends, exports, uploads, writes
// or runs, or a Bash network command) carries a synthetic scan unit naming that,
// which the agent-harness-tamper `tool-output-outbound-call` rule matches. The
// decision reads neither the returned text nor how it was produced, so it does not
// depend on the tool's name, the carrier an instruction was hidden in, or its wording.
import type { ScannableField } from './pre-tool-use-fields.ts';

export const MCP_OUTPUT_SESSION_MARKER = 'mcp-output-sessions';

/** The prefix of the synthetic scan unit; the rule's pattern matches it. */
export const MCP_OUTPUT_SESSION_TEXT = 'aka-session-state: mcp-output-in-session';

// The part of an `mcp__<server>__<tool>` name after the server.
function mcpToolPart(toolName: string): string | undefined {
  if (!toolName.startsWith('mcp__')) return undefined;
  return toolName.split('__').slice(2).join('__') || undefined;
}

const OUTBOUND_MCP_TOOL =
  /send|forward|export|upload|publish|share|transfer|post[_-]|webhook|exfil|dump|write|delete|exec|run[_-]|shell/i;

const OUTBOUND_BASH =
  /(?<![\w.-])(?:curl|wget|scp|sftp|rsync|ncat?|socat|sendmail|mail|mutt|swaks)(?![\w.-])/;

/** Whether a tool call sends data out of the session or acts on the machine. */
export function isOutboundCall(toolName: string, toolInput: Record<string, unknown>): boolean {
  const tool = mcpToolPart(toolName);
  if (tool !== undefined) return OUTBOUND_MCP_TOOL.test(tool);
  if (toolName !== 'Bash') return false;
  const command = toolInput.command;
  return typeof command === 'string' && OUTBOUND_BASH.test(command);
}

/** Whether a tool's output is MCP output, which marks the session. */
export function isMcpTool(toolName: string): boolean {
  return mcpToolPart(toolName) !== undefined;
}

/** The scan unit added to an outbound call in a session that has had MCP output. */
export function mcpOutputSessionField(toolName: string): ScannableField {
  return {
    path: [],
    executable: true,
    text: `${MCP_OUTPUT_SESSION_TEXT}; outbound tool ${toolName === 'Bash' ? 'Bash' : 'mcp'}`,
  };
}

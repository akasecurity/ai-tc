/**
 * Minimal popup status UI: native-host connection state, a whole-store
 * findings tally (via the health relay — see native-host/protocol.ts), and a
 * quick link to `aka dashboard`. Mirrors the CLI plugins' onboarding/health
 * surfaces, much smaller — this is a glance, not a dashboard.
 */
import type { BackgroundRequest, BackgroundResponse } from '../messaging.ts';

const DASHBOARD_URL = 'http://localhost:4319/security';

function relay(request: BackgroundRequest): Promise<BackgroundResponse> {
  return chrome.runtime.sendMessage<BackgroundRequest, BackgroundResponse>(request);
}

function setStatus(text: string, tone: 'ok' | 'error' | 'pending'): void {
  const dot = document.getElementById('status-dot');
  const label = document.getElementById('status-text');
  if (dot) dot.className = `dot ${tone === 'pending' ? '' : tone}`.trim();
  if (label) label.textContent = text;
}

function setFindings(count: number): void {
  const row = document.getElementById('findings-row');
  const text = document.getElementById('findings-text');
  if (!row || !text) return;
  text.textContent = `${count.toString()} finding${count === 1 ? '' : 's'} recorded (all time)`;
  row.hidden = false;
}

async function refresh(): Promise<void> {
  const ping = await relay({ type: 'ping' }).catch((): BackgroundResponse => ({
    type: 'error',
    requestId: undefined,
    ok: false,
    message: 'relay failed',
  }));

  if (ping.type !== 'ping') {
    setStatus('Native host not reachable — run `aka extension install`', 'error');
    return;
  }
  setStatus(ping.onboarded ? 'Connected' : 'Connected (not onboarded — run aka:setup)', 'ok');

  const health = await relay({ type: 'health' }).catch((): BackgroundResponse => ({
    type: 'error',
    requestId: undefined,
    ok: false,
    message: 'relay failed',
  }));
  if (health.type === 'health') setFindings(health.findings);
}

document.getElementById('open-dashboard')?.addEventListener('click', () => {
  void chrome.tabs.create({ url: DASHBOARD_URL });
});

void refresh();

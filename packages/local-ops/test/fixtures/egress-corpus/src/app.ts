// Multi-line call: the URL literal and the options object that carries the
// method sit on different lines.
export async function chargeCard(form: URLSearchParams, secretKey: string): Promise<unknown> {
  const response = await fetch('https://api.stripe.com/v1/charges', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${secretKey}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: form,
  });
  return response.json();
}

// Settlement events arrive over an encrypted socket held open for the life of
// the worker.
export function openSettlementStream(): WebSocket {
  return new WebSocket('wss://stream.acme-telemetry-live.com/v1/events');
}

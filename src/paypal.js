// Capturing an approved order. Kept free of the browser so it can be tested with node --test.
const SANDBOX_API = 'https://api-m.sandbox.paypal.com';

// The SDK's own capture can fail because it has no buyer token, even though the buyer approved the
// order. PayPal still gives us a token for this order, so capture through the REST API instead.
// Only that exact failure falls back, so a capture that may have run is never attempted twice.
export async function captureOrder(data, actions, fetchImpl = globalThis.fetch) {
  try {
    return await actions.order.capture();
  } catch (error) {
    if (!/Buyer access token/i.test(error?.message || '') || !data.facilitatorAccessToken) throw error;
  }
  const response = await fetchImpl(`${SANDBOX_API}/v2/checkout/orders/${encodeURIComponent(data.orderID)}/capture`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${data.facilitatorAccessToken}`, 'Content-Type': 'application/json' },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`PayPal capture failed: ${response.status} ${body.name || ''} ${body.debug_id || ''}`.trim());
  return body;
}

// Only a finished capture counts as paid. Anything but finished or pending is an error.
export function readCapture(order) {
  const capture = order?.purchase_units?.[0]?.payments?.captures?.[0];
  if (order?.status !== 'COMPLETED' || !capture) throw new Error(`Order finished as ${order?.status}`);
  if (capture.status === 'COMPLETED') return { id: capture.id, status: 'Paid' };
  if (capture.status === 'PENDING') return { id: capture.id, status: 'Pending' };
  throw new Error(`Capture finished as ${capture.status}`);
}

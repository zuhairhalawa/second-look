import { test } from 'node:test';
import assert from 'node:assert/strict';
import { captureOrder, readCapture } from '../src/paypal.js';

const data = { orderID: 'ORDER1', facilitatorAccessToken: 'token' };
const done = { status: 'COMPLETED', purchase_units: [{ payments: { captures: [{ id: 'CAP1', status: 'COMPLETED' }] } }] };
const noBuyerToken = () => Promise.reject(new Error('Buyer access token not present - can not call smart api: /x'));
const unusedFetch = () => assert.fail('should not call the REST API');

test('uses the SDK capture when it works', async () => {
  const order = await captureOrder(data, { order: { capture: async () => done } }, unusedFetch);
  assert.equal(order, done);
});

test('falls back to the REST API when the SDK has no buyer token', async () => {
  const calls = [];
  const order = await captureOrder(data, { order: { capture: noBuyerToken } }, async (url, options) => {
    calls.push({ url, options });
    return { ok: true, json: async () => done };
  });
  assert.equal(order, done);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER1/capture');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer token');
});

test('any other SDK error is not retried, so an order is never captured twice', async () => {
  const actions = { order: { capture: () => Promise.reject(new Error('INSTRUMENT_DECLINED')) } };
  await assert.rejects(captureOrder(data, actions, unusedFetch), /INSTRUMENT_DECLINED/);
});

test('a rejected REST capture is reported as a failure', async () => {
  const refuse = async () => ({ ok: false, status: 403, json: async () => ({ name: 'PERMISSION_DENIED', debug_id: 'abc' }) });
  await assert.rejects(captureOrder(data, { order: { capture: noBuyerToken } }, refuse), /403 PERMISSION_DENIED abc/);
});

test('without a token the original error stands', async () => {
  await assert.rejects(captureOrder({ orderID: 'ORDER1' }, { order: { capture: noBuyerToken } }, unusedFetch), /Buyer access token/);
});

test('readCapture only reports a finished capture as paid', () => {
  assert.deepEqual(readCapture(done), { id: 'CAP1', status: 'Paid' });
  const pending = { status: 'COMPLETED', purchase_units: [{ payments: { captures: [{ id: 'CAP2', status: 'PENDING' }] } }] };
  assert.deepEqual(readCapture(pending), { id: 'CAP2', status: 'Pending' });
  assert.throws(() => readCapture({ status: 'APPROVED', purchase_units: [{}] }), /APPROVED/);
  const declined = { status: 'COMPLETED', purchase_units: [{ payments: { captures: [{ id: 'CAP3', status: 'DECLINED' }] } }] };
  assert.throws(() => readCapture(declined), /DECLINED/);
});

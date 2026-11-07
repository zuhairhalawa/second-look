import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAG_MARGIN, STRONG_MARGIN, compareToLibrary, combine, whyLines, parseAmount, canPay, csvSafe } from '../src/risk.js';
import { PATTERNS, SCAM_EXAMPLES } from '../src/exemplars.js';
import { SAMPLES } from '../src/samples.js';

const ai = (margin, pattern = 'upfrontFee') => ({ margin, pattern });

test('compareToLibrary scores against the closest examples and names the nearest pattern', () => {
  const scam = [{ vector: [1, 0], pattern: 'upfrontFee' }, { vector: [0.9, 0.1], pattern: 'threat' }, { vector: [0.8, 0.2], pattern: 'threat' }];
  const normal = [[0, 1], [0.1, 0.9], [0.2, 0.8]];
  const result = compareToLibrary([1, 0], scam, normal);
  assert.equal(result.pattern, 'upfrontFee');
  assert.ok(result.margin > 0.5);
  assert.ok(compareToLibrary([0, 1], scam, normal).margin < 0);
});

test('a strong rule match means stop, whatever the model says', () => {
  assert.equal(combine({ band: 'high' }, ai(-1)).level, 'stop');
  assert.equal(combine({ band: 'high' }, null).level, 'stop');
});

test('a strong model match or rules and model agreeing means stop', () => {
  assert.equal(combine({ band: 'low' }, ai(STRONG_MARGIN)).level, 'stop');
  assert.equal(combine({ band: 'caution' }, ai(FLAG_MARGIN)).level, 'stop');
});

test('a weaker signal from one source means look twice', () => {
  assert.equal(combine({ band: 'caution' }, ai(-1)).level, 'look');
  assert.equal(combine({ band: 'low' }, ai(FLAG_MARGIN)).level, 'look');
});

test('no warning signs is never described as safe', () => {
  const result = combine({ band: 'low' }, ai(FLAG_MARGIN - 0.001));
  assert.equal(result.level, 'clear');
  assert.doesNotMatch(result.label + result.summary, /\bsafe\b/i);
});

test('without the model it says so, rather than implying a full check', () => {
  const result = combine({ band: 'low' }, null);
  assert.equal(result.level, 'clear');
  assert.equal(result.aiUsed, false);
  assert.match(result.summary, /rules only/i);
});

test('the explanation names the pattern only when the model flagged the message', () => {
  assert.match(whyLines({ signals: [] }, ai(FLAG_MARGIN, 'overpayment'))[0].text, /overpayment/);
  assert.equal(whyLines({ signals: [] }, ai(FLAG_MARGIN - 0.001, 'overpayment')).length, 0);
  assert.equal(whyLines({ signals: [{ label: 'Asks for a gift card' }] }, null)[0].source, 'rule');
});

test('every library example has a pattern with a description', () => {
  for (const [pattern] of SCAM_EXAMPLES) assert.ok(PATTERNS[pattern], pattern);
});

test('demo messages are not copied from the library, so the demo is a fair test', () => {
  const library = new Set(SCAM_EXAMPLES.map(([, text]) => text));
  for (const sample of SAMPLES) assert.equal(library.has(sample.text), false, sample.id);
});

test('parseAmount reads the first money amount', () => {
  assert.equal(parseAmount('Pay $1,250.50 by Friday, plus a $5 fee'), 1250.5);
  assert.equal(parseAmount('It comes to 32.50 USD each'), 32.5);
  assert.equal(parseAmount('No amount here, just 12 people'), null);
});

test('exported text cannot run as a spreadsheet formula', () => {
  assert.equal(csvSafe('=HYPERLINK("http://bad.example")'), '\'=HYPERLINK("http://bad.example")');
  assert.equal(csvSafe('  +1234'), '\'  +1234');
  assert.equal(csvSafe('@SUM(A1)'), '\'@SUM(A1)');
  assert.equal(csvSafe('Rent for June'), 'Rent for June');
  assert.equal(csvSafe(1200), 1200);
  assert.equal(csvSafe(null), null);
});

test('nothing can be paid while the check is still running', () => {
  assert.equal(canPay('clear', { checking: true }), false);
  assert.equal(canPay('look', { checking: true, checked: true }), false);
  assert.equal(canPay('stop', { checking: true, checked: true, typedAmount: '150', amount: 150 }), false);
});

test('a held payment cannot be paid until it is moved back to review', () => {
  assert.equal(canPay('clear', { held: true }), false);
  assert.equal(canPay('stop', { held: true, checked: true, typedAmount: '150', amount: 150 }), false);
});

test('payment gates depend on the level', () => {
  assert.equal(canPay('clear', {}), true);
  assert.equal(canPay('look', {}), false);
  assert.equal(canPay('look', { checked: true }), true);
  assert.equal(canPay('stop', { checked: true }), false);
  assert.equal(canPay('stop', { checked: true, typedAmount: '150.00', amount: 150 }), true);
  assert.equal(canPay('stop', { checked: true, typedAmount: '15', amount: 150 }), false);
  assert.equal(canPay('stop', { checked: true, typedAmount: '', amount: 0 }), false);
});

// Pure decision logic, kept free of the browser so it can be tested with node --test.
import { PATTERNS } from './exemplars.js';

// A message is flagged when it sits closer to the scam examples than to the normal ones.
// FLAG_MARGIN was chosen by leave-one-out on the library, then scored once on a held-out set.
export const FLAG_MARGIN = 0.01;
export const STRONG_MARGIN = 0.1;
const NEIGHBOURS = 3;

const dot = (a, b) => {
  let total = 0;
  for (let i = 0; i < a.length; i += 1) total += a[i] * b[i];
  return total;
};
const meanOfTop = (values, k) => {
  const top = [...values].sort((x, y) => y - x).slice(0, k);
  return top.reduce((n, v) => n + v, 0) / top.length;
};

// `vector` and the library vectors are normalized sentence embeddings.
export function compareToLibrary(vector, scamLibrary, normalLibrary) {
  const scamScores = scamLibrary.map((entry) => dot(vector, entry.vector));
  const normalScores = normalLibrary.map((entry) => dot(vector, entry));
  const nearest = scamScores.indexOf(Math.max(...scamScores));
  return {
    margin: meanOfTop(scamScores, NEIGHBOURS) - meanOfTop(normalScores, NEIGHBOURS),
    pattern: scamLibrary[nearest].pattern,
  };
}

const COPY = {
  stop: { label: 'Stop and check', summary: 'Strong warning signs. Hold this until you have checked it another way.' },
  look: { label: 'Look twice', summary: 'Something here looks off. Check before you pay.' },
  clear: { label: 'No warning signs', summary: 'Nothing stood out, but this can’t prove a request is genuine.' },
};

// `ai` is null when the model has not run or could not load.
export function combine(rule, ai) {
  const aiUsed = Boolean(ai);
  const flagged = aiUsed && ai.margin >= FLAG_MARGIN;
  const strong = aiUsed && ai.margin >= STRONG_MARGIN;
  let level = 'clear';
  if (rule.band === 'high' || strong || (rule.band === 'caution' && flagged)) level = 'stop';
  else if (rule.band === 'caution' || flagged) level = 'look';
  const summary = aiUsed ? COPY[level].summary : `${COPY[level].summary} Checked with rules only, because the on-device AI isn’t running.`;
  return { level, label: COPY[level].label, summary, aiUsed, flagged };
}

export function whyLines(rule, ai) {
  const lines = rule.signals.slice(0, 3).map((signal) => ({ text: signal.label, source: 'rule' }));
  if (ai && ai.margin >= FLAG_MARGIN) {
    lines.push({ text: `The wording is closest to ${PATTERNS[ai.pattern]}.`, source: 'on-device AI, may be wrong' });
  }
  return lines;
}

export function parseAmount(text) {
  const match = String(text).match(/\$\s?(\d[\d,]*(?:\.\d{1,2})?)|(\d[\d,]*(?:\.\d{1,2})?)\s?(?:USD|dollars)\b/i);
  if (!match) return null;
  const value = Number((match[1] ?? match[2]).replace(/,/g, ''));
  return Number.isFinite(value) && value > 0 ? value : null;
}

// How much friction stands between the person and the PayPal button.
export function canPay(level, { checked = false, typedAmount = '', amount = 0, checking = false, held = false } = {}) {
  if (checking || held) return false;
  if (level === 'clear') return true;
  if (level === 'look') return checked;
  return checked && String(typedAmount).trim() !== '' && Number(amount) > 0 && Number(typedAmount) === Number(amount);
}

// Message text comes from whoever sent it, so it must not run as a formula when the CSV is opened.
export function csvSafe(value) {
  return typeof value === 'string' && /^\s*[=+\-@]/.test(value) ? `'${value}` : value;
}

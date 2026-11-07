// Scores the shipped decision code on a held-out set. Results depend only on src/ and holdout.js.
import { pipeline, env } from 'https://cdn.jsdelivr.net/npm/@huggingface/transformers@4.3.2';
import { analyzeMessage } from '../src/analyzer.js';
import { SCAM_EXAMPLES, NORMAL_EXAMPLES } from '../src/exemplars.js';
import { FLAG_MARGIN, compareToLibrary, combine } from '../src/risk.js';
import { scams, legit } from './holdout.js';

env.allowLocalModels = false;
const embed = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2', { dtype: 'q8', device: 'wasm' });
const vectorOf = async (text) => Array.from((await embed(text, { pooling: 'mean', normalize: true })).data);

const scamLibrary = [];
for (const [pattern, text] of SCAM_EXAMPLES) scamLibrary.push({ pattern, vector: await vectorOf(text) });
const normalLibrary = [];
for (const text of NORMAL_EXAMPLES) normalLibrary.push(await vectorOf(text));

// How the threshold was chosen: leave each library example out, then see how the rest score it.
const scamMargins = scamLibrary.map((entry, i) => compareToLibrary(entry.vector, scamLibrary.filter((_, j) => j !== i), normalLibrary).margin);
const normalMargins = normalLibrary.map((vector, i) => compareToLibrary(vector, scamLibrary, normalLibrary.filter((_, j) => j !== i)).margin);
const leaveOneOut = {
  caught: scamMargins.filter((m) => m >= FLAG_MARGIN).length,
  scams: scamMargins.length,
  falseAlarms: normalMargins.filter((m) => m >= FLAG_MARGIN).length,
  normal: normalMargins.length,
};

const score = async (text) => {
  const rule = analyzeMessage(text);
  const started = performance.now();
  const ai = compareToLibrary(await vectorOf(text), scamLibrary, normalLibrary);
  const ms = performance.now() - started;
  const { level, flagged } = combine(rule, ai);
  return { text, level, margin: Number(ai.margin.toFixed(3)), pattern: flagged ? ai.pattern : null, ruleBand: rule.band, ms };
};
const scamResults = [];
for (const text of scams) scamResults.push(await score(text));
const legitResults = [];
for (const text of legit) legitResults.push(await score(text));

const flaggedBy = {
  rules: (r) => r.ruleBand !== 'low',
  model: (r) => r.margin >= FLAG_MARGIN,
  combined: (r) => r.level !== 'clear',
};
const heldOut = Object.fromEntries(Object.entries(flaggedBy).map(([name, test]) => [name, {
  caught: scamResults.filter(test).length,
  scams: scamResults.length,
  falseAlarms: legitResults.filter(test).length,
  genuine: legitResults.length,
}]));
const all = [...scamResults, ...legitResults];
const report = {
  threshold: FLAG_MARGIN,
  leaveOneOut,
  heldOut,
  levels: {
    scams: Object.fromEntries(['stop', 'look', 'clear'].map((l) => [l, scamResults.filter((r) => r.level === l).length])),
    genuine: Object.fromEntries(['stop', 'look', 'clear'].map((l) => [l, legitResults.filter((r) => r.level === l).length])),
  },
  msPerMessage: Math.round(all.reduce((n, r) => n + r.ms, 0) / all.length),
  missedScams: scamResults.filter((r) => r.level === 'clear').map((r) => r.text),
  falseAlarms: legitResults.filter((r) => r.level !== 'clear').map((r) => r.text),
  patternsNamed: scamResults.filter((r) => r.pattern).map((r) => ({ text: r.text.slice(0, 70), pattern: r.pattern })),
};
window.report = report;
document.getElementById('out').textContent = JSON.stringify(report, null, 2);

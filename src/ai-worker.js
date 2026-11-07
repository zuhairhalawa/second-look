// Runs the model off the main thread. Messages stay in this browser: the only network traffic here
// is downloading the library and the model, which the browser then caches.
import { pipeline, env } from 'https://cdn.jsdelivr.net/npm/@huggingface/transformers@4.3.2';
import { SCAM_EXAMPLES, NORMAL_EXAMPLES } from './exemplars.js';
import { compareToLibrary } from './risk.js';

env.allowLocalModels = false;

const MODEL = 'Xenova/all-MiniLM-L6-v2';
let embed = null;
let scamLibrary = [];
let normalLibrary = [];

const vectorOf = async (text) => (await embed(text, { pooling: 'mean', normalize: true })).data;

async function load() {
  embed = await pipeline('feature-extraction', MODEL, {
    dtype: 'q8',
    device: 'wasm',
    progress_callback: (p) => {
      if (p.status === 'progress' && p.file?.endsWith('.onnx')) self.postMessage({ type: 'progress', percent: Math.round(p.progress) });
    },
  });
  for (const [pattern, text] of SCAM_EXAMPLES) scamLibrary.push({ pattern, vector: await vectorOf(text) });
  for (const text of NORMAL_EXAMPLES) normalLibrary.push(await vectorOf(text));
  self.postMessage({ type: 'ready' });
}

self.onmessage = async ({ data }) => {
  try {
    if (data.type === 'load') {
      await load();
      return;
    }
    const result = compareToLibrary(await vectorOf(data.text), scamLibrary, normalLibrary);
    self.postMessage({ type: 'result', id: data.id, result });
  } catch (error) {
    self.postMessage({ type: 'error', id: data.id, message: String(error?.message || error).slice(0, 200) });
  }
};

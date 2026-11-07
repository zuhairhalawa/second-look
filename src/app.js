import { analyzeMessage } from './analyzer.js';
import { SAMPLES } from './samples.js';
import { combine, whyLines, parseAmount, canPay, csvSafe } from './risk.js';
import { captureOrder, readCapture } from './paypal.js';
import { PAYPAL_CLIENT_ID } from '../config.js';

const STORE = 'second-look-v1';
const $ = (id) => document.getElementById(id);
const money = (n) => (n == null ? 'Amount not found' : `$${Number(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`);

// ------------------------------------------------------------------ state
const load = () => {
  try {
    return JSON.parse(localStorage.getItem(STORE)) || {};
  } catch {
    return {};
  }
};
const saved = load();
const rows = [...(saved.added || []), ...SAMPLES].map((r) => ({
  ...r,
  rule: analyzeMessage(r.text),
  ai: null,
  checking: true,
  status: saved.status?.[r.id]?.status || 'To review',
  captureId: saved.status?.[r.id]?.captureId || null,
}));
let selected = null;
let levelFilter = 'all';
let aiState = 'loading';

const persist = () => {
  const status = {};
  for (const r of rows) if (r.status !== 'To review') status[r.id] = { status: r.status, captureId: r.captureId };
  const added = rows.filter((r) => r.added).map(({ id, from, amount, text, added: a }) => ({ id, from, amount, text, added: a }));
  localStorage.setItem(STORE, JSON.stringify({ status, added }));
};
const resultOf = (r) => combine(r.rule, r.ai);
const isPaidOrPending = (r) => r.status === 'Paid' || r.status === 'Pending';

// ------------------------------------------------------------------ grid
function verdictCell({ data }) {
  const el = document.createElement('span');
  if (!data || data.isTotals) return el;
  const pending = data.checking && aiState !== 'off';
  const result = resultOf(data);
  el.className = `chip ${pending ? 'wait' : result.level}`;
  el.textContent = pending ? 'Checking' : result.label;
  return el;
}

const totalsRow = () => {
  const sum = (status) => rows.filter((r) => r.status === status).reduce((n, r) => n + (r.amount || 0), 0);
  return [{ id: 'totals', from: 'Totals', text: `Held back ${money(sum('Held'))}. Paid ${money(sum('Paid'))}.`, isTotals: true }];
};

const LEVEL_ORDER = { stop: 0, look: 1, clear: 2 };
const gridApi = window.agGrid.createGrid($('grid'), {
  theme: window.agGrid.themeQuartz.withParams({
    fontFamily: 'var(--sans)',
    fontSize: 14,
    foregroundColor: '#17342e',
    headerBackgroundColor: '#eef4f0',
    headerFontWeight: 650,
    accentColor: '#17342e',
    selectedRowBackgroundColor: '#dfeae5',
    rowHoverColor: '#eef4f0',
    borderColor: '#cfdcd6',
    wrapperBorderRadius: 8,
  }),
  rowData: rows,
  getRowId: ({ data }) => data.id,
  rowSelection: { mode: 'singleRow', checkboxes: false, enableClickSelection: true },
  pinnedBottomRowData: totalsRow(),
  isExternalFilterPresent: () => levelFilter !== 'all',
  doesExternalFilterPass: ({ data }) => resultOf(data).level === levelFilter,
  defaultColDef: { sortable: true, resizable: true, suppressHeaderMenuButton: true },
  columnDefs: [
    {
      colId: 'result', headerName: 'Result', width: 172, cellRenderer: verdictCell,
      valueGetter: ({ data }) => (data.isTotals ? '' : resultOf(data).label),
      comparator: (a, b, nodeA, nodeB) => LEVEL_ORDER[resultOf(nodeA.data).level] - LEVEL_ORDER[resultOf(nodeB.data).level],
    },
    { headerName: 'From', field: 'from', width: 170, tooltipField: 'from' },
    { headerName: 'Request', field: 'text', flex: 1, minWidth: 120, tooltipField: 'text', colSpan: ({ data }) => (data?.isTotals ? 3 : 1) },
    {
      headerName: 'Amount', field: 'amount', width: 104, type: 'rightAligned',
      valueFormatter: ({ value, data }) => (data?.isTotals ? '' : money(value)),
      cellStyle: { fontVariantNumeric: 'tabular-nums' },
    },
    {
      headerName: 'Status', field: 'status', width: 100,
      cellClassRules: { 'status-paid': ({ value }) => value === 'Paid', 'status-held': ({ value }) => value === 'Held' },
    },
  ],
  alwaysShowVerticalScroll: true,
  tooltipShowDelay: 400,
  initialState: { sort: { sortModel: [{ colId: 'result', sort: 'asc' }] } },
  onRowSelected: ({ node }) => {
    if (node.isSelected() && !node.data.isTotals) select(node.data);
  },
});

// On a phone, keep the three columns needed to pick a request. The panel below shows the rest.
const narrow = window.matchMedia('(max-width: 600px)');
const fitColumns = () => {
  gridApi.setColumnsVisible(['text', 'status'], !narrow.matches);
  gridApi.applyColumnState({ state: [{ colId: 'from', flex: narrow.matches ? 1 : null, width: narrow.matches ? undefined : 170 }, { colId: 'result', width: narrow.matches ? 164 : 172 }, { colId: 'amount', width: narrow.matches ? 92 : 104 }] });
};
narrow.addEventListener('change', fitColumns);
fitColumns();

const refreshRow = (row) => {
  gridApi.applyTransaction({ update: [row] });
  gridApi.redrawRows({ rowNodes: [gridApi.getRowNode(row.id)].filter(Boolean) });
  gridApi.setGridOption('pinnedBottomRowData', totalsRow());
};

// ------------------------------------------------------------------ detail panel
function renderWhy(row) {
  const list = $('d-why');
  list.replaceChildren();
  for (const { text, source } of whyLines(row.rule, row.ai)) {
    const li = document.createElement('li');
    li.textContent = `${text} `;
    const tag = document.createElement('span');
    tag.className = 'source';
    tag.textContent = `(${source})`;
    li.append(tag);
    list.append(li);
  }
  $('why-title').hidden = list.children.length === 0;
}

let paypalReady = null;
function loadPayPal() {
  if (!PAYPAL_CLIENT_ID) return Promise.reject(new Error('no client id'));
  paypalReady ||= new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = `https://www.paypal.com/sdk/js?client-id=${encodeURIComponent(PAYPAL_CLIENT_ID)}&currency=USD&intent=capture&locale=en_US`;
    s.onload = () => resolve(window.paypal);
    s.onerror = () => reject(new Error('PayPal could not load'));
    document.head.append(s);
  });
  return paypalReady;
}

let latestRender = 0;
async function renderPayPal(row) {
  latestRender += 1;
  const thisRender = latestRender;
  const box = $('paypal-button');
  box.replaceChildren();
  const note = $('pay-note');
  note.textContent = '';
  if (isPaidOrPending(row)) return;
  if (row.amount == null || row.amount <= 0) {
    note.textContent = 'Second Look couldn’t find an amount in this message, so it can’t set up a payment.';
    return;
  }
  try {
    const paypal = await loadPayPal();
    if (thisRender !== latestRender) return;
    await paypal.Buttons({
      style: { layout: 'horizontal', tagline: false, height: 44, label: 'pay' },
      createOrder: (_d, actions) => actions.order.create({
        intent: 'CAPTURE',
        purchase_units: [{ amount: { value: Number(row.amount).toFixed(2), currency_code: 'USD' }, description: 'Second Look sandbox demo payment' }],
      }),
      onApprove: async (data, actions) => {
        const capture = readCapture(await captureOrder(data, actions));
        row.status = capture.status;
        row.captureId = capture.id;
        persist();
        refreshRow(row);
        select(row);
      },
      onCancel: () => { note.textContent = 'Payment cancelled. Nothing was charged.'; },
      onError: (err) => { note.textContent = 'PayPal reported a problem, and this payment did not go through.'; console.error(err); },
    }).render(box);
  } catch {
    // Picking another row removes the button that was still loading. That isn't a failure to report.
    if (thisRender !== latestRender) return;
    note.textContent = PAYPAL_CLIENT_ID ? 'PayPal checkout couldn’t load. Check your connection and try again.' : 'PayPal checkout isn’t set up yet. Add a sandbox client ID to config.js.';
  }
}

function applyGate(row) {
  const { level } = resultOf(row);
  const paid = isPaidOrPending(row);
  const checking = row.checking && aiState !== 'off';
  const held = row.status === 'Held';
  $('pay-wait').hidden = !checking || paid;
  $('gate').hidden = paid || level === 'clear' || checking || held;
  $('gate-check').hidden = level === 'clear';
  $('gate-type').hidden = level !== 'stop';
  const open = !paid && canPay(level, { checked: $('checked').checked, typedAmount: $('typed').value, amount: row.amount, checking, held });
  $('paypal-button').classList.toggle('is-locked', !open);
  $('hold').hidden = paid;
  $('hold').classList.toggle('quiet', !checking && level === 'clear' && row.status !== 'Held');
  $('hold').textContent = row.status === 'Held' ? 'Move back to review' : 'Hold this payment';
}

function select(row) {
  const changed = selected !== row;
  selected = row;
  const result = resultOf(row);
  $('empty').hidden = true;
  $('panel').hidden = false;
  $('verdict').className = `verdict ${row.checking && aiState !== 'off' ? '' : result.level}`;
  $('verdict').textContent = row.checking && aiState !== 'off' ? 'Checking' : result.label;
  $('d-from').textContent = row.from;
  $('d-amount').textContent = money(row.amount);
  $('d-text').textContent = row.text;
  $('d-summary').textContent = row.checking && aiState !== 'off' ? 'Second Look is still checking this request on your device.' : result.summary;
  renderWhy(row);
  $('stamp').hidden = row.status !== 'Held';
  $('d-receipt').hidden = !row.captureId;
  $('d-receipt').textContent = row.captureId ? `${row.status === 'Pending' ? 'Pending' : 'Paid'} in the PayPal sandbox. Capture ID: ${row.captureId}` : '';
  if (changed) {
    $('checked').checked = false;
    $('typed').value = '';
    renderPayPal(row);
  }
  applyGate(row);
}

$('checked').addEventListener('change', () => selected && applyGate(selected));
$('typed').addEventListener('input', () => selected && applyGate(selected));
$('hold').addEventListener('click', () => {
  if (!selected) return;
  selected.status = selected.status === 'Held' ? 'To review' : 'Held';
  persist();
  refreshRow(selected);
  select(selected);
});

// ------------------------------------------------------------------ on-device AI
const status = $('ai-status');
const pendingAi = new Map();
let worker;

function aiOff(reason) {
  aiState = 'off';
  status.className = 'ai-status is-off';
  status.textContent = 'On-device AI unavailable, using rules only';
  console.warn(reason);
  for (const r of rows) r.checking = false;
  gridApi.redrawRows();
  if (selected) select(selected);
}

const classify = (row) => new Promise((resolve) => {
  pendingAi.set(row.id, resolve);
  worker.postMessage({ type: 'classify', id: row.id, text: row.text });
});

let queue = Promise.resolve();
function check(row) {
  queue = queue.then(async () => {
    if (aiState !== 'ready') return;
    row.ai = await classify(row);
    row.checking = false;
    refreshRow(row);
    if (selected === row) select(row);
  });
  return queue;
}

function startAi() {
  try {
    worker = new Worker(new URL('./ai-worker.js', import.meta.url), { type: 'module' });
  } catch (error) {
    aiOff(error);
    return;
  }
  worker.onerror = (e) => aiOff(e.message);
  worker.onmessage = ({ data }) => {
    if (data.type === 'progress') {
      status.textContent = `Downloading the on-device AI, first time only (${data.percent}%)`;
    } else if (data.type === 'ready') {
      aiState = 'ready';
      status.className = 'ai-status is-ready';
      status.textContent = 'On-device AI ready. Messages stay in this browser.';
      rows.forEach(check);
    } else if (data.type === 'result') {
      pendingAi.get(data.id)?.(data.result);
      pendingAi.delete(data.id);
    } else if (data.type === 'error') {
      if (data.id) {
        pendingAi.get(data.id)?.(null);
        pendingAi.delete(data.id);
      } else {
        aiOff(data.message);
      }
    }
  };
  status.textContent = 'Starting the on-device AI';
  worker.postMessage({ type: 'load' });
}

// ------------------------------------------------------------------ toolbar and form
document.querySelectorAll('.filter').forEach((button) => {
  button.addEventListener('click', () => {
    levelFilter = button.dataset.level;
    document.querySelectorAll('.filter').forEach((b) => {
      const on = b === button;
      b.classList.toggle('is-on', on);
      b.setAttribute('aria-pressed', String(on));
    });
    gridApi.onFilterChanged();
  });
});
$('search').addEventListener('input', (e) => gridApi.setGridOption('quickFilterText', e.target.value));
$('export').addEventListener('click', () => gridApi.exportDataAsCsv({
  fileName: 'second-look-requests.csv',
  processCellCallback: ({ value }) => csvSafe(value),
}));
$('reset').addEventListener('click', () => {
  localStorage.removeItem(STORE);
  location.reload();
});
$('add').addEventListener('submit', (event) => {
  event.preventDefault();
  const text = $('new-text').value.trim();
  if (!text) return;
  const row = {
    id: `added-${Date.now()}`,
    from: $('new-from').value.trim() || 'Pasted message',
    amount: parseAmount(text),
    text,
    added: true,
    rule: analyzeMessage(text),
    ai: null,
    checking: aiState !== 'off',
    status: 'To review',
    captureId: null,
  };
  rows.unshift(row);
  gridApi.applyTransaction({ add: [row], addIndex: 0 });
  persist();
  $('add').reset();
  gridApi.getRowNode(row.id)?.setSelected(true);
  gridApi.setGridOption('pinnedBottomRowData', totalsRow());
  check(row);
});

startAi();

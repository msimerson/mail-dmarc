// One primitive at three scales: the hero band, a column per day, an inline
// band per row. HTML and CSS only, so it reflows and themes for free.

import { el, num, pct } from './core.js';

// Worst last: the ramp is ordered, not categorical.
export const BUCKETS = [
  { key: 'aligned_both', seg: 'seg-both', token: '--v-both',
    label: 'SPF + DKIM',  note: 'aligned both ways' },
  { key: 'aligned_dkim', seg: 'seg-dkim', token: '--v-dkim',
    label: 'DKIM only',   note: 'survives forwarding' },
  { key: 'aligned_spf',  seg: 'seg-spf',  token: '--v-spf',
    label: 'SPF only',    note: 'breaks when forwarded' },
  { key: 'aligned_none', seg: 'seg-none', token: '--v-none',
    label: 'Neither',     note: 'fails DMARC' },
];

const segments = (row, total, height) =>
  BUCKETS.map((bucket) => {
    const value = Number(row[bucket.key]) || 0;
    if (!value) return null;
    const size = `${(value / total) * 100}%`;
    return el('span', {
      class: bucket.seg,
      style: height ? `height:${size}` : `width:${size}`,
      title: `${bucket.label}: ${num(value)}`,
    });
  }).filter(Boolean);

export const alignBand = (totals) => {
  const total = Number(totals.messages) || 0;
  return el('div', {
    class: 'align-band',
    role: 'img',
    'aria-label': BUCKETS
      .map((b) => `${b.label} ${pct(totals[b.key], total)}`)
      .join(', '),
  }, total ? segments(totals, total) : []);
};

export const alignLegend = (totals) => {
  const total = Number(totals.messages) || 0;
  return el('div', { class: 'legend' }, BUCKETS.map((bucket) =>
    el('div', { style: `--swatch: var(${bucket.token})` }, [
      el('span', { class: 'pct', text: pct(totals[bucket.key], total) }),
      el('span', { class: 'label', text: bucket.label }),
      el('span', { class: 'cnt', text: `${num(totals[bucket.key])} · ${bucket.note}` }),
    ])));
};

export const rowBand = (row) => {
  const total = Number(row.messages) || 0;
  return el('div', { class: 'row-band' }, total ? segments(row, total) : []);
};

const DAY = 86400;

// A store spanning years would draw sub pixel columns without these.
const STEPS = [
  { days: 1,   label: 'Daily' },
  { days: 7,   label: 'Weekly' },
  { days: 28,  label: '4-weekly' },
  { days: 91,  label: 'Quarterly' },
  { days: 365, label: 'Yearly' },
];
const MAX_COLUMNS = 92;

const SUMMED = [...BUCKETS.map((b) => b.key), 'messages',
  'disp_none', 'disp_quarantine', 'disp_reject'];

// The store returns only days carrying reports, so a column per row would
// compress a gap to nothing and hide an outage. Fill, then aggregate.
export const bucketDays = (rows, since, until) => {
  if (!rows.length) return { rows: [], step: STEPS[0] };

  // Bounded by the selected window, or an outage at either edge would simply
  // not be drawn.
  const floor = (t) => Math.floor(Number(t) / DAY) * DAY;
  const first = since
    ? Math.min( Number(rows[0].day), floor(since) )
    : Number(rows[0].day);
  const last = until
    ? Math.max( Number(rows[rows.length - 1].day), floor(until - DAY) )
    : Number(rows[rows.length - 1].day);
  const span = Math.round((last - first) / DAY) + 1;

  const step = STEPS.find((s) => span / s.days <= MAX_COLUMNS)
    || STEPS[STEPS.length - 1];
  const width = step.days * DAY;

  const byBucket = new Map();
  for (const row of rows) {
    const start = first + Math.floor((Number(row.day) - first) / width) * width;
    let bucket = byBucket.get(start);
    if (!bucket) {
      bucket = { day: start, span: step.days };
      for (const key of SUMMED) bucket[key] = 0;
      byBucket.set(start, bucket);
    }
    for (const key of SUMMED) bucket[key] += Number(row[key]) || 0;
  }

  const filled = [];
  for (let start = first; start <= last; start += width) {
    const bucket = byBucket.get(start);
    if (bucket) { filled.push(bucket); continue; }
    const empty = { day: start, span: step.days };
    for (const key of SUMMED) empty[key] = 0;
    filled.push(empty);
  }

  return { rows: filled, step };
};

// Heights are relative to the busiest column; the readout carries absolutes.
export const dayColumns = (rows, onHover) => {
  const peak = rows.reduce((max, row) => Math.max(max, Number(row.messages) || 0), 0);

  const columns = rows.map((row) => {
    const total = Number(row.messages) || 0;
    return el('div', {
      class: 'day',
      tabindex: '0',
      style: `height:${peak ? (total / peak) * 100 : 0}%`,
      'aria-label': `${num(total)} messages`,
      on: {
        mouseenter: () => onHover(row),
        focus:      () => onHover(row),
        mouseleave: () => onHover(null),
        blur:       () => onHover(null),
      },
    }, total ? segments(row, total, true) : []);
  });

  return el('div', { class: 'days' }, columns);
};

// Overview: can this domain move to p=reject, and what is in the way.

import { el, replace, api, num, pct, day, dayFull, dayOrYear } from './core.js';
import { alignBand, alignLegend, dayColumns, bucketDays, BUCKETS } from './band.js';

// The reading of the band, in the words an operator would use. Stated rather
// than implied: every other view here shows figures and leaves the conclusion
// to the reader, and this is the conclusion they came for.
const verdict = (totals) => {
  const total = Number(totals.messages) || 0;
  if (!total) return null;

  const passing = Number(totals.dmarc_pass) || 0;
  const failing = Number(totals.aligned_none) || 0;
  const spfOnly = Number(totals.aligned_spf) || 0;

  const lines = [
    el('p', {}, [
      el('span', { class: 'fig fig-pass', text: pct(passing, total) }),
      document.createTextNode(' of this mail authenticates and would survive '),
      el('span', { class: 'mono', text: 'p=reject' }),
      document.createTextNode('.'),
    ]),
  ];

  lines.push(el('p', {}, failing
    ? [
      el('span', { class: 'fig fig-fail', text: pct(failing, total) }),
      document.createTextNode(` — ${num(failing)} message${failing === 1 ? '' : 's'} — would not. `),
      document.createTextNode('Check the sources below before tightening your policy.'),
    ]
    : [document.createTextNode('Nothing in this window failed DMARC.')]));

  if (spfOnly) {
    lines.push(el('p', { class: 'caveat' }, [
      document.createTextNode(`${num(spfOnly)} passed on SPF alone, so they would fail if forwarded. `),
      document.createTextNode('DKIM signing that mail closes the gap.'),
    ]));
  }

  return el('div', { class: 'verdict' }, lines);
};

const DELTAS = [
  { key: 'messages',        label: 'Messages',    kind: 'count' },
  { key: 'dmarc_pass',      label: 'DMARC pass',  kind: 'rate' },
  { key: 'disp_quarantine', label: 'Quarantined', kind: 'count', lowerIsBetter: true },
  { key: 'disp_reject',     label: 'Rejected',    kind: 'count', lowerIsBetter: true },
];

const delta = (stat, current, previous) => {
  if (!previous || !Number(previous.messages)) return null;

  if (stat.kind === 'rate') {
    const before = (Number(previous[stat.key]) / Number(previous.messages)) * 100;
    const after = (Number(current[stat.key]) / Number(current.messages)) * 100;
    const change = after - before;
    if (Math.abs(change) < 0.05) return el('span', { class: 'delta', text: 'no change' });
    return el('span', {
      class: `delta ${change > 0 ? 'better' : 'worse'}`,
      text: `${change > 0 ? '▲' : '▼'} ${Math.abs(change).toFixed(1)} pt`,
    });
  }

  const before = Number(previous[stat.key]) || 0;
  const after = Number(current[stat.key]) || 0;
  if (!before) return el('span', { class: 'delta', text: 'none before' });
  const change = ((after - before) / before) * 100;
  if (Math.abs(change) < 0.5) return el('span', { class: 'delta', text: 'no change' });
  const good = stat.lowerIsBetter ? change < 0 : change > 0;
  return el('span', {
    class: `delta ${good ? 'better' : 'worse'}`,
    text: `${change > 0 ? '▲' : '▼'} ${Math.abs(change).toFixed(0)}%`,
  });
};

const ledger = (current, previous, windowDays) => {
  const cells = el('div', { class: 'ledger' }, DELTAS.map((stat) => el('div', {}, [
    el('span', { class: 'label', text: stat.label }),
    el('span', { class: 'stat', text: stat.kind === 'rate'
      ? pct(current[stat.key], current.messages)
      : num(current[stat.key]) }),
    delta(stat, current, previous),
  ])));

  return el('section', { class: 'band band-tight' }, [
    el('h2', { class: 'band-head', text: previous && Number(previous.messages)
      ? `Movement against the previous ${windowDays} days`
      : 'In this window' }),
    cells,
  ]);
};

const DMARC_EPOCH = 1325376000;    // 2012-01-01, before which DMARC did not exist

const malformed = (series) => {
  const early = series.filter((row) => Number(row.day) < DMARC_EPOCH);
  if (!early.length) return null;
  const messages = early.reduce((sum, row) => sum + (Number(row.messages) || 0), 0);
  return el('p', { class: 'note',
    text: `${early.length} day${early.length === 1 ? '' : 's'} of reports `
        + `${early.length === 1 ? 'is' : 'are'} dated before DMARC existed, `
        + `carrying ${num(messages)} message${messages === 1 ? '' : 's'}. `
        + 'Those reports have an unusable window and are stretching this '
        + 'chart back to their date.' });
};

const volume = (series, scope) => {
  const { rows, step } = bucketDays(series, scope.since, scope.until);
  const readout = el('div', { class: 'readout' });
  const period = step.days === 1 ? 'day' : `${step.days} days`;

  const show = (row) => {
    if (!row) {
      replace(readout, el('span', { text: `Hover a column for its figures.` }));
      return;
    }
    const total = Number(row.messages) || 0;
    const span = step.days === 1
      ? dayFull(row.day)
      : `${dayFull(row.day)} + ${step.days - 1} days`;
    if (!total) {
      replace(readout, [
        el('strong', { text: span }),
        document.createTextNode(' · no reports'),
      ]);
      return;
    }
    replace(readout, [
      el('strong', { text: span }),
      document.createTextNode(` · ${num(total)} messages · `),
      ...BUCKETS.flatMap((bucket, index) => [
        index ? document.createTextNode(' · ') : null,
        el('span', { text: `${bucket.label} ${pct(row[bucket.key], total)}` }),
      ]).filter(Boolean),
    ]);
  };

  const gaps = rows.filter((row) => !row.messages).length;

  const band = el('section', { class: 'band' }, [
    el('h2', { text: `${step.label} volume by alignment` }),
    dayColumns(rows, show),
    el('div', { class: 'day-axis' }, rows.length ? [
      el('span', { text: dayOrYear(rows[0].day, step.days >= 28) }),
      el('span', { text: `one column per ${period}` }),
      el('span', { text: dayOrYear(rows[rows.length - 1].day, step.days >= 28) }),
    ] : []),
    readout,
    gaps
      ? el('p', { class: 'note',
          text: `${gaps} of ${rows.length} columns carry no reports at all.` })
      : null,
    malformed(series),
  ]);

  show(null);
  return band;
};

export const render = async (mount, scope, state, rerender) => {
  const [summary, series] = await Promise.all([
    api.summary(scope),
    api.timeseries(scope),
  ]);

  const current = summary.current;
  const rows = series.data || [];
  const windowDays = scope.since
    ? Math.round((scope.until - scope.since) / 86400) : null;

  if (!Number(current.messages)) {
    const totals = scope.domainTotals;
    replace(mount, el('div', { class: 'empty' }, [
      el('h2', { text: scope.from_domain
        ? `Nothing reported for ${scope.from_domain} in the ${scope.windowLabel}`
        : `No reports in the ${scope.windowLabel}` }),
      totals && Number(totals.reports)
        ? el('p', {}, [
            document.createTextNode(
              `This domain has ${num(totals.reports)} report`
              + `${Number(totals.reports) === 1 ? '' : 's'} on file, most `
              + `recently ${dayFull(totals.last_seen)}. `),
            el('button', {
              type: 'button', class: 'link', text: 'Show everything',
              on: { click: () => rerender({ window: 'all' }) },
            }),
            document.createTextNode('.'),
          ])
        : el('p', { text: 'Widen the window, or pick another domain. Reports '
            + 'arrive once a receiver has mail to report on, usually daily.' }),
    ]));
    return;
  }

  replace(mount, [
    el('section', { class: 'band band-hero' }, [
      verdict(current),
      alignBand(current),
      alignLegend(current),
    ]),
    ledger(current, summary.previous, windowDays),
    rows.length > 1 ? volume(rows, scope) : null,
  ]);
};

// Reports: the audit trail. One row per aggregate report received.

import { el, replace, api, num, pct, isoStamp } from './core.js';
import { table, nothingInWindow } from './table.js';
import * as ptr from './ptr.js';

const PAGE = 50;

// A store also queues the reports this host is preparing to send, which are
// about other people's domains. The other views leave those out; here, where
// the list is an audit trail, they are shown by default and can be separated.
const KINDS = [
  { key: 'all',      label: 'All reports' },
  { key: 'received', label: 'Received about your domains' },
  { key: 'outgoing', label: 'Queued to send by this host' },
];

const verdictCell = (value) => value
  ? el('span', { class: `verdict-cell verdict-${String(value).toLowerCase()}`,
      text: value })
  : document.createTextNode('—');

// The report's own From domain leads, since that is what it is a report about
// and what the list sorts on. The recipient domains come from its records and
// are the part you would otherwise expand to find.
const domainsCell = (row) => {
  const summary = row.summary || {};
  const from = summary.header_from && summary.header_from.length
    ? summary.header_from : [row.from_domain].filter(Boolean);

  return el('span', { class: 'stack' }, [
    el('span', {}, [
      el('span', { class: 'key', text: 'From' }),
      el('span', { class: 'val', text: domainList(from) }),
    ]),
    el('span', {}, [
      el('span', { class: 'key', text: 'To' }),
      el('span', { class: 'val', text: domainList(summary.envelope_to || []) }),
    ]),
  ]);
};

const domainList = (domains) => {
  if (!domains.length) return '—';
  if (domains.length <= 2) return domains.join(', ');
  return `${domains.slice(0, 2).join(', ')} +${domains.length - 2}`;
};

const windowCell = (row) => el('span', { class: 'stack' }, [
  el('span', {}, el('span', { class: 'val', text: isoStamp(row.begin) })),
  el('span', {}, el('span', { class: 'val', text: isoStamp(row.end) })),
]);

// What the report concluded, as three indicators rather than a bar: whether
// DMARC passed, and which of the two mechanisms carried it. A report covering
// many messages is rarely all one thing, so the colour is mixed by the share
// that passed and the whole ramp runs red, through the amber already used for
// SPF-only, to green.
const RATES = [
  { label: 'aligned',
    of: (s) => (Number(s.messages) || 0) - (Number(s.aligned_none) || 0),
    describe: 'passed DMARC' },
  { label: 'SPF',
    of: (s) => (Number(s.aligned_both) || 0) + (Number(s.aligned_spf) || 0),
    describe: 'aligned and passed SPF' },
  { label: 'DKIM',
    of: (s) => (Number(s.aligned_both) || 0) + (Number(s.aligned_dkim) || 0),
    describe: 'aligned and passed DKIM' },
];

const hue = (rate) => (rate >= 0.5
  ? `color-mix(in oklab, var(--v-both) ${(rate - 0.5) * 200}%, var(--v-spf))`
  : `color-mix(in oklab, var(--v-spf) ${rate * 200}%, var(--v-none))`);

// Colour alone must not carry the verdict, so the extremes are also marked.
const weight = (rate) => (rate === 0 ? ' none' : rate < 1 ? ' partial' : '');

// Small reports get a dot per message, which says 4 of 5 exactly rather than
// approximately. Past this many the dots stop being countable and the hue and
// underline carry it instead.
const MAX_DOTS = 12;

const dots = (passed, failed) => {
  const marks = [];
  for (let i = 0; i < passed; i++) marks.push(el('i', { class: 'dot on' }));
  for (let i = 0; i < failed; i++) marks.push(el('i', { class: 'dot off' }));
  return el('span', { class: 'dots', 'aria-hidden': 'true' }, marks);
};

const outcomeCell = (row) => {
  const summary = row.summary;
  if (!summary || !summary.messages) {
    return el('span', { class: 'summary-text', text: 'no messages' });
  }
  const total = Number(summary.messages) || 0;
  const countable = total <= MAX_DOTS;

  return el('span', { class: 'verdict-words' }, RATES.map((entry) => {
    const passed = Math.max(0, Math.min(total, entry.of(summary)));
    const rate = total ? passed / total : 0;
    const label = `${num(passed)} of ${num(total)} message`
      + `${total === 1 ? '' : 's'} ${entry.describe} (${pct(passed, total)})`;

    return el('span', { class: 'verdict-item', title: label }, [
      el('span', {
        // With a dot per message the underline would repeat what the dots
        // already show.
        class: `verdict-word${countable ? '' : weight(rate)}`,
        style: `color: ${hue(rate)}`,
        text: entry.label,
      }),
      countable ? dots(passed, total - passed) : null,
      el('span', { class: 'sr-only', text: label }),
    ]);
  }));
};

const rowsFor = async (report) => {
  const data = await api.reportRows(report.rid);
  const rows = data.data || [];

  if (!rows.length) {
    return el('p', { class: 'note', text: 'This report contained no rows.' });
  }

  const columns = [
    { label: 'Source', render: (row) => el('span', {}, [
        el('span', { class: 'ip', text: row.source_ip || '—' }),
        row.source_ip ? ptr.hostSlot(row.source_ip) : null,
      ]) },
    { label: 'Header From',
      render: (row) => document.createTextNode(row.header_from || '—') },
    { label: 'Messages', align: 'num',
      render: (row) => document.createTextNode(num(row.count)) },
    { label: 'Disposition', render: (row) => verdictCell(row.disposition) },
    { label: 'DKIM', render: (row) => verdictCell(row.dkim) },
    { label: 'SPF', render: (row) => verdictCell(row.spf) },
    { label: 'Envelope To',
      render: (row) => document.createTextNode(row.envelope_to || '—') },
    { label: 'Envelope From',
      render: (row) => document.createTextNode(row.envelope_from || '—') },
    // Receivers explain overrides here; the old viewer fetched these and never
    // showed them.
    { label: 'Reasons', render: (row) => document.createTextNode(
        (row.reasons || []).map((r) => r.comment
          ? `${r.type}: ${r.comment}` : r.type).join(', ') || '—') },
  ];

  const detail = el('div', { class: 'detail-grid' },
    el('div', {}, [
      el('h4', { text: 'Report rows' }),
      el('table', {}, [
        el('thead', {}, el('tr', {}, columns.map((column) =>
          el('th', { class: column.align === 'num' ? 'num' : '',
            text: column.label })))),
        el('tbody', {}, rows.map((row) => el('tr', {}, columns.map((column) =>
          el('td', { class: column.align === 'num' ? 'num' : '' },
            column.render(row)))))),
      ]),
    ]));

  ptr.resolveWithin(detail);
  return detail;
};

export const render = async (mount, scope, state, rerender) => {
  const start = Number(state.start) || 0;
  const kind = KINDS.some((k) => k.key === state.reports)
    ? state.reports : 'all';
  const sort = {
    col: state.sort || 'r.id',
    dir: state.dir === 'asc' ? 'asc' : 'desc',
  };

  const data = await api.reports({
    start,
    length: PAGE,
    sort_col: sort.col,
    sort_dir: sort.dir,
    search_domain: scope.from_domain || null,
    since: scope.since || null,
    until: scope.until,
    reports: kind,
    summary: 1,
  });

  const rows = data.data || [];
  const total = Number(data.recordsFiltered ?? data.recordsTotal) || 0;

  const parts = table({
    caption: 'Aggregate reports received',
    rows,
    empty: nothingInWindow({ scope, noun: 'reports', rerender }),
    sort,
    onSort: (next) => rerender({ sort: next.col, dir: next.dir, start: 0 }),
    columns: [
      { label: 'Id', align: 'num', sortKey: 'r.id',
        render: (row) => el('span', { class: 'mono', title: row.uuid || '',
          text: row.rid }) },
      { label: 'Reporter', sortKey: 'a.org_name',
        render: (row) => document.createTextNode(row.author || '—') },
      { label: 'Domains', sortKey: 'fd.domain', render: domainsCell,
        title: 'From is the domain the report is about; To comes from its '
             + 'records. Sorts on the report\u2019s own From domain.' },
      { label: 'Window', sortKey: 'r.begin', render: windowCell },
      { label: 'Messages', align: 'num',
        render: (row) => document.createTextNode(
          row.summary ? num(row.summary.messages) : '—') },
      { label: 'Outcome', render: outcomeCell },
    ],
    expand: rowsFor,
    page: { start, length: PAGE, total, unit: 'reports',
            onPage: (next) => rerender({ start: next }) },
  });

  const kindGroup = el('div', { class: 'control-group' }, [
    el('label', {}, [
      el('span', { text: 'Show' }),
      el('select', {
        'aria-label': 'Which reports to list',
        title: 'The domain picker lists the domains others report on, so it '
             + 'does not name the domains in this host\u2019s own queue.',
        on: { change: (event) =>
          rerender({ reports: event.target.value, start: 0 }) },
      }, KINDS.map((option) => {
        const node = el('option', { value: option.key, text: option.label });
        if (option.key === kind) node.selected = true;
        return node;
      })),
    ]),
  ]);

  replace(mount, [
    el('div', { class: 'controls' }, [
      kindGroup,
      ptr.controls(() => ptr.resolveWithin(mount)),
    ]),
    ...parts,
    el('p', { class: 'note', style: 'padding: 0 1.25rem 1rem',
      text: 'Reports are listed by the day their window begins. Window times '
          + 'come from the reporting receiver, in its own clock.' }),
  ]);
};

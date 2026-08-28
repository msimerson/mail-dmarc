// Sources: one row per sending IP, ranked by the mail it is breaking.

import { el, replace, api, num, pct, stamp } from './core.js';
import { rowBand } from './band.js';
import { table, nothingInWindow } from './table.js';
import * as ptr from './ptr.js';

const PAGE = 50;

const BUCKET_NOTE = {
  aligned:         'Everything from here authenticates.',
  forwarded:       'Failures are accounted for by forwarding or mailing lists.',
  failing:         'Failing mail with no forwarding explanation.',
  broken:          'Presented authentication that did not pass or align.',
  unauthenticated: 'Presented no authentication at all.',
};

const tag = (bucket) => el('span', {
  class: `tag tag-${bucket}`, text: bucket, title: BUCKET_NOTE[bucket] || '',
});

const verdictCell = (value) => value
  ? el('span', { class: `verdict-cell verdict-${String(value).toLowerCase()}`,
      text: value })
  : document.createTextNode('—');

const authTable = (caption, rows, columns) => {
  if (!rows || !rows.length) {
    return el('div', {}, [
      el('h4', { text: caption }),
      el('p', { class: 'note', text: 'None presented.' }),
    ]);
  }
  return el('div', {}, [
    el('h4', { text: caption }),
    el('table', {}, [
      el('thead', {}, el('tr', {}, columns.map((column) =>
        el('th', { class: column.align === 'num' ? 'num' : '', text: column.label })))),
      el('tbody', {}, rows.map((row) => el('tr', {}, columns.map((column) =>
        el('td', { class: column.align === 'num' ? 'num' : '' },
          column.render(row)))))),
    ]),
  ]);
};

const detail = async (source, scope) => {
  const data = await api.source({ ...scope, source_ip: source.source_ip });

  const grid = el('div', { class: 'detail-grid' }, [
    el('div', {}, [
      el('h4', { text: 'What this source is' }),
      el('p', { class: 'note' }, [
        tag(data.bucket),
        document.createTextNode(` ${BUCKET_NOTE[data.bucket] || ''}`),
      ]),
      data.bucket !== source.bucket
        ? el('p', { class: 'note',
            text: `Ranked as ${source.bucket} in the list above; the `
                + 'authentication it presented narrows that down.' })
        : null,
      source.reasons && source.reasons.length
        ? el('p', { class: 'note', text: `Cited for the failures: ${source.reasons
            .map((r) => (r.comment ? `${r.type} “${r.comment}”` : r.type)
              + ` (${num(r.messages)})`).join(', ')}` })
        : null,
      el('p', { class: 'note',
        text: `Seen by ${num(source.reporters)} reporter${source.reporters === 1 ? '' : 's'}, `
            + `${stamp(source.first_seen)} to ${stamp(source.last_seen)}.` }),
    ]),

    authTable('DKIM presented', data.dkim, [
      { label: 'd=', render: (r) => document.createTextNode(r.domain || '—') },
      { label: 's=', render: (r) => document.createTextNode(r.selector || '—') },
      { label: 'Result', render: (r) => verdictCell(r.result) },
      { label: 'Messages', align: 'num',
        render: (r) => document.createTextNode(num(r.messages)) },
    ]),

    authTable('SPF presented', data.spf, [
      { label: 'Domain', render: (r) => document.createTextNode(r.domain || '—') },
      { label: 'Scope', render: (r) => document.createTextNode(r.scope || '—') },
      { label: 'Result', render: (r) => verdictCell(r.result) },
      { label: 'Messages', align: 'num',
        render: (r) => document.createTextNode(num(r.messages)) },
    ]),

    authTable('Header From, as evaluated', data.records, [
      { label: 'From', render: (r) => document.createTextNode(r.header_from || '—') },
      { label: 'Disposition', render: (r) => verdictCell(r.disposition) },
      { label: 'DKIM', render: (r) => verdictCell(r.dkim) },
      { label: 'SPF', render: (r) => verdictCell(r.spf) },
      { label: 'Messages', align: 'num',
        render: (r) => document.createTextNode(num(r.messages)) },
    ]),
  ]);

  return grid;
};

// The store ranks by failing volume or by total volume; nothing else. Offering
// a click-to-sort on every column would imply an ordering the store cannot
// actually produce across pages.
const RANKS = [
  { key: '', label: 'most failures first' },
  { key: 'messages', label: 'most mail first' },
];

export const render = async (mount, scope, state, rerender, restate) => {
  const start = Number(state.start) || 0;
  const rank = state.rank === 'messages' ? 'messages' : '';

  const data = await api.sources({ ...scope, start, length: PAGE,
    sort_col: rank || null });
  const rows = data.data || [];
  const total = Number(data.recordsTotal) || 0;

  // Share is of the whole window, not of this page.
  const windowTotal = Number(data.messagesTotal) || 0;

  const rankGroup = el('div', { class: 'control-group' }, [
    el('label', {}, [
      el('span', { text: 'Rank by' }),
      el('select', {
        'aria-label': 'Ranking',
        on: { change: (event) => rerender({ rank: event.target.value, start: 0 }) },
      }, RANKS.map((option) => {
        const node = el('option', { value: option.key, text: option.label });
        if (option.key === rank) node.selected = true;
        return node;
      })),
    ]),
    el('span', { class: 'control-note',
      text: `${num(total)} source${total === 1 ? '' : 's'} in this window.` }),
  ]);

  const parts = table({
    caption: 'Sending sources',
    rows,
    empty: nothingInWindow({ scope, noun: 'sending sources', rerender }),
    columns: [
      { label: 'Source', cellClass: 'ip', render: (row) => el('span', {}, [
          el('span', { class: 'ip', text: row.source_ip }),
          ptr.hostSlot(row.source_ip),
        ]) },
      { label: 'Assessment', render: (row) => tag(row.bucket) },
      { label: 'Messages', align: 'num',
        render: (row) => document.createTextNode(num(row.messages)) },
      { label: 'Share', align: 'num',
        render: (row) => document.createTextNode(pct(row.messages, windowTotal)) },
      { label: 'Failing', align: 'num',
        title: 'Messages that authenticated neither way',
        render: (row) => el('span', {
          class: Number(row.aligned_none) ? 'verdict-fail' : '',
          text: num(row.aligned_none) }) },
      { label: 'Alignment', render: (row) => rowBand(row) },
      { label: 'Reporters', align: 'num',
        render: (row) => document.createTextNode(num(row.reporters)) },
      { label: 'Last seen', render: (row) =>
          document.createTextNode(stamp(row.last_seen)) },
    ],
    expand: (row) => detail(row, scope),
    // A source's detail is linkable, so an operator can paste one offending
    // sender straight into a ticket.
    rowKey: (row) => row.source_ip,
    openKey: state.open || null,
    onOpen: (key) => restate({ open: key || null }),
    page: { start, length: PAGE, total, unit: 'sources',
            onPage: (next) => rerender({ start: next }) },
  });

  replace(mount, [
    el('div', { class: 'controls' }, [
      rankGroup,
      ptr.controls(() => ptr.resolveWithin(mount)),
    ]),
    ...parts,
  ]);
  ptr.resolveWithin(mount);
};

// A sortable, pageable table with expandable detail rows.
//
// Sorting is always delegated to the caller, which forwards it to the report
// store. Sorting a single page in the browser would silently reorder 100 rows
// out of thousands and read as if it had ordered the whole set.

import { el, replace, num, dayFull } from './core.js';

export const table = ({ caption, columns, rows, empty, sort, onSort,
                        expand, page, rowKey, openKey, onOpen }) => {
  const head = el('tr', {}, [
    expand ? el('th', { 'aria-label': 'Expand' }) : null,
    ...columns.map((column) => {
      const clickable = Boolean(column.sortKey && onSort);
      const sorted = sort && column.sortKey && sort.col === column.sortKey;
      const arrow = sorted ? (sort.dir === 'asc' ? ' ↑' : ' ↓') : ' ↕';

      // The control is a button so it can be reached and fired from the
      // keyboard; aria-sort stays on the column header where readers expect it.
      const label = clickable
        ? el('button', {
            type: 'button',
            class: 'th-sort',
            on: { click: () => onSort({ col: column.sortKey,
                    dir: sorted && sort.dir === 'desc' ? 'asc' : 'desc' }) },
          }, [
            document.createTextNode(column.label),
            el('span', { class: 'arrow', text: arrow }),
          ])
        : document.createTextNode(column.label);

      return el('th', {
        class: [column.align === 'num' ? 'num' : '',
                clickable ? 'sortable' : ''].join(' ').trim(),
        'aria-sort': sorted
          ? (sort.dir === 'asc' ? 'ascending' : 'descending') : null,
        title: column.title,
      }, label);
    }),
  ]);

  const width = columns.length + (expand ? 1 : 0);
  const body = el('tbody');

  if (!rows.length) {
    body.append(el('tr', {}, el('td', { colspan: width, class: 'empty-cell' },
      typeof empty === 'string' || !empty
        ? el('p', { class: 'note', text: empty || 'Nothing to show.' })
        : empty)));
  }

  for (const row of rows) {
    const cells = columns.map((column) => el('td', {
      class: column.align === 'num' ? 'num' : column.cellClass,
    }, column.render ? column.render(row) : document.createTextNode(
      column.value ? column.value(row) : (row[column.key] ?? ''))));

    let toggle = null;
    let detail = null;

    if (expand) {
      toggle = el('button', {
        type: 'button', class: 'expander', text: '▶',
        'aria-expanded': 'false',
        'aria-label': 'Show detail',
      });
      cells.unshift(el('td', {}, toggle));
    }

    const tr = el('tr', {}, cells);
    body.append(tr);

    if (!expand) continue;

    const key = rowKey ? rowKey(row) : null;

    const close = () => {
      detail.remove();
      detail = null;
      toggle.textContent = '▶';
      toggle.setAttribute('aria-expanded', 'false');
    };

    const open = async () => {
      toggle.textContent = '▼';
      toggle.setAttribute('aria-expanded', 'true');
      detail = el('tr', { class: 'detail' },
        el('td', { colspan: width }, el('p', { class: 'note', text: 'Loading…' })));
      tr.after(detail);
      try {
        replace(detail.firstChild, await expand(row));
      } catch (error) {
        replace(detail.firstChild,
          el('p', { class: 'note', text: `Could not load detail: ${error.message}` }));
      }
    };

    toggle.addEventListener('click', () => {
      const opening = !detail;
      if (opening) open();
      else close();
      // Only the view knows whether an open row belongs in the URL.
      if (onOpen) onOpen(opening ? key : null);
    });

    if (key !== null && key === openKey) open();
  }

  const parts = [
    el('div', { class: 'table-wrap' },
      el('table', {}, [
        caption ? el('caption', { text: caption }) : null,
        el('thead', {}, head),
        body,
      ])),
  ];

  if (page) parts.push(pager(page));
  return parts;
};

const pager = ({ start, length, total, onPage, unit = 'rows' }) => {
  const first = total ? start + 1 : 0;
  const last = Math.min(start + length, total);
  return el('div', { class: 'paging' }, [
    el('button', {
      type: 'button', class: 'btn', text: '← Previous',
      disabled: start <= 0,
      on: { click: () => onPage(Math.max(0, start - length)) },
    }),
    el('button', {
      type: 'button', class: 'btn', text: 'Next →',
      disabled: last >= total,
      on: { click: () => onPage(start + length) },
    }),
    el('span', { class: 'count',
      text: total ? `${num(first)}–${num(last)} of ${num(total)} ${unit}`
                  : `no ${unit}` }),
  ]);
};

// A view that finds nothing in the chosen window should say which of the two
// reasons applies, and offer the way out rather than describing it.
export const nothingInWindow = ({ scope, noun, rerender }) => {
  const totals = scope.domainTotals;
  const lines = [];

  if (scope.from_domain) {
    lines.push(el('p', { class: 'empty-lead',
      text: `No ${noun} for ${scope.from_domain} in the ${scope.windowLabel}.` }));
    if (totals && Number(totals.reports)) {
      lines.push(el('p', { class: 'note' }, [
        document.createTextNode(
          `This domain has ${num(totals.reports)} report`
          + `${Number(totals.reports) === 1 ? '' : 's'} on file, most recently `
          + `${dayFull(totals.last_seen)}. `),
        el('button', {
          type: 'button', class: 'link',
          text: 'Show everything',
          on: { click: () => rerender({ window: 'all', start: null }) },
        }),
        document.createTextNode('.'),
      ]));
    }
  } else {
    lines.push(el('p', { class: 'empty-lead',
      text: `No ${noun} in the ${scope.windowLabel}.` }));
    lines.push(el('p', { class: 'note' }, [
      document.createTextNode('Widen the window, or '),
      el('button', {
        type: 'button', class: 'link',
        text: 'show everything',
        on: { click: () => rerender({ window: 'all', start: null }) },
      }),
      document.createTextNode('.'),
    ]));
  }

  return el('div', {}, lines);
};

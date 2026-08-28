// A filtering picker for lists too long to scroll: a store can hold thousands
// of domains, and a plain select makes finding one a scrolling exercise.

import { el, clear } from './core.js';

const VISIBLE = 60;

export const combobox = ({ id, placeholder, onSelect }) => {
  const input = el('input', {
    type: 'text',
    role: 'combobox',
    id,
    class: 'combo-input',
    placeholder,
    autocomplete: 'off',
    spellcheck: 'false',
    'aria-expanded': 'false',
    'aria-autocomplete': 'list',
    'aria-controls': `${id}-list`,
  });
  const list = el('ul', { id: `${id}-list`, class: 'combo-list', role: 'listbox',
    hidden: true });
  const node = el('div', { class: 'combo' }, [input, list]);

  // items: [{ value, label, note }]. The empty value is the "everything" row.
  let items = [];
  let matches = [];
  let active = -1;
  let committed = { value: '', label: placeholder };

  const close = () => {
    list.hidden = true;
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
    active = -1;
  };

  const revert = () => {
    input.value = committed.value ? committed.label : '';
    close();
  };

  const commit = (item) => {
    committed = item;
    input.value = item.value ? item.label : '';
    close();
    onSelect(item.value);
  };

  const highlight = (index) => {
    active = index;
    for (const [i, option] of [...list.children].entries()) {
      const on = i === index;
      option.classList.toggle('active', on);
      if (on) {
        input.setAttribute('aria-activedescendant', option.id);
        option.scrollIntoView({ block: 'nearest' });
      }
    }
  };

  // Domains are dotted labels, so a bare substring match buries the obvious
  // answer: typing "art" should offer artfulmail.net and theartfarm.com before
  // earthlink.net. Rank by where the match lands, keeping the existing order
  // inside each rank.
  const rank = (label, needle) => {
    if (label.startsWith(needle)) return 0;
    if (label.includes(`.${needle}`)) return 1;
    const at = label.indexOf(needle);
    if (at > 0 && !/[a-z0-9]/.test(label[at - 1])) return 1;
    return 2;
  };

  const render = (term) => {
    const needle = term.trim().toLowerCase();
    matches = items;

    if (needle) {
      matches = items
        .filter((item) => item.value && item.label.toLowerCase().includes(needle))
        .map((item, index) => ({
          item,
          index,
          rank: rank(item.label.toLowerCase(), needle),
        }))
        .sort((a, b) => a.rank - b.rank || a.index - b.index)
        .map((scored) => scored.item);
    }

    clear(list);

    if (!matches.length) {
      list.append(el('li', { class: 'combo-empty',
        text: `Nothing matches “${term.trim()}”` }));
      list.hidden = false;
      input.setAttribute('aria-expanded', 'true');
      active = -1;
      return;
    }

    const shown = matches.slice(0, VISIBLE);
    shown.forEach((item, index) => {
      const option = el('li', {
        id: `${id}-opt-${index}`,
        role: 'option',
        class: 'combo-option',
        'aria-selected': item.value === committed.value ? 'true' : 'false',
      }, [
        el('span', { text: item.label }),
        item.note ? el('span', { class: 'combo-note', text: item.note }) : null,
      ]);
      // mousedown, because blur would close the list before a click lands
      option.addEventListener('mousedown', (event) => {
        event.preventDefault();
        commit(item);
      });
      list.append(option);
    });

    if (matches.length > shown.length) {
      list.append(el('li', { class: 'combo-empty',
        text: `${matches.length - shown.length} more match. Keep typing.` }));
    }

    list.hidden = false;
    input.setAttribute('aria-expanded', 'true');
    highlight(matches.length ? 0 : -1);
  };

  input.addEventListener('focus', () => { input.select(); render(''); });
  input.addEventListener('input', () => render(input.value));
  input.addEventListener('blur', revert);

  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (list.hidden) { render(input.value); return; }
      const last = Math.min(matches.length, VISIBLE) - 1;
      if (last < 0) return;
      const step = event.key === 'ArrowDown' ? 1 : -1;
      highlight(active < 0 ? 0 : Math.min(last, Math.max(0, active + step)));
      return;
    }
    if (event.key === 'Enter') {
      if (list.hidden || active < 0) return;
      event.preventDefault();
      commit(matches[active]);
      return;
    }
    if (event.key === 'Escape') {
      event.preventDefault();
      revert();
    }
  });

  return {
    node,
    setItems(next) {
      items = next;
      const found = items.find((item) => item.value === committed.value);
      if (found) committed = found;
      if (!list.hidden) render(input.value);
      else input.value = committed.value ? committed.label : '';
    },
    setValue(value) {
      const found = items.find((item) => item.value === value)
        || { value: value || '', label: value || placeholder };
      committed = found;
      input.value = found.value ? found.label : '';
    },
    disable(reason) {
      input.disabled = true;
      input.placeholder = reason;
    },
  };
};

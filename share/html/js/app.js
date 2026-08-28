// Routing, shared scope controls, and boot.
//
// All view state lives in the location hash, so any view of the data is a
// link an operator can paste into a ticket.

import { el, replace, api, num, nowDay, days, dayFull, dayOrYear } from './core.js';
import { combobox } from './combo.js';
import * as ptr from './ptr.js';
import * as overview from './overview.js';
import * as sources from './sources.js';
import * as reports from './reports.js';

const VIEWS = { overview, sources, reports };

const WINDOWS = [
  { key: '7',   label: 'Last 7 days',   days: 7 },
  { key: '30',  label: 'Last 30 days',  days: 30 },
  { key: '90',  label: 'Last 90 days',  days: 90 },
  { key: '365', label: 'Last year',     days: 365 },
  { key: 'all', label: 'Everything',    days: null },
];

const THEME_KEY = 'dmarc.theme';

const mount = document.getElementById('view');
const windowSelect = document.getElementById('scope-window');

let domainPicker;
let domainInfo = new Map();

const parseHash = () => {
  const raw = location.hash.replace(/^#\/?/, '');
  const [name, query] = raw.split('?');
  const state = Object.fromEntries(new URLSearchParams(query || ''));
  return { view: VIEWS[name] ? name : 'overview', state };
};

const writeHash = (view, state) => {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(state)) {
    if (value === null || value === undefined || value === '') continue;
    query.set(key, value);
  }
  const next = `#/${view}${query.toString() ? `?${query}` : ''}`;
  if (location.hash !== next) location.hash = next;
  else route();
};

const DEFAULT_WINDOW = '30';

const windowPreset = (state) => WINDOWS.find((w) => w.key === state.window)
  || WINDOWS.find((w) => w.key === DEFAULT_WINDOW);

// The window and domain are scope, shared by every view; everything else is
// the view's own business.
const scopeFrom = (state) => {
  const preset = windowPreset(state);
  const until = nowDay() + days(1);
  return {
    from_domain: state.domain || null,
    since: preset.days === null ? 0 : until - days(preset.days),
    until,
    windowLabel: preset.label.toLowerCase(),
    // What the store holds for this domain regardless of window. A view that
    // finds nothing needs it to say whether the domain is quiet or the window
    // is simply too narrow.
    domainTotals: state.domain ? domainInfo.get(state.domain) || null : null,
  };
};

const describe = (scope) => (scope.since
  ? `${dayFull(scope.since)} to ${dayFull(scope.until - days(1))}`
  : 'all reports on file');

let routing = false;
let queued  = false;

const route = async () => {
  if (routing) { queued = true; return; }
  routing = true;
  try {
    do {
      queued = false;
      await renderCurrent();
    } while (queued);
  } finally {
    routing = false;
  }
};

const renderCurrent = async () => {
  const { view, state } = parseHash();
  const scope = scopeFrom(state);

  for (const link of document.querySelectorAll('#views a')) {
    const isCurrent = link.hash === `#/${view}`;
    if (isCurrent) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }

  domainPicker.setValue(state.domain || '');
  windowSelect.value = windowPreset(state).key;
  windowSelect.title = describe(scope);

  replace(mount, el('div', { class: 'loading', text: 'Reading reports…' }));

  const rerender = (patch) => writeHash(view, { ...state, ...patch });

  // Records view state in the URL without re-rendering, so an expanded row
  // stays open while its link stays copyable.
  const restate = (patch) => {
    const next = { ...state, ...patch };
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(next)) {
      if (value === null || value === undefined || value === '') continue;
      query.set(key, value);
    }
    history.replaceState(null, '',
      `#/${view}${query.toString() ? `?${query}` : ''}`);
  };

  try {
    await VIEWS[view].render(mount, scope, state, rerender, restate);
  } catch (error) {
    replace(mount, el('div', { class: 'failed' }, [
      el('h2', { text: 'Could not read the reports' }),
      el('p', {}, el('code', { text: error.message })),
      el('p', { class: 'note',
        text: 'The report store may be unreachable, or this build of '
            + 'dmarc_httpd may predate the aggregate views.' }),
    ]));
  }
};

const initScope = async () => {
  for (const option of WINDOWS) {
    windowSelect.append(el('option', { value: option.key, text: option.label }));
  }
  windowSelect.value = DEFAULT_WINDOW;

  const rescope = (patch) => {
    const { view, state } = parseHash();
    writeHash(view, { ...state, ...patch, start: null });
  };

  windowSelect.addEventListener('change',
    () => rescope({ window: windowSelect.value }));

  domainPicker = combobox({
    id: 'scope-domain',
    placeholder: 'All domains',
    onSelect: (domain) => rescope({ domain: domain || null }),
  });
  document.getElementById('scope-domain-mount').append(domainPicker.node);

  try {
    const { data } = await api.domains();
    domainInfo = new Map((data || []).map((row) => [row.domain, row]));
    domainPicker.setItems([
      { value: '', label: 'All domains' },
      // Nearly every domain in a long lived store was last heard from outside
      // the default window, so the count alone would promise reports the view
      // then cannot show.
      ...(data || []).map((row) => ({
        value: row.domain,
        label: row.domain,
        note: `${num(row.reports)} · last ${dayOrYear(row.last_seen, true)}`,
      })),
    ]);
  } catch {
    // The picker is a convenience; typing a domain into the URL still works.
    domainPicker.disable('domain list unavailable');
  }
  domainPicker.setValue(parseHash().state.domain || '');
};

const initTheme = () => {
  const button = document.getElementById('theme');
  let stored;
  try { stored = localStorage.getItem(THEME_KEY); } catch { stored = null; }
  if (stored) document.documentElement.dataset.theme = stored;

  button.addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme === 'dark'
      || (!document.documentElement.dataset.theme
          && matchMedia('(prefers-color-scheme: dark)').matches);
    const next = dark ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem(THEME_KEY, next); } catch { /* private browsing */ }
  });
};

ptr.load();
initTheme();
addEventListener('hashchange', route);
initScope().then(route);

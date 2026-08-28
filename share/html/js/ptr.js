// Reverse DNS for source IPs.
//
// Resolved in the browser, not by dmarc_httpd: report rows are full of IPs
// with no PTR record, and blocking the server on those lookups would stall it
// for every viewer. Off by default because it hands the source IPs of your
// reports to a third party resolver.

import { el } from './core.js';

const PRESETS = [
  { label: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { label: 'Google',     url: 'https://dns.google/resolve' },
];
const DEFAULT_URL   = PRESETS[0].url;
const TIMEOUT_MS    = 3000;
const CONCURRENCY   = 5;
const ENABLED_KEY   = 'dmarc.ptr.enabled';
const URL_KEY       = 'dmarc.ptr.doh_url';

let enabled = false;
let dohUrl  = DEFAULT_URL;

const storeGet = (key) => {
  try { return localStorage.getItem(key); } catch { return null; }
};
const storeSet = (key, value) => {
  try { localStorage.setItem(key, value); } catch { /* private browsing */ }
};

const expandIPv6 = (ip) => {
  if (!ip.includes(':') || !/^[0-9A-Fa-f:.]+$/.test(ip)) return null;

  let rest = ip;
  const v4 = rest.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4) {
    const octets = v4[1].split('.').map(Number);
    if (octets.some((o) => o > 255)) return null;
    rest = rest.slice(0, v4.index)
         + ((octets[0] << 8) | octets[1]).toString(16) + ':'
         + ((octets[2] << 8) | octets[3]).toString(16);
  }

  const halves = rest.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return null;

  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8) return null;

  let nibbles = '';
  for (const group of groups) {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(group)) return null;
    nibbles += group.toLowerCase().padStart(4, '0');
  }
  return nibbles;
};

const reverseName = (ip) => {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) {
    if (ip.split('.').some((o) => Number(o) > 255)) return null;
    return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  }
  const nibbles = expandIPv6(ip);
  return nibbles ? `${nibbles.split('').reverse().join('.')}.ip6.arpa` : null;
};

const dohQuery = (base, name) => {
  let url;
  try { url = new URL(base); } catch { return null; }
  if (!/^https?:$/.test(url.protocol)) return null;
  url.searchParams.set('name', name);
  url.searchParams.set('type', 'PTR');
  return url.href;
};

const cache = new Map();
const queue = [];
let active = 0;

// Answers in flight when the resolver changes belong to the old resolver.
let generation = 0;

const pump = () => {
  while (active < CONCURRENCY && queue.length) {
    active++;
    queue.shift()().then(() => { active--; pump(); });
  }
};

const lookup = (ip) => {
  if (!enabled) return Promise.resolve('');
  if (cache.has(ip)) return cache.get(ip);

  const name = reverseName(ip);
  const query = name && dohQuery(dohUrl, name);
  const era = generation;

  const result = !query ? Promise.resolve('') : new Promise((resolve) => {
    queue.push(() => {
      // The queue outlives an opt-out or a resolver change, and a job dequeued
      // afterwards would disclose a source IP the user just withdrew.
      if (!enabled || era !== generation) {
        resolve('');
        return Promise.resolve();
      }
      const control = new AbortController();
      const timer = setTimeout(() => control.abort(), TIMEOUT_MS);
      return fetch(query, {
          headers: { accept: 'application/dns-json' },
          signal: control.signal,
        })
        .then((r) => (r.ok ? r.json() : null))
        .then((json) => {
          const answer = (json?.Answer || []).find((a) => a.type === 12);
          resolve(answer ? String(answer.data).replace(/\.$/, '') : '');
        })
        .catch(() => resolve(''))
        .finally(() => clearTimeout(timer));
    });
    pump();
  });

  cache.set(ip, result);
  return result;
};

// A PTR record is controlled by the operator of the sending IP, so the answer
// is set as text, never parsed as markup.
export const resolveWithin = (container) => {
  if (!enabled) return;
  const era = generation;
  for (const node of container.querySelectorAll('.ptr-host[data-ip]')) {
    lookup(node.dataset.ip).then((host) => {
      if (host && enabled && era === generation) node.textContent = host;
    });
  }
};

export const hostSlot = (ip) => el('span', { class: 'ptr-host', dataset: { ip } });

// Every cached promise belongs to the generation that created it, so the two
// are invalidated together; a survivor would resolve empty at the dispatch
// check above and leave its row permanently blank.
const clearAll = () => {
  generation++;
  cache.clear();
  for (const node of document.querySelectorAll('.ptr-host')) node.textContent = '';
};

// The probe asks for a fixed public name, so typing a resolver never discloses
// a source IP to it. It doubles as the CORS check: a resolver that answers
// JSON but omits the CORS headers fails here exactly as it would in use.
const PROBE_NAME = '8.8.8.8.in-addr.arpa';

let probe;

const cancelProbe = () => { probe?.abort(); probe = null; };

const probeResolver = (url) => {
  const query = dohQuery(url, PROBE_NAME);
  if (!query) return Promise.reject(new Error('enter an http(s) URL'));

  cancelProbe();
  probe = new AbortController();
  const control = probe;
  const timer = setTimeout(() => { control.timedOut = true; control.abort(); },
    TIMEOUT_MS);

  return fetch(query, {
      headers: { accept: 'application/dns-json' },
      signal: control.signal,
    })
    .then((r) => (r.ok ? r.json().catch(() => null)
                       : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((json) => {
      if (!json || typeof json.Status !== 'number') {
        throw new Error('not a JSON DoH resolver');
      }
      if (json.Status !== 0) throw new Error(`resolver returned status ${json.Status}`);
      return true;
    })
    // an abort means the timeout fired; a newer keystroke's abort is left alone
    .catch((error) => { throw control.timedOut ? new Error('timed out') : error; })
    .finally(() => clearTimeout(timer));
};

export const load = () => {
  enabled = storeGet(ENABLED_KEY) === '1';
  dohUrl  = storeGet(URL_KEY) || DEFAULT_URL;
};

export const isEnabled = () => enabled;

// Rebuilt per view render; onChange re-resolves whatever is on screen.
export const controls = (onChange) => {
  const check  = el('input', { type: 'checkbox', id: 'ptr-enable' });
  const preset = el('select', { id: 'doh-preset', 'aria-label': 'Resolver' });
  const custom = el('input', {
    type: 'text', id: 'doh-url', spellcheck: 'false', hidden: true,
    'aria-label': 'Custom DNS-over-HTTPS resolver URL',
  });
  const status = el('span', { class: 'doh-status', role: 'status' });

  check.checked = enabled;

  for (const item of PRESETS) {
    preset.append(el('option', { value: item.url, text: item.label }));
  }
  preset.append(el('option', { value: '', text: 'Other…' }));

  const matched = PRESETS.some((item) => item.url === dohUrl);
  preset.value = matched ? dohUrl : '';
  custom.value = dohUrl;
  custom.hidden = matched;

  const setStatus = (state, text) => {
    status.className = `doh-status ${state}`;
    status.textContent = text;
  };

  const setUrl = (url) => {
    const next = url || DEFAULT_URL;
    if (next === dohUrl) return dohUrl;
    dohUrl = next;
    storeSet(URL_KEY, dohUrl);
    clearAll();
    onChange();
    return dohUrl;
  };

  const checkCustom = () => {
    const value = custom.value.trim();
    setStatus('', 'checking…');
    probeResolver(value)
      .then(() => {
        if (custom.value.trim() !== value) return;
        setStatus('ok', '✓ responding');
        setUrl(value);
      })
      .catch((error) => {
        if (error.name === 'AbortError' || custom.value.trim() !== value) return;
        setStatus('bad', `✗ ${error.message === 'Failed to fetch'
          ? 'unreachable, or no CORS headers' : error.message}`);
      });
  };

  check.addEventListener('change', () => {
    enabled = check.checked;
    storeSet(ENABLED_KEY, enabled ? '1' : '');
    clearAll();
    onChange();
  });

  let timer;
  preset.addEventListener('change', () => {
    clearTimeout(timer);
    cancelProbe();
    setStatus('', '');
    if (preset.value) {
      custom.hidden = true;
      custom.value = setUrl(preset.value);
      return;
    }
    custom.hidden = false;
    custom.focus();
    checkCustom();
  });

  custom.addEventListener('input', () => {
    clearTimeout(timer);
    cancelProbe();    // the probe in flight is for text that is already stale
    setStatus('', 'checking…');
    timer = setTimeout(checkCustom, 500);
  });
  custom.addEventListener('change', () => {
    clearTimeout(timer);
    checkCustom();
  });

  if (!matched) checkCustom();

  return el('div', { class: 'control-group' }, [
    el('label', {}, [check, document.createTextNode(' Resolve hostnames')]),
    el('label', {}, [el('span', { text: 'via' }), preset]),
    custom,
    status,
    el('span', { class: 'control-note',
      text: 'Source IPs are sent to this resolver.' }),
  ]);
};

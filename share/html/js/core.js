// Element building, formatting and the JSON API client.

// Report data is written by whoever operated the sending or reporting system,
// so it is never interpolated into markup. Text always arrives through
// textContent and attributes through setAttribute, which makes escaping a
// property of the builder rather than something each caller has to remember.
export const el = (tag, opts = {}, children = []) => {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(opts)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'text') { node.textContent = value; continue; }
    if (key === 'class') { node.className = value; continue; }
    if (key === 'style') { node.setAttribute('style', value); continue; }
    if (key === 'on') {
      for (const [event, handler] of Object.entries(value)) {
        node.addEventListener(event, handler);
      }
      continue;
    }
    if (key === 'dataset') {
      for (const [prop, val] of Object.entries(value)) node.dataset[prop] = val;
      continue;
    }
    node.setAttribute(key, value === true ? '' : value);
  }

  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child);
  }
  return node;
};

export const clear = (node) => {
  while (node.firstChild) node.firstChild.remove();
  return node;
};

export const replace = (node, ...children) => {
  clear(node);
  for (const child of children.flat()) if (child) node.append(child);
  return node;
};

// ---------- formatting ----------

const NUM = new Intl.NumberFormat();

export const num = (n) => NUM.format(Number(n) || 0);

export const pct = (part, whole, places = 1) => {
  if (!whole) return '0%';
  const value = (Number(part) / Number(whole)) * 100;
  // A failure rate that rounds to 0.0% but is not zero misreads as "none
  // failed", which is the one conclusion this page must not get wrong.
  if (value > 0 && value < 0.1) return '<0.1%';
  if (value < 100 && value > 99.9) return '>99.9%';
  return `${value.toFixed(places)}%`;
};

const DAY = 86400;

export const day = (epoch) =>
  new Date(Number(epoch) * 1000).toLocaleDateString(undefined,
    { month: 'short', day: 'numeric' });

// Long spans need the year, or a 1970 bucket reads as a December in this one.
export const dayOrYear = (epoch, withYear) => (withYear
  ? new Date(Number(epoch) * 1000).toLocaleDateString(undefined,
      { year: 'numeric', month: 'short' })
  : day(epoch));

export const dayFull = (epoch) =>
  new Date(Number(epoch) * 1000).toLocaleDateString(undefined,
    { year: 'numeric', month: 'short', day: 'numeric' });

export const stamp = (epoch) =>
  new Date(Number(epoch) * 1000).toLocaleString(undefined,
    { year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit' });

// get_report returns begin/end as a bare local timestamp, not an epoch.
export const isoStamp = (value) => {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? String(value)
    : parsed.toLocaleString(undefined, { year: 'numeric', month: 'short',
        day: 'numeric', hour: '2-digit', minute: '2-digit' });
};

export const days = (n) => n * DAY;

export const nowDay = () => Math.floor(Date.now() / 1000 / DAY) * DAY;

// ---------- API ----------

class ApiError extends Error {}

const request = async (path, params = {}) => {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '') continue;
    query.set(key, value);
  }
  const url = query.toString() ? `${path}?${query}` : path;

  let response;
  try {
    response = await fetch(url, { headers: { accept: 'application/json' } });
  } catch {
    throw new ApiError('the report server is not responding');
  }
  if (!response.ok) throw new ApiError(`${response.status} ${response.statusText}`);

  let json;
  try {
    json = await response.json();
  } catch {
    throw new ApiError('the report server returned a malformed response');
  }
  // dmarc_httpd reports store failures in an err key with a 200 status.
  if (json && json.err) throw new ApiError(String(json.err));
  return json;
};

export const api = {
  domains:    ()      => request('/dmarc/json/domains'),
  summary:    (scope) => request('/dmarc/json/summary', scope),
  timeseries: (scope) => request('/dmarc/json/timeseries', scope),
  sources:    (scope) => request('/dmarc/json/sources', scope),
  source:     (scope) => request('/dmarc/json/source', scope),
  reports:    (scope) => request('/dmarc/json/report', scope),
  reportRows: (rid)   => request('/dmarc/json/row', { rid }),
};

export { ApiError };

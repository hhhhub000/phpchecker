// HTML・ヘッダー解析の小さなヘルパー群。

export const STATUS_ORDER = ['danger', 'warn', 'unknown', 'manual', 'info', 'ok'];

/** 複数のステータスから最も重いものを返す */
export function worstStatus(statuses, fallback = 'ok') {
  let best = null;
  for (const s of statuses) {
    if (!s) continue;
    if (best === null || STATUS_ORDER.indexOf(s) < STATUS_ORDER.indexOf(best)) best = s;
  }
  return best ?? fallback;
}

export function item(id, title, status, summary, extra = {}) {
  return { id, title, status, summary, ...extra };
}

export function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#x2F;/gi, '/');
}

function attrValues(html, tagRe, attr) {
  const values = [];
  const attrRe = new RegExp(`\\b${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i');
  for (const m of String(html || '').matchAll(tagRe)) {
    const a = m[0].match(attrRe);
    if (a) values.push(decodeEntities(a[1] ?? a[2] ?? a[3] ?? ''));
  }
  return values;
}

export function extractMetaGenerators(html) {
  const tags = String(html || '').match(/<meta\b[^>]*>/gi) || [];
  return tags
    .filter((t) => /\bname\s*=\s*["']?generator["']?/i.test(t))
    .flatMap((t) => attrValues(t, /<meta\b[^>]*>/gi, 'content'));
}

export function extractScriptSrcs(html) {
  return attrValues(html, /<script\b[^>]*>/gi, 'src');
}

export function extractFormActions(html) {
  return attrValues(html, /<form\b[^>]*>/gi, 'action');
}

export function extractLinks(html) {
  return [
    ...attrValues(html, /<a\b[^>]*>/gi, 'href'),
    ...attrValues(html, /<link\b[^>]*>/gi, 'href'),
    ...attrValues(html, /<(?:script|img|iframe)\b[^>]*>/gi, 'src'),
  ];
}

/** 相対 URL を解決し、同一オリジンのものだけ返す */
export function sameOriginUrls(urls, baseUrl) {
  const base = new URL(baseUrl);
  const out = [];
  for (const raw of urls) {
    if (!raw || /^(javascript|mailto|tel|data):/i.test(raw)) continue;
    try {
      const u = new URL(raw, base);
      u.hash = '';
      if (u.origin === base.origin) out.push(u.href);
    } catch { /* 無視 */ }
  }
  return [...new Set(out)];
}

/** Set-Cookie ヘッダー 1 行を解析する */
export function parseSetCookie(line) {
  const parts = String(line).split(';').map((p) => p.trim());
  const [pair, ...attrs] = parts;
  const eq = pair.indexOf('=');
  const cookie = {
    name: eq >= 0 ? pair.slice(0, eq).trim() : pair,
    value: eq >= 0 ? pair.slice(eq + 1) : '',
    secure: false,
    httpOnly: false,
    sameSite: null,
    raw: line,
  };
  for (const attr of attrs) {
    const [k, ...v] = attr.split('=');
    const key = k.trim().toLowerCase();
    if (key === 'secure') cookie.secure = true;
    else if (key === 'httponly') cookie.httpOnly = true;
    else if (key === 'samesite') cookie.sameSite = v.join('=').trim() || '';
  }
  return cookie;
}

export function setCookieLines(headers) {
  const v = headers?.['set-cookie'];
  if (!v) return [];
  return Array.isArray(v) ? v : [v];
}

/** 秘密情報を含みうる値を伏せる */
export function maskValue(value) {
  const s = String(value ?? '');
  if (s.length <= 4) return '****';
  return `${s.slice(0, 2)}${'*'.repeat(Math.min(8, s.length - 2))}`;
}

export function snippet(text, index, radius = 120) {
  const s = String(text);
  const start = Math.max(0, index - radius);
  const end = Math.min(s.length, index + radius);
  return s.slice(start, end).replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
}

export function compareVersions(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

export function looksLikeHtml(body) {
  return /<(!doctype|html|head|body)\b/i.test(String(body || '').slice(0, 2000));
}

export function describeResponse(r) {
  if (!r) return '未取得';
  if (r.error) return `エラー: ${r.error}`;
  return `HTTP ${r.status}`;
}

// 6. 通信・HTTPヘッダー全般
import { tlsProbe } from '../net.js';
import { item, describeResponse } from '../util.js';

const HSTS_MIN_AGE = 15552000; // 180 日

export function parseCsp(csp) {
  const directives = {};
  for (const part of String(csp || '').split(';')) {
    const [name, ...values] = part.trim().split(/\s+/);
    if (name) directives[name.toLowerCase()] = values;
  }
  return directives;
}

function daysUntil(dateStr) {
  const t = Date.parse(dateStr);
  return Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86400000);
}

/** サーバーが TLS 1.0 / 1.1 を受け付けるか。クライアント側で試せない場合は null */
async function legacyTlsAccepted(host, port, version, probe) {
  const r = await probe(host, port, { minVersion: version, maxVersion: version, ciphers: 'DEFAULT:@SECLEVEL=0' });
  if (r.ok) return true;
  if (/no protocols available|unsupported protocol.*(client)/i.test(r.error || '') || r.code === 'ERR_SSL_NO_PROTOCOLS_AVAILABLE') return null;
  if (/ETIMEDOUT|ECONNREFUSED|EBLOCKED|ENOTFOUND/.test(r.code || '')) return null;
  return false;
}

export async function checkTransport(ctx, { tls: doTls = true, probe = tlsProbe } = {}) {
  const items = [];
  const top = ctx.top;
  const isHttps = ctx.base.protocol === 'https:';

  // 6-1 HTTPS 強制
  const httpUrl = new URL(ctx.base.href);
  httpUrl.protocol = 'http:';
  httpUrl.port = '';
  httpUrl.pathname = '/';
  httpUrl.search = '';
  const plain = await ctx.fetch(httpUrl.href, { maxBytes: 16 * 1024 });
  const loc = plain.headers?.location || '';
  if (plain.error) {
    items.push(item('https-redirect', 'HTTPS 強制', isHttps ? 'ok' : 'danger',
      isHttps ? `HTTP (80番) には接続できませんでした（${plain.error}）。HTTP を公開していないと考えられます。` : `HTTPS で提供されていません（入力URLが http:// です）。`,
      { evidence: `GET ${httpUrl.href} → ${describeResponse(plain)}` }));
  } else if (plain.status >= 300 && plain.status < 400 && /^https:/i.test(new URL(loc, httpUrl).href)) {
    items.push(item('https-redirect', 'HTTPS 強制', 'ok', `http でのアクセスは HTTP ${plain.status} で https へ転送されます。`,
      { evidence: `GET ${httpUrl.href} → HTTP ${plain.status}\nLocation: ${loc}` }));
  } else {
    items.push(item('https-redirect', 'HTTPS 強制', 'danger', 'http でのアクセスが https へ転送されません。',
      { evidence: `GET ${httpUrl.href} → HTTP ${plain.status}${loc ? `\nLocation: ${loc}` : ''}`, hint: 'http へのアクセスを 301 で https へ転送してください。' }));
  }

  // 6-2 HSTS
  const hsts = top.headers['strict-transport-security'];
  if (!isHttps) {
    items.push(item('hsts', 'HSTS', 'unknown', 'https で提供されていないため確認できません。'));
  } else if (!hsts) {
    items.push(item('hsts', 'HSTS', 'warn', 'Strict-Transport-Security ヘッダーがありません。',
      { hint: '例: Strict-Transport-Security: max-age=31536000; includeSubDomains' }));
  } else {
    const age = Number(hsts.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? 0);
    items.push(item('hsts', 'HSTS', age < HSTS_MIN_AGE ? 'warn' : 'ok',
      age < HSTS_MIN_AGE ? `max-age が短すぎます（${age} 秒）。半年（${HSTS_MIN_AGE} 秒）以上を推奨します。` : `HSTS が設定されています（max-age=${age}）。`,
      { evidence: `Strict-Transport-Security: ${hsts}` }));
  }

  const csp = top.headers['content-security-policy'];
  const cspDirectives = parseCsp(csp);

  // 6-3 クリックジャッキング対策
  const xfo = top.headers['x-frame-options'];
  const fa = cspDirectives['frame-ancestors'];
  items.push(xfo || fa
    ? item('clickjacking', 'クリックジャッキング対策', 'ok', '対策ヘッダーが設定されています。',
      { evidence: [xfo && `X-Frame-Options: ${xfo}`, fa && `CSP frame-ancestors ${fa.join(' ')}`].filter(Boolean).join('\n') })
    : item('clickjacking', 'クリックジャッキング対策', 'warn', 'X-Frame-Options も CSP の frame-ancestors もありません。',
      { hint: '例: X-Frame-Options: SAMEORIGIN または Content-Security-Policy: frame-ancestors \'self\'' }));

  // 6-4 MIME スニッフィング対策
  const xcto = top.headers['x-content-type-options'];
  items.push(/nosniff/i.test(xcto || '')
    ? item('nosniff', 'MIMEスニッフィング対策', 'ok', 'X-Content-Type-Options: nosniff が設定されています。')
    : item('nosniff', 'MIMEスニッフィング対策', 'warn', 'X-Content-Type-Options: nosniff がありません。', { evidence: xcto ? `X-Content-Type-Options: ${xcto}` : undefined }));

  // 6-5 CSP
  if (!csp) {
    const ro = top.headers['content-security-policy-report-only'];
    items.push(item('csp', 'CSP', 'warn', `Content-Security-Policy ヘッダーがありません${ro ? '（Report-Only のみ設定されています）' : ''}。`,
      { evidence: ro ? `Content-Security-Policy-Report-Only: ${ro}` : undefined }));
  } else {
    const scriptSrc = cspDirectives['script-src'] || cspDirectives['default-src'] || [];
    const weak = scriptSrc.filter((v) => /'unsafe-(inline|eval)'/i.test(v));
    items.push(item('csp', 'CSP', weak.length ? 'warn' : 'ok',
      weak.length ? `CSP は設定されていますが、script の制限に ${weak.join(' ')} が含まれ XSS 対策として弱くなっています。` : 'CSP が設定されています。',
      { evidence: `Content-Security-Policy: ${csp}` }));
  }

  // 6-6 TLS 設定
  if (!isHttps) {
    items.push(item('tls', 'TLS 設定', 'unknown', 'https で提供されていないため確認できません。'));
  } else if (!doTls) {
    items.push(item('tls', 'TLS 設定', 'manual', 'TLS 確認はオフにされています。', { hint: 'SSL Labs (https://www.ssllabs.com/ssltest/) で診断してください。' }));
  } else {
    const host = ctx.base.hostname.replace(/^\[|\]$/g, '');
    const port = Number(ctx.base.port) || 443;
    const main = await probe(host, port);
    if (!main.ok) {
      items.push(item('tls', 'TLS 設定', 'unknown', `TLS 接続に失敗しました（${main.error}）。`,
        { hint: 'SSL Labs (https://www.ssllabs.com/ssltest/) で診断してください。' }));
    } else {
      const findings = [];
      let status = 'ok';
      const days = main.cert ? daysUntil(main.cert.validTo) : null;
      if (!main.authorized) { status = 'danger'; findings.push(`証明書の検証に失敗しました（${main.authorizationError}）`); }
      if (days !== null && days < 0) { status = 'danger'; findings.push(`証明書の有効期限が切れています（${main.cert.validTo}）`); }
      else if (days !== null && days < 14) { status = 'danger'; findings.push(`証明書の有効期限まで ${days} 日です`); }
      else if (days !== null && days < 30) { if (status === 'ok') status = 'warn'; findings.push(`証明書の有効期限まで ${days} 日です`); }
      const legacy = [];
      const untested = [];
      for (const v of ['TLSv1', 'TLSv1.1']) {
        const accepted = await legacyTlsAccepted(host, port, v, probe);
        if (accepted) legacy.push(v === 'TLSv1' ? 'TLS 1.0' : 'TLS 1.1');
        else if (accepted === null) untested.push(v === 'TLSv1' ? 'TLS 1.0' : 'TLS 1.1');
      }
      if (legacy.length) { status = 'danger'; findings.push(`古いプロトコル ${legacy.join(' / ')} が有効です`); }
      const evidence = [
        `プロトコル: ${main.protocol} / 暗号スイート: ${main.cipher}`,
        main.cert && `証明書: CN=${main.cert.subject} / 発行者: ${main.cert.issuer} / 有効期限: ${main.cert.validTo}${days !== null ? `（残り ${days} 日）` : ''}`,
        `TLS 1.0/1.1: ${legacy.length ? `${legacy.join(', ')} 有効` : '無効'}${untested.length ? `（${untested.join(', ')} は判定できず）` : ''}`,
      ].filter(Boolean).join('\n');
      items.push(item('tls', 'TLS 設定', status,
        findings.length ? findings.join('。') + '。' : '証明書は有効で、TLS 1.0/1.1 は無効です。',
        { evidence, hint: '暗号スイートやプロトコルの総合評価は SSL Labs (https://www.ssllabs.com/ssltest/) で確認してください（評価B以下は要対応）。' }));
    }
  }

  return items;
}

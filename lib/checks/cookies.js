// 4. セッション・Cookie
import { item, parseSetCookie, setCookieLines, worstStatus } from '../util.js';

export const SESSION_COOKIE_RE = /^(PHPSESSID|MoodleSession\w*|laravel_session|ci_session|CAKEPHP|S?SESS[0-9a-f]{16,}|PrestaShop-\w+|wordpress_(?:logged_in|sec)_\w+|[\w-]*sess(?:ion)?(?:id)?)$/i;

function collectCookies(ctx) {
  const map = new Map();
  const sources = [...(ctx.top.chain || [ctx.top]), ...ctx.responses];
  for (const res of sources) {
    for (const line of setCookieLines(res.headers)) {
      const c = parseSetCookie(line);
      if (!map.has(c.name)) map.set(c.name, { ...c, url: res.url });
    }
  }
  return [...map.values()];
}

export function cookieIssues(cookie, isHttps) {
  const issues = [];
  if (!cookie.httpOnly) issues.push('HttpOnly なし');
  if (isHttps && !cookie.secure) issues.push('Secure なし');
  if (!cookie.sameSite) issues.push('SameSite 未指定');
  else if (cookie.sameSite.toLowerCase() === 'none' && !cookie.secure) issues.push('SameSite=None だが Secure なし');
  return issues;
}

export async function checkCookies(ctx) {
  const items = [];
  const isHttps = ctx.base.protocol === 'https:';
  const cookies = collectCookies(ctx);

  // 4-1 Cookie 属性
  if (!cookies.length) {
    items.push(item('cookie-attrs', 'Cookie 属性', 'unknown',
      '取得したページでは Cookie が発行されませんでした。',
      { hint: 'ログインページやフォームのあるページのURLを入力して再チェックするか、F12 → Application → Cookies で PHPSESSID の Secure / HttpOnly / SameSite 列を確認してください。' }));
  } else {
    const statuses = [];
    const lines = cookies.map((c) => {
      const isSession = SESSION_COOKIE_RE.test(c.name);
      const issues = cookieIssues(c, isHttps);
      const critical = issues.some((i) => i.startsWith('HttpOnly') || i.startsWith('Secure'));
      statuses.push(issues.length === 0 ? 'ok' : (isSession && critical ? 'danger' : 'warn'));
      const attrs = [c.secure && 'Secure', c.httpOnly && 'HttpOnly', c.sameSite !== null && `SameSite=${c.sameSite}`].filter(Boolean).join('; ');
      return `${c.name}${isSession ? '（セッション）' : ''}: ${attrs || '属性なし'}${issues.length ? `  ← ${issues.join('、')}` : ''}`;
    });
    const status = worstStatus(statuses);
    const sessions = cookies.filter((c) => SESSION_COOKIE_RE.test(c.name)).map((c) => c.name);
    items.push(item('cookie-attrs', 'Cookie 属性', status,
      status === 'ok'
        ? `発行された Cookie ${cookies.length} 件はすべて HttpOnly${isHttps ? '・Secure' : ''}・SameSite が設定されています。`
        : `属性が不足している Cookie があります。${sessions.length ? `セッションCookie: ${sessions.join(', ')}` : ''}`,
      { evidence: lines.join('\n'), hint: status === 'ok' ? undefined : 'php.ini の session.cookie_httponly = 1、session.cookie_secure = 1、session.cookie_samesite = Lax（または Strict）を設定してください。' }));
  }

  // 4-2 URL へのセッション ID 付与
  const sidRe = /[?&;](PHPSESSID|MoodleSession\w*|sid)=[A-Za-z0-9,-]{8,}/i;
  const hiddenRe = /<input[^>]+name=["']PHPSESSID["']/i;
  const hits = [];
  for (const res of [...(ctx.top.chain || []), ...ctx.responses]) {
    const loc = res.headers?.location;
    if (loc && sidRe.test(loc)) hits.push(`${res.url} → Location: ${loc.replace(/=([A-Za-z0-9,-]{4})[A-Za-z0-9,-]+/, '=$1****')}`);
    const m = res.body?.match(sidRe) || res.body?.match(hiddenRe);
    if (m) hits.push(`${res.url} 本文中: ${m[0].replace(/=([A-Za-z0-9,-]{4})[A-Za-z0-9,-]+/, '=$1****')}`);
  }
  items.push(hits.length
    ? item('trans-sid', 'URLへのセッションID付与', 'danger',
      'URLやフォームにセッションIDが埋め込まれています（session.use_trans_sid が有効の可能性）。リファラー等でセッションIDが漏れます。',
      { evidence: [...new Set(hits)].join('\n'), hint: 'session.use_trans_sid = 0、session.use_only_cookies = 1 を設定してください。' })
    : item('trans-sid', 'URLへのセッションID付与', 'ok', '取得したページのリンク・リダイレクト先にセッションIDは見当たりません。'));

  // 4-3, 4-4 はログイン操作が必要なため手動確認
  items.push(item('fixation', 'ログイン前後のID変化', 'manual',
    'ログイン操作が必要なため、本ツールでは確認できません。',
    { hint: 'F12 → Application → Cookies でログイン前のセッションIDを控え、ログイン後と比べてください。同じ値のままならセッション固定の恐れがあります（session_regenerate_id(true) が必要）。' }));
  items.push(item('logout', 'ログアウト後の無効化', 'manual',
    'ログイン操作が必要なため、本ツールでは確認できません。',
    { hint: 'ログアウト後にブラウザの戻るボタンで保護ページを開き、ログイン状態のまま操作できないか確認してください。' }));

  return items;
}

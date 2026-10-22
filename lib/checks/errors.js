// 3. エラー表示・設定の露出
import { item, snippet, describeResponse } from '../util.js';

const PHP_ERROR_RE = /(?:<b>)?\b(Fatal error|Warning|Notice|Deprecated|Parse error)\b(?:<\/b>)?\s*:\s*[^\n]{0,500}?\bon line\b/i;
const PATH_RE = /\bin\s+(?:<b>)?((?:\/|[A-Za-z]:\\)[^<\s]+\.php)/i;
const STACK_RES = [
  /Stack trace:\s*(?:<br\s*\/?>)?\s*#0/i,
  /#\d+\s+(?:\/|[A-Za-z]:\\)[^\s<]+\.php\(\d+\)/,
  /Whoops\\(?:Handler|Run)|class=["']whoops-container/i,
  /Symfony\\Component\\(?:ErrorHandler|Debug)\\/,
  /\b(?:Illuminate|Laminas|Zend|Cake|yii|CodeIgniter)\\[A-Za-z\\]*Exception/,
  /Moodle\s+exception|Debug info:\s*.*\n?.*Error code:/i,
];
const SQL_RES = [
  /SQLSTATE\[[0-9A-Z]{5}\]/,
  /You have an error in your SQL syntax/i,
  /\b(?:mysqli?|pg|sqlsrv|oci)_[a-z_]+\(\)/i,
  /\bORA-\d{5}\b/,
  /PostgreSQL query failed|unterminated quoted string at or near/i,
  /Warning:.*\bmysql/i,
  /Error reading from database|dmlreadexception/i,
];

function findIn(responses, regexes) {
  const hits = [];
  for (const res of responses) {
    if (!res || res.error || !res.body) continue;
    for (const re of regexes) {
      const m = res.body.match(re);
      if (m) { hits.push({ url: res.url, text: snippet(res.body, m.index) }); break; }
    }
  }
  return hits;
}

/** 最初のクエリパラメータを配列化した URL（?id=1 → ?id[]=1）を作る */
export function arrayParamVariant(url) {
  const u = new URL(url);
  const entries = [...u.searchParams.entries()];
  if (!entries.length) return null;
  const [name, value] = entries[0];
  if (name.endsWith('[]')) return null;
  u.searchParams.delete(name);
  const rest = u.searchParams.toString();
  u.search = `${encodeURIComponent(name)}[]=${encodeURIComponent(value)}${rest ? `&${rest}` : ''}`;
  return { url: u.href, param: name };
}

export async function checkErrors(ctx) {
  const items = [];
  const variant = arrayParamVariant(ctx.inputUrl.href);
  let variantRes = null;
  if (variant) variantRes = await ctx.fetch(variant.url, { maxBytes: 512 * 1024 });

  // 置き忘れファイルの探索結果（ソースコード等）は誤検知の元になるため除外する
  const bodies = [ctx.top, ctx.notFound, variantRes, ...ctx.responses.filter((r) => !r.probe)].filter(Boolean);

  // 3-1 PHP エラーの画面表示
  const errHits = [];
  for (const res of bodies) {
    if (res.error || !res.body) continue;
    const m = res.body.match(PHP_ERROR_RE);
    if (m && !errHits.some((h) => h.url === res.url)) {
      const p = res.body.slice(m.index, m.index + 800).match(PATH_RE);
      errHits.push({ url: res.url, text: snippet(res.body, m.index + 60, 160), path: p?.[1] });
    }
  }
  const variantNote = variant
    ? `パラメータ「${variant.param}」を配列にしたURLを1回だけ開きました（${describeResponse(variantRes)}）。`
    : '入力URLにクエリパラメータがないため、配列化の確認は行っていません。';
  if (errHits.length) {
    items.push(item('display-errors', 'PHPエラーの画面表示', 'danger',
      `PHPのエラーメッセージが画面に表示されています（display_errors = On の可能性）。${errHits.some((h) => h.path) ? 'サーバー内部のファイルパスも漏れています。' : ''}`,
      { evidence: errHits.map((h) => `${h.url}\n  ${h.text}`).join('\n'), hint: '本番環境では display_errors = Off、log_errors = On にしてください。' }));
  } else {
    items.push(item('display-errors', 'PHPエラーの画面表示', variant ? 'ok' : 'manual',
      `取得したページにPHPのエラー表示は見当たりません。${variantNote}`,
      { evidence: variant ? `GET ${variant.url} → ${describeResponse(variantRes)}` : undefined,
        hint: variant ? undefined : '`?id=1` のようにパラメータ付きのURLを入力すると、`?id[]=1` に変えた1回のリクエストで確認します。' }));
  }

  // 3-2 スタックトレース
  const stackHits = findIn([ctx.notFound, variantRes, ctx.top], STACK_RES);
  if (stackHits.length) {
    items.push(item('stacktrace', 'スタックトレースの露出', 'danger',
      'クラス名・関数名・行番号などのスタックトレースが表示されています（デバッグモードのままの可能性）。',
      { evidence: stackHits.map((h) => `${h.url}\n  ${h.text}`).join('\n'), hint: 'フレームワークのデバッグモード（APP_DEBUG 等）を本番では無効にしてください。' }));
  } else {
    items.push(item('stacktrace', 'スタックトレースの露出', 'ok',
      `存在しないURL${variant ? '・配列化パラメータ' : ''}でスタックトレースは表示されませんでした。`));
  }

  // 3-3 DB エラー（受動検出のみ。クォートは送らない）
  const sqlHits = findIn(bodies, SQL_RES);
  if (sqlHits.length) {
    items.push(item('db-error', 'DBエラーの露出', 'danger',
      '取得したページにSQL文やDBのエラーが表示されています。SQLインジェクションの可能性もあるため運用側へ報告してください。',
      { evidence: sqlHits.map((h) => `${h.url}\n  ${h.text}`).join('\n') }));
  } else {
    items.push(item('db-error', 'DBエラーの露出', 'manual',
      '取得したページにDBエラーは見当たりません。本ツールは攻撃とみなされうる入力（シングルクォート等）は送信しません。',
      { hint: '許可を得たうえで、検索欄などに `\'`（シングルクォート1文字）を手で入れて送信し、SQL文やDBエラーが出ないか確認してください。' }));
  }

  // 3-4 HTTP メソッド
  const opt = await ctx.fetch(ctx.base.href, { method: 'OPTIONS', maxBytes: 16 * 1024 });
  const allow = opt.headers?.allow || opt.headers?.['access-control-allow-methods'];
  if (opt.error) {
    items.push(item('methods', 'HTTPメソッド', 'unknown', `OPTIONS リクエストに失敗しました（${opt.error}）。`));
  } else if (!allow) {
    items.push(item('methods', 'HTTPメソッド', 'unknown',
      `OPTIONS に Allow ヘッダーが返りませんでした（HTTP ${opt.status}）。許可メソッドは外部から判定できません。`));
  } else {
    const risky = allow.split(',').map((m) => m.trim().toUpperCase()).filter((m) => ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT'].includes(m));
    items.push(item('methods', 'HTTPメソッド', risky.length ? 'warn' : 'ok',
      risky.length ? `不要な可能性のあるメソッドが許可されています: ${risky.join(', ')}` : '危険なメソッド（TRACE/PUT/DELETE）は Allow に含まれていません。',
      { evidence: `OPTIONS ${opt.url} → HTTP ${opt.status}\nAllow: ${allow}`,
        hint: risky.length ? 'API で PUT/DELETE を使っている場合は問題ありません。TRACE は TraceEnable Off で無効化してください。' : undefined }));
  }

  return items;
}

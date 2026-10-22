// PHP2Shell の悪用前提条件（セッションID受付・upload_progress）を調べるアクティブ検査。
//
// 【重要】通常のチェックより踏み込んだ検査です。対象サーバーにセッションを作成させ、
// POST を送るため、WAF/IDS に検知される可能性があり、負荷もかかります。そのため
// この検査はパスワードを入力したとき（＝運用側の許可がある前提）だけ実行されます。
// 送るのは良性の固定値だけで、PoC・攻撃コード・大きなファイルは一切送りません。
import { item, parseSetCookie, setCookieLines, worstStatus } from '../util.js';
import { SESSION_COOKIE_RE } from './cookies.js';

// 検査に使う良性の固定セッションID（PHPSESSID の既定文字種・長さに合わせる）
const PROBE_SID = 'phpchecker0benign0probe0id0';
const UPLOAD_KEY = 'phpchecker_probe';

/** トップページで発行されたセッションCookieの名前を推定する（なければ PHPSESSID） */
export function sessionCookieName(ctx) {
  const sources = [...(ctx.top.chain || [ctx.top]), ...ctx.responses];
  for (const res of sources) {
    for (const line of setCookieLines(res.headers)) {
      const c = parseSetCookie(line);
      if (SESSION_COOKIE_RE.test(c.name)) return c.name;
    }
  }
  return 'PHPSESSID';
}

function setCookieFor(res, name) {
  for (const line of setCookieLines(res.headers)) {
    const c = parseSetCookie(line);
    if (c.name === name) return c.value;
  }
  return null;
}

/**
 * クライアントが指定したセッションIDをサーバーが受け付けるか（session.use_strict_mode=0 の兆候）。
 * これは PHP2Shell のセッション経由攻撃の前提条件のひとつ。
 */
export async function probeSessionIdAcceptance(ctx, name) {
  const res = await ctx.fetch(ctx.base.href, {
    method: 'GET',
    headers: { cookie: `${name}=${PROBE_SID}` },
    maxBytes: 16 * 1024,
    noCache: true,
  });
  if (res.error) return { status: 'unknown', accepted: null, res };
  const issued = setCookieFor(res, name);
  let accepted;
  if (issued === null) accepted = true;            // 新しいIDを発行せず、こちらのIDをそのまま使った
  else if (issued === PROBE_SID) accepted = true;  // こちらのIDをそのまま返した
  else accepted = false;                           // サーバーが別のIDを再発行した＝未知IDを拒否
  return { status: accepted ? 'danger' : 'ok', accepted, issued, res };
}

/**
 * session.upload_progress の有効性を良性の multipart POST で確認する。
 * 外部からの確定的な判定は難しいため、結果は参考情報として扱う。
 */
export async function probeUploadProgress(ctx, name) {
  const boundary = '----phpchecker' + Date.now().toString(36);
  const part = (headers, value) => `--${boundary}\r\n${headers}\r\n\r\n${value}\r\n`;
  const body =
    part(`Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"`, UPLOAD_KEY) +
    part(`Content-Disposition: form-data; name="file"; filename="probe.txt"\r\nContent-Type: text/plain`, 'ok') +
    `--${boundary}--\r\n`;
  const res = await ctx.fetch(ctx.base.href, {
    method: 'POST',
    headers: {
      'content-type': `multipart/form-data; boundary=${boundary}`,
      cookie: `${name}=${PROBE_SID}`,
    },
    body,
    maxBytes: 16 * 1024,
    noCache: true,
  });
  return { res };
}

export async function checkActive(ctx) {
  const items = [];
  const name = sessionCookieName(ctx);

  // 1. クライアント指定セッションIDの受付
  const sid = await probeSessionIdAcceptance(ctx, name);
  if (sid.status === 'unknown') {
    items.push(item('session-id-accept', 'クライアント指定セッションIDの受付', 'unknown',
      `検査リクエストに失敗しました（${sid.res.error}）。`));
  } else if (sid.accepted) {
    items.push(item('session-id-accept', 'クライアント指定セッションIDの受付', 'danger',
      `こちらが指定したセッションID（Cookie: ${name}）をサーバーがそのまま受け付けました。session.use_strict_mode = 0 の兆候で、攻撃者がセッションファイル名を制御できる状態です。PHP2Shell のセッション経由攻撃の前提条件のひとつに該当します。`,
      {
        evidence: `GET ${sid.res.url}\n  送信 Cookie: ${name}=${PROBE_SID}\n  応答の Set-Cookie(${name}): ${sid.issued === null ? '（再発行なし）' : sid.issued}`,
        hint: 'php.ini で session.use_strict_mode = 1 を設定し、未知のセッションIDを拒否してください。あわせて PHP 本体を修正版へ更新してください。',
      }));
  } else {
    items.push(item('session-id-accept', 'クライアント指定セッションIDの受付', 'ok',
      `こちらが指定したセッションIDは受け付けられず、サーバーが新しいIDを再発行しました（session.use_strict_mode = 1 の兆候）。`,
      { evidence: `GET ${sid.res.url}\n  送信 Cookie: ${name}=${PROBE_SID}\n  応答の Set-Cookie(${name}): ${sid.issued}` }));
  }

  // 2. upload_progress の有効性（参考）
  const up = await probeUploadProgress(ctx, name);
  if (up.res.error) {
    items.push(item('upload-progress', 'session.upload_progress の有効性', 'unknown',
      `検査リクエストに失敗しました（${up.res.error}）。`));
  } else {
    items.push(item('upload-progress', 'session.upload_progress の有効性', 'manual',
      `良性の multipart POST（フィールド名 PHP_SESSION_UPLOAD_PROGRESS ＋ 数バイトのダミーファイル）を1回送信しました（応答 HTTP ${up.res.status}）。session.upload_progress.enabled は PHP の既定で有効で、PHP2Shell の前提条件のひとつですが、有効かどうかを外部から確定的に判定することはできません。`,
      {
        evidence: `POST ${up.res.url} → HTTP ${up.res.status}\n  送信フィールド: PHP_SESSION_UPLOAD_PROGRESS=${UPLOAD_KEY}（+ probe.txt 2バイト）`,
        hint: 'サーバー内で `php -i | grep upload_progress` を確認してください。既定の有効のままで問題ない設定ですが、PHP 本体を修正版へ更新することが本質的な対策です。',
      }));
  }

  // 前提条件の総合（PHP2Shell カードから参照する）
  const preconditionStatus = worstStatus(items.map((i) => i.status), 'unknown');
  ctx.php2shellPreconditions = {
    tested: true,
    sessionIdAccepted: sid.status === 'unknown' ? null : sid.accepted,
    status: preconditionStatus,
    items: items.map((i) => ({ id: i.id, title: i.title, status: i.status, summary: i.summary })),
  };

  return items;
}

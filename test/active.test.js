import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runScan } from '../lib/scanner.js';
import { listen } from './fixtures.js';

process.env.ALLOW_PRIVATE_TARGETS = '1';

// クライアント指定のセッションIDをそのまま受け付ける（use_strict_mode=0 相当）サーバー
function lenientHandler(req, res) {
  const m = /PHPSESSID=([^;]+)/.exec(req.headers.cookie || '');
  const id = m ? m[1] : 's0000000000000000000000000';
  res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': `PHPSESSID=${id}; path=/` });
  res.end('<!doctype html><html><body>ok</body></html>');
}

// 未知のIDを拒否し、必ず新しいIDを再発行する（use_strict_mode=1 相当）サーバー
let strictCounter = 0;
function strictHandler(req, res) {
  res.writeHead(200, { 'content-type': 'text/html', 'set-cookie': `PHPSESSID=fresh${strictCounter++}0000000000000000000; path=/` });
  res.end('<!doctype html><html><body>ok</body></html>');
}

let lenient;
let strict;
before(async () => {
  lenient = await listen(lenientHandler);
  strict = await listen(strictHandler);
});
after(() => {
  lenient.server.close();
  strict.server.close();
});

const fakeTls = async () => ({ ok: false, error: 'no tls', code: 'ECONNREFUSED' });
const scan = (url, active) => runScan(new URL(url), {
  contextOptions: { delayMs: 0 },
  options: { active, exposure: false, cms: false, tlsProbe: fakeTls },
});
const activeItems = (r) => r.sections.find((s) => s.id === 'active').items;

test('アクティブ検査は active=false のときスキップされる', async () => {
  const r = await scan(`${lenient.url}/`, false);
  assert.equal(r.sections.find((s) => s.id === 'active').skipped, true);
  assert.equal(r.php2shell.preconditions.tested, false);
});

test('クライアント指定セッションIDを受け付けるサーバーは要対応', async () => {
  const r = await scan(`${lenient.url}/`, true);
  const sid = activeItems(r).find((i) => i.id === 'session-id-accept');
  assert.equal(sid.status, 'danger');
  assert.equal(r.php2shell.preconditions.tested, true);
  assert.equal(r.php2shell.preconditions.sessionIdAccepted, true);
});

test('未知IDを再発行するサーバーは問題なし', async () => {
  const r = await scan(`${strict.url}/`, true);
  const sid = activeItems(r).find((i) => i.id === 'session-id-accept');
  assert.equal(sid.status, 'ok');
  assert.equal(r.php2shell.preconditions.sessionIdAccepted, false);
});

test('upload_progress は外部からは確定できないため手動確認扱い', async () => {
  const r = await scan(`${lenient.url}/`, true);
  const up = activeItems(r).find((i) => i.id === 'upload-progress');
  assert.equal(up.status, 'manual');
});

test('POST 本文（multipart）が送信される', async () => {
  const seen = [];
  const rec = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ method: req.method, type: req.headers['content-type'] || '', body });
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('ok');
    });
  });
  await new Promise((r) => rec.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${rec.address().port}/`;
  await scan(url, true);
  const post = seen.find((s) => s.method === 'POST');
  assert.ok(post, 'POST が送られること');
  assert.match(post.type, /multipart\/form-data/);
  assert.match(post.body, /PHP_SESSION_UPLOAD_PROGRESS/);
  rec.close();
});

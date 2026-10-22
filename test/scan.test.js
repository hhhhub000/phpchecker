import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../lib/scanner.js';
import { request } from '../lib/net.js';
import { listen, vulnerableHandler, hardenedHandler } from './fixtures.js';

process.env.ALLOW_PRIVATE_TARGETS = '1';

let vuln;
let safe;
before(async () => {
  vuln = await listen(vulnerableHandler);
  safe = await listen(hardenedHandler);
});
after(() => {
  vuln.server.close();
  safe.server.close();
});

const fakeTls = async () => ({ ok: false, error: 'no tls', code: 'ECONNREFUSED' });
const scan = (url) => runScan(new URL(url), { contextOptions: { delayMs: 0 }, options: { tlsProbe: fakeTls } });
const find = (result, sectionId, itemId) => result.sections.find((s) => s.id === sectionId).items.find((i) => i.id === itemId);

test('脆弱なサイトでは各種の問題を検出する', async () => {
  const r = await scan(`${vuln.url}/page.php?id=1`);
  // 入力URLはページだが、トップページ相当の判定は入力URLに対して行う
  assert.equal(find(r, 'version', 'xpb').status, 'danger');
  assert.equal(find(r, 'version', 'server').status, 'warn');
  assert.equal(find(r, 'version', 'errorpage').status, 'warn');
  assert.equal(find(r, 'exposure', 'phpinfo').status, 'danger');
  assert.equal(find(r, 'exposure', 'config').status, 'danger');
  assert.doesNotMatch(find(r, 'exposure', 'config').summary, /hunter2/, '秘密の値は表示しない');
  assert.equal(find(r, 'exposure', 'git').status, 'danger');
  assert.equal(find(r, 'exposure', 'composer').status, 'danger');
  assert.equal(find(r, 'exposure', 'dirlist').status, 'danger');
  assert.equal(find(r, 'exposure', 'apache-status').status, 'ok');
  assert.equal(find(r, 'errors', 'display-errors').status, 'danger');
  assert.equal(find(r, 'errors', 'methods').status, 'warn');
  assert.equal(find(r, 'cms', 'php-libs').status, 'danger');
  assert.equal(find(r, 'transport', 'https-redirect').status, 'danger');
  assert.equal(r.php2shell.status, 'danger');
  assert.ok(r.php2shell.versions.includes('8.3.30'));
  assert.ok(r.php2shell.findings.some((f) => f.source.startsWith('phpinfo')));
  assert.ok(r.verdicts.some((v) => v.title === '2章のファイルが見える'));
  assert.ok(r.requestCount <= 70);
});

test('脆弱なサイトのトップページ（CMS・Cookie）', async () => {
  const r = await scan(`${vuln.url}/`);
  assert.equal(find(r, 'cookies', 'cookie-attrs').status, 'danger');
  assert.equal(find(r, 'cookies', 'trans-sid').status, 'danger');
  assert.equal(find(r, 'cms', 'generator').status, 'warn');
  assert.equal(find(r, 'cms', 'wordpress').status, 'warn');
  assert.match(find(r, 'cms', 'wordpress').summary, /admin/);
  assert.equal(find(r, 'cms', 'wp-plugins').status, 'warn');
  assert.equal(find(r, 'cms', 'js-libs').status, 'danger');
  // フォーム送信先のエンドポイントで別バージョンを検出
  const ep = find(r, 'version', 'endpoints');
  assert.match(ep.summary, /8\.1\.2-1ubuntu2\.14/);
  assert.equal(find(r, 'version', 'distro').status, 'manual');
  assert.equal(find(r, 'errors', 'display-errors').status, 'manual');
  assert.equal(find(r, 'transport', 'hsts').status, 'unknown');
});

test('対策済みのサイトでは問題を検出しない', async () => {
  const r = await scan(`${safe.url}/`);
  assert.equal(find(r, 'version', 'xpb').status, 'unknown');
  assert.equal(find(r, 'version', 'server').status, 'ok');
  for (const it of r.sections.find((s) => s.id === 'exposure').items) assert.notEqual(it.status, 'danger', it.id);
  assert.equal(find(r, 'cookies', 'cookie-attrs').status, 'ok');
  assert.equal(find(r, 'transport', 'clickjacking').status, 'ok');
  assert.equal(find(r, 'transport', 'nosniff').status, 'ok');
  assert.equal(find(r, 'transport', 'csp').status, 'ok');
  assert.equal(r.php2shell.status, 'unknown');
  assert.equal(r.php2shell.findings.length, 0);
});

test('内部ネットワーク宛てのリクエストは既定で拒否する', async () => {
  delete process.env.ALLOW_PRIVATE_TARGETS;
  try {
    const literal = await request(`${vuln.url}/`);
    assert.equal(literal.code, 'EBLOCKED');
    const named = await request(`http://localhost:${vuln.server.address().port}/`);
    assert.equal(named.code, 'EBLOCKED');
  } finally {
    process.env.ALLOW_PRIVATE_TARGETS = '1';
  }
});

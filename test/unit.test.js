import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractPhpVersions, assessPhpVersion } from '../lib/php-version.js';
import { isBlockedAddress } from '../lib/net.js';
import { parseSetCookie, extractMetaGenerators, compareVersions, worstStatus } from '../lib/util.js';
import { detectJsLibraries, moodleBranch, detectCms } from '../lib/checks/cms.js';
import { arrayParamVariant } from '../lib/checks/errors.js';
import { parseCsp } from '../lib/checks/transport.js';
import { normalizeTargetUrl } from '../lib/scanner.js';

const assess = (s) => assessPhpVersion(extractPhpVersions(s)[0]).status;

test('PHP バージョンの抽出', () => {
  assert.deepEqual(extractPhpVersions('PHP/8.3.30').map((v) => v.raw), ['8.3.30']);
  assert.deepEqual(extractPhpVersions('Apache/2.4.52 (Ubuntu) PHP/8.1.2-1ubuntu2.14').map((v) => v.raw), ['8.1.2-1ubuntu2.14']);
  assert.deepEqual(extractPhpVersions('PHP Version 8.4.1').map((v) => v.raw), ['8.4.1']);
  assert.deepEqual(extractPhpVersions('nginx'), []);
});

test('PHP2Shell 修正版との照合', () => {
  assert.equal(assess('PHP/8.3.30'), 'danger');
  assert.equal(assess('PHP/8.3.36'), 'ok');
  assert.equal(assess('PHP/8.2.34'), 'danger');
  assert.equal(assess('PHP/8.2.35'), 'ok');
  assert.equal(assess('PHP/8.4.27'), 'ok');
  assert.equal(assess('PHP/8.5.11'), 'danger');
  assert.equal(assess('PHP/8.1.33'), 'danger');
  assert.equal(assess('PHP/7.4.33'), 'danger');
  assert.equal(assess('PHP/8.1.2-1ubuntu2.14'), 'warn');
  assert.equal(assess('PHP/8.6.0'), 'unknown');
});

test('内部ネットワークのアドレス判定', () => {
  for (const a of ['127.0.0.1', '10.1.2.3', '172.20.0.1', '192.168.1.1', '169.254.169.254', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '0.0.0.0', '100.100.1.1']) {
    assert.equal(isBlockedAddress(a), true, a);
  }
  for (const a of ['93.184.216.34', '8.8.8.8', '2606:4700::1111']) assert.equal(isBlockedAddress(a), false, a);
});

test('Set-Cookie の解析', () => {
  const c = parseSetCookie('PHPSESSID=abc; path=/; Secure; HttpOnly; SameSite=Lax');
  assert.equal(c.name, 'PHPSESSID');
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, 'Lax');
  const d = parseSetCookie('a=b');
  assert.equal(d.secure, false);
  assert.equal(d.sameSite, null);
});

test('generator・JSライブラリの検出', () => {
  assert.deepEqual(extractMetaGenerators('<meta name="generator" content="WordPress 6.4.2" />'), ['WordPress 6.4.2']);
  const libs = detectJsLibraries([
    '/js/jquery-1.12.4.min.js',
    '/wp-includes/js/jquery/jquery.min.js?ver=3.7.1',
    'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js',
    '/js/bootstrap-4.1.3.min.js',
    '/js/jquery-ui-1.12.1.min.js',
  ]);
  assert.deepEqual(libs.filter((l) => l.name === 'jQuery').map((l) => l.version), ['1.12.4', '3.7.1', '3.4.1']);
  assert.ok(libs.some((l) => l.name === 'bootstrap' && l.version === '4.1.3'));
});

test('Moodle のブランチ表記・CMS 検出', () => {
  assert.equal(moodleBranch('405'), '4.5');
  assert.equal(moodleBranch('500'), '5.0');
  assert.equal(moodleBranch('39'), '3.9');
  const cms = detectCms('<script>M.cfg = {"wwwroot":"https:\\/\\/example.com\\/moodle"};</script>', [], 'https://example.com/moodle/');
  assert.equal(cms.moodle, true);
  assert.equal(cms.moodlePath, '/moodle');
  const wp = detectCms('<link href="https://example.com/blog/wp-content/themes/x/style.css">', [], 'https://example.com/blog/');
  assert.equal(wp.wordpress, true);
  assert.equal(wp.wordpressPath, '/blog');
});

test('パラメータの配列化', () => {
  assert.equal(arrayParamVariant('https://e.com/p.php?id=1&x=2').url, 'https://e.com/p.php?id[]=1&x=2');
  assert.equal(arrayParamVariant('https://e.com/'), null);
});

test('その他のヘルパー', () => {
  assert.equal(compareVersions('3.4.1', '3.5.0'), -1);
  assert.equal(compareVersions('3.5', '3.5.0'), 0);
  assert.equal(worstStatus(['ok', 'warn', 'info']), 'warn');
  assert.deepEqual(parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline'")['script-src'], ["'self'", "'unsafe-inline'"]);
  assert.equal(normalizeTargetUrl('example.com').href, 'https://example.com/');
  assert.throws(() => normalizeTargetUrl('ftp://example.com'));
  assert.throws(() => normalizeTargetUrl('https://user:pw@example.com'));
  assert.throws(() => normalizeTargetUrl('https://example.com:22/'));
});

// 2. 置き忘れファイル・情報漏えい
import { extractPhpVersions, assessPhpVersion } from '../php-version.js';
import { item, looksLikeHtml, describeResponse } from '../util.js';

function detectPhpinfo(body) {
  const isPhpinfo = /<title>\s*phpinfo\(\)\s*<\/title>/i.test(body)
    || (/PHP Version \d/.test(body) && /(PHP License|Zend Engine|Configuration File \(php\.ini\) Path)/i.test(body));
  if (!isPhpinfo) return null;
  const v = body.match(/PHP Version (\d+\.\d+\.\d+[^\s<]*)/);
  return { detail: `phpinfo() のページが表示されます${v ? `（PHP ${v[1]}）` : ''}`, phpVersionText: v ? `PHP/${v[1]}` : null };
}

function detectEnv(body) {
  if (looksLikeHtml(body)) return null;
  const keys = [...body.matchAll(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=/gm)].map((m) => m[1]);
  if (keys.length < 2) return null;
  return { detail: `環境変数ファイルの内容が返されます。キー: ${[...new Set(keys)].slice(0, 12).join(', ')}${keys.length > 12 ? ' …' : ''}（値は表示していません）` };
}

function detectPhpSource(body) {
  if (!/<\?php/.test(body) && !/define\s*\(\s*['"]DB_/.test(body)) return null;
  const defines = [...body.matchAll(/define\s*\(\s*['"]([A-Z_]+)['"]/g)].map((m) => m[1]);
  const vars = [...body.matchAll(/\$(?:CFG->)?(db\w*|password|dbpass|dbuser|dbhost)\b/gi)].map((m) => m[1]);
  const names = [...new Set([...defines, ...vars])].slice(0, 10);
  return { detail: `PHPソースコードがそのまま返されます（${body.length} bytes）${names.length ? `。含まれる設定名: ${names.join(', ')}` : ''}（値は表示していません）` };
}

function detectGitHead(body) {
  const m = body.match(/^ref:\s*(refs\/\S+)/m) || body.match(/^([0-9a-f]{40})\s*$/m);
  return m ? { detail: `.git/HEAD が読めます（${m[1]}）。リポジトリ全体（ソース・履歴・設定）の取得が可能な恐れがあります` } : null;
}

function tryJson(body) {
  try { return JSON.parse(body); } catch { return null; }
}

function packagesFrom(json) {
  const list = Array.isArray(json) ? json : [...(json?.packages || []), ...(json?.['packages-dev'] || [])];
  return list.filter((p) => p && p.name).map((p) => ({ name: p.name, version: p.version || '' }));
}

function detectComposerJson(body) {
  const json = tryJson(body);
  if (!json || typeof json !== 'object' || !(json.require || json.name || json.autoload)) return null;
  const req = Object.entries(json.require || {}).slice(0, 15).map(([k, v]) => `${k} ${v}`);
  return { detail: `composer.json が読めます${req.length ? `。require: ${req.join(', ')}` : ''}` };
}

function detectComposerPackages(body) {
  const json = tryJson(body);
  if (!json) return null;
  const pkgs = packagesFrom(json);
  if (!pkgs.length) return null;
  return { detail: `依存パッケージ ${pkgs.length} 件とバージョンが読めます`, packages: pkgs };
}

function detectDirListing(body) {
  if (!/<title>\s*Index of \//i.test(body) && !/<h1>\s*Index of \//i.test(body) && !/Directory listing for/i.test(body)) return null;
  const entries = (body.match(/<a\s[^>]*href=/gi) || []).length;
  return { detail: `ディレクトリ一覧（Index of）が表示されます（リンク約 ${entries} 件）` };
}

function detectServerStatus(body) {
  return /Apache Server Status for/i.test(body) ? { detail: 'Apache の server-status が外部から表示されます（アクセス中のURL・クライアントIPが見えます）' } : null;
}

function detectServerInfo(body) {
  return /Apache Server Information/i.test(body) ? { detail: 'Apache の server-info（モジュール・設定内容）が外部から表示されます' } : null;
}

function detectMoodleEnvironment(body) {
  if (/id=["']login|login\/index\.php/i.test(body) && !/environmenttable/i.test(body)) return null;
  return /environmenttable|id=["']serverstatus|Server checks|サーバチェック/i.test(body)
    ? { detail: 'Moodle の環境ページがログインなしで表示されます' } : null;
}

export function probeGroups(ctx) {
  const moodleBase = ctx.cms?.moodle ? ctx.cms.moodlePath : null;
  return [
    { id: 'phpinfo', title: 'phpinfo() の置き忘れ', paths: ['/phpinfo.php', '/info.php', '/test.php', '/php.php', '/i.php'], detect: detectPhpinfo },
    { id: 'apache-status', title: 'Apache のステータスページ', paths: ['/server-status', '/server-info'], detect: (b, p) => (p.endsWith('status') ? detectServerStatus(b) : detectServerInfo(b)) },
    { id: 'config', title: '環境変数・設定ファイル', paths: ['/.env', '/config.php.bak', '/config.php~', '/wp-config.php.bak'], detect: (b, p) => (p === '/.env' ? detectEnv(b) : detectPhpSource(b)) },
    { id: 'git', title: 'Git リポジトリの公開', paths: ['/.git/HEAD'], detect: detectGitHead },
    { id: 'composer', title: 'Composer の依存情報', paths: ['/composer.json', '/composer.lock', '/vendor/composer/installed.json'], detect: (b, p) => (p === '/composer.json' ? detectComposerJson(b) : detectComposerPackages(b)) },
    { id: 'dirlist', title: 'ディレクトリリスティング', paths: ['/uploads/', '/backup/', '/vendor/'], detect: detectDirListing },
    moodleBase !== null && {
      id: 'moodle-admin', title: 'CMS/LMS の管理画面（Moodle）',
      paths: [`${moodleBase}/admin/phpinfo.php`, `${moodleBase}/admin/environment.php`],
      detect: (b, p) => (p.endsWith('phpinfo.php') ? detectPhpinfo(b) : detectMoodleEnvironment(b)),
    },
  ].filter(Boolean);
}

export async function checkExposure(ctx) {
  const items = [];
  const softBody = ctx.notFound?.status === 200 ? ctx.notFound.body : null;
  for (const group of probeGroups(ctx)) {
    const results = await Promise.all(group.paths.map(async (path) => {
      const res = await ctx.fetch(path, { maxBytes: 256 * 1024, probe: true });
      let hit = null;
      if (!res.error && res.status === 200 && res.body && res.body !== softBody) hit = group.detect(res.body, path);
      return { path, res, hit };
    }));
    const hits = results.filter((r) => r.hit);
    for (const h of hits) {
      if (h.hit.phpVersionText) {
        for (const v of extractPhpVersions(h.hit.phpVersionText)) {
          ctx.phpFindings.push({ source: `phpinfo ${h.path}`, version: v, assessment: assessPhpVersion(v) });
        }
      }
      if (h.hit.packages) ctx.composerPackages = h.hit.packages;
    }
    const forbidden = results.filter((r) => r.res.status === 403 || r.res.status === 401).map((r) => r.path);
    const evidence = results.map((r) => `GET ${r.path} → ${describeResponse(r.res)}${r.hit ? '  ★検出' : ''}`).join('\n');
    if (hits.length) {
      items.push(item(group.id, group.title, 'danger',
        hits.map((h) => `${h.path}: ${h.hit.detail}`).join(' / '),
        { evidence, hint: 'パッチ状況とは無関係に即対応が必要です。運用側に報告し、ファイルの削除またはアクセス制限を依頼してください。' }));
    } else {
      let summary = '外部から読める状態ではありませんでした。';
      if (forbidden.length) summary += ` ${forbidden.join(', ')} は 401/403（存在はするがアクセス制限あり、または一律拒否）。`;
      items.push(item(group.id, group.title, 'ok', summary, { evidence }));
    }
  }
  if (!ctx.cms?.moodle) {
    items.push(item('moodle-admin', 'CMS/LMS の管理画面', 'info',
      'Moodle は検出されなかったため、Moodle 管理画面の確認は省略しました。',
      { hint: 'その他の CMS/LMS では、管理用ページ（phpinfo・環境情報）をログアウト状態で開き、ログインを求められることを確認してください。' }));
  }
  return items;
}

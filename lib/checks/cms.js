// 5. CMS/LMS/ライブラリのバージョン
import { item, extractMetaGenerators, extractScriptSrcs, sameOriginUrls, compareVersions, describeResponse, worstStatus } from '../util.js';

const MAX_PLUGINS = 8;

/** トップページから CMS を推定し、設置パスも求める */
export function detectCms(html, setCookies = [], baseUrl) {
  const s = String(html || '');
  const cms = {};
  const gens = extractMetaGenerators(s).join(' ');
  const wp = s.match(/((?:https?:)?\/\/[^"'\s]+?|)(\/[^"'\s]*?)?\/wp-(?:content|includes)\//i);
  if (wp || /WordPress/i.test(gens)) {
    cms.wordpress = true;
    cms.wordpressPath = '';
    if (wp && baseUrl) {
      try {
        const u = new URL(`${wp[1] || ''}${wp[2] || ''}/`, baseUrl);
        if (u.origin === new URL(baseUrl).origin) cms.wordpressPath = u.pathname.replace(/\/$/, '');
      } catch { /* 無視 */ }
    }
  }
  const moodleCookie = setCookies.some((l) => /^MoodleSession/i.test(l));
  const wwwroot = s.match(/"wwwroot"\s*:\s*"([^"]+)"/);
  if (moodleCookie || wwwroot || /docs\.moodle\.org|\bM\.cfg\b/.test(s) || /Moodle/i.test(gens)) {
    cms.moodle = true;
    cms.moodlePath = '';
    if (wwwroot && baseUrl) {
      try {
        const u = new URL(wwwroot[1].replace(/\\\//g, '/'));
        if (u.origin === new URL(baseUrl).origin) cms.moodlePath = u.pathname.replace(/\/$/, '');
      } catch { /* 無視 */ }
    }
  }
  if (/Joomla/i.test(gens)) cms.joomla = true;
  if (/Drupal/i.test(gens) || /drupal-settings-json|\/sites\/default\/files\//.test(s)) cms.drupal = true;
  return cms;
}

/** docs.moodle.org/405/... の数字をブランチ表記にする */
export function moodleBranch(code) {
  const c = String(code);
  if (c.length === 2) return `${c[0]}.${c[1]}`;
  return `${c[0]}.${parseInt(c.slice(1), 10)}`;
}

/** script src から JS ライブラリとバージョンを拾う */
export function detectJsLibraries(srcs) {
  const libs = [];
  for (const src of srcs) {
    let m;
    if ((m = src.match(/jquery[.-]v?(\d+\.\d+(?:\.\d+)?)(?:\.slim)?(?:\.min)?\.js/i))
      || (m = src.match(/\/jquery\/(\d+\.\d+(?:\.\d+)?)\//i))
      || (m = src.match(/jquery(?:\.slim)?(?:\.min)?\.js\?(?:.*&)?ver=(\d+\.\d+(?:\.\d+)?)/i))) {
      if (!/jquery[.-]?(ui|migrate)/i.test(src)) { libs.push({ name: 'jQuery', version: m[1], src }); continue; }
    }
    if ((m = src.match(/\/([a-z][a-z0-9_.-]*?)[.-]v?(\d+\.\d+\.\d+)(?:\.min)?\.js/i))) {
      libs.push({ name: m[1], version: m[2], src });
    } else if ((m = src.match(/\/(?:npm\/)?([a-z][a-z0-9_.-]*)@(\d+\.\d+\.\d+)/i)) || (m = src.match(/cdnjs\.cloudflare\.com\/ajax\/libs\/([^/]+)\/(\d+\.\d+\.\d+)\//i))) {
      libs.push({ name: m[1], version: m[2], src });
    }
  }
  const seen = new Set();
  return libs.filter((l) => { const k = `${l.name}@${l.version}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

export async function checkCms(ctx) {
  const items = [];
  const html = ctx.html;
  const cms = ctx.cms;

  // 5-1 generator タグ
  const gens = extractMetaGenerators(html);
  if (gens.length) {
    const versioned = gens.filter((g) => /\d+\.\d+/.test(g));
    items.push(item('generator', 'ページの generator タグ', versioned.length ? 'warn' : 'info',
      versioned.length ? 'generator タグにバージョン付きの製品名が表示されています。各製品のセキュリティ情報と照合してください。' : 'generator タグはありますがバージョンは表示されていません。',
      { evidence: gens.map((g) => `<meta name="generator" content="${g}">`).join('\n') }));
  } else {
    items.push(item('generator', 'ページの generator タグ', 'ok', 'generator タグはありません。'));
  }

  // 5-2 WordPress 本体
  if (cms.wordpress) {
    const base = cms.wordpressPath;
    const [readme, wpjson, users] = await Promise.all([
      ctx.fetch(`${base}/readme.html`, { maxBytes: 64 * 1024 }),
      ctx.fetch(`${base}/wp-json/`, { maxBytes: 64 * 1024 }),
      ctx.fetch(`${base}/wp-json/wp/v2/users`, { maxBytes: 128 * 1024 }),
    ]);
    const findings = [];
    const statuses = [];
    const readmeVer = readme.status === 200 && readme.body?.match(/Version\s+(\d+\.\d+(?:\.\d+)?)/i);
    if (readmeVer) { findings.push(`readme.html からバージョン ${readmeVer[1]} が読めます`); statuses.push('warn'); }
    else if (readme.status === 200 && /WordPress/i.test(readme.body || '')) { findings.push('readme.html が公開されています（バージョン表記なし）'); statuses.push('info'); }
    const verParam = html.match(/wp-(?:includes|emoji)[^"']*\?ver=(\d+\.\d+(?:\.\d+)?)/i);
    if (verParam) { findings.push(`静的ファイルの ?ver= から ${verParam[1]} と推定できます`); statuses.push('warn'); }
    let userList = null;
    if (users.status === 200) {
      try { const j = JSON.parse(users.body); if (Array.isArray(j) && j.length) userList = j.map((u) => u.slug || u.name).filter(Boolean); } catch { /* 無視 */ }
    }
    if (userList) { findings.push(`REST API でユーザー一覧が取得できます（${userList.length} 件: ${userList.slice(0, 5).join(', ')}${userList.length > 5 ? ' …' : ''}）`); statuses.push('warn'); }
    if (wpjson.status === 200) findings.push('REST API (/wp-json/) は公開されています');
    items.push(item('wordpress', 'WordPress 本体', worstStatus(statuses, 'ok'),
      findings.length ? findings.join('。') + '。' : 'readme.html やユーザー一覧は読めませんでした。',
      { evidence: [readme, wpjson, users].map((r) => `GET ${r.url} → ${describeResponse(r)}`).join('\n'),
        hint: userList ? 'ユーザー名はブルートフォースの足がかりになります。/wp-json/wp/v2/users を未ログイン時に制限してください。' : 'バージョンは WordPress のセキュリティリリース情報と照合してください。' }));

    // 5-3 WordPress プラグイン
    const slugs = [...new Set([...html.matchAll(/\/wp-content\/plugins\/([a-z0-9_-]+)\//gi)].map((m) => m[1].toLowerCase()))].slice(0, MAX_PLUGINS);
    if (slugs.length) {
      const lines = [];
      let readable = 0;
      for (const slug of slugs) {
        const r = await ctx.fetch(`${base}/wp-content/plugins/${slug}/readme.txt`, { maxBytes: 32 * 1024 });
        const tag = r.status === 200 && r.body?.match(/Stable tag:\s*([^\s]+)/i);
        if (tag) readable++;
        lines.push(`${slug}: ${tag ? `Stable tag ${tag[1]}` : describeResponse(r)}  https://wpscan.com/plugin/${slug}`);
      }
      items.push(item('wp-plugins', 'WordPress プラグイン', readable ? 'warn' : 'info',
        `ソース中からプラグイン ${slugs.length} 件を検出しました${readable ? `。うち ${readable} 件は readme.txt からバージョンが読めます。既知の脆弱バージョンでないか照合してください` : ''}。`,
        { evidence: lines.join('\n'), hint: 'WPScan や Patchstack の脆弱性データベースで各プラグインのバージョンを照合してください。' }));
    } else {
      items.push(item('wp-plugins', 'WordPress プラグイン', 'info', 'トップページのソースからプラグインは検出されませんでした。'));
    }
  } else {
    items.push(item('wordpress', 'WordPress', 'info', 'WordPress は検出されませんでした。'));
  }

  // 5-4 Moodle
  if (cms.moodle) {
    const m = html.match(/docs\.moodle\.org\/(\d{2,3})\//);
    if (m) {
      const branch = moodleBranch(m[1]);
      const eol = compareVersions(branch, '4.5') < 0;
      items.push(item('moodle', 'Moodle', eol ? 'danger' : 'info',
        eol ? `Moodle ${branch} はサポート終了ブランチです。` : `Moodle ${branch} 系です。セキュリティ修正の適用状況をリリース情報と照合してください。`,
        { evidence: `docs.moodle.org/${m[1]}/`, hint: 'https://moodledev.io/general/releases でサポート期間とセキュリティリリースを確認してください。' }));
    } else {
      items.push(item('moodle', 'Moodle', 'manual', 'Moodle を検出しましたが、バージョンは読み取れませんでした。',
        { hint: 'ログイン後のページ下部「このページの Moodle Docs」リンク先URLの数字（docs.moodle.org/405/... → 4.5）でバージョンを確認してください。' }));
    }
  }

  // 5-5 JS ライブラリ
  const srcs = extractScriptSrcs(html);
  const libs = detectJsLibraries(srcs);
  if (!libs.some((l) => l.name === 'jQuery')) {
    // ファイル名にバージョンがない同一オリジンの jQuery は先頭のバナーを読む
    const jq = sameOriginUrls(srcs.filter((s) => /jquery(\.min)?\.js/i.test(s) && !/jquery[.-]?(ui|migrate)/i.test(s)), ctx.base.href)[0];
    if (jq) {
      const r = await ctx.fetch(jq, { maxBytes: 2048 });
      const v = r.body?.match(/jQuery (?:JavaScript Library )?v?(\d+\.\d+\.\d+)/i);
      if (v) libs.unshift({ name: 'jQuery', version: v[1], src: jq });
    }
  }
  if (libs.length) {
    const statuses = [];
    const lines = libs.map((l) => {
      const vulnerable = l.name === 'jQuery' && compareVersions(l.version, '3.5.0') < 0;
      statuses.push(vulnerable ? 'danger' : 'info');
      return `${l.name} ${l.version}${vulnerable ? '  ← 3.5.0 未満（CVE-2020-11022/11023 などXSSの既知脆弱性）' : ''}\n  ${l.src}`;
    });
    const status = worstStatus(statuses);
    items.push(item('js-libs', 'JSライブラリ', status,
      status === 'danger' ? '既知の脆弱性があるバージョンのJSライブラリが使われています。' : `バージョンが読めるJSライブラリが ${libs.length} 件あります。既知の脆弱性がないか照合してください。`,
      { evidence: lines.join('\n') }));
  } else {
    items.push(item('js-libs', 'JSライブラリ', 'info', 'ファイル名からバージョンを読めるJSライブラリは見つかりませんでした。',
      { hint: 'ブラウザの Console で `jQuery.fn.jquery` を実行すると jQuery のバージョンを確認できます。' }));
  }

  // 5-6 PHP ライブラリ
  if (ctx.composerPackages?.length) {
    items.push(item('php-libs', 'PHPライブラリ', 'danger',
      `composer.lock / installed.json が読めるため、使用ライブラリ ${ctx.composerPackages.length} 件のバージョンが外部から分かります（ファイルが読めること自体が要対応）。`,
      { evidence: ctx.composerPackages.slice(0, 40).map((p) => `${p.name} ${p.version}`).join('\n') + (ctx.composerPackages.length > 40 ? '\n…' : ''),
        hint: '`composer audit` や Packagist / GitHub Advisory Database で脆弱性を照合し、ファイルへのアクセスを禁止してください。' }));
  } else {
    items.push(item('php-libs', 'PHPライブラリ', 'ok', 'composer.lock 等は外部から読めませんでした（正常）。'));
  }

  return items;
}

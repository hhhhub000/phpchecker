// 1. バージョン露出
import { extractPhpVersions, assessPhpVersion, isDistroBuild, FIXED_VERSIONS, CVE_IDS } from '../php-version.js';
import { item, worstStatus, extractFormActions, extractLinks, sameOriginUrls, describeResponse } from '../util.js';

const MAX_ENDPOINTS = 5;

function recordPhp(ctx, source, text, ignoreRaws = []) {
  const versions = extractPhpVersions(text).filter((v) => !ignoreRaws.includes(v.raw));
  for (const v of versions) {
    const assessment = assessPhpVersion(v);
    ctx.phpFindings.push({ source, version: v, assessment });
  }
  return versions.map((v) => ({ version: v, assessment: assessPhpVersion(v) }));
}

const fixedList = Object.entries(FIXED_VERSIONS).map(([b, p]) => `${b}.${p}`).join(' / ');

export async function checkVersion(ctx) {
  const items = [];
  const top = ctx.top;

  // 1-1 X-Powered-By
  const xpb = top.headers['x-powered-by'];
  if (xpb) {
    const found = recordPhp(ctx, 'トップページ X-Powered-By', xpb);
    if (found.length) {
      items.push(item('xpb', 'X-Powered-By ヘッダー', worstStatus(found.map((f) => f.assessment.status)),
        found.map((f) => f.assessment.message).join(' / '),
        { evidence: `X-Powered-By: ${xpb}`, hint: `PHP2Shell 修正版: ${fixedList}（8.1以前は公式修正なし）。あわせて expose_php = Off でバージョン非表示化を推奨。` }));
    } else {
      items.push(item('xpb', 'X-Powered-By ヘッダー', 'info',
        'X-Powered-By ヘッダーはありますが、PHPのバージョンは含まれていません。',
        { evidence: `X-Powered-By: ${xpb}` }));
    }
  } else {
    items.push(item('xpb', 'X-Powered-By ヘッダー', 'unknown',
      'X-Powered-By ヘッダーは出ていません。非表示は推奨設定ですが、パッチ適用状況は外部からは判定できません。',
      { hint: '管理者権限で phpinfo を確認するか、運用側にバージョンを確認してください。' }));
  }

  // 1-2 Server
  const server = top.headers.server;
  if (server) {
    const found = recordPhp(ctx, 'トップページ Server', server);
    const showsVersion = /\/\d/.test(server);
    let status = showsVersion ? 'warn' : 'ok';
    let summary = showsVersion
      ? 'Server ヘッダーにソフトウェアのバージョンが表示されています。'
      : 'Server ヘッダーにバージョン番号は含まれていません。';
    if (found.length) {
      status = worstStatus([status, ...found.map((f) => f.assessment.status)]);
      summary += ' ' + found.map((f) => f.assessment.message).join(' / ');
    }
    items.push(item('server', 'Server ヘッダー', status, summary, {
      evidence: `Server: ${server}`,
      hint: showsVersion ? 'Apache なら ServerTokens Prod、nginx なら server_tokens off で非表示にできます。' : undefined,
    }));
  } else {
    items.push(item('server', 'Server ヘッダー', 'ok', 'Server ヘッダーは出ていません。'));
  }

  // 1-3 ページ以外のエンドポイント
  const candidates = sameOriginUrls([
    ...extractFormActions(ctx.html).filter((a) => a !== ''),
    ...extractLinks(ctx.html).filter((l) => /\.php(\?|$)|\/api\/|\/ajax/i.test(l)),
  ], ctx.base.href).filter((u) => u !== top.url).slice(0, MAX_ENDPOINTS);

  if (candidates.length) {
    const lines = [];
    const statuses = [];
    const topPhp = extractPhpVersions(`${xpb || ''} ${server || ''}`).map((v) => v.raw);
    const differing = [];
    for (const url of candidates) {
      let res = await ctx.fetch(url, { method: 'HEAD' });
      if (res.error || res.status === 405 || res.status === 501) res = await ctx.fetch(url, { maxBytes: 64 * 1024 });
      const hx = res.headers?.['x-powered-by'];
      const hs = res.headers?.server;
      // トップページと同じバージョンは 1-1/1-2 で評価済みなので、異なるものだけ評価する
      const found = recordPhp(ctx, `エンドポイント ${url}`, `${hx || ''} ${hs || ''}`, topPhp);
      statuses.push(...found.map((f) => f.assessment.status));
      for (const f of found) differing.push(`${url} → PHP ${f.version.raw}`);
      lines.push(`${res.method} ${url} → ${describeResponse(res)}${hx ? ` / X-Powered-By: ${hx}` : ''}${hs ? ` / Server: ${hs}` : ''}`);
    }
    let status = worstStatus(statuses, 'ok');
    let summary = `ページ内のフォーム送信先・PHP/APIエンドポイント ${candidates.length} 件のヘッダーを確認しました。`;
    if (differing.length) {
      status = worstStatus([status, 'warn']);
      summary += ` トップページと異なるPHPバージョンが見つかりました（別のFPMプールや別サーバーの可能性）: ${differing.join(', ')}`;
    } else {
      summary += topPhp.length ? ' トップページと異なるPHPバージョンは見つかりませんでした。' : ' PHPバージョンは表示されていません。';
    }
    items.push(item('endpoints', 'ページ以外のエンドポイント', status, summary, { evidence: lines.join('\n') }));
  } else {
    items.push(item('endpoints', 'ページ以外のエンドポイント', 'manual',
      'トップページからフォーム送信先やAPIエンドポイントが見つかりませんでした。',
      { hint: 'ブラウザで F12 → Network → Fetch/XHR を開き、各リクエストのレスポンスヘッダーに X-Powered-By が出ていないか確認してください。ログイン後のページのURLを入力して再チェックするのも有効です。' }));
  }

  // 1-4 エラーページのフッター
  const nf = ctx.notFound;
  if (nf && !nf.error) {
    const body = nf.body || '';
    const sig = body.match(/<address>([^<]*)<\/address>/i) || body.match(/((?:Apache|nginx|LiteSpeed|Microsoft-IIS|openresty)\/[\d.]+[^<\n]{0,80})/i);
    const topPhp = extractPhpVersions(`${xpb || ''} ${server || ''}`).map((v) => v.raw);
    const nfPhp = recordPhp(ctx, '404ページ ヘッダー', `${nf.headers['x-powered-by'] || ''} ${nf.headers.server || ''}`, topPhp);
    const statuses = [sig ? 'warn' : 'ok', ...nfPhp.map((f) => f.assessment.status)];
    let summary = sig
      ? '404ページにサーバー署名（ソフトウェア名・バージョン）が表示されています（ServerSignature On など）。'
      : '404ページにサーバー署名は見当たりません。';
    if (nf.status === 200) summary += ' なお、存在しないURLでも HTTP 200 が返ります（ソフト404）。';
    if (nfPhp.length) summary += ' トップページと異なるPHPバージョンが出ています: ' + nfPhp.map((f) => f.assessment.message).join(' / ');
    items.push(item('errorpage', 'エラーページのフッター', worstStatus(statuses), summary, {
      evidence: `GET ${nf.url} → HTTP ${nf.status}${sig ? `\n署名: ${sig[1].trim()}` : ''}`,
      hint: sig ? 'Apache なら ServerSignature Off、nginx なら server_tokens off を設定してください。' : undefined,
    }));
  } else {
    items.push(item('errorpage', 'エラーページのフッター', 'unknown', `404ページを取得できませんでした（${nf?.error || '未取得'}）。`));
  }

  // 1-5 ディストリのビルド表記
  const distro = ctx.phpFindings.filter((f) => isDistroBuild(f.version));
  if (distro.length) {
    const raws = [...new Set(distro.map((f) => f.version.raw))];
    items.push(item('distro', 'ディストリのビルド表記', 'manual',
      `ディストリビューションのビルド表記が見えます: ${raws.join(', ')}。番号が古いだけでは判断できません。`,
      { hint: `Ubuntu/Debian/RHEL 等のセキュリティ情報で ${CVE_IDS.join(' / ')} の修正ビルド番号を確認し、それ未満なら要対応です。` }));
  } else if (ctx.phpFindings.length) {
    items.push(item('distro', 'ディストリのビルド表記', 'info', '表示されているPHPバージョンにディストリのビルド表記はありません（公式ビルドとして判定しています）。'));
  } else {
    items.push(item('distro', 'ディストリのビルド表記', 'unknown', 'PHPバージョンが表示されていないため判定できません。'));
  }

  return items;
}

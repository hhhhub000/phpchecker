// 診断全体の実行順序と、8章「判定の読み方」に沿った総合判定。
import { ScanContext } from './context.js';
import { checkVersion } from './checks/version.js';
import { checkExposure } from './checks/exposure.js';
import { checkErrors } from './checks/errors.js';
import { checkCookies } from './checks/cookies.js';
import { checkCms, detectCms } from './checks/cms.js';
import { checkTransport } from './checks/transport.js';
import { setCookieLines, worstStatus } from './util.js';
import { FIXED_VERSIONS, CVE_IDS } from './php-version.js';

export const DEFAULT_OPTIONS = { exposure: true, errors: true, cms: true, tls: true };

export const SECTIONS = [
  { id: 'version', title: '1. バージョン露出', run: (ctx) => checkVersion(ctx) },
  { id: 'exposure', title: '2. 置き忘れファイル・情報漏えい', option: 'exposure', run: (ctx) => checkExposure(ctx) },
  { id: 'errors', title: '3. エラー表示・設定の露出', option: 'errors', run: (ctx) => checkErrors(ctx) },
  { id: 'cookies', title: '4. セッション・Cookie', run: (ctx) => checkCookies(ctx) },
  { id: 'cms', title: '5. CMS/LMS/ライブラリのバージョン', option: 'cms', run: (ctx) => checkCms(ctx) },
  { id: 'transport', title: '6. 通信・HTTPヘッダー全般', run: (ctx, opts) => checkTransport(ctx, { tls: opts.tls, ...(opts.tlsProbe && { probe: opts.tlsProbe }) }) },
];

/** 入力 URL を検証・正規化する。問題があれば Error を投げる */
export function normalizeTargetUrl(input, { allowAnyPort = false } = {}) {
  let s = String(input || '').trim();
  if (!s) throw new Error('URLを入力してください');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let u;
  try { u = new URL(s); } catch { throw new Error('URLの形式が正しくありません'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('http:// または https:// のURLを入力してください');
  if (u.username || u.password) throw new Error('認証情報を含むURLは使用できません');
  if (!u.hostname) throw new Error('ホスト名がありません');
  if (!allowAnyPort && u.port && !['80', '443', '8000', '8080', '8443', '8888'].includes(u.port)) {
    throw new Error('ポートは 80 / 443 / 8000 / 8080 / 8443 / 8888 のみ指定できます');
  }
  u.hash = '';
  return u;
}

const PHP2SHELL_HEADLINE = {
  danger: '影響を受ける可能性が高い',
  warn: 'ディストリ版のため要確認',
  unknown: '判定不能',
  ok: '修正版以上（表示上）',
};

/** PHP2Shell (CVE-2026-109618 / 109619) の判定。表示されている PHP バージョンだけを根拠にする */
export function buildPhp2Shell(ctx) {
  const findings = [];
  const seen = new Set();
  for (const f of ctx.phpFindings) {
    const key = `${f.source}|${f.version.raw}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push({ source: f.source, version: f.version.raw, status: f.assessment.status, message: f.assessment.message });
  }
  const fixedVersions = Object.entries(FIXED_VERSIONS).map(([branch, patch]) => ({ branch, fixed: `${branch}.${patch}` }));
  const base = { cves: CVE_IDS, fixedVersions, findings };
  if (!findings.length) {
    return {
      ...base,
      status: 'unknown',
      headline: 'PHPのバージョンが見えないため判定不能',
      detail: 'レスポンスヘッダー・404ページ・phpinfo の置き忘れなど、外部から見える場所にPHPのバージョンが出ていません。バージョンを隠すのは推奨設定ですが、パッチが当たっているかどうかは外部からは判断できません。',
      action: '管理者権限で phpinfo を確認するか、運用側にPHPのバージョン（ディストリ版はパッケージのバージョン）と修正適用の有無を確認してください。',
    };
  }
  const status = worstStatus(findings.map((f) => f.status));
  const versions = [...new Set(findings.map((f) => f.version))];
  const messages = [...new Set(findings.filter((f) => f.status === status).map((f) => f.message))];
  const action = {
    danger: '運用側にパッケージ変更履歴（CVE番号の有無）と適用日時、適用後の PHP-FPM / Apache 再起動の有無を至急確認してください。修正版へ更新するまでの間はログの監視を強化し、あわせてバージョン非表示化（expose_php = Off）を依頼してください。',
    warn: 'ディストリのバックポートで修正済みの可能性があります。Ubuntu / Debian / RHEL 等のセキュリティ情報で修正ビルド番号を確認し、それ未満なら要対応です。運用側にパッケージ変更履歴と再起動状況を確認してください。',
    unknown: '修正版の対応表にないブランチです。PHP の公式セキュリティ情報で該当ブランチの修正状況を確認してください。',
    ok: '表示されているバージョンは修正版以上です。ただし表示値が実際に稼働中のプロセスと一致するとは限らないため、修正適用後に PHP-FPM / Apache を再起動したかを運用側に確認してください。',
  }[status];
  return { ...base, status, headline: PHP2SHELL_HEADLINE[status], versions, detail: messages.join(' / '), action };
}

/** PHP2Shell 以外のチェック結果を 8 章の判定表に沿ってまとめる */
export function buildVerdicts(sections) {
  const verdicts = [];
  const byId = Object.fromEntries(sections.map((s) => [s.id, s]));
  const exposed = (byId.exposure?.items || []).filter((i) => i.status === 'danger');
  if (exposed.length) {
    verdicts.push({
      status: 'danger',
      title: '2章のファイルが見える',
      detail: exposed.map((i) => i.title).join('、'),
      action: 'パッチ状況と無関係に即対応が必要です。運用側にすぐ報告し、削除・アクセス制限を依頼してください。',
    });
  }
  const others = sections
    .filter((s) => ['errors', 'cookies', 'cms', 'transport'].includes(s.id))
    .flatMap((s) => s.items.filter((i) => i.status === 'danger' || i.status === 'warn').map((i) => ({ ...i, section: s.title })));
  if (others.length) {
    verdicts.push({
      status: worstStatus(others.map((o) => o.status)),
      title: '3〜6章で問題が見える',
      detail: others.map((o) => `${o.section.replace(/^\d+\.\s*/, '')}: ${o.title}`).join('、'),
      action: 'PHP2Shell とは別の脆弱性・設定不備です。優先度をつけて運用側に報告してください。',
    });
  }
  if (!verdicts.some((v) => v.status === 'danger' || v.status === 'warn')) {
    verdicts.push({
      status: 'ok',
      title: 'それ以外のチェックでは外から見える兆候がない',
      detail: '安全の証明ではありません。手動確認の項目も実施してください。',
      action: '内部での最終確認（パッケージ変更履歴・プロセス再起動）を省略しないでください。',
    });
  }
  return verdicts;
}

/**
 * 診断を実行する。onEvent には start / section / done / error イベントが順に渡される。
 */
export async function runScan(input, { options = {}, onEvent = () => {}, contextOptions = {} } = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const target = input instanceof URL ? input : normalizeTargetUrl(input);
  const ctx = new ScanContext(target.href, contextOptions);
  const started = Date.now();

  const top = await ctx.fetchFollow(target.href, { maxBytes: 2 * 1024 * 1024 });
  if (top.error) throw new Error(`対象URLに接続できませんでした: ${top.error}`);
  ctx.top = top;
  ctx.base = new URL(top.url);
  ctx.html = top.body || '';
  const rand = Math.random().toString(36).slice(2, 10);
  ctx.notFound = await ctx.fetch(`/no-such-page-test-${rand}`, { maxBytes: 256 * 1024 });
  const cookieLines = (top.chain || [top]).flatMap((r) => setCookieLines(r.headers));
  ctx.cms = detectCms(ctx.html, cookieLines, ctx.base.href);

  onEvent({
    type: 'start',
    target: target.href,
    finalUrl: top.url,
    redirects: (top.chain || []).slice(0, -1).map((r) => `${r.url} → HTTP ${r.status}`),
    status: top.status,
    cms: ctx.cms,
    sections: SECTIONS.map((s) => ({ id: s.id, title: s.title, skipped: s.option ? !opts[s.option] : false })),
  });

  const sections = [];
  for (const section of SECTIONS) {
    let result;
    if (section.option && !opts[section.option]) {
      result = { id: section.id, title: section.title, skipped: true, items: [] };
    } else {
      try {
        result = { id: section.id, title: section.title, items: await section.run(ctx, opts) };
      } catch (err) {
        result = { id: section.id, title: section.title, error: err.message, items: [] };
      }
    }
    sections.push(result);
    onEvent({ type: 'section', section: result });
  }

  const summary = {
    type: 'done',
    php2shell: buildPhp2Shell(ctx),
    verdicts: buildVerdicts(sections),
    requestCount: ctx.requestCount,
    requests: ctx.log,
    elapsedMs: Date.now() - started,
    finishedAt: new Date().toISOString(),
  };
  onEvent(summary);
  return { sections, ...summary };
}

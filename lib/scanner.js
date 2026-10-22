// 診断全体の実行順序と、8章「判定の読み方」に沿った総合判定。
import { ScanContext } from './context.js';
import { checkVersion } from './checks/version.js';
import { checkExposure } from './checks/exposure.js';
import { checkErrors } from './checks/errors.js';
import { checkCookies } from './checks/cookies.js';
import { checkCms, detectCms } from './checks/cms.js';
import { checkTransport } from './checks/transport.js';
import { setCookieLines, worstStatus } from './util.js';

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

/** 8章の判定表に沿って次のアクションをまとめる */
export function buildVerdicts(sections, ctx) {
  const verdicts = [];
  const byId = Object.fromEntries(sections.map((s) => [s.id, s]));
  const php = ctx.phpFindings;
  const vulnerable = php.filter((f) => f.assessment.status === 'danger' || f.assessment.status === 'warn');
  if (vulnerable.length) {
    verdicts.push({
      status: 'danger',
      title: '脆弱なバージョンが見える',
      detail: `${[...new Set(vulnerable.map((f) => f.assessment.message))].join(' / ')}。影響範囲内の可能性が高い一方、ディストリのバックポートで修正済みのこともあります。`,
      action: '運用側にパッケージ変更履歴（CVE番号の有無）と再起動状況を確認し、あわせてバージョン非表示化を依頼してください。',
    });
  } else if (!php.length) {
    verdicts.push({
      status: 'unknown',
      title: 'バージョンが表示されない（判定不能）',
      detail: 'PHPのバージョンが外部から見えません。隠す設定になっているだけで、パッチ状況はわかりません。',
      action: '管理者権限で phpinfo を確認するか、運用側に確認してください。',
    });
  } else {
    verdicts.push({
      status: 'ok',
      title: '表示されているPHPバージョンは修正版以上',
      detail: `${[...new Set(php.map((f) => f.version.raw))].join(', ')}。表示値が実際の稼働プロセスと一致するとは限りません。`,
      action: '修正適用後に PHP-FPM / Apache を再起動したか運用側に確認してください。バージョン非表示化も推奨です。',
    });
  }
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
      title: '外から見える範囲には兆候がない',
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
    verdicts: buildVerdicts(sections, ctx),
    phpVersions: ctx.phpFindings.map((f) => ({ source: f.source, version: f.version.raw, status: f.assessment.status, message: f.assessment.message })),
    requestCount: ctx.requestCount,
    requests: ctx.log,
    elapsedMs: Date.now() - started,
    finishedAt: new Date().toISOString(),
  };
  onEvent(summary);
  return { sections, ...summary };
}

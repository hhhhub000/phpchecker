const STATUS_LABEL = {
  danger: '要対応',
  warn: '要確認',
  unknown: '判定不能',
  manual: '手動確認',
  info: '情報',
  ok: '問題なし',
};
const STATUS_ORDER = ['danger', 'warn', 'unknown', 'manual', 'info', 'ok'];
const CMS_LABEL = { wordpress: 'WordPress', moodle: 'Moodle', joomla: 'Joomla', drupal: 'Drupal' };

const $ = (sel) => document.querySelector(sel);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const badge = (status) => h('span', { class: `badge s-${status}` }, STATUS_LABEL[status] || status);

const form = $('#scan-form');
const submitBtn = $('#submit');
const formError = $('#form-error');
let report = null;

function showError(msg) {
  formError.textContent = msg;
  formError.hidden = !msg;
}

function renderItem(it) {
  return h('article', { class: 'check-item' },
    h('header', {}, badge(it.status), h('h3', {}, it.title)),
    h('p', {}, it.summary),
    it.evidence && h('pre', { class: 'evidence' }, it.evidence),
    it.hint && h('p', { class: 'hint' }, it.hint));
}

function renderSection(section) {
  const statuses = section.items.map((i) => i.status);
  const worst = STATUS_ORDER.find((s) => statuses.includes(s));
  return h('section', { class: 'card section-card', id: `sec-${section.id}` },
    h('h2', {}, section.title, worst && badge(worst)),
    section.skipped && h('p', { class: 'help' }, 'このチェックはスキップされました。'),
    section.error && h('p', { class: 'section-error' }, `チェック中にエラーが発生しました: ${section.error}`),
    h('div', { class: 'items' }, section.items.map(renderItem)));
}

function renderCounts() {
  const counts = {};
  for (const s of report.sections) for (const i of s.items) counts[i.status] = (counts[i.status] || 0) + 1;
  $('#counts').replaceChildren(...STATUS_ORDER.filter((s) => counts[s]).map((s) =>
    h('span', { class: `badge s-${s}` }, `${STATUS_LABEL[s]} ${counts[s]}`)));
}

function renderOverview(extra = {}) {
  const s = report.start;
  const cms = Object.keys(CMS_LABEL).filter((k) => s.cms?.[k]).map((k) => CMS_LABEL[k]);
  const rows = [
    ['対象URL', s.target],
    s.finalUrl !== s.target && ['最終URL', s.finalUrl],
    s.redirects?.length && ['リダイレクト', s.redirects.join(' / ')],
    ['ステータス', `HTTP ${s.status}`],
    ['検出したCMS/LMS', cms.length ? cms.join(', ') : '検出なし'],
    extra.requestCount !== undefined && ['送信リクエスト数', `${extra.requestCount} 件（${(extra.elapsedMs / 1000).toFixed(1)} 秒）`],
    extra.finishedAt && ['実行日時', new Date(extra.finishedAt).toLocaleString('ja-JP')],
  ].filter(Boolean);
  $('#overview').replaceChildren(...rows.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
}

function renderVerdicts(verdicts) {
  $('#verdict-list').replaceChildren(...verdicts.map((v) =>
    h('div', { class: `verdict b-${v.status}` },
      h('h4', {}, badge(v.status), v.title),
      h('p', {}, v.detail),
      h('p', { class: 'action' }, `次のアクション: ${v.action}`))));
  $('#verdicts').hidden = false;
}

const P2S_BADGE = { danger: '要対応', warn: '要確認', unknown: '判定不能', ok: '修正版以上' };

function resetPhp2Shell() {
  $('#php2shell').className = 'card php2shell s-border-pending';
  $('#p2s-badge').className = 'badge big s-info';
  $('#p2s-badge').textContent = '確認中';
  $('#p2s-headline').textContent = 'チェック中です…';
  $('#p2s-detail').textContent = '外部から見えるPHPのバージョンを集めています。';
  $('#p2s-versions').hidden = true;
  $('#p2s-preconditions').hidden = true;
  $('#p2s-action').hidden = true;
  $('#p2s-findings').hidden = true;
}

function renderPhp2Shell(p) {
  $('#php2shell').className = `card php2shell s-border-${p.status}`;
  $('#p2s-badge').className = `badge big s-${p.status}`;
  $('#p2s-badge').textContent = P2S_BADGE[p.status] || STATUS_LABEL[p.status];
  $('#p2s-headline').textContent = p.headline;
  $('#p2s-detail').textContent = p.detail;
  const versions = $('#p2s-versions');
  versions.hidden = !p.versions?.length;
  if (p.versions?.length) versions.replaceChildren('検出したPHPバージョン: ', ...p.versions.map((v) => h('strong', {}, `PHP ${v}`)));
  const pre = $('#p2s-preconditions');
  if (p.preconditions?.tested) {
    pre.hidden = false;
    pre.className = `p2s-pre b-${p.preconditions.status}`;
    pre.replaceChildren(
      h('strong', {}, '悪用の前提条件（アクティブ検査）'),
      h('ul', {}, p.preconditions.items.map((i) => h('li', {}, badge(i.status), `${i.title}: ${i.summary}`))));
  } else {
    pre.hidden = true;
  }
  const action = $('#p2s-action');
  action.hidden = false;
  action.replaceChildren(h('strong', {}, '次のアクション'), h('p', {}, p.action));
  $('#p2s-findings').hidden = !p.findings.length;
  $('#p2s-findings-body').replaceChildren(...p.findings.map((f) =>
    h('tr', {}, h('td', {}, badge(f.status)), h('td', {}, f.version), h('td', {}, f.source))));
}

function setProgress(id, state) {
  const li = document.querySelector(`#progress-list li[data-id="${id}"]`);
  if (li) li.className = state;
}

function handleEvent(ev) {
  if (ev.type === 'start') {
    report = { start: ev, sections: [] };
    $('#progress-list').replaceChildren(...ev.sections.map((s) =>
      h('li', { 'data-id': s.id, class: s.skipped ? 'skipped' : '' }, s.title)));
    const first = ev.sections.find((s) => !s.skipped);
    if (first) setProgress(first.id, 'running');
    $('#results').hidden = false;
    renderOverview();
  } else if (ev.type === 'section') {
    report.sections.push(ev.section);
    setProgress(ev.section.id, ev.section.skipped ? 'skipped' : 'done');
    const next = report.start.sections.find((s) => !s.skipped && !report.sections.some((d) => d.id === s.id));
    if (next) setProgress(next.id, 'running');
    $('#sections').append(renderSection(ev.section));
    renderCounts();
  } else if (ev.type === 'done') {
    Object.assign(report, ev);
    renderOverview(ev);
    renderPhp2Shell(ev.php2shell);
    renderVerdicts(ev.verdicts);
    $('#copy-md').disabled = false;
    $('#download-json').disabled = false;
  } else if (ev.type === 'error') {
    showError(ev.error);
  }
}

async function runScan(payload) {
  const res = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let msg = `エラーが発生しました（HTTP ${res.status}）`;
    try { msg = (await res.json()).error || msg; } catch { /* 無視 */ }
    throw new Error(msg);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) handleEvent(JSON.parse(line));
    }
  }
  if (buf.trim()) handleEvent(JSON.parse(buf));
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  showError('');
  const url = $('#url').value.trim();
  if (!url) return showError('URLを入力してください。');
  if (!$('#consent').checked) return showError('自分が管理する、または運用側の許可があるサイトであることを確認し、チェックを入れてください。');
  const options = {};
  for (const name of ['exposure', 'errors', 'cms', 'tls']) options[name] = form.elements[name].checked;
  const activePassword = $('#active-password').value;
  if (activePassword) options.active = true;

  report = null;
  $('#sections').replaceChildren();
  $('#verdicts').hidden = true;
  $('#results').hidden = true;
  resetPhp2Shell();
  $('#copy-md').disabled = true;
  $('#download-json').disabled = true;
  $('#progress').hidden = false;
  $('#progress-list').replaceChildren(h('li', { class: 'running' }, 'トップページと404ページを取得'));
  submitBtn.disabled = true;
  submitBtn.textContent = 'チェック中…';
  try {
    await runScan({ url, consent: true, options, ...(activePassword ? { activePassword } : {}) });
  } catch (err) {
    showError(err.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'チェック開始';
  }
});

function toMarkdown() {
  const s = report.start;
  const p = report.php2shell;
  const lines = [
    '# PHP2Shell チェック結果',
    '',
    `- 対象URL: ${s.target}`,
    s.finalUrl !== s.target ? `- 最終URL: ${s.finalUrl}` : null,
    `- 実行日時: ${new Date(report.finishedAt).toLocaleString('ja-JP')}`,
    `- 送信リクエスト数: ${report.requestCount}`,
    '',
    '> 外部診断でわかるのは「危険な兆候が見えるか」までで、「安全である」ことの証明にはなりません。',
    '',
    `## PHP2Shell（${p.cves.join(' / ')}）: ${P2S_BADGE[p.status]} — ${p.headline}`,
    '',
    p.detail,
    '',
    `- 次のアクション: ${p.action}`,
    `- 修正版: ${p.fixedVersions.map((f) => f.fixed).join(' / ')}（8.1以前は公式修正なし）`,
    '',
    ...(p.findings.length ? ['| 判定 | バージョン | 表示されていた場所 |', '| --- | --- | --- |',
      ...p.findings.map((f) => `| ${STATUS_LABEL[f.status]} | ${f.version} | ${f.source} |`), ''] : []),
    ...(p.preconditions?.tested ? ['### 悪用の前提条件（アクティブ検査）', '',
      ...p.preconditions.items.map((i) => `- **[${STATUS_LABEL[i.status]}] ${i.title}**: ${i.summary}`), ''] : []),
    '# それ以外のチェック結果',
    '',
    '## 判定と次のアクション',
    '',
    ...report.verdicts.flatMap((v) => [`- **[${STATUS_LABEL[v.status]}] ${v.title}**: ${v.detail}`, `  - 次のアクション: ${v.action}`]),
    '',
  ].filter((l) => l !== null);
  for (const sec of report.sections) {
    lines.push(`## ${sec.title}`, '');
    if (sec.skipped) { lines.push('（スキップ）', ''); continue; }
    lines.push('| 判定 | チェック対象 | 結果 |', '| --- | --- | --- |');
    for (const it of sec.items) {
      const cell = (t) => String(t).replace(/\|/g, '\\|').replace(/\n/g, '<br>');
      lines.push(`| ${STATUS_LABEL[it.status]} | ${cell(it.title)} | ${cell(it.summary)}${it.hint ? `<br>対処: ${cell(it.hint)}` : ''} |`);
    }
    lines.push('');
  }
  lines.push('# 運用側への確認事項（PHP2Shell）', '',
    '- [ ] PHPのバージョン（ディストリ版の場合はパッケージのバージョン）',
    '- [ ] CVE-2026-109618 / CVE-2026-109619 の修正適用の有無と適用日時',
    '- [ ] 適用後にPHP-FPM（またはApache）を再起動したか',
    '- [ ] 2026年10月20日以降のログで、不審なアクセスやPHPワーカーの異常終了がないか確認したか', '');
  return lines.join('\n');
}

$('#copy-md').addEventListener('click', async () => {
  const btn = $('#copy-md');
  try {
    await navigator.clipboard.writeText(toMarkdown());
    btn.textContent = 'コピーしました';
  } catch {
    btn.textContent = 'コピーできませんでした';
  }
  setTimeout(() => { btn.textContent = 'Markdownをコピー'; }, 2000);
});

$('#download-json').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: `phpcheck-${new URL(report.start.finalUrl).hostname}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

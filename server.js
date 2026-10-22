// PHPサイト外部診断ツールの Web サーバー（依存パッケージなし）
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan, normalizeTargetUrl } from './lib/scanner.js';
import { allowPrivateTargets } from './lib/net.js';

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');
const MAX_CONCURRENT_SCANS = Number(process.env.MAX_CONCURRENT_SCANS) || 4;
const SCANS_PER_WINDOW = Number(process.env.SCANS_PER_WINDOW) || 10;
const WINDOW_MS = 10 * 60 * 1000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};

let activeScans = 0;
const activeByIp = new Set();
const history = new Map(); // ip -> timestamps

function clientIp(req) {
  if (process.env.TRUST_PROXY === '1') {
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS });
  res.end(JSON.stringify(obj));
}

async function readBody(req, limit = 16 * 1024) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error('リクエストが大きすぎます');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function handleScan(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch {
    return sendJson(res, 400, { error: 'リクエストの形式が正しくありません' });
  }
  if (payload.consent !== true) {
    return sendJson(res, 400, { error: '自分が管理する、または運用側の許可があるサイトであることを確認してください' });
  }
  let target;
  try {
    target = normalizeTargetUrl(payload.url, { allowAnyPort: allowPrivateTargets() });
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }

  const ip = clientIp(req);
  const now = Date.now();
  const recent = (history.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  if (activeByIp.has(ip)) return sendJson(res, 429, { error: '実行中のチェックが終わってから再実行してください' });
  if (recent.length >= SCANS_PER_WINDOW) return sendJson(res, 429, { error: '短時間に実行できる回数の上限に達しました。しばらく待ってから再実行してください' });
  if (activeScans >= MAX_CONCURRENT_SCANS) return sendJson(res, 503, { error: 'サーバーが混雑しています。しばらく待ってから再実行してください' });
  recent.push(now);
  history.set(ip, recent);
  activeByIp.add(ip);
  activeScans++;

  res.writeHead(200, {
    'content-type': 'application/x-ndjson; charset=utf-8',
    'cache-control': 'no-store',
    'x-accel-buffering': 'no',
    ...SECURITY_HEADERS,
  });
  const write = (event) => { if (!res.writableEnded) res.write(`${JSON.stringify(event)}\n`); };
  try {
    const opts = payload.options || {};
    await runScan(target, {
      options: {
        exposure: opts.exposure !== false,
        errors: opts.errors !== false,
        cms: opts.cms !== false,
        tls: opts.tls !== false,
      },
      onEvent: write,
    });
  } catch (err) {
    write({ type: 'error', error: err.message });
  } finally {
    activeScans--;
    activeByIp.delete(ip);
    res.end();
  }
}

async function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return sendJson(res, 404, { error: 'not found' });
  try {
    const data = await fs.readFile(file);
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', ...SECURITY_HEADERS });
    res.end(req.method === 'HEAD' ? undefined : data);
  } catch {
    sendJson(res, 404, { error: 'not found' });
  }
}

export function createServer() {
  return http.createServer((req, res) => {
    // 古い実行履歴を掃除
    if (history.size > 1000) {
      const now = Date.now();
      for (const [ip, ts] of history) if (!ts.some((t) => now - t < WINDOW_MS)) history.delete(ip);
    }
    if (req.url === '/api/scan' && req.method === 'POST') {
      handleScan(req, res).catch((err) => { if (!res.headersSent) sendJson(res, 500, { error: err.message }); else res.end(); });
    } else if (req.method === 'GET' || req.method === 'HEAD') {
      if (req.url === '/healthz') return sendJson(res, 200, { ok: true });
      serveStatic(req, res);
    } else {
      sendJson(res, 405, { error: 'method not allowed' });
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  createServer().listen(PORT, HOST, () => {
    console.log(`PHP Checker: http://localhost:${PORT}/`);
    if (allowPrivateTargets()) console.warn('警告: ALLOW_PRIVATE_TARGETS=1 のため内部ネットワーク宛てのチェックを許可しています');
  });
}

// 外部への HTTP/TLS 通信。SSRF 対策として内部ネットワーク宛ての接続を拒否する。
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import dns from 'node:dns';
import net from 'node:net';

export const USER_AGENT = 'PHPChecker/1.0 (non-destructive external check)';

const blockList = new net.BlockList();
for (const [addr, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blockList.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001:db8::', 32],
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
]) blockList.addSubnet(addr, prefix, 'ipv6');

export function allowPrivateTargets() {
  return process.env.ALLOW_PRIVATE_TARGETS === '1';
}

export function isBlockedAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return blockList.check(address, 'ipv4');
  if (family === 6) {
    const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped) return blockList.check(mapped[1], 'ipv4');
    return blockList.check(address, 'ipv6');
  }
  return true;
}

function blockedError(address) {
  const err = new Error(`内部ネットワークのアドレス (${address}) へは接続できません`);
  err.code = 'EBLOCKED';
  return err;
}

// 名前解決のたびに解決先を検査する（リダイレクトや DNS リバインディング対策）。
export function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!allowPrivateTargets()) {
      const bad = addresses.find((a) => isBlockedAddress(a.address));
      if (bad) return callback(blockedError(bad.address));
    }
    if (options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

function checkLiteralHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && !allowPrivateTargets() && isBlockedAddress(host)) return blockedError(host);
  return null;
}

/**
 * 1 回の HTTP リクエスト（リダイレクトは追わない）。失敗しても reject せず { error } を返す。
 */
export function request(url, { method = 'GET', headers = {}, body = null, maxBytes = 512 * 1024, timeout = 10000 } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ url, method, error: 'URLが不正です', code: 'EINVAL' }); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return resolve({ url, method, error: 'http/https 以外は対象外です', code: 'EINVAL' });
    }
    const literalErr = checkLiteralHost(u.hostname);
    if (literalErr) return resolve({ url, method, error: literalErr.message, code: literalErr.code });

    const started = Date.now();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      resolve({ url, method, ms: Date.now() - started, ...result });
    };
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, {
      method,
      headers: {
        'user-agent': USER_AGENT,
        accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
        'accept-language': 'ja,en;q=0.8',
        ...headers,
      },
      lookup: safeLookup,
      agent: false,
      // 証明書の妥当性は TLS チェックで別途評価するため、ここでは接続を優先する
      rejectUnauthorized: false,
      timeout,
    }, (res) => {
      const chunks = [];
      let size = 0;
      let truncated = false;
      const finish = () => done({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
        truncated,
      });
      res.on('data', (chunk) => {
        if (truncated) return;
        size += chunk.length;
        if (size > maxBytes) {
          chunks.push(chunk.subarray(0, chunk.length - (size - maxBytes)));
          truncated = true;
          finish();
          res.destroy();
        } else {
          chunks.push(chunk);
        }
      });
      res.on('end', finish);
      res.on('error', finish);
      res.on('close', finish);
    });
    req.on('timeout', () => {
      const err = new Error('タイムアウトしました');
      err.code = 'ETIMEDOUT';
      req.destroy(err);
    });
    req.on('error', (err) => done({ error: err.message, code: err.code }));
    if (body != null) req.write(body);
    req.end();
  });
}

/**
 * TLS ハンドシェイクだけを行い、プロトコル・証明書情報を返す。
 */
export function tlsProbe(host, port = 443, { minVersion, maxVersion, ciphers, timeout = 8000 } = {}) {
  return new Promise((resolve) => {
    const literalErr = checkLiteralHost(host);
    if (literalErr) return resolve({ ok: false, error: literalErr.message, code: literalErr.code });
    let settled = false;
    const done = (result) => { if (!settled) { settled = true; resolve(result); } };
    const opts = {
      host, port, lookup: safeLookup, rejectUnauthorized: false,
      servername: net.isIP(host) ? undefined : host,
    };
    if (minVersion) opts.minVersion = minVersion;
    if (maxVersion) opts.maxVersion = maxVersion;
    if (ciphers) opts.ciphers = ciphers;
    let socket;
    try {
      socket = tls.connect(opts, () => {
        const cert = socket.getPeerCertificate();
        done({
          ok: true,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          cert: cert && Object.keys(cert).length ? {
            subject: cert.subject?.CN,
            issuer: cert.issuer?.O || cert.issuer?.CN,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            altNames: cert.subjectaltname,
          } : null,
        });
        socket.end();
      });
    } catch (err) {
      return done({ ok: false, error: err.message, code: err.code });
    }
    socket.setTimeout(timeout, () => {
      socket.destroy();
      done({ ok: false, error: 'タイムアウトしました', code: 'ETIMEDOUT' });
    });
    socket.on('error', (err) => done({ ok: false, error: err.message, code: err.code }));
  });
}

// 1 回の診断で共有する状態と、リクエスト数・同時接続数を制限した取得処理。
import { request } from './net.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class ScanContext {
  constructor(inputUrl, { maxRequests = 70, concurrency = 2, delayMs = 150, requestImpl = request } = {}) {
    this.inputUrl = new URL(inputUrl);
    this.base = this.inputUrl;
    this.maxRequests = maxRequests;
    this.concurrency = concurrency;
    this.delayMs = delayMs;
    this.requestImpl = requestImpl;
    this.requestCount = 0;
    this.active = 0;
    this.waiters = [];
    this.cache = new Map();
    this.log = [];
    this.responses = [];
    // チェック間で共有する発見事項
    this.phpFindings = [];
    this.composerPackages = null;
  }

  get origin() { return this.base.origin; }

  resolve(pathOrUrl) {
    return new URL(pathOrUrl, this.base).href;
  }

  async acquire() {
    if (this.active < this.concurrency) { this.active++; return; }
    await new Promise((r) => this.waiters.push(r));
    this.active++;
  }

  release() {
    this.active--;
    const next = this.waiters.shift();
    if (next) next();
  }

  /** 1 リクエスト（キャッシュ・上限あり、リダイレクトは追わない） */
  async fetch(pathOrUrl, opts = {}) {
    const url = this.resolve(pathOrUrl);
    const method = opts.method || 'GET';
    // noCache はアクティブ検査用。同じ URL へ本文や Cookie を変えて送るためキャッシュしない
    const key = `${method} ${url}`;
    if (!opts.noCache && this.cache.has(key)) return this.cache.get(key);
    const promise = (async () => {
      if (this.requestCount >= this.maxRequests) {
        return { url, method, error: 'リクエスト上限に達したため省略しました', code: 'EBUDGET' };
      }
      this.requestCount++;
      await this.acquire();
      try {
        if (this.delayMs) await sleep(this.delayMs);
        const { probe, noCache, ...reqOpts } = opts;
        const res = await this.requestImpl(url, reqOpts);
        if (probe) res.probe = true;
        this.log.push({ method, url, status: res.status ?? null, error: res.error ?? null });
        if (!res.error && !noCache) this.responses.push(res);
        return res;
      } finally {
        this.release();
      }
    })();
    if (!opts.noCache) this.cache.set(key, promise);
    return promise;
  }

  /** リダイレクトを最大 maxHops 回まで追う */
  async fetchFollow(pathOrUrl, { maxHops = 5, ...opts } = {}) {
    let url = this.resolve(pathOrUrl);
    const chain = [];
    for (let i = 0; i <= maxHops; i++) {
      const res = await this.fetch(url, opts);
      chain.push(res);
      const loc = res.headers?.location;
      if (!res.error && res.status >= 300 && res.status < 400 && loc) {
        url = new URL(loc, url).href;
        continue;
      }
      return { ...res, chain };
    }
    const last = chain[chain.length - 1];
    return { ...last, chain, error: last.error || 'リダイレクトが多すぎます' };
  }
}

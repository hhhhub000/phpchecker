// テスト用の疑似サイト（脆弱な設定のサイトと、対策済みのサイト）
import http from 'node:http';

const VULN_HTML = `<!doctype html><html><head>
<meta name="generator" content="WordPress 6.1.1">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=1.12.4"></script>
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.1"></script>
</head><body>
<a href="/page.php?id=1&PHPSESSID=abcdef1234567890">link</a>
<form action="/api/submit.php" method="post"></form>
</body></html>`;

const PHPINFO = '<html><head><title>phpinfo()</title></head><body><h1 class="p">PHP Version 8.3.30</h1><table><tr><td>Zend Engine</td></tr></table></body></html>';

export function vulnerableHandler(req, res) {
  const url = new URL(req.url, 'http://x');
  const base = { 'x-powered-by': 'PHP/8.3.30', server: 'Apache/2.4.52 (Ubuntu)' };
  const send = (status, body, headers = {}) => { res.writeHead(status, { ...base, 'content-type': 'text/html', ...headers }); res.end(req.method === 'HEAD' ? undefined : body); };
  if (req.method === 'OPTIONS') return send(200, '', { allow: 'GET, POST, OPTIONS, TRACE, PUT' });
  switch (url.pathname) {
    case '/':
      return send(200, VULN_HTML, { 'set-cookie': ['PHPSESSID=abc123; path=/', 'lang=ja; path=/; SameSite=Lax'] });
    case '/page.php':
      if (url.search.includes('%5B%5D') || url.search.includes('[]')) {
        return send(200, '<br />\n<b>Warning</b>:  htmlspecialchars() expects parameter 1 to be string, array given in <b>/var/www/html/page.php</b> on line <b>12</b><br />');
      }
      return send(200, '<p>ok</p>');
    case '/api/submit.php':
      res.writeHead(200, { 'x-powered-by': 'PHP/8.1.2-1ubuntu2.14', 'content-type': 'application/json' });
      return res.end();
    case '/phpinfo.php': return send(200, PHPINFO);
    case '/.env': return send(200, 'APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n', { 'content-type': 'text/plain' });
    case '/.git/HEAD': return send(200, 'ref: refs/heads/main\n', { 'content-type': 'text/plain' });
    case '/composer.lock': return send(200, JSON.stringify({ packages: [{ name: 'monolog/monolog', version: '1.0.0' }] }), { 'content-type': 'application/json' });
    case '/uploads/': return send(200, '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><a href="a.jpg">a.jpg</a></body></html>');
    case '/server-status': return send(403, 'Forbidden');
    case '/readme.html': return send(200, '<h1>WordPress</h1><br /> Version 6.1.1');
    case '/wp-json/': return send(200, '{"namespaces":["wp/v2"]}', { 'content-type': 'application/json' });
    case '/wp-json/wp/v2/users': return send(200, JSON.stringify([{ id: 1, slug: 'admin' }]), { 'content-type': 'application/json' });
    case '/wp-content/plugins/contact-form-7/readme.txt': return send(200, '=== Contact Form 7 ===\nStable tag: 5.1\n', { 'content-type': 'text/plain' });
    default:
      return send(404, '<html><body><h1>Not Found</h1><hr><address>Apache/2.4.52 (Ubuntu) Server at localhost Port 80</address></body></html>');
  }
}

const SAFE_HEADERS = {
  server: 'nginx',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-frame-options': 'SAMEORIGIN',
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'self'",
};

export function hardenedHandler(req, res) {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/') {
    res.writeHead(200, { ...SAFE_HEADERS, 'content-type': 'text/html', 'set-cookie': 'PHPSESSID=abc; path=/; Secure; HttpOnly; SameSite=Lax' });
    return res.end('<!doctype html><html><head><title>ok</title></head><body>hello</body></html>');
  }
  res.writeHead(404, { ...SAFE_HEADERS, 'content-type': 'text/html' });
  res.end('<!doctype html><html><body>Not Found</body></html>');
}

export function listen(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

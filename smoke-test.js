const { spawn } = require('child_process');
const path = require('path');

const PORT = 3109;
const serverPath = path.join(__dirname, 'server.js');
const child = spawn(process.execPath, [serverPath], {
  env: {
    ...process.env,
    PORT: String(PORT),
    NODE_ENV: 'test',
    SESSION_SECRET: 'smoke-' + Math.random().toString(36).slice(2),
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let out = '';
let err = '';
let ready = false;
const results = [];

const base = `http://127.0.0.1:${PORT}`;

function timeout(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function req(method, pathname, body, headers) {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 10000);
    const res = await fetch(base + pathname, {
      method,
      headers: { 'content-type': 'application/json', ...(headers || {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctl.signal,
    });
    clearTimeout(t);
    let text = '';
    try { text = await res.text(); } catch {}
    return { status: res.status, text };
  } catch (e) {
    return { status: 'ERR', text: String(e.message || e) };
  }
}

child.stdout.on('data', (d) => { out += d; if (/listening|:300\d|:31\d\d/i.test(out)) ready = true; });
child.stderr.on('data', (d) => { err += d; });

(async () => {
  // Wait up to 10s for a listen line OR first error.
  for (let i = 0; i < 40 && !ready; i++) {
    if (err.includes('Error') || err.includes('at Object.<anonymous>')) { ready = true; }
    await timeout(250);
  }

  // smoke requests
  const r1 = await req('GET', '/api/posts');
  results.push(['GET /api/posts (anon, expect 4xx not crash)', `${r1.status}`]);
  const r2 = await req('GET', '/api/search?q=' + encodeURIComponent('test'));
  results.push(['GET /api/search?q=test (anon)', `${r2.status}`]);
  const r3 = await req('POST', '/api/signup', { name: '', email: '', password: '' });
  results.push(['POST /api/signup empty (expect 400 JSON)', `${r3.status} ${r3.text.slice(0, 60)}`]);
  const r4 = await req('POST', '/api/signup', { name: 'T', email: 't@x.io', password: 'short' });
  results.push(['POST /api/signup short pw (expect 400)', `${r4.status} ${r4.text.slice(0, 60)}`]);
  const r5 = await req('GET', '/api/posts/1/applications');
  results.push(['GET /api/posts/1/applications (anon, expect 4xx)', `${r5.status}`]);
  const r6 = await req('POST', '/api/signup', null);
  results.push(['POST /api/signup no body (expect 400)', `${r6.status} ${r6.text.slice(0, 60)}`]);

  console.log('--- smoke results ---');
  for (const [k, v] of results) console.log(`[${v}] ${k}`);
  console.log('--- server stderr (last 800 chars) ---');
  console.log(err.slice(-800) || '(none)');

  child.kill();
  setTimeout(() => process.exit(0), 500);
})();

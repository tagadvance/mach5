/*
 * Types `thisisunsafe` at a real certificate warning page.
 *
 * The page under test is not a fixture: it is captured from a running proxy
 * refusing a self-signed origin, so what runs here is the markup the listener
 * is actually embedded in, phrase and all. Point INTERSTITIAL at a saved copy.
 *
 * The bypass is the one piece of injected JavaScript that turns a refusal into
 * an acceptance, which makes "does it fire when it should" and "does it stay
 * silent when it should not" worth more than the usual assertion.
 *
 *     npm install jsdom && node proxy/tests/js/interstitial.test.js [page.html]
 */
const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');

const PAGE = process.argv[2] || path.join(__dirname, 'interstitial.html');
const html = fs.readFileSync(PAGE, 'utf8');

let pass = 0, fail = 0;
const ok = (name, cond, detail) => {
  if (cond) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
};

const script = (html.match(/<script[^>]*>([\s\S]*?)<\/script>/) || [])[1];

function load(opts = {}) {
  const vc = new VirtualConsole();
  const errors = [];
  vc.on('jsdomError', e => errors.push(e));
  const dom = new JSDOM(html, {
    runScripts: 'outside-only',
    virtualConsole: vc,
    url: 'https://staging.example.com/admin?tab=1',
  });
  const w = dom.window;

  // A bare `location` resolves lexically, so a wrapper parameter of the same
  // name shadows the one jsdom will not let anyone observe.
  let reloads = 0;
  const fake = { pathname: '/admin', search: '?tab=1', reload: () => { reloads += 1; } };

  const posts = [];
  w.fetch = (url, init = {}) => {
    posts.push({
      url,
      method: init.method || 'GET',
      body: init.body || null,
      type: (init.headers || {})['content-type'] || null,
      credentials: init.credentials,
    });
    if (opts.refused) return Promise.resolve({ ok: false, status: 403 });
    if (opts.offline) return Promise.reject(new Error('offline'));

    return Promise.resolve({ ok: true, status: 204 });
  };

  w.eval(`(function (location) { ${script} })`)(fake);

  return { w, posts, errors, reloads: () => reloads };
}

const settle = () => new Promise(r => setTimeout(r, 0));

const type = (w, text) => {
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    const e = new w.KeyboardEvent('keypress', { charCode: code, keyCode: code, bubbles: true });
    // jsdom does not populate the legacy charCode from the init dict.
    if (!e.charCode) Object.defineProperty(e, 'charCode', { value: code });
    w.dispatchEvent(e);
  }
};

console.log('\n=== the page itself ===');
ok('a script is embedded', !!script);
ok('it is the warning page', /not private/i.test(html));
ok('the page never names the phrase', !/thisisunsafe/i.test(html.replace(script || '', '')),
   'the markup must stay a refusal');

let TOKEN = (script.match(/const token = "([^"]*)"/) || [])[1];

async function main() {
console.log('\n=== typing the phrase ===');
{
  const p = load();
  type(p.w, 'thisisunsafe');
  await settle();
  const post = p.posts[0];
  ok('it posts', p.posts.length === 1, JSON.stringify(p.posts));
  ok('to the bypass endpoint', post && post.url === '/.mach5/bypass');
  ok('as a POST, not a navigation', post && post.method === 'POST');
  ok('as json, which a form cannot send cross-origin', post && post.type === 'application/json');
  ok('carrying the token the page was given', post && JSON.parse(post.body).token === TOKEN,
     post && post.body);
  ok('the token is not guessable', !!TOKEN && TOKEN.length >= 32 && /^[0-9a-f]+$/.test(TOKEN), TOKEN);
  ok('and reloads once it is accepted', p.reloads() === 1);
  ok('nothing threw', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
}

console.log('\n=== when the token is refused ===');
{
  const p = load({ refused: true });
  type(p.w, 'thisisunsafe');
  await settle();
  ok('it still asks', p.posts.length === 1);
  ok('but does not reload on a 403', p.reloads() === 0);
  ok('and does not throw', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
}

console.log('\n=== when the proxy does not answer ===');
{
  const p = load({ offline: true });
  type(p.w, 'thisisunsafe');
  await settle();
  ok('a rejected fetch is handled', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
  ok('and nothing is let through', p.reloads() === 0);
}

console.log('\n=== it stays shut otherwise ===');
for (const [name, text] of [
  ['a prefix of the phrase', 'thisisunsaf'],
  ['the wrong case', 'THISISUNSAFE'],
  ['the wrong phrase', 'letmein'],
  ['ordinary typing', 'hello there, what is this page'],
  ['the phrase backwards', 'efasnusisiht'],
]) {
  const p = load();
  type(p.w, text);
  ok(`${name} does nothing`, p.posts.length === 0, JSON.stringify(p.posts));
}

console.log('\n=== the rolling buffer ===');
{
  const p = load();
  type(p.w, 'xyzzy nonsense thisisunsafe');
  ok('junk before the phrase is forgiven', p.posts.length === 1, JSON.stringify(p.posts));

  const q = load();
  type(q.w, 'thisisunsafe');
  type(q.w, 'thisisunsafe');
  ok('typing it twice asks twice, not zero times', q.posts.length === 2);

  const r = load();
  type(r.w, 'thisisunsafex');
  ok('a trailing character after a match does not re-fire', r.posts.length === 1);

  const s = load();
  type(s.w, 'this');
  type(s.w, 'isun');
  type(s.w, 'safe');
  ok('it does not care about pauses', s.posts.length === 1);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
}

main();

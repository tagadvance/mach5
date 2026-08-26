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

function load() {
  const vc = new VirtualConsole();
  const errors = [];
  vc.on('jsdomError', e => errors.push(e));
  const dom = new JSDOM(html, {
    runScripts: 'outside-only',
    virtualConsole: vc,
    url: 'https://staging.example.com/admin?tab=1',
  });
  const w = dom.window;

  // The listener assigns to `location.href`, which jsdom will not let anyone
  // observe. A bare `location` resolves lexically, so a wrapper parameter of
  // the same name shadows it and the assignment lands somewhere readable.
  const went = [];
  const fake = {
    pathname: '/admin', search: '?tab=1',
    set href(v) { went.push(v); },
    get href() { return went[went.length - 1]; },
  };
  w.eval(`(function (location) { ${script} })`)(fake);

  return { w, went, errors };
}

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

console.log('\n=== typing the phrase ===');
{
  const p = load();
  type(p.w, 'thisisunsafe');
  ok('it navigates', p.went.length === 1, JSON.stringify(p.went));
  ok('to the bypass endpoint', p.went[0] && p.went[0].startsWith('/.mach5/bypass?next='));
  ok('carrying where you were', p.went[0] === '/.mach5/bypass?next=' + encodeURIComponent('/admin?tab=1'), p.went[0]);
  ok('nothing threw', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
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
  ok(`${name} does nothing`, p.went.length === 0, JSON.stringify(p.went));
}

console.log('\n=== the rolling buffer ===');
{
  const p = load();
  type(p.w, 'xyzzy nonsense thisisunsafe');
  ok('junk before the phrase is forgiven', p.went.length === 1, JSON.stringify(p.went));

  const q = load();
  type(q.w, 'thisisunsafe');
  type(q.w, 'thisisunsafe');
  ok('typing it twice navigates twice, not zero times', q.went.length === 2);

  const r = load();
  type(r.w, 'thisisunsafex');
  ok('a trailing character after a match does not re-fire', r.went.length === 1);

  const s = load();
  type(s.w, 'this');
  type(s.w, 'isun');
  type(s.w, 'safe');
  ok('it does not care about pauses', s.went.length === 1);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

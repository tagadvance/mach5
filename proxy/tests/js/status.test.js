/*
 * Clicks every button on the status page.
 *
 * The page is captured from a running proxy, so the buttons are the ones it
 * really emits with the attributes it really sets. Writing this found that a
 * failed POST was an unhandled rejection -- the last section below is the one
 * that caught it, and it now asserts the fix.
 *
 *     npm install jsdom && node proxy/tests/js/status.test.js [page.html]
 */
const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');

const PAGE = process.argv[2] || path.join(__dirname, 'status.html');
const html = fs.readFileSync(PAGE, 'utf8');
const script = (html.match(/<script[^>]*>([\s\S]*?)<\/script>/) || [])[1];

let pass = 0, fail = 0;
const ok = (name, cond, detail) => {
  if (cond) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
};

function load(opts = {}) {
  const vc = new VirtualConsole();
  const errors = [];
  let reloads = 0;
  vc.on('jsdomError', e => {
    if (/Not implemented: navigation/.test(e.message)) { reloads++; return; }
    errors.push(e);
  });
  const dom = new JSDOM(html, {
    runScripts: 'outside-only', virtualConsole: vc, url: 'https://localhost/.mach5/',
  });
  const w = dom.window;

  const calls = [];
  w.fetch = (url, init = {}) => {
    calls.push({ url, method: init.method || 'GET', body: init.body || null,
                 type: (init.headers || {})['content-type'] || null });
    return opts.fails ? Promise.reject(new Error('offline'))
                      : Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  };
  w.eval(script);

  return { w, d: w.document, calls, errors, reloads: () => reloads };
}

const click = (p, el) => {
  const e = new p.w.MouseEvent('click', { bubbles: true, cancelable: true });
  el.dispatchEvent(e);
};
const settle = () => new Promise(r => setTimeout(r, 0));

(async () => {
console.log('\n=== the page ===');
{
  const p = load();
  ok('a listener is embedded', !!script);
  ok('no error on load', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
  ok('it has a hidden-element remove button', !!p.d.querySelector('button[data-selector]'));
  ok('it has an action button', !!p.d.querySelector('button[data-post]'));
  ok('it has a settings button', !!p.d.querySelector('button[data-set]'));
}

console.log('\n=== removing one hidden element ===');
{
  const p = load();
  const button = p.d.querySelector('button[data-selector]');
  click(p, button);
  await settle();
  const c = p.calls[0];
  ok('posts to the remove endpoint', c && c.url === '/.mach5/hidden/remove', JSON.stringify(p.calls));
  ok('as json', c && c.type === 'application/json');
  ok('naming the selector on the button', c && JSON.parse(c.body).selector === button.dataset.selector,
     c && c.body);
  ok('and reloads', p.reloads() === 1);
}

console.log('\n=== an action button ===');
{
  const p = load();
  const button = p.d.querySelector('button[data-post]');
  click(p, button);
  await settle();
  ok('posts to the url on the button', p.calls[0] && p.calls[0].url === button.dataset.post);
  ok('with no body', p.calls[0] && !p.calls[0].body);
  ok('and reloads', p.reloads() === 1);
}

console.log('\n=== a settings button ===');
{
  const p = load();
  const button = p.d.querySelector('button[data-set]');
  click(p, button);
  await settle();
  const c = p.calls[0];
  ok('posts to settings', c && c.url === '/.mach5/settings');
  ok('sending the attribute verbatim', c && c.body === button.dataset.set, c && c.body);
  ok('which is valid json', (() => { try { JSON.parse(c.body); return true; } catch { return false; } })());
  ok('and reloads', p.reloads() === 1);
}

console.log('\n=== clicks that are not buttons ===');
{
  const p = load();
  click(p, p.d.querySelector('h1'));
  click(p, p.d.body);
  const link = p.d.querySelector('a');
  if (link) click(p, link);
  await settle();
  ok('nothing is posted', p.calls.length === 0, JSON.stringify(p.calls));
  ok('and nothing throws', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
}

console.log('\n=== clicking the label inside a button ===');
{
  const p = load();
  const button = p.d.querySelector('button[data-post]');
  // A real click lands on whatever is under the cursor; closest() is what makes
  // that the button. Give it a child to land on.
  const inner = p.d.createElement('span');
  inner.textContent = 'x';
  button.append(inner);
  click(p, inner);
  await settle();
  ok('still finds the button', p.calls.length === 1 && p.calls[0].url === button.dataset.post);
}

console.log('\n=== when the proxy does not answer ===');
{
  const p = load({ fails: true });
  click(p, p.d.querySelector('button[data-post]'));
  await settle();
  ok('the click is still sent', p.calls.length === 1);
  ok('the page does not reload on a failure', p.reloads() === 0);
  // Without a rejection handler this section did not fail, it terminated the
  // whole run. That is the shape the bug had in a browser too: not a broken
  // page, just a click that silently did nothing.
  ok('nothing visible breaks', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
})();

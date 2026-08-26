/*
 * Executes mach5.js in a DOM, because nothing else here does.
 *
 * Every other part of mach5 is exercised by cargo test or by curl against a
 * real origin. The injected picker and control panel are not: they are
 * JavaScript, and until this file existed they had never been parsed by an
 * engine, let alone run. That is a lot of code to ship on the strength of
 * having read it.
 *
 * jsdom is not a browser. There is no layout, so getBoundingClientRect is a
 * stub and nothing here can tell you the panel looks right; no CSS cascade, so
 * the shadow root's isolation is assumed rather than demonstrated; and the
 * shadow root is forced open below because a closed one cannot be inspected
 * from outside. What it does have is a real DOM, real events and a real
 * engine, which is enough to answer the questions that matter first: does it
 * throw, does it wire itself up, does it post what it claims to post, and does
 * it stay out of the way of the page it landed on.
 *
 * From this directory, `npm install` once and then `npm test` for all three
 * files, or a single file directly:
 *
 *     node panel.test.js
 */
const path = require('path');
const fs = require('fs');
const { JSDOM, VirtualConsole } = require('jsdom');

const SCRIPT = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'mach5.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (name, cond, detail) => {
  if (cond) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? '  -- ' + detail : ''}`); }
};

function makePage(html, opts = {}) {
  const errors = [];
  let reloaded = 0;
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => {
    if (/Not implemented: navigation/.test(e.message)) { reloaded++; return; }
    errors.push(e);
  });
  const dom = new JSDOM(html, { runScripts: 'outside-only', virtualConsole: vc, url: 'https://example.com/page' });
  const w = dom.window;

  // Capture the closed shadow root the panel hides in.
  let captured = null;
  const realAttach = w.Element.prototype.attachShadow;
  w.Element.prototype.attachShadow = function (init) {
    const root = realAttach.call(this, { ...init, mode: 'open' });
    captured = root;
    return root;
  };

  const calls = [];
  w.fetch = (path, init = {}) => {
    calls.push({ path, method: init.method || 'GET', body: init.body || null, credentials: init.credentials });
    if (opts.fetchFails) return Promise.reject(new Error('offline'));
    // A proxy that answers and says no. fetch resolves for this — it rejects
    // only on a network failure — which is what makes it the interesting case.
    if (opts.fetchRefuses) {
      return Promise.resolve({ ok: false, status: opts.fetchRefuses, json: () => Promise.resolve({}) });
    }
    const echoed = init.body ? JSON.parse(init.body) : (opts.settings || { image_quality: 'auto' });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(echoed) });
  };
  // jsdom will not let reload() be replaced, and reports the attempt as a
  // "navigation not implemented" error. That report IS the signal.

  // getBoundingClientRect is a stub in jsdom; give it something drawable.
  w.Element.prototype.getBoundingClientRect = function () {
    return { left: 10, top: 20, width: 100, height: 50, right: 110, bottom: 70, x: 10, y: 20 };
  };

  try {
    w.eval(SCRIPT);
  } catch (e) {
    errors.push(e);
  }
  return { dom, w, d: w.document, errors, calls, shadow: () => captured, reloads: () => reloaded };
}

const key = (w, code, mods = {}) => {
  const e = new w.KeyboardEvent('keydown', { code, bubbles: true, cancelable: true, ...mods });
  w.document.dispatchEvent(e);
  return e;
};
const click = (w, el) => {
  const e = new w.MouseEvent('click', { bubbles: true, cancelable: true });
  Object.defineProperty(e, 'target', { value: el });
  el.dispatchEvent(e);
  return e;
};
const tick = () => new Promise(r => setImmediate(r));

const NORMAL = `<!doctype html><html><head><title>t</title></head><body>
  <div id="wrap"><p class="a">one</p><p class="a">two</p></div>
  <aside id="ad-slot">advert</aside>
  <div><span>deep</span></div>
</body></html>`;

(async () => {
console.log('\n=== 1. it loads on an ordinary page without throwing ===');
{
  const p = makePage(NORMAL);
  ok('no uncaught error', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
  ok('leaves exactly one global behind', p.w.__mach5 === true);
  ok('panel host added to the page', !!p.d.querySelector('[data-mach5="panel"]'));
  const sh = p.shadow();
  ok('shadow root created', !!sh);
  ok('the dot exists', !!(sh && sh.getElementById('dot')));
  ok('the dot says m5', sh && sh.getElementById('dot').textContent === 'm5');
  ok('four quality tiers rendered', sh && sh.querySelectorAll('[data-tier]').length === 4);
  ok('panel starts closed', sh && !sh.getElementById('panel').classList.contains('open'));
}

console.log('\n=== 2. Ctrl+Shift+H opens the panel ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  const e = key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  ok('panel opened', sh.getElementById('panel').classList.contains('open'));
  ok('the page never sees the keystroke', e.defaultPrevented);
  await tick();
  ok('it re-reads settings on open', p.calls.some(c => c.path === '/.mach5/settings' && c.method === 'GET'));
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  ok('and closes again', !sh.getElementById('panel').classList.contains('open'));
}

console.log('\n=== 3. shortcut does not fire on near-misses ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  const open = () => sh.getElementById('panel').classList.contains('open');
  key(p.w, 'KeyH', { ctrlKey: true });                       ok('Ctrl+H alone ignored', !open());
  key(p.w, 'KeyH', { shiftKey: true });                      ok('Shift+H alone ignored', !open());
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true, altKey: true }); ok('Ctrl+Alt+Shift+H ignored', !open());
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true, metaKey: true }); ok('Ctrl+Meta+Shift+H ignored', !open());
  key(p.w, 'KeyG', { ctrlKey: true, shiftKey: true });        ok('a different letter ignored', !open());
}

console.log('\n=== 4. choosing a quality tier ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  const low = [...sh.querySelectorAll('[data-tier]')].find(b => b.dataset.tier === 'low');
  click(p.w, low);
  await tick();
  const posted = p.calls.find(c => c.method === 'POST' && c.path === '/.mach5/settings');
  ok('posts the new setting', !!posted, JSON.stringify(p.calls));
  ok('posts it as json', posted && JSON.parse(posted.body).image_quality === 'low');
  ok('omits credentials', posted && posted.credentials === 'omit');
  ok('marks the tier pressed', low.getAttribute('aria-pressed') === 'true');
  const others = [...sh.querySelectorAll('[data-tier]')].filter(b => b !== low);
  ok('and unpresses the rest', others.every(b => b.getAttribute('aria-pressed') === 'false'));
}

console.log('\n=== 5. picking an element to hide ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(p.w, sh.querySelector('[data-act="pick"]'));
  ok('picker armed, panel closed', !sh.getElementById('panel').classList.contains('open'));
  ok('crosshair cursor', p.d.documentElement.style.cursor === 'crosshair');
  ok('help badge shown', p.d.querySelector('[data-mach5="badge"]').style.display === 'block');

  const target = p.d.getElementById('ad-slot');
  const ev = click(p.w, target);
  await tick();
  ok('the page never sees the click', ev.defaultPrevented);
  ok('element hidden immediately', target.style.display === 'none');
  const hid = p.calls.find(c => c.path === '/.mach5/hidden' && c.method === 'POST');
  ok('selector posted', !!hid);
  ok('selector is the unique id', hid && JSON.parse(hid.body).selector === '#ad-slot', hid && hid.body);
  ok('and it actually matches one element', hid && p.d.querySelectorAll(JSON.parse(hid.body).selector).length === 1);
}

console.log('\n=== 6. a selector for an element with no id ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(p.w, sh.querySelector('[data-act="pick"]'));
  const target = p.d.querySelectorAll('#wrap p')[1];
  click(p.w, target);
  await tick();
  const hid = p.calls.find(c => c.path === '/.mach5/hidden');
  ok('posted a selector', !!hid);
  if (hid) {
    const sel = JSON.parse(hid.body).selector;
    ok(`selector "${sel}" matches exactly one`, p.d.querySelectorAll(sel).length === 1);
    ok('and it is the right one', p.d.querySelector(sel) === target);
  }
}

console.log('\n=== 7. Escape and u ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(p.w, sh.querySelector('[data-act="pick"]'));
  key(p.w, 'Escape');
  ok('Escape leaves picker mode', p.d.documentElement.style.cursor === '');
  ok('badge hidden again', p.d.querySelector('[data-mach5="badge"]').style.display === 'none');

  const q = makePage(NORMAL);
  const qs = q.shadow();
  key(q.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(q.w, qs.querySelector('[data-act="pick"]'));
  key(q.w, 'KeyU');
  await tick();
  ok('u clears the site', q.calls.some(c => c.path === '/.mach5/hidden/clear'));
  ok('and reloads', q.reloads() === 1);

  const r = makePage(NORMAL);
  key(r.w, 'KeyU');
  await tick();
  ok('u does nothing outside picker mode', !r.calls.some(c => c.path.includes('clear')));
}

console.log('\n=== 8. it refuses to eat itself ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(p.w, sh.querySelector('[data-act="pick"]'));
  const host = p.d.querySelector('[data-mach5="panel"]');
  click(p.w, host);
  await tick();
  ok('will not hide its own panel', !p.calls.some(c => c.path === '/.mach5/hidden'));
  click(p.w, p.d.body);
  await tick();
  ok('will not hide body', !p.calls.some(c => c.path === '/.mach5/hidden'));
}

console.log('\n=== 9. hostile and odd pages ===');
{
  const p = makePage(`<!doctype html><html><body><div id="dot">site has its own #dot</div>
    <div id="panel">and its own #panel</div><style>div{position:static!important}</style></body></html>`);
  ok('survives colliding ids', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
  ok('its own dot still exists in the shadow root', !!p.shadow().getElementById('dot'));
  ok('page dot untouched', p.d.getElementById('dot').textContent === 'site has its own #dot');

  const q = makePage(`<html><body></body></html>`);
  ok('survives an empty body', q.errors.length === 0 && !!q.shadow());

  const r = makePage(NORMAL, { fetchFails: true });
  const rs = r.shadow();
  key(r.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  await tick();
  ok('an offline proxy does not throw', r.errors.length === 0, r.errors.map(e => e.message).join('; '));
  click(r.w, [...rs.querySelectorAll('[data-tier]')][2]);
  await tick();
  ok('nor does a failed settings post', r.errors.length === 0);
}

console.log('\n=== 9b. a proxy that answers and says no ===');
{
  // The one the code got wrong: fetch resolves for a 409, so a refusal used to
  // be indistinguishable from a save. A selector the proxy threw away looked
  // exactly like one it kept, and the element stayed hidden until the reload
  // that brought it back.
  const badge = (p) => {
    const el = p.d.querySelector('[data-mach5="badge"]');
    return el ? el.textContent : '';
  };

  const p = makePage(NORMAL, { fetchRefuses: 409 });
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(p.w, p.shadow().querySelector('[data-act="pick"]'));
  await tick();
  const target = p.d.querySelector('#ad-slot');
  target.dispatchEvent(new p.w.MouseEvent('click', { bubbles: true, cancelable: true }));
  await tick();
  ok('a refused selector does not throw', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
  ok('and says so', /could not save/.test(badge(p)), `badge said: ${badge(p)}`);

  // The panel has no badge on screen, so a refused quality change reports
  // itself by putting the button back where it was.
  const q = makePage(NORMAL, { fetchRefuses: 507 });
  key(q.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  await tick();
  const chosen = (p) => {
    const on = [...p.shadow().querySelectorAll('[data-tier]')]
      .find((b) => b.getAttribute('aria-pressed') === 'true');
    return on ? on.dataset.tier : null;
  };
  const before = chosen(q);
  ok('a tier is marked to begin with', before !== null);
  const third = [...q.shadow().querySelectorAll('[data-tier]')][2];
  ok('and it is not the one about to be clicked', third.dataset.tier !== before);
  click(q.w, third);
  await tick();
  ok('a refused quality change puts the choice back', chosen(q) === before, `now: ${chosen(q)}, was: ${before}`);

  // The same click against a proxy that agrees, so the assertion above is
  // about the refusal and not about the button never moving.
  const accepted = makePage(NORMAL);
  key(accepted.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  await tick();
  click(accepted.w, [...accepted.shadow().querySelectorAll('[data-tier]')][2]);
  await tick();
  ok('an accepted one sticks', chosen(accepted) === third.dataset.tier, `now: ${chosen(accepted)}`);

  const r2 = makePage(NORMAL, { fetchRefuses: 500 });
  key(r2.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(r2.w, r2.shadow().querySelector('[data-act="pick"]'));
  await tick();
  key(r2.w, 'KeyU');
  await tick();
  ok('a refused clear does not reload the page', r2.reloads() === 0);
  ok('and says so', /could not clear/.test(badge(r2)), `badge said: ${badge(r2)}`);
}

console.log('\n=== 10. runs once, and only in the top frame ===');
{
  const p = makePage(NORMAL);
  const before = p.d.querySelectorAll('[data-mach5="panel"]').length;
  p.w.eval(SCRIPT);
  ok('a second run adds nothing', p.d.querySelectorAll('[data-mach5="panel"]').length === before);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
})();

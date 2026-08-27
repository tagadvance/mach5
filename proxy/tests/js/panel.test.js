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
 * from outside.
 *
 * Two consequences worth naming, because the picker is now aimed at a phone.
 * Nothing here can say where anything is on screen: where a rectangle matters
 * — the outline, and the panel moving out from under what is being confirmed —
 * the test feeds getBoundingClientRect a fixture and checks the arithmetic
 * done with it, which is not the same as checking it looks right. And there is
 * no touch: jsdom builds a TouchEvent but has no elementFromPoint, so the
 * hit-test the touch handler depends on is stubbed too. What it does have is a real DOM, real events and a real
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
const move = (w, el) => {
  const e = new w.MouseEvent('mousemove', { bubbles: true, cancelable: true });
  Object.defineProperty(e, 'target', { value: el });
  w.document.dispatchEvent(e);
  return e;
};
// jsdom has TouchEvent but no Touch, and accepts plain objects in `touches`.
// It has no elementFromPoint at all, so the caller stubs that; see `hit`.
const touch = (w, type, x, y, el) => {
  const spot = [{ clientX: x, clientY: y }];
  const e = new w.TouchEvent(type, {
    bubbles: true, cancelable: true,
    touches: type === 'touchend' ? [] : spot,
    changedTouches: spot,
  });
  (el || w.document).dispatchEvent(e);
  return e;
};
const hit = (p, el) => { p.d.elementFromPoint = () => el; };
// A fixture rectangle for one element. There is no layout here, so this is the
// only way anything geometric can be exercised at all.
const rect = (el, [left, top, width, height]) => {
  el.getBoundingClientRect = () => ({
    left, top, width, height, right: left + width, bottom: top + height, x: left, y: top,
  });
};
const act = (p, name) => p.shadow().querySelector(`[data-act="${name}"]`);
const text = (p, id) => { const el = p.shadow().getElementById(id); return el ? el.textContent : ''; };
const outline = (p) => p.d.querySelector('[data-mach5="outline"]');
const pick = (p) => {
  key(p.w, 'KeyH', { ctrlKey: true, shiftKey: true });
  click(p.w, act(p, 'pick'));
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

console.log('\n=== 5. tapping an element chooses it, and Hide hides it ===');
{
  const p = makePage(NORMAL);
  const sh = p.shadow();
  pick(p);
  ok('picker armed, panel closed', !sh.getElementById('panel').classList.contains('open'));
  ok('crosshair cursor', p.d.documentElement.style.cursor === 'crosshair');
  ok('help badge shown', p.d.querySelector('[data-mach5="badge"]').style.display === 'block');

  const target = p.d.getElementById('ad-slot');
  const ev = click(p.w, target);
  await tick();
  ok('the page never sees the click', ev.defaultPrevented);
  ok('nothing hidden yet', target.style.display === '');
  ok('and nothing posted yet', !p.calls.some(c => c.path === '/.mach5/hidden'));
  ok('the panel opens to confirm', sh.getElementById('panel').classList.contains('open'));
  ok('in confirm mode', sh.getElementById('panel').classList.contains('confirming'));
  ok('showing the selector', text(p, 'sel') === '#ad-slot', text(p, 'sel'));
  ok('and what it is, in words', /^aside#ad-slot · \d+ × \d+$/.test(text(p, 'what')), text(p, 'what'));
  ok('outline on the candidate', outline(p).style.display === 'block');

  click(p.w, act(p, 'hide'));
  await tick();
  ok('Hide hides it', target.style.display === 'none');
  const hid = p.calls.find(c => c.path === '/.mach5/hidden' && c.method === 'POST');
  ok('selector posted', !!hid);
  ok('selector is the unique id', hid && JSON.parse(hid.body).selector === '#ad-slot', hid && hid.body);
  ok('and it actually matches one element', hid && p.d.querySelectorAll(JSON.parse(hid.body).selector).length === 1);
  ok('omits credentials', hid && hid.credentials === 'omit');
  ok('the confirm view is done with', !sh.getElementById('panel').classList.contains('confirming'));
  ok('and the picker is still armed for the next one', p.d.documentElement.style.cursor === 'crosshair');
}

console.log('\n=== 5b. Wider walks up the tree, and stops before body ===');
{
  const p = makePage(NORMAL);
  pick(p);
  const target = p.d.querySelectorAll('#wrap p')[1];
  click(p.w, target);
  const first = text(p, 'sel');
  ok('starts on what was tapped', p.d.querySelector(first) === target, first);
  ok('Wider is offered', act(p, 'wider').disabled === false);

  click(p.w, act(p, 'wider'));
  ok('it moves to the parent', text(p, 'sel') === '#wrap', text(p, 'sel'));
  ok('which is not where it started', text(p, 'sel') !== first);
  ok('and the description follows', /^div#wrap · /.test(text(p, 'what')), text(p, 'what'));
  ok('the outline is redrawn on it', outline(p).style.display === 'block');

  // #wrap's parent is body, which nothing may ever aim at.
  ok('Wider is refused at the top', act(p, 'wider').disabled === true);
  click(p.w, act(p, 'wider'));
  ok('and clicking it anyway changes nothing', text(p, 'sel') === '#wrap');

  click(p.w, act(p, 'hide'));
  await tick();
  const hid = p.calls.find(c => c.path === '/.mach5/hidden');
  ok('the widened selector is what gets posted', hid && JSON.parse(hid.body).selector === '#wrap', hid && hid.body);
  ok('body itself was never hidden', p.d.body.style.display === '');
}

console.log('\n=== 5c. Cancel hides nothing ===');
{
  const p = makePage(NORMAL);
  pick(p);
  const target = p.d.getElementById('ad-slot');
  click(p.w, target);
  ok('there is a candidate to cancel', p.shadow().getElementById('panel').classList.contains('confirming'));

  click(p.w, act(p, 'cancel'));
  await tick();
  ok('nothing was posted', !p.calls.some(c => c.path.startsWith('/.mach5/hidden')));
  ok('nothing was hidden', target.style.display === '');
  ok('picker mode left', p.d.documentElement.style.cursor === '');
  ok('panel closed', !p.shadow().getElementById('panel').classList.contains('open'));
  ok('outline gone', outline(p).style.display === 'none');
  const after = click(p.w, target);
  ok('and the page has its clicks back', !after.defaultPrevented);
}

console.log('\n=== 5d. Undo takes back the last hide, and only that one ===');
{
  const p = makePage(NORMAL);
  pick(p);
  const target = p.d.getElementById('ad-slot');
  click(p.w, target);
  ok('nothing to undo before a hide', !p.shadow().getElementById('panel').classList.contains('undoable'));

  click(p.w, act(p, 'hide'));
  await tick();
  ok('undo offered after one', p.shadow().getElementById('panel').classList.contains('undoable'));
  ok('naming what went', text(p, 'hidden') === '#ad-slot', text(p, 'hidden'));

  click(p.w, act(p, 'undo'));
  await tick();
  const gone = p.calls.find(c => c.path === '/.mach5/hidden/remove');
  ok('posts to the remove endpoint', !!gone, JSON.stringify(p.calls.map(c => c.path)));
  ok('naming just that selector', gone && JSON.parse(gone.body).selector === '#ad-slot', gone && gone.body);
  ok('omits credentials', gone && gone.credentials === 'omit');
  ok('the element comes back', target.style.display === '');
  ok('the offer goes away with it', !p.shadow().getElementById('panel').classList.contains('undoable'));
  ok('and the rest of the host is untouched', !p.calls.some(c => c.path === '/.mach5/hidden/clear'));

  // An element the page had already given an inline display: putting it back
  // means putting that back, not guessing at block.
  const q = makePage(NORMAL);
  const flex = q.d.getElementById('wrap');
  flex.style.setProperty('display', 'flex');
  pick(q);
  click(q.w, flex);
  click(q.w, act(q, 'hide'));
  await tick();
  ok('hidden over the page\'s own display', flex.style.display === 'none');
  click(q.w, act(q, 'undo'));
  await tick();
  ok('undo puts back what the page had', flex.style.display === 'flex');
}

console.log('\n=== 5e. a finger moves the outline ===');
{
  // The part jsdom cannot answer: there is no hit-testing here, so
  // elementFromPoint is stubbed and the rectangles are fixtures. What this does
  // test is that a touch reaches the picker at all and redraws the outline from
  // whatever was under it — the thing mousemove alone could never do on a phone.
  const p = makePage(NORMAL);
  pick(p);
  const target = p.d.getElementById('ad-slot');
  rect(target, [12, 300, 320, 250]);
  ok('nothing outlined to begin with', outline(p).style.display === 'none');

  hit(p, target);
  touch(p.w, 'touchstart', 20, 310, target);
  ok('touchstart outlines what is under the finger', outline(p).style.display === 'block');
  ok('at that element', outline(p).style.left === '12px' && outline(p).style.width === '320px',
    `${outline(p).style.left} ${outline(p).style.width}`);

  const other = p.d.getElementById('wrap');
  rect(other, [5, 6, 40, 30]);
  hit(p, other);
  touch(p.w, 'touchmove', 8, 8, target);
  ok('touchmove follows it', outline(p).style.left === '5px' && outline(p).style.width === '40px',
    `${outline(p).style.left} ${outline(p).style.width}`);
  ok('and none of that hid anything', !p.calls.some(c => c.path === '/.mach5/hidden'));

  // Lifting is what chooses. The finger came down on #ad-slot and left on
  // #wrap: the compatibility click a browser sends after a tap carries the
  // element the gesture STARTED on, so choosing from that click would mean the
  // outline the user watched and the thing chosen are two different elements.
  hit(p, other);
  const end = touch(p.w, 'touchend', 8, 8, target);
  ok('touchend chooses what the finger left on', text(p, 'sel') === '#wrap', text(p, 'sel'));
  ok('and the page never sees the tap', end.defaultPrevented);
  ok('a tap alone still hides nothing', !p.calls.some(c => c.path === '/.mach5/hidden'));

  // The ghost click a stubborn browser sends anyway, aimed where the finger
  // came down. Whether any real browser still sends one is not testable here;
  // that it cannot change the choice if it does, is.
  const ghost = click(p.w, target);
  ok('a ghost click does not re-choose', text(p, 'sel') === '#wrap', text(p, 'sel'));
  ok('and the page does not see it either', ghost.defaultPrevented);
}

console.log('\n=== 5e2. a tap on the panel belongs to the panel ===');
{
  // touchend is prevented for the page, which would leave the panel's own
  // buttons untappable if it did not let ours past first.
  const p = makePage(NORMAL);
  pick(p);
  hit(p, p.d.getElementById('ad-slot'));
  const host = p.d.querySelector('[data-mach5="panel"]');
  const own = touch(p.w, 'touchend', 300, 700, host);
  ok('not prevented', !own.defaultPrevented);
  ok('and it chose nothing', !p.shadow().getElementById('panel').classList.contains('confirming'));
}

console.log('\n=== 5f. hover still previews, and a candidate pins the outline ===');
{
  const p = makePage(NORMAL);
  pick(p);
  const a = p.d.getElementById('ad-slot');
  const b = p.d.getElementById('wrap');
  rect(a, [12, 300, 320, 250]);
  rect(b, [5, 6, 40, 30]);

  ok('nothing outlined to begin with', outline(p).style.display === 'none');
  move(p.w, a);
  ok('mousemove still previews', outline(p).style.display === 'block' && outline(p).style.left === '12px');
  move(p.w, b);
  ok('and follows the pointer', outline(p).style.left === '5px');

  click(p.w, a);
  ok('a click pins the outline to the candidate', outline(p).style.left === '12px');
  move(p.w, b);
  ok('and hover no longer moves it', outline(p).style.left === '12px', outline(p).style.left);
}

console.log('\n=== 5g. the panel gets out from under the candidate ===');
{
  // jsdom has no layout: both rectangles are fixtures, so this is the overlap
  // arithmetic and the class it sets. Whether the panel then looks right on a
  // phone is not a question this harness can be asked.
  const p = makePage(NORMAL);
  const panel = p.shadow().getElementById('panel');
  rect(panel, [200, 400, 230, 200]);
  pick(p);
  ok('panel starts where it normally sits', !panel.classList.contains('away'));

  const low = p.d.getElementById('ad-slot');
  rect(low, [180, 380, 300, 260]);
  click(p.w, low);
  ok('a candidate underneath moves it', panel.classList.contains('away'));

  const high = p.d.getElementById('wrap');
  rect(high, [0, 0, 100, 100]);
  click(p.w, high);
  ok('one that is nowhere near does not', !panel.classList.contains('away'));
}

console.log('\n=== 5h. the panel keeps working while the picker is armed ===');
{
  // The capture-phase click handler eats every click on the page while picking.
  // If it ate the panel's too, Hide and Cancel would be unreachable — which is
  // the one way this whole flow could be dead on arrival.
  const p = makePage(NORMAL);
  pick(p);
  click(p.w, p.d.getElementById('ad-slot'));
  const hideButton = act(p, 'hide');
  const seen = [];
  hideButton.addEventListener('click', () => seen.push('panel'));
  click(p.w, hideButton);
  await tick();
  ok('the click reaches the panel', seen.length === 1);
  ok('and does its job', p.calls.some(c => c.path === '/.mach5/hidden'));
}

console.log('\n=== 5i. an element nothing unambiguous points at ===');
{
  // Both p's are the first of their type inside #deep, so every prefix the
  // walk tries matches two elements and it gives up rather than hide the wrong
  // one. Before Wider there was nothing a user could do about that.
  const p = makePage(`<!doctype html><html><body>
    <div id="deep"><p>one</p><section><p>two</p></section></div></body></html>`);
  pick(p);
  const target = p.d.querySelector('#deep p');
  click(p.w, target);
  ok('it says so instead of a selector', /nothing unambiguous/.test(text(p, 'sel')), text(p, 'sel'));
  ok('Hide is refused', act(p, 'hide').disabled === true);
  ok('but Wider is not', act(p, 'wider').disabled === false);

  click(p.w, act(p, 'hide'));
  await tick();
  ok('and clicking Hide anyway posts nothing', !p.calls.some(c => c.path === '/.mach5/hidden'));

  click(p.w, act(p, 'wider'));
  ok('one step up there is one', text(p, 'sel') === '#deep', text(p, 'sel'));
  ok('and Hide is offered again', act(p, 'hide').disabled === false);
  click(p.w, act(p, 'hide'));
  await tick();
  const hid = p.calls.find(c => c.path === '/.mach5/hidden');
  ok('which posts the container', hid && JSON.parse(hid.body).selector === '#deep', hid && hid.body);
}

console.log('\n=== 6. a selector for an element with no id ===');
{
  const p = makePage(NORMAL);
  pick(p);
  const target = p.d.querySelectorAll('#wrap p')[1];
  click(p.w, target);
  click(p.w, act(p, 'hide'));
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
  click(p.w, p.d.getElementById('ad-slot'));
  ok('a candidate is waiting to be confirmed', sh.getElementById('panel').classList.contains('confirming'));
  key(p.w, 'Escape');
  ok('Escape leaves picker mode', p.d.documentElement.style.cursor === '');
  ok('badge hidden again', p.d.querySelector('[data-mach5="badge"]').style.display === 'none');
  ok('the candidate goes with it', !sh.getElementById('panel').classList.contains('confirming'));
  ok('outline gone', outline(p).style.display === 'none');
  ok('and nothing was hidden on the way out', p.d.getElementById('ad-slot').style.display === '');

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
  pick(p);
  await tick();
  const target = p.d.querySelector('#ad-slot');
  // Dispatched raw, without the target override the helper does, so this one
  // also exercises jsdom's own retargeting on the way to the picker.
  target.dispatchEvent(new p.w.MouseEvent('click', { bubbles: true, cancelable: true }));
  click(p.w, act(p, 'hide'));
  ok('hidden on the spot, before the proxy has answered', target.style.display === 'none');
  await tick();
  ok('a refused selector does not throw', p.errors.length === 0, p.errors.map(e => e.message).join('; '));
  ok('and says so', /could not save/.test(badge(p)), `badge said: ${badge(p)}`);
  // Nothing was stored, so leaving it hidden would be a lie until the next load.
  ok('and puts the element back', target.style.display === '', target.style.display);
  ok('with nothing to undo', !p.shadow().getElementById('panel').classList.contains('undoable'));

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

console.log('\n=== 9c. a page whose body is not there yet ===');
{
  // buildPanel used to be called once and give up if document.body was
  // missing, leaving no panel and no way to get one. `defer` usually means a
  // body is already parsed — but "usually" was carrying the whole feature.
  const dom = new JSDOM('<!doctype html><html><head></head></html>', {
    runScripts: 'outside-only', pretendToBeVisual: true, url: 'https://late.example/'
  });
  const w = dom.window;
  let captured = null;
  const realAttach = w.Element.prototype.attachShadow;
  w.Element.prototype.attachShadow = function (init) {
    const root = realAttach.call(this, { ...init, mode: 'open' });
    captured = root;
    return root;
  };
  w.fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve({ image_quality: 'auto' }) });
  w.Element.prototype.getBoundingClientRect = function () {
    return { left: 0, top: 0, width: 0, height: 0, right: 0, bottom: 0, x: 0, y: 0 };
  };

  // No body at all when the script runs.
  w.document.documentElement.removeChild(w.document.body || w.document.createElement('body'));
  let threw = null;
  try { w.eval(SCRIPT); } catch (e) { threw = e; }
  ok('no body: does not throw', threw === null, threw && threw.message);
  ok('no body: no panel yet', captured === null);

  // The body arrives, and the document announces itself.
  const body = w.document.createElement('body');
  w.document.documentElement.appendChild(body);
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
  ok('the panel is built once the body exists', captured !== null);
  ok('and the dot is in it', !!(captured && captured.getElementById('dot')));
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

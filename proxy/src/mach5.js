/*
 * mach5's in-page control panel and element picker.
 *
 * Served from `/.mach5/mach5.js` and injected into every HTML page, so it runs
 * on sites that have never heard of it and must be able to fail without taking
 * one down with it: everything is wrapped in try/catch, nothing is added to the
 * page until the picker is actually switched on, and the whole file is an IIFE
 * so it leaves exactly one name behind.
 *
 * The endpoints it talks to are relative URLs. Because the deployment answers
 * every DNS query with the proxy's address they reach us as same-origin
 * requests, which is also why this is a `<script src>` rather than an inline
 * script: a site whose CSP is `script-src 'self'` still runs it.
 *
 * The panel lives in a shadow root. Without one, every site's stylesheet would
 * reach into it and it would look different on each — and a site that styles
 * `div { position: static !important }` would break it outright.
 *
 * What the panel can change is deliberately small: image quality, and the
 * elements hidden here. Anything that would make mach5 *less safe* is not
 * reachable from a page at all, because everything under `/.mach5/` is
 * same-origin on every site and so is reachable by every site. See
 * `settings.rs`.
 */
(() => {
	'use strict';

	if (window.__mach5) {
		return;
	}
	window.__mach5 = true;

	// One picker per page, not one per ad frame.
	if (window.top !== window) {
		return;
	}

	/* Marks the elements we add, so the picker can never be aimed at itself. */
	const OURS = 'data-mach5';

	/* An id we are willing to write into a selector unescaped. Anything outside
	 * this needs CSS.escape to be safe, and the proxy drops odd characters from
	 * the stylesheet anyway — so a strange id is treated as no id at all. */
	const PLAIN_ID = /^[A-Za-z_-][\w-]*$/;

	const HELP = 'mach5: click an element to hide it · u unhides all · Esc to stop';

	/* Bottom right rather than top: on a phone that is where a thumb already
	 * is. Sites put their own chat widgets here too, which is why this sits
	 * quietly at low opacity until it is pointed at. */
	const PANEL_STYLE = `
		:host { all: initial }
		#dot {
			position: fixed; right: 16px; bottom: 16px; z-index: 2147483645;
			width: 34px; height: 34px; border-radius: 50%; border: 0;
			background: #202124; color: #fff; opacity: .45; cursor: pointer;
			font: 600 12px/34px system-ui, sans-serif; text-align: center;
			padding: 0; transition: opacity .15s;
		}
		#dot:hover, #dot:focus { opacity: 1 }
		#panel {
			position: fixed; right: 16px; bottom: 60px; z-index: 2147483646;
			width: 230px; padding: 14px; border-radius: 10px; display: none;
			background: #202124; color: #e8eaed; box-shadow: 0 6px 24px rgba(0,0,0,.4);
			font: 13px/1.5 system-ui, -apple-system, sans-serif;
		}
		#panel.open { display: block }
		h2 { font: 600 12px/1 system-ui, sans-serif; margin: 0 0 10px; opacity: .6;
			letter-spacing: .06em; text-transform: uppercase }
		fieldset { border: 0; margin: 0 0 12px; padding: 0 }
		.tiers { display: flex; gap: 4px }
		.tiers button {
			flex: 1; border: 1px solid #5f6368; background: transparent; color: inherit;
			border-radius: 5px; padding: 5px 0; font: inherit; cursor: pointer;
		}
		.tiers button[aria-pressed="true"] { background: #8ab4f8; color: #202124; border-color: #8ab4f8 }
		.act { display: block; width: 100%; margin-top: 6px; border: 0; border-radius: 5px;
			padding: 7px; font: inherit; cursor: pointer; background: #3c4043; color: inherit }
		.act:hover { background: #4a4e51 }
		a { color: #8ab4f8; display: inline-block; margin-top: 10px; font-size: 12px }
		p { margin: 0 0 8px; opacity: .7; font-size: 12px }
	`;

	const TIERS = [
		['auto', 'Auto'],
		['high', 'High'],
		['low', 'Low'],
		['off', 'None'],
	];

	let picking = false;
	let hovered = null;
	let outline = null;
	let badge = null;
	let shadow = null;
	let panel = null;
	let settings = { image_quality: 'auto' };

	/* A broken picker must never break the page it is sitting on. */
	const guard = (fn) => (event) => {
		try {
			fn(event);
		} catch (e) {
			/* deliberately swallowed */
		}
	};

	const chrome = () => {
		if (badge || !document.body) {
			return;
		}

		outline = document.createElement('div');
		outline.setAttribute(OURS, 'outline');
		outline.style.cssText =
			'position:fixed;z-index:2147483646;box-sizing:border-box;pointer-events:none;' +
			'display:none;border:2px solid #e11d48;background:rgba(225,29,72,.12)';

		badge = document.createElement('div');
		badge.setAttribute(OURS, 'badge');
		badge.style.cssText =
			'position:fixed;z-index:2147483647;top:12px;left:12px;padding:6px 10px;' +
			'border-radius:4px;background:#111;color:#fff;pointer-events:none;display:none;' +
			'font:12px/1.4 system-ui,sans-serif';
		badge.textContent = HELP;

		document.body.append(outline, badge);
	};

	/* Never the page's own frame, and never our own furniture. */
	const usable = (element) =>
		element instanceof Element &&
		!element.hasAttribute(OURS) &&
		element !== document.body &&
		element !== document.documentElement;

	const unique = (selector) => {
		try {
			return document.querySelectorAll(selector).length === 1;
		} catch (e) {
			return false;
		}
	};

	const byId = (element) => {
		const id = element.id;
		if (!id || !PLAIN_ID.test(id)) {
			return null;
		}

		const selector = '#' + id;

		return unique(selector) ? selector : null;
	};

	const step = (element) => {
		const tag = element.localName;
		let n = 1;

		for (let prior = element.previousElementSibling; prior; prior = prior.previousElementSibling) {
			if (prior.localName === tag) {
				n += 1;
			}
		}

		return tag + ':nth-of-type(' + n + ')';
	};

	/* Walk up from the element, one `tag:nth-of-type(n)` step at a time, and
	 * take the first prefix that already matches exactly one element. A longer
	 * path is more specific than it needs to be and breaks sooner the next time
	 * the page is rebuilt. An ancestor with a unique id ends the walk either
	 * way: it is a better root than `body`, and nothing above it can narrow the
	 * match any further.
	 *
	 * Returning null when nothing is unambiguous is the point. A selector that
	 * matches two elements would hide something nobody asked to hide. */
	const selectorFor = (element) => {
		const direct = byId(element);
		if (direct) {
			return direct;
		}

		const path = [];

		for (
			let node = element;
			node && node !== document.body && node !== document.documentElement;
			node = node.parentElement
		) {
			const anchor = byId(node);
			path.unshift(anchor || step(node));

			const selector = anchor ? path.join(' ') : 'body ' + path.join(' ');
			if (unique(selector)) {
				return selector;
			}

			if (anchor) {
				return null;
			}
		}

		return null;
	};

	const draw = () => {
		if (!outline) {
			return;
		}

		if (!hovered) {
			outline.style.display = 'none';

			return;
		}

		const box = hovered.getBoundingClientRect();
		outline.style.display = 'block';
		outline.style.left = box.left + 'px';
		outline.style.top = box.top + 'px';
		outline.style.width = box.width + 'px';
		outline.style.height = box.height + 'px';
	};

	const say = (text) => {
		if (!badge) {
			return;
		}

		badge.textContent = text;
		window.setTimeout(() => {
			try {
				badge.textContent = HELP;
			} catch (e) {
				/* deliberately swallowed */
			}
		}, 1500);
	};

	const toggle = (on) => {
		chrome();
		picking = on;
		hovered = null;

		if (badge) {
			badge.textContent = HELP;
			badge.style.display = on ? 'block' : 'none';
		}

		document.documentElement.style.cursor = on ? 'crosshair' : '';
		draw();
	};

	/* `credentials: 'omit'` because these endpoints authenticate nothing: the
	 * host in the URL decides which list is touched, so there is no reason to
	 * hand the site's cookies to the proxy. */
	/* fetch rejects only on a network failure: a refusal — a selector too long,
	 * a host at its cap, a disk that would not take it — arrives as a resolved
	 * promise with ok === false. Without this every caller's error handling
	 * below is dead code: a selector the proxy threw away looks exactly like
	 * one it stored, and a refused read of the settings parses as `{}` and
	 * wipes what the panel already knew. */
	const checked = (response) => {
		if (!response.ok) {
			throw new Error('mach5: refused with ' + response.status);
		}

		return response;
	};

	const post = (path, body) =>
		window.fetch(path, {
			method: 'POST',
			credentials: 'omit',
			headers: body ? { 'content-type': 'application/json' } : {},
			body: body || null
		}).then(checked);

	/* The panel, in a shadow root so no site's CSS can reach it. Built once, on
	 * the first frame after load — early enough to be there when wanted, late
	 * enough not to compete with the page for the first paint. */
	const buildPanel = () => {
		if (shadow || !document.body) {
			return;
		}

		const host = document.createElement('div');
		host.setAttribute(OURS, 'panel');
		shadow = host.attachShadow({ mode: 'closed' });

		const style = document.createElement('style');
		style.textContent = PANEL_STYLE;

		const dot = document.createElement('button');
		dot.id = 'dot';
		dot.textContent = 'm5';
		dot.title = 'mach5';
		dot.setAttribute('aria-label', 'mach5 controls');

		panel = document.createElement('div');
		panel.id = 'panel';
		panel.innerHTML = `
			<h2>mach5</h2>
			<fieldset>
				<p>Image quality</p>
				<div class="tiers"></div>
			</fieldset>
			<button class="act" data-act="pick">Hide an element</button>
			<button class="act" data-act="clear">Unhide all here</button>
			<a href="/.mach5/">Status and settings</a>
		`;

		const tiers = panel.querySelector('.tiers');
		for (const [value, label] of TIERS) {
			const button = document.createElement('button');
			button.textContent = label;
			button.dataset.tier = value;
			tiers.append(button);
		}

		shadow.append(style, dot, panel);
		document.body.append(host);

		dot.addEventListener('click', guard(() => togglePanel()));
		panel.addEventListener('click', guard(onPanelClick));

		refreshTiers();
	};

	const togglePanel = (open) => {
		if (!panel) {
			return;
		}

		const wanted = open === undefined ? !panel.classList.contains('open') : open;
		panel.classList.toggle('open', wanted);

		if (wanted) {
			// Read rather than assume: another tab may have changed these.
			window
				.fetch('/.mach5/settings', { credentials: 'omit' })
				.then(checked)
				.then((r) => r.json())
				.then((current) => {
					settings = current;
					refreshTiers();
				})
				.catch(() => {});
		}
	};

	const refreshTiers = () => {
		if (!panel) {
			return;
		}

		for (const button of panel.querySelectorAll('[data-tier]')) {
			const active = button.dataset.tier === settings.image_quality;
			button.setAttribute('aria-pressed', active ? 'true' : 'false');
		}
	};

	const onPanelClick = (event) => {
		const tier = event.target.closest('[data-tier]');
		if (tier) {
			// Moved before the proxy has agreed, because a control that waits
			// for a round trip feels broken. The panel has nowhere to print a
			// message — the picker's badge is not on screen here — so a refusal
			// puts the choice back where it was, and the button snapping back
			// is the message.
			const previous = settings;
			settings = Object.assign({}, settings, { image_quality: tier.dataset.tier });
			refreshTiers();
			post('/.mach5/settings', JSON.stringify(settings))
				.then((r) => r.json())
				.then((current) => {
					settings = current;
					refreshTiers();
				})
				.catch(() => {
					settings = previous;
					refreshTiers();
				});

			return;
		}

		const act = event.target.closest('[data-act]');
		if (!act) {
			return;
		}

		if (act.dataset.act === 'pick') {
			togglePanel(false);
			toggle(true);
		} else if (act.dataset.act === 'clear') {
			post('/.mach5/hidden/clear', null)
				.then(() => window.location.reload())
				.catch(() => say('mach5: could not clear this site'));
		}
	};

	const track = (event) => {
		if (!picking) {
			return;
		}

		hovered = usable(event.target) ? event.target : null;
		draw();
	};

	const grab = (event) => {
		if (!picking) {
			return;
		}

		// Capture phase, so the page never sees the click that hid its element.
		event.preventDefault();
		event.stopPropagation();

		if (!usable(event.target)) {
			return;
		}

		const selector = selectorFor(event.target);
		if (!selector) {
			say('mach5: no unambiguous selector for that element');

			return;
		}

		// Hide it here as well as storing it: the stylesheet only runs on the
		// next load, and waiting until then to see anything happen is horrible.
		event.target.style.setProperty('display', 'none', 'important');
		hovered = null;
		draw();

		post('/.mach5/hidden', JSON.stringify({ selector })).catch(() => {
			say('mach5: could not save that selector');
		});
	};

	/* Only one global shortcut, because every combination is somebody's already:
	 * Ctrl+Shift+U is eaten by IBus on Linux before a page ever sees it, and
	 * Ctrl+Shift+H is Firefox's history library. Clearing therefore lives inside
	 * picker mode, where a bare key is free — you are aiming at elements, not
	 * typing. */
	const keys = (event) => {
		if (picking && event.code === 'Escape') {
			toggle(false);

			return;
		}

		if (!picking && event.code === 'Escape' && panel) {
			togglePanel(false);
		}

		if (picking && event.code === 'KeyU' && !event.ctrlKey && !event.altKey && !event.metaKey) {
			event.preventDefault();
			post('/.mach5/hidden/clear', null)
				.then(() => window.location.reload())
				.catch(() => say('mach5: could not clear this site'));

			return;
		}

		if (event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey && event.code === 'KeyH') {
			event.preventDefault();
			// The panel, not the picker: one shortcut to remember, and picking
			// is a button inside it.
			togglePanel();
		}
	};

	/* `defer` means this normally runs with a body already parsed — but "normally"
	 * is doing work there, and the old code called buildPanel once and gave up if
	 * document.body was missing, leaving no panel and no way to get one. A page
	 * that replaces its body, or any parse mach5 did not predict, lost the picker
	 * silently. Try again when the document says it is ready. */
	const buildWhenThereIsABody = () => {
		buildPanel();
		if (!shadow) {
			document.addEventListener('DOMContentLoaded', guard(buildPanel), { once: true });
			window.addEventListener('load', guard(buildPanel), { once: true });
		}
	};

	try {
		buildWhenThereIsABody();
		document.addEventListener('keydown', guard(keys), true);
		document.addEventListener('mousemove', guard(track), true);
		document.addEventListener('click', guard(grab), true);
		window.addEventListener('scroll', guard(draw), true);
		window.addEventListener('resize', guard(draw), true);
	} catch (e) {
		/* deliberately swallowed */
	}
})();

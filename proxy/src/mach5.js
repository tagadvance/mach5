/*
 * mach5's in-page element picker.
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

	let picking = false;
	let hovered = null;
	let outline = null;
	let badge = null;

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
	const post = (path, body) =>
		window.fetch(path, {
			method: 'POST',
			credentials: 'omit',
			headers: body ? { 'content-type': 'application/json' } : {},
			body: body || null
		});

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

		if (picking && event.code === 'KeyU' && !event.ctrlKey && !event.altKey && !event.metaKey) {
			event.preventDefault();
			post('/.mach5/hidden/clear', null)
				.then(() => window.location.reload())
				.catch(() => say('mach5: could not clear this site'));

			return;
		}

		if (event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey && event.code === 'KeyH') {
			event.preventDefault();
			toggle(!picking);
		}
	};

	try {
		document.addEventListener('keydown', guard(keys), true);
		document.addEventListener('mousemove', guard(track), true);
		document.addEventListener('click', guard(grab), true);
		window.addEventListener('scroll', guard(draw), true);
		window.addEventListener('resize', guard(draw), true);
	} catch (e) {
		/* deliberately swallowed */
	}
})();

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

	const HELP = 'mach5: tap an element to choose it · u unhides all · Esc to stop';

	/* How long after a tap a click is still that tap's ghost. Preventing
	 * touchend stops the compatibility click in every browser that follows the
	 * spec, and this covers the ones that send it anyway. */
	const GHOST = 500;

	/* Bottom right rather than top: on a phone that is where a thumb already
	 * is. Sites put their own chat widgets here too, which is why this sits
	 * quietly at low opacity until it is pointed at. */
	const PANEL_STYLE = `
		:host { all: initial }
		#dot {
			position: fixed; right: 16px; bottom: 16px; z-index: 2147483645;
			width: 40px; height: 40px; border-radius: 50%; border: 0;
			background: #202124; color: #fff; opacity: .45; cursor: pointer;
			font: 600 12px/40px system-ui, sans-serif; text-align: center;
			padding: 0; transition: opacity .15s;
		}
		#dot:hover, #dot:focus { opacity: 1 }
		#panel {
			position: fixed; right: 16px; bottom: 64px; z-index: 2147483646;
			width: 230px; padding: 14px; border-radius: 10px; display: none;
			background: #202124; color: #e8eaed; box-shadow: 0 6px 24px rgba(0,0,0,.4);
			font: 13px/1.5 system-ui, -apple-system, sans-serif;
		}
		#panel.open { display: block }
		/* The panel is parked over the bottom right corner, which on a phone is
		 * exactly where sticky footers and ad slots live — so the thing being
		 * confirmed is often underneath it. The away class sends it to the top
		 * for as long as that is true; see place(). */
		#panel.away { top: 16px; bottom: auto }
		/* On a narrow screen 230px plus margins is most of the width anyway, so
		 * stop pretending and use it: bigger buttons, less wrapped selector. */
		@media (max-width: 420px) {
			#panel { left: 16px; right: 16px; width: auto }
		}
		h2 { font: 600 12px/1 system-ui, sans-serif; margin: 0 0 10px; opacity: .6;
			letter-spacing: .06em; text-transform: uppercase }
		fieldset { border: 0; margin: 0 0 12px; padding: 0 }
		.tiers { display: flex; gap: 4px }
		/* What the controls above have actually bought, because otherwise a
		 * quality tier is an act of faith: the tiers change compression rather
		 * than colour, so on a cached page nothing visibly happens at all. */
		.note { margin: 8px 0 0; opacity: .65; font-size: 12px }
		/* Five of them now, so they may not fit one row on a narrow phone. */
		.tiers { flex-wrap: wrap }
		.tiers button {
			flex: 1 1 3.2em; white-space: nowrap; border: 1px solid #5f6368; background: transparent; color: inherit;
			border-radius: 5px; padding: 5px 0; font: inherit; cursor: pointer;
		}
		.tiers button[aria-pressed="true"] { background: #8ab4f8; color: #202124; border-color: #8ab4f8 }
		/* 40px because this is aimed at with a thumb now, not a mouse. */
		.act { display: block; width: 100%; min-height: 40px; margin-top: 6px; border: 0;
			border-radius: 5px; padding: 9px; font: inherit; cursor: pointer;
			background: #3c4043; color: inherit }
		.act:hover { background: #4a4e51 }
		.act[disabled] { opacity: .4; cursor: default }
		.act[disabled]:hover { background: #3c4043 }
		#hide { background: #e11d48; color: #fff }
		#hide:hover { background: #f43f5e }
		#hide[disabled]:hover { background: #e11d48 }
		a { color: #8ab4f8; display: inline-block; margin-top: 10px; font-size: 12px }
		p { margin: 0 0 8px; opacity: .7; font-size: 12px }
		/* Only one of these three is on screen at a time: the ordinary controls,
		 * the confirmation for what was just tapped, or neither. The undo line
		 * sits above the ordinary controls once there is something to undo. */
		#confirm, #undo { display: none }
		#panel.confirming #main { display: none }
		#panel.confirming #confirm { display: block }
		#panel.undoable #undo { display: block }
		#what { opacity: .9; font-size: 13px; margin: 0 0 6px }
		#sel, #hidden { display: block; margin: 0 0 10px; padding: 6px; border-radius: 4px;
			background: #17181a; word-break: break-all; opacity: .85;
			font: 11px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace }
		#undo { margin: 0 0 14px }
	`;

	/* Labelled by what you get rather than by what mach5 does internally, and
	 * ordered so that left to right is monotonically fewer bytes.
	 *
	 * Both were wrong. `off` was shown as "None", which reads as "no images"
	 * and means the exact opposite — leave the origin's images alone. And it
	 * sat to the right of "Low" in what looks like a quality scale, while
	 * being the *highest* quality of the lot. */
	const TIERS = [
		['off', 'As-is'],
		['high', 'High'],
		['auto', 'Auto'],
		['low', 'Low'],
		['none', 'None'],
	];

	let picking = false;
	let hovered = null;
	/* What a tap chose and is waiting on Hide, Wider or Cancel. Aiming and
	 * hiding used to be the same gesture, which is fine with a mouse — you can
	 * see the outline before you commit — and unusable with a finger, where the
	 * first feedback of any kind arrived after the element was already gone. */
	let candidate = null;
	let chosen = null;
	/* The last thing hidden, kept so it can be taken back. This is what `u` used
	 * to be for people with a keyboard. */
	let undone = null;
	let tapped = 0;
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
		if (badge || !shadow) {
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

		/* In the shadow root rather than in the page, which is where they used
		 * to be. `position: fixed` is relative to the viewport either way, so
		 * nothing about how they land changes — but a bare div in document.body
		 * is reachable by the page's stylesheet and deletable by its framework,
		 * and these are the two things a person is asked to check before
		 * hiding something. */
		shadow.append(outline, badge);
	};

	/* Never the page's own frame, and never our own furniture. */
	const usable = (element) =>
		element instanceof Element &&
		!element.hasAttribute(OURS) &&
		element !== document.body &&
		element !== document.documentElement;

	/* Our own furniture, including everything inside the panel. A click there is
	 * the user working the controls, not aiming at the page, and the picker has
	 * to let it past untouched — its capture-phase handler runs first and would
	 * otherwise swallow the click on Hide before the panel ever saw it.
	 *
	 * A click inside the shadow root reaches a listener out here retargeted to
	 * the host, which carries the attribute; the root-node check covers a node
	 * of ours that is aimed at directly. */
	const mine = (node) =>
		node instanceof Element &&
		(node.closest('[' + OURS + ']') !== null || node.getRootNode() === shadow);

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
	 * match any further. */
	const shortest = (element) => {
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

	/* The same path with `>` between every step instead of a space, which is
	 * always unique and so is what we fall back to.
	 *
	 * The descendant walk above cannot name a wrapper in a chain of only-children
	 * — `body div:nth-of-type(1) div:nth-of-type(1)` matches the wrapper *and*
	 * everything nested below it, because a space permits gaps. That shape is
	 * most of the modern web, and `Wider` walks straight into it, so refusing
	 * there meant refusing exactly where a finger needs the most help.
	 *
	 * Child steps pin each level to its actual parent, so tag plus position among
	 * its siblings identifies one element and no other. The cost is a selector
	 * that breaks when the page is rebuilt, which is why it is second choice
	 * rather than first. */
	const exact = (element) => {
		const path = [];

		for (
			let node = element;
			node && node !== document.documentElement;
			node = node.parentElement
		) {
			const anchor = byId(node);
			if (anchor) {
				path.unshift(anchor);
				return path.join(' > ');
			}

			if (node === document.body) {
				path.unshift('body');
				return path.join(' > ');
			}

			path.unshift(step(node));
		}

		return null;
	};

	/* Returning null still has to mean something, so it is kept for the one case
	 * that is genuinely unnameable: an element that is not under `body` at all. */
	const selectorFor = (element) => byId(element) || shortest(element) || exact(element);

	/* Keeps the panel off whatever is being confirmed, because a candidate in
	 * the bottom right corner is otherwise underneath it and the outline the
	 * user is being asked to check is the half they cannot see.
	 *
	 * Measured with `away` taken off first: left on, the panel would be scoring
	 * the overlap against where it had already moved to and would flip back and
	 * forth every time the page scrolled. */
	const place = (box) => {
		if (!panel) {
			return;
		}

		panel.classList.remove('away');

		const own = panel.getBoundingClientRect();
		const overlaps =
			box.left < own.right && box.right > own.left &&
			box.top < own.bottom && box.bottom > own.top;

		panel.classList.toggle('away', overlaps);
	};

	const draw = () => {
		if (!outline) {
			return;
		}

		/* A candidate pins the outline. Once something is chosen the pointer or
		 * the finger has to travel to the buttons, and an outline that kept
		 * following would leave the user confirming something else. */
		const target = candidate || hovered;

		if (!target) {
			outline.style.display = 'none';

			return;
		}

		const box = target.getBoundingClientRect();
		outline.style.display = 'block';
		outline.style.left = box.left + 'px';
		outline.style.top = box.top + 'px';
		outline.style.width = box.width + 'px';
		outline.style.height = box.height + 'px';

		if (candidate) {
			place(box);
		}
	};

	const say = (text) => {
		if (!badge) {
			return;
		}

		badge.textContent = text;
		/* Shown even outside picker mode: Undo and the quality controls can both
		 * fail with the badge parked, and a refusal nobody sees is a refusal
		 * that looks like success. */
		badge.style.display = 'block';
		window.setTimeout(() => {
			try {
				badge.textContent = HELP;
				badge.style.display = picking ? 'block' : 'none';
			} catch (e) {
				/* deliberately swallowed */
			}
		}, 1500);
	};

	const toggle = (on) => {
		chrome();
		picking = on;
		hovered = null;
		candidate = null;
		chosen = null;

		if (panel) {
			panel.classList.remove('confirming', 'away');
		}

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
	/* Put the host back when the page takes it away.
	 *
	 * A framework that owns document.body reconciles its children and removes
	 * anything it did not create, which is exactly what ours is. Every SPA
	 * hydration pass does this, and it took the panel, the outline and the
	 * badge with it — then nothing rebuilt them, because both builders returned
	 * early on a variable that was still truthy while detached. That is a
	 * picker that works on a static page and silently does not exist on a React
	 * one, which is most of what a phone visits.
	 *
	 * Shallow `childList` on each, not a subtree observer: this must not fire
	 * on every DOM change a busy page makes. documentElement catches the body
	 * being replaced outright, and body catches its children being reconciled. */
	const stayMounted = (host) => {
		if (typeof MutationObserver !== 'function') {
			return;
		}

		/* A page determined to remove it will win, and that is fine — what is
		 * not fine is trading appends with it forever. */
		let puts = 0;
		let watched = null;

		const observer = new MutationObserver(() => {
			if (!document.body) {
				return;
			}

			if (document.body !== watched) {
				watched = document.body;
				observer.observe(watched, { childList: true });
			}

			if (!host.isConnected && puts < 20) {
				puts += 1;
				document.body.append(host);
			}
		});

		observer.observe(document.documentElement, { childList: true });
		watched = document.body;
		observer.observe(watched, { childList: true });
	};

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
			<div id="main">
				<div id="undo">
					<p>Hidden just now</p>
					<code id="hidden"></code>
					<button class="act" data-act="undo">Undo</button>
				</div>
				<fieldset>
					<p>Image quality</p>
					<div class="tiers"></div>
					<p id="saved" class="note"></p>
				</fieldset>
				<button class="act" data-act="pick">Hide an element</button>
				<button class="act" data-act="clear">Unhide all here</button>
				<a href="/.mach5/">Status and settings</a>
			</div>
			<div id="confirm">
				<p id="what"></p>
				<code id="sel"></code>
				<button class="act" id="hide" data-act="hide">Hide</button>
				<button class="act" data-act="wider">Wider</button>
				<button class="act" data-act="cancel">Cancel</button>
			</div>
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
		stayMounted(host);

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

			refreshSaved();
		}
	};

	/* Bytes, in the largest unit that leaves a number worth reading. Mirrors
	 * what the status page does server-side, rather than printing a count of
	 * bytes nobody can parse at a glance. */
	const bytes = (n) => {
		if (!(n > 0)) {
			return '0 B';
		}

		const units = ['B', 'kB', 'MB', 'GB', 'TB'];
		let scaled = n;
		let unit = 0;
		while (scaled >= 1024 && unit < units.length - 1) {
			scaled /= 1024;
			unit += 1;
		}

		return (unit === 0 ? scaled : scaled.toFixed(1)) + ' ' + units[unit];
	};

	/* What the proxy has saved, and what it thinks this link can carry.
	 *
	 * Both are already on the status page, which is a tap away and a page load
	 * later. Here because the quality control is here: changing a tier and
	 * seeing no difference is what "the selector isn't working" looks like when
	 * it is working, since the tiers change compression and the browser is
	 * serving the old picture from its own cache anyway. */
	const refreshSaved = () => {
		if (!panel) {
			return;
		}

		window
			.fetch('/.mach5/stats.json', { credentials: 'omit' })
			.then(checked)
			.then((r) => r.json())
			.then((stats) => {
				const line = panel.querySelector('#saved');
				if (!line) {
					return;
				}

				const saved = bytes(
					(stats.bytes_saved_by_images || 0) + (stats.bytes_saved_by_compression || 0),
				);
				// Absent means nobody has measured this client yet, which is
				// not the same as a fast one — so it says so rather than
				// claiming a tier it has not earned.
				const link = stats.link_tier
					? stats.link_tier + (stats.link_kbps ? ' · ' + stats.link_kbps + ' kbps' : '')
					: 'not measured yet';

				line.textContent = saved + ' saved · link: ' + link;
			})
			.catch(() => {});
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

	/* Something a person can check the outline against. A selector on its own
	 * does not answer the question that matters — did I get the advert or the
	 * picture inside it — and a size does. */
	const describe = (element) => {
		const box = element.getBoundingClientRect();
		/* SVG hands back an SVGAnimatedString rather than a string. */
		const classes = typeof element.className === 'string' ? element.className.trim() : '';
		const hint = element.id ? '#' + element.id : classes ? '.' + classes.split(/\s+/)[0] : '';

		return element.localName + hint + ' · ' + Math.round(box.width) + ' × ' + Math.round(box.height);
	};

	const render = () => {
		if (!panel) {
			return;
		}

		panel.classList.toggle('confirming', !!candidate);
		panel.classList.toggle('undoable', !!undone);

		if (candidate) {
			panel.querySelector('#what').textContent = describe(candidate);
			panel.querySelector('#sel').textContent =
				chosen || 'nothing unambiguous points at this one — try Wider';
			// Nothing to store means nothing to hide; Wider is the way out.
			panel.querySelector('[data-act="hide"]').disabled = !chosen;
			panel.querySelector('[data-act="wider"]').disabled = !usable(candidate.parentElement);
		}

		if (undone) {
			panel.querySelector('#hidden').textContent = undone.selector;
		}
	};

	/* Chooses rather than hides. On a phone this is the first moment the user
	 * can see what they are aiming at, so hiding here would mean hiding things
	 * sight unseen — which is exactly what the old click-to-hide did. */
	const choose = (element) => {
		candidate = element;
		chosen = selectorFor(element);
		hovered = null;

		if (panel) {
			panel.classList.add('open');
		}

		render();
		draw();
	};

	/* A finger cannot aim at a container rather than its contents: tapping an
	 * advert lands on the image inside it every time. Walking up is how the
	 * advert itself gets picked, and `usable` ends the walk below body — hiding
	 * that would hide the site. */
	const wider = () => {
		if (candidate && usable(candidate.parentElement)) {
			choose(candidate.parentElement);
		}
	};

	const restore = (element, had) => {
		if (had.display) {
			element.style.setProperty('display', had.display, had.priority);
		} else {
			element.style.removeProperty('display');
		}
	};

	const hide = () => {
		if (!candidate || !chosen) {
			return;
		}

		const element = candidate;
		const selector = chosen;
		/* What the page had, so that Undo and a refusal can both put it back
		 * rather than guessing at `display: block`. */
		const had = {
			display: element.style.getPropertyValue('display'),
			priority: element.style.getPropertyPriority('display')
		};

		// Hide it here as well as storing it: the stylesheet only runs on the
		// next load, and waiting until then to see anything happen is horrible.
		element.style.setProperty('display', 'none', 'important');
		candidate = null;
		chosen = null;
		render();
		draw();

		post('/.mach5/hidden', JSON.stringify({ selector }))
			.then(() => {
				undone = { selector, element, had };
				render();
			})
			.catch(() => {
				/* Nothing was stored, so leaving it hidden is a lie that lasts
				 * until the next load quietly brings it back. */
				restore(element, had);
				say('mach5: could not save that selector');
			});
	};

	/* The same endpoint the status page's remove button uses, so one selector
	 * goes and the rest of this host's list stays. It sits in the panel until
	 * it is used or something else is hidden, because the moment you want it is
	 * a second or two after you look up and see the wrong thing missing. */
	const undo = () => {
		if (!undone) {
			return;
		}

		const { selector, element, had } = undone;

		post('/.mach5/hidden/remove', JSON.stringify({ selector }))
			.then(() => {
				restore(element, had);
				undone = null;
				render();
			})
			.catch(() => say('mach5: could not undo that'));
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

		if (act.disabled) {
			return;
		}

		if (act.dataset.act === 'pick') {
			togglePanel(false);
			toggle(true);
		} else if (act.dataset.act === 'clear') {
			post('/.mach5/hidden/clear', null)
				.then(() => window.location.reload())
				.catch(() => say('mach5: could not clear this site'));
		} else if (act.dataset.act === 'hide') {
			hide();
		} else if (act.dataset.act === 'wider') {
			wider();
		} else if (act.dataset.act === 'cancel') {
			// Out of picker mode entirely, and nothing hidden. The panel goes
			// with it: it is only open because something was being confirmed.
			toggle(false);
			panel.classList.remove('open');
		} else if (act.dataset.act === 'undo') {
			undo();
		}
	};

	const track = (event) => {
		if (!picking || candidate) {
			return;
		}

		hovered = usable(event.target) ? event.target : null;
		draw();
	};

	/* Touch has no hover, so the outline follows the finger while it is down and
	 * the tap that ends the gesture chooses whatever it was last over. That is
	 * the whole reason the picker was unusable on a phone: mousemove never
	 * fires, so the first feedback of any kind used to be the element vanishing.
	 *
	 * Registered passive, and it never calls preventDefault: picking must not
	 * stop the page scrolling, which is the only way to reach anything below the
	 * fold on a phone. */
	const finger = (event) => {
		if (!picking || candidate) {
			return;
		}

		const touch = event.touches[0];
		if (!touch) {
			return;
		}

		/* touchmove keeps reporting the element the gesture started on, so what
		 * is under the finger now has to be hit-tested for. */
		const element = document.elementFromPoint(touch.clientX, touch.clientY);
		hovered = usable(element) ? element : null;
		draw();
	};

	/* Lifting is what chooses, rather than the click the browser sends after a
	 * tap: that click is aimed at the element the finger came down on, which
	 * after any drag at all is not the one the outline has been showing. Hit
	 * testing where the finger left instead is the only way the preview above
	 * and the thing chosen are the same element.
	 *
	 * Preventing it also stops that compatibility click, which is why this one
	 * cannot be passive. */
	const lift = (event) => {
		if (!picking || mine(event.target)) {
			return;
		}

		const touch = event.changedTouches[0];
		if (!touch) {
			return;
		}

		event.preventDefault();
		tapped = Date.now();

		const element = document.elementFromPoint(touch.clientX, touch.clientY);
		if (usable(element)) {
			choose(element);
		}
	};

	const grab = (event) => {
		if (!picking) {
			return;
		}

		/* Before the preventDefault below, not after: this handler is on the
		 * capture phase, and stopping a click on Hide or Cancel here would kill
		 * the panel's own listener before it ran. */
		if (mine(event.target)) {
			return;
		}

		// Capture phase, so the page never sees the click that chose an element.
		event.preventDefault();
		event.stopPropagation();

		/* A tap that touchend has already dealt with. Swallowed rather than
		 * acted on, because a ghost click carries the element the finger
		 * started on and would quietly re-choose what the user dragged away
		 * from. */
		if (Date.now() - tapped < GHOST) {
			return;
		}

		if (!usable(event.target)) {
			return;
		}

		choose(event.target);
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
		document.addEventListener('touchstart', guard(finger), { capture: true, passive: true });
		document.addEventListener('touchmove', guard(finger), { capture: true, passive: true });
		document.addEventListener('touchend', guard(lift), true);
		document.addEventListener('click', guard(grab), true);
		window.addEventListener('scroll', guard(draw), true);
		window.addEventListener('resize', guard(draw), true);
	} catch (e) {
		/* deliberately swallowed */
	}
})();

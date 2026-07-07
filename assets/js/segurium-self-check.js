/**
 * Self-Check tab controller: renders the security grade, runs the
 * AJAX scan, and wires Fix-button navigation to the target tab.
 *
 * Depends on the global `seguriumScan` object for ajaxUrl + nonce +
 * i18n, and `window.seguriumSelfCheck` for server-side bootstrap
 * payload (last cached result + history).
 */
(function () {
	'use strict';

	var cfg   = (typeof window !== 'undefined' && window.seguriumScan) ? window.seguriumScan : {};
	var boot  = (typeof window !== 'undefined' && window.seguriumSelfCheck) ? window.seguriumSelfCheck : { last: null, history: [] };
	var i18n  = cfg.i18n || {};
	function $ (id) { return document.getElementById(id); }

	function t (key, fallback) {
		return (i18n && typeof i18n[key] === 'string') ? i18n[key] : fallback;
	}

	function format (template, values) {
		var result = template;
		values = values || {};
		for (var k in values) {
			if (Object.prototype.hasOwnProperty.call(values, k)) {
				result = result.split('{' + k + '}').join(String(values[k]));
			}
		}
		return result;
	}

	function sprintf (template) {
		var args = Array.prototype.slice.call(arguments, 1);
		return template.replace(/%(\d+)\$[ds]/g, function (_m, idx) {
			return String(args[parseInt(idx, 10) - 1]);
		}).replace(/%[ds]/g, function () {
			return String(args.shift());
		});
	}

	function humanSince (ts) {
		if (!ts) { return ''; }
		var diff = Math.max(0, Math.floor((Date.now() / 1000) - ts));
		if (diff < 60)      { return diff + 's'; }
		if (diff < 3600)    { return Math.floor(diff / 60) + 'm'; }
		if (diff < 86400)   { return Math.floor(diff / 3600) + 'h'; }
		return Math.floor(diff / 86400) + 'd';
	}

	function categoryLabel (key) {
		switch (key) {
			case 'headers':    return t('scCategoryHeaders', 'HTTP Security Headers');
			case 'disclosure': return t('scCategoryDisclosure', 'Information Disclosure');
			case 'hardening':  return t('scCategoryHardening', 'WordPress Hardening');
			case 'cookies':    return t('scCategoryCookies', 'Cookie Security');
			case 'malware':    return t('scCategoryMalware', 'Malware Protection');
			default:           return key;
		}
	}

	function statusIcon (status) {
		if (status === 'pass') { return '\u2714'; }
		if (status === 'warn' || status === 'partial') { return '\u26A0'; }
		return '\u2716';
	}

	function renderExternalLinks () {
		var origin = window.location.origin || (window.location.protocol + '//' + window.location.host);
		var host   = window.location.host;
		var sh = $('segurium-sc-sh-link');
		var mo = $('segurium-sc-mo-link');
		if (sh) { sh.href = 'https://securityheaders.com/?q=' + encodeURIComponent(origin) + '&hide=on&followRedirects=on'; }
		if (mo) { mo.href = 'https://developer.mozilla.org/en-US/observatory/analyze?host=' + encodeURIComponent(host); }
	}

	function renderGrade (result) {
		var grade = $('segurium-sc-grade');
		if (!grade) { return; }
		grade.setAttribute('data-grade', result.grade || '');
		var letterEl = grade.querySelector('.segurium-sc-grade-letter');
		var scoreEl  = grade.querySelector('.segurium-sc-grade-score');
		if (letterEl) { letterEl.textContent = result.grade || '\u2014'; }
		if (scoreEl)  { scoreEl.textContent = sprintf(t('scScoreOutOf', '%1$d/100'), result.score || 0); }

		var scannedAt = $('segurium-sc-scanned-at');
		if (scannedAt) {
			scannedAt.textContent = result.scanned_at
				? sprintf(t('scLastRun', 'Last checked %s ago.'), humanSince(result.scanned_at))
				: '';
		}

		var ping = $('segurium-sc-ping-error');
		if (ping) {
			if (result.self_ping_error) {
				ping.style.display = '';
				ping.textContent = sprintf(t('scSelfPingError', 'Self-check could not reach your site: %s. Results are incomplete.'), result.self_ping_error);
			} else {
				ping.style.display = 'none';
				ping.textContent = '';
			}
		}
	}

	function renderDelta (result, history) {
		var el = $('segurium-sc-delta');
		if (!el) { return; }
		if (!history || history.length < 2) { el.textContent = ''; return; }
		var prev = history[history.length - 2];
		var last = history[history.length - 1];
		if (!prev || !last) { el.textContent = ''; return; }
		if (prev.score === last.score && prev.grade === last.grade) {
			el.textContent = t('scNoChange', 'No change since last run.');
		} else {
			el.textContent = sprintf(
				t('scChangedFromTo', 'Changed from %1$s (%2$d) to %3$s (%4$d).'),
				prev.grade, prev.score, last.grade, last.score
			);
		}
	}

	function renderCategories (cats) {
		var wrap = $('segurium-sc-categories');
		if (!wrap) { return; }
		wrap.innerHTML = '';
		if (!cats) { return; }
		var order = ['hardening', 'malware', 'disclosure', 'cookies', 'headers'];
		order.forEach(function (key) {
			var c = cats[key];
			if (!c) { return; }
			var row = document.createElement('div');
			row.className = 'segurium-sc-cat-row';

			var name = document.createElement('div');
			name.className = 'segurium-sc-cat-name';
			name.textContent = categoryLabel(key);

			var bar = document.createElement('div');
			bar.className = 'segurium-sc-cat-bar';
			['pass', 'partial', 'warn', 'fail'].forEach(function (s) {
				if (c[s] > 0) {
					var seg = document.createElement('span');
					seg.className = s;
					seg.style.flexGrow = String(c[s]);
					bar.appendChild(seg);
				}
			});

			// `partial` rolls up with `warn` for category counts so we don't
			// proliferate UI buckets for what is functionally a soft fail.
			var warnish = (c.warn || 0) + (c.partial || 0);
			var counts = document.createElement('div');
			counts.className = 'segurium-sc-cat-counts';
			counts.textContent = sprintf(
				t('scPassWarnFail', '%1$d pass, %2$d warn, %3$d fail'),
				c.pass || 0, warnish, c.fail || 0
			);

			row.appendChild(name);
			row.appendChild(bar);
			row.appendChild(counts);
			wrap.appendChild(row);
		});
	}

	function renderChecks (checks) {
		var wrap = $('segurium-sc-checks');
		if (!wrap) { return; }
		wrap.innerHTML = '';
		if (!Array.isArray(checks)) { return; }

		var order = ['hardening', 'malware', 'disclosure', 'cookies', 'headers'];
		var grouped = { hardening: [], malware: [], disclosure: [], cookies: [], headers: [] };
		checks.forEach(function (c) {
			if (grouped[c.category]) { grouped[c.category].push(c); }
		});

		var statusOrder = { fail: 0, partial: 1, warn: 2, pass: 3 };
		order.forEach(function (cat) {
			grouped[cat].sort(function (a, b) {
				return (statusOrder[a.status] || 0) - (statusOrder[b.status] || 0);
			});
		});

		order.forEach(function (cat) {
			if (grouped[cat].length === 0) { return; }

			var fails = grouped[cat].filter(function (c) { return c.status === 'fail'; }).length;
			// `partial` rolls up with `warn` in the category badge.
			var warns = grouped[cat].filter(function (c) { return c.status === 'warn' || c.status === 'partial'; }).length;

			var group = document.createElement('div');
			group.className = 'segurium-sc-group';

			var header = document.createElement('button');
			header.type = 'button';
			header.className = 'segurium-sc-cat-header';
			header.setAttribute('aria-expanded', 'false');

			var titleSpan = document.createElement('span');
			titleSpan.className = 'segurium-sc-cat-title';
			titleSpan.textContent = categoryLabel(cat);
			header.appendChild(titleSpan);

			var badges = document.createElement('span');
			badges.className = 'segurium-sc-cat-badges';
			if (fails > 0) {
				var fb = document.createElement('span');
				fb.className = 'segurium-sc-badge segurium-sc-badge--fail';
				fb.textContent = fails + ' ' + t('scFail', 'fail');
				badges.appendChild(fb);
			}
			if (warns > 0) {
				var wb = document.createElement('span');
				wb.className = 'segurium-sc-badge segurium-sc-badge--warn';
				wb.textContent = warns + ' ' + t('scWarn', 'warn');
				badges.appendChild(wb);
			}
			header.appendChild(badges);

			var arrow = document.createElement('span');
			arrow.className = 'segurium-sc-cat-arrow';
			arrow.setAttribute('aria-hidden', 'true');
			header.appendChild(arrow);

			var items = document.createElement('div');
			items.className = 'segurium-sc-group-items';

			grouped[cat].forEach(function (c) {
				var row = document.createElement('div');
				row.className = 'segurium-sc-check';
				row.setAttribute('data-status', c.status);
				row.setAttribute('role', 'listitem');

				var icon = document.createElement('span');
				icon.className = 'segurium-sc-icon';
				icon.setAttribute('aria-hidden', 'true');
				icon.textContent = statusIcon(c.status);

				var body = document.createElement('div');
				body.className = 'segurium-sc-body';

				var label = document.createElement('div');
				label.className = 'segurium-sc-label';
				label.textContent = c.label;

				var detail = document.createElement('div');
				detail.className = 'segurium-sc-detail';
				detail.textContent = c.detail;

				body.appendChild(label);
				body.appendChild(detail);

				var action = document.createElement('div');
				action.className = 'segurium-sc-action';

				var hasHelp = typeof c.help_html === 'string' && c.help_html !== '';
				var help    = null;
				var helpBtn = null;
				var showTxt = t('scHowToFix', 'How to fix');
				var hideTxt = t('scHideFix', 'Hide details');

				if (c.status !== 'pass' && hasHelp) {
					help = document.createElement('div');
					help.className = 'segurium-sc-help';
					help.innerHTML = c.help_html;
					help.hidden    = true;

					helpBtn = document.createElement('button');
					helpBtn.type = 'button';
					helpBtn.className = 'button button-secondary segurium-sc-help-toggle';
					helpBtn.setAttribute('aria-expanded', 'false');
					helpBtn.textContent = showTxt;
					helpBtn.addEventListener('click', function () {
						var expanded = helpBtn.getAttribute('aria-expanded') === 'true';
						helpBtn.setAttribute('aria-expanded', expanded ? 'false' : 'true');
						helpBtn.textContent = expanded ? showTxt : hideTxt;
						help.hidden = expanded;
					});
					action.appendChild(helpBtn);
				} else if (c.fix_tab && c.status !== 'pass') {
					var btn = document.createElement('button');
					btn.type = 'button';
					btn.className = 'button button-secondary segurium-sc-fix';
					btn.setAttribute('data-fix-tab', c.fix_tab);
					btn.textContent = t('scFix', 'Fix');
					action.appendChild(btn);
				}

				row.appendChild(icon);
				row.appendChild(body);
				row.appendChild(action);
				if (help) {
					row.appendChild(help);
				}
				items.appendChild(row);
			});

			header.addEventListener('click', function () {
				var expanded = header.getAttribute('aria-expanded') === 'true';
				header.setAttribute('aria-expanded', expanded ? 'false' : 'true');
			});

			group.appendChild(header);
			group.appendChild(items);
			wrap.appendChild(group);
		});
	}

	function renderResult (result, history) {
		if (!result) {
			var scannedAt = $('segurium-sc-scanned-at');
			if (scannedAt) { scannedAt.textContent = t('scNeverRun', 'Click Run Self-Check to grade your site.'); }
			renderExternalLinks();
			return;
		}
		renderGrade(result);
		renderDelta(result, history);
		renderCategories(result.categories);
		renderChecks(result.checks);
		renderExternalLinks();
	}

	function navigateToFix (tabId) {
		var nav = document.querySelector('.segurium-nav-item[data-feature="' + tabId + '"]');
		if (nav) { nav.click(); }
	}

	function showStatus (message) {
		var slot = $('segurium-sc-ping-error');
		if (!slot) { return; }
		if (!message) {
			slot.style.display = 'none';
			slot.textContent = '';
		} else {
			slot.style.display = '';
			slot.textContent = message;
		}
	}

	function runScan (force) {
		showStatus('');

		var btn = $('segurium-sc-run');
		var originalLabel = btn ? btn.textContent : '';
		if (btn) {
			btn.disabled = true;
			btn.textContent = t('scRunning', 'Running...');
		}

		var body = new FormData();
		body.append('action', 'segurium_run_self_check');
		body.append('nonce', cfg.selfCheckNonce || '');
		body.append('force', force ? '1' : '0');

		fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
			.then(window.seguriumParseResponse)
			.then(function (res) {
				if (res && res.success) {
					boot.history = (boot.history || []).concat([{
						score: res.data.score,
						grade: res.data.grade,
						scanned_at: res.data.scanned_at
					}]);
					if (boot.history.length > 10) { boot.history = boot.history.slice(-10); }
					boot.last = res.data;
					renderResult(res.data, boot.history);
				} else {
					showStatus((res && res.data && res.data.message) || t('errGeneric', 'Request failed'));
				}
			})
			.catch(function () { showStatus(t('errNetworkError', 'Network error.')); })
			.then(function () {
				if (btn) {
					btn.disabled = false;
					btn.textContent = originalLabel || t('scRun', 'Run Self-Check');
				}
			});
	}

	document.addEventListener('DOMContentLoaded', function () {
		var runBtn = $('segurium-sc-run');
		if (!runBtn) { return; }
		runBtn.addEventListener('click', function () { runScan(true); });

		var checksWrap = $('segurium-sc-checks');
		if (checksWrap) {
			checksWrap.addEventListener('click', function (ev) {
				var target = ev.target;
				while (target && target !== checksWrap) {
					if (target.classList && target.classList.contains('segurium-sc-fix')) {
						var tab = target.getAttribute('data-fix-tab');
						if (tab) { navigateToFix(tab); }
						return;
					}
					target = target.parentNode;
				}
			});
		}

		renderResult(boot.last, boot.history || []);

		// SEGURIUM-435: cold-start auto-run. Fires once per install, when
		// the Self-Check tab opens with an empty history table. The
		// `historyEmpty` server flag is authoritative — it is computed
		// from `self_check_history` rows, not from this in-memory
		// `boot.history` (which is also empty before any run, by
		// construction). Once one row exists the flag is false and the
		// JS never auto-runs again. The Self-Check tab is the default-
		// active one in PHP, so DOMContentLoaded is the right hook.
		if (boot.historyEmpty === true) {
			runScan(false);
		}
	});
})();

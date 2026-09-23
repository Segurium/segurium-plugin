/**
 * Self-Check tab controller: renders the security grade, runs the
 * AJAX scan, applies in-place fixes one by one or all at once, hands
 * stale malware rows to the scanner, rescores after a scan finishes,
 * and wires the remaining Fix buttons to their target tab.
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

	// Per-row messages that outlive a re-render, keyed by check id.
	// Populated when a write lands but the rescore cannot observe it, or
	// when Fix all could not write a row.
	var rowNotices = {};

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

	function categoryBar (counts) {
		var bar = document.createElement('span');
		bar.className = 'segurium-sc-cat-bar';
		['pass', 'partial', 'warn', 'fail'].forEach(function (s) {
			if (counts[s] > 0) {
				var seg = document.createElement('span');
				seg.className = s;
				seg.style.flexGrow = String(counts[s]);
				bar.appendChild(seg);
			}
		});
		return bar;
	}

	function hasPending (checks, flag) {
		return Array.isArray(checks) && checks.some(function (c) {
			return c.status !== 'pass' && c[flag];
		});
	}

	function fixButton (className, attr, value) {
		var b = document.createElement('button');
		b.type = 'button';
		b.className = className;
		if (attr) { b.setAttribute(attr, value); }
		b.textContent = t('scFix', 'Fix');
		return b;
	}

	function notVisibleText () {
		return t(
			'scFixNotVisible',
			'Setting saved. Your page cache is still serving the old response, so this row will clear once the cache refreshes.'
		);
	}

	function renderChecks (checks, categories) {
		var wrap = $('segurium-sc-checks');
		if (!wrap) { return; }

		// Applying a fix redraws the whole list. Carry each group's open
		// state across so the user keeps the place they were reading.
		var wasOpen = {};
		Array.prototype.forEach.call(wrap.querySelectorAll('.segurium-sc-group'), function (g) {
			var head = g.querySelector('.segurium-sc-cat-header');
			if (head) {
				wasOpen[g.getAttribute('data-category')] = head.getAttribute('aria-expanded') === 'true';
			}
		});

		wrap.innerHTML = '';
		if (!Array.isArray(checks)) { return; }

		var order = ['malware', 'hardening', 'disclosure', 'cookies', 'headers'];
		var grouped = { malware: [], hardening: [], disclosure: [], cookies: [], headers: [] };
		checks.forEach(function (c) {
			if (grouped[c.category]) { grouped[c.category].push(c); }
		});

		var statusOrder = { fail: 0, partial: 1, warn: 2, pass: 3 };
		var pinned = function (c) { return c.id === 'malware_fresh' && c.status === 'fail'; };
		order.forEach(function (cat) {
			grouped[cat].sort(function (a, b) {
				return (pinned(b) - pinned(a)) || (statusOrder[a.status] || 0) - (statusOrder[b.status] || 0);
			});
		});

		order.forEach(function (cat) {
			if (grouped[cat].length === 0) { return; }

			var counts = (categories && categories[cat]) || { pass: 0, partial: 0, warn: 0, fail: 0 };
			var open = Object.prototype.hasOwnProperty.call(wasOpen, cat) ? wasOpen[cat] : counts.fail > 0;

			var group = document.createElement('div');
			group.className = 'segurium-sc-group';
			group.setAttribute('data-category', cat);

			var header = document.createElement('button');
			header.type = 'button';
			header.className = 'segurium-sc-cat-header';
			header.setAttribute('aria-expanded', open ? 'true' : 'false');

			var titleSpan = document.createElement('span');
			titleSpan.className = 'segurium-sc-cat-title';
			titleSpan.textContent = categoryLabel(cat);
			header.appendChild(titleSpan);

			header.appendChild(categoryBar(counts));

			// `partial` rolls up with `warn` so a soft fail does not get a
			// UI bucket of its own.
			var countsSpan = document.createElement('span');
			countsSpan.className = 'segurium-sc-cat-counts';
			countsSpan.textContent = sprintf(
				t('scPassWarnFail', '%1$d pass, %2$d warn, %3$d fail'),
				counts.pass, counts.warn + counts.partial, counts.fail
			);
			header.appendChild(countsSpan);

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

				if (c.status !== 'pass' && c.fix_action) {
					action.appendChild(fixButton('button button-primary segurium-sc-apply', 'data-fix-check', c.id));
				} else if (c.status !== 'pass' && c.fix_scan) {
					action.appendChild(fixButton('button button-primary segurium-sc-scan'));
				} else if (c.status !== 'pass' && hasHelp) {
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
					action.appendChild(fixButton('button button-secondary segurium-sc-fix', 'data-fix-tab', c.fix_tab));
				}

				row.appendChild(icon);
				row.appendChild(body);
				row.appendChild(action);
				if (help) {
					row.appendChild(help);
				}
				if (c.status === 'pass') { delete rowNotices[c.id]; }
				if (rowNotices[c.id]) {
					var notice = document.createElement('div');
					notice.className = 'segurium-sc-notice';
					notice.setAttribute('role', 'status');
					notice.textContent = rowNotices[c.id];
					row.appendChild(notice);
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
		renderFixAll(result);
		if (!result) {
			var scannedAt = $('segurium-sc-scanned-at');
			if (scannedAt) { scannedAt.textContent = t('scNeverRun', 'Click Run Self-Check to grade your site.'); }
			renderExternalLinks();
			return;
		}
		renderGrade(result);
		renderDelta(result, history);
		renderChecks(result.checks, result.categories);
		renderExternalLinks();
	}

	function renderFixAll (result) {
		var btn = $('segurium-sc-fix-all');
		if (!btn) { return; }
		var checks = result && result.checks;
		btn.hidden = !(hasPending(checks, 'fix_action') || hasPending(checks, 'fix_scan'));
	}

	function adoptResult (result) {
		boot.last = result;
		boot.history = (boot.history || []).concat([{
			score: result.score,
			grade: result.grade,
			scanned_at: result.scanned_at
		}]).slice(-10);
		renderResult(boot.last, boot.history);
	}

	function navigateToFix (tabId) {
		var nav = document.querySelector('.segurium-nav-item[data-feature="' + tabId + '"]');
		if (nav) { nav.click(); }
	}

	function startMalwareScan () {
		navigateToFix('scanner');
		document.dispatchEvent(new CustomEvent('segurium:start-malware-scan'));
	}

	function scanIfStale () {
		if (hasPending(boot.last && boot.last.checks, 'fix_scan')) { startMalwareScan(); }
	}

	function resetFixButton (btn) {
		btn.disabled = false;
		btn.textContent = t('scFix', 'Fix');
	}

	function applyFix (checkId, btn) {
		showStatus('');
		delete rowNotices[checkId];

		btn.disabled = true;
		btn.textContent = t('scFixing', 'Applying...');

		var body = new FormData();
		body.append('action', 'segurium_self_check_apply_fix');
		body.append('nonce', cfg.selfCheckNonce || '');
		body.append('check_id', checkId);

		fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
			.then(window.seguriumParseResponse)
			.then(function (res) {
				if (!res || !res.success || !res.data || !res.data.result) {
					if (res && res.data && res.data.message) { showStatus(res.data.message); }
					resetFixButton(btn);
					return;
				}

				// The write landed but the rescore reads the homepage the
				// way a visitor does, so a page cache can still be serving
				// the response from before the fix.
				if (!res.data.flipped) {
					rowNotices[checkId] = notVisibleText();
				}

				adoptResult(res.data.result);
			})
			.catch(function () {
				resetFixButton(btn);
			});
	}

	function fixAll (btn) {
		showStatus('');
		if (!hasPending(boot.last && boot.last.checks, 'fix_action')) {
			scanIfStale();
			return;
		}

		btn.disabled = true;
		btn.textContent = t('scFixing', 'Applying...');

		window.seguriumAdmin.post({
			action: 'segurium_self_check_apply_all_fixes',
			nonce: cfg.selfCheckNonce || ''
		})
			.then(function (res) {
				var data = res && res.data;
				if (!res || !res.success || !data || !data.result) {
					showStatus(window.seguriumAdmin.describeAjaxError(data));
					return false;
				}

				var errors = data.errors || {};
				(data.not_flipped || []).forEach(function (id) { rowNotices[id] = notVisibleText(); });
				Object.keys(errors).forEach(function (id) {
					rowNotices[id] = window.seguriumAdmin.describeAjaxError({ code: errors[id] });
				});

				if ((data.applied || []).length) {
					adoptResult(data.result);
				} else {
					renderResult(boot.last, boot.history);
				}
				return true;
			})
			.catch(function (err) {
				showStatus(window.seguriumAdmin.describeAjaxError({ raw: err && err.message }));
				return false;
			})
			.then(function (ok) {
				btn.disabled = false;
				btn.textContent = t('scFixAll', 'Fix all');
				if (ok) { scanIfStale(); }
			});
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

	function refreshAfterScan () {
		window.seguriumAdmin.post({
			action: 'segurium_run_self_check',
			nonce: cfg.selfCheckNonce || ''
		}).then(function (res) {
			if (!res || !res.success || !res.data) {
				showStatus(window.seguriumAdmin.describeAjaxError(res && res.data));
				return;
			}
			if (boot.last && boot.last.scanned_at === res.data.scanned_at) { return; }
			adoptResult(res.data);
		});
	}

	function runScan (force) {
		showStatus('');
		rowNotices = {};

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
					adoptResult(res.data);
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

		document.addEventListener('segurium:scan-finished', refreshAfterScan);

		var fixAllBtn = $('segurium-sc-fix-all');
		if (fixAllBtn) {
			fixAllBtn.addEventListener('click', function () { fixAll(fixAllBtn); });
		}

		var checksWrap = $('segurium-sc-checks');
		if (checksWrap) {
			checksWrap.addEventListener('click', function (ev) {
				var target = ev.target;
				while (target && target !== checksWrap) {
					if (target.classList && target.classList.contains('segurium-sc-apply')) {
						if (target.disabled) { return; }
						var checkId = target.getAttribute('data-fix-check');
						if (checkId) { applyFix(checkId, target); }
						return;
					}
					if (target.classList && target.classList.contains('segurium-sc-scan')) {
						startMalwareScan();
						return;
					}
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

		// Cold-start auto-run. Fires once per install, when
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

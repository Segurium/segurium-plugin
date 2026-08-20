(function () {
    'use strict';

    function el(id) {
        return document.getElementById(id);
    }

    // SEGURIUM-270: Page Visibility helpers — pause periodic polling while
    // the tab is backgrounded so a parked admin tab does not generate
    // ~9k admin-ajax round-trips/day.
    //
    // `onVisibilityResumed(fn)` fires every time the tab regains focus
    // (page-lifetime listener; see CTI health for the only caller).
    //
    // `makeVisibilityGate(resume)` returns a `{ wait, cancel }` pair for
    // chained pollers (scanner / integrity observers): `wait()` parks the
    // poller until the tab is visible, then calls `resume()`; `cancel()`
    // tears the listener down so a Stop click cannot leak it.
    function onVisibilityResumed(fn) {
        document.addEventListener('visibilitychange', function () {
            if (!document.hidden) fn();
        });
    }

    function makeVisibilityGate(resume) {
        var handler = null;
        return {
            wait: function () {
                handler = function () {
                    if (!document.hidden) {
                        document.removeEventListener('visibilitychange', handler);
                        handler = null;
                        resume();
                    }
                };
                document.addEventListener('visibilitychange', handler);
            },
            cancel: function () {
                if (handler) {
                    document.removeEventListener('visibilitychange', handler);
                    handler = null;
                }
            }
        };
    }

    function post(params) {
        var body = new URLSearchParams(params);
        return fetch(seguriumScan.ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        }).then(window.seguriumParseResponse).catch(function (err) {
            return {
                success: false,
                data: {
                    code: 'network_error',
                    message: '',
                    raw: err && err.message ? String(err.message) : ''
                }
            };
        });
    }

    // Map a structured error payload to a human-readable message. Falls
    // back to the server's own message, then to a raw-body excerpt, then
    // to a generic hint — but NEVER to a bare "Unknown".
    function describeAjaxError(data) {
        var i18n = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};
        var code = data && data.code;
        var serverMessage = data && data.message;
        var raw = data && data.raw;
        var httpStatus = data && data.http_status;

        var codeMap = {
            invalid_nonce: i18n.errSessionExpired,
            unauthorized: i18n.errUnauthorized,
            consent_required: i18n.errConsentRequired,
            scan_already_running: i18n.scanAlreadyRunning,
            scan_initialize_failed: i18n.errInitializeFailed,
            scan_dispatch_failed: i18n.errDispatchFailed,
            scan_start_exception: i18n.errScanStartException,
            scan_status_exception: i18n.errScanStatusException,
            scan_stop_exception: i18n.errScanStopException,
            schema_unavailable: i18n.errSchemaUnavailable,
            unexpected_error: i18n.errUnexpectedError,
            legacy_continue_action: i18n.errLegacyContinueAction,
            server_error: i18n.errServerError,
            network_error: i18n.errNetworkError,
            poll_handler_error: i18n.errPollHandler,
            unexpected_response: i18n.errUnexpectedResponse,
            envelope_empty: i18n.errEnvelopeEmpty || i18n.errUnexpectedResponse,
            envelope_absent: i18n.errEnvelopeAbsent || i18n.errUnexpectedResponse,
            envelope_truncated: i18n.errEnvelopeTruncated || i18n.errUnexpectedResponse,
            envelope_missing: i18n.errEnvelopeMissing || i18n.errUnexpectedResponse,
            envelope_malformed: i18n.errEnvelopeMalformed || i18n.errUnexpectedResponse,
            envelope_unexpected_shape: i18n.errEnvelopeMalformed || i18n.errUnexpectedResponse
        };

        if (serverMessage) return serverMessage;
        if (code && codeMap[code]) return codeMap[code];
        if (code) {
            return (i18n.errGeneric || 'Request failed') + ' (' + code +
                (httpStatus ? ', HTTP ' + httpStatus : '') + ')';
        }
        if (raw) {
            return (i18n.errGeneric || 'Request failed') + ': ' + raw;
        }
        return (i18n.errGeneric || 'Request failed') +
            (httpStatus ? ' (HTTP ' + httpStatus + ')' : '');
    }

    // Branded replacement for native alert() on the admin tabs. Reuses
    // the #segurium-confirm-modal shell (see class-segurium.php) and
    // hides the Cancel button so it presents as a notice. Downstream
    // confirm callers (showPaywallModal, restoreWithPreflight) reset
    // cancel.style.display themselves before opening, so we don't need
    // to restore it here.
    function seguriumNotice(message, code) {
        var i18n = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};
        var modal   = document.getElementById('segurium-confirm-modal');
        var okBtn   = document.getElementById('segurium-confirm-ok');
        if (!modal || !okBtn) {
            try { window.alert('Segurium — ' + String(message || '')); } catch (e) {}
            return;
        }
        var titleEl   = document.getElementById('segurium-confirm-title');
        var contentEl = document.getElementById('segurium-confirm-content');
        var cancel    = document.getElementById('segurium-confirm-cancel');
        var close     = document.getElementById('segurium-confirm-close');

        titleEl.textContent = 'Segurium';
        var bodyHtml = '<p style="margin:0 0 8px;">' + escHtml(String(message || '')) + '</p>';
        if (code) {
            bodyHtml += '<p style="margin:0;color:#646970;font-size:12px;">' +
                'code: <code>' + escHtml(String(code)) + '</code></p>';
        }
        contentEl.innerHTML = bodyHtml;

        okBtn.textContent = i18n.noticeOk || 'OK';
        okBtn.disabled = false;
        if (cancel) cancel.style.display = 'none';

        modal.style.display = '';

        function closeModal() { modal.style.display = 'none'; }
        okBtn.onclick = closeModal;
        if (close) close.onclick = closeModal;
        var overlay = modal.querySelector('.segurium-diff-overlay');
        if (overlay) overlay.onclick = closeModal;
    }

    function seguriumNoticeFromError(data, fallbackMessage) {
        var msg = (data && data.message) || fallbackMessage || (((typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {}).errGeneric) || 'Request failed';
        seguriumNotice(msg, data && data.code);
    }

    function escHtml(str) {
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(str));
        return d.innerHTML;
    }

    function escAttr(str) {
        // SEGURIUM-409: callers may pass JSON-numeric values (e.g. backup_id from /v1/cleanup) — coerce so .replace doesn't TypeError into a swallowed catch.
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function truncatePath(path) {
        if (!path || path.length <= 50) {
            return '<span class="segurium-path-truncated">' + escHtml(path || '') + '</span>';
        }
        var sep = path.lastIndexOf('/');
        var filename = sep >= 0 ? path.substring(sep) : path;
        var dir = sep >= 0 ? path.substring(0, sep) : '';
        return '<span class="segurium-path-truncated">' +
            '<span class="segurium-path-start">' + escHtml(dir) + '</span>' +
            '<span class="segurium-path-end">' + escHtml(filename) + '</span>' +
            '</span>';
    }

    function formatDate(ts) {
        var d = new Date(ts * 1000);
        return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    function formatElapsed(seconds) {
        var m = Math.floor(seconds / 60);
        var s = Math.floor(seconds % 60);
        return (m > 0 ? m + 'm ' : '') + s + 's';
    }

    // SEGURIUM-399: surface a "no progress" hint while data.running is
    // still true but the server-side heartbeat is older than the soft
    // threshold. Threshold matches HEARTBEAT_MAX_AGE (60 s) so the hint
    // stays silent during legitimate per-file work — a single
    // /v1/neo-ray RTT can take ~30 s, and the per-file heartbeat in
    // verdict_queue refreshes between files. If the user does see the
    // hint, it means the heartbeat has aged past the watchdog window
    // without the lock being reclaimed — i.e. the watchdog isn't doing
    // its job — which is the diagnostic signal we want surfaced. Clock
    // skew between browser and server can produce small negative ages;
    // clamp at zero and require >= threshold.
    //
    // SEGURIUM-764: lives at module scope because both the malware and
    // the integrity poller call it from their own IIFEs.
    function appendStalledHint(parts, data) {
        var i18n = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};
        if (!data || data.running !== true) return;
        var hb = data.heartbeat || 0;
        if (hb <= 0) return;
        var ageS = Math.max(0, Math.floor(Date.now() / 1000) - hb);
        if (ageS < 60) return;
        var msg = (i18n.scanWorkerStalled || 'no progress for %ds — waiting for worker')
            .replace('%d', ageS);
        parts.push(msg);
    }

    // SEGURIUM-764: post() resolves for every transport outcome — a failed
    // request comes back as a success:false envelope with code
    // network_error. An exception that reaches a .catch() on a post() chain
    // is therefore a bug in the handler, never a lost connection. Log it
    // under a stable label so support can find it in the console, and hand
    // back a status string that says what the user should do.
    function reportPollHandlerError(label, err) {
        var i18n = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};
        if (window.console && window.console.error) {
            window.console.error('[segurium] ' + label + ' poll_handler_error', err);
        }
        return (i18n.scanError || 'Error') + ': ' +
            describeAjaxError({ code: 'poll_handler_error' });
    }

    function restoreWithPreflight(backupId, btn, onSuccess) {
        var i18n = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};
        var origText = btn.textContent;
        btn.textContent = i18n.restoreChecking || 'Checking\u2026';
        btn.disabled = true;

        post({
            action: 'segurium_restore_preflight',
            nonce: seguriumScan.cleanupNonce,
            backup_id: backupId
        }).then(function (resp) {
            btn.textContent = origText;
            btn.disabled = false;

            if (!resp.success) {
                seguriumNotice(describeAjaxError(resp.data), resp.data && resp.data.code);
                return;
            }

            var d = resp.data;
            var state = d.state;
            var relPath = d.path || '';

            var title, body, okLabel;

            if (state === 'modified') {
                title   = i18n.restoreTitle || 'Restore file';
                body    = (i18n.restoreOverwrite || 'The file at %s has been modified since the last cleanup. Restoring will overwrite the existing file with the backed-up version. This cannot be undone.')
                    .replace('%s', '<code>' + escHtml(relPath) + '</code>');
                okLabel = i18n.restoreOverwriteBtn || 'Overwrite & Restore';
            } else if (state === 'already_restored') {
                title   = i18n.restoreTitle || 'Restore file';
                body    = i18n.restoreAlreadyRestored || 'The file on disk is already the backed-up version. Restore anyway to update database records?';
                okLabel = i18n.restore || 'Restore';
            } else {
                title   = i18n.restoreTitle || 'Restore file';
                body    = i18n.confirmRestore || 'This will restore the original infected file from backup. Continue?';
                okLabel = i18n.restore || 'Restore';
            }

            var modal   = el('segurium-confirm-modal');
            var mTitle  = el('segurium-confirm-title');
            var mBody   = el('segurium-confirm-content');
            var okBtn   = el('segurium-confirm-ok');
            var cancel  = el('segurium-confirm-cancel');
            var close   = el('segurium-confirm-close');

            mTitle.textContent = title;
            mBody.innerHTML    = body;
            okBtn.textContent  = okLabel;
            okBtn.disabled     = false;
            modal.style.display = '';

            function closeModal() { modal.style.display = 'none'; }
            cancel.onclick = closeModal;
            close.onclick  = closeModal;
            modal.querySelector('.segurium-diff-overlay').onclick = closeModal;

            okBtn.onclick = function () {
                closeModal();
                post({
                    action: 'segurium_restore_file',
                    nonce: seguriumScan.cleanupNonce,
                    backup_id: backupId
                }).then(function (response) {
                    if (response.success) {
                        onSuccess();
                    }
                });
            };
        });
    }

    function computeDiff(aLines, bLines) {
        if (aLines.length > 1500 || bLines.length > 1500) {
            return [{ type: 'info', line: 'File too large for inline diff (' + aLines.length + ' vs ' + bLines.length + ' lines).' }];
        }
        var m = aLines.length, n = bLines.length;
        var dp = new Array(m + 1);
        for (var i = 0; i <= m; i++) dp[i] = new Array(n + 1).fill(0);
        for (var i = 1; i <= m; i++) {
            for (var j = 1; j <= n; j++) {
                dp[i][j] = aLines[i - 1] === bLines[j - 1]
                    ? dp[i - 1][j - 1] + 1
                    : Math.max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
        var ops = [], i = m, j = n;
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0 && aLines[i - 1] === bLines[j - 1]) {
                ops.unshift({ type: 'ctx', line: aLines[i - 1] });
                i--; j--;
            } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
                ops.unshift({ type: 'add', line: bLines[j - 1] });
                j--;
            } else {
                ops.unshift({ type: 'del', line: aLines[i - 1] });
                i--;
            }
        }
        return ops;
    }

    function collapseDiff(ops) {
        var CTX = 3, show = {}, prev = -1, out = [];
        ops.forEach(function (op, i) {
            if (op.type !== 'ctx') {
                for (var k = Math.max(0, i - CTX); k <= Math.min(ops.length - 1, i + CTX); k++) show[k] = true;
            }
        });
        ops.forEach(function (op, i) {
            if (!show[i]) return;
            if (prev >= 0 && i > prev + 1) out.push({ type: 'hunk', line: '' });
            out.push(op);
            prev = i;
        });
        return out;
    }

    function showDiffModal(filePath, originalText, currentText) {
        var modal = el('segurium-diff-modal');
        var titleEl = el('segurium-diff-title');
        var contentEl = el('segurium-diff-content');
        if (!modal) return;

        titleEl.textContent = filePath;

        var origLines = originalText.split('\n');
        var currLines = currentText.split('\n');
        if (origLines.length && origLines[origLines.length - 1] === '') origLines.pop();
        if (currLines.length && currLines[currLines.length - 1] === '') currLines.pop();

        var segments = collapseDiff(computeDiff(origLines, currLines));

        var html = '<table class="segurium-diff-table">';
        if (segments.length === 0) {
            html += '<tr class="segurium-diff-info"><td colspan="2">Files are identical.</td></tr>';
        } else {
            segments.forEach(function (s) {
                var cls, prefix;
                if (s.type === 'del')       { cls = 'segurium-diff-del';  prefix = '-'; }
                else if (s.type === 'add')  { cls = 'segurium-diff-add';  prefix = '+'; }
                else if (s.type === 'hunk') { cls = 'segurium-diff-hunk'; prefix = ''; }
                else if (s.type === 'info') { cls = 'segurium-diff-info'; prefix = ''; }
                else                        { cls = 'segurium-diff-ctx';  prefix = ' '; }
                var lineContent = s.type === 'hunk'
                    ? '<span class="segurium-diff-hunk-marker">@@</span>'
                    : escHtml(s.line);
                html += '<tr class="' + cls + '"><td class="segurium-diff-prefix">' + escHtml(prefix) +
                        '</td><td class="segurium-diff-line">' + lineContent + '</td></tr>';
            });
        }
        html += '</table>';
        contentEl.innerHTML = html;
        modal.style.display = '';
        document.body.style.overflow = 'hidden';
    }

    function closeDiffModal() {
        var modal = el('segurium-diff-modal');
        if (!modal) return;
        modal.style.display = 'none';
        document.body.style.overflow = '';
        var contentEl = el('segurium-diff-content');
        if (contentEl) contentEl.innerHTML = '';
    }

    (function bindDiffModalClose() {
        var modal = el('segurium-diff-modal');
        if (!modal) return;
        var closeBtn = el('segurium-diff-close');
        var overlay = modal.querySelector('.segurium-diff-overlay');
        if (closeBtn) closeBtn.addEventListener('click', closeDiffModal);
        if (overlay) overlay.addEventListener('click', closeDiffModal);
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && modal.style.display !== 'none') closeDiffModal();
        });
    })();

    // SEGURIUM-248: generic close behaviour for `.segurium-modal` shells
    // (currently the "Show malware" textarea modal and the false-positive
    // form). The original implementation only had a close button on the
    // malware modal but no handler bound to it — the X did nothing and the
    // overlay click was not wired up either. Single delegated handler
    // covers every present and future `.segurium-modal` instance.
    (function bindGenericModalClose() {
        function closeNearestModal(target) {
            var modal = target.closest('.segurium-modal');
            if (!modal) return;
            modal.style.display = 'none';
        }
        document.addEventListener('click', function (e) {
            if (e.target.closest('.segurium-modal-close')) {
                e.preventDefault();
                closeNearestModal(e.target);
                return;
            }
            if (e.target.classList && e.target.classList.contains('segurium-modal-overlay')) {
                closeNearestModal(e.target);
            }
        });
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape') return;
            var open = document.querySelector('.segurium-modal:not([style*="display: none"]):not([style*="display:none"])');
            if (open) open.style.display = 'none';
        });
    })();

    var i18n = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};

    // SEGURIUM-301: batched first-paint read. Collapses the three init
    // round-trips (server_state + quota + cti_health) into a single
    // admin-ajax POST so first paint pays one WP bootstrap tax instead
    // of three. Each section consumes its slice exactly once via
    // `takeInitialState(key)`; subsequent reads (pagination, periodic
    // CTI poll, post-action quota refresh) fall through to the legacy
    // single-purpose handlers, which stay alive.
    var seguriumInitialPromise = post({
        action: 'segurium_initial_state',
        nonce: seguriumScan.nonce,
        page: 1,
        per_page: 20,
        recent_only: '1',
        filter: 'malicious'
    }).then(function (resp) {
        return (resp && resp.success && resp.data) ? resp.data : null;
    }).catch(function () { return null; });
    var seguriumInitialUsed = { server_state: false, quota: false, cti_health: false };
    function takeInitialState(key) {
        if (seguriumInitialUsed[key]) return Promise.resolve(null);
        seguriumInitialUsed[key] = true;
        return seguriumInitialPromise.then(function (initial) {
            return initial ? (initial[key] || null) : null;
        });
    }

    var refreshServerState = function () {};
    var ssResumeIfRunning   = function () {};
    var geoOnActivate       = function () {};
    var firewallOnActivate  = function () {};
    var bruteforceOnActivate = function () {};
    var headersOnActivate = function () {};
    var infoShieldOnActivate = function () {};
    var twoFactorOnActivate = function () {};
    var disableSSBtn = function () {};
    var enableSSBtn = function () {};

    // Surface area exposed for plugin/dev/* modules. Stays a stable
    // contract: dev modules consume seguriumAdmin.* helpers and listen
    // to the segurium:* CustomEvents below.
    window.seguriumAdmin = window.seguriumAdmin || {};
    window.seguriumAdmin.el                  = el;
    window.seguriumAdmin.post                = post;
    window.seguriumAdmin.escHtml             = escHtml;
    window.seguriumAdmin.escAttr             = escAttr;
    window.seguriumAdmin.truncatePath        = truncatePath;
    window.seguriumAdmin.formatDate          = formatDate;
    window.seguriumAdmin.formatElapsed       = formatElapsed;
    window.seguriumAdmin.describeAjaxError   = describeAjaxError;
    window.seguriumAdmin.notice              = seguriumNotice;
    window.seguriumAdmin.noticeFromError     = seguriumNoticeFromError;
    window.seguriumAdmin.isPaywallResponse   = isPaywallResponse;
    window.seguriumAdmin.showPaywallModal    = showPaywallModal;
    window.seguriumAdmin.restoreWithPreflight = restoreWithPreflight;
    window.seguriumAdmin.i18n                = i18n;
    // Wrapper preserves late-binding: refreshServerState is reassigned
    // by the Server State IIFE further down, and dev modules see the
    // current implementation, not the empty stub captured above.
    window.seguriumAdmin.refreshServerState  = function () { refreshServerState(); };

    // ── Paywall modal (SEGURIUM-207) ──
    //
    // Driven exclusively by `paywall_quota_exceeded`, the only paywall
    // signal CTI emits post-SEGURIUM-341 (Serviceware refactor). The
    // legacy `paywall_feature_pro_only` code is no longer produced —
    // every feature runs on every install and the cap is enforced by
    // the cloud quota ledger.
    //
    // Rendered into the existing #segurium-confirm-modal shell so the keyboard
    // dismiss / overlay-click behaviour comes for free. Hidden the Upgrade
    // button when seguriumScan.upgradeUrl is empty (Freemius unreachable) so
    // we never ship a dead "#" link — the user sees a Close button instead.
    function formatLocalizedDate(unixSecs) {
        if (!unixSecs) return '';
        try {
            return new Date(unixSecs * 1000).toLocaleDateString();
        } catch (err) {
            return '';
        }
    }

    function showPaywallModal(payload) {
        if (!payload || typeof payload !== 'object') return;
        var modal   = el('segurium-confirm-modal');
        var title   = el('segurium-confirm-title');
        var content = el('segurium-confirm-content');
        var okBtn   = el('segurium-confirm-ok');
        var cancel  = el('segurium-confirm-cancel');
        var close   = el('segurium-confirm-close');
        if (!modal || !okBtn) return;

        var titleText = i18n.paywallProTitle || 'Upgrade to Pro';
        var bodyHtml  = '';

        if (payload.code === 'paywall_quota_exceeded') {
            titleText = i18n.paywallQuotaTitle || 'Cleanup quota reached';
            var q       = payload.quota || {};
            var used    = (typeof q.used === 'number') ? q.used : 0;
            var pwindow = (typeof q.window_days === 'number' && q.window_days > 0) ? q.window_days : 30;
            var copy    = (i18n.paywallQuotaCopy || "You've used %1$d cloud cleanups in the last %2$d days. Upgrade to Pro for an unbounded cloud cleanup quota.")
                .replace('%1$d', String(used))
                .replace('%2$d', String(pwindow));
            bodyHtml  = '<p style="margin:0 0 12px;">' + escHtml(copy) + '</p>';
            var resetsOn = formatLocalizedDate(q.next_slot_at);
            if (resetsOn) {
                var resetsCopy = (i18n.paywallQuotaResets || 'Next slot opens %s')
                    .replace('%s', resetsOn);
                bodyHtml += '<p style="margin:0;color:#646970;">' + escHtml(resetsCopy) + '</p>';
            }
        } else {
            // Unknown code — fall back to the server's own message so we
            // surface the failure rather than a bare modal.
            bodyHtml = '<p style="margin:0 0 12px;">' +
                escHtml(payload.message || i18n.paywallProFallback || 'Cleanup quota reached.') +
                '</p>';
        }

        title.textContent  = titleText;
        content.innerHTML  = bodyHtml;
        var hasUrl         = !!(seguriumScan && seguriumScan.upgradeUrl);
        okBtn.textContent  = hasUrl
            ? (i18n.paywallProUpgrade || 'Upgrade to Pro')
            : (i18n.closeBtn || 'Close');
        okBtn.disabled     = false;
        cancel.textContent = i18n.paywallProMaybeLater || 'Maybe later';
        cancel.style.display = hasUrl ? '' : 'none';

        modal.style.display = '';

        function closeModal() { modal.style.display = 'none'; }
        cancel.onclick = closeModal;
        close.onclick  = closeModal;
        var overlay = modal.querySelector('.segurium-diff-overlay');
        if (overlay) overlay.onclick = closeModal;

        okBtn.onclick = function () {
            closeModal();
            if (hasUrl) {
                window.location.href = seguriumScan.upgradeUrl;
            }
        };
    }

    // Shared progress modal for batched per-file actions (Restore, Fix,
    // Ignore-all, Unignore-all). Single instance built lazily on first use,
    // reused across runQueue() invocations. The modal is shown after a
    // 250ms delay so fast queues (a handful of ignore-flag flips) finish
    // before anything pops up.
    var progressModal = (function () {
        var node = null, titleEl = null, barEl = null, countEl = null,
            labelEl = null, cancelBtn = null;
        var aborted = false;

        function build() {
            if (node) return;
            node = document.createElement('div');
            node.className = 'segurium-modal';
            node.setAttribute('role', 'dialog');
            node.setAttribute('aria-modal', 'true');
            node.style.display = 'none';
            node.innerHTML =
                '<div class="segurium-modal-overlay"></div>' +
                '<div class="segurium-modal-content" style="max-width:480px;max-height:none;">' +
                    '<div class="segurium-modal-header">' +
                        '<h3 class="segurium-progress-modal-title"></h3>' +
                    '</div>' +
                    '<div style="padding:16px;">' +
                        '<div class="segurium-progress-bar-wrap" style="margin:0 0 10px;">' +
                            '<div class="segurium-progress-bar" style="width:0"></div>' +
                        '</div>' +
                        '<div class="segurium-progress-modal-count" style="font-size:13px;color:#50575e;"></div>' +
                        '<div class="segurium-progress-modal-label" style="margin-top:4px;font-size:12px;color:#646970;font-family:Consolas,Monaco,monospace;word-break:break-all;min-height:1.4em;"></div>' +
                    '</div>' +
                    '<div style="padding:12px 16px;text-align:right;border-top:1px solid #dcdcde;">' +
                        '<button type="button" class="button segurium-progress-modal-cancel"></button>' +
                    '</div>' +
                '</div>';
            document.body.appendChild(node);
            titleEl   = node.querySelector('.segurium-progress-modal-title');
            barEl     = node.querySelector('.segurium-progress-bar');
            countEl   = node.querySelector('.segurium-progress-modal-count');
            labelEl   = node.querySelector('.segurium-progress-modal-label');
            cancelBtn = node.querySelector('.segurium-progress-modal-cancel');
            cancelBtn.addEventListener('click', function () {
                aborted = true;
                cancelBtn.disabled = true;
                cancelBtn.textContent = i18n.progressCancelling || 'Cancelling…';
            });
        }

        return {
            open: function (titleText) {
                build();
                aborted = false;
                titleEl.textContent = titleText || '';
                barEl.style.width = '0';
                countEl.textContent = '';
                labelEl.textContent = '';
                cancelBtn.disabled = false;
                cancelBtn.textContent = i18n.cancel || 'Cancel';
                node.style.display = '';
            },
            update: function (done, total, currentLabel) {
                if (!node) return;
                var pct = total > 0 ? Math.round((done / total) * 100) : 0;
                barEl.style.width = pct + '%';
                countEl.textContent = (i18n.progressOf || '%1$d of %2$d')
                    .replace('%1$d', String(done))
                    .replace('%2$d', String(total));
                labelEl.textContent = currentLabel || '';
            },
            close: function () {
                if (!node) return;
                node.style.display = 'none';
            },
            isAborted: function () { return aborted; }
        };
    })();

    // True when the server response carries a paywall envelope. Single check
    // point so cleanup + integrity-fix call sites stay symmetric. Only
    // `paywall_quota_exceeded` is emitted post-SEGURIUM-341.
    function isPaywallResponse(resp) {
        if (!resp || resp.success || !resp.data || !resp.data.code) return false;
        return resp.data.code === 'paywall_quota_exceeded';
    }

    // SEGURIUM-207: Free-tier cleanup quota readout, surfaced on every
    // cleanup-bearing panel (malware scanner + integrity scanner). Pro skips
    // entirely. `fail_open=true` (CTI down) ⇒ hide rather than render a stale
    // 0/3.
    //
    // SEGURIUM-247: phrase the window as a sliding "last N days" — the quota
    // is rolling, not calendar-month — and only mention the reset date once
    // the user has actually exhausted the quota. Until then a reset date is
    // misleading: every consumed slot expires individually as it ages out.
    function quotaReadoutNodes() {
        return document.querySelectorAll('.segurium-quota-readout');
    }

    function renderQuotaReadout(envelope) {
        var nodes = quotaReadoutNodes();
        if (!nodes.length) return;
        function hideAll() { nodes.forEach(function (n) { n.hidden = true; }); }
        // Pro: hide unconditionally, including any server pre-render.
        if (seguriumScan && seguriumScan.isPro) { hideAll(); return; }
        // Fail-open or missing envelope: keep whatever PHP pre-rendered
        // at page load — it's stale at worst, and blanking the counter
        // because CTI happens to be unreachable right now is hostile.
        if (!envelope || envelope.is_pro || envelope.fail_open) { return; }
        var used   = (typeof envelope.used === 'number') ? envelope.used : 0;
        var limit  = (typeof envelope.limit === 'number' && envelope.limit > 0) ? envelope.limit : 3;
        var window = (typeof envelope.window_days === 'number' && envelope.window_days > 0) ? envelope.window_days : 30;
        // SEGURIUM-355: gate the Upgrade-to-Pro CTA on the at-limit branch.
        // Rendering the upsell at 0/3 is constant promotion (WP.org
        // Guideline 11) — the user has not experienced the limit yet.
        // The counter itself still renders on every cleanup-bearing panel.
        var atLimit = used >= limit;
        var copy;
        if (atLimit) {
            var nextSlot = formatLocalizedDate(envelope.next_slot_at) || '—';
            copy = (i18n.quotaReadoutAtLimit || '%1$d of %2$d cleanups used in the last %3$d days — next slot opens %4$s')
                .replace('%1$d', String(used))
                .replace('%2$d', String(limit))
                .replace('%3$d', String(window))
                .replace('%4$s', nextSlot);
        } else {
            copy = (i18n.quotaReadout || '%1$d of %2$d cleanups used in the last %3$d days')
                .replace('%1$d', String(used))
                .replace('%2$d', String(limit))
                .replace('%3$d', String(window));
        }
        var html = '<span>' + escHtml(copy) + '</span>';
        if (atLimit && seguriumScan && seguriumScan.upgradeUrl) {
            html += '<a class="segurium-quota-readout-cta" href="' +
                escAttr(seguriumScan.upgradeUrl) + '">' +
                escHtml(i18n.quotaReadoutUpgradeCta || 'Upgrade to Pro') +
                '</a>';
        }
        nodes.forEach(function (n) { n.innerHTML = html; n.hidden = false; });
    }

    // SEGURIUM-270: cache the quota envelope for the page lifetime. The
    // sidebar already renders an authoritative counter at page load (PHP),
    // and every cleanup response includes a fresh envelope that updates
    // the readout. The tab-switch refetch was purely defensive; with a
    // short TTL we cap drift after non-cleanup actions (e.g. integrity
    // fixes that don't echo a quota envelope) to one fetch per session
    // rather than one per tab switch.
    var QUOTA_CACHE_TTL_MS = 5 * 60 * 1000;
    var quotaCacheTs = 0;
    function refreshQuotaReadout() {
        var nodes = quotaReadoutNodes();
        if (!nodes.length) return;
        if (seguriumScan && seguriumScan.isPro) {
            nodes.forEach(function (n) { n.hidden = true; });
            return;
        }
        if (quotaCacheTs && (Date.now() - quotaCacheTs) < QUOTA_CACHE_TTL_MS) {
            return;
        }
        if (!seguriumInitialUsed.quota) {
            takeInitialState('quota').then(function (data) {
                if (data) {
                    quotaCacheTs = Date.now();
                    renderQuotaReadout(data);
                    return;
                }
                fetchQuotaReadout();
            });
            return;
        }
        fetchQuotaReadout();
    }
    function fetchQuotaReadout() {
        post({
            action: 'segurium_quota_state',
            nonce: seguriumScan.nonce
        }).then(function (resp) {
            if (!resp || !resp.success || !resp.data) {
                // Leave any server-pre-rendered counter visible; a transient
                // admin-ajax failure shouldn't wipe it.
                return;
            }
            quotaCacheTs = Date.now();
            renderQuotaReadout(resp.data);
        }).catch(function () {
            // Same rationale as above — keep the pre-rendered value.
        });
    }

    // SEGURIUM-379: re-fetch the quota envelope after every interesting
    // action so the readout reflects the server-authoritative counters.
    // The cleanup-file and malicious-integrity-fix AJAX responses already
    // carry a fresh `quota` object that renderQuotaReadout consumes inline;
    // scan completion is the third hook the ticket calls out, and the
    // runner does not pass through admin-ajax (it's polled). Bypass the
    // 5-minute client-side TTL — the user just performed an action whose
    // entire point is to update what the readout shows.
    document.addEventListener('segurium:scan-finished', function () {
        if (seguriumScan && seguriumScan.isPro) {
            // Pro tier shows nothing about quotas anywhere in the plugin
            // UI (SEGURIUM-379 render rule). Hide whatever a stale render
            // left in place rather than refetching.
            quotaReadoutNodes().forEach(function (n) { n.hidden = true; });
            return;
        }
        quotaCacheTs = 0;
        fetchQuotaReadout();
    });

    // ── Consent ──

    var consentBtn = el('segurium-accept-consent');
    if (consentBtn) {
        consentBtn.addEventListener('click', function () {
            consentBtn.disabled = true;
            post({
                action: 'segurium_accept_consent',
                nonce: seguriumScan.consentNonce
            }).then(function (response) {
                if (response.success) {
                    location.reload();
                } else {
                    consentBtn.disabled = false;
                }
            }).catch(function () {
                consentBtn.disabled = false;
            });
        });
    }

    // ── CTI health status ──
    //
    // SEGURIUM-270: poll every 5 minutes (was 60s) and only while the
    // admin tab is foregrounded. The CTI status indicator is purely
    // informational and is also cached server-side for 5 minutes, so
    // tighter cadence buys nothing. On tab-resume we refresh once so the
    // indicator reflects the current state immediately.

    var ctiStatusEl = el('segurium-cti-status');
    var CTI_HEALTH_INTERVAL_MS = 5 * 60 * 1000;
    function renderCtiHealth(data) {
        if (!ctiStatusEl || !data) return;
        ctiStatusEl.innerHTML = data.healthy
            ? '&#x1F7E2; ' + escHtml(i18n.ctiConnected || 'Connected')
            : '&#x1F534; ' + escHtml(i18n.ctiDisconnected || 'Disconnected');
    }
    function checkCtiHealth() {
        if (!ctiStatusEl) return;
        if (!seguriumInitialUsed.cti_health) {
            takeInitialState('cti_health').then(function (data) {
                if (data) { renderCtiHealth(data); return; }
                fetchCtiHealth();
            });
            return;
        }
        fetchCtiHealth();
    }
    function fetchCtiHealth() {
        post({
            action: 'segurium_cti_health',
            nonce: seguriumScan.nonce
        }).then(function (response) {
            if (!response.success) return;
            renderCtiHealth(response.data);
        });
    }
    function ctiHealthTick() {
        if (!document.hidden) checkCtiHealth();
        setTimeout(ctiHealthTick, CTI_HEALTH_INTERVAL_MS);
    }
    if (ctiStatusEl) {
        checkCtiHealth();
        setTimeout(ctiHealthTick, CTI_HEALTH_INTERVAL_MS);
        onVisibilityResumed(checkCtiHealth);
    }


    // ── Tab switching ──

    var navItems = document.querySelectorAll('.segurium-nav-item[data-feature]');

    function currentTabFromUrl() {
        try {
            var t = new URLSearchParams(window.location.search).get('tab');
            return t || 'self-check';
        } catch (e) {
            return 'self-check';
        }
    }

    function tabOnActivate(feature) {
        if (feature === 'scanner') {
            refreshServerState();
            refreshQuotaReadout();
            // If the integrity scanner chained a malware scan and the
            // user just switched here, surface the in-flight progress.
            ssResumeIfRunning();
        }
        if (feature === 'integrity-scanner') {
            refreshQuotaReadout();
        }
        if (feature === 'geo') geoOnActivate();
        if (feature === 'firewall') firewallOnActivate();
        if (feature === 'bruteforce') bruteforceOnActivate();
        if (feature === 'twofactor') twoFactorOnActivate();
        if (feature === 'headers') headersOnActivate();
        if (feature === 'info-shield') infoShieldOnActivate();
    }

    function switchTab(feature) {
        navItems.forEach(function (n) { n.classList.remove('segurium-nav-item--active'); });
        document.querySelectorAll('.segurium-feature').forEach(function (panel) {
            panel.style.display = panel.id === 'segurium-feature-' + feature ? '' : 'none';
        });
        navItems.forEach(function (n) {
            if (n.getAttribute('data-feature') === feature) n.classList.add('segurium-nav-item--active');
        });
        document.dispatchEvent(new CustomEvent('segurium:tab-changed', { detail: { feature: feature } }));
        tabOnActivate(feature);
    }

    function buildTabUrl(feature) {
        var base = (seguriumScan && seguriumScan.adminPage)
            || (window.location.pathname + '?page=segurium');
        return base + '&tab=' + encodeURIComponent(feature);
    }

    navItems.forEach(function (item) {
        item.addEventListener('click', function (e) {
            // Honour modifier-clicks (open in new tab/window) — just follow href.
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button === 1) {
                return;
            }
            e.preventDefault();
            var feature = this.getAttribute('data-feature');
            if (!document.getElementById('segurium-feature-' + feature)) {
                return;
            }
            var url = buildTabUrl(feature);
            try {
                window.history.pushState({ seguriumTab: feature }, '', url);
            } catch (err) {
                // pushState can throw in sandboxed contexts; fall back to a
                // normal navigation so the tab still loads.
                window.location.href = url;
                return;
            }
            switchTab(feature);
        });
    });

    window.addEventListener('popstate', function () {
        var feature = currentTabFromUrl();
        if (!document.getElementById('segurium-feature-' + feature)) {
            feature = 'self-check';
        }
        switchTab(feature);
    });

    // PHP already rendered the right panel visible; fire OnActivate for the
    // active tab so tab-specific data loads on direct deep links and on
    // hard reload, without re-toggling display (no flicker).
    var initialTab = (seguriumScan && seguriumScan.activeTab) || currentTabFromUrl();
    if (initialTab && document.getElementById('segurium-feature-' + initialTab)) {
        tabOnActivate(initialTab);
    }

    // ── Settings save ──

    var saveBtn = el('segurium-save-settings');
    if (saveBtn) {
        saveBtn.addEventListener('click', function () {
            saveBtn.disabled = true;
            var statusEl = el('segurium-settings-status');
            statusEl.textContent = '';
            statusEl.classList.remove('segurium-status-warning');
            var textarea = el('segurium_scan_exclude');
            var cloudDetection = el('segurium_cloud_detection');
            var wipeOnUninstall = el('segurium_uninstall_wipe_data');
            // SEGURIUM-206: alerts opt-in.
            var alertsEnabled = el('segurium_alerts_email_enabled');
            var alertsEmail = el('segurium_alerts_email_address');
            // SEGURIUM-64: auto-fix opt-in.
            var autoFixEnabled = el('segurium_auto_fix_enabled');
            post({
                action: 'segurium_save_settings',
                nonce: seguriumScan.settingsNonce,
                scan_exclude: textarea ? textarea.value : '',
                cloud_detection: cloudDetection && cloudDetection.checked ? '1' : '',
                uninstall_wipe_data: wipeOnUninstall && wipeOnUninstall.checked ? '1' : '',
                alerts_email_enabled: alertsEnabled && alertsEnabled.checked ? '1' : '',
                alerts_email_address: alertsEmail ? alertsEmail.value : '',
                auto_fix_enabled: autoFixEnabled && autoFixEnabled.checked ? '1' : ''
            }).then(function (response) {
                saveBtn.disabled = false;
                if (!response.success) {
                    statusEl.textContent = 'Error saving.';
                    return;
                }
                var warnings = response.data && response.data.warnings || [];
                if (warnings.length > 0) {
                    statusEl.classList.add('segurium-status-warning');
                    statusEl.textContent = '\u26A0 ' + warnings.join(' ');
                    if (textarea) {
                        var lines = textarea.value.split('\n').filter(function (l) {
                            return l.trim() !== '*';
                        });
                        textarea.value = lines.join('\n');
                    }
                } else {
                    statusEl.textContent = '\u2713 Saved';
                }
            }).catch(function () {
                saveBtn.disabled = false;
                statusEl.textContent = 'Error saving.';
            });
        });
    }

    // ── Country helpers (shared across Geo Blocking tab and BF event log) ──
    // Full ISO 3166-1 alpha-2 country list, sorted by name (English).
    var COUNTRIES = [
        {code:'AD',name:'Andorra'},{code:'AE',name:'United Arab Emirates'},{code:'AF',name:'Afghanistan'},
        {code:'AG',name:'Antigua and Barbuda'},{code:'AI',name:'Anguilla'},{code:'AL',name:'Albania'},
        {code:'AM',name:'Armenia'},{code:'AO',name:'Angola'},{code:'AR',name:'Argentina'},
        {code:'AS',name:'American Samoa'},{code:'AT',name:'Austria'},{code:'AU',name:'Australia'},
        {code:'AW',name:'Aruba'},{code:'AZ',name:'Azerbaijan'},{code:'BA',name:'Bosnia and Herzegovina'},
        {code:'BB',name:'Barbados'},{code:'BD',name:'Bangladesh'},{code:'BE',name:'Belgium'},
        {code:'BF',name:'Burkina Faso'},{code:'BG',name:'Bulgaria'},{code:'BH',name:'Bahrain'},
        {code:'BI',name:'Burundi'},{code:'BJ',name:'Benin'},{code:'BM',name:'Bermuda'},
        {code:'BN',name:'Brunei'},{code:'BO',name:'Bolivia'},{code:'BR',name:'Brazil'},
        {code:'BS',name:'Bahamas'},{code:'BT',name:'Bhutan'},{code:'BW',name:'Botswana'},
        {code:'BY',name:'Belarus'},{code:'BZ',name:'Belize'},{code:'CA',name:'Canada'},
        {code:'CD',name:'DR Congo'},{code:'CF',name:'Central African Republic'},{code:'CG',name:'Congo'},
        {code:'CH',name:'Switzerland'},{code:'CI',name:'Ivory Coast'},{code:'CK',name:'Cook Islands'},
        {code:'CL',name:'Chile'},{code:'CM',name:'Cameroon'},{code:'CN',name:'China'},
        {code:'CO',name:'Colombia'},{code:'CR',name:'Costa Rica'},{code:'CU',name:'Cuba'},
        {code:'CV',name:'Cape Verde'},{code:'CW',name:'Curacao'},{code:'CY',name:'Cyprus'},
        {code:'CZ',name:'Czech Republic'},{code:'DE',name:'Germany'},{code:'DJ',name:'Djibouti'},
        {code:'DK',name:'Denmark'},{code:'DM',name:'Dominica'},{code:'DO',name:'Dominican Republic'},
        {code:'DZ',name:'Algeria'},{code:'EC',name:'Ecuador'},{code:'EE',name:'Estonia'},
        {code:'EG',name:'Egypt'},{code:'ER',name:'Eritrea'},{code:'ES',name:'Spain'},
        {code:'ET',name:'Ethiopia'},{code:'FI',name:'Finland'},{code:'FJ',name:'Fiji'},
        {code:'FK',name:'Falkland Islands'},{code:'FM',name:'Micronesia'},{code:'FO',name:'Faroe Islands'},
        {code:'FR',name:'France'},{code:'GA',name:'Gabon'},{code:'GB',name:'United Kingdom'},
        {code:'GD',name:'Grenada'},{code:'GE',name:'Georgia'},{code:'GG',name:'Guernsey'},
        {code:'GH',name:'Ghana'},{code:'GI',name:'Gibraltar'},{code:'GL',name:'Greenland'},
        {code:'GM',name:'Gambia'},{code:'GN',name:'Guinea'},{code:'GQ',name:'Equatorial Guinea'},
        {code:'GR',name:'Greece'},{code:'GT',name:'Guatemala'},{code:'GU',name:'Guam'},
        {code:'GW',name:'Guinea-Bissau'},{code:'GY',name:'Guyana'},{code:'HK',name:'Hong Kong'},
        {code:'HN',name:'Honduras'},{code:'HR',name:'Croatia'},{code:'HT',name:'Haiti'},
        {code:'HU',name:'Hungary'},{code:'ID',name:'Indonesia'},{code:'IE',name:'Ireland'},
        {code:'IL',name:'Israel'},{code:'IM',name:'Isle of Man'},{code:'IN',name:'India'},
        {code:'IQ',name:'Iraq'},{code:'IR',name:'Iran'},{code:'IS',name:'Iceland'},
        {code:'IT',name:'Italy'},{code:'JE',name:'Jersey'},{code:'JM',name:'Jamaica'},
        {code:'JO',name:'Jordan'},{code:'JP',name:'Japan'},{code:'KE',name:'Kenya'},
        {code:'KG',name:'Kyrgyzstan'},{code:'KH',name:'Cambodia'},{code:'KI',name:'Kiribati'},
        {code:'KM',name:'Comoros'},{code:'KN',name:'Saint Kitts and Nevis'},{code:'KP',name:'North Korea'},
        {code:'KR',name:'South Korea'},{code:'KW',name:'Kuwait'},{code:'KY',name:'Cayman Islands'},
        {code:'KZ',name:'Kazakhstan'},{code:'LA',name:'Laos'},{code:'LB',name:'Lebanon'},
        {code:'LC',name:'Saint Lucia'},{code:'LI',name:'Liechtenstein'},{code:'LK',name:'Sri Lanka'},
        {code:'LR',name:'Liberia'},{code:'LS',name:'Lesotho'},{code:'LT',name:'Lithuania'},
        {code:'LU',name:'Luxembourg'},{code:'LV',name:'Latvia'},{code:'LY',name:'Libya'},
        {code:'MA',name:'Morocco'},{code:'MC',name:'Monaco'},{code:'MD',name:'Moldova'},
        {code:'ME',name:'Montenegro'},{code:'MG',name:'Madagascar'},{code:'MH',name:'Marshall Islands'},
        {code:'MK',name:'North Macedonia'},{code:'ML',name:'Mali'},{code:'MM',name:'Myanmar'},
        {code:'MN',name:'Mongolia'},{code:'MO',name:'Macau'},{code:'MQ',name:'Martinique'},
        {code:'MR',name:'Mauritania'},{code:'MS',name:'Montserrat'},{code:'MT',name:'Malta'},
        {code:'MU',name:'Mauritius'},{code:'MV',name:'Maldives'},{code:'MW',name:'Malawi'},
        {code:'MX',name:'Mexico'},{code:'MY',name:'Malaysia'},{code:'MZ',name:'Mozambique'},
        {code:'NA',name:'Namibia'},{code:'NC',name:'New Caledonia'},{code:'NE',name:'Niger'},
        {code:'NG',name:'Nigeria'},{code:'NI',name:'Nicaragua'},{code:'NL',name:'Netherlands'},
        {code:'NO',name:'Norway'},{code:'NP',name:'Nepal'},{code:'NR',name:'Nauru'},
        {code:'NZ',name:'New Zealand'},{code:'OM',name:'Oman'},{code:'PA',name:'Panama'},
        {code:'PE',name:'Peru'},{code:'PG',name:'Papua New Guinea'},{code:'PH',name:'Philippines'},
        {code:'PK',name:'Pakistan'},{code:'PL',name:'Poland'},{code:'PR',name:'Puerto Rico'},
        {code:'PS',name:'Palestine'},{code:'PT',name:'Portugal'},{code:'PW',name:'Palau'},
        {code:'PY',name:'Paraguay'},{code:'QA',name:'Qatar'},{code:'RE',name:'Reunion'},
        {code:'RO',name:'Romania'},{code:'RS',name:'Serbia'},{code:'RU',name:'Russia'},
        {code:'RW',name:'Rwanda'},{code:'SA',name:'Saudi Arabia'},{code:'SB',name:'Solomon Islands'},
        {code:'SC',name:'Seychelles'},{code:'SD',name:'Sudan'},{code:'SE',name:'Sweden'},
        {code:'SG',name:'Singapore'},{code:'SH',name:'Saint Helena'},{code:'SI',name:'Slovenia'},
        {code:'SK',name:'Slovakia'},{code:'SL',name:'Sierra Leone'},{code:'SM',name:'San Marino'},
        {code:'SN',name:'Senegal'},{code:'SO',name:'Somalia'},{code:'SR',name:'Suriname'},
        {code:'SS',name:'South Sudan'},{code:'ST',name:'Sao Tome and Principe'},{code:'SV',name:'El Salvador'},
        {code:'SX',name:'Sint Maarten'},{code:'SY',name:'Syria'},{code:'SZ',name:'Eswatini'},
        {code:'TC',name:'Turks and Caicos'},{code:'TD',name:'Chad'},{code:'TG',name:'Togo'},
        {code:'TH',name:'Thailand'},{code:'TJ',name:'Tajikistan'},{code:'TL',name:'Timor-Leste'},
        {code:'TM',name:'Turkmenistan'},{code:'TN',name:'Tunisia'},{code:'TO',name:'Tonga'},
        {code:'TR',name:'Turkey'},{code:'TT',name:'Trinidad and Tobago'},{code:'TV',name:'Tuvalu'},
        {code:'TW',name:'Taiwan'},{code:'TZ',name:'Tanzania'},{code:'UA',name:'Ukraine'},
        {code:'UG',name:'Uganda'},{code:'US',name:'United States'},{code:'UY',name:'Uruguay'},
        {code:'UZ',name:'Uzbekistan'},{code:'VA',name:'Vatican City'},{code:'VC',name:'Saint Vincent and the Grenadines'},
        {code:'VE',name:'Venezuela'},{code:'VG',name:'British Virgin Islands'},{code:'VI',name:'US Virgin Islands'},
        {code:'VN',name:'Vietnam'},{code:'VU',name:'Vanuatu'},{code:'WS',name:'Samoa'},
        {code:'YE',name:'Yemen'},{code:'YT',name:'Mayotte'},{code:'ZA',name:'South Africa'},
        {code:'ZM',name:'Zambia'},{code:'ZW',name:'Zimbabwe'}
    ];

    var COUNTRY_NAME_BY_CODE = (function () {
        var m = {};
        for (var i = 0; i < COUNTRIES.length; i++) m[COUNTRIES[i].code] = COUNTRIES[i].name;
        return m;
    })();

    function countryName(code) {
        if (typeof code !== 'string' || code.length !== 2) return '';
        return COUNTRY_NAME_BY_CODE[code.toUpperCase()] || '';
    }

    // Render an ISO alpha-2 code as a Unicode regional-indicator flag emoji.
    // On Windows ≤ 10 these render as plain letters (e.g. "US") since the
    // OS lacks flag glyphs — that's a graceful, deps-free fallback.
    function countryFlagEmoji(code) {
        if (typeof code !== 'string' || code.length !== 2) return '';
        var c = code.toUpperCase();
        if (c.charCodeAt(0) < 0x41 || c.charCodeAt(0) > 0x5A) return '';
        if (c.charCodeAt(1) < 0x41 || c.charCodeAt(1) > 0x5A) return '';
        var base = 0x1F1E6 - 0x41;
        return String.fromCodePoint(base + c.charCodeAt(0)) + String.fromCodePoint(base + c.charCodeAt(1));
    }

    // ── Scheduled scan settings ──
    //
    // Frequency dropdown + locale-aware time/day-of-week pickers. The
    // server stores everything in UTC + integer hour/minute/day-of-week;
    // the JS only handles rendering and visibility.
    (function () {
        var modeSelect = el('segurium-scheduled-mode');
        if (!modeSelect) return;

        var timeRow    = el('segurium-scheduled-time-row');
        var timeInput  = el('segurium-scheduled-time');
        var timeHint   = el('segurium-scheduled-time-hint');
        var dayRow     = el('segurium-scheduled-day-row');
        var daySelect  = el('segurium-scheduled-day');
        var saveBtn    = el('segurium-scheduled-save');
        var statusEl   = el('segurium-scheduled-status');
        var nextRunEl  = el('segurium-scheduled-next-run');
        var i18n       = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};
        var locale     = (typeof navigator !== 'undefined' && navigator.language) || 'en-US';

        function pad2(n) { return (n < 10 ? '0' : '') + n; }

        function applyVisibility(mode) {
            var showTime = (mode === 'daily' || mode === 'weekly');
            var showDay  = (mode === 'weekly');
            timeRow.style.display = showTime ? '' : 'none';
            dayRow.style.display  = showDay  ? '' : 'none';
        }

        function populateDays() {
            // Render Sunday-first day labels in the user's browser locale.
            // Pick a known reference date (a Sunday) and walk seven days
            // forward; map back to the WordPress 0..6 (Sun..Sat) convention.
            try {
                var fmt = new Intl.DateTimeFormat(locale, { weekday: 'long' });
                var ref = new Date(Date.UTC(2024, 0, 7)); // Sunday 2024-01-07
                daySelect.innerHTML = '';
                for (var i = 0; i < 7; i++) {
                    var d = new Date(ref);
                    d.setUTCDate(ref.getUTCDate() + i);
                    var opt = document.createElement('option');
                    opt.value = String(i);
                    opt.textContent = fmt.format(d);
                    daySelect.appendChild(opt);
                }
            } catch (e) {
                // Fallback for headless / Intl-less environments.
                var en = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
                daySelect.innerHTML = '';
                for (var j = 0; j < 7; j++) {
                    var o = document.createElement('option');
                    o.value = String(j);
                    o.textContent = en[j];
                    daySelect.appendChild(o);
                }
            }
        }

        function formatNextRun(tsUtc) {
            if (!tsUtc) return '';
            var date = new Date(tsUtc * 1000);
            try {
                var fmt = new Intl.DateTimeFormat(locale, {
                    weekday: 'long',
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    timeZoneName: 'short'
                });
                return fmt.format(date);
            } catch (e) {
                return date.toString();
            }
        }

        function renderSettings(payload) {
            var s = payload.settings || {};
            modeSelect.value = s.mode || 'off';
            timeInput.value = pad2(parseInt(s.hour || 0, 10)) + ':' + pad2(parseInt(s.minute || 0, 10));
            daySelect.value = String(parseInt(s.day_of_week || 0, 10));
            applyVisibility(s.mode || 'off');
            timeHint.textContent = i18n.schedTimeHint || '';
            nextRunEl.textContent = payload.next_run_utc
                ? ((i18n.schedNextRunPrefix || 'Next run:') + ' ' + formatNextRun(payload.next_run_utc))
                : '';
        }

        function loadSettings() {
            post({
                action: 'segurium_get_scheduled_scan_settings',
                nonce: seguriumScan.settingsNonce
            }).then(function (response) {
                if (!response || !response.success) {
                    statusEl.textContent = describeAjaxError(response && response.data);
                    return;
                }
                renderSettings(response.data);
            });
        }

        modeSelect.addEventListener('change', function () {
            applyVisibility(modeSelect.value);
        });

        if (saveBtn) {
            saveBtn.addEventListener('click', function () {
                saveBtn.disabled = true;
                statusEl.textContent = '';
                var time = timeInput.value || '00:00';
                var hm   = time.split(':');
                var hour = parseInt(hm[0], 10) || 0;
                var minute = parseInt(hm[1], 10) || 0;
                post({
                    action: 'segurium_save_scheduled_scan_settings',
                    nonce: seguriumScan.settingsNonce,
                    mode: modeSelect.value,
                    hour: hour,
                    minute: minute,
                    day_of_week: daySelect.value
                }).then(function (response) {
                    saveBtn.disabled = false;
                    if (!response || !response.success) {
                        statusEl.textContent = (i18n.schedSaveError || 'Could not save schedule.') +
                            ' ' + describeAjaxError(response && response.data);
                        return;
                    }
                    statusEl.textContent = i18n.schedSaved || 'Schedule saved.';
                    renderSettings(response.data);
                });
            });
        }

        populateDays();
        loadSettings();
    })();

    // ── Cross-tab signaling for dev modules ──
    //
    // Diagnostic features (see plugin/dev/) consume the seguriumAdmin
    // helper namespace defined above and listen to these CustomEvents:
    //   segurium:scan-starting   — a scan is about to begin
    //   segurium:scan-finished   — the runner stopped
    //   segurium:tab-changed     — sidebar nav switched (detail.feature)
    // dev/ is stripped from the production ZIP via plugin/.distignore.

    // ── Server State ──

    (function () {
        var tbody = el('segurium-server-state-tbody');
        if (!tbody) return;

        var ssPage = 1;
        var ssPerPage = 20;
        var ssRecentOnly = true;
        var ssStatusFilter = 'malicious';
        // Keyed by file path → row snapshot the user has acted on in this
        // session. Survives tab switches / pagination so the user can see
        // what they just processed without hunting for it.
        var ssStickyRows = Object.create(null);
        var ssLastCounts = { all: 0, malicious: 0, cleaned: 0, fixed: 0, ignored: 0 };

        function ssIsActed(path) {
            return !!ssStickyRows[path];
        }

        function ssMarkActed(path, item) {
            ssStickyRows[path] = Object.assign({}, item, { actedAt: Date.now() });
        }

        function applyServerState(data) {
            renderServerState(data);
            ssLastCounts = Object.assign({ all: 0, malicious: 0, cleaned: 0, fixed: 0, ignored: 0 }, data.counts || {});
            updateTabCounts(ssLastCounts);
            updateThreatBanner(ssLastCounts);
            updateFixAllState(ssLastCounts);
        }

        function loadServerState() {
            // SEGURIUM-301: first call at default params demuxes the
            // server_state slice from the batched initial-state read.
            // Anything that drifts from the defaults (pagination, filter
            // change, recent_only toggle) skips the cache and fetches
            // fresh.
            var atDefaults = (ssPage === 1 && ssPerPage === 20 && ssRecentOnly === true && ssStatusFilter === 'malicious');
            if (atDefaults && !seguriumInitialUsed.server_state) {
                takeInitialState('server_state').then(function (data) {
                    if (data) { applyServerState(data); return; }
                    fetchServerState();
                });
                return;
            }
            fetchServerState();
        }

        function fetchServerState() {
            post({
                action: 'segurium_get_server_state',
                nonce: seguriumScan.nonce,
                page: ssPage,
                per_page: ssPerPage,
                recent_only: ssRecentOnly ? '1' : '',
                filter: ssStatusFilter
            }).then(function (response) {
                if (!response.success) return;
                applyServerState(response.data);
            });
        }

        function updateFixAllState(counts) {
            var btn = el('segurium-ss-fix-all-btn');
            if (!btn) return;
            btn.disabled = !(counts && counts.malicious > 0);
        }

        // Map UI states (what the row actually shows) → counts bucket.
        // 'malicious' and 'restored' both live in the "malicious" bucket.
        function ssBucketForState(state) {
            if (state === 'malicious' || state === 'restored') return 'malicious';
            if (state === 'cleaned') return 'cleaned';
            if (state === 'fixed') return 'fixed';
            if (state === 'ignored') return 'ignored';
            return null;
        }

        function updateTabCounts(counts) {
            var tabs = document.querySelectorAll('.segurium-ss-tab-count');
            for (var i = 0; i < tabs.length; i++) {
                var key = tabs[i].getAttribute('data-count');
                var val = counts[key];
                if (typeof val !== 'number') val = 0;
                tabs[i].textContent = String(val);
                if (val > 0) {
                    tabs[i].classList.add('is-nonzero');
                } else {
                    tabs[i].classList.remove('is-nonzero');
                }
            }
        }

        function updateThreatBanner(counts) {
            var banner = el('segurium-ss-threat-banner');
            if (!banner) return;
            if (ssStatusFilter !== 'malicious') {
                banner.textContent = '';
                banner.classList.remove('is-clear');
                banner.classList.remove('is-empty');
                return;
            }
            var n = (counts && typeof counts.malicious === 'number') ? counts.malicious : 0;
            // SEGURIUM-248: distinguish "no scans yet" from "scan ran, 0
            // threats". `lastScan` is null on a fresh install until the
            // first scan completes; ssShowResult() refreshes it after a
            // run so the empty-state banner switches over without a
            // page reload.
            var hasScanned = !!seguriumScan.lastScan;
            if (!hasScanned && n === 0) {
                banner.textContent = i18n.noScansYet
                    || 'No scans yet — run your first scan.';
                banner.classList.remove('is-clear');
                banner.classList.add('is-empty');
                return;
            }
            if (n > 0) {
                var tpl = i18n.threatsRemaining || '%d threats still need your attention';
                banner.textContent = tpl.replace('%d', String(n));
                banner.classList.remove('is-clear');
                banner.classList.remove('is-empty');
            } else {
                banner.textContent = i18n.noThreatsRemaining || 'No threats — you are clear.';
                banner.classList.add('is-clear');
                banner.classList.remove('is-empty');
            }
        }

        function buildStateHtml(state) {
            var label = '';
            var cls = '';
            if (state === 'cleaned') {
                label = i18n.cleaned || 'Cleaned';
                cls = 'segurium-state--cleaned';
            } else if (state === 'restored') {
                label = i18n.restored || 'Restored';
                cls = 'segurium-state--restored';
            } else if (state === 'fixed') {
                label = i18n.fixed || 'Fixed';
                cls = 'segurium-state--fixed';
            } else if (state === 'ignored') {
                label = i18n.ignored || 'Ignored';
                cls = 'segurium-state--ignored';
            } else {
                label = i18n.malware || 'Malware';
                cls = 'segurium-state--malware';
            }
            return '<span class="segurium-state ' + cls + '">' + escHtml(label) + '</span>';
        }

        var modal = el('segurium-malware-modal');
        var modalTitle = el('segurium-modal-title');
        var modalBody = el('segurium-modal-body');

        function buildActionsHtml(item) {
            if (item.state === 'malicious') {
                return '<span style="display:inline-flex;align-items:center;gap:4px;">' +
                    '<button class="button button-small segurium-ss-clean-btn"' +
                    ' data-path="' + escAttr(item.path || '') + '"' +
                    ' data-sha256="' + escAttr(item.sha256 || '') + '"' +
                    ' data-verdict="' + (item.verdict || 0) + '">' +
                    escHtml(i18n.clean || 'Clean') + '</button>' +
                    '<div class="segurium-dropdown">' +
                    '<button class="button button-small segurium-dropdown-toggle" type="button">...</button>' +
                    '<div class="segurium-dropdown-menu">' +
                    '<a href="#" class="segurium-dropdown-item segurium-ss-show-disk"' +
                    ' data-path="' + escAttr(item.path || '') + '">' +
                    escHtml(i18n.showMalware || 'Show malware') + '</a>' +
                    '<a href="#" class="segurium-dropdown-item segurium-ss-ignore-hash"' +
                    ' data-path="' + escAttr(item.path || '') + '"' +
                    ' data-sha256="' + escAttr(item.sha256 || '') + '">' +
                    escHtml(i18n.ignoreUntilSame || 'Ignore until file is the same') + '</a>' +
                    '<a href="#" class="segurium-dropdown-item segurium-ss-ignore-path"' +
                    ' data-path="' + escAttr(item.path || '') + '">' +
                    escHtml(i18n.alwaysIgnore || 'Always ignore') + '</a>' +
                    '</div></div></span>';
            }
            if (item.state === 'cleaned' && item.backup_id) {
                return '<div class="segurium-dropdown">' +
                    '<button class="button button-small segurium-dropdown-toggle" type="button">...</button>' +
                    '<div class="segurium-dropdown-menu">' +
                    '<a href="#" class="segurium-dropdown-item segurium-ss-show-malware"' +
                    ' data-backup-id="' + escAttr(item.backup_id) + '">' +
                    escHtml(i18n.showMalware || 'Show malware') + '</a>' +
                    '<a href="#" class="segurium-dropdown-item segurium-ss-restore-btn"' +
                    ' data-backup-id="' + escAttr(item.backup_id) + '">' +
                    escHtml(i18n.restore || 'Restore') + '</a>' +
                    '</div></div>';
            }
            if (item.state === 'ignored') {
                return '<button class="button button-small segurium-ss-unignore-btn"' +
                    ' data-path="' + escAttr(item.path || '') + '">' +
                    escHtml(i18n.removeFromIgnore || 'Remove from ignore') + '</button>';
            }
            return '';
        }

        // Locate a rendered server-state row by its file path. Paths can
        // hold quotes/brackets, so we iterate attributes rather than build
        // a CSS attribute selector.
        function ssFindRowByPath(path) {
            var rows = tbody.querySelectorAll('tr[data-path]');
            for (var i = 0; i < rows.length; i++) {
                if (rows[i].getAttribute('data-path') === path) return rows[i];
            }
            return null;
        }

        // Move one row's worth of count between buckets and refresh the
        // tab badges / threat banner / Fix-all button. Shared by
        // applyRowMutation (row present) and the Fix-all off-page path
        // (row not on the current page, but the count still moved).
        function ssBumpCounts(prevState, newState) {
            var from = ssBucketForState(prevState);
            var to = ssBucketForState(newState);
            if (from && from !== to) ssLastCounts[from] = Math.max(0, (ssLastCounts[from] || 0) - 1);
            if (to && from !== to) ssLastCounts[to] = (ssLastCounts[to] || 0) + 1;
            updateTabCounts(ssLastCounts);
            updateThreatBanner(ssLastCounts);
            updateFixAllState(ssLastCounts);
        }

        function applyRowMutation(tr, newState, extra) {
            if (!tr) return;
            var path = tr.getAttribute('data-path') || '';
            var prevState = tr.getAttribute('data-state') || '';
            var stateCell = tr.querySelector('.segurium-ss-state-cell');
            var actionsCell = tr.querySelector('.segurium-ss-actions-cell');
            var item = {
                path: path,
                sha256: tr.getAttribute('data-sha256') || '',
                state: newState,
                timestamp: Math.floor(Date.now() / 1000),
                verdict: parseInt(tr.getAttribute('data-verdict') || '0', 10),
                backup_id: (extra && extra.backup_id) ? extra.backup_id : (tr.getAttribute('data-backup-id') || null)
            };
            if (stateCell) stateCell.innerHTML = buildStateHtml(newState);
            if (actionsCell) {
                actionsCell.innerHTML = buildActionsHtml(item);
                bindSSRowActions(tr);
            }
            if (item.backup_id) tr.setAttribute('data-backup-id', item.backup_id);
            tr.setAttribute('data-state', newState);
            // Only dim + sticky-pin rows that have moved TO a resolved
            // state. Unignoring or restoring an item puts it back in the
            // malicious bucket — the user must see it as a live threat,
            // not as a handled ghost.
            if (newState === 'malicious' || newState === 'restored') {
                tr.classList.remove('segurium-ss-row--acted');
                delete ssStickyRows[path];
            } else {
                tr.classList.add('segurium-ss-row--acted');
                ssMarkActed(path, item);
            }

            // Nudge counts locally so the tab badges + threat banner
            // update immediately without a round-trip. `all` is unchanged
            // (we only moved the row between buckets).
            ssBumpCounts(prevState, newState);
        }

        function bindSSRowActions(tr) {
            var cleanBtn = tr.querySelector('.segurium-ss-clean-btn');
            if (cleanBtn) {
                cleanBtn.addEventListener('click', function () {
                    var self = this;
                    var origText = self.textContent;
                    self.disabled = true;
                    self.textContent = i18n.processing || 'Processing...';
                    var row = self.closest('tr');
                    if (row) row.classList.add('segurium-ss-row--pending');
                    post({
                        action: 'segurium_cleanup_file',
                        nonce: seguriumScan.cleanupNonce,
                        path: self.getAttribute('data-path'),
                        sha256: self.getAttribute('data-sha256'),
                        verdict: self.getAttribute('data-verdict')
                    }).then(function (response) {
                        if (row) row.classList.remove('segurium-ss-row--pending');
                        if (response.success) {
                            var backupId = (response.data && response.data.backup_id) ? response.data.backup_id : null;
                            applyRowMutation(row, 'cleaned', { backup_id: backupId });
                            if (response.data && response.data.quota) {
                                quotaCacheTs = Date.now();
                                renderQuotaReadout(response.data.quota);
                            }
                        } else if (isPaywallResponse(response)) {
                            // Quota exhausted: surface the upsell modal and
                            // leave the button in its idle "Clean" state so
                            // the user can retry after upgrading. No "Failed"
                            // mark — the action did not fail, it was gated.
                            self.disabled = false;
                            self.textContent = origText;
                            showPaywallModal(response.data);
                        } else {
                            self.disabled = false;
                            self.textContent = i18n.failed || 'Failed';
                            self.classList.add('segurium-action-btn--error');
                            if (response.data && response.data.message) self.title = response.data.message;
                        }
                    }).catch(function () {
                        if (row) row.classList.remove('segurium-ss-row--pending');
                        self.disabled = false;
                        self.textContent = i18n.failed || 'Failed';
                    });
                });
            }

            var toggle = tr.querySelector('.segurium-dropdown-toggle');
            if (toggle) {
                toggle.addEventListener('click', function (e) {
                    e.stopPropagation();
                    var menu = this.nextElementSibling;
                    document.querySelectorAll('.segurium-dropdown-menu.segurium-dropdown-menu--open')
                        .forEach(function (m) { if (m !== menu) m.classList.remove('segurium-dropdown-menu--open'); });
                    menu.classList.toggle('segurium-dropdown-menu--open');
                });
            }

            var showBtn = tr.querySelector('.segurium-ss-show-malware');
            if (showBtn) {
                showBtn.addEventListener('click', function (e) {
                    e.preventDefault();
                    this.closest('.segurium-dropdown-menu').classList.remove('segurium-dropdown-menu--open');
                    post({
                        action: 'segurium_get_backup_content',
                        nonce: seguriumScan.cleanupNonce,
                        backup_id: this.getAttribute('data-backup-id')
                    }).then(function (response) {
                        if (response.success && modal) {
                            modalTitle.textContent = i18n.originalFile || 'Original file content (malware)';
                            var text = '';
                            try { text = atob(response.data.content || ''); } catch (e) { text = response.data.content || ''; }
                            modalBody.value = text;
                            modal.style.display = '';
                        }
                    });
                });
            }

            var showDiskBtn = tr.querySelector('.segurium-ss-show-disk');
            if (showDiskBtn) {
                showDiskBtn.addEventListener('click', function (e) {
                    e.preventDefault();
                    this.closest('.segurium-dropdown-menu').classList.remove('segurium-dropdown-menu--open');
                    var path = this.getAttribute('data-path');
                    post({
                        action: 'segurium_get_disk_content',
                        nonce: seguriumScan.cleanupNonce,
                        path: path
                    }).then(function (response) {
                        if (!modal) return;
                        if (response.success) {
                            var tpl = i18n.diskFile || 'Current on-disk content (malware): %s';
                            modalTitle.textContent = tpl.replace('%s', path || '');
                            modalBody.value = response.data.content || '';
                            modal.style.display = '';
                        } else {
                            var msg = (response.data && response.data.message)
                                ? response.data.message
                                : (i18n.errGeneric || 'Request failed');
                            modalTitle.textContent = i18n.errGeneric || 'Request failed';
                            modalBody.value = msg;
                            modal.style.display = '';
                        }
                    });
                });
            }

            var restoreBtn = tr.querySelector('.segurium-ss-restore-btn');
            if (restoreBtn) {
                restoreBtn.addEventListener('click', function (e) {
                    e.preventDefault();
                    this.closest('.segurium-dropdown-menu').classList.remove('segurium-dropdown-menu--open');
                    var btn = this;
                    var row = btn.closest('tr');
                    restoreWithPreflight(btn.getAttribute('data-backup-id'), btn, function () {
                        applyRowMutation(row, 'restored', {});
                    });
                });
            }

            function bindIgnore(selector, ignoreType) {
                var btn = tr.querySelector(selector);
                if (btn) {
                    btn.addEventListener('click', function (e) {
                        e.preventDefault();
                        this.closest('.segurium-dropdown-menu').classList.remove('segurium-dropdown-menu--open');
                        var row = this.closest('tr');
                        post({
                            action: 'segurium_ignore_file',
                            nonce: seguriumScan.cleanupNonce,
                            path: this.getAttribute('data-path'),
                            sha256: this.getAttribute('data-sha256') || '',
                            ignore_type: ignoreType
                        }).then(function (response) {
                            if (response.success) applyRowMutation(row, 'ignored', {});
                        });
                    });
                }
            }
            bindIgnore('.segurium-ss-ignore-hash', 'hash');
            bindIgnore('.segurium-ss-ignore-path', 'path');

            var unignoreBtn = tr.querySelector('.segurium-ss-unignore-btn');
            if (unignoreBtn) {
                unignoreBtn.addEventListener('click', function () {
                    var self = this;
                    var row = self.closest('tr');
                    self.disabled = true;
                    post({
                        action: 'segurium_unignore_file',
                        nonce: seguriumScan.cleanupNonce,
                        path: self.getAttribute('data-path')
                    }).then(function (response) {
                        if (response.success) {
                            applyRowMutation(row, 'malicious', {});
                        } else {
                            self.disabled = false;
                        }
                    }).catch(function () {
                        self.disabled = false;
                    });
                });
            }
        }

        function renderRow(item, opts) {
            opts = opts || {};
            var tr = document.createElement('tr');
            tr.setAttribute('data-path', item.path || '');
            tr.setAttribute('data-sha256', item.sha256 || '');
            tr.setAttribute('data-verdict', String(item.verdict || 0));
            tr.setAttribute('data-state', item.state || '');
            if (item.backup_id) tr.setAttribute('data-backup-id', item.backup_id);
            if (opts.acted || ssIsActed(item.path)) tr.classList.add('segurium-ss-row--acted');
            tr.innerHTML = '<td class="segurium-path-cell" title="' + escAttr(item.path || '') + '">' +
                truncatePath(item.path) +
                (item.sha256 ? '<br><span class="segurium-ss-sha256" style="font-size:11px;color:#999">SHA256: <span style="user-select:all">' + escHtml(item.sha256) + '</span></span>' : '') +
                '</td>' +
                '<td class="segurium-ss-state-cell">' + buildStateHtml(item.state) + '</td>' +
                '<td>' + escHtml(formatDate(item.timestamp)) + '</td>' +
                '<td class="segurium-ss-actions-cell">' + buildActionsHtml(item) + '</td>';
            bindSSRowActions(tr);
            return tr;
        }

        function renderStickyDivider() {
            var tr = document.createElement('tr');
            tr.className = 'segurium-ss-recent-divider';
            tr.innerHTML = '<td colspan="4">' + escHtml(i18n.recentlyProcessed || 'Recently processed in this session') + '</td>';
            return tr;
        }

        function ssEmptyMessage() {
            switch (ssStatusFilter) {
                case 'malicious': return i18n.tabMaliciousEmpty || i18n.serverStateEmpty || 'No files found.';
                case 'cleaned':   return i18n.tabCleanedEmpty   || i18n.serverStateEmpty || 'No files found.';
                case 'fixed':     return i18n.tabFixedEmpty     || i18n.serverStateEmpty || 'No files found.';
                case 'ignored':   return i18n.tabIgnoredEmpty   || i18n.serverStateEmpty || 'No files found.';
                default:          return i18n.serverStateEmpty  || 'No files found.';
            }
        }

        function renderServerState(data) {
            tbody.innerHTML = '';

            var seen = Object.create(null);
            data.items.forEach(function (item) {
                seen[item.path] = true;
                tbody.appendChild(renderRow(item));
            });

            // Carry session-acted rows that are no longer in the current
            // filter forward, pinned to the bottom and dimmed. Keeps the
            // user's just-processed item visible across tab switches so
            // they can still click "Restore" / undo without a refresh.
            var stickyPaths = Object.keys(ssStickyRows);
            var stragglers = [];
            for (var i = 0; i < stickyPaths.length; i++) {
                var p = stickyPaths[i];
                if (!seen[p]) stragglers.push(ssStickyRows[p]);
            }
            if (stragglers.length > 0) {
                tbody.appendChild(renderStickyDivider());
                stragglers
                    .sort(function (a, b) { return (b.actedAt || 0) - (a.actedAt || 0); })
                    .forEach(function (item) { tbody.appendChild(renderRow(item, { acted: true })); });
            }

            if (data.items.length === 0 && stragglers.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4">' + escHtml(ssEmptyMessage()) + '</td></tr>';
            }

            renderPagination(data);
        }

        function renderPagination(data) {
            var container = el('segurium-server-state-pagination');
            if (!container) return;

            container.innerHTML = '';
            if (data.total <= 0 && data.total_pages <= 1) return;

            var html = '<span class="segurium-pagination-info">' +
                escHtml((i18n.page || 'Page') + ' ' + data.page + ' ' + (i18n.of || 'of') + ' ' + data.total_pages) +
                ' (' + data.total + ' ' + escHtml(i18n.items || 'items') + ')' +
                '</span>';

            html += '<span class="segurium-pagination-buttons">';
            if (data.page > 1) {
                html += '<button class="button button-small segurium-ss-prev">&laquo; ' +
                    escHtml(i18n.prev || 'Previous') + '</button> ';
            }
            if (data.page < data.total_pages) {
                html += '<button class="button button-small segurium-ss-next">' +
                    escHtml(i18n.next || 'Next') + ' &raquo;</button>';
            }
            html += '</span>';

            container.innerHTML = html;

            var prevBtn = container.querySelector('.segurium-ss-prev');
            if (prevBtn) {
                prevBtn.addEventListener('click', function () {
                    ssPage--;
                    loadServerState();
                });
            }
            var nextBtn = container.querySelector('.segurium-ss-next');
            if (nextBtn) {
                nextBtn.addEventListener('click', function () {
                    ssPage++;
                    loadServerState();
                });
            }
        }

        var tabsBar = el('segurium-ss-tabs');
        if (tabsBar) {
            tabsBar.addEventListener('click', function (ev) {
                var btn = ev.target.closest('.segurium-ss-tab');
                if (!btn) return;
                var filter = btn.getAttribute('data-filter');
                if (!filter || filter === ssStatusFilter) return;
                var all = tabsBar.querySelectorAll('.segurium-ss-tab');
                for (var i = 0; i < all.length; i++) {
                    var is = (all[i] === btn);
                    all[i].classList.toggle('is-active', is);
                    all[i].setAttribute('aria-selected', is ? 'true' : 'false');
                }
                ssStatusFilter = filter;
                ssPage = 1;
                loadServerState();
            });
        }

        var recentCheckbox = el('segurium-ss-recent-only');
        if (recentCheckbox) {
            recentCheckbox.addEventListener('change', function () {
                ssRecentOnly = this.checked;
                ssPage = 1;
                loadServerState();
            });
        }

        var perPageSelect = el('segurium-ss-per-page');
        if (perPageSelect) {
            perPageSelect.addEventListener('change', function () {
                ssPerPage = parseInt(this.value, 10) || 20;
                ssPage = 1;
                loadServerState();
            });
        }

        // ── Scan from Malware Scanner tab ──

        var ssBtn = el('segurium-ss-scan-btn');
        var ssStopBtn = el('segurium-ss-stop-btn');
        var ssStatus = el('segurium-ss-scan-status');
        var ssProgressWrap = el('segurium-ss-progress-wrap');
        var ssBar = el('segurium-ss-progress-bar');
        var ssProgressLabel = el('segurium-ss-progress-label');
        var ssScanning = false;
        var ssTotalStart = null;

        // SEGURIUM-248: stop button affordances. Visibility is toggled
        // from ssBeginObserving / ssDone so the button only appears
        // while a scan is actually in flight.
        function ssShowStop(visible) {
            if (!ssStopBtn) return;
            ssStopBtn.hidden = !visible;
            ssStopBtn.disabled = false;
        }

        disableSSBtn = function () { if (ssBtn) { ssScanning = true; ssBtn.disabled = true; } };
        enableSSBtn = function () { if (ssBtn) { ssScanning = false; ssBtn.disabled = false; } };

        function ssDone() {
            ssScanning = false;
            if (ssBtn) ssBtn.disabled = false;
            ssShowStop(false);
            // Tear down the live progress UI so a Stop click clears the
            // bar without waiting for a page refresh. Idempotent for the
            // other paths (renderLastScan / ssShowResult already hide it).
            if (ssProgressWrap) ssProgressWrap.style.display = 'none';
            if (ssBar) {
                ssBar.classList.remove('segurium-progress-bar--active');
                ssBar.style.width = '';
            }
            if (ssProgressLabel) ssProgressLabel.textContent = '';
            document.dispatchEvent(new CustomEvent('segurium:scan-finished'));
            ssStopPolling();
        }

        function ssUpdateStatus(data) {
            var elapsed = ssTotalStart ? Math.floor((Date.now() - ssTotalStart) / 1000) : 0;
            ssProgressWrap.style.display = '';

            if (data.phase === 'listing') {
                ssBar.classList.add('segurium-progress-bar--active');
                ssBar.style.width = '';
                if (ssProgressLabel) ssProgressLabel.textContent = '';
                var parts = ['Listing... ' + data.files_verdicted + ' checked of ' + data.files_found + ' found'];
                if (data.threats_found > 0) parts.push(data.threats_found + ' threats');
                parts.push(ssFormatDuration(elapsed));
                appendStalledHint(parts, data);
                ssStatus.textContent = parts.join(' | ');
            } else if (data.phase === 'scanning') {
                ssBar.classList.remove('segurium-progress-bar--active');
                var total = data.files_found || 1;
                var done = data.files_verdicted + data.files_failed;
                var pct = done >= total ? 100 : Math.min(99, Math.round(done / total * 100));
                ssBar.style.width = pct + '%';
                if (ssProgressLabel) ssProgressLabel.textContent = pct + '%';
                var parts = ['Scanning... ' + done + ' checked of ' + data.files_found + ' found'];
                if (data.threats_found > 0) parts.push(data.threats_found + ' threats');
                parts.push(ssFormatDuration(elapsed));
                appendStalledHint(parts, data);
                ssStatus.textContent = parts.join(' | ');
            }
        }

        function ssShowResult(data) {
            var elapsed = ssTotalStart ? Math.floor((Date.now() - ssTotalStart) / 1000) : 0;
            var summary = {
                status: 'completed',
                files_found: data.files_found,
                files_verdicted: data.files_verdicted || 0,
                files_failed: data.files_failed || 0,
                files_skipped: data.files_skipped || 0,
                threats_found: data.threats_found || 0,
                duration: elapsed
            };
            renderLastScan(summary);
            // SEGURIUM-248: keep the localized lastScan in sync so the
            // empty-state banner switches from "no scans yet" to the
            // clean / threats-remaining variant without a reload.
            seguriumScan.lastScan = summary;
            // A completed scan produces the fresh truth; ghost rows from
            // prior session actions should stop lingering. The Scans tab
            // (when present) refreshes via the segurium:scan-finished
            // event dispatched from ssDone() below.
            ssStickyRows = Object.create(null);
            loadServerState();
        }

        // ── Scanner tab: polling + dispatch via Segurium_Scan_Runner ──
        //
        // The Scanner tab's button delegates to the server-side runner
        // (SEGURIUM-250 life_support_system architecture). We kick off the
        // scan and then poll the dedicated `segurium_scan_tick` endpoint
        // until completion. The endpoint returns status synchronously and
        // — via the runner's shared `shutdown` action — drives the chunk
        // loop after fastcgi_finish_request() detaches the response, so
        // the browser never blocks on actual scan work.
        //
        // Adaptive cadence: 3s while heartbeat advances (smooth UI without
        // perceptible lag), 5s while heartbeat is stalled (avoid hammering
        // hosts where the worker is genuinely waiting on I/O). SEGURIUM-271
        // raised the fast cadence from 1.5s — the runner pairs the change
        // with an observer-fresh fast-path on the cron / pageload entry
        // hooks, so the lower JS poll rate does NOT hand off scan work to
        // wp-cron.

        var SS_POLL_FAST_MS = 3000;
        var SS_POLL_SLOW_MS = 5000;
        var ssPollTimer = null;
        var ssLastHeartbeat = 0;
        // SEGURIUM-270: while the tab is backgrounded the runner keeps
        // making progress via wp-cron / pageload fallback, so park the
        // observer until the user comes back instead of polling blind.
        var ssVisibilityGate = makeVisibilityGate(function () {
            if (ssScanning) ssPollScanStatus();
        });

        function ssStopPolling() {
            if (ssPollTimer) {
                clearTimeout(ssPollTimer);
                ssPollTimer = null;
            }
            ssVisibilityGate.cancel();
        }

        function ssPollScanStatus() {
            if (document.hidden) {
                ssVisibilityGate.wait();
                return;
            }
            post({
                action: 'segurium_scan_tick',
                scope: 'malware',
                nonce: seguriumScan.nonce
            }).then(function (response) {
                if (!response || !response.success) {
                    ssStatus.textContent = (i18n.scanError || 'Error') + ': ' +
                        describeAjaxError(response && response.data);
                    ssDone();
                    return;
                }
                var data = response.data || {};
                if (!data.running && !data.completed) {
                    // Runner finished between polls. The server returns
                    // the most recent terminal scan (completed | cancelled
                    // | aborted) so we can paint the final summary instead
                    // of freezing at the last observed progress.
                    // SEGURIUM-413: prefer `last_terminal` (carries status)
                    // and only fall back to legacy `last_completed` when
                    // the server is older.
                    var terminal = data.last_terminal || data.last_completed;
                    if (terminal) {
                        renderLastScan(terminal);
                        seguriumScan.lastScan = terminal;
                        ssStickyRows = Object.create(null);
                        loadServerState();
                    }
                    ssDone();
                    return;
                }
                if (data.completed) {
                    ssShowResult(data);
                    ssDone();
                    return;
                }
                ssUpdateStatus(data);

                var hb = data.heartbeat || 0;
                var advanced = hb > ssLastHeartbeat;
                ssLastHeartbeat = hb;
                ssPollTimer = setTimeout(
                    ssPollScanStatus,
                    advanced ? SS_POLL_FAST_MS : SS_POLL_SLOW_MS
                );
            }).catch(function (err) {
                // SEGURIUM-764: same guard as the integrity poll. Without it a
                // handler exception stops the loop with the Scan button stuck
                // disabled and nothing in the console.
                ssStatus.textContent = reportPollHandlerError('malware-poll', err);
                ssDone();
            });
        }

        function ssBeginObserving(data) {
            ssScanning = true;
            if (ssBtn) ssBtn.disabled = true;
            ssShowStop(true);
            document.dispatchEvent(new CustomEvent('segurium:scan-starting'));
            ssProgressWrap.style.display = '';
            ssBar.style.width = '';
            if (data && data.started_at) {
                ssTotalStart = data.started_at * 1000;
            } else if (!ssTotalStart) {
                ssTotalStart = Date.now();
            }
            ssLastHeartbeat = (data && data.heartbeat) || 0;
            ssUpdateStatus(data || { phase: 'listing', files_found: 0, files_verdicted: 0, files_failed: 0, threats_found: 0 });
            ssStopPolling();
            ssPollTimer = setTimeout(ssPollScanStatus, SS_POLL_FAST_MS);
        }

        if (ssStopBtn) {
            ssStopBtn.addEventListener('click', function () {
                if (!confirm(i18n.stopScanConfirm || 'Stop the running scan? Progress so far will be discarded.')) return;
                ssStopBtn.disabled = true;
                post({
                    action: 'segurium_stop_scan',
                    nonce: seguriumScan.nonce
                }).then(function (response) {
                    if (response && response.success) {
                        ssStatus.textContent = i18n.scanStopped || 'Scan stopped.';
                        ssDone();
                    } else {
                        ssStopBtn.disabled = false;
                        ssStatus.textContent = (i18n.stopScanFailed || 'Could not stop the scan.') +
                            ' ' + describeAjaxError(response && response.data);
                    }
                });
            });
        }

        if (ssBtn) {
            ssBtn.addEventListener('click', function () {
                if (ssScanning) return;
                // Disable immediately — double-click must not race itself.
                ssScanning = true;
                ssBtn.disabled = true;
                document.dispatchEvent(new CustomEvent('segurium:scan-starting'));
                ssTotalStart = Date.now();
                ssStatus.textContent = i18n.scanStarting || 'Starting scan...';
                ssProgressWrap.style.display = '';
                ssBar.style.width = '';
                if (ssProgressLabel) ssProgressLabel.textContent = '';

                post({
                    action: 'segurium_start_scan',
                    nonce: seguriumScan.nonce
                }).then(function (response) {
                    if (!response || !response.success) {
                        ssStatus.textContent = (i18n.scanError || 'Error') + ': ' +
                            describeAjaxError(response && response.data);
                        ssDone();
                        return;
                    }
                    ssBeginObserving(response.data);
                });
            });
        }

        function ssFormatDuration(seconds) {
            var m = Math.floor(seconds / 60);
            var s = Math.floor(seconds % 60);
            return (m > 0 ? m + 'm ' : '') + s + 's';
        }

        function renderLastScan(scan) {
            if (!scan || !ssStatus) return;
            ssProgressWrap.style.display = 'none';
            ssBar.classList.remove('segurium-progress-bar--active');
            ssBar.style.width = '';
            if (ssProgressLabel) ssProgressLabel.textContent = '';
            var status = scan.status || 'completed';
            var found = scan.files_found || 0;
            var verdicted = scan.files_verdicted || 0;
            var threats = scan.threats_found || 0;
            var cleaned = scan.files_cleaned || 0;
            var failed = scan.files_failed || 0;
            var skipped = scan.files_skipped || 0;
            var html;
            if (status === 'cancelled' || status === 'aborted') {
                // SEGURIUM-413: don't pretend the run completed. Show what
                // was actually scanned vs discovered before termination.
                var tpl = (status === 'cancelled')
                    ? (i18n.scanStoppedSummary || 'Scan stopped — %1$d of %2$d files scanned.')
                    : (i18n.scanAbortedSummary || 'Scan aborted — %1$d of %2$d files scanned.');
                html = escHtml(tpl.replace('%1$d', verdicted).replace('%2$d', found));
                if (threats > 0) {
                    html += ' <strong style="color:#d63638;">' + threats + ' threats</strong>.';
                }
                html += ' ' + ssFormatDuration(scan.duration) + '.';
                ssStatus.innerHTML = html;
                return;
            }
            // SEGURIUM-486: `files_found` from the snapshot is the count of
            // files that were hashed and submitted; it does NOT include
            // filesystem-stage skips (excludes/unreadable/too-large/etc).
            // Use `verdicted + failed + skipped` as the leading "X files" so
            // the line accounts for every inspected entry without dropping
            // the skipped bucket.
            var inspected = verdicted + failed + skipped;
            var parts = [inspected + ' ' + (i18n.scanSummaryFiles || 'files')];
            if (failed > 0) {
                parts.push('<strong style="color:#d63638;">' + failed + ' ' + (i18n.scanSummaryFailed || 'failed') + '</strong>');
            }
            if (skipped > 0) {
                parts.push(skipped + ' ' + (i18n.scanSummarySkipped || 'skipped'));
            }
            parts.push(verdicted + ' ' + (i18n.scanSummaryScanned || 'scanned') + '.');
            html = escHtml(i18n.scanComplete || 'Scan complete.') + ' ' + parts.join(', ');
            if (threats > 0) {
                html += ' <strong style="color:#d63638;">' + threats + ' threats</strong>';
                if (cleaned > 0) {
                    html += ', <strong style="color:#00a32a;">' + cleaned + ' cleaned</strong>';
                }
            } else {
                html += ' <strong style="color:#00a32a;">Clean.</strong>';
            }
            html += ' ' + ssFormatDuration(scan.duration) + '.';
            ssStatus.innerHTML = html;
        }

        refreshServerState = loadServerState;
        loadServerState();

        // Show last completed scan summary
        if (seguriumScan.lastScan) {
            renderLastScan(seguriumScan.lastScan);
        }

        // Resume scan progress after a page refresh OR after the user
        // switches to this tab while the integrity scanner has chained
        // a malware scan (called from switchTab → 'scanner'). Observes
        // whatever the runner is driving server-side without ever
        // issuing a chunk call from the browser.
        ssResumeIfRunning = function () {
            if (ssScanning) return;
            post({
                action: 'segurium_scan_status',
                nonce: seguriumScan.nonce
            }).then(function (response) {
                if (!response || !response.success) return;
                var data = response.data || {};
                if (!data.running || data.completed) return;
                if (ssScanning) return;
                ssBeginObserving(data);
            });
        };
        ssResumeIfRunning();

        // ── Fix all ──
        //
        // Mirrors the integrity Fix All UX. Available on every install;
        // each cleanup consumes a slot from the per-installation cloud
        // cleanup quota. The cloud surfaces paywall_quota_exceeded once
        // the rolling-window cap is hit, and we render the upsell modal
        // off that response — there's no client-side gate.
        var ssFixAllBtn = el('segurium-ss-fix-all-btn');
        if (ssFixAllBtn) {
            ssFixAllBtn.addEventListener('click', function () {
                ssFixAllBtn.disabled = true;
                post({
                    action: 'segurium_scanner_fix_all_preview',
                    nonce: seguriumScan.nonce
                }).then(function (resp) {
                    if (resp.success) {
                        ssFixAllBtn.disabled = !(resp.data && resp.data.count > 0);
                        showSSFixAllConfirmation(resp.data);
                        return;
                    }
                    if (isPaywallResponse(resp)) {
                        showPaywallModal(resp.data);
                        ssFixAllBtn.disabled = !(ssLastCounts.malicious > 0);
                        return;
                    }
                    ssFixAllBtn.disabled = !(ssLastCounts.malicious > 0);
                    seguriumNotice(describeAjaxError(resp.data), resp.data && resp.data.code);
                }).catch(function () {
                    ssFixAllBtn.disabled = !(ssLastCounts.malicious > 0);
                });
            });
        }

        function showSSFixAllConfirmation(preview) {
            var modal   = el('segurium-confirm-modal');
            var title   = el('segurium-confirm-title');
            var content = el('segurium-confirm-content');
            var okBtn   = el('segurium-confirm-ok');
            var cancel  = el('segurium-confirm-cancel');
            var close   = el('segurium-confirm-close');
            if (!modal || !okBtn) return;

            var count = (preview && typeof preview.count === 'number') ? preview.count : 0;
            var copy  = (i18n.scannerFixAllCopy || 'This will attempt to clean %d detected malicious file(s). Each file is backed up before cleanup.')
                .replace('%d', String(count));

            title.textContent = i18n.scannerFixAllTitle || 'Clean all detected malware';
            content.innerHTML = '<p style="margin:0;">' + escHtml(copy) + '</p>';
            okBtn.textContent = i18n.scannerFixAllConfirm || 'Clean all';
            okBtn.disabled    = (count === 0);
            cancel.textContent = i18n.cancel || 'Cancel';
            cancel.style.display = '';
            modal.style.display = '';

            function closeModal() { modal.style.display = 'none'; }
            cancel.onclick = closeModal;
            close.onclick  = closeModal;
            var overlay = modal.querySelector('.segurium-diff-overlay');
            if (overlay) overlay.onclick = closeModal;

            okBtn.onclick = function () {
                closeModal();
                executeSSFixAll(preview.files || []);
            };
        }

        function executeSSFixAll(files) {
            if (!files.length) return;
            var total  = files.length;
            var done   = 0;
            var errors = [];

            if (ssFixAllBtn) ssFixAllBtn.disabled = true;
            if (ssBtn) ssBtn.disabled = true;
            if (ssStatus) ssStatus.textContent = i18n.scannerFixAllRunning || 'Cleaning malware...';
            if (ssProgressWrap) ssProgressWrap.style.display = '';
            if (ssBar) ssBar.style.width = '0%';
            if (ssProgressLabel) ssProgressLabel.textContent = '';

            function next(i) {
                if (i >= total) {
                    if (ssBar) ssBar.style.width = '100%';
                    if (ssBtn) ssBtn.disabled = false;
                    if (ssFixAllBtn) ssFixAllBtn.disabled = !(ssLastCounts.malicious > 0);
                    setTimeout(function () {
                        if (ssProgressWrap) ssProgressWrap.style.display = 'none';
                    }, 400);
                    if (ssStatus) {
                        ssStatus.textContent = errors.length > 0
                            ? (i18n.completedWithErrors || 'Completed with') + ' ' + errors.length + ' ' + (i18n.errors || 'errors')
                            : (i18n.scanComplete || 'Done.');
                    }
                    // SEGURIUM-588: do NOT refetch server state here. Each
                    // cleaned file was already mutated in place via
                    // applyRowMutation below, so the rows stay visible,
                    // greyed + sticky — identical to the single "Clean"
                    // button. A refetch would instead drop them from the
                    // Malicious view, making the two paths inconsistent.
                    quotaCacheTs = 0;
                    fetchQuotaReadout();
                    return;
                }

                var f = files[i];
                post({
                    action: 'segurium_cleanup_file',
                    nonce: seguriumScan.cleanupNonce,
                    path: f.path,
                    sha256: f.sha256,
                    verdict: f.verdict
                }).then(function (resp) {
                    done++;
                    if (ssBar) ssBar.style.width = Math.round(done / total * 100) + '%';
                    if (resp && resp.data && resp.data.quota) {
                        quotaCacheTs = Date.now();
                        renderQuotaReadout(resp.data.quota);
                    }
                    if (!resp.success) {
                        if (isPaywallResponse(resp)) {
                            // Free-tier cap hit mid-batch (or Pro lost
                            // entitlement). Surface the modal, then mark
                            // the cap-hit file and the rest of the queue
                            // as errors and fall through to the terminal
                            // branch — that flips the scan status to
                            // "Completed with N errors" instead of leaving
                            // an empty status box behind the modal.
                            showPaywallModal(resp.data);
                            var capMsg = (resp.data && resp.data.message)
                                || i18n.paywallQuotaTitle
                                || 'Cleanup quota reached';
                            for (var j = i; j < total; j++) {
                                errors.push(files[j].path + ': ' + capMsg);
                            }
                            next(total);
                            return;
                        }
                        errors.push(f.path + ': ' + (resp.data && resp.data.message || 'failed'));
                        next(i + 1);
                        return;
                    }
                    // SEGURIUM-588: reflect the cleaned file in the table the
                    // same way the single "Clean" button does — grey + pin
                    // the row in place. If the file is not on the current
                    // page (pagination), there is no row to mutate, so just
                    // move the count between buckets.
                    var backupId = (resp.data && resp.data.backup_id) ? resp.data.backup_id : null;
                    var row = ssFindRowByPath(f.path);
                    if (row) {
                        applyRowMutation(row, 'cleaned', { backup_id: backupId });
                    } else {
                        ssBumpCounts('malicious', 'cleaned');
                    }
                    next(i + 1);
                }).catch(function () {
                    done++;
                    errors.push(f.path + ': connection error');
                    next(i + 1);
                });
            }

            next(0);
        }
    })();

    // ── Integrity (accumulated state) ─────────────────────────────────────────

    (function () {
        var isBtn       = el('segurium-is-scan-btn');
        var isStopBtn   = el('segurium-is-stop-btn');
        var isFixAll    = el('segurium-is-fix-all-btn');
        var isStatus    = el('segurium-is-scan-status');
        var isProgress  = el('segurium-is-progress-wrap');
        var isBar       = el('segurium-is-progress-bar');
        var isProgressLabel = el('segurium-is-progress-label');
        var isTbody     = el('segurium-integrity-state-tbody');
        if (!isBtn) return;

        function isShowStop(visible) {
            if (!isStopBtn) return;
            isStopBtn.hidden = !visible;
            isStopBtn.disabled = false;
        }

        var isPage    = 1;
        var isPerPage = 20;
        var isScanning = false;
        var isExpandedKey = null; // track expanded component "{type}:{slug}"

        // Per-page-load file-ordering snapshot, keyed by component. On the
        // first render of a component's file list, files in 'open' state
        // float to the top so the user immediately sees what still needs
        // attention. Subsequent renders (e.g. after a fix/ignore action
        // triggers loadIntegrityState) reuse the cached order so a row the
        // user just acted on does not shuffle out from under them. A page
        // refresh resets and re-sorts.
        var isFileOrderByComp = Object.create(null);

        function isOrderedFiles(comp) {
            var files = comp.files || [];
            if (files.length === 0) return files;
            var key = compKey(comp);
            var snapshot = isFileOrderByComp[key];
            var byPath = Object.create(null);
            files.forEach(function (f) { byPath[f.path] = f; });
            var ordered;
            if (snapshot) {
                ordered = [];
                var seen = Object.create(null);
                snapshot.forEach(function (p) {
                    if (byPath[p]) { ordered.push(byPath[p]); seen[p] = true; }
                });
                files.forEach(function (f) {
                    if (!seen[f.path]) ordered.push(f);
                });
            } else {
                var open = [], rest = [];
                files.forEach(function (f) {
                    (f.state === 'open' ? open : rest).push(f);
                });
                ordered = open.concat(rest);
            }
            isFileOrderByComp[key] = ordered.map(function (f) { return f.path; });
            return ordered;
        }

        // Per-page-load opaque id. Server uses it to freeze the row order so
        // fix/ignore/restore actions don't shuffle rows under the user. A
        // browser refresh generates a new id and therefore a fresh order.
        var isSortSnapshotId = (function () {
            var bytes = new Uint8Array(16);
            (window.crypto || window.msCrypto).getRandomValues(bytes);
            var hex = '';
            for (var i = 0; i < bytes.length; i++) {
                hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
            }
            return hex;
        })();

        function loadIntegrityState() {
            post({
                action: 'segurium_get_integrity_state',
                nonce: seguriumScan.nonce,
                page: isPage,
                per_page: isPerPage,
                snapshot_id: isSortSnapshotId
            }).then(function (resp) {
                if (!resp.success) return;
                renderIntegrityState(resp.data);
            });
        }

        var typeIcons = { core: '\uD83C\uDFDB', plugin: '\uD83E\uDDE9', theme: '\uD83C\uDFA8' };

        function timeAgo(ts) {
            var diff = Math.floor(Date.now() / 1000) - ts;
            if (diff < 60) return i18n.justNow || 'just now';
            if (diff < 3600) return Math.floor(diff / 60) + (i18n.mAgo || 'm ago');
            if (diff < 86400) return Math.floor(diff / 3600) + (i18n.hAgo || 'h ago');
            if (diff < 172800) return i18n.yesterday || 'yesterday';
            if (diff < 2592000) return Math.floor(diff / 86400) + (i18n.dAgo || 'd ago');
            if (diff < 31536000) return Math.floor(diff / 2592000) + (i18n.moAgo || 'mo ago');
            return Math.floor(diff / 31536000) + (i18n.yAgo || 'y ago');
        }

        function compKey(comp) { return comp.type + ':' + comp.slug; }

        // Component categories matching the spreadsheet.
        // "known" = Core / Known plugin / Known theme (srcs available)
        // "abandoned" = Abandoned plugin/theme (srcs available)
        // "unknown" = Unknown plugin / Unknown theme (srcs N/A)
        // "delisted" = Delisted plugin/theme (srcs N/A)
        function compCategory(comp) {
            var cs = comp.component_status || 'listed';
            if (cs === 'delisted') return 'delisted';
            if (cs === 'abandoned') return 'abandoned';
            if (cs === 'not_in_repository') return 'unknown';
            return 'known';
        }

        function isComponentIssue(comp) {
            if (comp.state === 'ignored' || comp.state === 'deleted' || comp.state === 'not_found') return false;
            var cat = compCategory(comp);
            if (cat === 'delisted' || cat === 'abandoned' || cat === 'unknown') return true;
            return (comp.files || []).some(function (f) { return f.state === 'open'; });
        }

        function renderIntegrityState(data) {
            isTbody.innerHTML = '';
            if (!data.items || data.items.length === 0) {
                isTbody.innerHTML = '<tr><td colspan="6">' +
                    escHtml(i18n.serverStateEmpty || 'No integrity data. Run a scan.') +
                    '</td></tr>';
                isFixAll.disabled = true;
                renderISPagination(data);
                return;
            }
            var hasActionable = false;
            data.items.forEach(function (comp) {
                var tr = document.createElement('tr');
                var cat = compCategory(comp);
                var isDeleted = comp.state === 'deleted' || comp.state === 'not_found';

                // Unknown components: don't show file details (not verifiable).
                // Deleted components: files are gone, nothing to show.
                var showFiles = !isDeleted && !isIgnored && cat !== 'unknown' && cat !== 'delisted' && comp.files && comp.files.length > 0;
                var expandHtml = showFiles
                    ? '<span class="segurium-is-expand-icon">\u25B6</span>'
                    : '<span style="display:inline-block;width:16px;"></span>';
                var icon = typeIcons[comp.type] || '\u2753';
                var nameHtml = '<span class="segurium-is-type-icon" title="' + escAttr(comp.type || '') + '">' +
                    icon + '</span> ' + escHtml(comp.slug || '') +
                    ' <small>' + escHtml(comp.version || '') + '</small>';
                var statusHtml = buildISStatusBadge(comp);
                var openCount = 0;
                (comp.files || []).forEach(function (f) {
                    if (f.state === 'open') openCount++;
                });
                if (isComponentIssue(comp)) hasActionable = true;

                var isIgnored = comp.state === 'ignored';
                var filesHtml = '';
                if (isDeleted || isIgnored) {
                    filesHtml = '';
                } else if (cat === 'unknown' || cat === 'delisted') {
                    // Always 1 issue (the component itself).
                    filesHtml = '<strong style="color:#d63638;">1 ' + escHtml(i18n.issue || 'issue') + '</strong>';
                } else if (cat === 'abandoned') {
                    // 1 (component) + open file issues.
                    var totalIssues = 1 + openCount;
                    var issueWord = totalIssues === 1 ? (i18n.issue || 'issue') : (i18n.issues || 'issues');
                    filesHtml = '<strong style="color:#d63638;">' + totalIssues + ' ' + escHtml(issueWord) + '</strong>';
                } else {
                    var issueWord = openCount === 1 ? (i18n.issue || 'issue') : (i18n.issues || 'issues');
                    if (openCount > 0) {
                        filesHtml = '<strong style="color:#d63638;">' + openCount + ' ' + escHtml(issueWord) + '</strong>, ';
                    }
                    filesHtml += (comp.ok_count || 0) + ' OK';
                }
                var dateHtml = comp.timestamp
                    ? '<span title="' + escAttr(formatDate(comp.timestamp)) + '">' + timeAgo(comp.timestamp) + '</span>'
                    : '';
                var actionsHtml = buildISComponentActions(comp);

                tr.innerHTML = '<td>' + expandHtml + '</td>' +
                    '<td>' + nameHtml + '</td>' +
                    '<td>' + statusHtml + '</td>' +
                    '<td>' + filesHtml + '</td>' +
                    '<td>' + dateHtml + '</td>' +
                    '<td>' + actionsHtml + '</td>';

                tr.setAttribute('data-comp-key', compKey(comp));

                if (showFiles) {
                    tr.style.cursor = 'pointer';
                    tr.addEventListener('click', function (e) {
                        if (e.target.closest('button, a, .segurium-dropdown')) return;
                        toggleISDetail(comp, tr);
                    });
                }

                bindISComponentActionHandlers(tr, comp);
                isTbody.appendChild(tr);

                // Re-expand previously expanded row.
                if (isExpandedKey && compKey(comp) === isExpandedKey && showFiles) {
                    toggleISDetail(comp, tr);
                }
            });
            isFixAll.disabled = !hasActionable;
            renderISPagination(data);
        }

        function isAllIgnored(comp) {
            var files = comp.files || [];
            return files.length > 0 && files.every(function (f) { return f.state === 'ignored'; });
        }

        function buildISStatusBadge(comp) {
            if (comp.state === 'deleted') {
                return '<span class="segurium-is-status segurium-is-status--deleted">' + escHtml(i18n.intDeleted || 'Deleted') + '</span>';
            }
            if (comp.state === 'not_found') {
                return '<span class="segurium-is-status segurium-is-status--deleted">' + escHtml(i18n.notFound || 'Not found') + '</span>';
            }
            // Component-level ignored (abandoned/unknown/delisted).
            if (comp.state === 'ignored') {
                return '<span class="segurium-is-status segurium-is-status--not-in-repo">' + escHtml(i18n.ignoredLabel || 'Ignored') + '</span>';
            }
            var cat = compCategory(comp);
            // For core/known: if all file issues are ignored → clean.
            if (cat === 'known' && isAllIgnored(comp)) {
                // Falls through to clean below.
            }
            var cs = comp.component_status || 'listed';
            if (cs === 'delisted') {
                return '<span class="segurium-is-status segurium-is-status--delisted">' + escHtml(i18n.intDelisted || 'Delisted') + '</span>';
            }
            if (cs === 'abandoned') {
                return '<span class="segurium-is-status segurium-is-status--abandoned">' + escHtml(i18n.intAbandoned || 'Abandoned') + '</span>';
            }
            if (cs === 'not_in_repository') {
                return '<span class="segurium-is-status segurium-is-status--issues">' + escHtml(i18n.intNotWpOrg || 'Not from WordPress.org') + '</span>';
            }
            var hasOpen = (comp.files || []).some(function (f) { return f.state === 'open'; });
            return hasOpen
                ? '<span class="segurium-is-status segurium-is-status--issues">' + escHtml(i18n.issuesFound || 'Issues') + '</span>'
                : '<span class="segurium-is-status segurium-is-status--clean">' + escHtml(i18n.clean || 'Clean') + '</span>';
        }

        // Component-level action availability per the spreadsheet.
        function buildISComponentActions(comp) {
            var cat = compCategory(comp);
            var files = comp.files || [];
            var hasOpen    = files.some(function (f) { return f.state === 'open'; });
            var hasIgnored = files.some(function (f) { return f.state === 'ignored'; });
            var hasFixed   = files.some(function (f) { return f.state === 'fixed'; });

            // Component deleted or not found → only Restore (if backup exists).
            if (comp.state === 'deleted' || comp.state === 'not_found') {
                if (comp.backup_id) {
                    return compBtn('segurium-is-restore-comp', comp, i18n.intRestore || 'Restore');
                }
                return '';
            }

            // Component-level ignored → only Unignore.
            if (comp.state === 'ignored') {
                return compBtn('segurium-is-unignore-comp', comp, i18n.removeFromIgnore || 'Unignore');
            }

            var btns = '';

            if (cat === 'known') {
                // Core/known: Fix (file-level), Ignore (file-level), Unignore (file-level), Restore.
                if (hasOpen) {
                    btns += compBtn('segurium-is-fix-comp', comp, i18n.intFix || 'Fix') + ' ';
                    btns += compBtn('segurium-is-ignore-comp', comp, i18n.intIgnore || 'Ignore') + ' ';
                }
                if (hasIgnored) {
                    btns += compBtn('segurium-is-unignore-comp', comp, i18n.removeFromIgnore || 'Unignore') + ' ';
                }
                if (hasFixed) {
                    btns += compBtn('segurium-is-restore-comp-files', comp, i18n.intRestore || 'Restore') + ' ';
                }
            } else {
                // Abandoned/unknown/delisted: Delete + Ignore (component-level).
                btns += compBtn('segurium-is-delete-comp', comp, i18n.delete || 'Delete') + ' ';
                btns += compBtn('segurium-is-ignore-comp', comp, i18n.intIgnore || 'Ignore') + ' ';
                // Restore only for abandoned (has sources). Not for unknown/delisted.
                if (hasFixed && cat === 'abandoned') {
                    btns += compBtn('segurium-is-restore-comp-files', comp, i18n.intRestore || 'Restore') + ' ';
                }
            }

            return btns;
        }

        function compBtn(cls, comp, label) {
            return '<button class="button button-small ' + cls + '"' +
                ' data-slug="' + escAttr(comp.slug) + '"' +
                ' data-type="' + escAttr(comp.type) + '"' +
                ' data-version="' + escAttr(comp.version || '') + '"' +
                ' data-backup="' + escAttr(comp.backup_id || '') + '">' +
                escHtml(label) + '</button>';
        }

        function bindISComponentActionHandlers(tr, comp) {
            var intNonce = seguriumScan.integrityNonce;
            var cat = compCategory(comp);

            // Fix (known only): fix all open files per file action table.
            bindClick(tr, '.segurium-is-fix-comp', function (btn) {
                var queue = [];
                (comp.files || []).forEach(function (f) {
                    if (f.state !== 'open') return;
                    var v = f.verdict || '';
                    var fixVerdict = (v === 'unknown' || v === 'version_not_found') ? 'new' : 'modified';
                    queue.push({
                        action: 'segurium_integrity_fix_file', nonce: intNonce,
                        comp_type: comp.type, comp_slug: comp.slug,
                        comp_version: comp.version, file_path: f.path,
                        sha256: f.sha256 || '', verdict: fixVerdict
                    });
                });
                if (queue.length === 0) return;
                btn.disabled = true;
                runQueue(queue, {
                    title: i18n.intFixAll || 'Fixing files...',
                    getLabel: function (item) { return item.file_path || ''; }
                });
            });

            // Delete (abandoned/unknown/delisted): backup & delete entire component.
            bindClick(tr, '.segurium-is-delete-comp', function (btn) {
                btn.disabled = true;
                post({
                    action: 'segurium_integrity_delete_component',
                    nonce: seguriumScan.nonce,
                    type: comp.type, slug: comp.slug
                }).then(function (resp) {
                    if (!resp.success) seguriumNoticeFromError(resp.data, i18n.intDeleteFailed || 'Delete failed');
                    loadIntegrityState();
                });
            });

            // Ignore: per component action table, applies to open files.
            // Abandoned special: fixed files → restore from backup & add to ignore.
            bindClick(tr, '.segurium-is-ignore-comp', function (btn) {
                btn.disabled = true;
                if (cat !== 'known') {
                    // Component-level ignore for abandoned/unknown/delisted.
                    post({
                        action: 'segurium_integrity_ignore_component', nonce: seguriumScan.nonce,
                        slug: comp.slug, type: comp.type
                    }).then(function () { loadIntegrityState(); }).catch(function () { loadIntegrityState(); });
                } else {
                    // Core/known: ignore individual open files.
                    var queue = [];
                    (comp.files || []).forEach(function (f) {
                        if (f.state === 'open') {
                            queue.push({
                                action: 'segurium_integrity_ignore_file', nonce: seguriumScan.nonce,
                                slug: comp.slug, type: comp.type, file_path: f.path
                            });
                        }
                    });
                    if (queue.length === 0) { loadIntegrityState(); return; }
                    runQueue(queue, {
                        title: i18n.progressIgnoring || 'Updating files…',
                        getLabel: function (item) { return item.file_path || ''; }
                    });
                }
            });

            // Remove from ignore.
            bindClick(tr, '.segurium-is-unignore-comp', function (btn) {
                btn.disabled = true;
                if (comp.state === 'ignored') {
                    // Component-level unignore.
                    post({
                        action: 'segurium_integrity_unignore_component', nonce: seguriumScan.nonce,
                        slug: comp.slug, type: comp.type
                    }).then(function () { loadIntegrityState(); }).catch(function () { loadIntegrityState(); });
                } else {
                    // File-level unignore (core/known).
                    var queue = [];
                    (comp.files || []).forEach(function (f) {
                        if (f.state === 'ignored') {
                            queue.push({
                                action: 'segurium_integrity_unignore_file', nonce: seguriumScan.nonce,
                                slug: comp.slug, type: comp.type, file_path: f.path
                            });
                        }
                    });
                    if (queue.length === 0) { loadIntegrityState(); return; }
                    runQueue(queue, {
                        title: i18n.progressIgnoring || 'Updating files…',
                        getLabel: function (item) { return item.file_path || ''; }
                    });
                }
            });

            // Restore component from backup (when component was deleted).
            bindClick(tr, '.segurium-is-restore-comp', function (btn) {
                btn.disabled = true;
                post({
                    action: 'segurium_integrity_restore_component',
                    nonce: seguriumScan.nonce,
                    type: comp.type, slug: comp.slug, backup_id: comp.backup_id
                }).then(function (resp) {
                    if (!resp.success) seguriumNoticeFromError(resp.data, i18n.intRestoreFailed || 'Restore failed');
                    loadIntegrityState();
                });
            });

            // Restore fixed files (restore from backup per file).
            bindClick(tr, '.segurium-is-restore-comp-files', function (btn) {
                var queue = [];
                (comp.files || []).forEach(function (f) {
                    if (f.state === 'fixed' && f.backup_id) {
                        queue.push({
                            action: 'segurium_integrity_restore_file', nonce: intNonce,
                            backup_id: f.backup_id, comp_type: comp.type,
                            comp_slug: comp.slug, file_path: f.path
                        });
                    }
                });
                if (queue.length === 0) return;
                btn.disabled = true;
                runQueue(queue, {
                    title: i18n.progressRestoring || 'Restoring files…',
                    getLabel: function (item) { return item.file_path || ''; }
                });
            });
        }

        function bindClick(parent, selector, handler) {
            var el = parent.querySelector(selector);
            if (!el) return;
            el.addEventListener('click', function (e) {
                e.stopPropagation();
                e.preventDefault();
                handler(el);
            });
        }

        function runQueue(queue, opts) {
            opts = opts || {};
            var total = queue.length;
            var i = 0;
            var firstError = null;
            var modalShown = false;
            var showTimer = setTimeout(function () {
                modalShown = true;
                progressModal.open(opts.title || '');
                progressModal.update(0, total, labelFor(queue[0]));
            }, 250);

            function labelFor(item) {
                if (!item) return '';
                if (opts.getLabel) return opts.getLabel(item) || '';
                return '';
            }

            function teardown() {
                if (showTimer) { clearTimeout(showTimer); showTimer = null; }
                if (modalShown) progressModal.close();
                // SEGURIUM-830: every exit (completion, paywall, abort)
                // surfaces the first refusal instead of dropping it.
                if (firstError) {
                    seguriumNoticeFromError(firstError, i18n.intFixFailed || 'Fix failed');
                    firstError = null;
                }
            }

            function next(resp) {
                // SEGURIUM-207: a paywall response from any item in the
                // queue aborts the rest — once the user has hit the cap
                // every subsequent integrity fix would 402 too. Surface
                // the modal once and let the user upgrade.
                if (isPaywallResponse(resp)) {
                    teardown();
                    showPaywallModal(resp.data);
                    loadIntegrityState();
                    return;
                }
                // SEGURIUM-830: keep the first refusal so it is not lost
                // when the queue finishes (e.g. integrity_protected_file).
                if (resp && !resp.success && !firstError) {
                    firstError = resp.data || {};
                }
                if (modalShown) {
                    progressModal.update(i, total, labelFor(queue[i]));
                    if (progressModal.isAborted()) {
                        teardown();
                        loadIntegrityState();
                        return;
                    }
                }
                if (i >= queue.length) {
                    teardown();
                    loadIntegrityState();
                    return;
                }
                post(queue[i++]).then(next).catch(function () { next(); });
            }
            next();
        }

        function toggleISDetail(comp, parentTr) {
            var next = parentTr.nextElementSibling;
            var isOpen = next && next.classList.contains('segurium-is-detail-row');

            // Collapse all other expanded rows first.
            var openRows = isTbody.querySelectorAll('.segurium-is-detail-row');
            for (var i = 0; i < openRows.length; i++) {
                var prev = openRows[i].previousElementSibling;
                if (prev) prev.classList.remove('segurium-is-expanded');
                openRows[i].remove();
            }

            if (isOpen) {
                isExpandedKey = null;
                return;
            }
            if (!comp.files || comp.files.length === 0) return;

            parentTr.classList.add('segurium-is-expanded');
            isExpandedKey = compKey(comp);
            var detailTr = document.createElement('tr');
            detailTr.className = 'segurium-is-detail-row';
            var td = document.createElement('td');
            td.colSpan = 6;

            var html = '<table class="segurium-is-file-table widefat"><thead><tr>' +
                '<th>' + escHtml(i18n.file || 'File') + '</th>' +
                '<th>' + escHtml(i18n.state || 'State') + '</th>' +
                '<th>' + escHtml(i18n.verdict || 'Verdict') + '</th>' +
                '<th>' + escHtml(i18n.actions || 'Actions') + '</th>' +
                '</tr></thead><tbody>';
            isOrderedFiles(comp).forEach(function (f) {
                var verdictCls = '';
                var verdictLabel = f.verdict || '';
                if (f.verdict === 'modified') verdictCls = 'segurium-state--malware';
                else if (f.verdict === 'unknown' || f.verdict === 'version_not_found') {
                    verdictCls = 'segurium-state--fixed';
                    verdictLabel = i18n.unrecognizedFile || 'unrecognized file';
                } else if (f.verdict === 'missing') verdictCls = 'segurium-state--ignored';

                // UI-only overlay (SHA-256 join with malware scanner): when the
                // same file body is currently flagged malicious, suffix the
                // verdict cell. Stored verdict in DB is unchanged.
                var verdictHtml = '<span class="' + verdictCls + '">' + escHtml(verdictLabel) + '</span>';
                if (f.has_malware) {
                    verdictHtml += ' <span class="segurium-state--malware"> / ' +
                        escHtml(i18n.verdictMalwareSuffix || '(!) malware') +
                        '</span>';
                }

                var stateCls = '';
                if (f.state === 'open') stateCls = 'segurium-state--malware';
                else if (f.state === 'fixed') stateCls = 'segurium-state--cleaned';
                else if (f.state === 'deleted') stateCls = 'segurium-state--cleaned';
                else if (f.state === 'ignored') stateCls = 'segurium-state--ignored';

                html += '<tr><td>' + escHtml(f.path) +
                    (f.sha256 ? '<br><span style="font-size:11px;color:#999">SHA256: <span style="user-select:all">' + escHtml(f.sha256) + '</span></span>' : '') +
                    '</td>' +
                    '<td><span class="' + stateCls + '">' + escHtml(f.state || '') + '</span></td>' +
                    '<td>' + verdictHtml + '</td>' +
                    '<td>' + buildISFileActions(comp, f) + '</td></tr>';
            });
            html += '</tbody></table>';
            td.innerHTML = html;
            detailTr.appendChild(td);
            parentTr.after(detailTr);
            bindISFileActionHandlers(detailTr, comp);
        }

        function bindISFileActionHandlers(detailTr, comp) {
            var intNonce = seguriumScan.integrityNonce;

            function getData(btn) {
                return {
                    type: btn.getAttribute('data-type'),
                    slug: btn.getAttribute('data-slug'),
                    version: btn.getAttribute('data-version'),
                    path: btn.getAttribute('data-path'),
                    sha256: btn.getAttribute('data-sha256') || '',
                    verdict: btn.getAttribute('data-verdict') || ''
                };
            }

            // Fix (restore integrity for modified, delete for new/unknown)
            detailTr.querySelectorAll('.segurium-is-fix-btn').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var d = getData(btn);
                    var fixVerdict = (d.verdict === 'unknown' || d.verdict === 'version_not_found') ? 'new' : 'modified';
                    btn.disabled = true;
                    btn.textContent = i18n.processing || '...';
                    post({
                        action: 'segurium_integrity_fix_file', nonce: intNonce,
                        comp_type: d.type, comp_slug: d.slug, comp_version: d.version,
                        file_path: d.path, sha256: d.sha256, verdict: fixVerdict
                    }).then(function (r) {
                        // SEGURIUM-207: per-file integrity-fix can hit the
                        // shared 3/30d quota when verdict='new' (delete added
                        // file). Show the upsell instead of a generic alert.
                        if (isPaywallResponse(r)) {
                            showPaywallModal(r.data);
                            loadIntegrityState();
                            return;
                        }
                        if (!r.success) seguriumNoticeFromError(r.data, i18n.intFixFailed || 'Fix failed');
                        loadIntegrityState();
                    }).catch(function () { loadIntegrityState(); });
                });
            });

            // Diff
            detailTr.querySelectorAll('.segurium-is-diff-btn').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var d = getData(btn);
                    btn.disabled = true;
                    btn.textContent = i18n.processing || '...';
                    post({
                        action: 'segurium_integrity_diff_file', nonce: intNonce,
                        comp_type: d.type, comp_slug: d.slug, comp_version: d.version, file_path: d.path
                    }).then(function (r) {
                        btn.disabled = false;
                        btn.textContent = i18n.intDiff || 'Diff';
                        if (!r.success) { seguriumNoticeFromError(r.data, i18n.intDiffFailed || 'Diff failed'); return; }
                        try { showDiffModal(r.data.path, atob(r.data.original), atob(r.data.current)); }
                        catch (e) { seguriumNotice((i18n.intDiffDecodeError || 'Diff decode error') + ': ' + e.message); }
                    }).catch(function () {
                        btn.disabled = false;
                        btn.textContent = i18n.intDiff || 'Diff';
                    });
                });
            });

            // Ignore
            detailTr.querySelectorAll('.segurium-is-file-ignore').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var d = getData(btn);
                    btn.disabled = true;
                    post({
                        action: 'segurium_integrity_ignore_file', nonce: seguriumScan.nonce,
                        slug: d.slug, type: d.type, file_path: d.path
                    }).then(function () { loadIntegrityState(); }).catch(function () { loadIntegrityState(); });
                });
            });

            // Remove from ignore
            detailTr.querySelectorAll('.segurium-is-file-unignore').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var d = getData(btn);
                    btn.disabled = true;
                    post({
                        action: 'segurium_integrity_unignore_file', nonce: seguriumScan.nonce,
                        slug: d.slug, type: d.type, file_path: d.path
                    }).then(function () { loadIntegrityState(); }).catch(function () { loadIntegrityState(); });
                });
            });

            // Restore from backup (file-level)
            detailTr.querySelectorAll('.segurium-is-file-restore').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var d = getData(btn);
                    btn.disabled = true;
                    btn.textContent = i18n.processing || '...';
                    // Find backup_id from the comp files array
                    var bkpId = '';
                    (comp.files || []).forEach(function (f) {
                        if (f.path === d.path && f.backup_id) bkpId = f.backup_id;
                    });
                    if (!bkpId) {
                        // Belt-and-braces: buildISFileActions already hides
                        // Restore when f.backup_id is empty, but rotation
                        // can drift between render and click.
                        btn.disabled = false;
                        btn.textContent = i18n.intRestore || 'Restore';
                        seguriumNotice(
                            i18n.intRestoreNoBackup ||
                            'Cannot restore — no backup recorded for this file. The backup may have been rotated out.'
                        );
                        loadIntegrityState();
                        return;
                    }
                    post({
                        action: 'segurium_integrity_restore_file', nonce: intNonce,
                        backup_id: bkpId, comp_type: d.type, comp_slug: d.slug, file_path: d.path
                    }).then(function (r) {
                        if (!r.success) seguriumNoticeFromError(r.data, i18n.intRestoreFailed || 'Restore failed');
                        loadIntegrityState();
                    }).catch(function () { loadIntegrityState(); });
                });
            });

            // View file content
            detailTr.querySelectorAll('.segurium-is-view-btn').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var d = getData(btn);
                    btn.disabled = true;
                    btn.textContent = i18n.processing || '...';
                    post({
                        action: 'segurium_integrity_view_file', nonce: intNonce,
                        file_path: d.path
                    }).then(function (r) {
                        btn.disabled = false;
                        btn.textContent = i18n.view || 'View';
                        if (!r.success) { seguriumNoticeFromError(r.data, i18n.intViewFailed || 'View failed'); return; }
                        var modal = el('segurium-diff-modal');
                        var titleEl = el('segurium-diff-title');
                        var contentEl = el('segurium-diff-content');
                        titleEl.textContent = d.path;
                        var text = '';
                        try { text = atob(r.data.content); } catch (e) { text = r.data.content || ''; }
                        contentEl.innerHTML = '<pre style="margin:0;padding:12px;font-size:12px;white-space:pre-wrap;word-break:break-all;">' + escHtml(text) + '</pre>';
                        modal.style.display = '';
                        document.body.style.overflow = 'hidden';
                    }).catch(function () {
                        btn.disabled = false;
                        btn.textContent = i18n.view || 'View';
                    });
                });
            });
        }

        // File-level action availability per the File Action table.
        function buildISFileActions(comp, f) {
            var cat = compCategory(comp);
            var state = f.state || 'open';
            var verdict = f.verdict || '';
            var btns = '';

            function fileBtn(cls, label) {
                return '<button class="button button-small ' + cls + '"' +
                    ' data-slug="' + escAttr(comp.slug) + '"' +
                    ' data-type="' + escAttr(comp.type) + '"' +
                    ' data-version="' + escAttr(comp.version || '') + '"' +
                    ' data-path="' + escAttr(f.path) + '"' +
                    ' data-sha256="' + escAttr(f.sha256 || '') + '"' +
                    ' data-verdict="' + escAttr(verdict) + '">' +
                    escHtml(label) + '</button> ';
            }

            if (state === 'open' && (verdict === 'unknown' || verdict === 'version_not_found')) {
                // "new" file (unknown)
                if (cat === 'known' || cat === 'abandoned') {
                    btns += fileBtn('segurium-is-fix-btn', i18n.delete || 'Delete');
                    btns += fileBtn('segurium-is-file-ignore', i18n.intIgnore || 'Ignore');
                } else if (cat === 'unknown' || cat === 'delisted') {
                    btns += fileBtn('segurium-is-file-ignore', i18n.intIgnore || 'Ignore');
                }
            } else if (state === 'open' && verdict === 'modified') {
                // "modified" file
                if (cat === 'known' || cat === 'abandoned') {
                    btns += fileBtn('segurium-is-fix-btn', i18n.intFix || 'Fix');
                    btns += fileBtn('segurium-is-diff-btn', i18n.intDiff || 'Diff');
                    btns += fileBtn('segurium-is-file-ignore', i18n.intIgnore || 'Ignore');
                }
                // unknown/delisted modified: all "-"
            } else if (state === 'ignored') {
                // all categories: only "Remove from ignore"
                btns += fileBtn('segurium-is-file-unignore', i18n.removeFromIgnore || 'Unignore');
            } else if (state === 'fixed') {
                // "Restore from backup" — available for known, abandoned, unknown. NOT delisted.
                // f.backup_id guards rotated-out backups: without a backup
                // id the server-side restore would 400 anyway.
                if (cat !== 'delisted' && f.backup_id) {
                    btns += fileBtn('segurium-is-file-restore', i18n.intRestore || 'Restore');
                }
            }
            // "original" state: no actions (all "-")

            // View button — available for all files that exist on disk. A
            // fixed file whose original verdict was unknown/version_not_found
            // was deleted as part of the fix, so reading it from disk would
            // 404 — hide View in that case.
            var wasDeleted = state === 'fixed' && (verdict === 'unknown' || verdict === 'version_not_found');
            if (!wasDeleted && (state !== 'fixed' || cat === 'known' || cat === 'abandoned')) {
                btns += fileBtn('segurium-is-view-btn', i18n.view || 'View');
            }

            return btns;
        }

        function renderISPagination(data) {
            var container = el('segurium-integrity-state-pagination');
            if (!container) return;
            container.innerHTML = '';
            if (data.total_pages <= 1) return;

            var html = '<span class="segurium-pagination-info">' +
                escHtml((i18n.page || 'Page') + ' ' + data.page + ' / ' + data.total_pages) +
                ' (' + data.total + ' ' + escHtml(i18n.items || 'items') + ')' +
                '</span>';
            if (data.page > 1) {
                html += ' <button class="button button-small segurium-is-prev">' + escHtml(i18n.prev || 'Prev') + '</button>';
            }
            if (data.page < data.total_pages) {
                html += ' <button class="button button-small segurium-is-next">' + escHtml(i18n.next || 'Next') + '</button>';
            }
            container.innerHTML = html;

            var prevBtn = container.querySelector('.segurium-is-prev');
            var nextBtn = container.querySelector('.segurium-is-next');
            if (prevBtn) prevBtn.addEventListener('click', function () { isPage--; loadIntegrityState(); });
            if (nextBtn) nextBtn.addEventListener('click', function () { isPage++; loadIntegrityState(); });
        }

        // Per-page selector
        var isPerPageSelect = el('segurium-is-per-page');
        if (isPerPageSelect) {
            isPerPageSelect.addEventListener('change', function () {
                isPerPage = parseInt(this.value, 10) || 20;
                isPage = 1;
                loadIntegrityState();
            });
        }

        // ── Integrity scan status polling ──
        //
        // The runner drives integrity scan execution server-side (see
        // Segurium_Scan_Runner — SEGURIUM-250 life_support_system). The
        // admin UI is a pure observer: it polls the segurium_integrity_status
        // endpoint (which keeps the chained malware → integrity logic) and
        // never advances chunks itself. The runner's shared `shutdown`
        // action drives life_support_system() on every poll, so each
        // request both reads progress AND keeps the worker alive.
        //
        // Adaptive cadence: 3s while heartbeat advances, 5s while waiting.
        // Same rationale as the malware scanner — see SS_POLL_FAST_MS above.

        var IS_POLL_FAST_MS = 3000;
        var IS_POLL_SLOW_MS = 5000;
        var isPollTimer = null;
        var isLastHeartbeat = 0;
        // SEGURIUM-270: pause observer while tab is hidden — runner
        // continues server-side via wp-cron / pageload fallback.
        var isVisibilityGate = makeVisibilityGate(function () {
            if (isScanning) isPollStatus();
        });

        function isStopPolling() {
            if (isPollTimer) {
                clearTimeout(isPollTimer);
                isPollTimer = null;
            }
            isVisibilityGate.cancel();
        }

        function isPollStatus() {
            if (document.hidden) {
                isVisibilityGate.wait();
                return;
            }
            post({
                action: 'segurium_integrity_status',
                nonce: seguriumScan.nonce
            }).then(function (response) {
                if (!response || !response.success) {
                    isStatus.textContent = (i18n.scanError || 'Error') + ': ' + describeAjaxError(response && response.data);
                    isScanDone();
                    return;
                }
                var data = response.data || {};
                // SEGURIUM-205: when the user cancels the chained malware
                // scan, the deferred integrity start is dropped. The
                // server returns a one-shot chain_message describing what
                // happened — surface it before we tear the UI down.
                if (!data.running && !data.completed) {
                    if (data.chain_message) {
                        isStatus.textContent = data.chain_message;
                    }
                    isScanDone();
                    return;
                }
                if (data.running && !data.completed) {
                    isUpdateStatus(data);
                    var hb = data.heartbeat || 0;
                    var advanced = hb > isLastHeartbeat;
                    isLastHeartbeat = hb;
                    isPollTimer = setTimeout(
                        isPollStatus,
                        advanced ? IS_POLL_FAST_MS : IS_POLL_SLOW_MS
                    );
                    return;
                }
                if (!data.running || data.completed) {
                    isRenderCompletion();
                    isScanDone();
                }
            }).catch(function (err) {
                // Stop observing rather than retry: a handler bug repeats on
                // every poll. The runner keeps working server-side, so a
                // reload reattaches through isResumeIfRunning().
                isStatus.textContent = reportPollHandlerError('integrity-poll', err);
                isScanDone();
            });
        }

        function isBeginObserving() {
            isScanning = true;
            isBtn.disabled = true;
            isShowStop(true);
            isProgress.style.display = '';
            // SEGURIUM-247: match the malware scanner — show an indeterminate
            // animation until the runner reports a total, otherwise the user
            // sees a stuck 0% bar during the discovery / chained-malware phase.
            isBar.classList.add('segurium-progress-bar--active');
            isBar.style.width = '';
            if (isProgressLabel) isProgressLabel.textContent = '';
            isLastHeartbeat = 0;
            isStopPolling();
            isPollTimer = setTimeout(isPollStatus, IS_POLL_FAST_MS);
        }

        if (isStopBtn) {
            isStopBtn.addEventListener('click', function () {
                if (!confirm(i18n.stopScanConfirm || 'Stop the running scan? Progress so far will be discarded.')) return;
                isStopBtn.disabled = true;
                post({
                    action: 'segurium_integrity_stop',
                    nonce: seguriumScan.nonce
                }).then(function (response) {
                    if (response && response.success) {
                        isStatus.textContent = '';
                        isBar.classList.remove('segurium-progress-bar--active');
                        if (isProgressLabel) isProgressLabel.textContent = '';
                        isProgress.style.display = 'none';
                        isScanDone();
                    } else {
                        isStopBtn.disabled = false;
                        isStatus.textContent = (i18n.stopScanFailed || 'Could not stop the scan.') +
                            ' ' + describeAjaxError(response && response.data);
                    }
                });
            });
        }

        // Scan button — dispatches to runner, then polls for status
        isBtn.addEventListener('click', function () {
            if (isScanning) return;
            isScanning = true;
            isBtn.disabled = true;
            isStatus.textContent = i18n.scanStarting || 'Starting scan...';
            isProgress.style.display = '';
            // SEGURIUM-247: indeterminate animation until the first poll
            // returns a total — same UX as the malware scanner's listing phase.
            isBar.classList.add('segurium-progress-bar--active');
            isBar.style.width = '';
            if (isProgressLabel) isProgressLabel.textContent = '';

            post({
                action: 'segurium_integrity_start',
                nonce: seguriumScan.nonce
            }).then(function (response) {
                if (!response || !response.success) {
                    isStatus.textContent = (i18n.scanError || 'Error') + ': ' + describeAjaxError(response && response.data);
                    isScanDone();
                    return;
                }
                // SEGURIUM-406: queued = chain helper kicked off a
                // malware scan first. Show a one-shot informational
                // label and stop observing — the integrity tab waits
                // in not-running state until its turn arrives. The
                // user can watch the malware tab if they want
                // mid-chain progress.
                if (response.data && response.data.queued) {
                    isStatus.textContent = response.data.chain_message
                        || i18n.intChainRunningMalware
                        || 'Running a quick malware scan first…';
                    isScanDone();
                    return;
                }
                isBeginObserving();
            }).catch(function (err) {
                // The start request itself reports failure through the
                // success:false branch above, so this only fires when
                // isBeginObserving() throws — the scan is running, the
                // observer is not.
                isStatus.textContent = reportPollHandlerError('integrity-start', err);
                isScanDone();
            });
        });

        function isUpdateStatus(data) {
            var parts;
            if (data.total > 0) {
                var pct = data.processed >= data.total ? 100 : Math.min(99, Math.round(data.processed / data.total * 100));
                isBar.classList.remove('segurium-progress-bar--active');
                isBar.style.width = pct + '%';
                if (isProgressLabel) isProgressLabel.textContent = pct + '%';
                parts = [escHtml(i18n.checking || 'Checking') + ' ' + data.processed + ' / ' + data.total + ' (' + pct + '%)'];
            } else {
                isBar.classList.add('segurium-progress-bar--active');
                isBar.style.width = '';
                if (isProgressLabel) isProgressLabel.textContent = '';
                parts = [escHtml(i18n.discoveringComponents || 'Discovering components…')];
            }
            if (data.currently) parts.push(data.currently);
            if (data.elapsed_secs != null) parts.push(formatElapsed(data.elapsed_secs));
            appendStalledHint(parts, data);
            isStatus.textContent = parts.join(' | ');
        }

        function isRenderCompletion() {
            isStatus.textContent = '';
            isBar.classList.remove('segurium-progress-bar--active');
            isBar.style.width = '100%';
            if (isProgressLabel) isProgressLabel.textContent = '100%';
            setTimeout(function () {
                isProgress.style.display = 'none';
                if (isProgressLabel) isProgressLabel.textContent = '';
            }, 400);
            loadIntegrityState();
        }

        function isScanDone() {
            isScanning = false;
            isBtn.disabled = false;
            isShowStop(false);
            isStopPolling();
            // SEGURIUM-379: integrity scan terminations dispatch the same
            // signal the malware scanner already emits in ssDone(). The
            // post-action quota refresh listener (see "scan-finished →
            // refetch quota" below) re-reads /v1/quota/state so the
            // free-tier counter reflects any rolling-window decay or
            // slot consumption that happened during the run.
            document.dispatchEvent(new CustomEvent('segurium:scan-finished'));
        }

        // Resume observation on page load if an integrity scan is already
        // running (e.g. user closed the tab and came back).
        (function isResumeIfRunning() {
            post({
                action: 'segurium_integrity_status',
                nonce: seguriumScan.nonce
            }).then(function (response) {
                if (response && response.success && response.data && response.data.running) {
                    isStatus.textContent = i18n.scanRunning || 'Scan in progress...';
                    isProgress.style.display = '';
                    isUpdateStatus(response.data);
                    isBeginObserving();
                }
            }).catch(function (err) {
                // SEGURIUM-764: isUpdateStatus() runs here too. Without this
                // guard an exception is an unhandled rejection — silent, with
                // the tab left claiming nothing is running.
                isStatus.textContent = reportPollHandlerError('integrity-resume', err);
                isScanDone();
            });
        })();

        // Integrity Fix All button. Available on every install; clicks
        // consume cloud cleanup-quota slots and surface the upsell modal
        // only when the cloud returns paywall_quota_exceeded.
        isFixAll.addEventListener('click', function () {
            post({
                action: 'segurium_integrity_fix_all_preview',
                nonce: seguriumScan.nonce
            }).then(function (resp) {
                if (resp.success) {
                    showFixAllConfirmation(resp.data);
                    return;
                }
                if (isPaywallResponse(resp)) {
                    showPaywallModal(resp.data);
                }
            });
        });

        function fmtBytes(n) {
            n = Math.max(0, Number(n) || 0);
            var units = ['B', 'KB', 'MB', 'GB', 'TB'];
            var i = 0;
            while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
            var v = (n < 10 && i > 0) ? n.toFixed(1) : Math.round(n);
            return v + ' ' + units[i];
        }

        // SEGURIUM-279: render the bucket-eviction warning when the upcoming
        // batch would rotate out non-pinned envelopes. Returns '' for safe
        // runs (zero evictions or only pinned-skipped) so the modal stays
        // quiet when there's nothing to warn about.
        function renderBucketEvictionWarning(preview) {
            var be = preview.bucket_eviction;
            if (!be || (be.would_evict_count | 0) <= 0) {
                return '';
            }
            var body1 = (i18n.intFixAllEvictBody1 || 'You are about to fix %1$d files (~%2$s).')
                .replace('%1$d', String(be.files_count | 0))
                .replace('%2$s', fmtBytes(be.bytes_total));
            var body2 = (i18n.intFixAllEvictBody2 ||
                '%1$d older backups (~%2$s) will be rotated out — these are restore points for previously-fixed files.')
                .replace('%1$d', String(be.would_evict_count | 0))
                .replace('%2$s', fmtBytes(be.would_evict_bytes));
            var html = '<div class="segurium-fix-all-evict" data-evict="1" style="background:#fcf0c3;border-left:4px solid #dba617;padding:8px 12px;margin-bottom:12px;">';
            html += '<strong>' + escHtml(i18n.intFixAllEvictHeading || 'Older backups will be rotated out') + '</strong>';
            html += '<p style="margin:4px 0;">' + escHtml(body1) + '</p>';
            html += '<p style="margin:4px 0;">' + escHtml(body2) + '</p>';
            if ((be.would_evict_pinned_count | 0) > 0) {
                var pinned = (i18n.intFixAllEvictPinned ||
                    '%d pinned backups will be kept (still referenced by Restore).')
                    .replace('%d', String(be.would_evict_pinned_count | 0));
                html += '<p style="margin:4px 0;">' + escHtml(pinned) + '</p>';
            }
            html += '</div>';
            return html;
        }

        function showFixAllConfirmation(preview) {
            var html = '<div class="segurium-fix-all-preview">';

            html += renderBucketEvictionWarning(preview);

            if (preview.warnings.length > 0) {
                html += '<div style="background:#fcf0c3;border-left:4px solid #dba617;padding:8px 12px;margin-bottom:12px;">';
                html += '<strong>' + escHtml(i18n.warnings || 'Warnings') + '</strong><ul style="margin:4px 0 0 16px;">';
                preview.warnings.forEach(function (w) { html += '<li>' + escHtml(w) + '</li>'; });
                html += '</ul></div>';
            }

            if (preview.components_delete.length > 0) {
                html += '<h4 style="margin:12px 0 4px;">' + escHtml(i18n.componentsToDelete || 'Components to delete') +
                    ' (' + preview.components_delete.length + ')</h4><ul style="margin:0 0 8px 16px;font-size:12px;">';
                preview.components_delete.forEach(function (c) {
                    html += '<li>' + escHtml(c.type) + ': ' + escHtml(c.slug) + ' — ' + escHtml(c.reason) + '</li>';
                });
                html += '</ul>';
            }

            if (preview.files_replace.length > 0) {
                html += '<h4 style="margin:12px 0 4px;">' + escHtml(i18n.filesToReplace || 'Files to replace with originals') +
                    ' (' + preview.files_replace.length + ')</h4>';
                html += '<details><summary style="cursor:pointer;font-size:12px;">' + escHtml(i18n.showFiles || 'Show files') + '</summary>';
                html += '<ul style="margin:0 0 8px 16px;font-size:12px;">';
                preview.files_replace.forEach(function (f) {
                    html += '<li>' + escHtml(f.component) + ': ' + escHtml(f.path) + '</li>';
                });
                html += '</ul></details>';
            }

            if (preview.files_delete.length > 0) {
                html += '<h4 style="margin:12px 0 4px;">' + escHtml(i18n.filesToDelete || 'Files to delete') +
                    ' (' + preview.files_delete.length + ')</h4>';
                html += '<details><summary style="cursor:pointer;font-size:12px;">' + escHtml(i18n.showFiles || 'Show files') + '</summary>';
                html += '<ul style="margin:0 0 8px 16px;font-size:12px;">';
                preview.files_delete.forEach(function (f) {
                    html += '<li>' + escHtml(f.component) + ': ' + escHtml(f.path) + '</li>';
                });
                html += '</ul></details>';
            }

            if (preview.skipped.length > 0) {
                html += '<details><summary style="cursor:pointer;font-size:12px;margin-top:8px;">' +
                    escHtml(i18n.skippedItems || 'Skipped') + ' (' + preview.skipped.length + ')</summary>';
                html += '<ul style="margin:0 0 8px 16px;font-size:12px;">';
                preview.skipped.forEach(function (s) {
                    html += '<li>' + escHtml(s.slug || '') +
                        (s.path ? ': ' + escHtml(s.path) : '') +
                        ' — ' + escHtml(s.reason) + '</li>';
                });
                html += '</ul></details>';
            }

            var total = preview.summary.files_replace + preview.summary.files_delete + preview.summary.components_delete;
            if (total === 0) {
                html += '<p>' + escHtml(i18n.nothingToFix || 'Nothing to fix.') + '</p>';
            }

            html += '</div>';

            var modal   = el('segurium-confirm-modal');
            var title   = el('segurium-confirm-title');
            var content = el('segurium-confirm-content');
            var okBtn   = el('segurium-confirm-ok');
            var cancel  = el('segurium-confirm-cancel');
            var close   = el('segurium-confirm-close');

            title.textContent = i18n.intFixAllTitle || 'Fix All — Preview';
            content.innerHTML = html;
            okBtn.textContent = i18n.intFixAllConfirm || 'Apply all fixes';
            okBtn.disabled = (total === 0);
            modal.style.display = '';

            // SEGURIUM-279: when the run would evict non-pinned backups,
            // the default focus moves to Cancel so an Enter keypress doesn't
            // trigger an unintended bulk fix.
            var be = preview.bucket_eviction;
            if (be && (be.would_evict_count | 0) > 0 && total > 0) {
                try { cancel.focus(); } catch (e) { /* ignore */ }
            } else {
                try { okBtn.focus(); } catch (e) { /* ignore */ }
            }

            function closeModal() { modal.style.display = 'none'; }
            cancel.onclick = closeModal;
            close.onclick  = closeModal;
            modal.querySelector('.segurium-diff-overlay').onclick = closeModal;

            okBtn.onclick = function () {
                closeModal();
                executeFixAll(preview);
            };
        }

        function executeFixAll(preview) {
            var queue = [];
            var intNonce = seguriumScan.integrityNonce;

            // delete_component uses the segurium_scan nonce with type/slug fields.
            preview.components_delete.forEach(function (c) {
                queue.push({
                    action: 'segurium_integrity_delete_component',
                    nonce: seguriumScan.nonce,
                    data: { type: c.type, slug: c.slug }
                });
            });
            // fix_file uses the segurium_integrity nonce with comp_* field names.
            preview.files_replace.forEach(function (f) {
                queue.push({
                    action: 'segurium_integrity_fix_file',
                    nonce: intNonce,
                    data: {
                        comp_type: f.type,
                        comp_slug: f.component,
                        comp_version: f.version || '',
                        file_path: f.path,
                        sha256: f.sha256 || '',
                        verdict: 'modified'
                    }
                });
            });
            preview.files_delete.forEach(function (f) {
                queue.push({
                    action: 'segurium_integrity_fix_file',
                    nonce: intNonce,
                    data: {
                        comp_type: f.type,
                        comp_slug: f.component,
                        comp_version: f.version || '',
                        file_path: f.path,
                        sha256: f.sha256 || '',
                        verdict: 'new'
                    }
                });
            });

            if (queue.length === 0) return;

            var total = queue.length;
            var done = 0;
            var errors = [];
            var firstError = null;

            isFixAll.disabled = true;
            isBtn.disabled = true;
            isStatus.textContent = i18n.intFixAll || 'Applying fixes...';
            isProgress.style.display = '';
            isBar.style.width = '0%';
            if (isProgressLabel) isProgressLabel.textContent = '';

            function next(i) {
                if (i >= queue.length) {
                    isBar.style.width = '100%';
                    isBtn.disabled = false;
                    isFixAll.disabled = false;
                    setTimeout(function () { isProgress.style.display = 'none'; }, 400);
                    isStatus.textContent = errors.length > 0
                        ? (i18n.completedWithErrors || 'Completed with') + ' ' + errors.length + ' ' + (i18n.errors || 'errors')
                        : (i18n.scanComplete || 'Done.');
                    if (firstError) {
                        seguriumNoticeFromError(firstError, i18n.intFixFailed || 'Fix failed');
                    }
                    quotaCacheTs = 0;
                    fetchQuotaReadout();
                    loadIntegrityState();
                    return;
                }

                var item = queue[i];
                var pd = Object.assign({ nonce: item.nonce }, item.data);
                pd.action = item.action;

                post(pd).then(function (resp) {
                    done++;
                    isBar.style.width = Math.round(done / total * 100) + '%';
                    if (resp && resp.data && resp.data.quota) {
                        quotaCacheTs = Date.now();
                        renderQuotaReadout(resp.data.quota);
                    }
                    if (!resp.success) {
                        if (!firstError) firstError = resp.data || {};
                        errors.push((item.data.slug || item.data.path || item.data.file_path || '') + ': ' + (resp.data && resp.data.message || 'failed'));
                    }
                    next(i + 1);
                }).catch(function () {
                    done++;
                    errors.push((item.data.slug || item.data.path || item.data.file_path || '') + ': connection error');
                    next(i + 1);
                });
            }

            next(0);
        }

        // Load state on init
        loadIntegrityState();
    })();

    // ── Geo Blocking ──────────────────────────────────────────────────────────
    (function () {
        if (!el('segurium-feature-geo')) return;

        // COUNTRIES is hoisted to module scope (top of file) and reused across tabs.

        var REGIONS = {
            eu:           ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE',
                           'IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE'],
            americas:     ['US','CA','MX','BR','AR','CL','CO','PE','VE','EC','BO','UY','PY','GY',
                           'SR','BZ','GT','HN','SV','NI','CR','PA','CU','JM','HT','DO','TT','BB',
                           'LC','VC','GD','AG','DM','KN','AW','CW','SX','TC','KY','VG','VI','BM',
                           'GL','GP','MQ','GF','PM','FK'],
            asia_pacific: ['CN','JP','KR','IN','AU','NZ','PH','TH','VN','ID','MY','SG','PK','BD',
                           'LK','NP','MM','KH','LA','BN','TW','HK','MO','MN','KZ','UZ','TJ','TM',
                           'KG','AF'],
            africa:       ['ZA','NG','EG','KE','GH','TZ','ET','CI','SN','CM','MZ','UG','ZM','AO',
                           'ZW','MG','BF','ML','MR','NE','SL','LR','GW','GN','GM','TG','BJ','TD',
                           'CF','SS','SD','ER','DJ','SO','MW','BI','RW','MU','SC','CV','ST','KM',
                           'LS','SZ','NA','BW','GA','CG','CD','GQ'],
            middle_east:  ['SA','AE','IL','TR','IR','IQ','JO','LB','SY','KW','QA','BH','OM','YE','PS'],
            high_risk:    ['CN','RU','KP','IR','NG','PK','BD','VN','IN','ID','TH']
        };

        // ─ state
        var selectedCodes = [];
        var pendingToken  = null;
        var countdownTimer = null;
        var settingsLoaded = false;
        var baselineSettings = null; // last confirmed/loaded state for form reset on revert

        // ─ elements
        var enabledChk      = el('segurium-geo-enabled');
        var countryInput    = el('segurium-geo-country-input');
        var countryDropdown = el('segurium-geo-country-dropdown');
        var tagsContainer   = el('segurium-geo-tags');
        var countriesLabel  = el('segurium-geo-countries-label');
        var countriesDesc   = el('segurium-geo-countries-desc');
        var blockAction     = el('segurium-geo-block-action');
        var redirectRow     = el('segurium-geo-redirect-row');
        var redirectUrl     = el('segurium-geo-redirect-url');
        var pendingBanner   = el('segurium-geo-pending-banner');
        var countdownEl     = el('segurium-geo-countdown');
        var confirmBtn      = el('segurium-geo-confirm-btn');
        var revertBtn       = el('segurium-geo-revert-btn');
        var saveBtn         = el('segurium-geo-save-btn');
        var saveStatus      = el('segurium-geo-save-status');
        var statsSection    = el('segurium-geo-stats-section');
        var statsTbody      = el('segurium-geo-stats-tbody');
        var modeRadios      = document.querySelectorAll('input[name="segurium-geo-mode"]');
        var regionBtns      = document.querySelectorAll('.segurium-geo-region-btn');

        // ─ helpers

        function countryName(code) {
            for (var i = 0; i < COUNTRIES.length; i++) {
                if (COUNTRIES[i].code === code) return COUNTRIES[i].name;
            }
            return code;
        }

        function getMode() {
            for (var i = 0; i < modeRadios.length; i++) {
                if (modeRadios[i].checked) return modeRadios[i].value;
            }
            return 'block';
        }

        function updateModeLabels() {
            var mode = getMode();
            if ('allow' === mode) {
                countriesLabel.innerHTML = '<strong>' + escHtml(i18n.geoAllowedCountries || 'Allowed Countries') + '</strong>';
                countriesDesc.textContent = i18n.geoAllowedCountriesDesc || 'Type a country name or ISO code to add it to the allow list.';
            } else {
                countriesLabel.innerHTML = '<strong>' + escHtml(i18n.geoBlockedCountries || 'Blocked Countries') + '</strong>';
                countriesDesc.textContent = i18n.geoBlockedCountriesDesc || 'Type a country name or ISO code to add it to the block list.';
            }
            renderTags(); // also calls updateRegionButtonStates
        }

        function updateRegionButtonStates() {
            var mode = getMode();
            regionBtns.forEach(function (btn) {
                var region   = btn.getAttribute('data-region');
                var codes    = REGIONS[region] || [];
                var inList   = codes.filter(function (c) { return selectedCodes.indexOf(c) !== -1; }).length;
                var isActive = inList === codes.length;
                var isPartial = inList > 0 && !isActive;
                btn.classList.toggle('segurium-geo-region-btn--active', isActive);
                btn.classList.toggle('segurium-geo-region-btn--partial', isPartial);
                if ('allow' === mode) {
                    btn.title = isActive ? (i18n.geoAllowedCountries || 'Allowed') : '';
                } else {
                    btn.title = isActive ? (i18n.geoBlockedCountries || 'Blocked') : '';
                }
            });
        }

        // ─ country picker

        function renderTags() {
            var mode = getMode();
            tagsContainer.innerHTML = '';
            selectedCodes.forEach(function (code) {
                var tag = document.createElement('span');
                tag.className = 'segurium-geo-tag segurium-geo-tag--' + mode;
                var label = document.createTextNode(code + ' \u00b7 ' + countryName(code) + ' ');
                var btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'segurium-geo-tag-remove';
                btn.setAttribute('data-code', code);
                btn.innerHTML = '&times;';
                btn.addEventListener('click', function () { removeCountry(this.getAttribute('data-code')); });
                tag.appendChild(label);
                tag.appendChild(btn);
                tagsContainer.appendChild(tag);
            });
            updateRegionButtonStates();
        }

        function addCountry(code) {
            if (selectedCodes.indexOf(code) === -1) {
                selectedCodes.push(code);
                renderTags();
            }
            countryInput.value = '';
            countryDropdown.style.display = 'none';
        }

        function removeCountry(code) {
            selectedCodes = selectedCodes.filter(function (c) { return c !== code; });
            renderTags();
        }

        function showDropdown(query) {
            query = query.toLowerCase().trim();
            if (!query) { countryDropdown.style.display = 'none'; return; }

            var filtered = COUNTRIES.filter(function (c) {
                return (c.name.toLowerCase().indexOf(query) !== -1 ||
                        c.code.toLowerCase().indexOf(query) !== -1) &&
                       selectedCodes.indexOf(c.code) === -1;
            }).slice(0, 10);

            if (!filtered.length) { countryDropdown.style.display = 'none'; return; }

            countryDropdown.innerHTML = '';
            filtered.forEach(function (c) {
                var item = document.createElement('div');
                item.className = 'segurium-geo-dropdown-item';
                item.textContent = c.name + ' (' + c.code + ')';
                item.addEventListener('mousedown', function (e) { e.preventDefault(); addCountry(c.code); });
                countryDropdown.appendChild(item);
            });
            countryDropdown.style.display = '';
        }

        countryInput.addEventListener('input', function () { showDropdown(this.value); });
        countryInput.addEventListener('blur', function () {
            setTimeout(function () { countryDropdown.style.display = 'none'; }, 150);
        });
        countryInput.addEventListener('focus', function () { if (this.value) showDropdown(this.value); });

        regionBtns.forEach(function (btn) {
            btn.addEventListener('click', function () {
                var codes = REGIONS[this.getAttribute('data-region')] || [];
                var allPresent = codes.every(function (c) { return selectedCodes.indexOf(c) !== -1; });
                if (allPresent) {
                    selectedCodes = selectedCodes.filter(function (c) { return codes.indexOf(c) === -1; });
                } else {
                    codes.forEach(function (c) { if (selectedCodes.indexOf(c) === -1) selectedCodes.push(c); });
                }
                renderTags();
            });
        });

        modeRadios.forEach(function (radio) {
            radio.addEventListener('change', updateModeLabels);
        });

        // ─ enabled state

        function syncEnabledState() {
            var body = el('segurium-geo-settings-body');
            if (body) body.style.display = enabledChk.checked ? '' : 'none';
        }

        enabledChk.addEventListener('change', syncEnabledState);

        // ─ form

        function populateForm(d) {
            enabledChk.checked  = !!d.enabled;
            var mode = (d.block_mode === 'allow') ? 'allow' : 'block';
            modeRadios.forEach(function (r) { r.checked = (r.value === mode); });
            selectedCodes       = (d.blocked_countries || []).slice();
            updateModeLabels();
            blockAction.value   = d.block_action || 'deny_403';
            redirectUrl.value   = d.block_redirect_url || '';
            redirectRow.style.display = (d.block_action === 'redirect') ? '' : 'none';
            syncEnabledState();
        }

        function collectForm() {
            return {
                enabled:            enabledChk.checked,
                block_mode:         getMode(),
                blocked_countries:  selectedCodes.slice(),
                block_action:       blockAction.value,
                block_redirect_url: redirectUrl.value
            };
        }

        blockAction.addEventListener('change', function () {
            redirectRow.style.display = this.value === 'redirect' ? '' : 'none';
        });

        // ─ AJAX

        function postGeoSettings(settings) {
            var p = new URLSearchParams();
            p.append('action', 'segurium_save_geo_settings');
            p.append('nonce', seguriumScan.settingsNonce);
            p.append('settings[enabled]', settings.enabled ? '1' : '');
            p.append('settings[block_mode]', settings.block_mode || 'block');
            (settings.blocked_countries || []).forEach(function (cc) { p.append('settings[blocked_countries][]', cc); });
            p.append('settings[block_action]', settings.block_action || 'deny_403');
            p.append('settings[block_redirect_url]', settings.block_redirect_url || '');
            return fetch(seguriumScan.ajaxUrl, {
                method: 'POST', credentials: 'same-origin',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: p
            }).then(window.seguriumParseResponse);
        }

        function loadSettings() {
            post({action: 'segurium_get_geo_settings', nonce: seguriumScan.settingsNonce})
                .then(function (response) {
                    if (!response.success) return;
                    baselineSettings = response.data;
                    populateForm(response.data);
                });
        }

        function loadStats() {
            post({action: 'segurium_get_geo_stats', nonce: seguriumScan.settingsNonce})
                .then(function (response) {
                    if (!response.success) return;
                    var stats = response.data || {};
                    var keys  = Object.keys(stats);
                    statsSection.style.display = keys.length ? '' : 'none';
                    statsTbody.innerHTML = '';
                    keys.forEach(function (cc) {
                        var tr = document.createElement('tr');
                        tr.innerHTML = '<td>' + escHtml(cc + ' \u00b7 ' + countryName(cc)) + '</td>' +
                                       '<td>' + escHtml(String(stats[cc])) + '</td>';
                        statsTbody.appendChild(tr);
                    });
                });
        }

        // ─ pending changes countdown

        function stopCountdown() {
            if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
        }

        function startCountdown(seconds) {
            stopCountdown();
            pendingBanner.style.display = '';
            countdownEl.textContent = seconds;
            var remaining = seconds;
            countdownTimer = setInterval(function () {
                remaining--;
                countdownEl.textContent = remaining;
                if (remaining <= 0) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    pendingToken = null;
                    if (baselineSettings) populateForm(baselineSettings);
                    saveStatus.textContent = i18n.geoReverted || 'Changes reverted.';
                }
            }, 1000);
        }

        // ─ save

        saveBtn.addEventListener('click', function () {
            saveBtn.disabled = true;
            saveStatus.textContent = '';
            postGeoSettings(collectForm()).then(function (response) {
                saveBtn.disabled = false;
                if (!response.success) {
                    saveStatus.textContent = (response.data && response.data.message) || 'Error.';
                    return;
                }
                if (!response.data.token) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    pendingToken = null;
                    baselineSettings = collectForm();
                    saveStatus.textContent = '\u2713 ' + (i18n.geoConfirmed || 'Saved.');
                    return;
                }
                pendingToken = response.data.token;
                startCountdown(response.data.expires_in || 60);
            }).catch(function () {
                saveBtn.disabled = false;
                saveStatus.textContent = 'Error saving.';
            });
        });

        // ─ confirm / revert

        confirmBtn.addEventListener('click', function () {
            confirmBtn.disabled = true;
            post({action: 'segurium_confirm_pending', nonce: seguriumScan.settingsNonce, token: pendingToken})
                .then(function (response) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    confirmBtn.disabled = false;
                    if (response.success) {
                        baselineSettings = collectForm();
                        saveStatus.textContent = '\u2713 ' + (i18n.geoConfirmed || 'Saved permanently.');
                    } else {
                        saveStatus.textContent = (response.data && response.data.message) || 'Error.';
                    }
                    pendingToken = null;
                }).catch(function () { confirmBtn.disabled = false; });
        });

        revertBtn.addEventListener('click', function () {
            revertBtn.disabled = true;
            post({action: 'segurium_revert_pending', nonce: seguriumScan.settingsNonce, token: pendingToken})
                .then(function (response) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    revertBtn.disabled = false;
                    if (response.success) {
                        if (baselineSettings) populateForm(baselineSettings);
                        saveStatus.textContent = i18n.geoReverted || 'Changes reverted.';
                    }
                    pendingToken = null;
                }).catch(function () { revertBtn.disabled = false; });
        });

        // ─ lazy init on tab activation

        geoOnActivate = function () {
            if (settingsLoaded) return;
            settingsLoaded = true;
            loadSettings();
            loadStats();
            if (seguriumScan.geoPending && seguriumScan.geoPending.remaining > 0) {
                pendingToken = seguriumScan.geoPending.token;
                startCountdown(seguriumScan.geoPending.remaining);
            }
        };


    })();

    // ── Firewall panel ──────────────────────────────────────────────────────

    (function () {
        if (!el('segurium-feature-firewall')) return;

        var enabledChk    = el('segurium-fw-enabled');
        var ipListTa      = el('segurium-fw-ip-list');
        var ipListLabel   = el('segurium-fw-ip-list-label');
        var ipListDesc    = el('segurium-fw-ip-list-desc');
        var proxiesTa     = el('segurium-fw-proxies');
        var saveBtn       = el('segurium-fw-save-btn');
        var saveStatus    = el('segurium-fw-save-status');
        var pendingBanner = el('segurium-fw-pending-banner');
        var countdownEl   = el('segurium-fw-countdown');
        var confirmBtn    = el('segurium-fw-confirm-btn');
        var revertBtn     = el('segurium-fw-revert-btn');
        var modeRadios    = document.querySelectorAll('input[name="segurium-fw-mode"]');
        var loaded        = false;
        var pendingToken  = null;
        var countdownTimer   = null;
        var baselineSettings = null;

        function getMode() {
            var checked = document.querySelector('input[name="segurium-fw-mode"]:checked');
            return checked ? checked.value : 'deny_list';
        }

        function syncModeLabels() {
            if ('allow_list' === getMode()) {
                ipListLabel.innerHTML = '<strong>' + escHtml(i18n.fwAllowedIps || 'Allowed IPs / CIDRs') + '</strong>';
                ipListDesc.textContent = i18n.fwAllowedIpsDesc || 'Only these IPs can access the site. All others are blocked. One entry per line.';
            } else {
                ipListLabel.innerHTML = '<strong>' + escHtml(i18n.fwBlockedIps || 'Blocked IPs / CIDRs') + '</strong>';
                ipListDesc.textContent = i18n.fwBlockedIpsDesc || 'These IPs are always blocked. One entry per line. Accepts IPv4, IPv6, and CIDR ranges.';
            }
        }

        modeRadios.forEach(function (r) { r.addEventListener('change', syncModeLabels); });

        function syncEnabledState() {
            var body = el('segurium-fw-settings-body');
            if (body) body.style.display = enabledChk.checked ? '' : 'none';
        }

        enabledChk.addEventListener('change', syncEnabledState);

        function collectForm() {
            return {
                enabled:         enabledChk.checked,
                mode:            getMode(),
                ip_list:         ipListTa.value.split('\n').map(function (l) { return l.trim(); }).filter(Boolean),
                trusted_proxies: proxiesTa.value.split('\n').map(function (l) { return l.trim(); }).filter(Boolean)
            };
        }

        function populateForm(d) {
            enabledChk.checked = !!d.enabled;
            modeRadios.forEach(function (r) { r.checked = (r.value === (d.mode || 'deny_list')); });
            ipListTa.value   = (d.ip_list || []).join('\n');
            proxiesTa.value  = (d.trusted_proxies || []).join('\n');
            syncModeLabels();
            syncEnabledState();
        }

        function stopCountdown() {
            if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
        }

        function startCountdown(seconds) {
            stopCountdown();
            pendingBanner.style.display = '';
            countdownEl.textContent = seconds;
            var remaining = seconds;
            countdownTimer = setInterval(function () {
                remaining--;
                countdownEl.textContent = remaining;
                if (remaining <= 0) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    pendingToken = null;
                    if (baselineSettings) populateForm(baselineSettings);
                    saveStatus.textContent = i18n.geoReverted || 'Changes reverted.';
                }
            }, 1000);
        }

        function loadSettings() {
            post({action: 'segurium_get_firewall_settings', nonce: seguriumScan.settingsNonce})
                .then(function (r) {
                    if (!r.success) return;
                    baselineSettings = r.data;
                    populateForm(r.data);
                });
        }

        function postSettings(settings) {
            var p = new URLSearchParams();
            p.append('action', 'segurium_save_firewall_settings');
            p.append('nonce', seguriumScan.settingsNonce);
            p.append('settings[enabled]', settings.enabled ? '1' : '');
            p.append('settings[mode]', settings.mode);
            settings.ip_list.forEach(function (ip) { p.append('settings[ip_list][]', ip); });
            settings.trusted_proxies.forEach(function (ip) { p.append('settings[trusted_proxies][]', ip); });
            return fetch(seguriumScan.ajaxUrl, {
                method: 'POST', credentials: 'same-origin',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: p
            }).then(window.seguriumParseResponse);
        }

        saveBtn.addEventListener('click', function () {
            saveBtn.disabled = true;
            saveStatus.textContent = '';
            postSettings(collectForm()).then(function (r) {
                saveBtn.disabled = false;
                if (!r.success) {
                    saveStatus.textContent = (r.data && r.data.message) || 'Error.';
                    return;
                }
                if (!r.data.token) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    pendingToken = null;
                    baselineSettings = collectForm();
                    saveStatus.textContent = '\u2713 ' + (i18n.geoConfirmed || 'Saved.');
                    return;
                }
                pendingToken = r.data.token;
                startCountdown(r.data.expires_in || 60);
            }).catch(function () {
                saveBtn.disabled = false;
                saveStatus.textContent = 'Error.';
            });
        });

        confirmBtn.addEventListener('click', function () {
            confirmBtn.disabled = true;
            post({action: 'segurium_confirm_pending', nonce: seguriumScan.settingsNonce, token: pendingToken})
                .then(function (r) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    confirmBtn.disabled = false;
                    if (r.success) {
                        baselineSettings = collectForm();
                        saveStatus.textContent = '\u2713 ' + (i18n.geoConfirmed || 'Saved permanently.');
                    } else {
                        saveStatus.textContent = (r.data && r.data.message) || 'Error.';
                    }
                    pendingToken = null;
                }).catch(function () { confirmBtn.disabled = false; });
        });

        revertBtn.addEventListener('click', function () {
            revertBtn.disabled = true;
            post({action: 'segurium_revert_pending', nonce: seguriumScan.settingsNonce, token: pendingToken})
                .then(function (r) {
                    stopCountdown();
                    pendingBanner.style.display = 'none';
                    revertBtn.disabled = false;
                    if (r.success && baselineSettings) {
                        populateForm(baselineSettings);
                        saveStatus.textContent = i18n.geoReverted || 'Changes reverted.';
                    }
                    pendingToken = null;
                }).catch(function () { revertBtn.disabled = false; });
        });

        // ── Trusted proxies status ──

        var tpStatusText = el('segurium-tp-status-text');

        function tpRelativeTime(ts) {
            if (!ts) return { text: '\u2014', fresh: false };
            var diff = Math.floor(Date.now() / 1000) - ts;
            var hours = Math.floor(diff / 3600);
            if (hours < 24) return { text: i18n.tpToday || 'today', fresh: true };
            var days = Math.floor(hours / 24);
            if (days === 1) return { text: i18n.tpOneDayAgo || '1 day ago', fresh: false };
            return { text: days + ' ' + (i18n.tpDaysAgo || 'days ago'), fresh: false };
        }

        function renderTpStatus(d) {
            if (!tpStatusText) return;
            if (!d.exists) {
                tpStatusText.textContent = i18n.tpNotAvailable || 'Auto-proxy list not yet available \u2014 will be fetched shortly.';
                return;
            }
            var rel = tpRelativeTime(d.updated_at);
            var emoji = rel.fresh ? '\u2705 ' : '\u26a0\ufe0f ';
            tpStatusText.innerHTML = emoji + '<strong>' + escHtml(i18n.tpKnownProxies || 'Known CDNs, proxies') + ':</strong> '
                + '<strong>' + escHtml(String(d.total_cidrs || 0)) + '</strong> ' + escHtml(i18n.tpCidrs || 'CIDRs')
                + ' &mdash; ' + escHtml(i18n.tpUpdated || 'Updated') + ': ' + escHtml(rel.text)
                + ' <a href="#" id="segurium-tp-refresh">' + escHtml(i18n.tpRefresh || 'Refresh now') + '</a>';
            var refreshLink = el('segurium-tp-refresh');
            if (refreshLink) {
                refreshLink.addEventListener('click', function (e) {
                    e.preventDefault();
                    tpStatusText.textContent = i18n.tpRefreshing || 'Refreshing\u2026';
                    post({action: 'segurium_trigger_trusted_proxies_update', nonce: seguriumScan.settingsNonce})
                        .then(function (r) {
                            if (r.success) renderTpStatus(r.data);
                            else tpStatusText.textContent = (r.data && r.data.message) || 'Error';
                        })
                        .catch(function () { tpStatusText.textContent = 'Error'; });
                });
            }
        }

        function loadTpStatus() {
            post({action: 'segurium_get_trusted_proxies_status', nonce: seguriumScan.settingsNonce})
                .then(function (r) { if (r.success) renderTpStatus(r.data); });
        }

        firewallOnActivate = function () {
            if (loaded) return;
            loaded = true;
            loadSettings();
            loadTpStatus();
            if (seguriumScan.fwPending && seguriumScan.fwPending.remaining > 0) {
                pendingToken = seguriumScan.fwPending.token;
                startCountdown(seguriumScan.fwPending.remaining);
            }
        };

    })();

    // ── Brute-Force panel ───────────────────────────────────────────────────

    (function () {
        if (!el('segurium-feature-bruteforce')) return;

        var enabledChk        = el('segurium-bf-enabled');
        var maxAttempts       = el('segurium-bf-max-attempts');
        var countWindow       = el('segurium-bf-count-window');
        var tier1Duration     = el('segurium-bf-tier1-duration');
        var tier2Threshold    = el('segurium-bf-tier2-threshold');
        var tier2Duration     = el('segurium-bf-tier2-duration');
        var historyWindow     = el('segurium-bf-history-window');
        var protectXmlrpc     = el('segurium-bf-protect-xmlrpc');
        var honeypot          = el('segurium-bf-honeypot');
        var logRetention      = el('segurium-bf-log-retention');
        var hcaptchaEnabled   = el('segurium-bf-hcaptcha-enabled');
        var hcaptchaSiteKey   = el('segurium-bf-hcaptcha-site-key');
        var hcaptchaSecretKey = el('segurium-bf-hcaptcha-secret-key');
        var captchaThreshold  = el('segurium-bf-captcha-threshold');
        var hcaptchaBody      = el('segurium-bf-hcaptcha-body');
        var saveBtn           = el('segurium-bf-save-btn');
        var saveStatus        = el('segurium-bf-save-status');
        var lockoutsTbody     = el('segurium-bf-lockouts-tbody');
        var lockoutsEmpty     = el('segurium-bf-lockouts-empty');
        var settingsBody      = el('segurium-bf-settings-body');
        // Sections that should be hidden when the feature is disabled — same UX as
        // the firewall/geo tabs (only the enable checkbox + save button visible).
        var hiddenWhenOff     = [
            settingsBody,
            document.querySelector('#segurium-feature-bruteforce .segurium-bf-aside'),
            document.querySelector('#segurium-feature-bruteforce .segurium-bf-stats-section'),
            document.querySelector('#segurium-feature-bruteforce .segurium-bf-log-section')
        ];
        var statActive        = el('segurium-bf-stat-active');
        var statAttempts      = el('segurium-bf-stat-attempts');
        var statLockouts      = el('segurium-bf-stat-lockouts');
        var statHoneypot      = el('segurium-bf-stat-honeypot');
        var statCaptcha       = el('segurium-bf-stat-captcha');
        var topIpsTbody       = el('segurium-bf-top-ips-tbody');
        var topIpsEmpty       = el('segurium-bf-top-ips-empty');
        var topUsersTbody     = el('segurium-bf-top-users-tbody');
        var topUsersEmpty     = el('segurium-bf-top-users-empty');
        var logTbody          = el('segurium-bf-log-tbody');
        var logEmpty          = el('segurium-bf-log-empty');
        var logFilter         = el('segurium-bf-log-filter');
        var logPrev           = el('segurium-bf-log-prev');
        var logNext           = el('segurium-bf-log-next');
        var logPageInfo       = el('segurium-bf-log-pageinfo');

        var loaded         = false;
        var currentLogPage = 1;
        var LOG_PER_PAGE   = 25;

        // ── Recommended/Custom mode ────────────────────────────────────────
        // The Brute-Force tab opens with a two-option radio. In Recommended
        // mode the 9 fields below are locked and pinned to BF_RECOMMENDED;
        // in Custom mode they are editable and remembered per-browser via
        // localStorage. The hCaptcha section is unaffected by the radio.
        var BF_MODE = { RECOMMENDED: 'recommended', CUSTOM: 'custom' };

        // Single source of truth for the 9 lockable fields. snapshot/apply/lock
        // all iterate this — adding or removing a field touches one place.
        var BF_LOCKABLE_FIELDS = [
            { key: 'max_attempts',           node: maxAttempts,    type: 'number'   },
            { key: 'count_window',           node: countWindow,    type: 'number'   },
            { key: 'tier1_duration',         node: tier1Duration,  type: 'number'   },
            { key: 'tier2_threshold',        node: tier2Threshold, type: 'number'   },
            { key: 'tier2_duration',         node: tier2Duration,  type: 'number'   },
            { key: 'lockout_history_window', node: historyWindow,  type: 'number'   },
            { key: 'protect_xmlrpc',         node: protectXmlrpc,  type: 'checkbox' },
            { key: 'honeypot_enabled',       node: honeypot,       type: 'checkbox' },
            { key: 'log_retention_days',     node: logRetention,   type: 'number'   }
        ];

        // Mirrors Segurium_Brute_Force::default_settings() on the PHP side for
        // the 9 lockable fields. Keep both sides in sync — the JS does not
        // fetch these from PHP at runtime.
        var BF_RECOMMENDED = {
            max_attempts:           5,
            count_window:           1800,
            tier1_duration:         900,
            tier2_threshold:        3,
            tier2_duration:         86400,
            lockout_history_window: 604800,
            protect_xmlrpc:         true,
            honeypot_enabled:       true,
            log_retention_days:     30
        };
        var modeRadios    = document.querySelectorAll('#segurium-feature-bruteforce input[name="segurium-bf-mode"]');
        var lockedSection = el('segurium-bf-locked-section');
        var MEMORY_KEY    = 'segurium_bf_custom_memory_v1';
        var currentMode   = null;

        function readMemory() {
            try {
                var raw = window.localStorage.getItem(MEMORY_KEY);
                if (!raw) return null;
                var parsed = JSON.parse(raw);
                return (parsed && typeof parsed === 'object') ? parsed : null;
            } catch (e) { return null; }
        }
        function writeMemory(snapshot) {
            try { window.localStorage.setItem(MEMORY_KEY, JSON.stringify(snapshot)); }
            catch (e) { /* private mode / quota — silently ignore */ }
        }
        function snapshotLockableValues() {
            var snap = {};
            BF_LOCKABLE_FIELDS.forEach(function (f) {
                if (!f.node) return;
                snap[f.key] = (f.type === 'checkbox') ? !!f.node.checked : f.node.value;
            });
            return snap;
        }
        function applyLockableSnapshot(snap) {
            if (!snap) return;
            BF_LOCKABLE_FIELDS.forEach(function (f) {
                if (!f.node || !(f.key in snap)) return;
                if (f.type === 'checkbox') f.node.checked = !!snap[f.key];
                else f.node.value = snap[f.key];
            });
        }
        function setLocked(locked) {
            BF_LOCKABLE_FIELDS.forEach(function (f) { if (f.node) f.node.disabled = !!locked; });
            if (lockedSection) lockedSection.classList.toggle('segurium-bf-mode-locked', !!locked);
        }
        function applyMode(mode, opts) {
            opts = opts || {};
            var prevMode = currentMode;
            if (mode === BF_MODE.CUSTOM) {
                // Spec: "If this is 1st click and there were not saved values
                // - leave recommended values" — so a missing memory is a no-op.
                if (prevMode === BF_MODE.RECOMMENDED && !opts.fromInitialLoad) {
                    var mem = readMemory();
                    if (mem) applyLockableSnapshot(mem);
                }
                setLocked(false);
            } else {
                mode = BF_MODE.RECOMMENDED;
                if (prevMode === BF_MODE.CUSTOM && !opts.fromInitialLoad) {
                    writeMemory(snapshotLockableValues());
                }
                applyLockableSnapshot(BF_RECOMMENDED);
                setLocked(true);
            }
            currentMode = mode;
            modeRadios.forEach(function (r) { r.checked = (r.value === mode); });
        }

        modeRadios.forEach(function (r) {
            r.addEventListener('change', function () {
                if (r.checked) applyMode(r.value);
            });
        });

        function syncEnabledState() {
            var visible = enabledChk.checked;
            hiddenWhenOff.forEach(function (node) {
                if (node) node.style.display = visible ? '' : 'none';
            });
        }

        function syncHcaptchaState() {
            if (hcaptchaBody) hcaptchaBody.style.display = hcaptchaEnabled.checked ? '' : 'none';
        }

        enabledChk.addEventListener('change', syncEnabledState);
        hcaptchaEnabled.addEventListener('change', syncHcaptchaState);

        function populate(s) {
            enabledChk.checked        = !!s.enabled;
            maxAttempts.value         = s.max_attempts;
            countWindow.value         = s.count_window;
            tier1Duration.value       = s.tier1_duration;
            tier2Threshold.value      = s.tier2_threshold;
            tier2Duration.value       = s.tier2_duration;
            historyWindow.value       = s.lockout_history_window;
            protectXmlrpc.checked     = !!s.protect_xmlrpc;
            honeypot.checked          = !!s.honeypot_enabled;
            logRetention.value        = s.log_retention_days;
            hcaptchaEnabled.checked   = !!s.hcaptcha_enabled;
            hcaptchaSiteKey.value     = s.hcaptcha_site_key || '';
            // The server returns '__set__' as a marker when a secret is configured
            // (the plaintext is never shipped back). Leave the input blank but show
            // a placeholder so the admin knows a secret is on file.
            hcaptchaSecretKey.value       = '';
            hcaptchaSecretKey.placeholder = ('__set__' === s.hcaptcha_secret_key)
                ? '\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022 (set)'
                : '';
            captchaThreshold.value    = s.captcha_threshold;
            syncEnabledState();
            syncHcaptchaState();
            applyMode(s.settings_mode === BF_MODE.CUSTOM ? BF_MODE.CUSTOM : BF_MODE.RECOMMENDED, {fromInitialLoad: true});
        }

        function collect() {
            return {
                enabled:                enabledChk.checked ? '1' : '',
                max_attempts:           maxAttempts.value,
                count_window:           countWindow.value,
                tier1_duration:         tier1Duration.value,
                tier2_threshold:        tier2Threshold.value,
                tier2_duration:         tier2Duration.value,
                lockout_history_window: historyWindow.value,
                protect_xmlrpc:         protectXmlrpc.checked ? '1' : '',
                honeypot_enabled:       honeypot.checked ? '1' : '',
                log_retention_days:     logRetention.value,
                hcaptcha_enabled:       hcaptchaEnabled.checked ? '1' : '',
                hcaptcha_site_key:      hcaptchaSiteKey.value,
                hcaptcha_secret_key:    hcaptchaSecretKey.value,
                captcha_threshold:      captchaThreshold.value,
                settings_mode:          currentMode || BF_MODE.RECOMMENDED
            };
        }

        function loadSettings() {
            return post({action: 'segurium_get_bf_settings', nonce: seguriumScan.bfNonce})
                .then(function (r) { if (r.success) populate(r.data.settings); });
        }

        function loadLockouts() {
            return post({action: 'segurium_get_bf_lockouts', nonce: seguriumScan.bfNonce, page: 1, per_page: 50})
                .then(function (r) {
                    if (!r.success) return;
                    renderLockouts(r.data.rows || []);
                });
        }

        function renderLockouts(rows) {
            lockoutsTbody.innerHTML = '';
            if (!rows.length) {
                lockoutsEmpty.style.display = '';
                return;
            }
            lockoutsEmpty.style.display = 'none';
            rows.forEach(function (row) {
                var tr = document.createElement('tr');
                tr.innerHTML =
                    '<td><code>' + escHtml(row.ip_display) + '</code></td>' +
                    '<td>' + escHtml(String(row.tier)) + '</td>' +
                    '<td>' + escHtml(formatDate(parseInt(row.created_at, 10))) + '</td>' +
                    '<td>' + escHtml(formatDate(parseInt(row.expires_at, 10))) + '</td>' +
                    '<td><button class="button button-small segurium-bf-unlock-btn" data-ip="' + escHtml(row.ip_display) + '">' + escHtml(i18n.bfUnlock || 'Unlock') + '</button></td>';
                lockoutsTbody.appendChild(tr);
            });
            lockoutsTbody.querySelectorAll('.segurium-bf-unlock-btn').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    if (!window.confirm(i18n.bfUnlockConfirm || 'Unlock this IP?')) return;
                    btn.disabled = true;
                    post({action: 'segurium_unlock_bf_ip', nonce: seguriumScan.bfNonce, ip: btn.getAttribute('data-ip')})
                        .then(function () { loadLockouts(); })
                        .catch(function () { btn.disabled = false; });
                });
            });
        }

        function postSettings() {
            var s = collect();
            var p = new URLSearchParams();
            p.append('action', 'segurium_save_bf_settings');
            p.append('nonce', seguriumScan.bfNonce);
            Object.keys(s).forEach(function (k) { p.append('settings[' + k + ']', s[k]); });
            return fetch(seguriumScan.ajaxUrl, {
                method: 'POST', credentials: 'same-origin',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: p
            }).then(window.seguriumParseResponse);
        }

        saveBtn.addEventListener('click', function () {
            saveBtn.disabled = true;
            saveStatus.textContent = '';
            postSettings().then(function (r) {
                saveBtn.disabled = false;
                if (!r.success) {
                    saveStatus.textContent = (r.data && r.data.message) || 'Error.';
                    return;
                }
                if (r.data && r.data.settings) populate(r.data.settings);
                saveStatus.textContent = '\u2713 ' + (i18n.bfSettingsSaved || 'Settings saved.');
                loadLockouts();
                loadStats();
                loadLog(1);
            }).catch(function () {
                saveBtn.disabled = false;
                saveStatus.textContent = 'Error.';
            });
        });

        function loadStats() {
            return post({action: 'segurium_get_bf_stats', nonce: seguriumScan.bfNonce})
                .then(function (r) { if (r.success) renderStats(r.data); });
        }

        function renderStats(s) {
            statActive.textContent   = String(s.active_lockouts);
            statAttempts.textContent = String(s.attempts_24h);
            statLockouts.textContent = String(s.lockouts_24h);
            statHoneypot.textContent = String(s.honeypot_24h);
            statCaptcha.textContent  = String(s.captcha_fail_24h);
            renderTopList(topIpsTbody,   topIpsEmpty,   s.top_ips || [],       'ip');
            renderTopList(topUsersTbody, topUsersEmpty, s.top_usernames || [], 'username');
        }

        function renderTopList(tbody, emptyEl, rows, key) {
            tbody.innerHTML = '';
            if (!rows.length) {
                emptyEl.style.display = '';
                return;
            }
            emptyEl.style.display = 'none';
            rows.forEach(function (row) {
                var tr = document.createElement('tr');
                tr.innerHTML =
                    '<td><code>' + escHtml(row[key]) + '</code></td>' +
                    '<td>' + escHtml(String(row.count)) + '</td>';
                tbody.appendChild(tr);
            });
        }

        var EVENT_LABELS = {
            attempt:      i18n.bfEventAttempt,
            lockout:      i18n.bfEventLockout,
            honeypot:     i18n.bfEventHoneypot,
            unlock:       i18n.bfEventUnlock,
            captcha_fail: i18n.bfEventCaptchaFail
        };
        var SURFACE_LABELS = {
            'wp-login': i18n.bfSurfaceWpLogin,
            'xmlrpc':   i18n.bfSurfaceXmlrpc
        };

        function loadLog(page) {
            return post({
                action:   'segurium_get_bf_log',
                nonce:    seguriumScan.bfNonce,
                page:     page || 1,
                per_page: LOG_PER_PAGE,
                event:    logFilter.value
            }).then(function (r) {
                if (r.success) renderLog(r.data);
            });
        }

        function renderLog(data) {
            currentLogPage = data.page;
            logTbody.innerHTML = '';
            var rows = data.rows || [];
            if (!rows.length) {
                logEmpty.style.display = '';
                logPageInfo.textContent = '';
                logPrev.disabled = true;
                logNext.disabled = true;
                return;
            }
            logEmpty.style.display = 'none';
            rows.forEach(function (row) {
                var tr = document.createElement('tr');
                var eventLabel   = EVENT_LABELS[row.event] || row.event;
                var surfaceLabel = SURFACE_LABELS[row.surface] || row.surface;
                var tier         = (row.tier !== null && row.tier !== undefined) ? String(row.tier) : '';
                var countryCell  = '—';
                if (row.country) {
                    var flag = countryFlagEmoji(row.country);
                    var name = countryName(row.country) || row.country;
                    countryCell = (flag ? flag + ' ' : '') + escHtml(name);
                }
                tr.innerHTML =
                    '<td>' + escHtml(formatDate(row.created_at)) + '</td>' +
                    '<td>' + escHtml(eventLabel) + '</td>' +
                    '<td><code>' + escHtml(row.ip_display) + '</code></td>' +
                    '<td>' + countryCell + '</td>' +
                    '<td>' + escHtml(row.username) + '</td>' +
                    '<td>' + escHtml(surfaceLabel) + '</td>' +
                    '<td>' + escHtml(tier) + '</td>';
                logTbody.appendChild(tr);
            });
            var totalPages = Math.max(1, Math.ceil(data.total / data.per_page));
            logPageInfo.textContent = i18n.bfLogPage + ' ' + data.page + ' ' + i18n.bfLogOf + ' ' + totalPages;
            logPrev.disabled = (data.page <= 1);
            logNext.disabled = (data.page >= totalPages);
        }

        logFilter.addEventListener('change', function () { loadLog(1); });
        logPrev.addEventListener('click', function () { if (!logPrev.disabled) loadLog(currentLogPage - 1); });
        logNext.addEventListener('click', function () { if (!logNext.disabled) loadLog(currentLogPage + 1); });

        bruteforceOnActivate = function () {
            if (loaded) return;
            loaded = true;
            loadSettings()
                .then(loadLockouts)
                .then(loadStats)
                .then(function () { return loadLog(1); });
        };

    })();

    // ── Security Headers Tab ──

    (function () {
        var loaded = false;
        var i18n = (typeof seguriumScan !== 'undefined' && seguriumScan.i18n) || {};

        var enabledCb     = el('segurium-sh-enabled');
        var settingsBody  = el('segurium-sh-settings-body');
        var customFields  = el('segurium-sh-custom-fields');
        var previewEl     = el('segurium-sh-preview');
        var previewContent = el('segurium-sh-preview-content');
        var saveBtn       = el('segurium-sh-save-btn');
        var saveStatus    = el('segurium-sh-save-status');
        var cookieHardening = el('segurium-sh-cookie-hardening');
        var cookieFields    = el('segurium-sh-cookie-fields');
        var hstsEnabled     = el('segurium-sh-hsts-enabled');
        var hstsFields      = el('segurium-sh-hsts-fields');
        var hstsSubWarn     = el('segurium-sh-hsts-subdomain-warning');
        var cspEnabled      = el('segurium-sh-csp-enabled');
        var cspFields       = el('segurium-sh-csp-fields');
        var cspMode         = el('segurium-sh-csp-mode');
        var cspDirectives   = el('segurium-sh-csp-directives');
        var cspReportUri    = el('segurium-sh-csp-report-uri');

        if (!enabledCb) return;

        var serverInfo = { is_subdomain: false, is_ssl: false };

        function getSelectedMode() {
            var radios = document.querySelectorAll('input[name="segurium-sh-mode"]');
            for (var i = 0; i < radios.length; i++) {
                if (radios[i].checked) return radios[i].value;
            }
            return 'recommended';
        }

        function setSelectedMode(mode) {
            var radios = document.querySelectorAll('input[name="segurium-sh-mode"]');
            for (var i = 0; i < radios.length; i++) {
                radios[i].checked = radios[i].value === mode;
            }
            onModeChange();
        }

        function onModeChange() {
            var mode = getSelectedMode();
            if (customFields) customFields.style.display = mode === 'custom' ? '' : 'none';
            var hint = el('segurium-sh-preset-hint');
            if (hint) hint.style.display = (mode === 'basic' || mode === 'recommended' || mode === 'strict') ? '' : 'none';
            updatePreview(mode);
        }

        function updatePreview(mode) {
            if (!previewEl || !previewContent) return;
            var lines = [];
            if (mode === 'off') {
                lines.push('(no headers)');
            } else {
                lines.push('X-Content-Type-Options: nosniff');
                lines.push('X-Frame-Options: ' + (el('segurium-sh-x-frame') ? el('segurium-sh-x-frame').value : 'SAMEORIGIN'));
                lines.push('X-XSS-Protection: ' + (el('segurium-sh-xss') ? el('segurium-sh-xss').value : '0'));
            }
            if (mode === 'recommended' || mode === 'strict' || mode === 'custom') {
                lines.push('Referrer-Policy: ' + (el('segurium-sh-referrer') ? el('segurium-sh-referrer').value : 'strict-origin-when-cross-origin'));
                lines.push('Permissions-Policy: (per feature settings)');
                if (serverInfo.is_ssl) {
                    lines.push('Strict-Transport-Security: max-age=...');
                }
            }
            if (mode === 'strict' || mode === 'custom') {
                lines.push('Cross-Origin-Opener-Policy: ' + (el('segurium-sh-coop') ? el('segurium-sh-coop').value || '(not set)' : 'same-origin'));
                lines.push('Cross-Origin-Resource-Policy: ' + (el('segurium-sh-corp') ? el('segurium-sh-corp').value || '(not set)' : 'same-origin'));
                lines.push('X-DNS-Prefetch-Control: off');
                lines.push('Cache-Control: no-store (admin pages only)');
            }
            if (cspEnabled && cspEnabled.checked) {
                var cspName = (cspMode && cspMode.value === 'enforce')
                    ? 'Content-Security-Policy'
                    : 'Content-Security-Policy-Report-Only';
                var cspVal = cspDirectives ? (cspDirectives.value || '').trim() : '';
                if (cspVal) {
                    var ru = cspReportUri ? (cspReportUri.value || '').trim() : '';
                    if (ru && cspVal.toLowerCase().indexOf('report-uri') === -1) {
                        cspVal = cspVal.replace(/[;\s]+$/, '') + '; report-uri ' + ru;
                    }
                    lines.push(cspName + ': ' + cspVal);
                }
            }
            previewContent.textContent = lines.join('\n');
            previewEl.style.display = (!enabledCb.checked || (mode === 'off' && (!cspEnabled || !cspEnabled.checked))) ? 'none' : '';
        }

        function populateForm(data) {
            var s = data.settings || {};
            var c = s.custom || {};
            var pp = c.permissions_policy || {};

            enabledCb.checked = !!s.enabled;
            settingsBody.style.display = s.enabled ? '' : 'none';
            setSelectedMode(s.mode || 'off');

            if (el('segurium-sh-x-frame')) el('segurium-sh-x-frame').value = c.x_frame_options || 'SAMEORIGIN';
            if (el('segurium-sh-referrer')) el('segurium-sh-referrer').value = c.referrer_policy || 'strict-origin-when-cross-origin';
            if (el('segurium-sh-xss')) el('segurium-sh-xss').value = c.x_xss_protection || '0';

            if (hstsEnabled) hstsEnabled.checked = c.hsts_enabled !== false;
            if (el('segurium-sh-hsts-max-age')) el('segurium-sh-hsts-max-age').value = c.hsts_max_age || 31536000;
            if (el('segurium-sh-hsts-subdomains')) el('segurium-sh-hsts-subdomains').checked = c.hsts_include_subdomains !== false;
            if (el('segurium-sh-hsts-preload')) el('segurium-sh-hsts-preload').checked = !!c.hsts_preload;

            if (el('segurium-sh-coop')) el('segurium-sh-coop').value = c.coop || '';
            if (el('segurium-sh-corp')) el('segurium-sh-corp').value = c.corp || '';
            if (el('segurium-sh-coep')) el('segurium-sh-coep').value = c.coep || '';

            document.querySelectorAll('[data-pp-feature]').forEach(function (sel) {
                var feat = sel.getAttribute('data-pp-feature');
                sel.value = pp[feat] || 'none';
            });

            if (cookieHardening) cookieHardening.checked = s.cookie_hardening !== false;
            if (el('segurium-sh-cookie-samesite')) el('segurium-sh-cookie-samesite').value = s.cookie_samesite || 'Lax';
            if (cookieFields) cookieFields.style.display = cookieHardening && cookieHardening.checked ? '' : 'none';

            if (cspEnabled) cspEnabled.checked = !!s.csp_enabled;
            if (cspMode) cspMode.value = s.csp_mode || 'report-only';
            if (cspDirectives) cspDirectives.value = s.csp_directives || '';
            if (cspReportUri) cspReportUri.value = s.csp_report_uri || '';
            if (cspFields) cspFields.style.display = cspEnabled && cspEnabled.checked ? '' : 'none';

            serverInfo = { is_subdomain: !!data.is_subdomain, is_ssl: !!data.is_ssl };
            if (hstsSubWarn) hstsSubWarn.style.display = serverInfo.is_subdomain ? '' : 'none';

            onModeChange();
        }

        function collectForm() {
            var pp = {};
            document.querySelectorAll('[data-pp-feature]').forEach(function (sel) {
                pp[sel.getAttribute('data-pp-feature')] = sel.value;
            });

            return {
                enabled: enabledCb.checked ? '1' : '',
                mode: getSelectedMode(),
                custom: {
                    x_content_type_options: 'nosniff',
                    x_frame_options: el('segurium-sh-x-frame') ? el('segurium-sh-x-frame').value : 'SAMEORIGIN',
                    x_xss_protection: el('segurium-sh-xss') ? el('segurium-sh-xss').value : '0',
                    referrer_policy: el('segurium-sh-referrer') ? el('segurium-sh-referrer').value : 'strict-origin-when-cross-origin',
                    hsts_enabled: hstsEnabled && hstsEnabled.checked ? '1' : '',
                    hsts_max_age: el('segurium-sh-hsts-max-age') ? el('segurium-sh-hsts-max-age').value : '31536000',
                    hsts_include_subdomains: el('segurium-sh-hsts-subdomains') && el('segurium-sh-hsts-subdomains').checked ? '1' : '',
                    hsts_preload: el('segurium-sh-hsts-preload') && el('segurium-sh-hsts-preload').checked ? '1' : '',
                    coop: el('segurium-sh-coop') ? el('segurium-sh-coop').value : '',
                    corp: el('segurium-sh-corp') ? el('segurium-sh-corp').value : '',
                    coep: el('segurium-sh-coep') ? el('segurium-sh-coep').value : '',
                    x_dns_prefetch_control: 'off',
                    cache_control_admin: '1',
                    permissions_policy: pp
                },
                cookie_hardening: cookieHardening && cookieHardening.checked ? '1' : '',
                cookie_samesite: el('segurium-sh-cookie-samesite') ? el('segurium-sh-cookie-samesite').value : 'Lax',
                csp_enabled: cspEnabled && cspEnabled.checked ? '1' : '',
                csp_mode: cspMode ? cspMode.value : 'report-only',
                csp_directives: cspDirectives ? cspDirectives.value : '',
                csp_report_uri: cspReportUri ? cspReportUri.value : ''
            };
        }

        function loadSettings() {
            return post({ action: 'segurium_get_sh_settings', nonce: seguriumScan.settingsNonce })
                .then(function (r) {
                    if (!r.success) return;
                    populateForm(r.data);
                });
        }

        function postSettings(settings) {
            var p = new URLSearchParams();
            p.append('action', 'segurium_save_sh_settings');
            p.append('nonce', seguriumScan.settingsNonce);
            p.append('settings[enabled]', settings.enabled);
            p.append('settings[mode]', settings.mode);
            p.append('settings[cookie_hardening]', settings.cookie_hardening);
            p.append('settings[cookie_samesite]', settings.cookie_samesite);
            p.append('settings[csp_enabled]', settings.csp_enabled);
            p.append('settings[csp_mode]', settings.csp_mode);
            p.append('settings[csp_directives]', settings.csp_directives);
            p.append('settings[csp_report_uri]', settings.csp_report_uri);

            var c = settings.custom;
            Object.keys(c).forEach(function (k) {
                if (k === 'permissions_policy') {
                    Object.keys(c.permissions_policy).forEach(function (feat) {
                        p.append('settings[custom][permissions_policy][' + feat + ']', c.permissions_policy[feat]);
                    });
                } else {
                    p.append('settings[custom][' + k + ']', c[k]);
                }
            });

            return fetch(seguriumScan.ajaxUrl, {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: p
            }).then(window.seguriumParseResponse);
        }

        enabledCb.addEventListener('change', function () {
            settingsBody.style.display = enabledCb.checked ? '' : 'none';
            if (previewEl) previewEl.style.display = enabledCb.checked && getSelectedMode() !== 'off' ? '' : 'none';
        });

        document.querySelectorAll('input[name="segurium-sh-mode"]').forEach(function (radio) {
            radio.addEventListener('change', onModeChange);
        });

        if (cookieHardening) {
            cookieHardening.addEventListener('change', function () {
                if (cookieFields) cookieFields.style.display = cookieHardening.checked ? '' : 'none';
            });
        }

        if (hstsEnabled) {
            hstsEnabled.addEventListener('change', function () {
                if (hstsFields) hstsFields.style.display = hstsEnabled.checked ? '' : 'none';
            });
        }

        if (cspEnabled) {
            cspEnabled.addEventListener('change', function () {
                if (cspFields) cspFields.style.display = cspEnabled.checked ? '' : 'none';
                onModeChange();
            });
        }
        if (cspMode) cspMode.addEventListener('change', onModeChange);
        if (cspDirectives) cspDirectives.addEventListener('input', onModeChange);
        if (cspReportUri) cspReportUri.addEventListener('input', onModeChange);

        if (saveBtn) {
            saveBtn.addEventListener('click', function () {
                saveBtn.disabled = true;
                saveStatus.textContent = '';
                postSettings(collectForm()).then(function (r) {
                    saveBtn.disabled = false;
                    if (!r.success) {
                        saveStatus.textContent = (r.data && r.data.message) || 'Error.';
                        return;
                    }
                    saveStatus.textContent = '\u2713 ' + (i18n.settingsSaved || 'Saved.');
                }).catch(function () {
                    saveBtn.disabled = false;
                    saveStatus.textContent = 'Error.';
                });
            });
        }

        headersOnActivate = function () {
            if (loaded) return;
            loaded = true;
            loadSettings();
        };

    })();

    // ── Information Shield tab ──
    (function () {
        var panel = el('segurium-feature-info-shield');
        if (!panel) return;
        var loaded = false;
        var i18n = seguriumScan.i18n || {};

        var enabledCb = el('segurium-is-enabled');
        var settingsBody = el('segurium-is-settings-body');
        var saveBtn = el('segurium-is-save-btn');
        var saveStatus = el('segurium-is-save-status');
        var enableAllBtn = el('segurium-is-enable-all');
        var enableAllStatus = el('segurium-is-enable-all-status');

        // SEGURIUM-397: Info Shield rows now use the shared `.segurium-setting-row`
        // class. The `[data-key]` filter scopes the query to the per-toggle rows
        // (only Info Shield's rows carry data-key inside this panel).
        var toggleRows = panel.querySelectorAll('.segurium-setting-row[data-key]');
        var defaults = {};

        function post(params) {
            return fetch(seguriumScan.ajaxUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(params)
            }).then(window.seguriumParseResponse);
        }

        function getToggle(key) {
            var row = panel.querySelector('[data-key="' + key + '"]');
            return row ? row.querySelector('.segurium-is-toggle') : null;
        }

        function applyMasterState() {
            var on = enabledCb && enabledCb.checked;
            if (settingsBody) settingsBody.style.display = on ? '' : 'none';
        }

        function showWarning(key, message) {
            var target = panel.querySelector('[data-warning="' + key + '"]');
            if (!target) return;
            if (message) {
                target.textContent = message;
                target.style.display = '';
            } else {
                target.textContent = '';
                target.style.display = 'none';
            }
        }

        function updateWarnings(env, conflicts) {
            env = env || {};
            conflicts = conflicts || {};
            showWarning('server_header', env.server_header_note || '');
            showWarning('x_powered_by', env.x_powered_by_note || '');
            showWarning('jetpack_xmlrpc', conflicts.jetpack_xmlrpc || '');
        }

        function populateForm(data) {
            var settings = data.settings || {};
            defaults = data.defaults || {};
            if (enabledCb) enabledCb.checked = !!settings.enabled;
            toggleRows.forEach(function (row) {
                var key = row.getAttribute('data-key');
                var cb = row.querySelector('.segurium-is-toggle');
                if (cb && key) cb.checked = !!settings[key];
            });
            applyMasterState();
            updateWarnings(data.environment, data.conflicts);
        }

        function collectForm() {
            var out = { enabled: enabledCb && enabledCb.checked ? '1' : '' };
            toggleRows.forEach(function (row) {
                var key = row.getAttribute('data-key');
                var cb = row.querySelector('.segurium-is-toggle');
                if (key && cb) out[key] = cb.checked ? '1' : '';
            });
            return out;
        }

        function loadSettings() {
            if (saveStatus) saveStatus.textContent = i18n.isLoading || '';
            return post({ action: 'segurium_get_info_shield_settings', nonce: seguriumScan.settingsNonce })
                .then(function (r) {
                    if (saveStatus) saveStatus.textContent = '';
                    if (!r.success) {
                        if (saveStatus) saveStatus.textContent = (r.data && r.data.message) || (i18n.isLoadError || 'Error.');
                        return;
                    }
                    populateForm(r.data || {});
                })
                .catch(function () {
                    if (saveStatus) saveStatus.textContent = i18n.isLoadError || 'Error.';
                });
        }

        function saveSettings() {
            var settings = collectForm();
            var params = { action: 'segurium_save_info_shield_settings', nonce: seguriumScan.settingsNonce };
            Object.keys(settings).forEach(function (k) {
                params['settings[' + k + ']'] = settings[k];
            });
            if (saveBtn) saveBtn.disabled = true;
            if (saveStatus) saveStatus.textContent = i18n.isSaving || '';
            return post(params)
                .then(function (r) {
                    if (saveBtn) saveBtn.disabled = false;
                    if (!r.success) {
                        if (saveStatus) saveStatus.textContent = (r.data && r.data.message) || (i18n.isSaveError || 'Error.');
                        return;
                    }
                    if (saveStatus) saveStatus.textContent = '\u2713 ' + (i18n.isSaved || 'Saved.');
                })
                .catch(function () {
                    if (saveBtn) saveBtn.disabled = false;
                    if (saveStatus) saveStatus.textContent = i18n.isSaveError || 'Error.';
                });
        }

        function enableAllRecommended() {
            if (enabledCb) enabledCb.checked = true;
            toggleRows.forEach(function (row) {
                var key = row.getAttribute('data-key');
                var cb = row.querySelector('.segurium-is-toggle');
                if (cb && key && Object.prototype.hasOwnProperty.call(defaults, key)) {
                    cb.checked = !!defaults[key];
                }
            });
            applyMasterState();
            if (enableAllStatus) {
                enableAllStatus.textContent = i18n.isEnableAllDone || '';
                setTimeout(function () { if (enableAllStatus) enableAllStatus.textContent = ''; }, 3000);
            }
        }

        if (enabledCb) enabledCb.addEventListener('change', applyMasterState);
        if (saveBtn) saveBtn.addEventListener('click', saveSettings);
        if (enableAllBtn) enableAllBtn.addEventListener('click', enableAllRecommended);

        infoShieldOnActivate = function () {
            if (loaded) return;
            loaded = true;
            loadSettings();
        };

    })();

    // ── Two-Factor Authentication tab ──
    (function () {
        var loaded = false;

        function post(params) {
            var body = new URLSearchParams(params);
            return fetch(seguriumScan.ajaxUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body,
            }).then(window.seguriumParseResponse);
        }

        function loadSettings() {
            return post({
                action: 'segurium_get_2fa_settings',
                nonce: seguriumScan.tfaNonce,
            }).then(function (r) {
                if (!r.success) return;
                var s = r.data.settings;
                var el = document.getElementById('sgm-2fa-enabled');
                if (el) el.checked = !!s.enabled;

                // Methods.
                var totp = document.getElementById('sgm-2fa-method-totp');
                var email = document.getElementById('sgm-2fa-method-email');
                if (totp) totp.checked = (s.available_methods || []).indexOf('totp') !== -1;
                if (email) email.checked = (s.available_methods || []).indexOf('email') !== -1;

                // Enforced roles: build checkboxes from AJAX response.
                var rolesContainer = document.getElementById('sgm-2fa-roles');
                var roles = r.data.roles || {};
                var enforced = s.enforced_roles || [];
                if (rolesContainer) {
                    var rolesHtml = '';
                    Object.keys(roles).forEach(function (slug) {
                        var checked = enforced.indexOf(slug) !== -1 ? ' checked' : '';
                        rolesHtml += '<label style="display:block;margin-top:4px;"><input type="checkbox" class="sgm-2fa-role" value="' + slug + '"' + checked + '> ' + roles[slug] + '</label>';
                    });
                    rolesContainer.innerHTML = rolesHtml;
                }

                // Numbers.
                var grace = document.getElementById('sgm-2fa-grace');
                if (grace) grace.value = s.grace_period_days != null ? s.grace_period_days : 3;
                var trusted = document.getElementById('sgm-2fa-trusted-days');
                if (trusted) trusted.value = s.trusted_device_days != null ? s.trusted_device_days : 30;

                toggleOptions(!!s.enabled);
            });
        }

        function toggleOptions(show) {
            var opts = document.getElementById('sgm-2fa-options');
            if (opts) opts.style.display = show ? '' : 'none';
        }

        function collectSettings() {
            var methods = [];
            var totp = document.getElementById('sgm-2fa-method-totp');
            var email = document.getElementById('sgm-2fa-method-email');
            if (totp && totp.checked) methods.push('totp');
            if (email && email.checked) methods.push('email');

            var roles = [];
            document.querySelectorAll('.sgm-2fa-role').forEach(function (cb) {
                if (cb.checked) roles.push(cb.value);
            });

            var grace = document.getElementById('sgm-2fa-grace');
            var trusted = document.getElementById('sgm-2fa-trusted-days');

            return {
                enabled: document.getElementById('sgm-2fa-enabled').checked ? '1' : '',
                available_methods: methods,
                enforced_roles: roles,
                grace_period_days: grace ? grace.value : '3',
                trusted_device_days: trusted ? trusted.value : '30',
            };
        }

        function saveSettings() {
            var s = collectSettings();
            var p = new URLSearchParams();
            p.append('action', 'segurium_save_2fa_settings');
            p.append('nonce', seguriumScan.tfaNonce);

            Object.keys(s).forEach(function (k) {
                var v = s[k];
                if (Array.isArray(v)) {
                    v.forEach(function (item) { p.append('settings[' + k + '][]', item); });
                } else {
                    p.append('settings[' + k + ']', v);
                }
            });

            return fetch(seguriumScan.ajaxUrl, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: p,
            }).then(window.seguriumParseResponse);
        }

        function loadUserStats() {
            return post({
                action: 'segurium_get_2fa_user_stats',
                nonce: seguriumScan.tfaNonce,
            }).then(function (r) {
                if (!r.success) return;
                var tbody = document.querySelector('#sgm-2fa-user-stats tbody');
                if (!tbody) return;
                var stats = r.data.stats;
                var html = '';
                html += '<tr><td>Authenticator App (TOTP)</td><td>' + (stats.totp || 0) + '</td></tr>';
                html += '<tr><td>Email Verification</td><td>' + (stats.email || 0) + '</td></tr>';
                html += '<tr><td><strong>Total</strong></td><td><strong>' + ((stats.totp || 0) + (stats.email || 0)) + '</strong></td></tr>';
                tbody.innerHTML = html;
            });
        }

        // Enable toggle.
        var enableCb = document.getElementById('sgm-2fa-enabled');
        if (enableCb) {
            enableCb.addEventListener('change', function () {
                toggleOptions(this.checked);
            });
        }

        // Save button.
        var saveBtn = document.getElementById('sgm-2fa-save');
        if (saveBtn) {
            saveBtn.addEventListener('click', function () {
                var status = document.getElementById('sgm-2fa-save-status');
                saveBtn.disabled = true;
                saveSettings().then(function (r) {
                    saveBtn.disabled = false;
                    if (status) {
                        status.style.display = '';
                        status.textContent = r.success ? 'Saved.' : 'Error.';
                        status.style.color = r.success ? '#00a32a' : '#d63638';
                        setTimeout(function () { status.style.display = 'none'; }, 3000);
                    }
                }).catch(function () {
                    saveBtn.disabled = false;
                    if (status) {
                        status.style.display = '';
                        status.textContent = 'Error.';
                        status.style.color = '#d63638';
                    }
                });
            });
        }

        // Reset user button.
        var resetBtn = document.getElementById('sgm-2fa-reset-btn');
        if (resetBtn) {
            resetBtn.addEventListener('click', function () {
                var input = document.getElementById('sgm-2fa-reset-user');
                var status = document.getElementById('sgm-2fa-reset-status');
                var val = input ? input.value.trim() : '';
                if (!val) return;

                resetBtn.disabled = true;
                post({
                    action: 'segurium_admin_reset_user_2fa',
                    nonce: seguriumScan.tfaNonce,
                    user: val,
                }).then(function (r) {
                    resetBtn.disabled = false;
                    if (status) {
                        status.style.display = '';
                        status.textContent = r.data && r.data.message ? r.data.message : (r.success ? 'Done.' : 'Error.');
                        status.style.color = r.success ? '#00a32a' : '#d63638';
                        setTimeout(function () { status.style.display = 'none'; }, 4000);
                    }
                    if (r.success) {
                        if (input) input.value = '';
                        loadUserStats();
                    }
                });
            });
        }

        twoFactorOnActivate = function () {
            if (loaded) return;
            loaded = true;
            loadSettings().then(loadUserStats);
        };

    })();

    // SEGURIUM-248: hydrate every settings panel up-front so switching tabs
    // does not block on a per-tab AJAX round-trip. Each *OnActivate hook is
    // already idempotent (gated on its own `loaded` / `settingsLoaded`
    // flag), so calling them all here is equivalent to the user clicking
    // each tab once — only the active tab is visible, but all settings are
    // populated when their tab gets shown.
    (function preloadAllPanels() {
        try { geoOnActivate(); } catch (e) {}
        try { firewallOnActivate(); } catch (e) {}
        try { bruteforceOnActivate(); } catch (e) {}
        try { headersOnActivate(); } catch (e) {}
        try { infoShieldOnActivate(); } catch (e) {}
        try { twoFactorOnActivate(); } catch (e) {}
    })();

    // SEGURIUM-248: surface host-environment warnings (short
    // max_execution_time, disabled WP-Cron) into both scanner panels so
    // the user gets a banner instead of a stuck progress bar.
    (function renderEnvWarnings() {
        var warnings = (seguriumScan && seguriumScan.envWarnings) || [];
        if (!warnings.length) return;
        var nodes = document.querySelectorAll('.segurium-env-warnings');
        if (!nodes.length) return;
        var title = i18n.envWarningsTitle || 'Hosting environment warnings';
        var listHtml = warnings.map(function (msg) {
            return '<li>' + escHtml(msg) + '</li>';
        }).join('');
        var html = '<p><strong>' + escHtml(title) + '</strong></p><ul>' + listHtml + '</ul>';
        nodes.forEach(function (n) {
            n.innerHTML = html;
            n.hidden = false;
        });
    })();
})();

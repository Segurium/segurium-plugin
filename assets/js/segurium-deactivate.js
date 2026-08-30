/**
 * Exit-reason dialog on the plugins screen.
 *
 * The Deactivate link keeps working no matter what happens here. Every
 * path out of the dialog either navigates to the original URL or leaves
 * the user exactly where they were:
 *
 *   Continue → report, then navigate once the request settles
 *   Skip     → navigate at once, nothing reported
 *   × / Esc / overlay → cancel, stay on the plugins screen
 *
 * A report that hangs must not trap the user, so the navigation is also
 * armed on a watchdog. Whichever fires first wins. Cancelling disarms
 * both, including a report still in flight.
 */
(function () {
    'use strict';

    var cfg = window.seguriumDeactivate;
    if (!cfg || !cfg.ajaxUrl || !cfg.nonce || !cfg.basename) return;

    // Without the envelope client there is no way to report, and an
    // intercepted link with no way forward would strand the user on a
    // dialog whose Continue does nothing. Leave the link alone instead.
    if (typeof window.seguriumFetchJson !== 'function') return;

    var modal = document.getElementById('segurium-deact-modal');
    if (!modal) return;

    var REPORT_TIMEOUT = 3000;

    var link = findDeactivateLink(cfg.basename);
    if (!link) return;

    var submitBtn = document.getElementById('segurium-deact-submit');
    var skipBtn = document.getElementById('segurium-deact-skip');
    var detail = document.getElementById('segurium-deact-detail');
    var target = '';
    var leaving = false;
    var watchdog = 0;
    var attempt = 0;

    /**
     * The row action for our own plugin, matched on the `plugin` query
     * parameter rather than on the generated element id. WordPress builds
     * that id from the translated plugin name, so it differs per locale.
     */
    function findDeactivateLink(basename) {
        var links = document.querySelectorAll('a[href*="action=deactivate"]');
        for (var i = 0; i < links.length; i++) {
            var params;
            try {
                params = new URL(links[i].href, window.location.origin).searchParams;
            } catch (err) {
                continue;
            }
            if (params.get('plugin') === basename) return links[i];
        }
        return null;
    }

    function open() {
        modal.style.display = '';
        var first = modal.querySelector('input[name="segurium_deact_reason"]');
        if (first) first.focus();
        document.addEventListener('keydown', onKeydown);
    }

    function cancel() {
        // Disarm first. Cancelling after Continue, while the report is
        // still in flight, must not let the watchdog carry the user out
        // of a deactivation they just changed their mind about.
        window.clearTimeout(watchdog);
        attempt++;
        target = '';
        modal.style.display = 'none';
        submitBtn.disabled = !selectedReason();
        skipBtn.disabled = false;
        document.removeEventListener('keydown', onKeydown);
    }

    function leave() {
        if (leaving || !target) return;
        leaving = true;
        window.location.href = target;
    }

    function onKeydown(event) {
        if (event.key === 'Escape') cancel();
    }

    function selectedReason() {
        var picked = modal.querySelector('input[name="segurium_deact_reason"]:checked');
        return picked ? picked.value : '';
    }

    function report(reason) {
        return window.seguriumFetchJson(cfg.ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                action: cfg.action,
                nonce: cfg.nonce,
                reason: reason,
                detail: detail ? detail.value : ''
            })
        });
    }

    link.addEventListener('click', function (event) {
        event.preventDefault();
        target = link.href;
        open();
    });

    modal.addEventListener('click', function (event) {
        if (event.target.closest('.segurium-deact-close') ||
            event.target.closest('.segurium-deact-overlay')) {
            cancel();
        }
    });

    modal.addEventListener('change', function (event) {
        if (event.target.name !== 'segurium_deact_reason') return;
        submitBtn.disabled = false;
    });

    skipBtn.addEventListener('click', leave);

    submitBtn.addEventListener('click', function () {
        var reason = selectedReason();
        if (!reason) return;

        submitBtn.disabled = true;
        skipBtn.disabled = true;

        // A report outlives the dialog it came from: cancel, then reopen,
        // and the first promise could still settle and navigate a user who
        // has pressed nothing. Only the current attempt may leave.
        var mine = ++attempt;
        var settle = function () {
            if (mine === attempt) leave();
        };
        watchdog = window.setTimeout(settle, REPORT_TIMEOUT);
        report(reason).then(settle, settle);
    });
})();

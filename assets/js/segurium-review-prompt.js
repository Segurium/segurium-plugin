/**
 * SEGURIUM-709: review-ask notice behaviour.
 *
 * Three buttons, one AJAX action. "Leave a review" keeps its native
 * new-tab navigation and reports in parallel. A failed report always
 * leaves the notice on screen with the server's error code in view —
 * the server state machine is the authority, and hiding the notice on a
 * write that never landed would desync the two and ask again later.
 */
(function () {
    'use strict';

    var notice = document.querySelector('.segurium-review-prompt');
    if (!notice) return;

    var i18n = (window.seguriumScan && window.seguriumScan.i18n) || {};

    var nonce = notice.getAttribute('data-segurium-review-nonce') || '';
    var ajaxUrl = (window.seguriumScan && window.seguriumScan.ajaxUrl) || window.ajaxurl || '';

    function showError(code) {
        var el = notice.querySelector('.segurium-review-prompt__error');
        if (!el) {
            el = document.createElement('p');
            el.className = 'segurium-review-prompt__error';
            notice.appendChild(el);
        }
        el.textContent = (i18n.reviewPromptError || 'Could not save your choice.') +
            (code ? ' (' + code + ')' : '');
    }

    if (!nonce || !ajaxUrl) {
        showError('review_prompt_bootstrap_missing');
        return;
    }

    function report(action) {
        return window.seguriumFetchJson(ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                action: 'segurium_review_prompt_action',
                nonce: nonce,
                review_action: action
            })
        });
    }

    function errorCode(response) {
        var data = (response && response.data) || {};
        return data.error_code || data.code || data.message || 'unknown';
    }

    function dismiss() {
        if (notice.parentNode) notice.parentNode.removeChild(notice);
    }

    notice.addEventListener('click', function (event) {
        var target = event.target.closest('[data-segurium-review-action]');
        if (!target) return;

        var action = target.getAttribute('data-segurium-review-action');
        var isLink = action === 'review';

        // The anchor opens wordpress.org in a new tab on its own; the
        // other two have nothing to navigate to.
        if (!isLink) event.preventDefault();
        target.disabled = true;

        report(action).then(function (response) {
            if (response && response.success) {
                dismiss();
                return;
            }
            target.disabled = false;
            showError(errorCode(response));
        }).catch(function () {
            target.disabled = false;
            showError('review_prompt_transport_failed');
        });
    });
})();

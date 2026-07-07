(function () {
    'use strict';

    var form = document.getElementById('segurium-support-form');
    if (!form) return;

    var i18n = seguriumScan.i18n || {};

    var typeSelect    = form.querySelector('#segurium-sup-type');
    var attachmentRow = document.getElementById('segurium-sup-attachment-row');
    var attachmentInp = document.getElementById('segurium-sup-attachment');
    var MAX_BYTES     = 100 * 1024 * 1024;

    function syncAttachmentVisibility() {
        if (!attachmentRow || !typeSelect) return;
        var on = typeSelect.value === 'fn_report';
        attachmentRow.style.display = on ? '' : 'none';
        if (attachmentInp) attachmentInp.required = on;
    }
    if (typeSelect) typeSelect.addEventListener('change', syncAttachmentVisibility);
    syncAttachmentVisibility();

    function escHtml(str) {
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(String(str)));
        return d.innerHTML;
    }

    function showResult(el, html, isError) {
        el.style.display = 'block';
        el.className = 'segurium-sup-result ' + (isError ? 'segurium-sup-result--error' : 'segurium-sup-result--success');
        el.innerHTML = html;
    }

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var submitBtn = form.querySelector('[type=submit]');
        var resultEl  = document.getElementById('segurium-sup-result');
        var origLabel = submitBtn.textContent;
        var emailInp  = form.querySelector('#segurium-sup-email');
        var emailVal  = emailInp ? emailInp.value.trim() : '';
        var emailRe   = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        var nameInp   = form.querySelector('#segurium-sup-name');
        var nameVal   = nameInp ? nameInp.value.trim() : '';

        if (!nameVal) {
            showResult(resultEl, escHtml(i18n.suppMissingName || 'Please enter your name.'), true);
            if (nameInp) nameInp.focus();
            return;
        }
        if (!emailVal || !emailRe.test(emailVal)) {
            showResult(resultEl, escHtml(i18n.suppInvalidEmail || 'Please enter a valid reply-to email.'), true);
            if (emailInp) emailInp.focus();
            return;
        }

        submitBtn.disabled = true;
        submitBtn.textContent = i18n.suppSubmitting || 'Submitting\u2026';
        if (resultEl) resultEl.style.display = 'none';

        var typeVal = form.querySelector('#segurium-sup-type').value;
        var fetchInit;

        if (typeVal === 'fn_report') {
            if (!attachmentInp || !attachmentInp.files || !attachmentInp.files[0]) {
                submitBtn.disabled = false;
                submitBtn.textContent = origLabel;
                showResult(resultEl, escHtml(i18n.suppFnNoFile || 'Please attach a file before submitting.'), true);
                return;
            }
            if (attachmentInp.files[0].size > MAX_BYTES) {
                submitBtn.disabled = false;
                submitBtn.textContent = origLabel;
                showResult(resultEl, escHtml(i18n.suppFnTooLarge || 'Selected file exceeds the 100 MB limit.'), true);
                return;
            }
            var fd = new FormData();
            fd.append('action', 'segurium_submit_support_ticket');
            fd.append('nonce', seguriumScan.supportNonce);
            fd.append('name', nameVal);
            fd.append('email', emailVal);
            fd.append('type', typeVal);
            fd.append('message', form.querySelector('#segurium-sup-message').value);
            fd.append('include_diag', form.querySelector('#segurium-sup-diag').checked ? '1' : '');
            fd.append('attachment', attachmentInp.files[0]);
            fetchInit = { method: 'POST', credentials: 'same-origin', body: fd };
        } else {
            var body = new URLSearchParams({
                action:       'segurium_submit_support_ticket',
                nonce:        seguriumScan.supportNonce,
                name:         nameVal,
                email:        emailVal,
                type:         typeVal,
                message:      form.querySelector('#segurium-sup-message').value,
                include_diag: form.querySelector('#segurium-sup-diag').checked ? '1' : ''
            });
            fetchInit = {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body
            };
        }

        fetch(seguriumScan.ajaxUrl, fetchInit)
        .then(window.seguriumParseResponse)
        .then(function (response) {
            submitBtn.disabled = false;
            submitBtn.textContent = origLabel;
            if (!response.success) {
                var msg = response.data && response.data.message || i18n.suppError || 'Error';
                showResult(resultEl, escHtml(msg), true);
                return;
            }
            var ticketId = response.data && response.data.ticket_id;
            var html = escHtml(i18n.suppSuccess || 'Ticket submitted.');
            if (ticketId) {
                html += ' ' + escHtml(i18n.suppTicketRef || 'Your ticket reference:') + ' <strong>#' + escHtml(String(ticketId)) + '</strong>.';
            }
            showResult(resultEl, html, false);
            form.reset();
            form.querySelector('#segurium-sup-diag').checked = true;
            syncAttachmentVisibility();
        })
        .catch(function () {
            submitBtn.disabled = false;
            submitBtn.textContent = origLabel;
            showResult(resultEl, escHtml(i18n.suppError || 'Connection error. Please try again.'), true);
        });
    });
})();

/**
 * 2FA configurator on the WordPress user profile page.
 *
 * Self-contained: depends only on `window.segurium2faProfile` (localized by
 * Segurium_2FA::render_profile_section) and `window.seguriumParseResponse`
 * (segurium-ajax.js). Deliberately does NOT depend on `seguriumScan`, which
 * is only localized on the toplevel_page_segurium admin screen.
 */
(function () {
    'use strict';

    var cfg = window.segurium2faProfile;
    if (!cfg) return;

    var container = document.getElementById('segurium-2fa-profile');
    if (!container) return;

    var i18n = cfg.i18n || {};

    function post(params) {
        var body = new URLSearchParams(params);
        return fetch(cfg.ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        }).then(window.seguriumParseResponse);
    }

    function escHtml(s) {
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(s));
        return d.innerHTML;
    }

    function renderStatus() {
        var method = cfg.method;
        var html = '';

        if (cfg.enforced) {
            html += '<p style="color:#b32d2e;"><strong>' + escHtml(i18n.enforced || '2FA is required for your role.') + '</strong></p>';
        }

        if (!method || method === 'none') {
            html += '<p>' + escHtml(i18n.notConfigured || 'Not configured') + '</p>';
            html += '<div class="segurium-2fa-profile-setup">';
            if ((cfg.availableMethods || []).indexOf('totp') !== -1) {
                html += '<button type="button" class="button" id="sgm-2fa-btn-setup-totp">' + escHtml(i18n.setupTotp || 'Set up Authenticator App') + '</button> ';
            }
            if ((cfg.availableMethods || []).indexOf('email') !== -1) {
                html += '<button type="button" class="button" id="sgm-2fa-btn-setup-email">' + escHtml(i18n.setupEmail || 'Set up Email Verification') + '</button>';
            }
            html += '</div>';
        } else {
            var methodLabel = method === 'totp' ? (i18n.totp || 'Authenticator App') : (i18n.email || 'Email Verification');
            html += '<p><strong>' + escHtml(i18n.currentMethod || 'Current method:') + '</strong> ' + escHtml(methodLabel) + '</p>';
            html += '<p>' + escHtml(i18n.backupCodes || 'Backup codes remaining:') + ' <strong>' + cfg.backupCount + '</strong></p>';
            html += '<div class="segurium-2fa-profile-setup">';
            html += '<button type="button" class="button" id="sgm-2fa-btn-regenerate">' + escHtml(i18n.regenerate || 'Regenerate Backup Codes') + '</button> ';
            if (!cfg.enforced) {
                html += '<button type="button" class="button" id="sgm-2fa-btn-disable">' + escHtml(i18n.disable || 'Disable 2FA') + '</button>';
            }
            html += '</div>';
        }

        container.innerHTML = html;
        bindButtons();
    }

    function bindButtons() {
        var btnTotp = document.getElementById('sgm-2fa-btn-setup-totp');
        if (btnTotp) btnTotp.addEventListener('click', startTotpSetup);

        var btnEmail = document.getElementById('sgm-2fa-btn-setup-email');
        if (btnEmail) btnEmail.addEventListener('click', startEmailSetup);

        var btnRegen = document.getElementById('sgm-2fa-btn-regenerate');
        if (btnRegen) btnRegen.addEventListener('click', promptCodeAction.bind(null, 'regenerate'));

        var btnDisable = document.getElementById('sgm-2fa-btn-disable');
        if (btnDisable) btnDisable.addEventListener('click', promptCodeAction.bind(null, 'disable'));
    }

    function startTotpSetup() {
        container.innerHTML = '<p>' + escHtml(i18n.verifying || 'Loading...') + '</p>';
        post({ action: 'segurium_2fa_setup_totp', nonce: cfg.nonce }).then(function (r) {
            if (!r.success) {
                container.innerHTML = '<p style="color:red;">' + escHtml(r.data.message || 'Error') + '</p>';
                return;
            }
            var d = r.data;
            var html = '<p><strong>' + escHtml(i18n.scanQr || 'Scan this QR code with your authenticator app:') + '</strong></p>';
            html += '<div class="segurium-2fa-qr">' + d.qr_svg + '</div>';
            html += '<p>' + escHtml(i18n.manualEntry || 'Or enter this key manually:') + '</p>';
            html += '<div class="segurium-2fa-secret">' + escHtml(d.secret) + '</div>';
            html += '<p>' + escHtml(i18n.enterCode || 'Enter the 6-digit code from your app to confirm:') + '</p>';
            html += '<input type="text" id="sgm-2fa-confirm-code" class="regular-text" maxlength="6" inputmode="numeric" autocomplete="one-time-code" style="font-size:18px;width:150px;"> ';
            html += '<button type="button" class="button button-primary" id="sgm-2fa-confirm-btn">' + escHtml(i18n.confirm || 'Confirm') + '</button> ';
            html += '<button type="button" class="button" id="sgm-2fa-cancel-btn">' + escHtml(i18n.cancel || 'Cancel') + '</button>';
            html += '<p id="sgm-2fa-setup-error" style="color:red;display:none;"></p>';
            container.innerHTML = html;

            document.getElementById('sgm-2fa-confirm-btn').addEventListener('click', function () {
                var code = document.getElementById('sgm-2fa-confirm-code').value.trim();
                if (!code) return;
                this.disabled = true;
                post({ action: 'segurium_2fa_confirm_totp', nonce: cfg.nonce, code: code }).then(function (cr) {
                    if (!cr.success) {
                        document.getElementById('sgm-2fa-setup-error').textContent = cr.data.message || 'Error';
                        document.getElementById('sgm-2fa-setup-error').style.display = '';
                        document.getElementById('sgm-2fa-confirm-btn').disabled = false;
                        return;
                    }
                    cfg.method = 'totp';
                    cfg.backupCount = cr.data.backup_codes.length;
                    showBackupCodes(cr.data.backup_codes);
                });
            });

            document.getElementById('sgm-2fa-cancel-btn').addEventListener('click', renderStatus);
        });
    }

    function startEmailSetup() {
        container.innerHTML = '<p>' + escHtml(i18n.verifying || 'Loading...') + '</p>';
        post({ action: 'segurium_2fa_setup_email', nonce: cfg.nonce }).then(function (r) {
            if (!r.success) {
                container.innerHTML = '<p style="color:red;">' + escHtml(r.data.message || 'Error') + '</p>';
                return;
            }
            var html = '<p>' + escHtml(i18n.emailSent || 'A verification code has been sent to your email.') + '</p>';
            html += '<input type="text" id="sgm-2fa-confirm-code" class="regular-text" maxlength="8" inputmode="numeric" style="font-size:18px;width:150px;"> ';
            html += '<button type="button" class="button button-primary" id="sgm-2fa-confirm-btn">' + escHtml(i18n.confirm || 'Confirm') + '</button> ';
            html += '<button type="button" class="button" id="sgm-2fa-cancel-btn">' + escHtml(i18n.cancel || 'Cancel') + '</button>';
            html += '<p id="sgm-2fa-setup-error" style="color:red;display:none;"></p>';
            container.innerHTML = html;

            document.getElementById('sgm-2fa-confirm-btn').addEventListener('click', function () {
                var code = document.getElementById('sgm-2fa-confirm-code').value.trim();
                if (!code) return;
                this.disabled = true;
                post({ action: 'segurium_2fa_confirm_email', nonce: cfg.nonce, code: code }).then(function (cr) {
                    if (!cr.success) {
                        document.getElementById('sgm-2fa-setup-error').textContent = cr.data.message || 'Error';
                        document.getElementById('sgm-2fa-setup-error').style.display = '';
                        document.getElementById('sgm-2fa-confirm-btn').disabled = false;
                        return;
                    }
                    cfg.method = 'email';
                    cfg.backupCount = cr.data.backup_codes.length;
                    showBackupCodes(cr.data.backup_codes);
                });
            });

            document.getElementById('sgm-2fa-cancel-btn').addEventListener('click', renderStatus);
        });
    }

    function showBackupCodes(codes) {
        var html = '<div class="segurium-2fa-backup-codes">';
        html += '<p><strong>' + escHtml(i18n.saveBackupCodes || 'Save these backup codes. They will not be shown again.') + '</strong></p>';
        html += '<code style="display:block;background:#f0f0f1;padding:12px 16px;font-size:14px;line-height:2;margin:8px 0 12px;">';
        codes.forEach(function (c) { html += escHtml(c) + '<br>'; });
        html += '</code>';
        html += '</div>';
        html += '<p style="color:#00a32a;"><strong>' + escHtml(i18n.setupComplete || '2FA set up successfully.') + '</strong></p>';
        html += '<button type="button" class="button" id="sgm-2fa-done-btn">OK</button>';
        container.innerHTML = html;
        document.getElementById('sgm-2fa-done-btn').addEventListener('click', renderStatus);
    }

    function promptCodeAction(action) {
        var html = '<p>' + escHtml(i18n.enterToVerify || 'Enter your current 2FA code to confirm:') + '</p>';
        html += '<input type="text" id="sgm-2fa-action-code" class="regular-text" maxlength="20" inputmode="numeric" style="font-size:18px;width:150px;"> ';
        html += '<button type="button" class="button button-primary" id="sgm-2fa-action-btn">' + escHtml(i18n.confirm || 'Confirm') + '</button> ';
        html += '<button type="button" class="button" id="sgm-2fa-action-cancel">' + escHtml(i18n.cancel || 'Cancel') + '</button>';
        html += '<p id="sgm-2fa-action-error" style="color:red;display:none;"></p>';
        container.innerHTML = html;

        document.getElementById('sgm-2fa-action-btn').addEventListener('click', function () {
            var code = document.getElementById('sgm-2fa-action-code').value.trim();
            if (!code) return;
            this.disabled = true;
            var ajaxAction = action === 'disable' ? 'segurium_2fa_disable' : 'segurium_2fa_regenerate_backup';
            post({ action: ajaxAction, nonce: cfg.nonce, code: code }).then(function (r) {
                if (!r.success) {
                    document.getElementById('sgm-2fa-action-error').textContent = r.data.message || 'Error';
                    document.getElementById('sgm-2fa-action-error').style.display = '';
                    document.getElementById('sgm-2fa-action-btn').disabled = false;
                    return;
                }
                if (action === 'disable') {
                    cfg.method = '';
                    cfg.backupCount = 0;
                    container.innerHTML = '<p style="color:#00a32a;">' + escHtml(i18n.disabled || '2FA disabled.') + '</p>';
                    setTimeout(renderStatus, 2000);
                } else {
                    cfg.backupCount = r.data.backup_codes.length;
                    showBackupCodes(r.data.backup_codes);
                }
            });
        });

        document.getElementById('sgm-2fa-action-cancel').addEventListener('click', renderStatus);
    }

    renderStatus();
})();

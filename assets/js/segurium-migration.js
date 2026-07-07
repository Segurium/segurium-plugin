(function () {
    'use strict';

    var panel = document.getElementById('segurium-migration-list');
    if (!panel) return;

    var i18n = seguriumScan.i18n || {};
    var loaded = false;

    function post(params) {
        var body = new URLSearchParams(params);
        return fetch(seguriumScan.ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        }).then(window.seguriumParseResponse);
    }

    function escHtml(str) {
        var d = document.createElement('div');
        d.appendChild(document.createTextNode(String(str)));
        return d.innerHTML;
    }

    function statusClass(status) {
        if (status === 'import') return 'segurium-mig-status--import';
        if (status === 'pending_feature') return 'segurium-mig-status--pending';
        return 'segurium-mig-status--skip';
    }

    function statusLabel(item) {
        if (item.status === 'import') return escHtml(item.action_label || i18n.migImport || 'Import');
        if (item.status === 'pending_feature') return escHtml(i18n.migPending || 'Planned feature');
        return escHtml(i18n.migSkip || 'Skip');
    }

    function renderPreviewTable(slug, name, items) {
        var cardId = 'segurium-mig-card-' + slug;
        var card = document.getElementById(cardId);
        if (!card) return;

        var rows = '';
        items.forEach(function (item) {
            var noteHtml = item.note ? '<br><small class="segurium-mig-note">' + escHtml(item.note) + '</small>' : '';
            rows += '<tr>' +
                '<td>' + escHtml(item.label) + noteHtml + '</td>' +
                '<td>' + (item.count > 0 ? escHtml(item.preview_text) : '&mdash;') + '</td>' +
                '<td><span class="segurium-mig-status ' + statusClass(item.status) + '">' + statusLabel(item) + '</span></td>' +
                '</tr>';
        });

        var hasImportable = items.some(function (item) { return item.status === 'import' && item.count > 0; });

        card.innerHTML =
            '<div class="segurium-mig-card-header">' +
                '<strong>' + escHtml(name) + '</strong>' +
            '</div>' +
            '<table class="widefat segurium-mig-table">' +
                '<thead><tr>' +
                    '<th>' + escHtml(i18n.migFeature || 'Feature') + '</th>' +
                    '<th>' + escHtml(i18n.migValue || 'Value') + '</th>' +
                    '<th>' + escHtml(i18n.migAction || 'Action') + '</th>' +
                '</tr></thead>' +
                '<tbody>' + rows + '</tbody>' +
            '</table>' +
            '<div class="segurium-mig-card-actions">' +
                (hasImportable
                    ? '<button class="button button-primary segurium-mig-apply-btn" data-slug="' + escHtml(slug) + '">' + escHtml(i18n.migApply || 'Apply Migration') + '</button> '
                    : '') +
                '<button class="button segurium-mig-cancel-btn" data-slug="' + escHtml(slug) + '">' + escHtml(i18n.migCancel || 'Cancel') + '</button>' +
            '</div>';

        var applyBtn = card.querySelector('.segurium-mig-apply-btn');
        if (applyBtn) {
            applyBtn.addEventListener('click', function () {
                applyMigration(slug, name, card);
            });
        }

        var cancelBtn = card.querySelector('.segurium-mig-cancel-btn');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', function () {
                renderCard({ slug: slug, name: name, item_count: 0 }, card);
            });
        }
    }

    function applyMigration(slug, name, card) {
        card.innerHTML = '<p class="segurium-mig-loading">' + escHtml(name) + '&hellip;</p>';
        post({
            action: 'segurium_migration_apply',
            nonce: seguriumScan.migrationNonce,
            slug: slug
        }).then(function (response) {
            if (!response.success) {
                card.innerHTML = '<p class="segurium-mig-error">' + escHtml(response.data && response.data.message || 'Error') + '</p>';
                return;
            }
            var result = response.data;
            var appliedCount = (result.applied || []).length;
            var pendingCount = (result.pending || []).length;
            var summary = escHtml(i18n.migApplied || 'Migration complete.');
            if (appliedCount > 0) summary += ' <strong>' + appliedCount + ' ' + escHtml(i18n.migItemsImported || 'items imported') + '</strong>.';
            if (pendingCount > 0) summary += ' ' + pendingCount + ' ' + escHtml(i18n.migItemsPending || 'features planned') + '.';
            card.innerHTML =
                '<div class="segurium-mig-card-header"><strong>' + escHtml(name) + '</strong></div>' +
                '<p class="segurium-mig-success">' + summary + '</p>';
        }).catch(function () {
            card.innerHTML = '<p class="segurium-mig-error">Connection error. Please try again.</p>';
        });
    }

    function renderCard(plugin, container) {
        container = container || document.createElement('div');
        container.className = 'segurium-mig-card';
        container.id = 'segurium-mig-card-' + plugin.slug;
        var importable = plugin.item_count || 0;
        container.innerHTML =
            '<div class="segurium-mig-card-header">' +
                '<strong>' + escHtml(plugin.name) + '</strong>' +
                (importable > 0 ? ' <span class="segurium-mig-badge">' + importable + '</span>' : '') +
            '</div>' +
            '<div class="segurium-mig-card-actions">' +
                '<button class="button segurium-mig-preview-btn" data-slug="' + escHtml(plugin.slug) + '">' +
                    escHtml(i18n.migPreview || 'Preview') +
                '</button>' +
            '</div>';

        var previewBtn = container.querySelector('.segurium-mig-preview-btn');
        if (previewBtn) {
            previewBtn.addEventListener('click', function () {
                var slug = this.getAttribute('data-slug');
                container.innerHTML = '<p class="segurium-mig-loading">' + escHtml(plugin.name) + '&hellip;</p>';
                post({
                    action: 'segurium_migration_preview',
                    nonce: seguriumScan.migrationNonce,
                    slug: slug
                }).then(function (response) {
                    if (!response.success) {
                        container.innerHTML = '<p class="segurium-mig-error">' + escHtml(response.data && response.data.message || 'Error') + '</p>';
                        return;
                    }
                    renderPreviewTable(response.data.slug, response.data.name, response.data.items);
                }).catch(function () {
                    container.innerHTML = '<p class="segurium-mig-error">Connection error. Please try again.</p>';
                });
            });
        }

        return container;
    }

    function loadMigrations() {
        if (loaded) return;
        loaded = true;
        panel.innerHTML = '<p class="segurium-mig-loading">Detecting&hellip;</p>';
        post({
            action: 'segurium_migration_detect',
            nonce: seguriumScan.migrationNonce
        }).then(function (response) {
            panel.innerHTML = '';
            if (!response.success || !response.data || !response.data.length) {
                panel.innerHTML = '<p>' + escHtml(i18n.migNoPlugins || 'No supported security plugins detected.') + '</p>';
                return;
            }
            response.data.forEach(function (plugin) {
                panel.appendChild(renderCard(plugin));
            });
        }).catch(function () {
            panel.innerHTML = '<p class="segurium-mig-error">Connection error. Please try again.</p>';
        });
    }

    // Load when Migration tab is activated
    var navItems = document.querySelectorAll('.segurium-nav-item[data-feature]');
    navItems.forEach(function (item) {
        if (item.getAttribute('data-feature') === 'migration') {
            item.addEventListener('click', loadMigrations);
        }
    });

    // Load on direct deep links (`?page=segurium&tab=migration`) and any
    // in-app switch (segurium-scan.js dispatches segurium:tab-changed after
    // pushState / popstate).
    if (window.seguriumScan && window.seguriumScan.activeTab === 'migration') {
        loadMigrations();
    }
    document.addEventListener('segurium:tab-changed', function (e) {
        if (e.detail && e.detail.feature === 'migration') {
            loadMigrations();
        }
    });
})();

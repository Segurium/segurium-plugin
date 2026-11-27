/**
 * Phase rows on the Scanner tab: one row per phase of the newest run.
 */
(function () {
    'use strict';

    var sa = window.seguriumAdmin;
    var cfg = window.seguriumPhaseRows;
    if (!sa || !cfg) return;

    var scanBtn = sa.el('segurium-ss-scan-btn');
    var scanArea = scanBtn && scanBtn.closest('.segurium-ss-scan-area');
    if (!scanArea) return;

    // These phases have a summary of their own on their tab.
    var OWN_SUMMARY = { files: true, integrity: true, self_check: true };

    var i18n = sa.i18n || {};

    var rows = document.createElement('ol');
    rows.id = 'segurium-phase-rows';
    rows.className = 'segurium-phase-rows';
    rows.hidden = true;
    scanArea.insertAdjacentElement('afterend', rows);

    function label(map, key) {
        return Object.prototype.hasOwnProperty.call(map || {}, key) ? map[key] : key;
    }

    function cell(className, text) {
        var span = document.createElement('span');
        span.className = className;
        span.textContent = text;
        return span;
    }

    function count(key, value) {
        var name = key.replace(/_/g, ' ');
        return typeof value === 'number' ? value + ' ' + name : name + ' ' + value;
    }

    function describe(phase) {
        var counters = phase.counters || {};
        var parts = [];
        Object.keys(counters).forEach(function (key) {
            if (key !== cfg.threatsKey) parts.push(count(key, counters[key]));
        });
        if (Object.prototype.hasOwnProperty.call(counters, cfg.threatsKey)) {
            var clean = counters[cfg.threatsKey] === 0 && phase.status === 'done' && !OWN_SUMMARY[phase.id];
            parts.push(clean ? (i18n.noThreats || 'No threats found.') : count(cfg.threatsKey, counters[cfg.threatsKey]));
        }
        if (phase.error_code) parts.push(phase.error_code);
        return parts.join(' · ');
    }

    function render(run) {
        rows.textContent = '';
        rows.hidden = !run;
        if (!run) return;
        rows.setAttribute('data-run-id', run.run_id);
        rows.setAttribute('data-run-status', run.status);
        (run.phases || []).forEach(function (phase) {
            var row = document.createElement('li');
            row.className = 'segurium-phase-row';
            row.setAttribute('data-phase', phase.id);
            row.setAttribute('data-status', phase.status);
            row.appendChild(cell('segurium-phase-name', label(cfg.phaseLabels, phase.id)));
            row.appendChild(cell('segurium-phase-counters', describe(phase)));
            row.appendChild(cell('segurium-phase-state', label(cfg.stateLabels, phase.status)));
            rows.appendChild(row);
        });
    }

    var integrityBtn = sa.el('segurium-is-scan-btn');
    var timer = null;
    var seq = 0;
    var missed = false;
    var lastRun = '';

    function shown() {
        return !document.hidden && scanArea.getClientRects().length > 0;
    }

    function refresh() {
        missed = !shown();
        if (missed) return;
        var mine = ++seq;
        sa.post({
            action: 'segurium_scan_phase_rows',
            nonce: seguriumScan.nonce
        }).then(function (response) {
            if (mine !== seq) return;
            if (response && response.success && response.data) {
                render(response.data.run);
            } else {
                missed = true;
            }
        });
    }

    function kick() {
        seq++;
        clearTimeout(timer);
        timer = setTimeout(refresh, 0);
    }

    function watch(button) {
        var last = null;
        function check() {
            if (button.disabled === last) return;
            last = button.disabled;
            kick();
        }
        new MutationObserver(check).observe(button, { attributes: true, attributeFilter: ['disabled'] });
        check();
    }

    watch(scanBtn);
    if (integrityBtn) watch(integrityBtn);

    // The run row changes only when a phase starts or ends, so the rows
    // read again when the phase list of the Scanner tab's poll changes.
    document.addEventListener('segurium:run-status', function (e) {
        var data = e.detail || {};
        var key = data.run_active ? [data.run_id, data.run_phase, JSON.stringify(data.run_phases || [])].join('|') : '';
        if (key === lastRun && !missed) return;
        lastRun = key;
        kick();
    });

    document.addEventListener('segurium:tab-changed', function (e) {
        if (missed && e.detail && e.detail.feature === 'scanner') kick();
    });

    document.addEventListener('visibilitychange', function () {
        if (!document.hidden && missed) kick();
    });
})();

(function () {
    'use strict';

    function copyIid(button) {
        var row = button.closest('.segurium-iid-row');
        if (!row) return;
        var iid = row.getAttribute('data-segurium-iid') || '';
        if (!iid) return;

        var done = function () {
            button.classList.add('is-copied');
            window.setTimeout(function () {
                button.classList.remove('is-copied');
            }, 1500);
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(iid).then(done, function () {
                fallbackCopy(iid, done);
            });
        } else {
            fallbackCopy(iid, done);
        }
    }

    function fallbackCopy(text, done) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'absolute';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(ta);
        done();
    }

    document.addEventListener('click', function (event) {
        var button = event.target.closest && event.target.closest('.segurium-iid-copy');
        if (!button) return;
        event.preventDefault();
        copyIid(button);
    });
})();

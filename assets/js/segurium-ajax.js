/**
 * Segurium AJAX client helper.
 *
 * Unwraps the `<<<SEG-JSON:1:BEGIN>>> … <<<SEG-JSON:1:END>>>` envelope.
 * On failure returns a normalized `{ success: false, data: { code, … } }`
 * with `code` ∈ envelope_empty | envelope_absent | envelope_truncated |
 * envelope_malformed | envelope_unexpected_shape. Triggers and root
 * causes for each code: docs/features/ajax-envelope.md.
 */
(function () {
    'use strict';

    var BEGIN = '<<<SEG-JSON:1:BEGIN>>>';
    var END   = '<<<SEG-JSON:1:END>>>';
    var MAX_RAW = 1024;

    function makeEnvelopeError(code, httpStatus, rawText) {
        return {
            success: false,
            data: {
                code: code,
                message: '',
                http_status: httpStatus,
                raw: rawText ? String(rawText).slice(0, MAX_RAW) : '',
                contaminated: true
            }
        };
    }

    /**
     * Parse a fetch() Response whose body is wrapped in the Segurium
     * envelope. Returns the decoded JSON payload. On any deviation from
     * the expected format the result is a normalized error object so
     * callers never need to branch on `response.ok`.
     *
     * @param {Response} response
     * @returns {Promise<object>}
     */
    function seguriumParseResponse(response) {
        return response.text().then(function (text) {
            if (!text) {
                return makeEnvelopeError('envelope_empty', response.status, '');
            }
            var b = text.indexOf(BEGIN);
            var e = text.indexOf(END);
            if (b < 0) {
                return makeEnvelopeError('envelope_absent', response.status, text);
            }
            if (e < 0 || e <= b) {
                return makeEnvelopeError('envelope_truncated', response.status, text);
            }
            var inner = text.slice(b + BEGIN.length, e);
            try {
                var parsed = JSON.parse(inner);
                if (parsed && typeof parsed === 'object' && 'success' in parsed) {
                    return parsed;
                }
                return makeEnvelopeError('envelope_unexpected_shape', response.status, text);
            } catch (err) {
                return makeEnvelopeError('envelope_malformed', response.status, text);
            }
        });
    }

    /**
     * Convenience wrapper: fetch(url, init) then parse envelope.
     *
     * @param {string|Request} url
     * @param {RequestInit}    init
     * @returns {Promise<object>}
     */
    function seguriumFetchJson(url, init) {
        return fetch(url, init).then(seguriumParseResponse);
    }

    window.seguriumParseResponse = seguriumParseResponse;
    window.seguriumFetchJson     = seguriumFetchJson;
    window.seguriumEnvelope      = {
        BEGIN: BEGIN,
        END: END,
        VERSION: 1
    };
})();

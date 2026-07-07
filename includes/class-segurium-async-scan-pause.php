<?php
/**
 * IID-scoped pause transients for the async scan pipeline.
 *
 * SEGURIUM-478: replaces the per-`scan_id` `async_scan:retry_after:`
 * `runtime_kv` row introduced in SEGURIUM-476. CTI's per-IID gates
 * (file-count bucket, fleet gate, NRS-queue gate) emit `Retry-After`
 * for the whole IID, so the pause is IID-scoped too — one WP install
 * runs at most one set of concurrent scans against one IID, and they
 * all share the same back-off.
 *
 * Two endpoints, two independent transients:
 *   - `segurium_submit_pause_until`  → `POST /v1/scan/submit` Retry-After
 *   - `segurium_results_pause_until` → `GET  /v1/scan/results` Retry-After
 *
 * See `docs/features/async-submit-concurrency.md` §5.1 and §7.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * IID-scoped Retry-After gate for /v1/scan/submit and /v1/scan/results.
 */
class Segurium_Async_Scan_Pause {

	const ENDPOINT_SUBMIT  = 'submit';
	const ENDPOINT_RESULTS = 'results';

	const TRANSIENT_SUBMIT  = 'segurium_submit_pause_until';
	const TRANSIENT_RESULTS = 'segurium_results_pause_until';

	/**
	 * SEGURIUM-483: sibling transients that record when the pause was
	 * stamped, so the resume observability event can report how long
	 * the pause was actually honoured (vs. the requested length).
	 */
	const TRANSIENT_SUBMIT_SET_AT  = 'segurium_submit_pause_set_at';
	const TRANSIENT_RESULTS_SET_AT = 'segurium_results_pause_set_at';

	/**
	 * Seconds added to the transient TTL on top of the requested pause.
	 * The transient stores the absolute unix deadline so a slightly long
	 * TTL is safe — read paths recompute remaining time against `time()`
	 * — but a too-tight TTL could expire the row just as a tick wakes up
	 * to honour it.
	 */
	const GRACE_SECS = 5;

	/**
	 * Map an endpoint label to its transient key. Returns '' for unknown
	 * labels; callers should treat that as "no pause to read."
	 *
	 * @param string $endpoint One of self::ENDPOINT_*.
	 * @return string
	 */
	private static function transient_key( $endpoint ) {
		switch ( $endpoint ) {
			case self::ENDPOINT_SUBMIT:
				return self::TRANSIENT_SUBMIT;
			case self::ENDPOINT_RESULTS:
				return self::TRANSIENT_RESULTS;
			default:
				return '';
		}
	}

	/**
	 * Sibling-transient key tracking when a pause was first stamped
	 * (SEGURIUM-483). Empty for unknown endpoints.
	 *
	 * @param string $endpoint One of self::ENDPOINT_*.
	 * @return string
	 */
	private static function set_at_key( $endpoint ) {
		switch ( $endpoint ) {
			case self::ENDPOINT_SUBMIT:
				return self::TRANSIENT_SUBMIT_SET_AT;
			case self::ENDPOINT_RESULTS:
				return self::TRANSIENT_RESULTS_SET_AT;
			default:
				return '';
		}
	}

	/**
	 * Stamp an absolute deadline `now + $seconds` for the given endpoint.
	 * `$seconds <= 0` clears the pause rather than stamping a past time.
	 *
	 * @param string $endpoint One of self::ENDPOINT_*.
	 * @param int    $seconds  Pause length in seconds.
	 * @return void
	 */
	public static function set_pause( $endpoint, $seconds ) {
		$key = self::transient_key( $endpoint );
		if ( '' === $key ) {
			return;
		}
		$seconds = (int) $seconds;
		if ( $seconds <= 0 ) {
			self::clear( $endpoint );
			return;
		}
		$now = time();

		// SEGURIUM-483: only stamp `_set_at` on a fresh pause — back-to-
		// back Retry-Afters extend the deadline but should not reset
		// the elapsed-time clock the resume event reports.
		$prior_set_at = self::pause_set_at( $endpoint );
		$set_at_key   = self::set_at_key( $endpoint );

		set_transient( $key, $now + $seconds, $seconds + self::GRACE_SECS );

		if ( '' !== $set_at_key && $prior_set_at <= 0 ) {
			set_transient( $set_at_key, $now, $seconds + self::GRACE_SECS );
		}
	}

	/**
	 * Unix timestamp at which the active pause was first stamped, or 0
	 * when no pause is currently set. Used by SEGURIUM-483's
	 * `scan_submit_resume` event to compute `paused_for_secs`.
	 *
	 * @param string $endpoint One of self::ENDPOINT_*.
	 * @return int
	 */
	public static function pause_set_at( $endpoint ) {
		$set_at_key = self::set_at_key( $endpoint );
		if ( '' === $set_at_key ) {
			return 0;
		}
		$raw = get_transient( $set_at_key );
		return false === $raw ? 0 : (int) $raw;
	}

	/**
	 * True when an unexpired pause deadline is stamped for the endpoint.
	 *
	 * @param string $endpoint One of self::ENDPOINT_*.
	 * @return bool
	 */
	public static function is_paused( $endpoint ) {
		return self::pause_remaining( $endpoint ) > 0;
	}

	/**
	 * Seconds remaining on the pause, or 0 when none is active. A stale
	 * transient (deadline in the past, but TTL not yet expired) is
	 * cleaned up to keep `is_paused()` honest.
	 *
	 * @param string $endpoint One of self::ENDPOINT_*.
	 * @return int
	 */
	public static function pause_remaining( $endpoint ) {
		$key = self::transient_key( $endpoint );
		if ( '' === $key ) {
			return 0;
		}
		$raw = get_transient( $key );
		if ( false === $raw ) {
			return 0;
		}
		$deadline  = (int) $raw;
		$remaining = $deadline - time();
		if ( $remaining <= 0 ) {
			delete_transient( $key );
			$set_at_key = self::set_at_key( $endpoint );
			if ( '' !== $set_at_key ) {
				delete_transient( $set_at_key );
			}
			return 0;
		}
		return $remaining;
	}

	/**
	 * Drop any stamped deadline for the endpoint. No-op when none exists.
	 *
	 * @param string $endpoint One of self::ENDPOINT_*.
	 * @return void
	 */
	public static function clear( $endpoint ) {
		$key = self::transient_key( $endpoint );
		if ( '' === $key ) {
			return;
		}
		delete_transient( $key );
		$set_at_key = self::set_at_key( $endpoint );
		if ( '' !== $set_at_key ) {
			delete_transient( $set_at_key );
		}
	}
}

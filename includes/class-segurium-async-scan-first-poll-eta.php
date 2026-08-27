<?php
/**
 * Dynamic first-poll ETA for the async scan pipeline.
 *
 * Stamps a per-`scan_id` unix-ts in `runtime_kv` on the
 * first successful `/v1/scan/submit` response. The Phase B
 * poll loop uses the stamp to skip a wasted first poll before NRS has
 * had time to produce any verdict.
 *
 * Formula (spec §6 of `docs/features/async-submit-concurrency.md`):
 *
 *     first_poll_eligible_at = first_submit_unix
 *                            + ceil(first_batch_file_count × avg_ms_per_file / 1000)
 *
 * where `avg_ms_per_file` is the `segurium_scan_neoray_avg_ms_per_file`
 * wp_option (default 200). The stamp is cleared once a results poll
 * returns at least one verdict for the scan — after that point Phase B
 * has its own cadence and the ETA no longer matters.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stamping + lookup helpers for the per-scan first-poll ETA.
 */
class Segurium_Async_Scan_First_Poll_Eta {

	/**
	 * `wp_option` key whose integer value (ms) drives the ETA formula.
	 * Mirror of CTI's `[neoray_capacity].avg_scan_ms`; see spec §6.
	 */
	const OPTION_AVG_MS_PER_FILE = 'segurium_scan_neoray_avg_ms_per_file';

	/**
	 * Default ms/file when the option is unset. Matches NRS' steady-state
	 * per-file scan time (~100–250 ms).
	 */
	const DEFAULT_AVG_MS_PER_FILE = 200;

	/**
	 * Hard lower bound on the avg-ms knob. Filters out misconfigured
	 * zero/negative values that would let the first poll fire instantly
	 * for arbitrary batch sizes.
	 */
	const MIN_AVG_MS_PER_FILE = 1;

	/**
	 * Hard upper bound on the avg-ms knob. Guards against accidental
	 * `1_000_000`-style values that would push the first poll out by
	 * literal years on a large batch.
	 */
	const MAX_AVG_MS_PER_FILE = 60000;

	/**
	 * Runtime_kv key prefix. The full key is `KV_PREFIX . $scan_id`.
	 */
	const KV_PREFIX = 'async_scan:first_poll_eta:';

	/**
	 * Sibling key that records the first-batch file count
	 * used to compute the deadline. Phase B emits this in
	 * `scan_poll_first_wait` so operators can correlate the wait with
	 * how big the first submit was.
	 */
	const KV_PREFIX_FILES = 'async_scan:first_poll_eta_files:';

	/**
	 * TTL (seconds) for the stamped row. A scan that drags past 24 h is
	 * pathological — the stamp can disappear and Phase B will fall back
	 * to "poll right away" without harm.
	 */
	const KV_TTL_SECS = 86400;

	/**
	 * Bind the submitter's first-success action to {@see stamp()}.
	 * Idempotent: WordPress de-duplicates `(hook, callable)` pairs.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action(
			'segurium_async_scan_submit_first_success',
			array( __CLASS__, 'stamp' ),
			10,
			3
		);
	}

	/**
	 * Stamp the first-poll ETA for `$scan_id` if not already set.
	 *
	 * Idempotent on scan_id: every subsequent submit for the same scan
	 * is a no-op. Submitter fires the action on every clean 200, so the
	 * idempotency check is the only thing keeping the value pinned to
	 * the first batch's file count.
	 *
	 * @param string $scan_id          Plugin-side scan UUID.
	 * @param int    $batch_files      Number of files in the just-accepted batch.
	 * @param int    $submit_unix      Wall-clock unix ts of the submit.
	 * @return int 0 when no stamp was written (already exists / invalid input);
	 *             the stamped deadline otherwise.
	 */
	public static function stamp( $scan_id, $batch_files, $submit_unix ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return 0;
		}
		$batch_files = max( 1, (int) $batch_files );
		$submit_unix = (int) $submit_unix;
		if ( $submit_unix <= 0 ) {
			$submit_unix = time();
		}
		if ( self::get( $scan_id ) > 0 ) {
			return 0;
		}
		$deadline = $submit_unix + (int) ceil( $batch_files * self::avg_ms_per_file() / 1000 );
		self::set( $scan_id, $deadline );
		// Record the first-batch file count alongside the
		// deadline so `scan_poll_first_wait` can report it. Best-effort —
		// a missing sibling row degrades the event field to 0.
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_PREFIX_FILES . $scan_id,
				'kv_value'   => (string) $batch_files,
				'expires_at' => $now + self::KV_TTL_SECS,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
		return $deadline;
	}

	/**
	 * Read the recorded first-batch file count for a scan, or 0 if no
	 * sibling row exists.
	 *
	 * @param string $scan_id Plugin-side scan UUID.
	 * @return int
	 */
	public static function get_eta_files( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return 0;
		}
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_PREFIX_FILES . $scan_id )
		);
		if ( null === $raw || '' === $raw ) {
			return 0;
		}
		return (int) $raw;
	}

	/**
	 * Resolve the configured avg-ms knob, clamped to a sane range.
	 *
	 * @return int
	 */
	public static function avg_ms_per_file() {
		$raw = (int) Segurium_Storage::setting_get( self::OPTION_AVG_MS_PER_FILE, self::DEFAULT_AVG_MS_PER_FILE );
		if ( $raw < self::MIN_AVG_MS_PER_FILE ) {
			return self::DEFAULT_AVG_MS_PER_FILE;
		}
		if ( $raw > self::MAX_AVG_MS_PER_FILE ) {
			return self::MAX_AVG_MS_PER_FILE;
		}
		return $raw;
	}

	/**
	 * Read the stamped deadline for a scan. Returns 0 when none exists.
	 *
	 * @param string $scan_id Plugin-side scan UUID.
	 * @return int Unix ts, or 0.
	 */
	public static function get( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return 0;
		}
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_PREFIX . $scan_id )
		);
		if ( null === $raw || '' === $raw ) {
			return 0;
		}
		return (int) $raw;
	}

	/**
	 * Persist a stamped deadline. Refuses zero/negative values; use
	 * {@see clear()} instead.
	 *
	 * @param string $scan_id  Plugin-side scan UUID.
	 * @param int    $unix_ts  Deadline.
	 * @return void
	 */
	public static function set( $scan_id, $unix_ts ) {
		$scan_id = (string) $scan_id;
		$unix_ts = (int) $unix_ts;
		if ( '' === $scan_id || $unix_ts <= 0 ) {
			return;
		}
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_PREFIX . $scan_id,
				'kv_value'   => (string) $unix_ts,
				'expires_at' => $now + self::KV_TTL_SECS,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Drop the stamped row for a scan. No-op when no row exists.
	 *
	 * @param string $scan_id Plugin-side scan UUID.
	 * @return void
	 */
	public static function clear( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		Segurium_Storage::table_delete(
			'runtime_kv',
			array( 'kv_key' => self::KV_PREFIX . $scan_id )
		);
		Segurium_Storage::table_delete(
			'runtime_kv',
			array( 'kv_key' => self::KV_PREFIX_FILES . $scan_id )
		);
	}

	/**
	 * True when the deadline has not yet elapsed. Used by Phase B's
	 * first-poll gate.
	 *
	 * @param string $scan_id Plugin-side scan UUID.
	 * @return bool
	 */
	public static function is_eligible_to_poll( $scan_id ) {
		$deadline = self::get( $scan_id );
		if ( $deadline <= 0 ) {
			return true;
		}
		return time() >= $deadline;
	}
}

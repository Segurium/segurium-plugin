<?php
/**
 * Malware scan lock helper.
 *
 * Option-backed single-slot lock used by Segurium_Scan_Runner to guarantee
 * that only one scan runs at a time across the site, regardless of scan
 * type (manual, scheduled, etc.). The lock carries a heartbeat that the
 * worker refreshes each chunk so a crashed worker can be reclaimed.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Single-slot lock for malware scans.
 */
final class Segurium_Scan_Lock {

	/**
	 * Option key where the lock payload is persisted.
	 */
	const OPTION = 'segurium_scan_lock';

	/**
	 * Hard ceiling for lock age (seconds). A lock older than this is eligible
	 * for reclamation even if the heartbeat somehow kept refreshing.
	 */
	const LOCK_MAX_AGE = 21600;

	/**
	 * Maximum heartbeat staleness (seconds) before the lock is considered
	 * abandoned by a crashed worker. SEGURIUM-399 dropped this from 240 s
	 * to 60 s once {@see Segurium_Verdict_Queue::resolve_and_record()}
	 * started stamping the heartbeat per file (not just at chunk
	 * boundaries). The previous 240 s ceiling was margin around a single
	 * chunk's worst case — tens of seconds for sequential per-file
	 * `/v1/neo-ray` escalations — so a dead worker froze the UI for ~4 min
	 * before the watchdog reclaimed. With per-file heartbeat the longest
	 * legitimate gap is one in-flight Neo-Ray RTT (~30 s cap), so 60 s is
	 * the right margin: tight enough to surface dead-worker stalls within
	 * a minute, loose enough to absorb a single Unknown-verdict file that
	 * spends its full Neo-Ray budget plus normal network jitter / GC.
	 */
	const HEARTBEAT_MAX_AGE = 60;

	/**
	 * Try to acquire the lock for the given scan.
	 *
	 * @param string $scan_id   Scan UUID.
	 * @param string $scan_type Scan type label (e.g. 'manual', 'scheduled').
	 * @return bool True on success, false if a fresh lock is held.
	 */
	public static function acquire( $scan_id, $scan_type ) {
		$existing = self::get();
		if ( self::is_fresh( $existing ) ) {
			return false;
		}

		$now     = time();
		$payload = array(
			'scan_id'            => (string) $scan_id,
			'scan_type'          => (string) $scan_type,
			'started_at'         => $now,
			'heartbeat'          => $now,
			// SEGURIUM-271: 0 means "no observer-driven tick yet". Any
			// caller checking observer freshness will treat this as stale
			// and fall through to its own LSS path.
			'observer_last_seen' => 0,
		);

		Segurium_Storage::setting_set( self::OPTION, $payload );
		return true;
	}

	/**
	 * Refresh the heartbeat for the given scan. When `$is_observer` is true the
	 * `observer_last_seen` field is also stamped in the same option write, so
	 * cron / visitor-pageload entry hooks can cheaply detect that a browser
	 * observer is currently driving the runner and bail (SEGURIUM-271). Folded
	 * into heartbeat() so observer-driven ticks pay zero extra DB writes vs.
	 * the existing per-chunk heartbeat refresh.
	 *
	 * @param string $scan_id     Scan UUID that must match the current lock.
	 * @param bool   $is_observer When true, also update `observer_last_seen` to now.
	 * @return bool True on success, false if the lock is missing or owned by
	 *              another scan.
	 */
	public static function heartbeat( $scan_id, $is_observer = false ) {
		$lock = self::get();
		if ( null === $lock || $lock['scan_id'] !== (string) $scan_id ) {
			return false;
		}
		$now               = time();
		$lock['heartbeat'] = $now;
		if ( $is_observer ) {
			$lock['observer_last_seen'] = $now;
		}
		Segurium_Storage::setting_set( self::OPTION, $lock );
		return true;
	}

	/**
	 * Release the lock unconditionally.
	 *
	 * @return void
	 */
	public static function release() {
		Segurium_Storage::setting_delete( self::OPTION );
	}

	/**
	 * Return the current lock payload, or null when no lock is stored.
	 *
	 * @return array|null
	 */
	public static function get() {
		$raw = Segurium_Storage::setting_get( self::OPTION, null );
		if ( ! is_array( $raw ) || empty( $raw['scan_id'] ) ) {
			return null;
		}
		return array(
			'scan_id'            => (string) $raw['scan_id'],
			'scan_type'          => isset( $raw['scan_type'] ) ? (string) $raw['scan_type'] : '',
			'started_at'         => isset( $raw['started_at'] ) ? (int) $raw['started_at'] : 0,
			'heartbeat'          => isset( $raw['heartbeat'] ) ? (int) $raw['heartbeat'] : 0,
			'observer_last_seen' => isset( $raw['observer_last_seen'] ) ? (int) $raw['observer_last_seen'] : 0,
		);
	}

	/**
	 * Returns true if a scan is currently considered running.
	 *
	 * @return bool
	 */
	public static function is_running() {
		return self::is_fresh( self::get() );
	}

	/**
	 * Whether the given lock snapshot is past its freshness window —
	 * either older than `LOCK_MAX_AGE` overall or with a heartbeat older
	 * than `HEARTBEAT_MAX_AGE`. A `null` lock counts as not-stale (there
	 * is nothing to reclaim).
	 *
	 * SEGURIUM-405: this replaces the old `watchdog_sweep()` helper which
	 * conflated staleness detection with lock release. The runner now
	 * checks `is_stale()` and routes through `Segurium_Scan_Runner::terminate()`
	 * so every termination path goes through one orchestration site.
	 *
	 * @param array|null $lock Lock payload as returned by `get()`.
	 * @return bool
	 */
	public static function is_stale( $lock ) {
		if ( null === $lock ) {
			return false;
		}
		return ! self::is_fresh( $lock );
	}

	/**
	 * Internal freshness check.
	 *
	 * @param array|null $lock Lock payload.
	 * @return bool True if the lock is still considered held.
	 */
	private static function is_fresh( $lock ) {
		if ( null === $lock ) {
			return false;
		}
		$now = time();
		if ( $now - $lock['started_at'] > self::LOCK_MAX_AGE ) {
			return false;
		}
		if ( $now - $lock['heartbeat'] > self::HEARTBEAT_MAX_AGE ) {
			return false;
		}
		return true;
	}
}

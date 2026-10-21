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
	 * abandoned by a crashed worker. Dropped from 240 s
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

	const WRITE_ATTEMPTS = 5;

	/**
	 * The last lock this request read or wrote. Answers get() when a read fails.
	 *
	 * @var array|null
	 */
	private static $last_known = null;

	/**
	 * Try to acquire the lock for the given scan.
	 *
	 * Refuses while any lock within `LOCK_MAX_AGE` exists,
	 * heartbeat ignored. A stale heartbeat is a resume signal for the next
	 * driver tick, not a free slot; overwriting such a lock
	 * left the previous scan's history row at RUNNING forever. Callers that
	 * want the slot of an ancient lock close it through
	 * `Segurium_Scan_Runner::terminate()` first.
	 *
	 * @param string $scan_id   Scan UUID.
	 * @param string $scan_type Scan type label (e.g. 'manual', 'scheduled').
	 * @return bool True when this scan now holds the lock, false otherwise.
	 * @throws Segurium_Storage_Exception When the lock row cannot be read or written.
	 */
	public static function acquire( $scan_id, $scan_type ) {
		$raw = self::read_raw();
		if ( self::is_held( self::decode( $raw ) ) ) {
			return false;
		}

		$now     = time();
		$payload = maybe_serialize(
			array(
				'scan_id'            => (string) $scan_id,
				'scan_type'          => (string) $scan_type,
				'started_at'         => $now,
				'heartbeat'          => $now,
				// 0 means "no observer-driven tick yet". Any
				// caller checking observer freshness will treat this as stale
				// and fall through to its own LSS path.
				'observer_last_seen' => 0,
			)
		);

		$won = null === $raw
			? Segurium_Storage::setting_insert_raw( self::OPTION, $payload )
			: Segurium_Storage::setting_swap_raw( self::OPTION, $raw, $payload );
		if ( $won ) {
			self::$last_known = self::decode( $payload );
		}
		return $won;
	}

	/**
	 * Refresh the heartbeat for the given scan. When `$is_observer` is true the
	 * `observer_last_seen` field is also stamped in the same option write, so
	 * cron / visitor-pageload entry hooks can cheaply detect that a browser
	 * observer is currently driving the runner and bail. Folded
	 * into heartbeat() so observer-driven ticks pay zero extra DB writes vs.
	 * the existing per-chunk heartbeat refresh.
	 *
	 * @param string $scan_id     Scan UUID that must match the current lock.
	 * @param bool   $is_observer When true, also update `observer_last_seen` to now.
	 * @return bool True on success, false if the lock is missing, owned by
	 *              another scan, or could not be written (logged).
	 */
	public static function heartbeat( $scan_id, $is_observer = false ) {
		try {
			for ( $attempt = 0; $attempt < self::WRITE_ATTEMPTS; $attempt++ ) {
				$raw  = self::read_raw();
				$lock = self::decode( $raw );
				if ( null === $lock || $lock['scan_id'] !== (string) $scan_id ) {
					return false;
				}
				$now               = time();
				$lock['heartbeat'] = $now;
				if ( $is_observer ) {
					$lock['observer_last_seen'] = $now;
				}
				$next = maybe_serialize( $lock );
				if ( $next === $raw || Segurium_Storage::setting_swap_raw( self::OPTION, $raw, $next ) ) {
					self::$last_known = $lock;
					return true;
				}
			}
			self::log_failure( 'SCAN_LOCK_HEARTBEAT_CONTENDED', $scan_id, self::WRITE_ATTEMPTS . ' conditional writes lost' );
		} catch ( Segurium_Storage_Exception $e ) {
			self::log_failure( 'SCAN_LOCK_HEARTBEAT_FAILED', $scan_id, $e->getMessage() );
		}
		return false;
	}

	/**
	 * Release the lock held by `$scan_id`. A lock naming another scan stays,
	 * so a late caller cannot free the slot of the scan that replaced it.
	 *
	 * @param string $scan_id Scan UUID that must hold the lock.
	 * @return bool True when this call removed the lock.
	 */
	public static function release( $scan_id ) {
		try {
			for ( $attempt = 0; $attempt < self::WRITE_ATTEMPTS; $attempt++ ) {
				$raw  = self::read_raw();
				$lock = self::decode( $raw );
				if ( null === $lock || $lock['scan_id'] !== (string) $scan_id ) {
					return false;
				}
				if ( Segurium_Storage::setting_delete_raw( self::OPTION, $raw ) ) {
					self::$last_known = null;
					return true;
				}
			}
			self::log_failure( 'SCAN_LOCK_RELEASE_CONTENDED', $scan_id, self::WRITE_ATTEMPTS . ' conditional deletes lost' );
		} catch ( Segurium_Storage_Exception $e ) {
			self::log_failure( 'SCAN_LOCK_RELEASE_FAILED', $scan_id, $e->getMessage() );
		}
		return false;
	}

	/**
	 * Return the current lock payload, or null when no lock is stored. Reads
	 * the database, since a long worker's request cache can hold a lock that
	 * another request has since replaced.
	 *
	 * @return array|null
	 */
	public static function get() {
		try {
			return self::decode( self::read_raw() );
		} catch ( Segurium_Storage_Exception $e ) {
			self::log_failure( 'SCAN_LOCK_READ_FAILED', '', $e->getMessage() );
			return self::$last_known;
		}
	}

	/**
	 * Cheap pre-check through the object cache, for hooks that run on every
	 * request. Can be stale inside a long request; decide with get().
	 *
	 * @return bool True when the cached option names a scan.
	 */
	public static function maybe_held() {
		return null !== self::normalize( Segurium_Storage::setting_get( self::OPTION, null ) );
	}

	/**
	 * Read the lock row from the database and remember it for this request.
	 *
	 * @return string|null Serialized row, or null when absent.
	 * @throws Segurium_Storage_Exception When the read fails.
	 */
	private static function read_raw() {
		$raw              = Segurium_Storage::setting_get_raw( self::OPTION );
		self::$last_known = self::decode( $raw );
		return $raw;
	}

	/**
	 * Log a lock operation that did not complete.
	 *
	 * @param string $code    Error code.
	 * @param string $scan_id Scan UUID, '' when none applies.
	 * @param string $detail  Cause.
	 * @return void
	 */
	private static function log_failure( $code, $scan_id, $detail ) {
		Segurium_Debug::log( sprintf( '[segurium-scan-lock] %s scan=%s: %s', $code, (string) $scan_id, $detail ) );
	}

	/**
	 * Unserialize a stored lock row.
	 *
	 * @param string|null $raw Serialized row, or null when absent.
	 * @return array|null Null for a missing or unreadable row.
	 */
	private static function decode( $raw ) {
		return self::normalize( null === $raw ? null : maybe_unserialize( $raw ) );
	}

	/**
	 * Normalise a lock payload.
	 *
	 * @param mixed $lock Unserialized payload.
	 * @return array|null Null when the payload names no scan.
	 */
	private static function normalize( $lock ) {
		if ( ! is_array( $lock ) || empty( $lock['scan_id'] ) ) {
			return null;
		}
		return array(
			'scan_id'            => (string) $lock['scan_id'],
			'scan_type'          => isset( $lock['scan_type'] ) ? (string) $lock['scan_type'] : '',
			'started_at'         => isset( $lock['started_at'] ) ? (int) $lock['started_at'] : 0,
			'heartbeat'          => isset( $lock['heartbeat'] ) ? (int) $lock['heartbeat'] : 0,
			'observer_last_seen' => isset( $lock['observer_last_seen'] ) ? (int) $lock['observer_last_seen'] : 0,
		);
	}

	/**
	 * Whether a scan currently holds the lock: a lock row exists and its
	 * `started_at` is within `LOCK_MAX_AGE`.
	 *
	 * This no longer reads the heartbeat. A stale heartbeat
	 * means the worker died and the next driver tick takes the scan over
	 * the scan itself is still in progress, so status
	 * consumers (`get_status()`, `ajax_tick()`, REST `/scan-tick`) must keep
	 * reporting it as running. Use {@see is_worker_alive()} to ask whether a
	 * worker is actively advancing it.
	 *
	 * @param array|null $lock Lock snapshot from {@see get()}; re-read when null.
	 * @return bool
	 */
	public static function is_running( $lock = null ) {
		return self::is_held( null === $lock ? self::get() : $lock );
	}

	/**
	 * Whether the lock is held AND its worker heartbeat is within
	 * `HEARTBEAT_MAX_AGE`. False for a stalled (dead-worker) lock that
	 * {@see is_running()} still reports as running.
	 *
	 * @param array|null $lock Lock snapshot from {@see get()}; re-read when null.
	 * @return bool
	 */
	public static function is_worker_alive( $lock = null ) {
		return self::is_fresh( null === $lock ? self::get() : $lock );
	}

	/**
	 * Seconds since the lock heartbeat was last stamped, or 0 when no lock
	 * is held. Clamped at zero so clock drift never yields a negative age.
	 *
	 * @param array|null $lock Lock payload; defaults to the stored lock.
	 * @return int
	 */
	public static function heartbeat_age( $lock = null ) {
		if ( null === $lock ) {
			$lock = self::get();
		}
		if ( null === $lock || (int) $lock['heartbeat'] <= 0 ) {
			return 0;
		}
		return max( 0, time() - (int) $lock['heartbeat'] );
	}

	/**
	 * Whether the given lock snapshot is past its freshness window —
	 * either older than `LOCK_MAX_AGE` overall or with a heartbeat older
	 * than `HEARTBEAT_MAX_AGE`. A `null` lock counts as not-stale (there
	 * is nothing to reclaim).
	 *
	 * This replaces the old `watchdog_sweep()` helper which
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
	 * Internal "lock held" check: a lock exists and is within the
	 * `LOCK_MAX_AGE` ceiling, heartbeat ignored.
	 *
	 * @param array|null $lock Lock payload.
	 * @return bool
	 */
	private static function is_held( $lock ) {
		if ( null === $lock ) {
			return false;
		}
		return ( time() - (int) $lock['started_at'] ) <= self::LOCK_MAX_AGE;
	}

	/**
	 * Internal freshness check: lock held AND heartbeat within
	 * `HEARTBEAT_MAX_AGE`.
	 *
	 * @param array|null $lock Lock payload.
	 * @return bool True if a live worker is considered to hold the lock.
	 */
	private static function is_fresh( $lock ) {
		if ( ! self::is_held( $lock ) ) {
			return false;
		}
		return ( time() - (int) $lock['heartbeat'] ) <= self::HEARTBEAT_MAX_AGE;
	}
}

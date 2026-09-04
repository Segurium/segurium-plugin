<?php
/**
 * Integrity → malware scan chaining.
 *
 * The Free/Pro packaging classifies integrity findings as benign-restore
 * vs malicious-deletion, and that classification is only
 * trustworthy when each file's CTI verdict is fresh. The packaging
 * therefore requires every integrity scan to be preceded by a malware
 * scan no older than 24h.
 *
 * Behaviour: never block — always chain. If the most recent malware scan
 * is older than `STALE_AFTER_SECS`, this helper kicks off a malware scan
 * and queues an integrity scan to run on its completion. The two-step is
 * transparent to the caller; the AJAX layer surfaces a "Running a quick
 * malware scan first" status while the chain is in flight.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static helper that owns the freshness gate and the deferred-start hook.
 */
final class Segurium_Integrity_Chain {

	/**
	 * Window after which an integrity scan must be preceded by a fresh
	 * malware scan. 24 hours.
	 */
	const STALE_AFTER_SECS = 86400;

	/**
	 * Runtime_kv keys. Public so tests and the WP-CLI diagnostics can
	 * inspect/clear them deterministically.
	 */
	const KV_LAST_MALWARE    = 'malware:last_scan';
	const KV_PENDING         = 'integrity:chain_pending';
	const KV_PENDING_TRIGGER = 'integrity:chain_trigger';
	const KV_STATUS_MSG      = 'integrity:chain_status';

	/**
	 * WP-Cron action used to start the deferred integrity scan after the
	 * chained malware scan releases the runner lock. Firing via a
	 * single-event cron rather than calling start() directly from the
	 * completion hook avoids racing the lock.
	 */
	const CHAIN_HOOK = 'segurium_chain_integrity_start';

	/**
	 * Wire up hooks. Called once during plugin bootstrap from
	 * Segurium::register_hooks().
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( self::CHAIN_HOOK, array( __CLASS__, 'fire_pending_integrity_start' ), 10, 1 );
	}

	/**
	 * Whether the most recent malware scan completed within the freshness
	 * window. Returns false when no malware scan has ever completed.
	 *
	 * @return bool
	 */
	public static function is_malware_scan_fresh() {
		$last = self::get_last_malware_scan_at();
		if ( $last <= 0 ) {
			return false;
		}
		return ( time() - $last ) < self::STALE_AFTER_SECS;
	}

	/**
	 * Read the last successful malware scan timestamp (unix seconds).
	 *
	 * @return int 0 when no scan has ever completed.
	 */
	public static function get_last_malware_scan_at() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_LAST_MALWARE )
		);
		return null === $raw ? 0 : (int) $raw;
	}

	/**
	 * Whether a chained integrity scan is queued behind an in-flight
	 * malware scan.
	 *
	 * @return bool
	 */
	public static function is_chain_pending() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_PENDING )
		);
		return null !== $raw && '' !== (string) $raw;
	}

	/**
	 * Start an integrity scan, automatically chaining a malware scan first
	 * when the freshness gate fails. Always non-blocking: the caller never
	 * has to wait for the chained malware scan, the integrity scan kicks
	 * itself off when the chain completes.
	 *
	 * @return array{kind:string,scan_id?:string,message?:string}|WP_Error
	 *         kind = 'integrity' when the integrity scan started directly,
	 *         kind = 'chain'     when a malware scan is running first.
	 */
	public static function start_or_chain() {
		// Always clear stale chain state from a previous interrupted run
		// before evaluating freshness — otherwise a leftover pending flag
		// from an aborted scan could confuse the next user click.
		if ( self::is_chain_pending() && ! Segurium_Scan_Lock::is_running() ) {
			self::clear_pending();
		}

		if ( self::is_malware_scan_fresh() ) {
			$result = Segurium_Scan_Runner::start( 'integrity' );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			return array(
				'kind'    => 'integrity',
				'scan_id' => (string) $result,
			);
		}

		// Stale or never-scanned → chain.
		self::clear_status_message();
		$result = Segurium_Scan_Runner::start( 'manual' );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// Mark chain pending only after the malware scan started — if the
		// runner refused (lock contention, schema, etc.) we must not leave
		// a stale flag behind.
		self::set_pending( (string) $result );

		return array(
			'kind'    => 'chain',
			'scan_id' => (string) $result,
			'message' => __( 'Running a quick malware scan first…', 'segurium' ),
		);
	}

	/**
	 * Called from Segurium::on_scan_completed() after every successful
	 * malware scan. Records the freshness timestamp; if a chain is
	 * pending, schedules the deferred integrity start for ~now via
	 * WP-Cron (so the runner lock has time to release).
	 *
	 * @return void
	 */
	public static function note_malware_completed() {
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_LAST_MALWARE,
				'kv_value'   => (string) $now,
				'expires_at' => null,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);

		if ( ! self::is_chain_pending() ) {
			return;
		}
		$trigger = self::get_pending_trigger();
		self::clear_pending();

		// Defer the integrity start by one cron tick. The completion hook
		// fires before Segurium_Scan_Runner releases the malware lock, so
		// calling start() inline would hit `scan_already_running`. The
		// trigger rides along as the event argument because the marker it
		// came from is already gone by the time the event fires.
		wp_unschedule_hook( self::CHAIN_HOOK );
		wp_schedule_single_event( $now, self::CHAIN_HOOK, array( $trigger ) );
	}

	/**
	 * Called from ajax_stop_scan when the user cancels the in-flight
	 * malware scan. If a chain was queued behind it, clears the pending
	 * flag and writes a status message the next integrity-status poll
	 * surfaces to the UI.
	 *
	 * @return void
	 */
	public static function note_malware_cancelled() {
		if ( ! self::is_chain_pending() ) {
			return;
		}
		self::clear_pending();
		self::set_status_message(
			__( 'The chained malware scan was cancelled — integrity scan was not started.', 'segurium' )
		);
	}

	/**
	 * WP-Cron handler that fires the deferred integrity start after a
	 * chained malware scan completes. Public for the hook callable.
	 *
	 * @param string $trigger Origin recorded when the chain was enrolled.
	 * @return void
	 */
	public static function fire_pending_integrity_start( $trigger = 'manual' ) {
		$result = Segurium_Scan_Runner::start( 'integrity', (string) $trigger );
		if ( is_wp_error( $result ) ) {
			Segurium_Debug::log(
				sprintf(
					'[segurium-integrity-chain] deferred integrity start failed: %s — %s',
					$result->get_error_code(),
					$result->get_error_message()
				)
			);
			self::set_status_message(
				sprintf(
					/* translators: %s: underlying error message */
					__( 'Could not start the chained integrity scan: %s', 'segurium' ),
					$result->get_error_message()
				)
			);
		}
	}

	/**
	 * Pop the chain status message (read-and-clear). Surfaced by the
	 * integrity-status AJAX handler so the JS can render a one-shot
	 * banner about cancellation/failure of the chained malware scan.
	 *
	 * @return string Empty string when no message is queued.
	 */
	public static function pop_status_message() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_STATUS_MSG )
		);
		if ( null === $raw || '' === (string) $raw ) {
			return '';
		}
		self::clear_status_message();
		return (string) $raw;
	}

	/**
	 * Test/debug helper: zero every chain-related runtime_kv key.
	 *
	 * @return void
	 */
	public static function reset_for_testing() {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_LAST_MALWARE ) );
		self::clear_pending();
		self::clear_status_message();
	}

	/**
	 * Mark a malware scan as the head of a chain so its completion can
	 * fan out into a deferred integrity start.
	 *
	 * Public so other entry points (scheduled scans, future automation)
	 * can opt their own malware run into the chain without re-deriving
	 * the runtime_kv plumbing.
	 *
	 * @param string $malware_scan_id Lock scan_id of the chained run.
	 * @param string $trigger         Origin of the follow-up integrity scan,
	 *                                reported to CTI when it runs.
	 */
	public static function set_pending( $malware_scan_id, $trigger = 'manual' ) {
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_PENDING,
				'kv_value'   => (string) $malware_scan_id,
				'expires_at' => null,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_PENDING_TRIGGER,
				'kv_value'   => (string) $trigger,
				'expires_at' => null,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Origin of the queued follow-up. A marker written before this key
	 * existed reads back as 'manual', which is how those runs already
	 * report themselves to CTI.
	 *
	 * @return string
	 */
	public static function get_pending_trigger() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_PENDING_TRIGGER )
		);
		return ( null === $raw || '' === (string) $raw ) ? 'manual' : (string) $raw;
	}

	/**
	 * Drop the pending-chain marker so the next malware completion does
	 * not auto-trigger an integrity scan. It is public so
	 * the unified `Segurium_Scan_Runner::terminate()` can clear the marker
	 * on every termination path (cancel, all aborts, runtime error) — the
	 * marker previously leaked when a chained malware scan was aborted by
	 * watchdog / stale heartbeat / stuck counter, leaving the UI showing
	 * "running" against a dead UUID until the next interactive scan click
	 * triggered the self-heal in `start_or_chain()`.
	 */
	public static function clear_pending() {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_PENDING ) );
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_PENDING_TRIGGER ) );
	}

	/**
	 * Persist a one-shot user-facing message for the next integrity
	 * status poll (cancellation/failure of the chained malware scan).
	 *
	 * @param string $message Translated, user-visible message.
	 */
	private static function set_status_message( $message ) {
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_STATUS_MSG,
				'kv_value'   => (string) $message,
				'expires_at' => null,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Erase any pending status message so it is shown at most once.
	 */
	private static function clear_status_message() {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_STATUS_MSG ) );
	}
}

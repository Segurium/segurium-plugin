<?php
/**
 * Freshness gate between the integrity scan and the malware scan.
 *
 * The Free/Pro packaging classifies integrity findings as benign-restore
 * vs malicious-deletion, and that classification is only
 * trustworthy when each file's CTI verdict is fresh. The packaging
 * therefore requires every integrity scan to be preceded by a malware
 * scan no older than 24h.
 *
 * A start from the Integrity tab never blocks: past `STALE_AFTER_SECS` the
 * run gets the files phase ahead of the integrity phase, under one lock.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static helper that owns the freshness gate and the Integrity tab's notices.
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
	const KV_LAST_MALWARE = 'malware:last_scan';
	const KV_STATUS_MSG   = 'integrity:chain_status';

	/**
	 * Marker rows and WP-Cron hook an updated site can still hold. Nothing writes them.
	 */
	const KV_PENDING         = 'integrity:chain_pending';
	const KV_PENDING_TRIGGER = 'integrity:chain_trigger';
	const CHAIN_HOOK         = 'segurium_chain_integrity_start';

	/**
	 * Trigger value of a run started from the Integrity tab.
	 */
	const TRIGGER = 'integrity_tab';

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
	 * Start a run from the Integrity tab, files phase first when the gate fails.
	 *
	 * @return array{kind:string,scan_id?:string,message?:string}|WP_Error
	 *         kind = 'integrity' when the integrity phase starts the run,
	 *         kind = 'chain'     when the files phase runs first.
	 */
	public static function start_or_chain() {
		self::clear_status_message();
		$fresh  = self::is_malware_scan_fresh();
		$phases = $fresh
			? array( Segurium_Scan_Phase_Integrity::ID )
			: array( Segurium_Scan_Phase_Files::ID, Segurium_Scan_Phase_Integrity::ID );
		$result = Segurium_Scan_Runner::start_run( $phases, self::TRIGGER );
		if ( is_wp_error( $result ) ) {
			// The caller shows the error; a queued notice would repeat it.
			self::clear_status_message();
			return $result;
		}
		if ( $fresh ) {
			return array(
				'kind'    => 'integrity',
				'scan_id' => (string) $result,
			);
		}
		return array(
			'kind'    => 'chain',
			'scan_id' => (string) $result,
			'message' => __( 'Running a quick malware scan first…', 'segurium' ),
		);
	}

	/**
	 * Called from Segurium::on_scan_completed() after every successful
	 * malware scan. Records the freshness timestamp.
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
	}

	/**
	 * A stop skipped the integrity phase: queue the notice for the Integrity tab.
	 *
	 * @return void
	 */
	public static function note_malware_cancelled() {
		self::set_status_message(
			__( 'The chained malware scan was cancelled — integrity scan was not started.', 'segurium' )
		);
	}

	/**
	 * The integrity phase could not start: queue the notice for the Integrity tab.
	 *
	 * @param string $error Underlying error message.
	 * @return void
	 */
	public static function note_integrity_start_failed( $error ) {
		Segurium_Debug::log( '[segurium-integrity-chain] integrity phase did not start: ' . $error );
		self::set_status_message(
			sprintf(
				/* translators: %s: underlying error message */
				__( 'Could not start the chained integrity scan: %s', 'segurium' ),
				(string) $error
			)
		);
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
		self::clear_legacy_marker();
		self::clear_status_message();
	}

	/**
	 * Trigger of the integrity scan a legacy marker queues behind a file scan.
	 *
	 * @param string $scan_id Scan ID holding the lock.
	 * @return string '' when no marker names the scan.
	 */
	public static function legacy_marker_trigger( $scan_id ) {
		$rows = Segurium_Storage::table_get_results(
			'runtime_kv',
			'SELECT kv_key, kv_value FROM {{table}} WHERE kv_key IN ( %s, %s )',
			array( self::KV_PENDING, self::KV_PENDING_TRIGGER ),
			ARRAY_A
		);
		$map  = array_column( $rows, 'kv_value', 'kv_key' );
		if ( ! isset( $map[ self::KV_PENDING ] ) || (string) $map[ self::KV_PENDING ] !== (string) $scan_id ) {
			return '';
		}
		return empty( $map[ self::KV_PENDING_TRIGGER ] ) ? 'manual' : (string) $map[ self::KV_PENDING_TRIGGER ];
	}

	/**
	 * Drop the legacy marker rows.
	 *
	 * @return void
	 */
	public static function clear_legacy_marker() {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_PENDING ) );
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_PENDING_TRIGGER ) );
	}

	/**
	 * Unschedule a legacy deferred-start event. Nothing listens to the hook.
	 *
	 * @return void
	 */
	public static function drop_legacy_event() {
		foreach ( (array) _get_cron_array() as $hooks ) {
			if ( isset( $hooks[ self::CHAIN_HOOK ] ) ) {
				wp_unschedule_hook( self::CHAIN_HOOK );
				return;
			}
		}
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

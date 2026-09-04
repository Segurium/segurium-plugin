<?php
/**
 * Scheduled malware-scan scheduler.
 *
 * Re-arms a single-event WP cron callback at the user's chosen
 * hour/minute (and day-of-week for weekly mode), running the scan
 * through Segurium_Scan_Runner so it shares the same browser-
 * independent worker as a manual scan. The runner's lock provides
 * mutual exclusion with manual scans: a scheduled tick that fires
 * while a manual scan is already running is logged and skipped, NOT
 * queued.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Glue between Segurium_Scheduled_Scan_Settings and the runner.
 */
final class Segurium_Scheduled_Scan {

	const CRON_HOOK = 'segurium_scheduled_scan';
	const LOG_MAX   = 20;

	/**
	 * Wire the cron hook callback. Idempotent.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'run' ) );
	}

	/**
	 * Clear and re-queue the next scheduled-scan firing for the
	 * currently configured hour/minute (and weekly day-of-week).
	 *
	 * Uses wp_schedule_single_event so the timing matches the user's
	 * chosen wall clock instead of drifting under recurring schedule
	 * registration. Each `run()` call re-arms the next firing.
	 *
	 * @return void
	 */
	public static function reschedule() {
		wp_clear_scheduled_hook( self::CRON_HOOK );

		$settings = Segurium_Scheduled_Scan_Settings::get();
		if ( Segurium_Scheduled_Scan_Settings::MODE_OFF === $settings['mode'] ) {
			return;
		}

		$ts = Segurium_Scheduled_Scan_Settings::to_next_timestamp_utc();
		if ( $ts <= 0 ) {
			return;
		}

		wp_schedule_single_event( $ts, self::CRON_HOOK );
	}

	/**
	 * Tear down any pending scheduled scan event. Used on plugin
	 * deactivation and on consent revocation.
	 *
	 * @return void
	 */
	public static function unschedule() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/**
	 * Cron callback. Dispatches a scheduled scan via the runner unless
	 * another scan (manual or scheduled) is already running, in which
	 * case it logs a `scheduled_skipped` event and re-arms the next
	 * firing for the following slot.
	 *
	 * @return void
	 */
	public static function run() {
		try {
			if ( Segurium_Scan_Runner::is_running() ) {
				self::log(
					'scheduled_skipped',
					array(
						'reason' => 'another_scan_running',
						'lock'   => Segurium_Scan_Lock::get(),
					)
				);
				return;
			}

			$result = Segurium_Scan_Runner::start( 'scheduled' );
			if ( is_wp_error( $result ) ) {
				self::log(
					'scheduled_failed',
					array(
						'code'    => $result->get_error_code(),
						'message' => $result->get_error_message(),
					)
				);
			} else {
				// SEGURIUM: a scheduled run is the comprehensive nightly
				// baseline — chain an integrity scan behind the malware
				// scan so component drift is checked on the same cadence.
				// Segurium::on_scan_completed() will fan out via
				// Segurium_Integrity_Chain::note_malware_completed().
				if ( class_exists( 'Segurium_Integrity_Chain' ) ) {
					Segurium_Integrity_Chain::set_pending( (string) $result, 'scheduled' );
				}
				self::log(
					'scheduled_started',
					array( 'scan_id' => $result )
				);
			}
		} catch ( Throwable $e ) {
			self::log(
				'scheduled_exception',
				array(
					'class'   => get_class( $e ),
					'message' => $e->getMessage(),
				)
			);
			Segurium_Debug::log(
				sprintf(
					'[segurium-scheduled-scan] %s: %s',
					get_class( $e ),
					$e->getMessage()
				)
			);
		} finally {
			// Always re-arm so a one-time failure (or skip) doesn't
			// silently disable scheduled scanning forever.
			self::reschedule();
		}
	}

	/**
	 * Append an entry to the bounded scheduled-scan log option.
	 *
	 * @param string $event   Event identifier.
	 * @param array  $details Arbitrary detail map.
	 * @return void
	 */
	public static function log( $event, $details = array() ) {
		$now       = time();
		$scan_uuid = null;
		if ( isset( $details['scan_id'] ) && is_string( $details['scan_id'] ) && '' !== $details['scan_id'] ) {
			$scan_uuid = $details['scan_id'];
		}
		try {
			Segurium_Storage::table_insert(
				'scheduled_scan_log',
				array(
					'scan_uuid'  => $scan_uuid,
					'level'      => self::level_for_event( $event ),
					'message'    => substr(
						wp_json_encode(
							array(
								'event'   => $event,
								'details' => $details,
							)
						),
						0,
						65535
					),
					'created_at' => $now,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-scheduled-scan] log insert failed: ' . $e->getMessage() );
			return;
		}

		// Cap rows on insert so the table stays bounded without relying on GC.
		global $wpdb;
		$table = Segurium_Storage::table_name( 'scheduled_scan_log' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE id NOT IN (SELECT id FROM (SELECT id FROM %i ORDER BY id DESC LIMIT %d) AS keep)', $table, $table, self::LOG_MAX ) );
	}

	/**
	 * Map event identifiers onto the scheduled_scan_log.level vocabulary.
	 *
	 * @param string $event Event identifier.
	 * @return string
	 */
	private static function level_for_event( $event ) {
		if ( false !== strpos( (string) $event, 'failed' ) || false !== strpos( (string) $event, 'exception' ) ) {
			return 'error';
		}
		if ( false !== strpos( (string) $event, 'skipped' ) ) {
			return 'warn';
		}
		return 'info';
	}

	/**
	 * Read the scheduled-scan log entries (most recent last, legacy order).
	 *
	 * @return array
	 */
	public static function get_log() {
		$rows = Segurium_Storage::table_get_results(
			'scheduled_scan_log',
			'SELECT message, created_at FROM {{table}} ORDER BY id ASC LIMIT %d',
			array( self::LOG_MAX ),
			ARRAY_A
		);
		$out  = array();
		foreach ( $rows as $row ) {
			$decoded = json_decode( (string) $row['message'], true );
			if ( ! is_array( $decoded ) ) {
				continue;
			}
			$out[] = array(
				'at'      => (int) $row['created_at'],
				'event'   => $decoded['event'] ?? '',
				'details' => $decoded['details'] ?? array(),
			);
		}
		return $out;
	}
}

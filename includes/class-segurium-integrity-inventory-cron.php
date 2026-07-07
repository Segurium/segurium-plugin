<?php
/**
 * Daily WP-Cron event that pushes the site's component inventory to CTI.
 *
 * Runs once per day independent of scans, so sites that never run an
 * integrity scan still produce a fresh inventory snapshot for CTI. On-scan
 * snapshots (see Segurium_Integrity_Scan_State::start) supply the same
 * signal on the active-scan path.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scheduler + handler for the daily component-inventory snapshot.
 */
final class Segurium_Integrity_Inventory_Cron {

	const HOOK = 'segurium_daily_components_snapshot';

	/**
	 * Wire the hook handler on plugins_loaded. Scheduling itself is driven
	 * by activation (schedule()) and deactivation (unschedule()).
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( self::HOOK, array( __CLASS__, 'run' ) );
	}

	/**
	 * Schedule the daily event. Idempotent — safe to call on every
	 * activation / auto-update bootstrap.
	 *
	 * @return void
	 */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::HOOK );
		}
	}

	/**
	 * Clear the daily event. Called on plugin deactivation.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		$ts = wp_next_scheduled( self::HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::HOOK );
		}
		wp_clear_scheduled_hook( self::HOOK );
	}

	/**
	 * Cron handler — enumerate the inventory and post it to CTI.
	 *
	 * @return void
	 */
	public static function run(): void {
		try {
			$data_dir  = class_exists( 'Segurium_Storage_Fs' ) ? (string) Segurium_Storage_Fs::data_dir() : '';
			$inventory = Segurium_Integrity_Component_Discovery::enumerate_inventory( $data_dir );
			if ( ! empty( $inventory ) ) {
				Segurium_Storage::cti_log_components_inventory( $inventory );
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] daily components snapshot failed: ' . $e->getMessage() );
		}
	}
}

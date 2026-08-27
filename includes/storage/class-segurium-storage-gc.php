<?php
/**
 * Daily cron handler for Layer 3 garbage collection.
 *
 * Scheduled as `segurium_storage_gc` at plugin activation. Sweeps stale tmp
 * workspaces (default 24 h) and rotates every registered backup bucket, then
 * records a single `activity_log` entry summarising the run.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Layer 3 GC cron handler.
 */
class Segurium_Storage_GC {

	const HOOK = 'segurium_storage_gc';

	/**
	 * Wire the cron action. Called once at load time.
	 */
	public static function boot(): void {
		add_action( self::HOOK, array( __CLASS__, 'run' ) );
	}

	/**
	 * Schedule the daily event. Idempotent.
	 */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::HOOK );
		}
	}

	/**
	 * Clear the scheduled event.
	 */
	public static function unschedule(): void {
		wp_clear_scheduled_hook( self::HOOK );
	}

	/**
	 * Cron callback: GC tmp + rotate backups + emit an activity_log line.
	 *
	 * Filter `segurium_storage_tmp_max_age` (seconds) to override the tmp TTL.
	 */
	public static function run(): void {
		$max_age         = (int) apply_filters( 'segurium_storage_tmp_max_age', DAY_IN_SECONDS );
		$tmp_removed     = Segurium_Storage_Tmp::gc( $max_age );
		$backups_removed = Segurium_Storage_Backup::gc();
		$activity_pruned = self::prune_activity_log();
		$stats_pruned    = Segurium_Storage::table_prune_older_than( 'stats_daily', time() - 365 * DAY_IN_SECONDS );
		// Backstop for the async_pending table. A scan's pending
		// rows are normally dropped by cleanup_scan_state() on teardown, but a
		// scan that dies before teardown (the crash-loop this ticket fixes, a
		// fatal, a killed worker) would otherwise leak its rows forever — the
		// table has no expires_at and is never read by a later scan. Any row
		// older than the cutoff belongs to a scan that ended long ago (live
		// scans are bounded by heartbeat-staleness in hours, not days), so it
		// is safe to prune by created_at. Filterable for unusually long scans.
		$pending_max_age = (int) apply_filters( 'segurium_async_pending_max_age', 2 * DAY_IN_SECONDS );
		$pending_pruned  = Segurium_Storage::table_prune_older_than( 'async_pending', time() - $pending_max_age, 'created_at' );

		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => 'storage_gc',
					'severity'   => 0,
					'data_json'  => wp_json_encode(
						array(
							'tmp_removed'     => $tmp_removed,
							'backups_removed' => $backups_removed,
							'activity_pruned' => $activity_pruned,
							'stats_pruned'    => $stats_pruned,
							'pending_pruned'  => $pending_pruned,
							'tmp_max_age'     => $max_age,
						)
					),
					'created_at' => time(),
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( 'Segurium: storage GC failed to log activity: ' . $e->getMessage() );
		}
	}

	/**
	 * Retention matrix (seconds) per activity_log event_type. The fallback
	 * applies to anything not explicitly listed.
	 *
	 * @return array<string, int>
	 */
	public static function activity_retention_seconds(): array {
		/**
		 * Filter per-event-type retention seconds.
		 *
		 * Keys are either exact `event_type` values or a `prefix_*` glob. A
		 * `_default` key applies to anything that doesn't match.
		 *
		 * @param array<string, int> $retention
		 */
		return (array) apply_filters(
			'segurium_activity_log_retention_seconds',
			array(
				'geo_block'       => 30 * DAY_IN_SECONDS,
				'firewall_hit'    => 30 * DAY_IN_SECONDS,
				'brute_force_*'   => 90 * DAY_IN_SECONDS,
				'2fa_*'           => 90 * DAY_IN_SECONDS,
				'info_shield'     => 90 * DAY_IN_SECONDS,
				'scan_started'    => 180 * DAY_IN_SECONDS,
				'scan_finished'   => 180 * DAY_IN_SECONDS,
				'malware_cured'   => 365 * DAY_IN_SECONDS,
				'integrity_fix'   => 365 * DAY_IN_SECONDS,
				'self_check'      => 180 * DAY_IN_SECONDS,
				'storage_gc'      => 30 * DAY_IN_SECONDS,
				'pro_activated'   => 365 * DAY_IN_SECONDS,
				'pro_deactivated' => 365 * DAY_IN_SECONDS,
				'_default'        => 90 * DAY_IN_SECONDS,
			)
		);
	}

	/**
	 * Prune activity_log rows according to {@see activity_retention_seconds()}.
	 *
	 * @return int Rows deleted.
	 */
	private static function prune_activity_log(): int {
		$retention = self::activity_retention_seconds();
		$default   = isset( $retention['_default'] ) ? (int) $retention['_default'] : 90 * DAY_IN_SECONDS;
		$now       = time();
		$removed   = 0;

		global $wpdb;
		$table = Segurium_Storage::table_name( 'activity_log' );

		$handled_exact = array();
		foreach ( $retention as $key => $seconds ) {
			if ( '_default' === $key ) {
				continue;
			}
			$seconds = (int) $seconds;
			if ( $seconds <= 0 ) {
				continue;
			}
			$cutoff = $now - $seconds;
			if ( false !== strpos( $key, '*' ) ) {
				$prefix = rtrim( $key, '*' );
				$like   = $wpdb->esc_like( $prefix ) . '%';
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$n = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE event_type LIKE %s AND created_at < %d', $table, $like, $cutoff ) );
			} else {
				$handled_exact[] = $key;
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				$n = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE event_type = %s AND created_at < %d', $table, $key, $cutoff ) );
			}
			$removed += ( false === $n ? 0 : (int) $n );
		}

		$default_cutoff = $now - $default;
		if ( ! empty( $handled_exact ) ) {
			$placeholders = implode( ',', array_fill( 0, count( $handled_exact ), '%s' ) );
			$args         = array_merge( array( $table ), $handled_exact, array( $default_cutoff ) );
			$sql_body     = 'DELETE FROM %i WHERE event_type NOT IN (' . $placeholders . ") AND event_type NOT LIKE 'brute_force_%%' AND event_type NOT LIKE '2fa_%%' AND created_at < %d";
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL template uses %i for table; placeholders dynamically generated for hardcoded IN-arg count
			$n        = $wpdb->query( $wpdb->prepare( $sql_body, $args ) );
			$removed += ( false === $n ? 0 : (int) $n );
		}

		return $removed;
	}
}

<?php
/**
 * Public REST endpoint /wp-json/segurium/v1/scan-tick.
 *
 * Consumed by mechanisms III (visitor browser) and VI (CTI remote tick).
 * The handler returns the runner's current status synchronously, then flips
 * the observer flag so the existing shutdown handler in
 * {@see Segurium_Scan_Runner::maybe_pageload_tick()} runs the next chunk
 * AFTER fastcgi_finish_request() / litespeed_finish_request() detaches the
 * connection — callers do not block on engine work.
 *
 * Status values are echoed verbatim from the runner / scan history:
 *   running | completed | cancelled | aborted | not_found
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST controller for /wp-json/segurium/v1/scan-tick.
 */
final class Segurium_Rest_Scan_Tick {

	const NAMESPACE_V1 = 'segurium/v1';
	const ROUTE        = '/scan-tick';

	/**
	 * Wire the rest_api_init hook. Idempotent — safe to call multiple times.
	 */
	public static function register_hooks() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	/**
	 * Register the route on the REST server.
	 */
	public static function register_routes() {
		register_rest_route(
			self::NAMESPACE_V1,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle' ),
				'permission_callback' => array( 'Segurium_Scan_Trigger_Auth', 'rest_permission' ),
				'args'                => array(
					'site_id' => array(
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'scan_id' => array(
						'required'          => false,
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);
	}

	/**
	 * REST handler. Returns the documented JSON shape. `site_id` is accepted
	 * and ignored. `scan_id`, when present, scopes the answer
	 * to that scan (see {@see build_payload()}) so CTI never receives
	 * another scan's terminal status for the row it is ticking.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public static function handle( $request ) {
		$scan_id = $request instanceof WP_REST_Request ? (string) $request->get_param( 'scan_id' ) : '';
		$payload = self::build_payload( $scan_id );

		// Mark this request as the runner observer so the existing
		// shutdown handler runs life_support_system('ajax') AFTER
		// fastcgi_finish_request() / litespeed_finish_request() detaches
		// the response. Without this, the shutdown path would either
		// suppress (observer-fresh fast-path) or run as 'pageload' and
		// not stamp observer_last_seen — both leave VI ticks doing no
		// useful chunk work for this site.
		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			Segurium_Scan_Runner::mark_request_as_observer();
		}

		return new WP_REST_Response( $payload, 200 );
	}

	/**
	 * Compute the documented response payload from current runner state.
	 * Pure — does not advance the scan; safe to call from tests.
	 *
	 * `running` = lock held, heartbeat ignored (a stalled lock still answers
	 * running so mechanism VI keeps driving; see Segurium_Scan_Lock::is_running()).
	 *
	 * Per scan_id:
	 *   - scan_id equals the lock's scan_id → `running`;
	 *   - scan_id given and differs → that scan's `scan_history` row status
	 *     (running | completed | cancelled | aborted), or `not_found` when
	 *     no row exists; never another scan's terminal row. A failed lookup
	 *     answers `running` so CTI retries instead of dropping the row;
	 *   - no scan_id → lock status, else newest terminal row, else not_found.
	 *
	 * @param string $scan_id Optional scan UUID from the request body.
	 * @return array{status:string,scan_id:?string,chunks_done:int,chunks_total:int}
	 */
	public static function build_payload( $scan_id = '' ) {
		$scan_id = (string) $scan_id;
		$lock    = Segurium_Scan_Lock::get();
		if ( null !== $lock && Segurium_Scan_Lock::is_running( $lock )
			&& ( '' === $scan_id || (string) $lock['scan_id'] === $scan_id ) ) {
			$status   = self::status_from_runner( $lock );
			$progress = self::progress_from_runner( $lock );
			return array(
				'status'       => $status,
				'scan_id'      => (string) $lock['scan_id'],
				'chunks_done'  => (int) $progress['chunks_done'],
				'chunks_total' => (int) $progress['chunks_total'],
			);
		}

		if ( '' !== $scan_id ) {
			return self::payload_for_scan( $scan_id );
		}

		$terminal = null;
		if ( class_exists( 'Segurium' ) ) {
			$terminal = Segurium::get_instance()->get_last_terminal_scan();
		}
		if ( is_array( $terminal ) ) {
			$terminal_status = isset( $terminal['status'] ) ? (string) $terminal['status'] : '';
			if ( in_array( $terminal_status, Segurium_Scan_Runner::TERMINAL_STATUSES, true ) ) {
				return array(
					'status'       => $terminal_status,
					'scan_id'      => isset( $terminal['scan_id'] ) ? (string) $terminal['scan_id'] : null,
					'chunks_done'  => isset( $terminal['files_verdicted'] ) ? (int) $terminal['files_verdicted'] : 0,
					'chunks_total' => isset( $terminal['files_found'] ) ? (int) $terminal['files_found'] : 0,
				);
			}
		}

		return array(
			'status'       => 'not_found',
			'scan_id'      => null,
			'chunks_done'  => 0,
			'chunks_total' => 0,
		);
	}

	/**
	 * Per-scan answer from `scan_history` for a scan_id that
	 * does not hold the lock.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return array{status:string,scan_id:?string,chunks_done:int,chunks_total:int}
	 */
	private static function payload_for_scan( $scan_id ) {
		global $wpdb;
		$wpdb->last_error = '';
		$row              = Segurium_Storage::table_get_row(
			'scan_history',
			'SELECT status, files_found, files_scanned FROM {{table}} WHERE scan_uuid = %s',
			array( $scan_id ),
			ARRAY_A
		);
		if ( '' !== (string) $wpdb->last_error ) {
			Segurium_Debug::log( '[segurium-rest-scan-tick] scan_history lookup failed: ' . $wpdb->last_error );
			return array(
				'status'       => 'running',
				'scan_id'      => $scan_id,
				'chunks_done'  => 0,
				'chunks_total' => 0,
			);
		}
		$status = is_array( $row ) && isset( $row['status'] ) ? (string) $row['status'] : '';
		$known  = 'running' === $status || in_array( $status, Segurium_Scan_Runner::TERMINAL_STATUSES, true );
		return array(
			'status'       => $known ? $status : 'not_found',
			'scan_id'      => $known ? $scan_id : null,
			'chunks_done'  => $known && isset( $row['files_scanned'] ) ? (int) $row['files_scanned'] : 0,
			'chunks_total' => $known && isset( $row['files_found'] ) ? (int) $row['files_found'] : 0,
		);
	}

	/**
	 * Status string for an active lock. Always 'running' today; reserved
	 * here as a single mapping site if a future lock state (e.g. paused)
	 * lands.
	 *
	 * @param array $lock Lock payload from Segurium_Scan_Lock::get().
	 * @return string
	 */
	private static function status_from_runner( $lock ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- $lock reserved for future state mapping.
		return 'running';
	}

	/**
	 * Best-effort progress proxy for VI consumers — files_verdicted vs.
	 * files_found from the engine progress snapshot. Falls back to
	 * (heartbeat - started_at) seconds if the engine snapshot is empty
	 * (early in the scan or transient state load failure).
	 *
	 * @param array $lock Lock payload from Segurium_Scan_Lock::get().
	 * @return array{chunks_done:int,chunks_total:int}
	 */
	private static function progress_from_runner( $lock ) {
		$snapshot = Segurium_Scan_Runner::get_status();
		$done     = 0;
		$total    = 0;
		if ( is_array( $snapshot ) ) {
			if ( isset( $snapshot['files_verdicted'] ) ) {
				$done = (int) $snapshot['files_verdicted'];
			} elseif ( isset( $snapshot['files_submitted'] ) ) {
				$done = (int) $snapshot['files_submitted'];
			}
			if ( isset( $snapshot['files_found'] ) ) {
				$total = (int) $snapshot['files_found'];
			}
		}
		if ( 0 === $done && isset( $lock['heartbeat'], $lock['started_at'] ) ) {
			$done = max( 0, (int) $lock['heartbeat'] - (int) $lock['started_at'] );
		}
		return array(
			'chunks_done'  => $done,
			'chunks_total' => $total,
		);
	}
}

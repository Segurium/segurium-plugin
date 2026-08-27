<?php
/**
 * Public REST endpoint /wp-json/segurium/v1/scan-spawn.
 *
 * Mechanism V — fire-and-forget self-trigger. The runner's graceful-exit path
 * POSTs to this route so a fresh PHP worker picks up the next chunk without
 * the +5s recurring-cron gap. The handler is one-way: it returns 202 with an
 * empty body and does NOT echo any state. Callers that need scan status use
 * /scan-tick (mechanisms III + VI).
 *
 * The handler marks the request as the runner observer so the existing
 * shutdown handler in {@see Segurium_Scan_Runner::maybe_pageload_tick()}
 * runs `life_support_system('ajax')` AFTER fastcgi_finish_request() /
 * litespeed_finish_request() detaches the connection — same pattern as
 * /scan-tick.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST controller for /wp-json/segurium/v1/scan-spawn.
 */
final class Segurium_Rest_Scan_Spawn {

	const NAMESPACE_V1 = 'segurium/v1';
	const ROUTE        = '/scan-spawn';

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
				'permission_callback' => array( 'Segurium_Scan_Trigger_Auth', 'rest_permission_secret_only' ),
			)
		);
	}

	/**
	 * Full route path (namespace + route) — used by callers that build the
	 * trigger URL.
	 *
	 * @return string
	 */
	public static function route_path() {
		return self::NAMESPACE_V1 . self::ROUTE;
	}

	/**
	 * REST handler. Returns 202 with no body. Marks the request as observer
	 * so the shutdown LSS path runs the next chunk after the response is
	 * detached.
	 *
	 * @param WP_REST_Request $request Incoming request (unused).
	 * @return WP_REST_Response
	 */
	public static function handle( $request ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- REST contract.
		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			Segurium_Scan_Runner::mark_request_as_observer();
		}
		return new WP_REST_Response( null, 202 );
	}
}

<?php
/**
 * Public REST endpoint /wp-json/segurium/v1/actions-poke.
 *
 * CTI calls this to wake the hourly action pull early. The request carries
 * no instructions of its own — the handler only starts the pull, which
 * then fetches and verifies the queue over the normal signed channel. A
 * replayed poke therefore costs one extra pull and nothing else, which is
 * why the body needs no replay defence.
 *
 * WP-Cron is not on the path. On any host that can detach a response —
 * PHP-FPM and LiteSpeed, which is nearly every install — the handler
 * answers 202, closes the connection, and runs the pull itself on
 * shutdown. spawn_cron() was too quiet to depend on: it refuses on a POST
 * under ALTERNATE_WP_CRON, returns false while the doing_cron transient
 * holds its 60-second lock, and fires its loopback to wp-cron.php
 * non-blocking, so a host that blocks that file reports nothing. Hosts
 * with neither detach function keep the schedule-plus-spawn path, which
 * is also what a site running with DISABLE_WP_CRON and a system crontab
 * collects on its next tick.
 *
 * XML-RPC was the original proposal and was rejected: the plugin ships
 * `disable_xmlrpc` in Info Shield and brute-force gating on xmlrpc.php, so
 * the channel would depend on a surface we sell protection against and
 * that many hosts already block.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST controller for /wp-json/segurium/v1/actions-poke.
 */
final class Segurium_Rest_Actions_Poke {

	const NAMESPACE_V1 = 'segurium/v1';
	const ROUTE        = '/actions-poke';

	/**
	 * Which path the site took. CTI records the value, so the set is
	 * closed.
	 */
	const REASON_DETACHED = 'detached';
	const REASON_QUEUED   = 'queued';
	const REASON_RUNNING  = 'already_queued';

	const REASONS = array( self::REASON_DETACHED, self::REASON_QUEUED, self::REASON_RUNNING );

	/**
	 * Denial text for an unsigned or badly signed poke. Only CTI reads
	 * it, so it is not translated.
	 */
	const DENY_UNAUTHORIZED = 'Remote actions require authentication.';

	/**
	 * Wire the rest_api_init hook. Idempotent.
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	/**
	 * Register the route on the REST server.
	 *
	 * @return void
	 */
	public static function register_routes(): void {
		register_rest_route(
			self::NAMESPACE_V1,
			self::ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle' ),
				'permission_callback' => array( __CLASS__, 'rest_permission' ),
			)
		);
	}

	/**
	 * Signature first, consent second.
	 *
	 * The order matters. Answering 403 to an unsigned request would turn
	 * this route into an oracle for whether a site has the channel
	 * switched off — anyone could read that setting off any install, which
	 * is fleet reconnaissance. An anonymous caller therefore always gets
	 * 401 and learns nothing. Only a caller that already proved it holds
	 * the CTI key is told the channel is closed.
	 *
	 * @param WP_REST_Request|mixed $request Incoming request.
	 * @return true|WP_Error
	 */
	public static function rest_permission( $request ) {
		$verified = self::verify_signature( $request );
		if ( true !== $verified ) {
			return $verified;
		}

		if ( '' !== Segurium_Remote_Actions::closed_reason() ) {
			return new WP_Error(
				'segurium_actions_channel_closed',
				'Remote actions are switched off for this site.',
				array( 'status' => 403 )
			);
		}

		return true;
	}

	/**
	 * The CTI Ed25519 proof over the raw request body.
	 *
	 * @param WP_REST_Request|mixed $request Incoming request.
	 * @return true|WP_Error
	 */
	private static function verify_signature( $request ) {
		if ( ! ( $request instanceof WP_REST_Request ) || ! class_exists( 'Segurium_CTI_Signature' ) ) {
			return self::deny( 'segurium_actions_unauthorized', self::DENY_UNAUTHORIZED );
		}

		$sig_b64 = (string) $request->get_header( Segurium_CTI_Signature::HEADER_SIG );
		$ts_str  = (string) $request->get_header( Segurium_CTI_Signature::HEADER_TIMESTAMP );
		$key_id  = (string) $request->get_header( Segurium_CTI_Signature::HEADER_KEY_ID );

		if ( '' === $sig_b64 && '' === $ts_str && '' === $key_id ) {
			return self::deny( 'segurium_actions_unauthorized', self::DENY_UNAUTHORIZED );
		}

		$verified = Segurium_CTI_Signature::verify_signature(
			$sig_b64,
			$ts_str,
			$key_id,
			(string) $request->get_body(),
			'actions-poke'
		);
		if ( true === $verified ) {
			return true;
		}

		return self::deny( $verified->get_error_code(), $verified->get_error_message() );
	}

	/**
	 * Answer immediately, then pull. The pull can end in an upgrader run,
	 * which is far too slow to hold a request open, so the work happens
	 * on shutdown once the connection is detached.
	 *
	 * A host with no way to detach falls back to a scheduled event.
	 * WordPress refuses a duplicate single event inside a 10-minute
	 * window there, so report what actually happened rather than claiming
	 * every poke booked a new one. `already_queued` is not a failure: a
	 * pull is coming either way.
	 *
	 * @return WP_REST_Response
	 */
	public static function handle() {
		if ( self::detach_available() ) {
			add_action( 'shutdown', array( __CLASS__, 'run_detached' ), 1 );
			return self::answer( true, self::REASON_DETACHED );
		}

		$scheduled = wp_schedule_single_event( time(), Segurium_Remote_Actions::HOOK, array( 'poke' ) );
		spawn_cron();

		return self::answer(
			true === $scheduled,
			true === $scheduled ? self::REASON_QUEUED : self::REASON_RUNNING
		);
	}

	/**
	 * Shutdown callback for the detached path. Closes the connection
	 * first so the caller is not held for the length of the work, then
	 * runs the same pull the scheduled event would have run.
	 *
	 * Public because it is a hook callback. Never throws: a fatal here
	 * would land after the response was sent, where nothing can report
	 * it.
	 *
	 * @return void
	 */
	public static function run_detached() {
		self::detach_response();

		try {
			Segurium_Remote_Actions::run( 'poke' );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] detached action pull failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Whether this host can close the response and keep running.
	 *
	 * Filterable so a host whose FPM build misbehaves under a detached
	 * request can force the scheduled-event path back on without editing
	 * the plugin.
	 *
	 * @return bool
	 */
	public static function detach_available() {
		$available = function_exists( 'fastcgi_finish_request' )
			|| function_exists( 'litespeed_finish_request' );

		return (bool) apply_filters( 'segurium_actions_poke_can_detach', $available );
	}

	/**
	 * Close the connection to the caller. Mirrors the scan runner's
	 * detach: PHP-FPM and LSAPI each expose their own call, and bare
	 * mod_php has no portable equivalent.
	 *
	 * @return void
	 */
	private static function detach_response() {
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			@fastcgi_finish_request(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort detach
			return;
		}
		if ( function_exists( 'litespeed_finish_request' ) ) {
			@litespeed_finish_request(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort detach
		}
	}

	/**
	 * Build the 202 body CTI reads.
	 *
	 * @param bool   $scheduled Whether a pull is now coming.
	 * @param string $reason    One of self::REASONS.
	 * @return WP_REST_Response
	 */
	private static function answer( $scheduled, $reason ) {
		return new WP_REST_Response(
			array(
				'scheduled' => (bool) $scheduled,
				'reason'    => $reason,
			),
			202
		);
	}

	/**
	 * Build a 401 WP_Error, preserving the underlying code for debugging.
	 *
	 * @param string $code    Error code.
	 * @param string $message Human-readable message.
	 * @return WP_Error
	 */
	private static function deny( string $code, string $message ): WP_Error {
		return new WP_Error( $code, $message, array( 'status' => 401 ) );
	}
}

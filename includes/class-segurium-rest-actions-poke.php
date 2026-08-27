<?php
/**
 * Public REST endpoint /wp-json/segurium/v1/actions-poke.
 *
 * CTI calls this to wake the hourly action pull early. The request carries
 * no instructions of its own — the handler only schedules the pull, which
 * then fetches and verifies the queue over the normal signed channel. A
 * replayed poke therefore costs one extra pull and nothing else, which is
 * why the body needs no replay defence.
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
				__( 'Remote actions are switched off for this site.', 'segurium' ),
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
			return self::deny( 'segurium_actions_unauthorized', __( 'Remote actions require authentication.', 'segurium' ) );
		}

		$sig_b64 = (string) $request->get_header( Segurium_CTI_Signature::HEADER_SIG );
		$ts_str  = (string) $request->get_header( Segurium_CTI_Signature::HEADER_TIMESTAMP );
		$key_id  = (string) $request->get_header( Segurium_CTI_Signature::HEADER_KEY_ID );

		if ( '' === $sig_b64 && '' === $ts_str && '' === $key_id ) {
			return self::deny( 'segurium_actions_unauthorized', __( 'Remote actions require authentication.', 'segurium' ) );
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
	 * Schedule the pull and answer immediately. The pull itself can end in
	 * an upgrader run, which is far too slow to hold a request open.
	 *
	 * WordPress refuses a duplicate single event inside a 10-minute window,
	 * so report what actually happened rather than claiming every poke
	 * landed. `already_queued` is not a failure — a pull is coming either
	 * way — but CTI should not be told a new one was booked when it wasn't.
	 *
	 * @return WP_REST_Response
	 */
	public static function handle() {
		$scheduled = wp_schedule_single_event( time(), Segurium_Remote_Actions::HOOK, array( 'poke' ) );
		spawn_cron();

		return new WP_REST_Response(
			array(
				'scheduled' => true === $scheduled,
				'reason'    => true === $scheduled ? 'queued' : 'already_queued',
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

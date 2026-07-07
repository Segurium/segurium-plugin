<?php
/**
 * SEGURIUM-607: permission gate for the public scan-trigger REST routes
 * (`/wp-json/segurium/v1/scan-tick` and `/scan-spawn`).
 *
 * Both routes drive server-side scan work and, for scan-tick, disclose scan
 * state. Neither has a logged-in user (the callers are the fire-and-forget
 * loopback self-trigger — mechanism V — and CTI's remote tick worker —
 * mechanism VI), so a user nonce is impossible. Two machine-to-machine
 * proofs are accepted, checked in `rest_permission()`:
 *
 *   1. Loopback self-trigger — a per-site shared secret in the
 *      `segurium_scan_trigger_secret` option, sent verbatim in the
 *      `X-Segurium-Tick-Auth` header and compared with `hash_equals()`.
 *      The secret never leaves the site: the self-trigger POSTs to its own
 *      REST URL.
 *   2. CTI remote tick — an Ed25519 signature over the request body,
 *      verified with the CTI public key the plugin already bundles
 *      ({@see Segurium_CTI_Signature}). No secret is shared with CTI.
 *
 * Anything else is rejected with 401 before the route handler runs, so an
 * unauthenticated caller learns no scan state and never flips the runner
 * observer flag (no work amplification).
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shared permission_callback for the scan-trigger REST routes.
 */
final class Segurium_Scan_Trigger_Auth {

	const SECRET_OPTION = 'segurium_scan_trigger_secret';
	const HEADER_SECRET = 'X-Segurium-Tick-Auth';

	/**
	 * Get the per-site loopback secret, minting it on first use. Stored
	 * non-autoloaded — it is only read on the self-trigger request path,
	 * never on a normal page load.
	 *
	 * @return string 64-char hex secret, or '' if no CSPRNG is available.
	 */
	public static function secret(): string {
		$secret = (string) Segurium_Storage::setting_get( self::SECRET_OPTION, '' );
		if ( '' !== $secret ) {
			return $secret;
		}
		try {
			$secret = bin2hex( random_bytes( 32 ) );
		} catch ( \Exception $e ) {
			return '';
		}
		Segurium_Storage::setting_set( self::SECRET_OPTION, $secret );
		// Re-read: a concurrent request may have won the write race.
		return (string) Segurium_Storage::setting_get( self::SECRET_OPTION, $secret );
	}

	/**
	 * REST permission_callback for `/scan-tick` — accepts either the
	 * loopback secret (mechanism V) or a CTI Ed25519 signature
	 * (mechanism VI). Returns `true` when authenticated, otherwise a 401
	 * `WP_Error` (which suppresses the handler).
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return true|WP_Error
	 */
	public static function rest_permission( $request ) {
		$secret_ok = self::secret_result( $request );
		if ( null !== $secret_ok ) {
			return true === $secret_ok ? true : self::deny_bad_secret();
		}
		return self::verify_cti_signature( $request );
	}

	/**
	 * REST permission_callback for `/scan-spawn` — loopback secret ONLY.
	 * The runner only ever self-triggers this route (mechanism V); CTI
	 * never calls it, so the Ed25519 path is intentionally not accepted,
	 * keeping the spawn route's trust boundary local-only.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return true|WP_Error
	 */
	public static function rest_permission_secret_only( $request ) {
		$secret_ok = self::secret_result( $request );
		if ( null !== $secret_ok ) {
			return true === $secret_ok ? true : self::deny_bad_secret();
		}
		return self::deny( 'segurium_scan_trigger_unauthorized', __( 'Scan trigger requires authentication.', 'segurium' ) );
	}

	/**
	 * Evaluate the loopback-secret proof.
	 *
	 * @param WP_REST_Request|mixed $request Incoming request.
	 * @return bool|null `true` if the header matches, `false` if a
	 *                   non-empty header was supplied but did not match,
	 *                   `null` if no secret header was supplied.
	 */
	private static function secret_result( $request ) {
		$provided = '';
		if ( $request instanceof WP_REST_Request ) {
			$provided = (string) $request->get_header( self::HEADER_SECRET );
		}
		if ( '' === $provided ) {
			return null;
		}
		$expected = self::secret();
		return ( '' !== $expected && hash_equals( $expected, $provided ) );
	}

	/**
	 * 401 for a supplied-but-wrong loopback secret.
	 *
	 * @return WP_Error
	 */
	private static function deny_bad_secret(): WP_Error {
		return self::deny( 'segurium_scan_trigger_bad_secret', __( 'Scan trigger secret did not match.', 'segurium' ) );
	}

	/**
	 * Try the CTI Ed25519 proof (mechanism VI). Delegates the crypto to
	 * {@see Segurium_CTI_Signature::verify_signature()} over the raw
	 * request body, normalising any failure to a 401.
	 *
	 * @param WP_REST_Request|mixed $request Incoming request.
	 * @return true|WP_Error
	 */
	private static function verify_cti_signature( $request ) {
		if ( ! ( $request instanceof WP_REST_Request ) || ! class_exists( 'Segurium_CTI_Signature' ) ) {
			return self::deny( 'segurium_scan_trigger_unauthorized', __( 'Scan trigger requires authentication.', 'segurium' ) );
		}

		$sig_b64 = (string) $request->get_header( Segurium_CTI_Signature::HEADER_SIG );
		$ts_str  = (string) $request->get_header( Segurium_CTI_Signature::HEADER_TIMESTAMP );
		$key_id  = (string) $request->get_header( Segurium_CTI_Signature::HEADER_KEY_ID );

		if ( '' === $sig_b64 && '' === $ts_str && '' === $key_id ) {
			return self::deny( 'segurium_scan_trigger_unauthorized', __( 'Scan trigger requires authentication.', 'segurium' ) );
		}

		$verified = Segurium_CTI_Signature::verify_signature(
			$sig_b64,
			$ts_str,
			$key_id,
			(string) $request->get_body(),
			'scan-tick'
		);
		if ( true === $verified ) {
			return true;
		}

		return self::deny( $verified->get_error_code(), $verified->get_error_message() );
	}

	/**
	 * Build a 401 `WP_Error`, preserving the underlying code for debugging.
	 *
	 * @param string $code    Error code.
	 * @param string $message Human-readable message.
	 * @return WP_Error
	 */
	private static function deny( string $code, string $message ): WP_Error {
		return new WP_Error( $code, $message, array( 'status' => 401 ) );
	}
}

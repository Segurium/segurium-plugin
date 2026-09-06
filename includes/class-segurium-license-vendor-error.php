<?php
/**
 * Recovers the machine-readable code from a Freemius refusal.
 *
 * `activate_license()` reduces the vendor's error object to prose before it
 * returns, and it does so differently on each of its two branches. The
 * response body is the one shape common to both, so the code is read there.
 *
 * The body echoes the submitted licence key back in its `request` block, so
 * only `error.code` is ever kept. Nothing else from the body is stored,
 * logged or returned.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scoped listener over Freemius HTTP responses.
 */
final class Segurium_License_Vendor_Error {

	/**
	 * The two branches of `activate_license()` speak to different hosts: an
	 * install that already has a Freemius user goes to `api.freemius.com`,
	 * and one that does not opts in against `wp.freemius.com`. The second is
	 * the path every field install takes, so matching only the first would
	 * miss every refusal that matters.
	 */
	const VENDOR_DOMAIN = 'freemius.com';

	/**
	 * Last vendor error code seen.
	 *
	 * @var string
	 */
	private $code = '';

	/**
	 * Whether the vendor answered at all while watching. A transport
	 * failure never reaches `http_response`, so "no answer" tells a dead
	 * network apart from a refusal without reading any prose.
	 *
	 * @var bool
	 */
	private $answered = false;

	/**
	 * The registered listener, kept so it can be removed again.
	 *
	 * @var callable|null
	 */
	private $filter = null;

	/**
	 * Start listening. Paired with {@see self::release()}.
	 *
	 * @return void
	 */
	public function watch() {
		if ( null !== $this->filter ) {
			return;
		}
		$this->code     = '';
		$this->answered = false;
		$this->filter   = function ( $response, $args, $url ) {
			unset( $args );
			$this->capture( $response, $url );
			return $response;
		};
		add_filter( 'http_response', $this->filter, 10, 3 );
	}

	/**
	 * Stop listening.
	 *
	 * @return void
	 */
	public function release() {
		if ( null === $this->filter ) {
			return;
		}
		remove_filter( 'http_response', $this->filter, 10 );
		$this->filter = null;
	}

	/**
	 * The last vendor error code seen while watching.
	 *
	 * @return string
	 */
	public function code() {
		return $this->code;
	}

	/**
	 * Whether the vendor answered at all, whatever it said.
	 *
	 * @return bool
	 */
	public function answered() {
		return $this->answered;
	}

	/**
	 * Match the vendor's own domain and nothing that merely looks like it.
	 * Compared on the parsed host with a leading dot, so neither
	 * `freemius.com.evil.test` nor `notfreemius.com` passes.
	 *
	 * @param mixed $host Parsed host component.
	 * @return bool
	 */
	private static function is_vendor_host( $host ) {
		if ( ! is_string( $host ) || '' === $host ) {
			return false;
		}
		$host = strtolower( $host );
		if ( self::VENDOR_DOMAIN === $host ) {
			return true;
		}
		$suffix = '.' . self::VENDOR_DOMAIN;
		return substr( $host, -strlen( $suffix ) ) === $suffix;
	}

	/**
	 * Keep the error code from a vendor response, and nothing else.
	 *
	 * @param mixed  $response WP HTTP response array.
	 * @param string $url      Request URL.
	 * @return void
	 */
	private function capture( $response, $url ) {
		if ( ! self::is_vendor_host( wp_parse_url( (string) $url, PHP_URL_HOST ) ) ) {
			return;
		}
		$this->answered = true;

		// Only a refusal carries a code worth keeping. Ignoring the 2xx
		// traffic the SDK makes in the same window (plan and update
		// probes) stops an unrelated body from being read as this
		// activation's answer.
		if ( (int) wp_remote_retrieve_response_code( $response ) < 400 ) {
			return;
		}

		$body = wp_remote_retrieve_body( $response );
		if ( ! is_string( $body ) || '' === $body ) {
			return;
		}
		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) || ! isset( $decoded['error']['code'] ) ) {
			return;
		}
		$code = $decoded['error']['code'];
		if ( is_string( $code ) && '' !== $code ) {
			$this->code = $code;
		}
	}
}

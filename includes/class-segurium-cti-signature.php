<?php
/**
 * Verify Ed25519 signatures attached to CTI responses (SEGURIUM-192,
 * SEGURIUM-194).
 *
 * A network-adjacent attacker (compromised CA, DNS hijack, rogue TLS
 * proxy) could previously substitute CTI response bodies for the four
 * endpoints whose bytes the plugin persists as remediation content.
 * CTI now signs those bodies with Ed25519; this class rejects any
 * response whose signature does not verify against the bundled public
 * key.
 *
 * Wire format emitted by CTI:
 *   X-Segurium-Signature:            base64 (no padding) of the signature
 *   X-Segurium-Signature-Timestamp:  unix seconds (decimal)
 *   X-Segurium-Signature-Key-Id:     e.g. "v1"
 *   canonical blob = b"segurium-sig-v1\n" + ts + b"\n" + sha256_hex(body)
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ed25519 verifier for CTI response bodies.
 */
class Segurium_CTI_Signature {

	const HEADER_SIG       = 'x-segurium-signature';
	const HEADER_TIMESTAMP = 'x-segurium-signature-timestamp';
	const HEADER_KEY_ID    = 'x-segurium-signature-key-id';
	const CANONICAL_PREFIX = "segurium-sig-v1\n";
	/**
	 * Max clock-skew tolerance in seconds. Caps the replay window; the
	 * ±300 s slack covers a minute of NTP drift plus WP Cron's minute
	 * granularity without being generous enough to be useful to an
	 * attacker with a recorded response.
	 */
	const TIMESTAMP_SKEW_SECS = 300;

	/**
	 * Trust list — `key_id => base64(no-pad) public key`. Ship two
	 * entries during a rotation window so a plugin that hasn't upgraded
	 * yet still verifies CTI responses signed by the new key (and vice
	 * versa).
	 *
	 * NOTE: the public key below was generated alongside the CTI
	 * private seed under SEGURIUM-192. Operator deploys the matching
	 * seed to CTI; there is no credential here — this value is
	 * inherently public.
	 *
	 * @return array<string, string>
	 */
	public static function trust_list(): array {
		$bundled = array(
			'v1' => 'VkLruUJklvyJBtz4ALCVMmYbPPP5h9/YwrTDd6whY8Y',
		);
		/**
		 * Override the trust list of CTI signing keys. Intended for test
		 * harnesses — production sites should never filter this.
		 *
		 * @param array<string, string> $bundled Key-id => base64 (no-pad) pub key.
		 */
		$out = apply_filters( 'segurium_cti_signature_trust_list', $bundled ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- prefix is `segurium_`
		return is_array( $out ) && ! empty( $out ) ? $out : $bundled;
	}

	/**
	 * Verify the signature on an HTTP response returned by
	 * `wp_remote_*`. Returns `true` when the signature is valid,
	 * otherwise a descriptive `WP_Error`.
	 *
	 * The caller is responsible for reading the body with
	 * `wp_remote_retrieve_body( $response )` AFTER this function
	 * returns true — the response object is the authoritative source
	 * for both headers and body bytes.
	 *
	 * @param array|mixed $response wp_remote_* response (associative array).
	 * @param string      $label    Endpoint label for error messages / logs.
	 * @return true|WP_Error
	 */
	public static function verify_response( $response, string $label = 'cti' ) {
		if ( ! is_array( $response ) ) {
			return new WP_Error(
				'cti_signature_no_response',
				/* translators: %s: endpoint label */
				sprintf( __( 'CTI %s: no response to verify.', 'segurium' ), $label )
			);
		}

		$sig_b64 = (string) wp_remote_retrieve_header( $response, self::HEADER_SIG );
		$ts_str  = (string) wp_remote_retrieve_header( $response, self::HEADER_TIMESTAMP );
		$key_id  = (string) wp_remote_retrieve_header( $response, self::HEADER_KEY_ID );
		$body    = (string) wp_remote_retrieve_body( $response );

		return self::verify_signature( $sig_b64, $ts_str, $key_id, $body, $label );
	}

	/**
	 * Core Ed25519 verification over already-extracted header values and
	 * body bytes. Reused by {@see self::verify_response()} (CTI → plugin
	 * response bodies) and by inbound REST authentication where the caller
	 * pulls the headers/body off a `WP_REST_Request` (SEGURIUM-607
	 * mechanism VI scan-tick). Returns `true` on a valid signature, else a
	 * descriptive `WP_Error`.
	 *
	 * @param string $sig_b64 Base64 (padded or no-pad) signature.
	 * @param string $ts_str  Decimal unix-seconds timestamp string.
	 * @param string $key_id  Signing key id (must be in the trust list).
	 * @param string $body    Exact body bytes the signature covers.
	 * @param string $label   Endpoint label for error messages / logs.
	 * @return true|WP_Error
	 */
	public static function verify_signature( string $sig_b64, string $ts_str, string $key_id, string $body, string $label = 'cti' ) {
		if ( '' === $sig_b64 || '' === $ts_str || '' === $key_id ) {
			return new WP_Error(
				'cti_signature_missing',
				/* translators: %s: endpoint label */
				sprintf( __( 'CTI %s: request missing signature headers.', 'segurium' ), $label )
			);
		}

		$trust = self::trust_list();
		if ( ! isset( $trust[ $key_id ] ) ) {
			return new WP_Error(
				'cti_signature_untrusted_key',
				sprintf(
					/* translators: 1: endpoint label, 2: key id from response */
					__( 'CTI %1$s: response signed by untrusted key "%2$s".', 'segurium' ),
					$label,
					$key_id
				)
			);
		}

		$pub = self::b64_decode( $trust[ $key_id ] );
		if ( false === $pub || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pub ) ) {
			return new WP_Error(
				'cti_signature_bad_trust_list',
				__( 'CTI signature trust list is corrupt — public key failed to decode.', 'segurium' )
			);
		}

		$sig = self::b64_decode( $sig_b64 );
		if ( false === $sig || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return new WP_Error(
				'cti_signature_bad_signature',
				sprintf(
					/* translators: %s: endpoint label */
					__( 'CTI %s: signature header malformed.', 'segurium' ),
					$label
				)
			);
		}

		if ( ! preg_match( '/^[0-9]+$/', $ts_str ) ) {
			return new WP_Error(
				'cti_signature_bad_timestamp',
				sprintf(
					/* translators: %s: endpoint label */
					__( 'CTI %s: signature timestamp malformed.', 'segurium' ),
					$label
				)
			);
		}
		$ts   = (int) $ts_str;
		$now  = time();
		$skew = abs( $now - $ts );
		if ( $skew > self::TIMESTAMP_SKEW_SECS ) {
			return new WP_Error(
				'cti_signature_stale',
				sprintf(
					/* translators: 1: endpoint label, 2: skew in seconds */
					__( 'CTI %1$s: signature timestamp is %2$d seconds out of range.', 'segurium' ),
					$label,
					$skew
				)
			);
		}

		$canonical = self::CANONICAL_PREFIX . $ts_str . "\n" . hash( 'sha256', $body );

		$ok = false;
		try {
			$ok = sodium_crypto_sign_verify_detached( $sig, $canonical, $pub );
		} catch ( \SodiumException $e ) {
			return new WP_Error(
				'cti_signature_sodium_error',
				sprintf(
					/* translators: 1: endpoint label, 2: error message */
					__( 'CTI %1$s: libsodium rejected signature (%2$s).', 'segurium' ),
					$label,
					$e->getMessage()
				)
			);
		}

		if ( ! $ok ) {
			return new WP_Error(
				'cti_signature_invalid',
				sprintf(
					/* translators: %s: endpoint label */
					__( 'CTI %s: signature did not verify — response rejected.', 'segurium' ),
					$label
				)
			);
		}

		return true;
	}

	/**
	 * Tolerant base64 decode: CTI emits `STANDARD_NO_PAD`, but be lenient
	 * with padded variants a MITM-free hop might introduce. The encoded
	 * form is also lowercase-sensitive so a case-insensitive compare is
	 * never appropriate here.
	 *
	 * @param string $input Encoded input.
	 * @return string|false
	 */
	private static function b64_decode( string $input ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- verifying signature, strict=true below.
		$decoded = base64_decode( $input, true );
		if ( false === $decoded ) {
			$padded = $input . str_repeat( '=', ( 4 - strlen( $input ) % 4 ) % 4 );
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- strict=true below.
			$decoded = base64_decode( $padded, true );
		}
		return $decoded;
	}
}

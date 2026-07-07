<?php
/**
 * IP address helpers.
 *
 * All custom tables store IPs as BINARY(16). This helper canonicalises any
 * printable IPv4 / IPv6 string into its 16-byte packed form (IPv4 addresses
 * are packed as IPv4-mapped IPv6 — ::ffff:A.B.C.D — so a single column
 * covers both families) and unpacks them back for display.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * IP pack / unpack utilities.
 */
class Segurium_IP {

	/**
	 * Pack a printable IPv4 or IPv6 string into 16 raw bytes.
	 *
	 * @param string $ip Printable address.
	 * @return string|null 16 bytes on success, null on invalid input.
	 */
	public static function pack( string $ip ): ?string {
		$ip = trim( $ip );
		if ( '' === $ip ) {
			return null;
		}
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $bin ) {
			return null;
		}
		if ( 4 === strlen( $bin ) ) {
			// Promote IPv4 to IPv4-mapped IPv6 (::ffff:a.b.c.d).
			$bin = str_repeat( "\0", 10 ) . "\xff\xff" . $bin;
		}
		if ( 16 !== strlen( $bin ) ) {
			return null;
		}
		return $bin;
	}

	/**
	 * Unpack 16 raw bytes back to a printable string.
	 *
	 * IPv4-mapped prefixes (::ffff:0:0/96) are unwrapped to plain IPv4.
	 *
	 * @param string $bin 16-byte packed IP.
	 * @return string|null Printable form or null on invalid input.
	 */
	public static function unpack( string $bin ): ?string {
		if ( 16 !== strlen( $bin ) ) {
			return null;
		}
		if ( "\0\0\0\0\0\0\0\0\0\0\xff\xff" === substr( $bin, 0, 12 ) ) {
			$ipv4 = @inet_ntop( substr( $bin, 12, 4 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $ipv4 ) {
				return null;
			}
			return $ipv4;
		}
		$out = @inet_ntop( $bin ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return false === $out ? null : $out;
	}
}

<?php
/**
 * Bundled Cloudflare published IP ranges (SEGURIUM-194).
 *
 * `Segurium_Geo_Blocker::get_real_ip()` historically honoured
 * `HTTP_CF_CONNECTING_IP` whenever `REMOTE_ADDR` was in the
 * trusted-proxy list. But "trusted proxy" can contain arbitrary CDN,
 * WAF, or reverse-proxy ranges — any one of those would be enough for
 * a spoofed `CF-Connecting-IP` to land on `get_real_ip()`'s output,
 * bypassing the firewall deny-list, brute-force counter, and geo-blocker.
 *
 * This class restricts CF-Connecting-IP honouring to the real
 * Cloudflare ranges. The list ships statically with the plugin and
 * refreshes at release cadence from Cloudflare's published edge
 * IP-ranges documentation. No remote fetch happens at runtime — if
 * the bundled list goes stale, CF-originated traffic silently falls
 * back to the XFF path rather than failing hard.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static matcher for Cloudflare's published edge IP ranges.
 */
class Segurium_Cloudflare_Ranges {

	/**
	 * Cloudflare IPv4 ranges. Source: Cloudflare's published edge
	 * IP-ranges documentation. Snapshot refreshed on 2026-04-24.
	 *
	 * @return string[]
	 */
	public static function ipv4_cidrs(): array {
		return array(
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'172.64.0.0/13',
			'131.0.72.0/22',
		);
	}

	/**
	 * Cloudflare IPv6 ranges. Source: Cloudflare's published edge
	 * IP-ranges documentation. Snapshot refreshed on 2026-04-24.
	 *
	 * @return string[]
	 */
	public static function ipv6_cidrs(): array {
		return array(
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
		);
	}

	/**
	 * Test whether an IP belongs to Cloudflare's published edge ranges.
	 *
	 * Callers must validate `$ip` is a syntactically-valid IP first;
	 * we early-return false on malformed input to keep this hot-path
	 * cheap on every request.
	 *
	 * @param string $ip Candidate IP (IPv4 or IPv6 presentation form).
	 * @return bool
	 */
	public static function contains( string $ip ): bool {
		if ( '' === $ip ) {
			return false;
		}
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $bin ) {
			return false;
		}
		$is_v6 = 16 === strlen( $bin ) && false !== strpos( $ip, ':' );
		$cidrs = $is_v6 ? self::ipv6_cidrs() : self::ipv4_cidrs();
		foreach ( $cidrs as $cidr ) {
			if ( self::match( $bin, $cidr, $is_v6 ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match an IP's binary representation against a CIDR string.
	 *
	 * @param string $bin   Raw bytes of the IP (`inet_pton` output).
	 * @param string $cidr  `prefix/bits` string in the same family.
	 * @param bool   $is_v6 Whether the candidate is v6.
	 * @return bool
	 */
	private static function match( string $bin, string $cidr, bool $is_v6 ): bool {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) ) {
			return false;
		}
		$prefix_bin = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $prefix_bin ) {
			return false;
		}
		if ( strlen( $prefix_bin ) !== strlen( $bin ) ) {
			return false;
		}
		$bits     = (int) $parts[1];
		$max_bits = $is_v6 ? 128 : 32;
		if ( $bits < 0 || $bits > $max_bits ) {
			return false;
		}
		$full_bytes = intdiv( $bits, 8 );
		$rem_bits   = $bits % 8;

		if ( $full_bytes > 0 && 0 !== substr_compare( $bin, $prefix_bin, 0, $full_bytes ) ) {
			return false;
		}
		if ( 0 === $rem_bits ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF;
		return ( ord( $bin[ $full_bytes ] ) & $mask ) === ( ord( $prefix_bin[ $full_bytes ] ) & $mask );
	}
}

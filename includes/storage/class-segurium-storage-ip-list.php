<?php
/**
 * Layer 2 helper — unified IP list table access.
 *
 * Wraps the `ip_list` table with a small CIDR-aware API. Every feature that
 * tracks IPs (firewall allow/block, trusted proxies, brute-force lockouts,
 * geo whitelist, …) writes into this single table via the façade.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Helper for the `ip_list` table.
 */
class Segurium_Storage_IP_List {

	const DEFAULT_CIDR_FLOOR_V4 = 24;
	const DEFAULT_CIDR_FLOOR_V6 = 48;

	/**
	 * Sentinel used when the caller wants a permanent entry. Chosen as the
	 * upper bound of INT UNSIGNED (year 2106) so every "expires in the
	 * future" predicate passes without special-casing NULL in SQL.
	 */
	const EXPIRES_NEVER = 4294967294;

	/**
	 * Insert or refresh a row.
	 *
	 * @param string   $ip         Printable IP (v4, v6, v4-mapped-v6).
	 * @param string   $list_type  `allow`, `block`, `trusted_proxy`, `bf_lockout`, etc.
	 * @param int|null $expires_at Unix seconds, null for permanent entries.
	 * @param string   $reason     Optional human-readable reason (191 chars).
	 * @param string   $source     `manual`, `trusted_proxy_feed`, `geo_feed`, `bf`, `firewall_rule`.
	 * @param int      $cidr_bits  Prefix length (32 for v4 default, 128 for v6).
	 * @return bool
	 */
	public static function add( string $ip, string $list_type, ?int $expires_at = null, string $reason = '', string $source = 'manual', int $cidr_bits = 128 ): bool {
		$bin = Segurium_IP::pack( $ip );
		if ( null === $bin ) {
			return false;
		}
		$cidr_bits = self::clamp_bits( $ip, $cidr_bits );
		$masked    = self::mask_bytes( $bin, $cidr_bits );

		$data = array(
			'ip'         => $masked,
			'cidr_bits'  => $cidr_bits,
			'list_type'  => self::sanitize_list_type( $list_type ),
			'reason'     => '' === $reason ? null : substr( $reason, 0, 191 ),
			'source'     => self::sanitize_source( $source ),
			'hits'       => 0,
			'created_at' => time(),
			'expires_at' => null === $expires_at ? self::EXPIRES_NEVER : (int) $expires_at,
		);
		try {
			Segurium_Storage::table_upsert( 'ip_list', $data, array( 'ip', 'cidr_bits', 'list_type' ) );
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-ip-list] add failed: ' . $e->getMessage() );
			return false;
		}
		Segurium_Storage_IP_List_Cache::bump_version( $data['list_type'] );
		return true;
	}

	/**
	 * Remove a single row keyed on (ip, cidr_bits, list_type).
	 *
	 * @param string $ip         Printable IP.
	 * @param string $list_type  List type.
	 * @param int    $cidr_bits  Prefix length.
	 * @return bool
	 */
	public static function remove( string $ip, string $list_type, int $cidr_bits = 128 ): bool {
		$bin = Segurium_IP::pack( $ip );
		if ( null === $bin ) {
			return false;
		}
		$cidr_bits = self::clamp_bits( $ip, $cidr_bits );
		$masked    = self::mask_bytes( $bin, $cidr_bits );
		$type      = self::sanitize_list_type( $list_type );
		try {
			Segurium_Storage::table_delete(
				'ip_list',
				array(
					'ip'        => $masked,
					'cidr_bits' => $cidr_bits,
					'list_type' => $type,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-ip-list] remove failed: ' . $e->getMessage() );
			return false;
		}
		Segurium_Storage_IP_List_Cache::bump_version( $type );
		return true;
	}

	/**
	 * Match an IP against a list_type honoring CIDR entries.
	 *
	 * Walks /128 → /cidr_floor (v6) or /32 → /cidr_floor (v4) and returns
	 * the first matching non-expired row.
	 *
	 * @param string $ip        Printable IP.
	 * @param string $list_type List type.
	 * @return array|null
	 */
	public static function match( string $ip, string $list_type ): ?array {
		$bin = Segurium_IP::pack( $ip );
		if ( null === $bin ) {
			return null;
		}
		$is_v4 = self::is_v4_mapped( $bin );
		$now   = time();
		$type  = self::sanitize_list_type( $list_type );

		// Only probe prefix lengths that are actually stored for this
		// list_type — typically 1-3 distinct values — so a lookup stays
		// O(distinct_cidrs) + one index probe per value.
		$bits_list = Segurium_Storage::table_get_col(
			'ip_list',
			'SELECT DISTINCT cidr_bits FROM {{table}} WHERE list_type = %s ORDER BY cidr_bits DESC',
			array( $type )
		);
		if ( empty( $bits_list ) ) {
			return null;
		}

		foreach ( $bits_list as $bits ) {
			$bits = (int) $bits;
			if ( $is_v4 && $bits < 96 ) {
				continue;
			}
			$masked = self::mask_bytes( $bin, $bits );
			$row    = Segurium_Storage::table_get_row(
				'ip_list',
				'SELECT id, HEX(ip) AS ip_hex, cidr_bits, list_type, reason, source, hits, created_at, expires_at
				 FROM {{table}}
				 WHERE ip = %s AND cidr_bits = %d AND list_type = %s
				 AND (expires_at IS NULL OR expires_at > %d)
				 LIMIT 1',
				array( $masked, $bits, $type, $now ),
				ARRAY_A
			);
			if ( is_array( $row ) ) {
				return $row;
			}
		}
		return null;
	}

	/**
	 * Paginated listing of a list_type. Expired rows are filtered out.
	 *
	 * @param string $list_type List type.
	 * @param int    $limit     Rows per page (max 500).
	 * @param int    $offset    Offset.
	 * @return array
	 */
	public static function list_rows( string $list_type, int $limit = 100, int $offset = 0 ): array {
		$limit  = max( 1, min( 500, $limit ) );
		$offset = max( 0, $offset );
		return Segurium_Storage::table_get_results(
			'ip_list',
			'SELECT id, HEX(ip) AS ip_hex, cidr_bits, list_type, reason, source, hits, created_at, expires_at
			 FROM {{table}}
			 WHERE list_type = %s AND (expires_at IS NULL OR expires_at > %d)
			 ORDER BY created_at DESC, id DESC
			 LIMIT %d OFFSET %d',
			array( self::sanitize_list_type( $list_type ), time(), $limit, $offset ),
			ARRAY_A
		);
	}

	/**
	 * Count active entries of a list_type.
	 *
	 * @param string $list_type List type.
	 * @return int
	 */
	public static function count( string $list_type ): int {
		$val = Segurium_Storage::table_get_var(
			'ip_list',
			'SELECT COUNT(*) FROM {{table}} WHERE list_type = %s AND (expires_at IS NULL OR expires_at > %d)',
			array( self::sanitize_list_type( $list_type ), time() )
		);
		return (int) $val;
	}

	/**
	 * Delete expired rows.
	 *
	 * @return int Rows removed.
	 */
	public static function gc(): int {
		global $wpdb;
		$table = Segurium_Storage::table_name( 'ip_list' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$n = $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE expires_at IS NOT NULL AND expires_at <= %d', $table, time() ) );
		if ( $n > 0 ) {
			// gc deletes from every list_type at once; we don't know
			// which lost rows. Bump the cache version on every type
			// we currently materialise so stale cache files get
			// rebuilt before the next match.
			foreach ( array( 'trusted_proxy', 'block', 'allow' ) as $type ) {
				Segurium_Storage_IP_List_Cache::bump_version( $type );
			}
		}
		return false === $n ? 0 : (int) $n;
	}

	/**
	 * Replace every row with `source=$source` and `list_type=$list_type` in
	 * one transaction. Used by feeds (trusted-proxies, geo) so the admin UI
	 * never sees a half-replaced list.
	 *
	 * @param string $list_type List type.
	 * @param string $source    Source tag (must be a "feed" source).
	 * @param array  $entries   Array of `['ip' => ..., 'cidr_bits' => ..., 'reason' => ..., 'expires_at' => ...]`.
	 * @return int Rows upserted.
	 */
	public static function replace_feed( string $list_type, string $source, array $entries ): int {
		global $wpdb;
		$table = Segurium_Storage::table_name( 'ip_list' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( 'START TRANSACTION' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE list_type = %s AND source = %s', $table, self::sanitize_list_type( $list_type ), self::sanitize_source( $source ) ) );
		// SEGURIUM-272: feed imports can upsert thousands of rows.
		// Defer the cache version bump until the loop finishes so we
		// write the autoloaded option once instead of once per row.
		Segurium_Storage_IP_List_Cache::suspend_bumps();
		$n = 0;
		foreach ( $entries as $entry ) {
			$ip   = (string) ( $entry['ip'] ?? '' );
			$bits = isset( $entry['cidr_bits'] ) ? (int) $entry['cidr_bits'] : 128;
			if ( '' === $ip ) {
				continue;
			}
			if ( self::add(
				$ip,
				$list_type,
				isset( $entry['expires_at'] ) ? (int) $entry['expires_at'] : null,
				(string) ( $entry['reason'] ?? '' ),
				$source,
				$bits
			) ) {
				++$n;
			}
		}
		Segurium_Storage_IP_List_Cache::resume_bumps();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( 'COMMIT' );
		return $n;
	}

	/**
	 * Whether an IP (packed) is an IPv4-mapped IPv6 address.
	 *
	 * @param string $bin 16-byte binary.
	 * @return bool
	 */
	private static function is_v4_mapped( string $bin ): bool {
		return "\0\0\0\0\0\0\0\0\0\0\xff\xff" === substr( $bin, 0, 12 );
	}

	/**
	 * Clamp prefix bits to the valid range for the given IP family.
	 *
	 * IPv4 addresses stored as IPv4-mapped IPv6 carry a bit-length up to
	 * 128 as well; callers normally pass `/32`..`/0` for v4 and the helper
	 * adds the v4-mapped prefix offset (96).
	 *
	 * @param string $ip   Printable IP.
	 * @param int    $bits Requested prefix bits.
	 * @return int
	 */
	private static function clamp_bits( string $ip, int $bits ): int {
		$is_v4 = false !== strpos( $ip, '.' ) && false === strpos( $ip, ':' );
		if ( $is_v4 ) {
			if ( $bits <= 32 ) {
				$bits += 96;
			}
		}
		if ( $bits < 0 ) {
			$bits = 0;
		}
		if ( $bits > 128 ) {
			$bits = 128;
		}
		return $bits;
	}

	/**
	 * Zero out bits beyond the given prefix length.
	 *
	 * @param string $bin  16-byte binary.
	 * @param int    $bits Prefix length in bits (0..128).
	 * @return string 16 bytes masked.
	 */
	private static function mask_bytes( string $bin, int $bits ): string {
		if ( $bits >= 128 ) {
			return $bin;
		}
		if ( $bits <= 0 ) {
			return str_repeat( "\0", 16 );
		}
		$full_bytes = intdiv( $bits, 8 );
		$remain     = $bits % 8;
		$prefix     = substr( $bin, 0, $full_bytes );
		if ( $remain > 0 ) {
			$mask    = chr( 0xFF & ( 0xFF << ( 8 - $remain ) ) );
			$prefix .= chr( ord( $bin[ $full_bytes ] ) & ord( $mask ) );
		}
		return str_pad( $prefix, 16, "\0" );
	}

	/**
	 * Sanitize a list_type identifier (snake_case, max 20 chars).
	 *
	 * @param string $list_type Input.
	 * @return string
	 */
	private static function sanitize_list_type( string $list_type ): string {
		$list_type = strtolower( preg_replace( '/[^a-z0-9_]/i', '', $list_type ) ?? '' );
		return substr( $list_type, 0, 20 );
	}

	/**
	 * Sanitize a source tag.
	 *
	 * @param string $source Input.
	 * @return string
	 */
	private static function sanitize_source( string $source ): string {
		$source = strtolower( preg_replace( '/[^a-z0-9_]/i', '', $source ) ?? '' );
		return '' === $source ? 'manual' : substr( $source, 0, 40 );
	}
}

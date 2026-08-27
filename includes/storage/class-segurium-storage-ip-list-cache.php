<?php
/**
 * On-disk in-memory IP-list cache.
 *
 * The trusted_proxy and firewall block lists are matched on
 * every request via Geo_Blocker on plugins_loaded@0/@1. The DB-backed
 * `Segurium_Storage_IP_List::match()` does ~1+N queries per call (one
 * for the distinct CIDR widths, one per width); on a site fed by
 * Cloudflare-range or proxy-detector feeds the trusted_proxy list can
 * easily reach 5,000+ entries which makes that match cost ~15-20 ms
 * per request.
 *
 * This class materialises a list_type as a PHP file that returns the
 * entries grouped by cidr_bits. PHP's opcache loads the file once and
 * the match becomes in-memory hash lookups — 0 DB queries, sub-
 * millisecond even for thousands of CIDRs.
 *
 * **Freshness model.** Cache invalidation is via an autoloaded version
 * counter: `segurium_iplist_ver_<type>` (int). Every mutation in
 * `Segurium_Storage_IP_List` bumps the counter; the cache file
 * embeds the counter value it was built at; readers compare two
 * integers (one in memory, one from the included file) and rebuild
 * on mismatch. No DB query on the hot path.
 *
 * Cache files live under `uploads/segurium-data/cache/` and are
 * guarded by the .htaccess / index.php that ensure_layout() drops.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * IP-list on-disk cache materialiser + reader.
 */
class Segurium_Storage_IP_List_Cache {

	const CACHE_VERSION = 1;

	/**
	 * Per-request memoisation of (version, cidrs) keyed by list_type.
	 *
	 * @var array<string, array{ver:int, cidrs:array<int, array<int,string>>}>
	 */
	private static $loaded = array();

	/**
	 * Absolute path of the cache file for a list_type.
	 *
	 * @param string $list_type List type name.
	 * @return string
	 */
	public static function file_path( string $list_type ): string {
		$safe = preg_replace( '/[^a-z0-9_]/', '', strtolower( $list_type ) );
		return Segurium_Storage_Fs::cache_dir() . '/ip-list-' . $safe . '.php';
	}

	/**
	 * The autoloaded option name carrying the version counter.
	 *
	 * @param string $list_type List type name.
	 */
	public static function version_option( string $list_type ): string {
		$safe = preg_replace( '/[^a-z0-9_]/', '', strtolower( $list_type ) );
		return 'segurium_iplist_ver_' . $safe;
	}

	/**
	 * Read the live version counter for a list_type. Hot-path
	 * helper: this is an autoloaded option read so it's served from
	 * the in-memory options cache that WordPress fills once per
	 * request.
	 *
	 * @param string $list_type List type name.
	 */
	public static function current_version( string $list_type ): int {
		return (int) Segurium_Storage::setting_get_int( self::version_option( $list_type ), 0 );
	}

	/**
	 * Bump the version counter. Called by every IP-list mutation.
	 * The autoloaded option keeps growing monotonically; readers
	 * never trust an old cache file because its embedded version
	 * will be lower than the live counter.
	 *
	 * @param string $list_type List type to bump.
	 */
	public static function bump_version( string $list_type ): void {
		$safe = preg_replace( '/[^a-z0-9_]/', '', strtolower( $list_type ) );
		// Bulk callers (replace_feed) wrap their loop with
		// suspend_bumps() / resume_bumps() so they only fire one
		// bump at the end. Per-call mutations always bump immediately.
		if ( self::$bumps_suspended ) {
			self::$pending_bumps[ $safe ] = true;
			return;
		}

		$key = self::version_option( $list_type );
		$cur = (int) Segurium_Storage::setting_get_int( $key, 0 );
		Segurium_Storage::setting_set( $key, $cur + 1, true );
		unset( self::$loaded[ $safe ] );
	}

	/**
	 * Begin a bulk-mutation block: bump_version() calls accumulate
	 * into $pending_bumps and emit one write per list_type when
	 * resume_bumps() runs. Used by replace_feed to avoid writing
	 * the autoloaded option once per row when importing thousands
	 * of CIDRs from a feed.
	 */
	public static function suspend_bumps(): void {
		self::$bumps_suspended = true;
	}

	/**
	 * Flush pending bumps and re-enable per-call bumping.
	 */
	public static function resume_bumps(): void {
		self::$bumps_suspended = false;
		$pending               = self::$pending_bumps;
		self::$pending_bumps   = array();
		foreach ( array_keys( $pending ) as $type ) {
			self::bump_version( $type );
		}
	}

	/**
	 * Reset the in-process state. Used by tests to make sure a
	 * suspend that bailed mid-loop doesn't leak into the next test;
	 * production code never calls this.
	 */
	public static function reset_request_state(): void {
		self::$bumps_suspended = false;
		self::$pending_bumps   = array();
		self::$loaded          = array();
	}

	/**
	 * Defer flag for bump_version().
	 *
	 * @var bool When true, bump_version() defers writes until
	 *           resume_bumps() flushes them.
	 */
	private static $bumps_suspended = false;

	/**
	 * Pending bumps emitted while $bumps_suspended is true.
	 *
	 * @var array<string, bool>
	 */
	private static $pending_bumps = array();

	/**
	 * Materialise the current rows of $list_type to disk. Atomic via
	 * tmp + rename. Returns true on success, false on I/O failure.
	 *
	 * Always called with `current_version()` snapshotted into the
	 * file header — readers compare against the live option to
	 * detect drift since the last rebuild.
	 *
	 * @param string $list_type List type to rebuild.
	 * @return bool
	 */
	public static function rebuild( string $list_type ): bool {
		Segurium_Storage_Fs::ensure_layout();
		$path = self::file_path( $list_type );
		$dir  = dirname( $path );
		if ( ! is_dir( $dir ) ) {
			return false;
		}

		$rows = Segurium_Storage::table_get_results(
			'ip_list',
			'SELECT HEX(ip) AS ip_hex, cidr_bits, expires_at FROM {{table}}
			 WHERE list_type = %s AND (expires_at IS NULL OR expires_at > %d)',
			array( $list_type, time() ),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			$rows = array();
		}

		$grouped = array();
		foreach ( $rows as $r ) {
			$bin = isset( $r['ip_hex'] ) ? (string) $r['ip_hex'] : '';
			$bin = is_string( $bin ) && '' !== $bin ? hex2bin( $bin ) : false;
			if ( false === $bin || 16 !== strlen( $bin ) ) {
				continue;
			}
			$bits               = (int) $r['cidr_bits'];
			$grouped[ $bits ]   = $grouped[ $bits ] ?? array();
			$grouped[ $bits ][] = $bin;
		}
		// Sort widths DESC so the most-specific match wins (mirrors
		// `ORDER BY cidr_bits DESC` in the SQL matcher).
		krsort( $grouped, SORT_NUMERIC );

		$ver   = self::current_version( $list_type );
		$body  = "<?php\n";
		$body .= "// Segurium IP-list cache. AUTO-GENERATED — do not edit.\n";
		$body .= '// list_type=' . $list_type . ' cache_version=' . self::CACHE_VERSION . ' data_version=' . $ver . "\n";
		$body .= "if ( ! defined( 'ABSPATH' ) ) { exit; }\n";
		$body .= "return array(\n";
		$body .= "\t'version' => " . self::CACHE_VERSION . ",\n";
		$body .= "\t'data_ver' => " . $ver . ",\n";
		$body .= "\t'cidrs' => array(\n";
		foreach ( $grouped as $bits => $bins ) {
			$body .= "\t\t" . (int) $bits . " => array(\n";
			foreach ( $bins as $b ) {
				$body .= "\t\t\t\"" . self::escape_binary( $b ) . "\",\n";
			}
			$body .= "\t\t),\n";
		}
		$body .= "\t),\n";
		$body .= ");\n";

		$tmp = $path . '.tmp.' . wp_generate_password( 8, false, false );
		if ( false === Segurium_Fs::write( $tmp, $body, LOCK_EX ) ) {
			return false;
		}
		if ( ! Segurium_Fs::rename( $tmp, $path ) ) {
			wp_delete_file( $tmp );
			return false;
		}
		$safe = preg_replace( '/[^a-z0-9_]/', '', strtolower( $list_type ) );
		unset( self::$loaded[ $safe ] );
		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $path, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		return true;
	}

	/**
	 * Match $ip against the cached $list_type. Returns
	 * `[ip_hex, cidr_bits]` on hit, null on miss.
	 *
	 * Hot path: free option read (`current_version`) → if the file
	 * is fresh, in-memory CIDR walk. If the file is stale or
	 * missing, rebuild() and retry once.
	 *
	 * @param string $ip        Printable IP.
	 * @param string $list_type One of trusted_proxy / block / allow.
	 * @return array|null
	 */
	public static function match( string $ip, string $list_type ): ?array {
		$bin = Segurium_IP::pack( $ip );
		if ( null === $bin ) {
			return null;
		}
		$cidrs = self::load( $list_type );
		if ( null === $cidrs ) {
			return null;
		}

		$is_v4 = self::is_v4_mapped( $bin );
		foreach ( $cidrs as $bits => $needles ) {
			$bits = (int) $bits;
			if ( $is_v4 && $bits < 96 ) {
				continue;
			}
			$masked = self::mask_bytes( $bin, $bits );
			if ( in_array( $masked, $needles, true ) ) {
				return array( bin2hex( $masked ), $bits );
			}
		}
		return null;
	}

	/**
	 * Return the in-memory grouped-CIDR map for a list_type, lazily
	 * loading and rebuilding as necessary. Null when the rebuild
	 * fails too (caller should fall back to the DB matcher).
	 *
	 * @param string $list_type List type to load.
	 * @return array<int, array<int,string>>|null
	 */
	private static function load( string $list_type ) {
		$safe = preg_replace( '/[^a-z0-9_]/', '', strtolower( $list_type ) );
		$live = self::current_version( $list_type );
		if ( isset( self::$loaded[ $safe ] ) && self::$loaded[ $safe ]['ver'] === $live ) {
			return self::$loaded[ $safe ]['cidrs'];
		}

		$path = self::file_path( $list_type );
		if ( is_readable( $path ) ) {
			$data = include $path;
			if (
				is_array( $data )
				&& isset( $data['data_ver'], $data['cidrs'] )
				&& (int) $data['data_ver'] === $live
				&& is_array( $data['cidrs'] )
			) {
				self::$loaded[ $safe ] = array(
					'ver'   => $live,
					'cidrs' => $data['cidrs'],
				);
				return $data['cidrs'];
			}
		}

		// Cache stale or missing — rebuild, then retry once.
		if ( ! self::rebuild( $list_type ) ) {
			return null;
		}
		$data = include $path;
		if (
			! is_array( $data )
			|| ! isset( $data['data_ver'], $data['cidrs'] )
			|| ! is_array( $data['cidrs'] )
		) {
			return null;
		}
		self::$loaded[ $safe ] = array(
			'ver'   => (int) $data['data_ver'],
			'cidrs' => $data['cidrs'],
		);
		return $data['cidrs'];
	}

	/**
	 * Drop the cache file and reset memoisation. Used by tests and
	 * by uninstall.
	 *
	 * @param string $list_type List type to purge.
	 */
	public static function purge( string $list_type ): void {
		$path = self::file_path( $list_type );
		if ( file_exists( $path ) ) {
			wp_delete_file( $path );
		}
		$safe = preg_replace( '/[^a-z0-9_]/', '', strtolower( $list_type ) );
		unset( self::$loaded[ $safe ] );
	}

	/**
	 * Mask a packed 16-byte IP to its first $bits bits. Same logic
	 * as Segurium_Storage_IP_List::mask_bytes (kept private there).
	 *
	 * @param string $bin  16-byte packed IP.
	 * @param int    $bits Prefix length in bits.
	 */
	private static function mask_bytes( string $bin, int $bits ): string {
		$bytes = (int) ( $bits / 8 );
		$rem   = $bits % 8;
		$out   = substr( $bin, 0, $bytes );
		if ( $rem > 0 && $bytes < 16 ) {
			$mask = chr( 0xFF << ( 8 - $rem ) & 0xFF );
			$out .= ( $bin[ $bytes ] & $mask );
			++$bytes;
		}
		return str_pad( $out, 16, "\x00" );
	}

	/**
	 * IPv4-mapped detection: ::ffff:0:0/96.
	 *
	 * @param string $bin 16-byte packed IP.
	 */
	private static function is_v4_mapped( string $bin ): bool {
		return 16 === strlen( $bin )
			&& "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" === substr( $bin, 0, 12 );
	}

	/**
	 * Quote a 16-byte string for inclusion as a PHP double-quoted
	 * literal. Every byte goes through `\xNN` so the file stays
	 * valid even when the bin contains nulls / control bytes /
	 * backslashes.
	 *
	 * @param string $bin 16-byte packed IP.
	 */
	private static function escape_binary( string $bin ): string {
		$out = '';
		$len = strlen( $bin );
		for ( $i = 0; $i < $len; $i++ ) {
			$out .= sprintf( '\\x%02x', ord( $bin[ $i ] ) );
		}
		return $out;
	}
}

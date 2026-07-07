<?php
/**
 * Binary geo-IP database reader.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provides IP-to-country lookups using a compact binary database.
 */
class Segurium_Geo_DB {

	const MAGIC       = 'SGGE';
	const VERSION     = "\x01";
	const HEADER_SIZE = 13;
	const RECORD_SIZE = 34;
	const IPV4_PREFIX = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff";

	/** 24 hours. */
	const TRANSIENT_TTL = 86400;

	/**
	 * Optional override for the database file path.
	 *
	 * @var string|null
	 */
	private static $db_path_override = null;

	/**
	 * Total record count read from the database header.
	 *
	 * @var int|null
	 */
	private static $record_count = null;

	/**
	 * Open file handle for the binary database.
	 *
	 * @var resource|null
	 */
	private static $db_handle = null;

	/**
	 * In-process lookup cache keyed by IP hash.
	 *
	 * @var array
	 */
	private static $cache = array();

	/**
	 * Override DB path (for tests).
	 *
	 * @param string|null $path Database file path or null to reset.
	 */
	public static function set_db_path( $path ) {
		self::$db_path_override = $path;
		self::$record_count     = null;
		if ( self::$db_handle ) {
			Segurium_Fs::close( self::$db_handle );
			self::$db_handle = null;
		}
	}

	/**
	 * Clear in-process and transient caches (for tests).
	 */
	public static function clear_cache() {
		self::$cache = array();
	}

	/**
	 * Normalise an IP address to a 16-byte big-endian binary string.
	 * IPv4 addresses are mapped to ::ffff:x.x.x.x.
	 *
	 * @param string $ip Human-readable IP address.
	 * @return string|false 16-byte binary string, or false on invalid input.
	 */
	public static function normalize_ip( $ip ) {
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $bin ) {
			return false;
		}
		if ( 4 === strlen( $bin ) ) {
			return self::IPV4_PREFIX . $bin;
		}
		return $bin;
	}

	/**
	 * Test whether an IP address falls within a CIDR range.
	 *
	 * @param string $ip   IP address (IPv4 or IPv6).
	 * @param string $cidr CIDR notation (e.g. '192.168.1.0/24' or '2001:db8::/32').
	 * @return bool
	 */
	public static function ip_in_cidr( $ip, $cidr ) {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) ) {
			return false;
		}

		$net_raw = @inet_pton( $parts[0] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $net_raw ) {
			return false;
		}

		$ip_bin  = self::normalize_ip( $ip );
		$net_bin = self::normalize_ip( $parts[0] );
		$prefix  = (int) $parts[1];

		if ( false === $ip_bin || false === $net_bin ) {
			return false;
		}

		// IPv4 CIDR prefix refers to IPv4 bits; add 96 for the ::ffff: mapping.
		if ( 4 === strlen( $net_raw ) ) {
			$prefix += 96;
		}

		if ( $prefix < 0 || $prefix > 128 ) {
			return false;
		}

		$full_bytes = intdiv( $prefix, 8 );
		$rem_bits   = $prefix % 8;

		if ( substr( $ip_bin, 0, $full_bytes ) !== substr( $net_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( $rem_bits > 0 ) {
			$mask = 0xff << ( 8 - $rem_bits ) & 0xff;
			if ( ( ord( $ip_bin[ $full_bytes ] ) & $mask ) !== ( ord( $net_bin[ $full_bytes ] ) & $mask ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Look up the ISO 3166-1 alpha-2 country code for an IP address.
	 *
	 * @param string $ip Human-readable IP address.
	 * @return string|null Country code or null if not found / DB unavailable.
	 */
	public static function get_country( $ip ) {
		$ip_bin = self::normalize_ip( $ip );
		if ( false === $ip_bin ) {
			return null;
		}

		$cache_key = substr( md5( $ip_bin ), 0, 12 );

		if ( array_key_exists( $cache_key, self::$cache ) ) {
			return self::$cache[ $cache_key ];
		}

		$transient_key = 'segurium_geo_' . $cache_key;
		$cached        = get_transient( $transient_key );
		if ( false !== $cached ) {
			self::$cache[ $cache_key ] = ( '' === $cached ) ? null : $cached;
			return self::$cache[ $cache_key ];
		}

		$country = self::lookup_in_db( $ip_bin );

		self::$cache[ $cache_key ] = $country;
		set_transient( $transient_key, ( null === $country ) ? '' : $country, self::TRANSIENT_TTL );

		return $country;
	}

	/**
	 * Get the path to the binary geo database file.
	 *
	 * @return string File path.
	 */
	private static function get_db_path() {
		if ( null !== self::$db_path_override ) {
			return self::$db_path_override;
		}
		$upload_dir = wp_upload_dir();
		$basedir    = $upload_dir['basedir'] ?? '';
		return $basedir . '/segurium-data/geo/geo.bin';
	}

	/**
	 * Open the binary database and read the header.
	 *
	 * @return bool True if the database is ready for queries.
	 */
	private static function open_db() {
		if ( self::$db_handle && null !== self::$record_count ) {
			return true;
		}

		$path = self::get_db_path();
		if ( ! file_exists( $path ) ) {
			return false;
		}

		$fh = Segurium_Fs::open( $path, 'rb' );
		if ( ! $fh ) {
			return false;
		}

		$header = Segurium_Fs::get( $fh, self::HEADER_SIZE );
		if ( strlen( $header ) < self::HEADER_SIZE ) {
			Segurium_Fs::close( $fh );
			return false;
		}

		if ( self::MAGIC !== substr( $header, 0, 4 ) || self::VERSION !== $header[4] ) {
			Segurium_Fs::close( $fh );
			return false;
		}

		$unpacked           = unpack( 'Vlo/Vhi', substr( $header, 5, 8 ) );
		self::$record_count = $unpacked['lo']; // High word ignored; count fits in uint32 for practical DB sizes.
		self::$db_handle    = $fh;

		return true;
	}

	/**
	 * Perform a binary search in the database for the given IP.
	 *
	 * @param string $ip_bin 16-byte binary IP address.
	 * @return string|null Two-character country code or null.
	 */
	private static function lookup_in_db( $ip_bin ) {
		if ( ! self::open_db() ) {
			return null;
		}

		$lo = 0;
		$hi = self::$record_count - 1;

		while ( $lo <= $hi ) {
			$mid    = intdiv( $lo + $hi, 2 );
			$offset = self::HEADER_SIZE + $mid * self::RECORD_SIZE;

			fseek( self::$db_handle, $offset );
			$record = Segurium_Fs::get( self::$db_handle, self::RECORD_SIZE );
			if ( strlen( $record ) < self::RECORD_SIZE ) {
				break;
			}

			$start   = substr( $record, 0, 16 );
			$end     = substr( $record, 16, 16 );
			$country = substr( $record, 32, 2 );

			if ( strcmp( $ip_bin, $start ) < 0 ) {
				$hi = $mid - 1;
			} elseif ( strcmp( $ip_bin, $end ) > 0 ) {
				$lo = $mid + 1;
			} else {
				return $country;
			}
		}

		return null;
	}
}

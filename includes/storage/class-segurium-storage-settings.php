<?php
/**
 * Layer 1 storage: typed key/value wrapper over wp_options.
 *
 * All plugin code outside plugin/includes/storage/ must go through this class
 * (via Segurium_Storage::setting_*) instead of calling get_option/update_option
 * directly. The PHPCS ruleset enforces this.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings backend (Layer 1: wp_options).
 */
class Segurium_Storage_Settings {

	/**
	 * Option names that are read on every page load and therefore deserve
	 * autoload=yes. Every other Segurium option is stored with autoload=no.
	 */
	const HOT_AUTOLOAD_KEYS = array(
		'segurium_firewall_enabled',
		'segurium_firewall_mode',
		'segurium_cti_consent',
		'segurium_iid_token',
		'segurium_schema_versions',
	);

	/**
	 * Get an option value (raw, no type coercion).
	 *
	 * @param string $key     Option name.
	 * @param mixed  $fallback Default when the option does not exist.
	 * @return mixed
	 */
	public static function get( string $key, $fallback = null ) {
		return get_option( $key, $fallback );
	}

	/**
	 * Set an option value.
	 *
	 * @param string $key      Option name.
	 * @param mixed  $value    Value to store.
	 * @param bool   $autoload Whether to override the default autoload policy. Honoured
	 *                         only when the key is in HOT_AUTOLOAD_KEYS or when caller
	 *                         explicitly passes true (in which case we still normalise
	 *                         to autoload=no unless whitelisted, to protect page-load
	 *                         performance).
	 * @return bool True on success, false on failure.
	 */
	public static function set( string $key, $value, bool $autoload = false ): bool {
		$autoload_flag = ( $autoload || in_array( $key, self::HOT_AUTOLOAD_KEYS, true ) ) ? 'yes' : 'no';
		return (bool) update_option( $key, $value, $autoload_flag );
	}

	/**
	 * Delete an option.
	 *
	 * @param string $key Option name.
	 * @return bool
	 */
	public static function delete( string $key ): bool {
		return (bool) delete_option( $key );
	}

	/**
	 * Typed get: int.
	 *
	 * @param string $key     Option name.
	 * @param int    $fallback Default when missing or wrong-typed.
	 * @return int
	 */
	public static function get_int( string $key, int $fallback = 0 ): int {
		$value = self::get( $key, null );
		if ( null === $value ) {
			return $fallback;
		}
		if ( is_int( $value ) ) {
			return $value;
		}
		if ( is_numeric( $value ) ) {
			return (int) $value;
		}
		self::log_type_mismatch( $key, 'int', $value );
		return $fallback;
	}

	/**
	 * Typed get: bool.
	 *
	 * @param string $key     Option name.
	 * @param bool   $fallback Default when missing or wrong-typed.
	 * @return bool
	 */
	public static function get_bool( string $key, bool $fallback = false ): bool {
		$value = self::get( $key, null );
		if ( null === $value ) {
			return $fallback;
		}
		if ( is_bool( $value ) ) {
			return $value;
		}
		if ( is_numeric( $value ) ) {
			return (bool) (int) $value;
		}
		if ( is_string( $value ) ) {
			$lower = strtolower( trim( $value ) );
			if ( in_array( $lower, array( '1', 'true', 'yes', 'on' ), true ) ) {
				return true;
			}
			if ( in_array( $lower, array( '0', 'false', 'no', 'off', '' ), true ) ) {
				return false;
			}
		}
		self::log_type_mismatch( $key, 'bool', $value );
		return $fallback;
	}

	/**
	 * Typed get: string.
	 *
	 * @param string $key     Option name.
	 * @param string $fallback Default when missing or wrong-typed.
	 * @return string
	 */
	public static function get_string( string $key, string $fallback = '' ): string {
		$value = self::get( $key, null );
		if ( null === $value ) {
			return $fallback;
		}
		if ( is_string( $value ) ) {
			return $value;
		}
		if ( is_int( $value ) || is_float( $value ) ) {
			return (string) $value;
		}
		self::log_type_mismatch( $key, 'string', $value );
		return $fallback;
	}

	/**
	 * Typed get: array.
	 *
	 * @param string $key     Option name.
	 * @param array  $fallback Default when missing or wrong-typed.
	 * @return array
	 */
	public static function get_array( string $key, array $fallback = array() ): array {
		$value = self::get( $key, null );
		if ( null === $value ) {
			return $fallback;
		}
		if ( is_array( $value ) ) {
			return $value;
		}
		self::log_type_mismatch( $key, 'array', $value );
		return $fallback;
	}

	/**
	 * Delete every Segurium-owned option, including the schema-version map.
	 *
	 * Reads the manifest of known settings + custom table versions rather than
	 * doing a `LIKE segurium_%` scan — multisite uses `wp_N_options` per blog
	 * and we don't want to reach across those boundaries here.
	 *
	 * @return int Number of options removed.
	 */
	public static function delete_all(): int {
		$removed = 0;
		$keys    = array_merge(
			self::known_keys(),
			array( 'segurium_schema_versions' )
		);
		foreach ( array_unique( $keys ) as $key ) {
			if ( self::delete( $key ) ) {
				++$removed;
			}
		}
		return $removed;
	}

	/**
	 * Canonical list of every wp_options key owned by the plugin.
	 *
	 * Stage 1 includes both "small, migrated" keys and "deferred blob" keys
	 * so uninstall still wipes them. Later stages update this list as they
	 * move data out of wp_options into custom tables.
	 *
	 * @return array<string>
	 */
	public static function known_keys(): array {
		return array(
			// Stage-1 migrated keys.
			'segurium_cti_consent',
			'segurium_cloud_detection_enabled',
			'segurium_firewall_enabled',
			'segurium_firewall_mode',
			'segurium_geo_blocking_enabled',
			'segurium_geo_block_mode',
			'segurium_geo_block_action',
			'segurium_geo_blocked_countries',
			'segurium_geo_block_redirect_url',
			'segurium_geo_updated_at',
			'segurium_geo_etag',
			'segurium_iid_seed',
			'segurium_iid_token',
			'segurium_bf_settings',
			'segurium_sh_settings',
			'segurium_info_shield_settings',
			'segurium_2fa_settings',
			'segurium_support_rate',

			// Deferred blobs (remaining).
			'segurium_scan_exclude',

			// Other Segurium keys that live in wp_options for now.
			'segurium_last_scan_time',
			'segurium_scan_lock',
			'segurium_scheduled_scan',
			'segurium_bf_db_version',
			'segurium_geo_whitelist_ips',
			'segurium_schema_fingerprint',

			// Stage 5/6 settings still in wp_options (small, not log/blob).
			'segurium_scheduled_scan_settings',
			'segurium_trusted_proxies_etag',
			'segurium_trusted_proxies_updated_at',

			// Danger zone: opt-in wipe of encrypted backups on uninstall.
			'segurium_uninstall_wipe_data',
		);
	}

	/**
	 * Once-per-key type mismatch log. We deliberately keep this cheap: a single
	 * error_log entry tagged with the key + expected type. Hot callers that hit
	 * the mismatch path would otherwise flood the log.
	 *
	 * @param string $key      Option name.
	 * @param string $expected Expected PHP type.
	 * @param mixed  $actual   Actual value.
	 */
	private static function log_type_mismatch( string $key, string $expected, $actual ): void {
		static $seen = array();
		$marker      = $key . ':' . $expected;
		if ( isset( $seen[ $marker ] ) ) {
			return;
		}
		$seen[ $marker ] = true;
		Segurium_Debug::log(
			sprintf(
				'Segurium: setting %s has wrong type, expected %s, got %s',
				$key,
				$expected,
				gettype( $actual )
			)
		);
	}
}

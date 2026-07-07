<?php
/**
 * Migration adapter for Wordfence Security.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Imports scan exclusions, country blocks, and IP blocks from Wordfence.
 */
class Segurium_Migration_Wordfence extends Segurium_Migration_Source {

	/** Block type constant: manual IP block (wfBlock::TYPE_IP_MANUAL). */
	const TYPE_IP_MANUAL = 1;

	/** Block type constant: country block (wfBlock::TYPE_COUNTRY). */
	const TYPE_COUNTRY = 3;

	/**
	 * Return the human-readable plugin name.
	 *
	 * @return string
	 */
	public static function get_plugin_name() {
		return 'Wordfence Security';
	}

	/**
	 * Return the machine slug for this adapter.
	 *
	 * @return string
	 */
	public static function get_plugin_slug() {
		return 'wordfence';
	}

	/**
	 * Check if Wordfence data exists in the database.
	 *
	 * @return bool
	 */
	public static function has_data() {
		// Third-party plugin detection — not a Segurium-owned option, direct access retained.
		if ( false !== get_option( 'wordfence_version' ) ) { // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
			return true;
		}
		global $wpdb;
		// Also detect by table presence (orphaned data after deletion).
		$table = $wpdb->prefix . 'wfConfig';
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table; // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name is hard-coded competitor-plugin table suffix
	}

	/**
	 * Return a preview of migratable Wordfence data.
	 *
	 * @return array
	 */
	public function preview() {
		return array(
			$this->preview_scan_exclusions(),
			$this->preview_geo_countries(),
			$this->preview_ip_blocks(),
			$this->make_item( 'brute_force', __( 'Brute Force Protection', 'segurium' ), 0, 'pending_feature', '', __( 'Segurium brute force protection (planned)', 'segurium' ) ),
			$this->preview_2fa(),
			$this->make_item( 'waf', __( 'WAF Rules', 'segurium' ), 0, 'pending_feature', '', __( 'Segurium WAF rules (planned)', 'segurium' ) ),
		);
	}

	/**
	 * Apply the migration from Wordfence.
	 *
	 * @return array Result summary with applied, skipped, and pending items.
	 */
	public function apply() {
		$applied = array();
		$skipped = array();
		$pending = array();

		foreach ( $this->preview() as $item ) {
			if ( 'pending_feature' === $item['status'] ) {
				$pending[] = $item;
				continue;
			}
			if ( 'skip' === $item['status'] || 0 === $item['count'] ) {
				$skipped[] = $item;
				continue;
			}
			$this->apply_item( $item['feature'] );
			$item['result'] = 'applied';
			$applied[]      = $item;
		}

		return array(
			'applied' => $applied,
			'skipped' => $skipped,
			'pending' => $pending,
		);
	}

	/**
	 * Apply a single migration feature.
	 *
	 * @param string $feature Feature key to apply.
	 */
	private function apply_item( $feature ) {
		if ( 'scan_exclusions' === $feature ) {
			$new_patterns = $this->get_scan_exclusions();
			if ( ! empty( $new_patterns ) ) {
				// segurium_scan_exclude stays in wp_options (small settings-array, kept per plan).
				$existing = (string) Segurium_Storage::setting_get( 'segurium_scan_exclude', '' );
				Segurium_Storage::setting_set( 'segurium_scan_exclude', $this->merge_scan_exclusions( $existing, $new_patterns ), true );
			}
		} elseif ( 'geo_countries' === $feature ) {
			$countries = $this->get_blocked_countries();
			if ( ! empty( $countries ) ) {
				$existing = Segurium_Storage::setting_get_array( 'segurium_geo_blocked_countries' );
				Segurium_Storage::setting_set( 'segurium_geo_blocked_countries', array_values( array_unique( array_merge( $existing, $countries ) ) ) );
				Segurium_Storage::setting_set( 'segurium_geo_blocking_enabled', true );
				if ( 'block' !== Segurium_Storage::setting_get_string( 'segurium_geo_block_mode' ) ) {
					Segurium_Storage::setting_set( 'segurium_geo_block_mode', 'block' );
				}
			}
		} elseif ( '2fa' === $feature ) {
			$this->apply_2fa_migration();
		} elseif ( 'ip_blocklist' === $feature ) {
			$ips = $this->get_blocked_ips();
			if ( ! empty( $ips ) ) {

				$existing = Segurium::firewall_rules_read();
				$merged   = $this->merge_ip_list( $existing, $ips );
				Segurium::firewall_rules_save( Segurium_Storage::setting_get_string( 'segurium_firewall_mode', 'deny_list' ), $merged );
				if ( ! Segurium_Storage::setting_get_bool( 'segurium_firewall_enabled' ) ) {
					Segurium_Storage::setting_set( 'segurium_firewall_enabled', true );
					Segurium_Storage::setting_set( 'segurium_firewall_mode', 'deny_list' );
				}
			}
		}
	}

	/**
	 * Build a preview item for scan exclusions.
	 *
	 * @return array Preview item descriptor.
	 */
	private function preview_scan_exclusions() {
		$patterns = $this->get_scan_exclusions();
		if ( empty( $patterns ) ) {
			return $this->make_item( 'scan_exclusions', __( 'Scan Exclusions', 'segurium' ), 0, 'skip', '', __( 'No exclusion patterns configured in Wordfence.', 'segurium' ) );
		}
		return $this->make_item( 'scan_exclusions', __( 'Scan Exclusions', 'segurium' ), count( $patterns ), 'import', __( 'Merge', 'segurium' ) );
	}

	/**
	 * Build a preview item for country blocks.
	 *
	 * @return array Preview item descriptor.
	 */
	private function preview_geo_countries() {
		$countries = $this->get_blocked_countries();
		if ( empty( $countries ) ) {
			return $this->make_item( 'geo_countries', __( 'Blocked Countries', 'segurium' ), 0, 'skip', '', __( 'No country blocks configured in Wordfence.', 'segurium' ) );
		}
		return $this->make_item( 'geo_countries', __( 'Blocked Countries', 'segurium' ), count( $countries ), 'import', __( 'Import', 'segurium' ) );
	}

	/**
	 * Build a preview item for IP blocks.
	 *
	 * @return array Preview item descriptor.
	 */
	private function preview_ip_blocks() {
		$ips = $this->get_blocked_ips();
		if ( empty( $ips ) ) {
			return $this->make_item( 'ip_blocklist', __( 'Blocked IPs', 'segurium' ), 0, 'skip', '', __( 'No manual IP blocks found in Wordfence.', 'segurium' ) );
		}
		return $this->make_item( 'ip_blocklist', __( 'Blocked IPs', 'segurium' ), count( $ips ), 'import', __( 'Merge', 'segurium' ) );
	}

	/**
	 * Retrieve scan exclusion patterns from Wordfence configuration.
	 *
	 * @return array
	 */
	public function get_scan_exclusions() {
		global $wpdb;
		$table = $wpdb->prefix . 'wfConfig';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name is hard-coded competitor-plugin table suffix
			return array();
		}
		$val = $wpdb->get_var( $wpdb->prepare( 'SELECT val FROM %i WHERE name = %s', $table, 'scan_exclude' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- competitor-plugin table read
		if ( empty( $val ) ) {
			return array();
		}
		return $this->parse_newline_list( $val );
	}

	/**
	 * Retrieve blocked countries from Wordfence.
	 *
	 * @return array Country codes.
	 */
	public function get_blocked_countries() {
		global $wpdb;
		$table = $wpdb->prefix . 'wfBlocks7';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name is hard-coded competitor-plugin table suffix
			return array();
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT parameters FROM %i WHERE type = %d LIMIT 1', $table, self::TYPE_COUNTRY ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- competitor-plugin table read
		if ( ! $row || empty( $row['parameters'] ) ) {
			return array();
		}
		$params = json_decode( $row['parameters'], true );
		if ( ! is_array( $params ) || empty( $params['countries'] ) ) {
			return array();
		}
		return array_values( array_filter( array_map( 'strtoupper', (array) $params['countries'] ) ) );
	}

	/**
	 * Retrieve manually blocked IPs from Wordfence.
	 *
	 * @return array Validated IP addresses.
	 */
	public function get_blocked_ips() {
		global $wpdb;
		$table = $wpdb->prefix . 'wfBlocks7';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name is hard-coded competitor-plugin table suffix
			return array();
		}
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- competitor-plugin table read
			$wpdb->prepare(
				'SELECT HEX(IP) AS ip_hex FROM %i WHERE type = %d AND (expiration = 0 OR expiration > %d)',
				$table,
				self::TYPE_IP_MANUAL,
				time()
			),
			ARRAY_A
		);

		$ips = array();
		foreach ( (array) $rows as $row ) {
			if ( empty( $row['ip_hex'] ) ) {
				continue;
			}
			$binary = pack( 'H*', str_pad( $row['ip_hex'], 32, '0', STR_PAD_LEFT ) );
			$ip     = @inet_ntop( $binary ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $ip ) {
				continue;
			}
			if ( 0 === strpos( $ip, '::ffff:' ) ) {
				$ip = substr( $ip, 7 );
			}
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$ips[] = $ip;
			}
		}
		return $ips;
	}

	/**
	 * Build a preview item for 2FA migration.
	 *
	 * @return array Preview item descriptor.
	 */
	private function preview_2fa() {
		$count = $this->get_wordfence_2fa_count();
		if ( $count > 0 ) {
			return $this->make_item(
				'2fa',
				__( 'Two-Factor Authentication', 'segurium' ),
				$count,
				'import',
				sprintf(
					/* translators: %d: number of users with 2FA */
					__( 'Import %d user(s) with TOTP', 'segurium' ),
					$count
				),
				__( 'Import into Segurium 2FA', 'segurium' )
			);
		}

		return $this->make_item(
			'2fa',
			__( 'Two-Factor Authentication', 'segurium' ),
			0,
			'skip',
			'',
			__( 'No Wordfence 2FA data found', 'segurium' )
		);
	}

	/**
	 * Count users with Wordfence Login Security 2FA data.
	 *
	 * @return int User count.
	 */
	private function get_wordfence_2fa_count() {
		global $wpdb;
		$table  = $wpdb->prefix . 'wfls_2fa_secrets';
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( ! $exists ) {
			return 0;
		}
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM `{$wpdb->prefix}wfls_2fa_secrets` WHERE `mode` = 'otp'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name is hard-coded competitor-plugin table suffix
	}

	/**
	 * Apply 2FA migration from Wordfence.
	 *
	 * @return void
	 */
	private function apply_2fa_migration() {
		global $wpdb;

		$rows = $wpdb->get_results( "SELECT `user_id`, `secret`, `recovery` FROM `{$wpdb->prefix}wfls_2fa_secrets` WHERE `mode` = 'otp'", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name is hard-coded competitor-plugin table suffix

		if ( empty( $rows ) ) {
			return;
		}

		foreach ( $rows as $row ) {
			$user_id = (int) $row['user_id'];

			// Skip users who already have Segurium 2FA.
			$existing = get_user_meta( $user_id, Segurium_2FA::USER_META_METHOD, true );
			if ( ! empty( $existing ) && 'none' !== $existing ) {
				continue;
			}

			Segurium_2FA::import_from_wordfence(
				$user_id,
				$row['secret'],
				$row['recovery']
			);
		}
	}
}

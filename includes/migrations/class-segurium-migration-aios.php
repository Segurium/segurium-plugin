<?php
/**
 * Migration adapter for All-In-One Security (AIOS).
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Imports IP blocklists and scan exclusions from AIOS.
 */
class Segurium_Migration_AIOS extends Segurium_Migration_Source {

	/**
	 * Return the human-readable plugin name.
	 *
	 * @return string
	 */
	public static function get_plugin_name() {
		return 'All-In-One Security (AIOS)';
	}

	/**
	 * Return the machine slug for this adapter.
	 *
	 * @return string
	 */
	public static function get_plugin_slug() {
		return 'aios';
	}

	/**
	 * Check if AIOS data exists in the database.
	 *
	 * @return bool
	 */
	public static function has_data() {
		// Third-party plugin detection — direct access retained.
		return false !== get_option( 'aiowpsec_db_version' ) // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
			|| false !== get_option( 'aio_wp_security_configs' ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
	}

	/**
	 * Return a preview of migratable AIOS data.
	 *
	 * @return array
	 */
	public function preview() {
		return array(
			$this->preview_ip_blocklist(),
			$this->preview_scan_exclusions(),
			$this->make_item( 'ip_whitelist', __( 'IP Whitelist', 'segurium' ), 0, 'skip', '', __( 'AIOS IP whitelist (bypass) has no direct equivalent in Segurium\'s deny-list firewall mode. Configure manually if needed.', 'segurium' ) ),
			$this->make_item( 'brute_force', __( 'Brute Force Protection', 'segurium' ), 0, 'pending_feature', '', __( 'Segurium brute force protection (planned)', 'segurium' ) ),
			$this->make_item( 'geo_countries', __( 'Country Blocking', 'segurium' ), 0, 'skip', '', __( 'AIOS country blocking is a paid cloud feature and cannot be imported locally.', 'segurium' ) ),
		);
	}

	/**
	 * Apply the migration from AIOS.
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
		if ( 'ip_blocklist' === $feature ) {
			$ips = $this->get_banned_ips();
			if ( ! empty( $ips ) ) {

				$existing = Segurium::firewall_rules_read();
				$merged   = $this->merge_ip_list( $existing, $ips );
				Segurium::firewall_rules_save( Segurium_Storage::setting_get_string( 'segurium_firewall_mode', 'deny_list' ), $merged );
				if ( ! Segurium_Storage::setting_get_bool( 'segurium_firewall_enabled' ) ) {
					Segurium_Storage::setting_set( 'segurium_firewall_enabled', true );
					Segurium_Storage::setting_set( 'segurium_firewall_mode', 'deny_list' );
				}
			}
		} elseif ( 'scan_exclusions' === $feature ) {
			$patterns = $this->get_scan_exclusions();
			if ( ! empty( $patterns ) ) {
				// segurium_scan_exclude stays in wp_options per plan.
				$existing = (string) Segurium_Storage::setting_get( 'segurium_scan_exclude', '' );
				Segurium_Storage::setting_set( 'segurium_scan_exclude', $this->merge_scan_exclusions( $existing, $patterns ), true );
			}
		}
	}

	/**
	 * Build a preview item for the IP blocklist feature.
	 *
	 * @return array Preview item descriptor.
	 */
	private function preview_ip_blocklist() {
		$ips = $this->get_banned_ips();
		if ( empty( $ips ) ) {
			return $this->make_item( 'ip_blocklist', __( 'Blocked IPs', 'segurium' ), 0, 'skip', '', __( 'No banned IPs configured in AIOS.', 'segurium' ) );
		}
		return $this->make_item( 'ip_blocklist', __( 'Blocked IPs', 'segurium' ), count( $ips ), 'import', __( 'Merge', 'segurium' ) );
	}

	/**
	 * Build a preview item for the scan exclusions feature.
	 *
	 * @return array Preview item descriptor.
	 */
	private function preview_scan_exclusions() {
		$patterns = $this->get_scan_exclusions();
		if ( empty( $patterns ) ) {
			return $this->make_item( 'scan_exclusions', __( 'Scan Exclusions', 'segurium' ), 0, 'skip', '', __( 'No file exclusions configured in AIOS.', 'segurium' ) );
		}
		return $this->make_item( 'scan_exclusions', __( 'Scan Exclusions', 'segurium' ), count( $patterns ), 'import', __( 'Merge', 'segurium' ) );
	}

	/**
	 * Retrieve AIOS configuration array from the database.
	 *
	 * @return array
	 */
	private function get_configs() {
		// Third-party plugin data — direct access retained.
		$configs = get_option( 'aio_wp_security_configs', array() ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
		if ( ! is_array( $configs ) ) {
			$configs = array();
		}
		return $configs;
	}

	/**
	 * Retrieve validated banned IPs from AIOS configuration.
	 *
	 * @return array
	 */
	public function get_banned_ips() {
		$configs = $this->get_configs();
		$raw     = isset( $configs['aiowps_banned_ip_addresses'] ) ? $configs['aiowps_banned_ip_addresses'] : '';
		if ( empty( $raw ) ) {
			return array();
		}
		return $this->validate_ip_list( $this->parse_newline_list( $raw ) );
	}

	/**
	 * Retrieve scan exclusion patterns from AIOS configuration.
	 *
	 * @return array
	 */
	public function get_scan_exclusions() {
		$configs  = $this->get_configs();
		$patterns = array();

		$raw_files = isset( $configs['aiowps_fcd_exclude_files'] ) ? $configs['aiowps_fcd_exclude_files'] : '';
		if ( ! empty( $raw_files ) ) {
			foreach ( $this->parse_newline_list( $raw_files ) as $p ) {
				$patterns[] = $p;
			}
		}

		// aiowps_fcd_exclude_filetypes: comma or newline-separated extensions e.g. ".log,.tmp".
		$raw_types = isset( $configs['aiowps_fcd_exclude_filetypes'] ) ? $configs['aiowps_fcd_exclude_filetypes'] : '';
		if ( ! empty( $raw_types ) ) {
			$parts = preg_split( '/[\r\n,]+/', $raw_types );
			foreach ( $parts as $ext ) {
				$ext = trim( $ext );
				if ( empty( $ext ) ) {
					continue;
				}
				// Convert ".log" to "*.log".
				if ( '.' === substr( $ext, 0, 1 ) ) {
					$patterns[] = '*' . $ext;
				} else {
					$patterns[] = '*.' . $ext;
				}
			}
		}

		return array_values( array_unique( $patterns ) );
	}
}

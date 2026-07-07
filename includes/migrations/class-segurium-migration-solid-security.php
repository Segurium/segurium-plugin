<?php
/**
 * Migration adapter for Solid Security (iThemes Security).
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Imports IP bans from Solid Security.
 */
class Segurium_Migration_Solid_Security extends Segurium_Migration_Source {

	/**
	 * Return the human-readable plugin name.
	 *
	 * @return string
	 */
	public static function get_plugin_name() {
		return 'Solid Security (iThemes Security)';
	}

	/**
	 * Return the machine slug for this adapter.
	 *
	 * @return string
	 */
	public static function get_plugin_slug() {
		return 'solid-security';
	}

	/**
	 * Check if Solid Security data exists in the database.
	 *
	 * @return bool
	 */
	public static function has_data() {
		// Third-party plugin detection — direct access retained.
		if ( false !== get_option( 'itsec-version' ) || false !== get_option( 'itsec_version' ) ) { // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
			return true;
		}
		// Detect orphaned data via custom table.
		global $wpdb;
		$table = $wpdb->base_prefix . 'itsec_bans';
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table; // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name is hard-coded competitor-plugin table suffix
	}

	/**
	 * Return a preview of migratable Solid Security data.
	 *
	 * @return array
	 */
	public function preview() {
		return array(
			$this->preview_ip_bans(),
			$this->make_item( 'brute_force', __( 'Brute Force Protection', 'segurium' ), 0, 'pending_feature', '', __( 'Segurium brute force protection (planned)', 'segurium' ) ),
			$this->make_item( '2fa', __( 'Two-Factor Authentication', 'segurium' ), 0, 'pending_feature', '', __( 'Segurium 2FA (planned)', 'segurium' ) ),
			$this->make_item( 'geo_countries', __( 'Country Blocking', 'segurium' ), 0, 'skip', '', __( 'Solid Security stores country blocks in the cloud dashboard. Configure manually in the Geo Blocking tab.', 'segurium' ) ),
		);
	}

	/**
	 * Apply the migration from Solid Security.
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
		if ( 'ip_bans' === $feature ) {
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
		}
	}

	/**
	 * Build a preview item for the IP bans feature.
	 *
	 * @return array Preview item descriptor.
	 */
	private function preview_ip_bans() {
		$ips = $this->get_banned_ips();
		if ( empty( $ips ) ) {
			return $this->make_item( 'ip_bans', __( 'Banned IPs', 'segurium' ), 0, 'skip', '', __( 'No banned IPs found in Solid Security.', 'segurium' ) );
		}
		return $this->make_item( 'ip_bans', __( 'Banned IPs', 'segurium' ), count( $ips ), 'import', __( 'Merge', 'segurium' ) );
	}

	/**
	 * Retrieve validated banned IPs from Solid Security.
	 *
	 * @return array
	 */
	public function get_banned_ips() {
		global $wpdb;
		$table = $wpdb->base_prefix . 'itsec_bans';
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table name is hard-coded competitor-plugin table suffix
			// Fallback: older versions stored bans in site option.
			$option = get_site_option( 'itsec_ban_users', array() );
			if ( isset( $option['hosts'] ) && is_array( $option['hosts'] ) ) {
				return $this->validate_ip_list( $option['hosts'] );
			}
			return array();
		}
		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name is hard-coded competitor-plugin table suffix
			"SELECT host FROM `{$wpdb->base_prefix}itsec_bans` WHERE type IN ('ip', 'range')",
			ARRAY_A
		);
		if ( empty( $rows ) ) {
			return array();
		}
		$ips = array();
		foreach ( $rows as $row ) {
			$ips[] = $row['host'];
		}
		return $this->validate_ip_list( $ips );
	}
}

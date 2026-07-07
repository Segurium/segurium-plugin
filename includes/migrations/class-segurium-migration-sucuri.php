<?php
/**
 * Migration adapter for Sucuri Security.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles migration detection for Sucuri (cloud-only settings).
 */
class Segurium_Migration_Sucuri extends Segurium_Migration_Source {

	/**
	 * Return the human-readable plugin name.
	 *
	 * @return string
	 */
	public static function get_plugin_name() {
		return 'Sucuri Security';
	}

	/**
	 * Return the machine slug for this adapter.
	 *
	 * @return string
	 */
	public static function get_plugin_slug() {
		return 'sucuri';
	}

	/**
	 * Check if Sucuri data exists in the database.
	 *
	 * @return bool
	 */
	public static function has_data() {
		// Third-party plugin detection — direct access retained.
		return false !== get_option( 'sucuriscan_version' ) // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
			|| false !== get_option( 'sucuriscan_api_key' ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
	}

	/**
	 * Return a preview of migratable Sucuri data.
	 *
	 * @return array
	 */
	public function preview() {
		return array(
			$this->make_item(
				'info',
				__( 'Cloud-Managed Settings', 'segurium' ),
				0,
				'skip',
				'',
				__( 'Sucuri Security stores its WAF rules, geo-blocking, and malware scanning settings in the Sucuri cloud dashboard. These cannot be imported locally.', 'segurium' )
			),
			$this->make_item( 'waf', __( 'WAF Rules', 'segurium' ), 0, 'pending_feature', '', __( 'Segurium WAF rules (planned)', 'segurium' ) ),
			$this->make_item( 'geo_countries', __( 'Country Blocking', 'segurium' ), 0, 'pending_feature', '', __( 'Segurium geo-blocking (available) — configure manually in the Geo Blocking tab.', 'segurium' ) ),
		);
	}

	/**
	 * Apply the migration from Sucuri (no-op since all data is cloud-only).
	 *
	 * @return array Result summary.
	 */
	public function apply() {
		return array(
			'applied' => array(),
			'skipped' => array_filter(
				$this->preview(),
				function ( $item ) {
					return 'skip' === $item['status']; }
			),
			'pending' => array_filter(
				$this->preview(),
				function ( $item ) {
					return 'pending_feature' === $item['status']; }
			),
		);
	}
}

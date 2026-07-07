<?php
/**
 * Default discovery layer for Segurium_Integrity_Scan_State.
 *
 * Walks the real WordPress installation via get_plugins() / wp_get_themes()
 * and lazily collects per-component file hashes via Segurium_Integrity.
 * Tests inject their own stub via the Segurium_Integrity_Scan_State
 * constructor so they don't need to scaffold real plugin/theme directories.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Discovers WordPress components and collects their file hashes.
 */
class Segurium_Integrity_Component_Discovery {

	/**
	 * WordPress installation root path.
	 *
	 * @var string
	 */
	private $base_path;

	/**
	 * Integrity scanner instance.
	 *
	 * @var Segurium_Integrity
	 */
	private $integrity;

	/**
	 * Constructor.
	 *
	 * @param string $base_path        WordPress installation root.
	 * @param array  $exclude_patterns User-defined exclusion patterns.
	 */
	public function __construct( $base_path, $exclude_patterns = array() ) {
		$this->base_path = rtrim( $base_path, '/' );
		$this->integrity = new Segurium_Integrity( $this->base_path, $exclude_patterns );
	}

	/**
	 * Discover all WordPress components (core, plugins, themes).
	 *
	 * @return array Queue of component descriptors.
	 */
	public function discover() {
		$queue = array();

		$queue[] = array(
			'type'    => 'core',
			'slug'    => 'WordPress',
			'name'    => 'WordPress',
			'version' => function_exists( 'get_bloginfo' ) ? get_bloginfo( 'version' ) : '',
		);

		if ( ! function_exists( 'get_plugins' ) ) {
			Segurium_Path_Helpers::wp_admin_include( 'plugin.php' );
		}
		foreach ( get_plugins() as $plugin_file => $plugin_data ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				continue;
			}
			$queue[] = array(
				'type'    => 'plugin',
				'slug'    => $slug,
				'name'    => $plugin_data['Name'] ?? $slug,
				'version' => $plugin_data['Version'] ?? '',
			);
		}

		foreach ( wp_get_themes() as $slug => $theme ) {
			$theme_name    = $theme->get( 'Name' );
			$theme_version = $theme->get( 'Version' );
			$queue[]       = array(
				'type'    => 'theme',
				'slug'    => $slug,
				'name'    => $theme_name ? $theme_name : $slug,
				'version' => $theme_version ? $theme_version : '',
			);
		}

		return $queue;
	}

	/**
	 * Enumerate the site's full component inventory for CTI reporting.
	 * Walks core, regular plugins, mu-plugins, dropins, and themes, and
	 * attaches a status derived from WP state + the plugin's own integrity
	 * state file (ignored / deleted overrides).
	 *
	 * Returns a flat list of { component_type, slug, version, status }.
	 * Used by the pre-scan snapshot and the daily cron event.
	 *
	 * @param string|null $integrity_data_dir Path to the integrity state dir.
	 *                                        When null, ignore/deleted overrides
	 *                                        are skipped.
	 * @return array
	 */
	public static function enumerate_inventory( $integrity_data_dir = null ): array {
		$inventory = array();

		$overrides = array();
		if ( is_string( $integrity_data_dir ) && '' !== $integrity_data_dir && class_exists( 'Segurium_Integrity_Server_State' ) ) {
			try {
				$state = new Segurium_Integrity_Server_State( $integrity_data_dir );
				$state->load();
				foreach ( $state->get_component_status_overrides() as $override ) {
					$key               = $override['type'] . ':' . $override['slug'];
					$overrides[ $key ] = $override['status'];
				}
			} catch ( Throwable $e ) {
				Segurium_Debug::log( '[segurium] enumerate_inventory: state load failed: ' . $e->getMessage() );
			}
		}

		$inventory[] = array(
			'component_type' => 'core',
			'slug'           => 'WordPress',
			'version'        => function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'version' ) : '',
			'status'         => 'active',
		);

		if ( ! function_exists( 'get_plugins' ) ) {
			Segurium_Path_Helpers::wp_admin_include( 'plugin.php' );
		}

		foreach ( get_plugins() as $plugin_file => $plugin_data ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				continue;
			}
			$key         = 'plugin:' . $slug;
			$wp_status   = is_plugin_active( $plugin_file ) ? 'active' : 'inactive';
			$inventory[] = array(
				'component_type' => 'plugin',
				'slug'           => $slug,
				'version'        => (string) ( $plugin_data['Version'] ?? '' ),
				'status'         => $overrides[ $key ] ?? $wp_status,
			);
		}

		if ( function_exists( 'get_mu_plugins' ) ) {
			foreach ( get_mu_plugins() as $mu_file => $mu_data ) {
				$slug        = dirname( $mu_file );
				$slug        = ( '.' === $slug || '' === $slug ) ? basename( $mu_file, '.php' ) : $slug;
				$inventory[] = array(
					'component_type' => 'plugin',
					'slug'           => (string) $slug,
					'version'        => (string) ( $mu_data['Version'] ?? '' ),
					'status'         => 'must_use',
				);
			}
		}

		if ( function_exists( 'get_dropins' ) ) {
			foreach ( get_dropins() as $drop_file => $drop_data ) {
				$inventory[] = array(
					'component_type' => 'plugin',
					'slug'           => (string) basename( $drop_file, '.php' ),
					'version'        => (string) ( $drop_data['Version'] ?? '' ),
					'status'         => 'dropin',
				);
			}
		}

		$active_theme = function_exists( 'wp_get_theme' ) ? wp_get_theme() : null;
		$active_slug  = $active_theme ? $active_theme->get_stylesheet() : '';
		foreach ( wp_get_themes() as $slug => $theme ) {
			$key         = 'theme:' . $slug;
			$wp_status   = ( $slug === $active_slug ) ? 'active' : 'inactive';
			$inventory[] = array(
				'component_type' => 'theme',
				'slug'           => (string) $slug,
				'version'        => (string) $theme->get( 'Version' ),
				'status'         => $overrides[ $key ] ?? $wp_status,
			);
		}

		return $inventory;
	}

	/**
	 * Collect file hashes for a specific component.
	 *
	 * @param string $type Component type (core, plugin, theme).
	 * @param string $slug Component slug.
	 * @return array List of path/sha256 pairs.
	 */
	public function collect_hashes( $type, $slug ) {
		switch ( $type ) {
			case 'core':
				return $this->integrity->collect_core_hashes();
			case 'plugin':
				return $this->integrity->collect_plugin_hashes( $slug );
			case 'theme':
				return $this->integrity->collect_theme_hashes( $slug );
		}
		return array();
	}
}

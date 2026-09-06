<?php
/**
 * Information Shield feature.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Consolidates WordPress information disclosure reduction:
 * HTTP header cleanup, HTML head meta/link removal,
 * asset version query stripping, and XML-RPC disable.
 */
class Segurium_Info_Shield {

	const SETTINGS_SLUG   = 'info_shield';
	const OPTION_SETTINGS = 'segurium_settings_info_shield';

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private $settings = null;

	/**
	 * Whether hooks have been registered.
	 *
	 * @var bool
	 */
	private $hooks_registered = false;

	/**
	 * Return the singleton instance.
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor (singleton).
	 */
	private function __construct() {}

	/**
	 * Reset singleton for tests.
	 */
	public static function reset_instance() {
		self::$instance = null;
	}

	/**
	 * Return default settings array.
	 *
	 * @return array
	 */
	public static function default_settings() {
		return array(
			'enabled'                    => false,
			// HTTP Headers.
			'remove_x_powered_by'        => true,
			'remove_server_header'       => true,
			'remove_x_pingback'          => true,
			'remove_rest_api_header'     => true,
			'remove_shortlink_header'    => true,
			// HTML <head>.
			'remove_wp_generator'        => true,
			'remove_rsd_link'            => true,
			'remove_wlw_manifest'        => true,
			'remove_rest_api_link'       => true,
			'remove_oembed_links'        => true,
			'remove_shortlink_link'      => true,
			'remove_emoji'               => true,
			'remove_feed_links'          => false,
			'remove_adjacent_post_links' => true,
			// Assets.
			'remove_version_query'       => true,
			// XML-RPC.
			'disable_xmlrpc'             => false,
		);
	}

	/**
	 * Get current settings, lazy-loaded from DB.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( null === $this->settings ) {
			$this->load_settings();
		}
		return $this->settings;
	}

	/**
	 * Load settings from DB and merge with defaults.
	 */
	private function load_settings() {
		$this->settings = Segurium_Settings::get( self::SETTINGS_SLUG );
	}

	/**
	 * Validate, persist and report settings.
	 *
	 * @param array $raw Raw input from AJAX POST.
	 * @return array Cleaned and persisted settings.
	 */
	public function save_settings( $raw ) {
		Segurium_Settings_Writer::save( self::SETTINGS_SLUG, $raw );
		return $this->get_settings();
	}

	/**
	 * Post-write hook driven by the settings registry.
	 *
	 * @return void
	 */
	public function refresh_settings() {
		$this->load_settings();
	}

	/**
	 * Validate raw input to boolean toggles.
	 *
	 * @param array $input Input to validate.
	 * @return array Validated settings with all keys as booleans.
	 */
	public function validate_settings( $input ) {
		$defaults = self::default_settings();
		$input    = is_array( $input ) ? $input : array();
		$clean    = array();
		foreach ( $defaults as $key => $default_value ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}
		return $clean;
	}

	/**
	 * Register WordPress hooks based on current settings.
	 */
	public function init() {
		$s = $this->get_settings();
		if ( empty( $s['enabled'] ) ) {
			return;
		}
		if ( $this->hooks_registered ) {
			return;
		}
		$this->hooks_registered = true;

		// -- HTTP Header Disclosure --
		add_action( 'send_headers', array( $this, 'clean_http_headers' ), 999 );

		if ( $s['remove_x_pingback'] ) {
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		}
		if ( $s['remove_rest_api_header'] ) {
			remove_action( 'template_redirect', 'rest_output_link_header', 11, 0 );
		}
		if ( $s['remove_shortlink_header'] ) {
			remove_action( 'template_redirect', 'wp_shortlink_header', 11, 0 );
		}

		// -- HTML <head> Cleanup --
		if ( $s['remove_wp_generator'] ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( $s['remove_rsd_link'] ) {
			remove_action( 'wp_head', 'rsd_link' );
		}
		if ( $s['remove_wlw_manifest'] ) {
			remove_action( 'wp_head', 'wlwmanifest_link' );
		}
		if ( $s['remove_rest_api_link'] ) {
			remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
		}
		if ( $s['remove_oembed_links'] ) {
			remove_action( 'wp_head', 'wp_oembed_add_discovery_links' );
			remove_action( 'wp_head', 'wp_oembed_add_host_js' );
		}
		if ( $s['remove_shortlink_link'] ) {
			remove_action( 'wp_head', 'wp_shortlink_wp_head', 10, 0 );
		}
		if ( $s['remove_emoji'] ) {
			remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
			remove_action( 'wp_print_styles', 'print_emoji_styles' );
			remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
			remove_action( 'admin_print_styles', 'print_emoji_styles' );
			remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
			remove_filter( 'comment_text_rss', 'wp_staticize_emoji' );
			add_filter( 'emoji_svg_url', '__return_false' );
		}
		if ( $s['remove_feed_links'] ) {
			remove_action( 'wp_head', 'feed_links', 2 );
			remove_action( 'wp_head', 'feed_links_extra', 3 );
		}
		if ( $s['remove_adjacent_post_links'] ) {
			remove_action( 'wp_head', 'adjacent_posts_rel_link_wp_head', 10, 0 );
		}

		// -- Asset Fingerprinting --
		if ( $s['remove_version_query'] ) {
			add_filter( 'style_loader_src', array( $this, 'strip_version_query' ), 9999 );
			add_filter( 'script_loader_src', array( $this, 'strip_version_query' ), 9999 );
			// WP 6.5+ script modules (Interactivity API, core blocks). This
			// covers module script tags, preloads, and import-map entries
			// since all three paths run through WP_Script_Modules::get_src().
			// On WP < 6.5 the filter is never applied, so this is a no-op.
			add_filter( 'script_module_loader_src', array( $this, 'strip_version_query' ), 9999 );
		}

		// -- XML-RPC --
		if ( $s['disable_xmlrpc'] ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
			add_filter( 'xmlrpc_methods', array( $this, 'disable_xmlrpc_methods' ) );
		}
	}

	/**
	 * Remove X-Powered-By and Server headers on send_headers.
	 */
	public function clean_http_headers() {
		$s = $this->get_settings();
		if ( $s['remove_x_powered_by'] ) {
			header_remove( 'X-Powered-By' );
			@ini_set( 'expose_php', 'off' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.PHP.IniSet.Risky,Squiz.PHP.DiscouragedFunctions.Discouraged -- intentional info-shield hardening, silenced for hosts where ini_set is disabled
		}
		if ( $s['remove_server_header'] ) {
			header_remove( 'Server' );
		}
	}

	/**
	 * Remove the X-Pingback header from the response.
	 *
	 * @param array $headers Response headers.
	 * @return array Filtered headers.
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Strip the ver query argument from asset URLs.
	 *
	 * @param string $src Asset URL.
	 * @return string URL with ver query arg removed.
	 */
	public function strip_version_query( $src ) {
		if ( strpos( $src, 'ver=' ) !== false ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Disable all XML-RPC methods by returning an empty array.
	 *
	 * @return array Empty array.
	 */
	public function disable_xmlrpc_methods() {
		return array();
	}

	/**
	 * Detect the server environment for UI capability warnings.
	 *
	 * @return array Server info with capability flags and guidance notes.
	 */
	public static function detect_server_environment() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] )
			? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
			: '';
		$sapi     = php_sapi_name();

		$server_type = 'unknown';
		if ( stripos( $software, 'Apache' ) !== false ) {
			$server_type = 'apache';
		} elseif ( stripos( $software, 'nginx' ) !== false ) {
			$server_type = 'nginx';
		} elseif ( stripos( $software, 'LiteSpeed' ) !== false ) {
			$server_type = 'litespeed';
		} elseif ( stripos( $software, 'Microsoft-IIS' ) !== false ) {
			$server_type = 'iis';
		}

		$is_fastcgi = (
			stripos( $sapi, 'fpm' ) !== false
			|| stripos( $sapi, 'fcgi' ) !== false
			|| stripos( $sapi, 'cgi' ) !== false
		);

		return array(
			'server_type'          => $server_type,
			'server_software'      => $software,
			'sapi'                 => $sapi,
			'is_fastcgi'           => $is_fastcgi,
			'can_remove_server'    => ( 'apache' === $server_type && ! $is_fastcgi ) || 'litespeed' === $server_type,
			'can_remove_x_powered' => ! $is_fastcgi,
			'server_header_note'   => self::server_header_guidance( $server_type, $is_fastcgi ),
			'x_powered_by_note'    => self::x_powered_by_guidance( $is_fastcgi ),
		);
	}

	/**
	 * Return guidance text for the Server header based on server type.
	 *
	 * @param string $server_type Detected server type.
	 * @param bool   $is_fastcgi  Whether PHP runs as FastCGI.
	 * @return string Guidance text (translated).
	 */
	private static function server_header_guidance( $server_type, $is_fastcgi ) {
		switch ( $server_type ) {
			case 'nginx':
				return __( 'On Nginx, the Server header must be removed at the server level (server_tokens off;). This toggle has no effect.', 'segurium' );
			case 'apache':
				if ( $is_fastcgi ) {
					return __( 'On Apache with FastCGI, the Server header is added after PHP runs. Use ServerTokens Prod in Apache config.', 'segurium' );
				}
				return '';
			case 'iis':
				return __( 'On IIS, use the removeServerHeader attribute in web.config. This toggle has limited effect.', 'segurium' );
			default:
				return '';
		}
	}

	/**
	 * Return guidance text for X-Powered-By based on SAPI type.
	 *
	 * @param bool $is_fastcgi Whether PHP runs as FastCGI.
	 * @return string Guidance text (translated).
	 */
	private static function x_powered_by_guidance( $is_fastcgi ) {
		if ( $is_fastcgi ) {
			return __( 'Your server uses FastCGI, which may re-add the X-Powered-By header. Verify removal by inspecting response headers.', 'segurium' );
		}
		return '';
	}

	/**
	 * Detect plugin conflicts relevant to Information Shield settings.
	 *
	 * @return array Keyed warnings about plugin conflicts.
	 */
	public static function detect_conflicts() {
		$conflicts = array();
		if ( class_exists( 'Jetpack' ) ) {
			$conflicts['jetpack_xmlrpc'] = __( 'Jetpack is active and requires XML-RPC. Disabling XML-RPC will break the Jetpack connection.', 'segurium' );
		}
		return $conflicts;
	}
}

<?php
/**
 * Security Headers feature.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds HTTP security response headers, cookie hardening (SameSite),
 * Cache-Control for admin pages, and X-DNS-Prefetch-Control.
 */
class Segurium_Security_Headers {

	const SETTINGS_SLUG   = 'security_headers';
	const OPTION_SETTINGS = 'segurium_settings_security_headers';

	const VALID_MODES = array( 'off', 'basic', 'recommended', 'strict', 'custom' );

	const VALID_CSP_MODES = array( 'enforce', 'report-only' );

	const CSP_MAX_LEN = 4096;

	const CSP_DEFAULT_DIRECTIVES = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'";

	const VALID_X_FRAME_OPTIONS = array( 'DENY', 'SAMEORIGIN' );

	const VALID_REFERRER_POLICIES = array(
		'no-referrer',
		'no-referrer-when-downgrade',
		'origin',
		'origin-when-cross-origin',
		'same-origin',
		'strict-origin',
		'strict-origin-when-cross-origin',
		'unsafe-url',
	);

	const VALID_COOKIE_SAMESITE = array( 'Lax', 'Strict', '' );

	const VALID_PP_VALUES = array( 'none', 'self', '*' );

	const PP_FEATURES = array(
		'accelerometer',
		'autoplay',
		'camera',
		'encrypted-media',
		'fullscreen',
		'geolocation',
		'gyroscope',
		'magnetometer',
		'microphone',
		'midi',
		'payment',
		'usb',
	);

	const DEFAULT_PERMISSIONS_POLICY = array(
		'accelerometer'   => 'none',
		'autoplay'        => 'self',
		'camera'          => 'none',
		'encrypted-media' => 'self',
		'fullscreen'      => 'self',
		'geolocation'     => 'none',
		'gyroscope'       => 'none',
		'magnetometer'    => 'none',
		'microphone'      => 'none',
		'midi'            => 'none',
		'payment'         => 'none',
		'usb'             => 'none',
	);

	/**
	 * Fixed header values per non-custom mode. Looked up by `build_headers()` whenever
	 * `mode != 'custom'` so per-header `custom.*` toggles cannot silently override the
	 * preset the admin picked.
	 */
	const MODE_PRESETS = array(
		'basic'       => array(
			'x_content_type_options'  => 'nosniff',
			'x_frame_options'         => 'SAMEORIGIN',
			'x_xss_protection'        => '0',
			'referrer_policy'         => '',
			'hsts_enabled'            => false,
			'hsts_max_age'            => 0,
			'hsts_include_subdomains' => false,
			'hsts_preload'            => false,
			'coop'                    => '',
			'corp'                    => '',
			'coep'                    => '',
			'x_dns_prefetch_control'  => '',
			'cache_control_admin'     => false,
			'permissions_policy'      => array(),
		),
		'recommended' => array(
			'x_content_type_options'  => 'nosniff',
			'x_frame_options'         => 'SAMEORIGIN',
			'x_xss_protection'        => '0',
			'referrer_policy'         => 'strict-origin-when-cross-origin',
			'hsts_enabled'            => true,
			'hsts_max_age'            => 31536000,
			'hsts_include_subdomains' => true,
			'hsts_preload'            => false,
			'coop'                    => '',
			'corp'                    => '',
			'coep'                    => '',
			'x_dns_prefetch_control'  => '',
			'cache_control_admin'     => false,
			'permissions_policy'      => self::DEFAULT_PERMISSIONS_POLICY,
		),
		'strict'      => array(
			'x_content_type_options'  => 'nosniff',
			'x_frame_options'         => 'SAMEORIGIN',
			'x_xss_protection'        => '0',
			'referrer_policy'         => 'strict-origin-when-cross-origin',
			'hsts_enabled'            => true,
			'hsts_max_age'            => 31536000,
			'hsts_include_subdomains' => true,
			'hsts_preload'            => false,
			'coop'                    => 'same-origin',
			'corp'                    => 'same-origin',
			'coep'                    => '',
			'x_dns_prefetch_control'  => 'off',
			'cache_control_admin'     => true,
			'permissions_policy'      => self::DEFAULT_PERMISSIONS_POLICY,
		),
	);

	const TWO_PART_TLDS = array(
		'co.uk',
		'com.au',
		'co.nz',
		'co.za',
		'com.br',
		'co.jp',
		'co.kr',
		'com.cn',
		'org.uk',
		'net.au',
		'ac.uk',
		'gov.uk',
		'co.in',
		'com.mx',
		'com.ar',
	);

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
	 * Reset singleton (for tests).
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
			'enabled'          => false,
			'mode'             => 'off',
			'custom'           => array(
				'x_content_type_options'  => 'nosniff',
				'x_frame_options'         => 'SAMEORIGIN',
				'x_xss_protection'        => '0',
				'referrer_policy'         => 'strict-origin-when-cross-origin',
				'hsts_enabled'            => true,
				'hsts_max_age'            => 31536000,
				'hsts_include_subdomains' => true,
				'hsts_preload'            => false,
				'coop'                    => 'same-origin',
				'corp'                    => 'same-origin',
				'coep'                    => '',
				'x_dns_prefetch_control'  => 'off',
				'cache_control_admin'     => true,
				'permissions_policy'      => self::DEFAULT_PERMISSIONS_POLICY,
			),
			'cookie_hardening' => true,
			'cookie_samesite'  => 'Lax',
			'csp_enabled'      => false,
			'csp_mode'         => 'report-only',
			'csp_directives'   => self::CSP_DEFAULT_DIRECTIVES,
			'csp_report_uri'   => '',
		);
	}

	/**
	 * Get current settings (lazy-loaded from DB).
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
	 * Validate and sanitize settings input.
	 *
	 * @param array $input Raw input.
	 * @return array Sanitized settings.
	 */
	public function validate_settings( $input ) {
		$defaults = self::default_settings();
		$input    = is_array( $input ) ? $input : array();
		$clean    = array();

		$clean['enabled'] = ! empty( $input['enabled'] );
		$clean['mode']    = ( isset( $input['mode'] ) && in_array( $input['mode'], self::VALID_MODES, true ) )
			? $input['mode']
			: $defaults['mode'];

		$custom_input    = isset( $input['custom'] ) && is_array( $input['custom'] ) ? $input['custom'] : array();
		$custom_defaults = $defaults['custom'];
		$clean['custom'] = array();

		$clean['custom']['x_content_type_options'] = 'nosniff';

		$clean['custom']['x_frame_options'] = ( isset( $custom_input['x_frame_options'] )
			&& in_array( $custom_input['x_frame_options'], self::VALID_X_FRAME_OPTIONS, true ) )
			? $custom_input['x_frame_options']
			: $custom_defaults['x_frame_options'];

		$clean['custom']['x_xss_protection'] = isset( $custom_input['x_xss_protection'] )
			&& in_array( $custom_input['x_xss_protection'], array( '0', '1', '1; mode=block' ), true )
			? $custom_input['x_xss_protection']
			: $custom_defaults['x_xss_protection'];

		$clean['custom']['referrer_policy'] = ( isset( $custom_input['referrer_policy'] )
			&& in_array( $custom_input['referrer_policy'], self::VALID_REFERRER_POLICIES, true ) )
			? $custom_input['referrer_policy']
			: $custom_defaults['referrer_policy'];

		$clean['custom']['hsts_enabled']            = ! empty( $custom_input['hsts_enabled'] ?? $custom_defaults['hsts_enabled'] );
		$clean['custom']['hsts_max_age']            = max( 0, (int) ( $custom_input['hsts_max_age'] ?? $custom_defaults['hsts_max_age'] ) );
		$clean['custom']['hsts_include_subdomains'] = ! empty( $custom_input['hsts_include_subdomains'] ?? $custom_defaults['hsts_include_subdomains'] );
		$clean['custom']['hsts_preload']            = ! empty( $custom_input['hsts_preload'] ?? false );

		$valid_co                = array( 'same-origin', 'same-origin-allow-popups', 'unsafe-none', '' );
		$clean['custom']['coop'] = ( isset( $custom_input['coop'] ) && in_array( $custom_input['coop'], $valid_co, true ) )
			? $custom_input['coop']
			: $custom_defaults['coop'];

		$valid_corp              = array( 'same-origin', 'same-site', 'cross-origin', '' );
		$clean['custom']['corp'] = ( isset( $custom_input['corp'] ) && in_array( $custom_input['corp'], $valid_corp, true ) )
			? $custom_input['corp']
			: $custom_defaults['corp'];

		$valid_coep              = array( 'require-corp', 'same-origin', 'unsafe-none', '' );
		$clean['custom']['coep'] = ( isset( $custom_input['coep'] ) && in_array( $custom_input['coep'], $valid_coep, true ) )
			? $custom_input['coep']
			: $custom_defaults['coep'];

		$clean['custom']['x_dns_prefetch_control'] = ( isset( $custom_input['x_dns_prefetch_control'] )
			&& in_array( $custom_input['x_dns_prefetch_control'], array( 'on', 'off' ), true ) )
			? $custom_input['x_dns_prefetch_control']
			: $custom_defaults['x_dns_prefetch_control'];

		$clean['custom']['cache_control_admin'] = ! empty( $custom_input['cache_control_admin'] ?? $custom_defaults['cache_control_admin'] );

		$pp_input                              = isset( $custom_input['permissions_policy'] ) && is_array( $custom_input['permissions_policy'] )
			? $custom_input['permissions_policy']
			: array();
		$clean['custom']['permissions_policy'] = array();
		foreach ( self::PP_FEATURES as $feature ) {
			$val = $pp_input[ $feature ] ?? $custom_defaults['permissions_policy'][ $feature ] ?? 'none';
			$clean['custom']['permissions_policy'][ $feature ] = in_array( $val, self::VALID_PP_VALUES, true )
				? $val
				: 'none';
		}

		$clean['cookie_hardening'] = ! empty( $input['cookie_hardening'] ?? $defaults['cookie_hardening'] );
		$clean['cookie_samesite']  = ( isset( $input['cookie_samesite'] )
			&& in_array( $input['cookie_samesite'], self::VALID_COOKIE_SAMESITE, true ) )
			? $input['cookie_samesite']
			: $defaults['cookie_samesite'];

		$clean['csp_enabled'] = ! empty( $input['csp_enabled'] );
		$clean['csp_mode']    = ( isset( $input['csp_mode'] ) && in_array( $input['csp_mode'], self::VALID_CSP_MODES, true ) )
			? $input['csp_mode']
			: $defaults['csp_mode'];

		$directives              = isset( $input['csp_directives'] ) && is_string( $input['csp_directives'] )
			? $input['csp_directives']
			: $defaults['csp_directives'];
		$clean['csp_directives'] = self::sanitize_csp_directives( $directives );
		$clean['csp_report_uri'] = self::sanitize_csp_report_uri( $input['csp_report_uri'] ?? '' );

		return $clean;
	}

	/**
	 * Strip control characters (incl. CR/LF that would enable header injection)
	 * and collapse repeated whitespace inside a CSP directive string.
	 *
	 * @param string $directives Raw policy text.
	 * @return string Sanitized policy.
	 */
	public static function sanitize_csp_directives( $directives ) {
		if ( ! is_string( $directives ) ) {
			return '';
		}
		$directives = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $directives );
		$directives = preg_replace( '/\s+/', ' ', (string) $directives );
		$directives = trim( (string) $directives );
		$directives = preg_replace( '/\s*;\s*/', '; ', $directives );
		$directives = trim( (string) $directives, "; \t" );
		if ( strlen( $directives ) > self::CSP_MAX_LEN ) {
			$directives = substr( $directives, 0, self::CSP_MAX_LEN );
		}
		return $directives;
	}

	/**
	 * Validate the CSP report-uri input — http(s) URL or empty.
	 *
	 * @param string $url Raw URL.
	 * @return string Sanitized URL or empty string when invalid.
	 */
	public static function sanitize_csp_report_uri( $url ) {
		if ( ! is_string( $url ) ) {
			return '';
		}
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		if ( ! preg_match( '#^https?://#i', $url ) ) {
			return '';
		}
		$clean = esc_url_raw( $url, array( 'http', 'https' ) );
		if ( '' === $clean ) {
			return '';
		}
		$scheme = wp_parse_url( $clean, PHP_URL_SCHEME );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}
		return $clean;
	}

	/**
	 * Validate, persist settings, and report to CTI.
	 *
	 * @param array $input Raw settings input.
	 * @return array Saved (validated) settings.
	 */
	public function save_settings( $input ) {
		Segurium_Settings_Writer::save( self::SETTINGS_SLUG, $input );
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
	 * Register hooks if feature is enabled and CTI consent granted.
	 */
	public function init() {
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}

		$settings = $this->get_settings();
		if ( ! $settings['enabled'] ) {
			return;
		}

		add_action( 'send_headers', array( $this, 'send_headers' ), 999 );

		if ( $settings['cookie_hardening'] && ! empty( $settings['cookie_samesite'] ) ) {
			add_action( 'set_auth_cookie', array( $this, 'harden_auth_cookie' ), 10, 6 );
			add_action( 'set_logged_in_cookie', array( $this, 'harden_logged_in_cookie' ), 10, 6 );
		}
	}

	/**
	 * Send security headers, skipping any already set by the server.
	 */
	public function send_headers() {
		$headers  = $this->build_headers();
		$existing = array();

		foreach ( headers_list() as $h ) {
			$parts = explode( ':', $h, 2 );
			if ( 2 === count( $parts ) ) {
				$existing[ strtolower( trim( $parts[0] ) ) ] = true;
			}
		}

		foreach ( $headers as $name => $value ) {
			if ( isset( $existing[ strtolower( $name ) ] ) ) {
				continue;
			}
			header( "{$name}: {$value}" );
		}
	}

	/**
	 * Assemble the headers array for the current mode and settings.
	 *
	 * @return array Header name => value pairs.
	 */
	public function build_headers() {
		$settings = $this->get_settings();
		$mode     = $settings['mode'];
		$headers  = array();

		$csp = $this->build_csp_header( $settings );
		if ( null !== $csp ) {
			$headers[ $csp['name'] ] = $csp['value'];
		}

		if ( 'off' === $mode ) {
			return $headers;
		}

		// `custom.*` flows through only when mode is 'custom'; every other mode reads
		// its full header set from MODE_PRESETS so stale per-header toggles from a
		// past Custom session cannot silently downgrade the preset.
		$values = ( 'custom' === $mode )
			? $settings['custom']
			: ( self::MODE_PRESETS[ $mode ] ?? array() );

		$headers['X-Content-Type-Options'] = $values['x_content_type_options'];
		$headers['X-Frame-Options']        = $values['x_frame_options'];
		$headers['X-XSS-Protection']       = $values['x_xss_protection'];

		if ( 'basic' === $mode ) {
			return $headers;
		}

		if ( ! empty( $values['referrer_policy'] ) ) {
			$headers['Referrer-Policy'] = $values['referrer_policy'];
		}

		$pp_value = $this->build_permissions_policy_value( $values['permissions_policy'] ?? array() );
		if ( '' !== $pp_value ) {
			$headers['Permissions-Policy'] = $pp_value;
		}

		if ( ! empty( $values['hsts_enabled'] ) && is_ssl() ) {
			$hsts = 'max-age=' . (int) ( $values['hsts_max_age'] ?? 0 );
			if ( ! empty( $values['hsts_include_subdomains'] ) ) {
				$hsts .= '; includeSubDomains';
			}
			if ( ! empty( $values['hsts_preload'] ) ) {
				$hsts .= '; preload';
			}
			$headers['Strict-Transport-Security'] = $hsts;
		}

		if ( 'recommended' === $mode ) {
			return $headers;
		}

		if ( ! empty( $values['coop'] ) ) {
			$headers['Cross-Origin-Opener-Policy'] = $values['coop'];
		}
		if ( ! empty( $values['corp'] ) ) {
			$headers['Cross-Origin-Resource-Policy'] = $values['corp'];
		}
		if ( ! empty( $values['coep'] ) ) {
			$headers['Cross-Origin-Embedder-Policy'] = $values['coep'];
		}
		if ( ! empty( $values['x_dns_prefetch_control'] ) ) {
			$headers['X-DNS-Prefetch-Control'] = $values['x_dns_prefetch_control'];
		}

		if ( ! empty( $values['cache_control_admin'] ) && $this->is_sensitive_page() ) {
			$headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0';
			$headers['Pragma']        = 'no-cache';
		}

		return $headers;
	}

	/**
	 * Compose the Content-Security-Policy header (or its Report-Only twin)
	 * from the CSP-specific settings. Returns null if CSP is disabled or the
	 * directive list is empty.
	 *
	 * @param array $settings Resolved settings array.
	 * @return array|null Either ['name' => ..., 'value' => ...] or null.
	 */
	public function build_csp_header( $settings ) {
		if ( empty( $settings['csp_enabled'] ) ) {
			return null;
		}

		$directives = isset( $settings['csp_directives'] ) ? trim( (string) $settings['csp_directives'] ) : '';
		if ( '' === $directives ) {
			return null;
		}

		$report_uri = isset( $settings['csp_report_uri'] ) ? (string) $settings['csp_report_uri'] : '';
		if ( '' !== $report_uri && false === stripos( $directives, 'report-uri' ) ) {
			$directives = rtrim( $directives, '; ' ) . '; report-uri ' . $report_uri;
		}

		$mode = isset( $settings['csp_mode'] ) && in_array( $settings['csp_mode'], self::VALID_CSP_MODES, true )
			? $settings['csp_mode']
			: 'report-only';

		return array(
			'name'  => 'enforce' === $mode ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only',
			'value' => $directives,
		);
	}

	/**
	 * Build the Permissions-Policy header value from per-feature settings.
	 *
	 * @param array $pp Per-feature permission values.
	 * @return string Assembled header value.
	 */
	public function build_permissions_policy_value( $pp ) {
		if ( empty( $pp ) || ! is_array( $pp ) ) {
			return '';
		}

		$directives = array();
		foreach ( self::PP_FEATURES as $feature ) {
			$val = $pp[ $feature ] ?? 'none';
			if ( 'none' === $val ) {
				$directives[] = $feature . '=()';
			} elseif ( 'self' === $val ) {
				$directives[] = $feature . '=(self)';
			} elseif ( '*' === $val ) {
				$directives[] = $feature . '=*';
			}
		}

		$value = apply_filters( 'segurium_permissions_policy_directives', implode( ', ', $directives ), $pp );

		return is_string( $value ) ? $value : implode( ', ', $directives );
	}

	/**
	 * Detect if the current request is a sensitive page (admin or login).
	 *
	 * @return bool
	 */
	public function is_sensitive_page() {
		if ( is_admin() ) {
			return true;
		}
		$script = isset( $_SERVER['SCRIPT_NAME'] )
			? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) )
			: '';
		return 'wp-login.php' === $script;
	}

	/**
	 * Check if a given hostname is a subdomain.
	 *
	 * @param string|null $host Hostname to check. Defaults to site's host.
	 * @return bool
	 */
	public function is_subdomain( $host = null ) {
		if ( null === $host ) {
			$host = wp_parse_url( home_url(), PHP_URL_HOST );
		}
		if ( ! $host || filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$parts = explode( '.', $host );
		if ( count( $parts ) < 3 ) {
			return false;
		}

		$last_two   = implode( '.', array_slice( $parts, -2 ) );
		$base_parts = in_array( $last_two, self::TWO_PART_TLDS, true ) ? 3 : 2;

		return count( $parts ) > $base_parts;
	}

	/**
	 * Re-emit the auth cookie with the SameSite attribute.
	 *
	 * @param string $auth_cookie  Cookie value.
	 * @param int    $expire       Expiry timestamp.
	 * @param int    $expiration   Expiration duration (unused).
	 * @param int    $user_id      User ID (unused).
	 * @param string $scheme       Auth scheme (secure_auth or auth).
	 * @param string $token        Session token (unused).
	 */
	public function harden_auth_cookie( $auth_cookie, $expire, $expiration, $user_id, $scheme, $token ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		$name = ( 'secure_auth' === $scheme ) ? SECURE_AUTH_COOKIE : AUTH_COOKIE;
		$this->set_cookie_with_samesite( $name, $auth_cookie, $expire );
	}

	/**
	 * Re-emit the logged-in cookie with the SameSite attribute.
	 *
	 * @param string $logged_in_cookie Cookie value.
	 * @param int    $expire           Expiry timestamp.
	 * @param int    $expiration       Expiration duration (unused).
	 * @param int    $user_id          User ID (unused).
	 * @param string $scheme           Auth scheme (unused).
	 * @param string $token            Session token (unused).
	 */
	public function harden_logged_in_cookie( $logged_in_cookie, $expire, $expiration, $user_id, $scheme, $token ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		$this->set_cookie_with_samesite( LOGGED_IN_COOKIE, $logged_in_cookie, $expire );
	}

	/**
	 * Set a cookie with the SameSite attribute.
	 *
	 * @param string $name   Cookie name.
	 * @param string $value  Cookie value.
	 * @param int    $expire Expiry timestamp.
	 */
	private function set_cookie_with_samesite( $name, $value, $expire ) {
		$settings = $this->get_settings();
		$samesite = ! empty( $settings['cookie_samesite'] ) ? $settings['cookie_samesite'] : 'Lax';
		$secure   = is_ssl();
		$path     = defined( 'COOKIEPATH' ) ? COOKIEPATH : '/';
		$domain   = defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '';

		if ( PHP_VERSION_ID >= 70300 ) {
			setcookie(
				$name,
				$value,
				array(
					'expires'  => $expire,
					'path'     => $path,
					'domain'   => $domain,
					'secure'   => $secure,
					'httponly' => true,
					'samesite' => $samesite,
				)
			);
		} else {
			$cookie  = rawurlencode( $name ) . '=' . rawurlencode( $value );
			$cookie .= '; Expires=' . gmdate( 'D, d M Y H:i:s T', $expire );
			$cookie .= '; Path=' . $path;
			if ( $domain ) {
				$cookie .= '; Domain=' . $domain;
			}
			if ( $secure ) {
				$cookie .= '; Secure';
			}
			$cookie .= '; HttpOnly';
			$cookie .= '; SameSite=' . $samesite;
			header( 'Set-Cookie: ' . $cookie, false );
		}
	}
}

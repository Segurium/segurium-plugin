<?php
/**
 * Geo-blocking and IP firewall functionality.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Blocks requests based on geographic location or IP firewall rules.
 */
class Segurium_Geo_Blocker {

	const CONTEXT       = 'geo_blocking';
	const SETTINGS_SLUG = 'geo';

	const CTI_INBOUND_ROUTES = array( 'actions-poke', 'scan-tick' );

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Forced answer for is_cli_request(), or null to auto-detect.
	 *
	 * @var bool|null
	 */
	private static $cli_override = null;

	/**
	 * Request body to judge instead of php://input, or null to read it.
	 *
	 * @var string|null
	 */
	private static $raw_body_override = null;

	/**
	 * Force or release the CLI-context answer.
	 *
	 * Ignored unless the PHPUnit bootstrap defined SEGURIUM_TESTING. Code
	 * that runs before `plugins_loaded` can reach every public method here,
	 * and a setter that switches the firewall off is not something to leave
	 * callable in production. It is not a security boundary — anything able
	 * to call this could unhook the blockers instead — it just keeps the
	 * test seam out of the shipped surface.
	 *
	 * @param bool|null $value True/false to force, null to auto-detect.
	 * @return void
	 */
	public static function set_cli_override( $value ) {
		if ( ! defined( 'SEGURIUM_TESTING' ) ) {
			return;
		}
		self::$cli_override = ( null === $value ) ? null : (bool) $value;
	}

	/**
	 * Force or release the request body is_signed_cti_call() verifies.
	 * Inert without SEGURIUM_TESTING, like set_cli_override().
	 *
	 * @param string|null $body Body bytes, or null to read php://input.
	 * @return void
	 */
	public static function set_raw_body_override( $body ) {
		if ( ! defined( 'SEGURIUM_TESTING' ) ) {
			return;
		}
		self::$raw_body_override = ( null === $body ) ? null : (string) $body;
	}

	/**
	 * Whether this request is a CTI-signed call to a route CTI drives.
	 *
	 * @return bool
	 */
	public static function is_signed_cti_call() {
		if ( ! class_exists( 'Segurium_CTI_Signature' ) ) {
			return false;
		}

		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' !== strtoupper( $method ) ) {
			return false;
		}

		// Exact match on the whole raw URI. A query string, PATH_INFO under
		// another script, or a `//host` request line all fail, because the
		// signature covers neither the site nor the URL.
		$home     = rtrim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		$prefix   = trim( rest_get_url_prefix(), '/' );
		$expected = array();
		foreach ( array( '', '/index.php' ) as $front ) {
			foreach ( self::CTI_INBOUND_ROUTES as $route ) {
				$uri        = $home . $front . '/' . $prefix . '/segurium/v1/' . $route;
				$expected[] = $uri;
				$expected[] = $uri . '/';
			}
		}
		if ( ! isset( $_SERVER['REQUEST_URI'] ) || ! in_array( wp_unslash( $_SERVER['REQUEST_URI'] ), $expected, true ) ) {
			return false;
		}

		$sig    = isset( $_SERVER['HTTP_X_SEGURIUM_SIGNATURE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SEGURIUM_SIGNATURE'] ) ) : '';
		$ts     = isset( $_SERVER['HTTP_X_SEGURIUM_SIGNATURE_TIMESTAMP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SEGURIUM_SIGNATURE_TIMESTAMP'] ) ) : '';
		$key_id = isset( $_SERVER['HTTP_X_SEGURIUM_SIGNATURE_KEY_ID'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_SEGURIUM_SIGNATURE_KEY_ID'] ) ) : '';
		if ( '' === $sig || '' === $ts || '' === $key_id ) {
			return false;
		}

		$body = self::$raw_body_override;
		if ( null === $body ) {
			$body = (string) file_get_contents( 'php://input' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- raw request body, not a remote URL
		}

		return Segurium_CTI_Signature::is_valid( $sig, $ts, $key_id, $body );
	}

	/**
	 * Whether this process is a command-line run rather than a visitor request.
	 *
	 * WP-CLI puts 127.0.0.1 in REMOTE_ADDR, so the empty-IP guards below
	 * never fire for it and every list rule judges the local machine as if
	 * it were a visitor. There is no visitor to judge, and the SAPI cannot
	 * be reached over HTTP, so nothing is given away by skipping.
	 *
	 * @return bool
	 */
	public static function is_cli_request() {
		if ( null !== self::$cli_override ) {
			return self::$cli_override;
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}

		return 'cli' === PHP_SAPI || 'phpdbg' === PHP_SAPI;
	}

	/**
	 * Get the singleton instance.
	 *
	 * @return self Singleton instance.
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor. Registers pending-change hooks.
	 */
	private function __construct() {
		add_action( 'segurium_pending_revert', array( $this, 'on_pending_revert' ), 10, 3 );
		add_action( 'segurium_pending_confirmed', array( $this, 'on_pending_confirmed' ), 10, 3 );
	}

	/**
	 * Hook: plugins_loaded priority 0. IP-level firewall (deny/allow list), runs before geo-blocking.
	 */
	public function maybe_block_by_firewall() {
		Segurium_Pending_Changes::check_expired( 'firewall' );

		if ( self::is_cli_request() ) {
			return;
		}

		if ( ! Segurium_Settings::get_field( 'firewall', 'enabled' ) ) {
			return;
		}

		if ( self::is_signed_cti_call() ) {
			return;
		}

		$ip = $this->get_real_ip();
		// No remote IP → not a real HTTP request (WP-CLI, internal hand-offs).
		// Nothing to evaluate; nothing to block. wp-cron.php IS reachable
		// over HTTP and DOES carry REMOTE_ADDR — it must run the firewall.
		if ( '' === (string) $ip ) {
			return;
		}

		$mode      = Segurium_Settings::get_field( 'firewall', 'mode' );
		$list_type = 'allow_list' === $mode ? 'allow' : 'block';
		// Hot path → opcached in-memory match.
		if ( class_exists( 'Segurium_Storage_IP_List_Cache' ) ) {
			$in_list = null !== Segurium_Storage_IP_List_Cache::match( $ip, $list_type );
		} else {
			$in_list = null !== Segurium_Storage::ip_match( $ip, $list_type );
		}
		$blocked = ( 'allow_list' === $mode ) ? ! $in_list : $in_list;

		if ( $blocked ) {
			$this->send_block_response();
		}
	}

	/**
	 * Hook: plugins_loaded priority 1.
	 */
	public function maybe_block_request() {
		Segurium_Pending_Changes::check_expired( 'geo_blocking' );

		if ( self::is_cli_request() ) {
			return;
		}

		if ( ! Segurium_Settings::get_field( self::SETTINGS_SLUG, 'enabled' ) ) {
			return;
		}

		if ( self::is_signed_cti_call() ) {
			return;
		}

		$ip = $this->get_real_ip();
		// No remote IP → CLI / internal. Same rule as the firewall above.
		if ( '' === (string) $ip ) {
			return;
		}

		if ( ! $this->is_ip_allowed( $ip ) ) {
			$this->send_block_response();
		}
	}

	/**
	 * Pure logic: returns true if the IP is allowed to proceed.
	 *
	 * @param string $ip Client IP address.
	 * @return bool
	 */
	public function is_ip_allowed( $ip ) {
		$country = Segurium_Geo_DB::get_country( $ip );
		if ( null === $country ) {
			return true;
		}

		$geo     = Segurium_Settings::get( self::SETTINGS_SLUG );
		$list    = $geo['blocked_countries'];
		$mode    = $geo['block_mode'];
		$in_list = in_array( $country, $list, true );

		$blocked = ( 'allow' === $mode ) ? ! $in_list : $in_list;

		if ( $blocked ) {
			$this->increment_stat( $country );
			return false;
		}

		return true;
	}

	/**
	 * Detect the real client IP, respecting configured trusted proxies.
	 *
	 * Walks the X-Forwarded-For chain from right (nearest proxy) to left
	 * (original client), stopping at the first IP not in the trusted-proxy
	 * list.  This prevents spoofed IPs injected by untrusted hops from
	 * being accepted.
	 *
	 * @return string
	 */
	public function get_real_ip() {
		// Memoize within a request. maybe_block_by_firewall
		// and maybe_block_request both call this on plugins_loaded@0/@1
		// and is_ip_allowed reaches it again. Each call costs an
		// ip_is_trusted DB query against the trusted_proxy list (which
		// can contain thousands of CIDRs from Cloudflare/proxy feeds);
		// memo cuts that to one per request.
		//
		// Cache key includes REMOTE_ADDR + XFF + CF header so PHPUnit
		// tests that mutate $_SERVER between cases cleanly invalidate.
		// In production those headers don't change between calls in
		// the same request, so the cache hits the fast path.
		static $cached_key = null;
		static $cached_ip  = null;

		$remote = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';
		$xff    = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) )
			: '';
		$cf     = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] )
			? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) )
			: '';
		$key    = $remote . '|' . $xff . '|' . $cf;
		if ( $cached_key === $key && null !== $cached_ip ) {
			return $cached_ip;
		}
		$cached_key = $key;

		if ( ! self::ip_is_trusted( $remote ) ) {
			$cached_ip = $remote;
			return $cached_ip;
		}

		// Unwrap X-Forwarded-For right-to-left through trusted proxies.
		if ( '' !== $xff ) {
			$chain = array_map( 'trim', explode( ',', $xff ) );
			for ( $i = count( $chain ) - 1; $i >= 0; $i-- ) {
				if ( false === @inet_pton( $chain[ $i ] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					continue;
				}
				if ( ! self::ip_is_trusted( $chain[ $i ] ) ) {
					$cached_ip = $chain[ $i ];
					return $cached_ip;
				}
			}
			// All entries trusted — leftmost is the best guess.
			if ( false !== @inet_pton( $chain[0] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$cached_ip = $chain[0];
				return $cached_ip;
			}
		}

		// Cloudflare-specific fallback when no XFF is present.
		// Honour HTTP_CF_CONNECTING_IP only when the
		// immediate peer (REMOTE_ADDR) is inside Cloudflare's published
		// edge ranges. Before this gate, any trusted proxy could forge
		// the header and land arbitrary IPs on get_real_ip() — enough
		// to sidestep the firewall deny-list, brute-force counter, and
		// geo-blocker. The check does not fail closed: a non-CF trusted
		// peer without XFF still produces its own REMOTE_ADDR as the
		// best guess.
		if (
			'' !== $cf
			&& Segurium_Cloudflare_Ranges::contains( $remote )
		) {
			$cf_value = trim( $cf );
			if ( false !== @inet_pton( $cf_value ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$cached_ip = $cf_value;
				return $cached_ip;
			}
		}

		$cached_ip = $remote;
		return $cached_ip;
	}

	/**
	 * Check whether an IP matches any trusted-proxy entry in ip_list.
	 *
	 * @param string $ip IP address to check.
	 * @return bool
	 */
	private static function ip_is_trusted( $ip ) {
		if ( '' === (string) $ip ) {
			return false;
		}
		// A peer on a local address is a reverse proxy in front of PHP —
		// nginx, LiteSpeed, Varnish, a CDN agent. Without this the whole
		// X-Forwarded-For walk below never runs on those installs and
		// every visitor resolves to the same private address, which
		// leaves the firewall and the geo-blocker judging the proxy
		// instead of the client.
		if ( Segurium_Geo_DB::is_local_ip( $ip ) ) {
			return true;
		}
		// Hot path. The trusted_proxy list can hold
		// thousands of CIDRs (Cloudflare ranges, proxy-detector feeds);
		// the DB matcher does ~2-N queries per call which dominates
		// every request's TTFB when the firewall is enabled. The
		// on-disk cache turns this into an opcache file include +
		// in-memory walk.
		if ( class_exists( 'Segurium_Storage_IP_List_Cache' ) ) {
			$cached = Segurium_Storage_IP_List_Cache::match( $ip, 'trusted_proxy' );
			if ( null !== $cached ) {
				return true;
			}
			// Cache lookup found nothing AND match() rebuilt the cache
			// itself if it was stale — so a null here is authoritative.
			return false;
		}
		return null !== Segurium_Storage::ip_match( $ip, 'trusted_proxy' );
	}

	/**
	 * Validate and sanitise incoming settings array.
	 *
	 * @param array $data Raw settings input.
	 * @return array|WP_Error Cleaned data or error.
	 */
	public function validate_settings( $data ) {
		$clean = array();

		$clean['enabled']    = ! empty( $data['enabled'] );
		$clean['block_mode'] = ( 'allow' === ( $data['block_mode'] ?? '' ) ) ? 'allow' : 'block';

		$clean['blocked_countries'] = array();
		foreach ( (array) ( $data['blocked_countries'] ?? array() ) as $cc ) {
			$cc = strtoupper( sanitize_text_field( $cc ) );
			if ( preg_match( '/^[A-Z]{2}$/', $cc ) ) {
				$clean['blocked_countries'][] = $cc;
			}
		}

		if ( array_key_exists( 'trusted_proxies', $data ) ) {
			$clean['trusted_proxies'] = Segurium_Trusted_Proxies::sanitize_cidr_list( (array) $data['trusted_proxies'] );
		}

		$allowed_actions       = array( 'deny_403', 'redirect', 'silent_drop' );
		$action                = sanitize_text_field( $data['block_action'] ?? 'deny_403' );
		$clean['block_action'] = in_array( $action, $allowed_actions, true ) ? $action : 'deny_403';

		$clean['block_redirect_url'] = '';
		if ( 'redirect' === $clean['block_action'] ) {
			$clean['block_redirect_url'] = esc_url_raw( $data['block_redirect_url'] ?? '' );
		}

		return $clean;
	}

	/**
	 * Apply settings to wp_options immediately (used both on initial save and on revert).
	 *
	 * @param array $settings Validated settings array.
	 */
	public function apply_settings( $settings ) {
		// Restoring a reverted value must not arm a fresh fuse, so staging
		// is off here. Runs from light tiers (visitor / login /
		// admin_other / ajax_other) when an expired pending revert fires,
		// which is why the writer and the registry load on every tier.
		Segurium_Settings_Writer::save(
			self::SETTINGS_SLUG,
			$settings,
			array( 'stage' => false )
		);
	}

	/**
	 * Validate, apply, and stage for confirmation.
	 * Returns null when disabling (no fuse needed — no self-lockout risk).
	 *
	 * @param array $data Raw input.
	 * @return string|null|WP_Error Token, null (direct save), or error.
	 */
	public function save_settings( $data ) {
		$result = Segurium_Settings_Writer::save( self::SETTINGS_SLUG, $data );
		if ( ! $result['ok'] ) {
			$error = $result['errors'][0];
			return new WP_Error( $error['code'], Segurium_Settings_Writer::error_message( $error ) );
		}
		return $result['token'];
	}

	/**
	 * Retrieve the current geo-blocking settings from wp_options.
	 *
	 * @return array Current persisted settings.
	 */
	public function get_settings() {
		return Segurium_Settings::get( self::SETTINGS_SLUG, true );
	}

	/**
	 * Retrieve per-country block statistics.
	 *
	 * @return array Per-country block counts, sorted descending.
	 */
	public function get_stats() {
		$rows  = Segurium_Storage::table_get_results(
			'stats_daily',
			'SELECT metric_key, SUM(value) AS total FROM {{table}} WHERE scope = %s GROUP BY metric_key ORDER BY total DESC',
			array( 'geo_block' ),
			ARRAY_A
		);
		$stats = array();
		foreach ( $rows as $row ) {
			$stats[ strtoupper( (string) $row['metric_key'] ) ] = (int) $row['total'];
		}
		return $stats;
	}

	/**
	 * Handle reverting pending geo-blocking changes.
	 *
	 * @param string $context   Change context identifier.
	 * @param array  $old_value Previous settings to restore.
	 * @param string $token     Pending change token.
	 * @return void
	 */
	public function on_pending_revert( $context, $old_value, $token ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		if ( self::CONTEXT !== $context ) {
			return;
		}
		$this->apply_settings( $old_value );
	}

	/**
	 * Handle confirmation of pending geo-blocking changes.
	 *
	 * @param string $context   Change context identifier.
	 * @param array  $old_value Previous settings.
	 * @param array  $new_value Newly confirmed settings.
	 * @return void
	 */
	public function on_pending_confirmed( $context, $old_value, $new_value ) {
		if ( self::CONTEXT !== $context ) {
			return;
		}
		$this->send_change_messages( $old_value, $new_value );
	}

	/**
	 * Send a block response to the client and exit.
	 *
	 * @return void
	 */
	private function send_block_response() {
		$action = Segurium_Settings::get_field( self::SETTINGS_SLUG, 'block_action' );

		if ( 'redirect' === $action ) {
			$url = Segurium_Settings::get_field( self::SETTINGS_SLUG, 'block_redirect_url' );
			if ( $url ) {
				wp_safe_redirect( $url );
				exit;
			}
		}

		if ( 'silent_drop' === $action ) {
			http_response_code( 444 );
			exit;
		}

		// Literal English — translation functions would call `_load_textdomain_just_in_time`
		// before `after_setup_theme` (this hook fires on `plugins_loaded` priority 1) and
		// trip WP 6.7's "translation triggered too early" notice. The page is shown only
		// to blocked bots, not localized users; no .mo ships anyway.
		wp_die(
			'Access from your location is not allowed.',
			'Access Denied',
			array( 'response' => 403 )
		);
	}

	/**
	 * Increment the block counter for a country.
	 *
	 * @param string $country_code ISO 3166-1 alpha-2 country code.
	 * @return void
	 */
	private function increment_stat( $country_code ) {
		$day    = gmdate( 'Y-m-d' );
		$metric = strtoupper( (string) $country_code );
		global $wpdb;
		$table = Segurium_Storage::table_name( 'stats_daily' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( 'INSERT INTO %i (day, scope, metric_key, value) VALUES (%s, %s, %s, 1) ON DUPLICATE KEY UPDATE value = value + 1', $table, $day, 'geo_block', $metric ) );

		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => 'geo_block',
					'severity'   => 1,
					'actor_ip'   => null,
					'subject'    => $metric,
					'data_json'  => (string) wp_json_encode( array( 'day' => $day ) ),
					'created_at' => time(),
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-geo-blocker] activity_log insert failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Notify CTI about country blocking changes.
	 *
	 * @param array $old          Previous settings.
	 * @param array $new_settings New settings.
	 * @return void
	 */
	private function send_change_messages( $old, $new_settings ) {
		$old_countries = $old['blocked_countries'] ?? array();
		$new_countries = $new_settings['blocked_countries'] ?? array();

		$newly_blocked   = array_values( array_diff( $new_countries, $old_countries ) );
		$newly_unblocked = array_values( array_diff( $old_countries, $new_countries ) );

		if ( ! empty( $newly_blocked ) ) {
			Segurium_Storage::cti_send_message( 'geo_country_blocked', implode( ',', $newly_blocked ) );
		}

		if ( ! empty( $newly_unblocked ) ) {
			Segurium_Storage::cti_send_message( 'geo_country_unblocked', implode( ',', $newly_unblocked ) );
		}
	}
}

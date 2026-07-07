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

	const CONTEXT = 'geo_blocking';

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

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

		if ( ! Segurium_Storage::setting_get_bool( 'segurium_firewall_enabled' ) ) {
			return;
		}

		$ip = $this->get_real_ip();
		// No remote IP → not a real HTTP request (WP-CLI, internal hand-offs).
		// Nothing to evaluate; nothing to block. wp-cron.php IS reachable
		// over HTTP and DOES carry REMOTE_ADDR — it must run the firewall.
		if ( '' === (string) $ip ) {
			return;
		}

		$mode      = Segurium_Storage::setting_get_string( 'segurium_firewall_mode', 'deny_list' );
		$list_type = 'allow_list' === $mode ? 'allow' : 'block';
		// SEGURIUM-272: hot path → opcached in-memory match.
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

		if ( ! Segurium_Storage::setting_get_bool( 'segurium_geo_blocking_enabled' ) ) {
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

		$list    = Segurium_Storage::setting_get_array( 'segurium_geo_blocked_countries' );
		$mode    = Segurium_Storage::setting_get_string( 'segurium_geo_block_mode', 'block' );
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
		// SEGURIUM-272: memoize within a request. maybe_block_by_firewall
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
		// SEGURIUM-194: honour HTTP_CF_CONNECTING_IP only when the
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
		// SEGURIUM-272: hot path. The trusted_proxy list can hold
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

		foreach ( array( 'trusted_proxies' ) as $key ) {
			if ( ! array_key_exists( $key, $data ) ) {
				continue;
			}
			$clean[ $key ] = array();
			foreach ( (array) $data[ $key ] as $entry ) {
				$entry = trim( sanitize_text_field( $entry ) );
				if ( false !== strpos( $entry, '/' ) ) {
					$parts = explode( '/', $entry, 2 );
					if ( false !== @inet_pton( $parts[0] ) && ctype_digit( $parts[1] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
						$clean[ $key ][] = $entry;
					}
				} elseif ( false !== @inet_pton( $entry ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$bits            = ( false !== strpos( $entry, ':' ) ) ? 128 : 32;
					$clean[ $key ][] = $entry . '/' . $bits;
				}
			}
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
		Segurium_Storage::setting_set( 'segurium_geo_blocking_enabled', ! empty( $settings['enabled'] ) );
		Segurium_Storage::setting_set( 'segurium_geo_block_mode', ( 'allow' === ( $settings['block_mode'] ?? '' ) ) ? 'allow' : 'block' );
		Segurium_Storage::setting_set( 'segurium_geo_blocked_countries', $settings['blocked_countries'] ?? array() );
		if ( array_key_exists( 'trusted_proxies', $settings ) ) {
			// SEGURIUM-392: must call the firewall-group helper, NOT the
			// main Segurium class. This path runs from light tiers
			// (visitor/login/admin_other/ajax_other) when an expired
			// pending revert fires, and the main class is not loaded
			// there. Calling Segurium:: here previously fataled wp-admin.
			Segurium_Trusted_Proxies::manual_save( (array) $settings['trusted_proxies'] );
		}
		Segurium_Storage::setting_set( 'segurium_geo_block_action', $settings['block_action'] ?? 'deny_403' );
		Segurium_Storage::setting_set( 'segurium_geo_block_redirect_url', $settings['block_redirect_url'] ?? '' );
	}

	/**
	 * Validate, apply, and stage for confirmation.
	 * Returns null when disabling (no fuse needed — no self-lockout risk).
	 *
	 * @param array $data Raw input.
	 * @return string|null|WP_Error Token, null (direct save), or error.
	 */
	public function save_settings( $data ) {
		$clean = $this->validate_settings( $data );
		if ( is_wp_error( $clean ) ) {
			return $clean;
		}

		$old = $this->get_settings();
		$this->apply_settings( $clean );

		if ( empty( $clean['enabled'] ) ) {
			// segurium_pending_ctx_* lookups are handled by Segurium_Pending_Changes.
			$existing = Segurium_Storage::setting_get( 'segurium_pending_ctx_' . self::CONTEXT );
			if ( $existing ) {
				Segurium_Pending_Changes::cancel( $existing );
			}
			return null;
		}

		return Segurium_Pending_Changes::stage( self::CONTEXT, $old, $clean );
	}

	/**
	 * Retrieve the current geo-blocking settings from wp_options.
	 *
	 * @return array Current persisted settings.
	 */
	public function get_settings() {
		return array(
			'enabled'            => Segurium_Storage::setting_get_bool( 'segurium_geo_blocking_enabled' ),
			'block_mode'         => Segurium_Storage::setting_get_string( 'segurium_geo_block_mode', 'block' ),
			'blocked_countries'  => Segurium_Storage::setting_get_array( 'segurium_geo_blocked_countries' ),
			'trusted_proxies'    => Segurium_Trusted_Proxies::manual_read(),
			'block_action'       => Segurium_Storage::setting_get_string( 'segurium_geo_block_action', 'deny_403' ),
			'block_redirect_url' => Segurium_Storage::setting_get_string( 'segurium_geo_block_redirect_url' ),
		);
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
		$action = Segurium_Storage::setting_get_string( 'segurium_geo_block_action', 'deny_403' );

		if ( 'redirect' === $action ) {
			$url = Segurium_Storage::setting_get_string( 'segurium_geo_block_redirect_url' );
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

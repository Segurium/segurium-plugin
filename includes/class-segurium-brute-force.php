<?php
/**
 * Brute-force protection for wp-login.php and XML-RPC.
 *
 * Hybrid storage:
 *   - Per-IP and per-username failure counters live in transients (cheap, auto-expire).
 *   - Lockouts live in a custom DB table so they survive object-cache flushes.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Brute-force protection handler for wp-login.php and XML-RPC endpoints.
 */
class Segurium_Brute_Force {

	const OPTION_SETTINGS   = 'segurium_bf_settings';
	const OPTION_DB_VERSION = 'segurium_bf_db_version';
	const DB_VERSION        = 3;
	const CRON_PRUNE        = 'segurium_bf_prune';
	const NONCE_ACTION      = 'segurium_bf';

	const TRANSIENT_IP   = 'segurium_bf_ip_';
	const TRANSIENT_USER = 'segurium_bf_user_';

	const SURFACE_LOGIN  = 'wp-login';
	const SURFACE_XMLRPC = 'xmlrpc';

	const EVENT_ATTEMPT      = 'attempt';
	const EVENT_LOCKOUT      = 'lockout';
	const EVENT_HONEYPOT     = 'honeypot';
	const EVENT_UNLOCK       = 'unlock';
	const EVENT_CAPTCHA_FAIL = 'captcha_fail';

	const ERR_LOCKOUT  = 'bf_lockout';
	const ERR_HONEYPOT = 'bf_honeypot';
	const ERR_CAPTCHA  = 'bf_captcha';

	const REASON_THRESHOLD = 'threshold';
	const REASON_HONEYPOT  = 'honeypot';

	/**
	 * Priority of the `authenticate` callback that re-asserts our verdict.
	 *
	 * Must sit above every core callback that can replace an incoming error
	 * with a WP_User: wp_authenticate_username_password / _email_password /
	 * _application_password at 20, and wp_authenticate_cookie at 30. Must stay
	 * below 99 so the 2FA challenge never starts for a blocked request.
	 */
	const AUTH_ENFORCE_PRIORITY = 50;

	const CTI_LOCKOUT      = 'brute_force_lockout';
	const CTI_HONEYPOT     = 'brute_force_honeypot';
	const CTI_CAPTCHA_FAIL = 'brute_force_captcha_fail';

	const HCAPTCHA_API_JS         = 'https://js.hcaptcha.com/1/api.js';
	const HCAPTCHA_VERIFY         = 'https://hcaptcha.com/siteverify';
	const HCAPTCHA_RESPONSE_FIELD = 'h-captcha-response';

	const COUNTER_IP   = 'ip';
	const COUNTER_USER = 'user';

	// UI mode for the admin Brute-Force tab. Recommended → all 9 brute-force
	// inputs are locked to default_settings() values; Custom → admin edits each
	// field directly. The flag is purely a UI hint; the runtime enforcement
	// path validates whatever values land in the option regardless of mode.
	const MODE_RECOMMENDED = 'recommended';
	const MODE_CUSTOM      = 'custom';

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Cached settings, lazy-loaded via get_settings().
	 *
	 * @var array|null
	 */
	private $settings = null;

	/**
	 * Per-request memoized resolved IP.
	 *
	 * @var string|null
	 */
	private $real_ip_cache = null;

	/**
	 * REMOTE_ADDR value when the IP cache was populated.
	 *
	 * @var string|null
	 */
	private $real_ip_cache_remote = null;

	/**
	 * Per-request memoized firewall verdict keyed by IP.
	 *
	 * @var array<string, string>
	 */
	private $firewall_verdict_cache = array();

	/**
	 * The WP_Error authenticate_check issued for the current request, if any.
	 *
	 * Serves two purposes: enforce_block re-asserts it after core has had its
	 * turn on the `authenticate` filter, and the wp_login_failed handler uses
	 * its presence to skip re-counting a verdict we issued ourselves.
	 *
	 * @var WP_Error|null
	 */
	private $blocked_error = null;

	/**
	 * Guard so init() cannot double-register hooks within the same instance.
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
	 * Read a value from a caller-supplied input snapshot.
	 *
	 * The helper itself does NOT touch $_POST — the caller is responsible
	 * for snapshotting the already-unslashed request payload in a context
	 * that has been gated upstream (here: the WP `authenticate` filter,
	 * which only runs from wp-login.php / XML-RPC after WP's own request
	 * routing).
	 *
	 * @param array  $source Caller-owned, already-unslashed input array.
	 * @param string $key    Key to read.
	 * @return string
	 */
	private static function post_value( array $source, $key ) {
		$value = isset( $source[ $key ] ) ? $source[ $key ] : '';
		if ( is_array( $value ) ) {
			return '';
		}
		return (string) $value;
	}

	/**
	 * Drop the singleton and remove any registered hooks — for use in tests only.
	 */
	public static function reset_instance() {
		if ( self::$instance ) {
			$inst = self::$instance;
			remove_action( 'login_init', array( $inst, 'maybe_block_locked_request' ) );
			remove_filter( 'authenticate', array( $inst, 'authenticate_check' ), 1 );
			remove_filter( 'authenticate', array( $inst, 'enforce_block' ), self::AUTH_ENFORCE_PRIORITY );
			remove_action( 'wp_login_failed', array( $inst, 'on_login_failed' ), 10 );
			remove_action( 'wp_login', array( $inst, 'on_login_success' ), 10 );
			remove_action( 'login_form', array( $inst, 'render_honeypot_field' ) );
			remove_action( 'login_form', array( $inst, 'render_hcaptcha_widget' ) );
			remove_action( 'login_enqueue_scripts', array( $inst, 'enqueue_hcaptcha' ) );
			remove_action( self::CRON_PRUNE, array( $inst, 'prune_old_records' ) );
		}
		self::$instance = null;
	}

	/**
	 * Constructor. Settings are lazy-loaded.
	 */
	private function __construct() {
		// Settings are lazy-loaded.
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Schema management.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Create or upgrade the lockout and log database tables.
	 *
	 * @return void
	 */
	public static function create_tables() {
		global $wpdb;

		// Stage 5 folded BF log into activity_log; Stage 6 folds BF lockouts
		// into the unified ip_list table. Drop the two legacy standalone
		// tables if an older install still has them.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table identifier built from $wpdb->prefix + hard-coded suffix
		$wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_bf_log`" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table identifier built from $wpdb->prefix + hard-coded suffix
		$wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_bf_lockouts`" );

		Segurium_Storage::setting_set( self::OPTION_DB_VERSION, self::DB_VERSION );
	}

	/**
	 * Drop the lockout and log database tables.
	 *
	 * @return void
	 */
	public static function drop_tables() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table identifier built from $wpdb->prefix + hard-coded suffix
		$wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_bf_lockouts`" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table identifier built from $wpdb->prefix + hard-coded suffix
		$wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_bf_log`" );
		Segurium_Storage::setting_delete( self::OPTION_DB_VERSION );
	}

	/**
	 * Paginated firewall-blocked log slice kept for API compatibility.
	 *
	 * @param int $limit  Results per call.
	 * @param int $offset Offset.
	 * @return array
	 */
	public function get_active_firewall_blocks( $limit = 50, $offset = 0 ) {
		return Segurium_Storage::ip_list( 'block', $limit, $offset );
	}

	/**
	 * Cheap version check that runs on every plugin load via init().
	 * If the stored DB version is older than the constant, run dbDelta to create
	 * or upgrade the tables. The option is autoloaded so the no-op path is one
	 * in-memory array lookup.
	 */
	public static function maybe_upgrade_schema() {
		if ( Segurium_Storage::setting_get_int( self::OPTION_DB_VERSION ) >= self::DB_VERSION ) {
			return;
		}
		self::create_tables();
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Settings.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Return the default brute-force settings array.
	 *
	 * @return array
	 */
	public static function default_settings() {
		return array(
			'enabled'                => false,
			'protect_xmlrpc'         => true,
			'max_attempts'           => 5,
			'count_window'           => 1800,
			'tier1_duration'         => 900,
			'tier2_threshold'        => 3,
			'tier2_duration'         => 86400,
			'lockout_history_window' => 604800,
			'honeypot_enabled'       => true,
			'honeypot_field_name'    => 'segurium_hpot',
			'hcaptcha_enabled'       => false,
			'hcaptcha_site_key'      => '',
			'hcaptcha_secret_key'    => '',
			'captcha_threshold'      => 3,
			'log_retention_days'     => 30,
			'settings_mode'          => self::MODE_RECOMMENDED,
		);
	}

	/**
	 * Get the current brute-force settings, loading them if necessary.
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
	 * Load settings from the database and merge with defaults.
	 *
	 * @return void
	 */
	private function load_settings() {
		$persisted      = Segurium_Storage::setting_get_array( self::OPTION_SETTINGS );
		$this->settings = wp_parse_args( $persisted, self::default_settings() );
	}

	/**
	 * Validate and sanitize brute-force settings input.
	 *
	 * @param array $input Raw settings input.
	 * @return array Sanitized settings.
	 */
	public function validate_settings( $input ) {
		$defaults = self::default_settings();
		$input    = is_array( $input ) ? $input : array();
		$clean    = array();

		$clean['enabled']          = ! empty( $input['enabled'] );
		$clean['protect_xmlrpc']   = array_key_exists( 'protect_xmlrpc', $input ) ? ! empty( $input['protect_xmlrpc'] ) : $defaults['protect_xmlrpc'];
		$clean['honeypot_enabled'] = array_key_exists( 'honeypot_enabled', $input ) ? ! empty( $input['honeypot_enabled'] ) : $defaults['honeypot_enabled'];

		$clean['max_attempts']           = max( 2, (int) ( $input['max_attempts'] ?? $defaults['max_attempts'] ) );
		$clean['count_window']           = max( 60, (int) ( $input['count_window'] ?? $defaults['count_window'] ) );
		$clean['tier1_duration']         = max( 60, (int) ( $input['tier1_duration'] ?? $defaults['tier1_duration'] ) );
		$clean['tier2_threshold']        = max( 1, (int) ( $input['tier2_threshold'] ?? $defaults['tier2_threshold'] ) );
		$clean['tier2_duration']         = max( $clean['tier1_duration'], (int) ( $input['tier2_duration'] ?? $defaults['tier2_duration'] ) );
		$clean['lockout_history_window'] = max( 3600, (int) ( $input['lockout_history_window'] ?? $defaults['lockout_history_window'] ) );
		$clean['log_retention_days']     = max( 1, (int) ( $input['log_retention_days'] ?? $defaults['log_retention_days'] ) );

		$field_name = isset( $input['honeypot_field_name'] ) ? sanitize_text_field( (string) $input['honeypot_field_name'] ) : $defaults['honeypot_field_name'];
		if ( ! preg_match( '/^[a-z][a-z0-9_]{2,32}$/i', $field_name ) ) {
			$field_name = $defaults['honeypot_field_name'];
		}
		$clean['honeypot_field_name'] = $field_name;

		$existing                  = Segurium_Storage::setting_get_array( self::OPTION_SETTINGS );
		$clean['hcaptcha_enabled'] = ! empty( $input['hcaptcha_enabled'] );

		$site_key                   = isset( $input['hcaptcha_site_key'] ) ? sanitize_text_field( (string) $input['hcaptcha_site_key'] ) : '';
		$clean['hcaptcha_site_key'] = ( strlen( $site_key ) >= 8 ) ? substr( $site_key, 0, 200 ) : '';

		// Treat empty submitted secret as "keep existing": the admin UI never shows the
		// stored secret back to the browser, so a save without re-typing must not wipe it.
		$secret_in = isset( $input['hcaptcha_secret_key'] ) ? sanitize_text_field( (string) $input['hcaptcha_secret_key'] ) : '';
		if ( '' === $secret_in ) {
			$clean['hcaptcha_secret_key'] = $existing['hcaptcha_secret_key'] ?? '';
		} elseif ( strlen( $secret_in ) >= 8 ) {
			$clean['hcaptcha_secret_key'] = substr( $secret_in, 0, 200 );
		} else {
			$clean['hcaptcha_secret_key'] = '';
		}

		// captcha_threshold must be at least 1 and strictly less than max_attempts so the
		// CAPTCHA actually has a chance to fire before the hard lockout.
		$threshold                  = (int) ( $input['captcha_threshold'] ?? $defaults['captcha_threshold'] );
		$clean['captcha_threshold'] = max( 1, min( $threshold, $clean['max_attempts'] - 1 ) );

		$clean['settings_mode'] = ( self::MODE_CUSTOM === ( $input['settings_mode'] ?? '' ) )
			? self::MODE_CUSTOM
			: self::MODE_RECOMMENDED;

		return $clean;
	}

	/**
	 * Validate, save, and return the brute-force settings.
	 *
	 * @param array $input Raw settings input.
	 * @return array Sanitized settings that were persisted.
	 */
	public function save_settings( $input ) {
		$clean = $this->validate_settings( $input );
		Segurium_Storage::setting_set( self::OPTION_SETTINGS, $clean );
		$this->settings = $clean;
		return $clean;
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Hook registration.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Register WordPress hooks for brute-force protection.
	 *
	 * @return void
	 */
	public function init() {
		// Self-heal the schema regardless of feature state. The activation hook only
		// fires on (re)activation, so a plugin update or a test bootstrap that loads
		// the file without going through activation would otherwise leave the tables
		// missing and every wp_login_failed write would error out.
		self::maybe_upgrade_schema();

		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}
		if ( $this->hooks_registered ) {
			return;
		}
		$this->hooks_registered = true;

		// Hook on login_init (not plugins_loaded) so wp_die() runs after WordPress
		// is fully bootstrapped — otherwise the wp_die error template can call
		// is_embed()/is_search() before the main query exists and trip "doing it
		// wrong" notices on the lockout page. That only covers wp-login.php page
		// loads; the pair of authenticate callbacks below covers credentials that
		// reach wp_authenticate() on either login surface. Both still gate on
		// is_login_surface(), so a front-end login form calling wp_signon() from
		// some other URL is out of scope here.
		add_action( 'login_init', array( $this, 'maybe_block_locked_request' ) );
		add_filter( 'authenticate', array( $this, 'authenticate_check' ), 1, 3 );
		add_filter( 'authenticate', array( $this, 'enforce_block' ), self::AUTH_ENFORCE_PRIORITY, 3 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 1 );
		add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 1 );

		if ( ! empty( $settings['honeypot_enabled'] ) ) {
			add_action( 'login_form', array( $this, 'render_honeypot_field' ) );
		}

		if ( $this->hcaptcha_active() ) {
			add_action( 'login_enqueue_scripts', array( $this, 'enqueue_hcaptcha' ) );
			add_action( 'login_form', array( $this, 'render_hcaptcha_widget' ) );
		}

		add_action( self::CRON_PRUNE, array( $this, 'prune_old_records' ) );

		// Self-heal the prune cron in case it was cleared by a migration or another plugin.
		self::schedule_prune();
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Request lifecycle.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Block an already-locked-out IP before the login form renders.
	 *
	 * @return void
	 */
	public function maybe_block_locked_request() {
		if ( ! $this->is_login_surface() ) {
			return;
		}
		$ip = $this->get_real_ip();
		if ( ! $ip ) {
			return;
		}
		if ( $this->is_whitelisted( $ip ) ) {
			return;
		}
		if ( ! $this->is_locked_out( $ip ) ) {
			return;
		}
		$this->send_lockout_response( $ip );
	}

	/**
	 * Hook: authenticate filter (priority 1).
	 *
	 * @param null|WP_User|WP_Error $user     Current authentication result.
	 * @param string                $username  Submitted username.
	 * @param string                $password  Submitted password.
	 * @return null|WP_User|WP_Error
	 */
	public function authenticate_check( $user, $username, $password ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		// This is the WP `authenticate` filter callback.
		// It runs from wp-login.php after WP has accepted the form post.
		// There is no nonce on the WP login form to verify here and no
		// user is yet authenticated (that is the whole point of this
		// filter).

		if ( $user instanceof WP_User ) {
			return $user;
		}
		if ( ! $this->is_login_surface() ) {
			return $user;
		}
		$ip = $this->get_real_ip();
		if ( ! $ip ) {
			return $user;
		}
		if ( $this->is_whitelisted( $ip ) ) {
			return $user;
		}

		if ( $this->is_locked_out( $ip ) ) {
			return $this->block( $this->wp_error_lockout( $ip ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WP login filter; values sanitized at use.
		$post = isset( $_POST ) && is_array( $_POST ) ? wp_unslash( $_POST ) : array();

		$settings = $this->get_settings();
		if ( ! empty( $settings['honeypot_enabled'] ) ) {
			$field = $settings['honeypot_field_name'];
			if ( '' !== trim( sanitize_text_field( self::post_value( $post, $field ) ) ) ) {
				$this->log_event( self::EVENT_HONEYPOT, $ip, $username );
				$this->apply_lockout( $ip, $username, self::REASON_HONEYPOT );
				return $this->block(
					new WP_Error(
						self::ERR_HONEYPOT,
						esc_html__( 'Login blocked.', 'segurium' )
					)
				);
			}
		}

		if ( $this->should_show_hcaptcha( $ip ) ) {
			$token = trim( sanitize_text_field( self::post_value( $post, self::HCAPTCHA_RESPONSE_FIELD ) ) );
			if ( ! $this->verify_hcaptcha( $ip, $token ) ) {
				$this->log_event( self::EVENT_CAPTCHA_FAIL, $ip, $username );
				$this->report_to_cti( self::CTI_CAPTCHA_FAIL, $ip, $username, array() );
				return $this->block(
					new WP_Error(
						self::ERR_CAPTCHA,
						esc_html__( 'Please complete the CAPTCHA challenge.', 'segurium' )
					)
				);
			}
		}

		return $user;
	}

	/**
	 * Record a self-issued verdict for this request and hand it back to the filter.
	 *
	 * @param WP_Error $error The verdict.
	 * @return WP_Error
	 */
	private function block( WP_Error $error ) {
		$this->blocked_error = $error;
		return $error;
	}

	/**
	 * Hook: authenticate filter (priority AUTH_ENFORCE_PRIORITY).
	 *
	 * Returning a WP_Error from priority 1 is not enforcement.
	 * Core's wp_authenticate_username_password() runs at 20 and only honours an
	 * incoming error when a credential is empty — with both fields filled it
	 * authenticates anyway and replaces our verdict with a WP_User. On
	 * wp-login.php page loads maybe_block_locked_request() already sent a 403,
	 * but XML-RPC reached this point unguarded, so a locked-out IP holding the
	 * correct password still got in.
	 *
	 * Re-assert the verdict once core has had its turn. This only re-asserts a
	 * verdict authenticate_check already recorded, so the is_login_surface()
	 * gate still decides which surfaces are covered.
	 *
	 * @param null|WP_User|WP_Error $user     Current authentication result.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return null|WP_User|WP_Error
	 */
	public function enforce_block( $user, $username, $password ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( null === $this->blocked_error ) {
			return $user;
		}
		return $this->blocked_error;
	}

	/**
	 * Handle a failed login attempt by incrementing counters and applying lockouts.
	 *
	 * @param string $username The username that failed to authenticate.
	 * @return void
	 */
	public function on_login_failed( $username ) {
		if ( null !== $this->blocked_error ) {
			// Authenticate filter already returned a self-issued verdict for this
			// request; don't double-count. Reset so subsequent requests in the same
			// PHP process (e.g. tests) start clean.
			$this->blocked_error = null;
			return;
		}

		if ( ! $this->is_login_surface() ) {
			return;
		}

		$this->record_failed_attempt( $username );
	}

	/**
	 * Count a failed credential check and lock the IP out once it crosses
	 * the threshold.
	 *
	 * Public because authentication surfaces the `authenticate` filter does
	 * not cover must call it directly. `on_login_failed()` is
	 * the hook-driven entry point for wp-login.php and XML-RPC; the pre-login
	 * 2FA AJAX endpoint calls this method itself, since `wp_login_failed`
	 * fires on that request but `is_login_surface()` rejects admin-ajax.php.
	 *
	 * @param string $username The username that failed to authenticate.
	 * @return void
	 */
	public function record_failed_attempt( $username ) {
		if ( empty( $this->get_settings()['enabled'] ) ) {
			return;
		}
		$ip = $this->get_real_ip();
		if ( ! $ip ) {
			return;
		}
		if ( $this->is_whitelisted( $ip ) ) {
			return;
		}
		if ( $this->is_already_blocked( $ip ) ) {
			return;
		}
		if ( $this->is_locked_out( $ip ) ) {
			return;
		}

		$username   = is_string( $username ) ? trim( $username ) : '';
		$ip_count   = $this->incr_counter( self::COUNTER_IP, $ip );
		$user_count = '' !== $username ? $this->incr_counter( self::COUNTER_USER, $username ) : 0;

		$this->log_event( self::EVENT_ATTEMPT, $ip, $username );

		$max = $this->get_settings()['max_attempts'];
		if ( $ip_count >= $max || $user_count >= $max ) {
			$this->apply_lockout( $ip, $username, self::REASON_THRESHOLD );
		}
	}

	/**
	 * Lockout verdict for the current request, for callers that authenticate
	 * outside the `authenticate` filter.
	 *
	 * Callers must deny the request before reaching `wp_authenticate()`. The
	 * `authenticate` filter cannot cover them: `authenticate_check` bails on
	 * anything that is not a login surface, so neither it nor `enforce_block`
	 * ever runs for admin-ajax.
	 *
	 * @return WP_Error|null Lockout error, or null when the request may proceed.
	 */
	public function lockout_error_for_request() {
		if ( empty( $this->get_settings()['enabled'] ) ) {
			return null;
		}
		$ip = $this->get_real_ip();
		if ( ! $ip ) {
			return null;
		}
		if ( $this->is_whitelisted( $ip ) ) {
			return null;
		}
		if ( ! $this->is_locked_out( $ip ) ) {
			return null;
		}
		return $this->wp_error_lockout( $ip );
	}

	/**
	 * Clear the IP failure counter after a successful login.
	 *
	 * @param string $username The username that successfully authenticated.
	 * @return void
	 */
	public function on_login_success( $username ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		$ip = $this->get_real_ip();
		if ( $ip ) {
			$this->clear_counter( self::COUNTER_IP, $ip );
		}
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Counters (transients).
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Build the transient key for a counter.
	 *
	 * @param string $kind  Counter kind (self::COUNTER_IP or self::COUNTER_USER).
	 * @param string $value IP address or username.
	 * @return string
	 */
	private function counter_key( $kind, $value ) {
		$prefix = self::COUNTER_USER === $kind ? self::TRANSIENT_USER : self::TRANSIENT_IP;
		return $prefix . sha1( $value );
	}

	/**
	 * Increment a failure counter and return the new value.
	 *
	 * @param string $kind  Counter kind (self::COUNTER_IP or self::COUNTER_USER).
	 * @param string $value IP address or username.
	 * @return int
	 */
	public function incr_counter( $kind, $value ) {
		$key  = $this->counter_key( $kind, $value );
		$next = (int) get_transient( $key ) + 1;
		set_transient( $key, $next, $this->get_settings()['count_window'] );
		return $next;
	}

	/**
	 * Read the current failure counter value.
	 *
	 * @param string $kind  Counter kind (self::COUNTER_IP or self::COUNTER_USER).
	 * @param string $value IP address or username.
	 * @return int
	 */
	public function read_counter( $kind, $value ) {
		return (int) get_transient( $this->counter_key( $kind, $value ) );
	}

	/**
	 * Delete a failure counter transient.
	 *
	 * @param string $kind  Counter kind (self::COUNTER_IP or self::COUNTER_USER).
	 * @param string $value IP address or username.
	 * @return void
	 */
	public function clear_counter( $kind, $value ) {
		delete_transient( $this->counter_key( $kind, $value ) );
	}

	/**
	 * Read the IP failure counter (test and back-compat shortcut).
	 *
	 * @param string $ip IP address.
	 * @return int
	 */
	public function read_ip_counter( $ip ) {
		return $this->read_counter( self::COUNTER_IP, $ip );
	}

	/**
	 * Read the username failure counter (test and back-compat shortcut).
	 *
	 * @param string $username Username.
	 * @return int
	 */
	public function read_username_counter( $username ) {
		return $this->read_counter( self::COUNTER_USER, $username );
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Lockout state (DB).
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Check whether the given IP is currently locked out.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public function is_locked_out( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		return null !== Segurium_Storage::ip_match( $ip, 'bf_lockout' );
	}

	/**
	 * Get the active lockout row (if any).
	 *
	 * @param string $ip IP address.
	 * @return array|null
	 */
	public function get_active_lockout( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return null;
		}
		$row = Segurium_Storage::ip_match( $ip, 'bf_lockout' );
		if ( null === $row ) {
			return null;
		}
		$tier = 1;
		if ( ! empty( $row['reason'] ) && preg_match( '/tier:(\d)/', (string) $row['reason'], $m ) ) {
			$tier = (int) $m[1];
		}
		return array(
			'id'          => (int) $row['id'],
			'ip'          => isset( $row['ip_hex'] ) ? hex2bin( (string) $row['ip_hex'] ) : '',
			'ip_display'  => $ip,
			'tier'        => $tier,
			'created_at'  => (int) $row['created_at'],
			'expires_at'  => null !== $row['expires_at'] ? (int) $row['expires_at'] : 0,
			'unlocked_at' => null,
		);
	}

	/**
	 * Apply (create) a lockout for an IP.
	 *
	 * @param string $ip       IP address to lock out.
	 * @param string $username Username associated with the attempt.
	 * @param string $reason   self::REASON_THRESHOLD or self::REASON_HONEYPOT.
	 *                         Honeypot lockouts skip tier escalation and use a dedicated CTI message type.
	 * @return void
	 */
	public function apply_lockout( $ip, $username, $reason = self::REASON_THRESHOLD ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}
		$settings = $this->get_settings();

		$tier = 1;
		if ( self::REASON_HONEYPOT !== $reason ) {
			$cutoff = time() - $settings['lockout_history_window'];
			$past   = (int) Segurium_Storage::table_get_var(
				'activity_log',
				'SELECT COUNT(*) FROM {{table}} WHERE event_type = %s AND actor_ip = %s AND created_at >= %d',
				array( self::event_type( self::EVENT_LOCKOUT ), Segurium_IP::pack( $ip ), $cutoff )
			);
			if ( ( $past + 1 ) >= $settings['tier2_threshold'] ) {
				$tier = 2;
			}
		}

		$duration = ( 2 === $tier ) ? $settings['tier2_duration'] : $settings['tier1_duration'];
		$now      = time();

		Segurium_Storage::ip_add(
			$ip,
			'bf_lockout',
			$now + $duration,
			'tier:' . $tier,
			'bf',
			128
		);

		$this->log_event( self::EVENT_LOCKOUT, $ip, $username, $tier );
		$this->clear_counter( self::COUNTER_IP, $ip );

		$message_type = self::REASON_HONEYPOT === $reason ? self::CTI_HONEYPOT : self::CTI_LOCKOUT;
		$this->report_to_cti(
			$message_type,
			$ip,
			$username,
			array(
				'tier'     => $tier,
				'duration' => $duration,
				'attempts' => $settings['max_attempts'],
			)
		);
	}

	/**
	 * Unlock an IP by marking active lockout rows as unlocked.
	 *
	 * @param string $ip IP address.
	 * @return bool True if any rows were updated.
	 */
	public function unlock_ip( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		$existed = null !== Segurium_Storage::ip_match( $ip, 'bf_lockout' );
		if ( ! $existed ) {
			return false;
		}
		Segurium_Storage::ip_remove( $ip, 'bf_lockout', 128 );
		$this->log_event( self::EVENT_UNLOCK, $ip, '' );
		return true;
	}

	/**
	 * Paginated active lockouts for the admin UI.
	 *
	 * @param int $page     Page number.
	 * @param int $per_page Results per page.
	 * @return array {rows, total, page, per_page}
	 */
	public function get_active_lockouts( $page = 1, $per_page = 20 ) {
		$page     = max( 1, (int) $page );
		$per_page = max( 1, min( 100, (int) $per_page ) );
		$offset   = ( $page - 1 ) * $per_page;

		$total = Segurium_Storage::ip_count( 'bf_lockout' );
		$raw   = Segurium_Storage::ip_list( 'bf_lockout', $per_page, $offset );

		$rows = array();
		foreach ( $raw as $r ) {
			$bin  = isset( $r['ip_hex'] ) && '' !== $r['ip_hex'] ? hex2bin( (string) $r['ip_hex'] ) : '';
			$ip   = $bin ? (string) Segurium_IP::unpack( $bin ) : '';
			$tier = 1;
			if ( ! empty( $r['reason'] ) && preg_match( '/tier:(\d)/', (string) $r['reason'], $m ) ) {
				$tier = (int) $m[1];
			}
			$rows[] = array(
				'id'         => (int) $r['id'],
				'ip_display' => $ip,
				'tier'       => $tier,
				'created_at' => (int) $r['created_at'],
				'expires_at' => null !== $r['expires_at'] ? (int) $r['expires_at'] : 0,
			);
		}

		return array(
			'rows'     => $rows,
			'total'    => $total,
			'page'     => $page,
			'per_page' => $per_page,
		);
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Audit log.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Insert an event row into the brute-force log table.
	 *
	 * @param string   $event    Event type constant.
	 * @param string   $ip       IP address.
	 * @param string   $username Username associated with the event.
	 * @param int|null $tier     Lockout tier, if applicable.
	 * @return void
	 */
	public function log_event( $event, $ip, $username, $tier = null ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}
		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => self::event_type( $event ),
					'severity'   => self::severity_for_event( $event ),
					'actor_ip'   => Segurium_IP::pack( $ip ),
					'subject'    => '' !== $username ? substr( (string) $username, 0, 191 ) : null,
					'data_json'  => (string) wp_json_encode(
						array(
							'event'      => $event,
							'tier'       => null === $tier ? null : (int) $tier,
							'surface'    => $this->detect_surface(),
							'ip_display' => (string) $ip,
						)
					),
					'created_at' => time(),
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-brute-force] log_event failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Translate a BF event code into the activity_log event_type vocabulary.
	 *
	 * @param string $event Event constant.
	 * @return string
	 */
	private static function event_type( $event ) {
		return 'brute_force_' . preg_replace( '/[^a-z0-9_]/i', '', (string) $event );
	}

	/**
	 * Map BF events to a severity bucket.
	 *
	 * @param string $event Event constant.
	 * @return int
	 */
	private static function severity_for_event( $event ) {
		switch ( $event ) {
			case self::EVENT_LOCKOUT:
				return 3;
			case self::EVENT_HONEYPOT:
				return 2;
			case self::EVENT_CAPTCHA_FAIL:
				return 2;
			case self::EVENT_UNLOCK:
				return 0;
			default:
				return 1;
		}
	}

	/**
	 * Delete old log and lockout records based on retention settings.
	 *
	 * @return void
	 */
	public function prune_old_records() {
		global $wpdb;
		$settings   = $this->get_settings();
		$log_cutoff = time() - ( $settings['log_retention_days'] * DAY_IN_SECONDS );

		$activity  = Segurium_Storage::table_name( 'activity_log' );
		$like_expr = $wpdb->esc_like( 'brute_force_' ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE event_type LIKE %s AND created_at < %d', $activity, $like_expr, $log_cutoff ) );

		// Expired BF lockouts are swept by Segurium_Storage::ip_gc(); trigger
		// a run here so the BF prune cron retains its historical behaviour.
		Segurium_Storage::ip_gc();
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Stats and log read API (no writes, no side effects).
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Allowed values for the get_log() event filter.
	 *
	 * @return array
	 */
	public static function event_types() {
		return array(
			self::EVENT_ATTEMPT,
			self::EVENT_LOCKOUT,
			self::EVENT_HONEYPOT,
			self::EVENT_UNLOCK,
			self::EVENT_CAPTCHA_FAIL,
		);
	}

	/**
	 * Count log events of a given type since a cutoff timestamp.
	 *
	 * @param string $event  Event type constant.
	 * @param int    $cutoff Unix timestamp cutoff.
	 * @return int
	 */
	private function count_events( $event, $cutoff ) {
		return (int) Segurium_Storage::table_get_var(
			'activity_log',
			'SELECT COUNT(*) FROM {{table}} WHERE event_type = %s AND created_at >= %d',
			array( self::event_type( $event ), $cutoff )
		);
	}

	/**
	 * Retrieve brute-force statistics for the dashboard.
	 *
	 * @return array
	 */
	public function get_stats() {
		$now        = time();
		$cutoff_24h = $now - DAY_IN_SECONDS;
		$cutoff_7d  = $now - 7 * DAY_IN_SECONDS;

		$active_lockouts = Segurium_Storage::ip_count( 'bf_lockout' );

		$top_ips_rows = Segurium_Storage::table_get_results(
			'activity_log',
			'SELECT HEX(actor_ip) AS ip_hex, COUNT(*) AS c FROM {{table}}
			 WHERE event_type = %s AND created_at >= %d AND actor_ip IS NOT NULL
			 GROUP BY actor_ip
			 ORDER BY c DESC, ip_hex ASC
			 LIMIT 10',
			array( self::event_type( self::EVENT_ATTEMPT ), $cutoff_24h ),
			ARRAY_A
		);

		$top_users_rows = Segurium_Storage::table_get_results(
			'activity_log',
			'SELECT subject AS username, COUNT(*) AS c FROM {{table}}
			 WHERE event_type = %s AND created_at >= %d AND subject IS NOT NULL AND subject <> \'\'
			 GROUP BY subject
			 ORDER BY c DESC, username ASC
			 LIMIT 10',
			array( self::event_type( self::EVENT_ATTEMPT ), $cutoff_24h ),
			ARRAY_A
		);

		return array(
			'attempts_24h'     => $this->count_events( self::EVENT_ATTEMPT, $cutoff_24h ),
			'attempts_7d'      => $this->count_events( self::EVENT_ATTEMPT, $cutoff_7d ),
			'lockouts_24h'     => $this->count_events( self::EVENT_LOCKOUT, $cutoff_24h ),
			'lockouts_7d'      => $this->count_events( self::EVENT_LOCKOUT, $cutoff_7d ),
			'honeypot_24h'     => $this->count_events( self::EVENT_HONEYPOT, $cutoff_24h ),
			'captcha_fail_24h' => $this->count_events( self::EVENT_CAPTCHA_FAIL, $cutoff_24h ),
			'active_lockouts'  => $active_lockouts,
			'top_ips'          => array_map(
				static function ( $r ) {
					$bin = isset( $r['ip_hex'] ) ? hex2bin( (string) $r['ip_hex'] ) : '';
					$ip  = $bin ? Segurium_IP::unpack( $bin ) : '';
					return array(
						'ip'    => (string) $ip,
						'count' => (int) $r['c'],
					);
				},
				$top_ips_rows ? $top_ips_rows : array()
			),
			'top_usernames'    => array_map(
				static function ( $r ) {
					return array(
						'username' => $r['username'],
						'count'    => (int) $r['c'],
					);
				},
				$top_users_rows ? $top_users_rows : array()
			),
		);
	}

	/**
	 * Retrieve paginated and filtered brute-force log entries.
	 *
	 * @param array $args Optional filters: page, per_page, event, ip.
	 * @return array {rows, total, page, per_page}
	 */
	public function get_log( array $args = array() ) {
		$page     = max( 1, (int) ( $args['page'] ?? 1 ) );
		$per_page = max( 1, min( 100, (int) ( $args['per_page'] ?? 25 ) ) );

		$where  = array( "event_type LIKE 'brute_force_%'" );
		$params = array();

		$event = isset( $args['event'] ) ? (string) $args['event'] : '';
		if ( '' !== $event && in_array( $event, self::event_types(), true ) ) {
			$where[]  = 'event_type = %s';
			$params[] = self::event_type( $event );
		}

		$ip = isset( $args['ip'] ) ? (string) $args['ip'] : '';
		if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			$where[]  = 'actor_ip = %s';
			$params[] = Segurium_IP::pack( $ip );
		}

		$where_sql = implode( ' AND ', $where );

		$total = (int) Segurium_Storage::table_get_var(
			'activity_log',
			'SELECT COUNT(*) FROM {{table}} WHERE ' . $where_sql,
			$params
		);

		$max_page = max( 1, (int) ceil( $total / $per_page ) );
		if ( $page > $max_page ) {
			$page = $max_page;
		}
		$offset = ( $page - 1 ) * $per_page;

		$rows_params = array_merge( $params, array( $per_page, $offset ) );
		$rows        = Segurium_Storage::table_get_results(
			'activity_log',
			'SELECT id, event_type, HEX(actor_ip) AS ip_hex, subject, data_json, created_at
			 FROM {{table}}
			 WHERE ' . $where_sql . '
			 ORDER BY created_at DESC, id DESC
			 LIMIT %d OFFSET %d',
			$rows_params,
			ARRAY_A
		);

		$rows = array_map(
			static function ( $r ) {
				$decoded    = isset( $r['data_json'] ) ? json_decode( (string) $r['data_json'], true ) : array();
				$bin        = isset( $r['ip_hex'] ) && '' !== $r['ip_hex'] ? hex2bin( (string) $r['ip_hex'] ) : '';
				$ip_display = is_array( $decoded ) && isset( $decoded['ip_display'] )
					? (string) $decoded['ip_display']
					: ( $bin ? (string) Segurium_IP::unpack( $bin ) : '' );
				$country    = '' !== $ip_display ? Segurium_Geo_DB::get_country( $ip_display ) : null;
				return array(
					'id'         => (int) $r['id'],
					'event'      => isset( $decoded['event'] ) ? (string) $decoded['event'] : str_replace( 'brute_force_', '', (string) $r['event_type'] ),
					'ip_display' => $ip_display,
					'country'    => is_string( $country ) && '' !== $country ? $country : null,
					'username'   => (string) ( $r['subject'] ?? '' ),
					'tier'       => isset( $decoded['tier'] ) && null !== $decoded['tier'] ? (int) $decoded['tier'] : null,
					'surface'    => isset( $decoded['surface'] ) ? (string) $decoded['surface'] : '',
					'created_at' => (int) $r['created_at'],
				);
			},
			$rows ? $rows : array()
		);

		return array(
			'rows'     => $rows,
			'total'    => $total,
			'page'     => $page,
			'per_page' => $per_page,
		);
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Helpers.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Get the real client IP address via the geo-blocker resolver.
	 *
	 * @return string
	 */
	public function get_real_ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';
		if ( null !== $this->real_ip_cache && $this->real_ip_cache_remote === $remote ) {
			return $this->real_ip_cache;
		}
		$ip                         = Segurium_Geo_Blocker::get_instance()->get_real_ip();
		$this->real_ip_cache_remote = $remote;
		$this->real_ip_cache        = ( $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) ? $ip : '';
		return $this->real_ip_cache;
	}

	/**
	 * Check whether the current request targets a login surface.
	 *
	 * @return bool
	 */
	public function is_login_surface() {
		$path = $this->request_path_basename();
		if ( 'wp-login.php' === $path ) {
			return true;
		}
		if ( ! empty( $this->get_settings()['protect_xmlrpc'] ) ) {
			if ( 'xmlrpc.php' === $path || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Detect which login surface the current request targets.
	 *
	 * @return string
	 */
	private function detect_surface() {
		if ( 'xmlrpc.php' === $this->request_path_basename() || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
			return self::SURFACE_XMLRPC;
		}
		return self::SURFACE_LOGIN;
	}

	/**
	 * Extract the basename from the current request URI.
	 *
	 * @return string
	 */
	private function request_path_basename() {
		$uri = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) )
			: '';
		if ( '' === $uri ) {
			return '';
		}
		$path = wp_parse_url( $uri, PHP_URL_PATH );
		if ( ! is_string( $path ) || '' === $path ) {
			return '';
		}
		return basename( $path );
	}

	/**
	 * Returns the firewall verdict for the IP, memoized per request.
	 *
	 * @param string $ip IP address.
	 * @return string 'allow' | 'block' | 'pass'
	 *                  - 'allow': firewall is in allow_list mode and IP is whitelisted (skip brute-force)
	 *                  - 'block': firewall would block this IP (skip brute-force; already handled)
	 *                  - 'pass':  firewall doesn't have an opinion (continue brute-force)
	 */
	private function firewall_verdict( $ip ) {
		if ( isset( $this->firewall_verdict_cache[ $ip ] ) ) {
			return $this->firewall_verdict_cache[ $ip ];
		}
		$verdict = 'pass';
		if ( Segurium_Storage::setting_get_bool( 'segurium_firewall_enabled' ) ) {
			$mode      = Segurium_Storage::setting_get_string( 'segurium_firewall_mode', 'deny_list' );
			$list_type = 'allow_list' === $mode ? 'allow' : 'block';
			$in_list   = null !== Segurium_Storage::ip_match( $ip, $list_type );
			if ( 'allow_list' === $mode ) {
				$verdict = $in_list ? 'allow' : 'block';
			} elseif ( $in_list ) {
				$verdict = 'block';
			}
		}
		$this->firewall_verdict_cache[ $ip ] = $verdict;
		return $verdict;
	}

	/**
	 * Check whether the IP is whitelisted by the firewall allow list.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public function is_whitelisted( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		return 'allow' === $this->firewall_verdict( $ip );
	}

	/**
	 * Check whether the IP is already blocked by the firewall or geo-blocker.
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	public function is_already_blocked( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		if ( 'block' === $this->firewall_verdict( $ip ) ) {
			return true;
		}
		if ( Segurium_Storage::setting_get_bool( 'segurium_geo_blocking_enabled' ) ) {
			if ( ! Segurium_Geo_Blocker::get_instance()->is_ip_allowed( $ip ) ) {
				return true;
			}
		}
		return false;
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Honeypot.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Render the hidden honeypot input field on the login form.
	 *
	 * @return void
	 */
	public function render_honeypot_field() {
		$settings = $this->get_settings();
		if ( empty( $settings['honeypot_enabled'] ) ) {
			return;
		}
		$field = $settings['honeypot_field_name'];
		echo '<p style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">';
		echo '<label>' . esc_html__( 'Leave this field empty', 'segurium' ) . ' ';
		echo '<input type="text" name="' . esc_attr( $field ) . '" tabindex="-1" autocomplete="off" value=""></label>';
		echo '</p>';
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * hCaptcha (Stage 2).
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Check whether hCaptcha is fully configured and enabled.
	 *
	 * @return bool
	 */
	private function hcaptcha_active() {
		$s = $this->get_settings();
		return ! empty( $s['hcaptcha_enabled'] )
			&& '' !== (string) $s['hcaptcha_site_key']
			&& '' !== (string) $s['hcaptcha_secret_key'];
	}

	/**
	 * Decision: should the hCaptcha widget be shown and verified for this IP right now?
	 *
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function should_show_hcaptcha( $ip ) {
		if ( ! $this->hcaptcha_active() ) {
			return false;
		}
		if ( ! $ip || $this->is_whitelisted( $ip ) ) {
			return false;
		}
		$threshold = (int) $this->get_settings()['captcha_threshold'];
		return $this->read_counter( self::COUNTER_IP, $ip ) >= $threshold;
	}

	/**
	 * Enqueue the hCaptcha API script on the login page.
	 *
	 * @return void
	 */
	public function enqueue_hcaptcha() {
		if ( ! $this->should_show_hcaptcha( $this->get_real_ip() ) ) {
			return;
		}
		// `null` version: don't append `?ver=` query string — hCaptcha's CDN URL is opaque.
		// phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion
		wp_enqueue_script( 'segurium-hcaptcha', self::HCAPTCHA_API_JS, array(), null, true );
	}

	/**
	 * Render the hCaptcha widget on the login form.
	 *
	 * @return void
	 */
	public function render_hcaptcha_widget() {
		if ( ! $this->should_show_hcaptcha( $this->get_real_ip() ) ) {
			return;
		}
		$key = $this->get_settings()['hcaptcha_site_key'];
		echo '<div class="h-captcha segurium-bf-hcaptcha" data-sitekey="' . esc_attr( $key ) . '"></div>';
	}

	/**
	 * Verify an hCaptcha token against the hCaptcha API.
	 *
	 * @param string $ip    Client IP address.
	 * @param string $token hCaptcha response token.
	 * @return bool
	 */
	private function verify_hcaptcha( $ip, $token ) {
		if ( '' === $token ) {
			return false;
		}

		$settings = $this->get_settings();
		$response = wp_safe_remote_post(
			self::HCAPTCHA_VERIFY,
			array(
				'timeout' => 5,
				'body'    => array(
					'secret'   => $settings['hcaptcha_secret_key'],
					'response' => $token,
					'remoteip' => $ip,
					'sitekey'  => $settings['hcaptcha_site_key'],
				),
			)
		);

		// Fail OPEN on transport errors so a hCaptcha outage doesn't lock site owners out.
		if ( is_wp_error( $response ) ) {
			return true;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return is_array( $body ) && ! empty( $body['success'] );
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * CTI reporting.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Send a brute-force event to the CTI service.
	 *
	 * @param string $message_type CTI message type constant.
	 * @param string $ip           Client IP address.
	 * @param string $username     Username associated with the event.
	 * @param array  $extra        Additional payload fields.
	 * @return void
	 */
	private function report_to_cti( $message_type, $ip, $username, array $extra = array() ) {
		$payload = array_merge(
			$extra,
			array(
				'ip'            => $ip,
				'username_hash' => '' !== $username ? hash( 'sha256', $username ) : '',
				'surface'       => $this->detect_surface(),
			)
		);
		Segurium_Storage::cti_send_message( $message_type, wp_json_encode( $payload ) );
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Block response.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Send a 403 wp_die response for a locked-out IP.
	 *
	 * @param string $ip IP address.
	 * @return void
	 */
	private function send_lockout_response( $ip ) {
		$row       = $this->get_active_lockout( $ip );
		$remaining = $row ? max( 0, (int) $row['expires_at'] - time() ) : 0;
		wp_die(
			esc_html(
				sprintf(
					/* translators: %s: human-readable time remaining */
					__( 'Too many failed login attempts. Try again in %s.', 'segurium' ),
					human_time_diff( time(), time() + $remaining )
				)
			),
			esc_html__( 'Login Locked', 'segurium' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Create a WP_Error for a locked-out IP with a human-readable remaining time.
	 *
	 * @param string $ip IP address.
	 * @return WP_Error
	 */
	private function wp_error_lockout( $ip ) {
		$row       = $this->get_active_lockout( $ip );
		$remaining = $row ? max( 0, (int) $row['expires_at'] - time() ) : 0;
		return new WP_Error(
			self::ERR_LOCKOUT,
			esc_html(
				sprintf(
					/* translators: %s: human-readable time remaining */
					__( 'Too many failed login attempts. Try again in %s.', 'segurium' ),
					human_time_diff( time(), time() + $remaining )
				)
			)
		);
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * Cron scheduling helpers (called from activation and deactivation).
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Schedule the daily log prune cron event if not already scheduled.
	 *
	 * @return void
	 */
	public static function schedule_prune() {
		if ( ! wp_next_scheduled( self::CRON_PRUNE ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', self::CRON_PRUNE );
		}
	}

	/**
	 * Clear the scheduled log prune cron event.
	 *
	 * @return void
	 */
	public static function unschedule_prune() {
		wp_clear_scheduled_hook( self::CRON_PRUNE );
	}

	/**
	 * Record a 2FA verification failure.
	 *
	 * Called by Segurium_2FA when a user submits an incorrect 2FA code.
	 * Feeds the failure into the brute-force IP counter and triggers
	 * a lockout if the threshold is reached.
	 *
	 * @param string $ip       Client IP address.
	 * @param string $username WordPress username.
	 * @return void
	 */
	public function record_2fa_failure( $ip, $username ) {
		if ( ! $this->get_settings()['enabled'] ) {
			return;
		}
		if ( ! $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}
		if ( $this->is_whitelisted( $ip ) ) {
			return;
		}

		$ip_count = $this->incr_counter( self::COUNTER_IP, $ip );
		$this->log_event( self::EVENT_ATTEMPT, $ip, is_string( $username ) ? $username : '' );

		$max = $this->get_settings()['max_attempts'];
		if ( $ip_count >= $max ) {
			$this->apply_lockout( $ip, is_string( $username ) ? $username : '', self::REASON_THRESHOLD );
		}
	}
}

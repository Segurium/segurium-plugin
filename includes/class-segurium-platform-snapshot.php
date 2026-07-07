<?php
/**
 * Daily WP-Cron event that pushes the site's hosting-platform snapshot to
 * CTI. Plugin-side counterpart of SEGURIUM-328 (the /v1/platform endpoint).
 *
 * SEGURIUM-329 / SEGURIUM-21.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Collector + scheduler for the daily platform telemetry snapshot.
 */
final class Segurium_Platform_Snapshot {

	const HOOK                = 'segurium_daily_platform_snapshot';
	const OPTION_HASH         = 'segurium_platform_hash';
	const OPTION_LAST_SENT_AT = 'segurium_platform_last_sent_at';
	const TRANSIENT_DB_INFO   = 'segurium_platform_db_info';
	const TRANSIENT_LOCK      = 'segurium_platform_oos_lock';

	const DB_TTL_SECONDS   = DAY_IN_SECONDS;
	const STALE_AFTER_SECS = 2 * DAY_IN_SECONDS;
	const OOS_LOCK_SECONDS = 5 * MINUTE_IN_SECONDS;

	/**
	 * Wire the cron hook + the out-of-schedule fallback. Called from
	 * Segurium::register_hooks().
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( self::HOOK, array( __CLASS__, 'run' ) );
		add_action( self::HOOK . '_oneshot', array( __CLASS__, 'run' ) );
		// Opportunistic catch-up only on admin requests — never on
		// front-end traffic. Cheap timestamp / constant checks short-
		// circuit before any work happens.
		add_action( 'admin_init', array( __CLASS__, 'maybe_run_out_of_schedule' ) );
	}

	/**
	 * Schedule the daily event. Idempotent. Called on activation. The
	 * cron handler itself short-circuits before any HTTP traffic if
	 * consent (SEGURIUM-295) is not granted, so scheduling pre-consent
	 * is safe and matches the integrity-inventory cron pattern.
	 *
	 * @return void
	 */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::HOOK );
		}
	}

	/**
	 * Clear the daily event + cached state. Called on deactivation.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		$ts = wp_next_scheduled( self::HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::HOOK );
		}
		wp_clear_scheduled_hook( self::HOOK );
		delete_transient( self::TRANSIENT_DB_INFO );
		delete_transient( self::TRANSIENT_LOCK );
	}

	/**
	 * One-shot piggyback fired immediately after the user accepts the
	 * External Service Disclosure (SEGURIUM-295). Lets the dashboard
	 * see new sites without waiting for the daily cron tick.
	 *
	 * @return void
	 */
	public static function send_on_consent(): void {
		// Schedule a single event on the same HOOK; WP-Cron will
		// fire it on the next request that triggers spawn_cron(),
		// or on the operator's system cron if WP-Cron is disabled
		// (in which case maybe_run_out_of_schedule() handles
		// admin-side catch-up).
		if ( ! wp_next_scheduled( self::HOOK . '_oneshot' ) ) {
			wp_schedule_single_event( time() + 5, self::HOOK . '_oneshot' );
		}
	}

	/**
	 * Cron handler: collect, change-detect, post.
	 *
	 * @return void
	 */
	public static function run(): void {
		try {
			self::do_run();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] platform snapshot failed: ' . $e->getMessage() );
		}
	}

	/**
	 * `admin_init` fallback. Fires the snapshot when WP-Cron has been
	 * disabled (DISABLE_WP_CRON / ALTERNATE_WP_CRON unset and the
	 * site relies on system cron) or the last successful report is
	 * more than {@see self::STALE_AFTER_SECS} old.
	 *
	 * Guarded by a 5-minute transient lock so concurrent admin
	 * pageloads do not stampede the endpoint.
	 *
	 * @return void
	 */
	public static function maybe_run_out_of_schedule(): void {
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}
		if ( null === Segurium_IID::get_iid() ) {
			return;
		}

		$last = Segurium_Storage::setting_get_int( self::OPTION_LAST_SENT_AT, 0 );
		$now  = time();

		$cron_disabled = self::wp_cron_disabled();
		$is_stale      = ( $last <= 0 ) || ( ( $now - $last ) >= self::STALE_AFTER_SECS );

		if ( ! $cron_disabled && ! $is_stale ) {
			return;
		}

		// Stampede guard.
		if ( false !== get_transient( self::TRANSIENT_LOCK ) ) {
			return;
		}
		set_transient( self::TRANSIENT_LOCK, $now, self::OOS_LOCK_SECONDS );

		self::run();
	}

	/**
	 * Detect whether automatic WP-Cron is unavailable for this site.
	 * `DISABLE_WP_CRON` is the operator-flagged opt-out; the tickle
	 * happens via system cron / external pinger and we cannot know
	 * how often that fires from PHP, so we treat the constant as
	 * authoritative for the purpose of the catch-up.
	 *
	 * @return bool
	 */
	public static function wp_cron_disabled(): bool {
		$disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		// Filterable so tests (and operators who tickle WP-Cron from
		// outside despite the constant being set) can override.
		return (bool) apply_filters( 'segurium_platform_wp_cron_disabled', $disabled );
	}

	/**
	 * Build the snapshot payload from cheap sources. Public so tests can
	 * pin the shape across SAPI / web-server combinations.
	 *
	 * @return array
	 */
	public static function collect(): array {
		global $wp_version, $wpdb;

		$env      = Segurium_Info_Shield::detect_server_environment();
		$db_info  = self::cached_db_info( $wpdb );
		$theme    = wp_get_theme();
		$home_url = home_url();
		$scheme   = wp_parse_url( $home_url, PHP_URL_SCHEME );

		$webserver_version = self::parse_webserver_version(
			(string) ( $env['server_software'] ?? '' )
		);

		$theme_slug    = '';
		$theme_version = '';
		if ( $theme instanceof WP_Theme ) {
			$theme_slug    = (string) $theme->get_stylesheet();
			$theme_version = (string) $theme->get( 'Version' );
		}

		return array(
			'wp_version'             => (string) $wp_version,
			'wp_locale'              => (string) get_locale(),
			'wp_multisite'           => (bool) is_multisite(),
			'wp_debug'               => (bool) ( defined( 'WP_DEBUG' ) && WP_DEBUG ),
			'wp_cron_disabled'       => self::wp_cron_disabled(),
			'site_https'             => 'https' === $scheme,
			'php_version'            => PHP_VERSION,
			'php_sapi'               => (string) ( PHP_SAPI ?? '' ),
			'php_memory_limit_mb'    => self::parse_memory_limit_mb( (string) ini_get( 'memory_limit' ) ),
			'php_max_execution_time' => (int) ini_get( 'max_execution_time' ),
			'php_max_input_vars'     => (int) ini_get( 'max_input_vars' ),
			'webserver'              => self::map_server_type( (string) ( $env['server_type'] ?? '' ) ),
			'webserver_version'      => $webserver_version,
			'server_software'        => (string) ( $env['server_software'] ?? '' ),
			'db_engine'              => $db_info['engine'],
			'db_version'             => $db_info['version'],
			'os_family'              => self::parse_os_family( php_uname( 's' ) ),
			'os_arch'                => self::parse_os_arch( php_uname( 'm' ) ),
			'plugin_version'         => defined( 'SEGURIUM_VERSION' ) ? (string) SEGURIUM_VERSION : '',
			'active_theme_slug'      => $theme_slug,
			'active_theme_version'   => $theme_version,
		);
	}

	/**
	 * Parse `memory_limit` into MB. `'-1'` (unlimited) and empty become 0;
	 * suffixes K / M / G are honoured (case-insensitive).
	 *
	 * @param string $raw Raw `ini_get('memory_limit')` value.
	 * @return int Megabytes, never negative.
	 */
	public static function parse_memory_limit_mb( string $raw ): int {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return 0;
		}
		if ( '-1' === $raw ) {
			return 0;
		}
		$len  = strlen( $raw );
		$last = strtolower( $raw[ $len - 1 ] );
		$num  = (float) $raw;
		if ( $num < 0 ) {
			return 0;
		}
		switch ( $last ) {
			case 'g':
				$bytes = $num * 1024 * 1024 * 1024;
				break;
			case 'm':
				$bytes = $num * 1024 * 1024;
				break;
			case 'k':
				$bytes = $num * 1024;
				break;
			default:
				$bytes = $num;
		}
		return (int) max( 0, (int) ( $bytes / ( 1024 * 1024 ) ) );
	}

	/**
	 * Pull `db_server_info()` + `db_version()` out of the existing $wpdb
	 * (or whatever is injected for tests). Cached for {@see DB_TTL_SECONDS}
	 * to keep it at one query per day max.
	 *
	 * @param mixed $wpdb wpdb-like object exposing db_server_info() / db_version().
	 * @return array{ engine: string, version: string, raw: string }
	 */
	public static function cached_db_info( $wpdb ): array {
		$cached = get_transient( self::TRANSIENT_DB_INFO );
		if ( is_array( $cached ) && isset( $cached['engine'], $cached['version'] ) ) {
			return $cached;
		}

		$raw     = '';
		$version = '';
		if ( is_object( $wpdb ) && method_exists( $wpdb, 'db_server_info' ) ) {
			$raw = (string) $wpdb->db_server_info();
		}
		if ( is_object( $wpdb ) && method_exists( $wpdb, 'db_version' ) ) {
			$version = (string) $wpdb->db_version();
		}

		$info = array(
			'engine'  => self::detect_db_engine( $raw ),
			'version' => $version,
			'raw'     => $raw,
		);

		set_transient( self::TRANSIENT_DB_INFO, $info, self::DB_TTL_SECONDS );
		return $info;
	}

	/**
	 * Identify the DB flavour from a raw `db_server_info()` string.
	 *
	 * @param string $raw Raw db_server_info() string.
	 * @return string mysql|mariadb|percona
	 */
	public static function detect_db_engine( string $raw ): string {
		if ( '' === $raw ) {
			return 'mysql';
		}
		if ( false !== stripos( $raw, 'mariadb' ) ) {
			return 'mariadb';
		}
		if ( false !== stripos( $raw, 'percona' ) ) {
			return 'percona';
		}
		return 'mysql';
	}

	/**
	 * Normalise the Info_Shield server-type label to the closed set the
	 * /v1/platform endpoint accepts.
	 *
	 * @param string $type Detected server-type label from Info_Shield.
	 * @return string apache|nginx|litespeed|iis|other
	 */
	public static function map_server_type( string $type ): string {
		$known = array( 'apache', 'nginx', 'litespeed', 'iis' );
		return in_array( $type, $known, true ) ? $type : 'other';
	}

	/**
	 * Best-effort `Apache/2.4.58 (Ubuntu)` → `2.4.58`.
	 *
	 * @param string $software Raw $_SERVER['SERVER_SOFTWARE'].
	 * @return string Version string, or '' if not found.
	 */
	public static function parse_webserver_version( string $software ): string {
		if ( '' === $software ) {
			return '';
		}
		if ( preg_match( '#/(\d+(?:\.\d+){1,3})#', $software, $m ) ) {
			return $m[1];
		}
		return '';
	}

	/**
	 * Bucket `php_uname('s')` into the closed OS-family set.
	 *
	 * @param string $uname `php_uname('s')` value.
	 * @return string linux|darwin|windows|other
	 */
	public static function parse_os_family( string $uname ): string {
		$lower = strtolower( $uname );
		if ( false !== strpos( $lower, 'linux' ) ) {
			return 'linux';
		}
		if ( false !== strpos( $lower, 'darwin' ) ) {
			return 'darwin';
		}
		if ( false !== strpos( $lower, 'windows' ) || false !== strpos( $lower, 'winnt' ) ) {
			return 'windows';
		}
		return 'other';
	}

	/**
	 * Bucket `php_uname('m')` into the closed CPU-arch set.
	 *
	 * @param string $uname `php_uname('m')` value.
	 * @return string x86_64|aarch64|armv7|other
	 */
	public static function parse_os_arch( string $uname ): string {
		$lower = strtolower( $uname );
		if ( 'x86_64' === $lower || 'amd64' === $lower ) {
			return 'x86_64';
		}
		if ( 'aarch64' === $lower || 'arm64' === $lower ) {
			return 'aarch64';
		}
		if ( 0 === strpos( $lower, 'armv7' ) ) {
			return 'armv7';
		}
		return 'other';
	}

	/**
	 * Hash the payload deterministically. 32 hex chars to match the
	 * server-side validator (SEGURIUM-328).
	 *
	 * @param array $payload Snapshot payload to hash.
	 * @return string
	 */
	public static function payload_hash( array $payload ): string {
		ksort( $payload );
		$json = wp_json_encode( $payload );
		if ( false === $json ) {
			$json = '';
		}
		return substr( md5( $json ), 0, 32 );
	}

	/**
	 * The actual work, separated from {@see run()} so failures bubble
	 * up to the catch-block for logging.
	 *
	 * @return void
	 */
	private static function do_run(): void {
		// Hard consent gate — defence in depth on top of the IID
		// gate inside the CTI client. Pre-consent the detector still
		// runs (cheap), but we never reach the HTTP layer.
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}
		if ( null === Segurium_IID::get_iid() ) {
			return;
		}

		$payload = self::collect();
		$hash    = self::payload_hash( $payload );

		$prev = Segurium_Storage::setting_get_string( self::OPTION_HASH, '' );
		if ( $hash === $prev ) {
			// No change — refresh the timestamp so the staleness
			// heuristic does not retrigger the catch-up forever.
			Segurium_Storage::setting_set( self::OPTION_LAST_SENT_AT, time() );
			return;
		}

		$payload['snapshot_hash'] = $hash;
		$ok                       = Segurium_Storage::cti_send_platform_snapshot( $payload );
		if ( ! $ok ) {
			return;
		}

		Segurium_Storage::setting_set( self::OPTION_HASH, $hash );
		Segurium_Storage::setting_set( self::OPTION_LAST_SENT_AT, time() );
	}
}

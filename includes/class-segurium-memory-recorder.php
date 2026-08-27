<?php
/**
 * Production memory telemetry recorder.
 *
 * Companion to the offline bench probe in tests/perf/memory/. The bench
 * measures synthetic peaks; this class samples real-world peaks from
 * active installs and ships them to CTI, so the system-requirements
 * numbers can be validated against (or corrected by) production data.
 *
 * Sampling strategy (intentional):
 *   - Every scan run produces one sample on `segurium_scan_completed`,
 *     scope_id `scan_run`. Peak is reset at `segurium_scan_started`
 *     when the PHP runtime supports it (8.2+), so the recorded peak
 *     reflects the scan itself rather than the whole request.
 *   - One sample per day from a dedicated WP-Cron event, scope_id
 *     `cron_daily`. Captures the lightweight cron-tick baseline.
 *
 * Privacy contract: the payload carries memory metrics + version
 * strings + plan tier only. No paths, no URLs, no user identifiers.
 * Site-level identification (IID, site_url, domain) is added at the
 * envelope layer by Segurium_CTI_Client::send_message.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scheduler + collector for the runtime memory-sample telemetry.
 */
final class Segurium_Memory_Recorder {

	const HOOK = 'segurium_daily_memory_sample';

	const SCOPE_SCAN_RUN   = 'scan_run';
	const SCOPE_CRON_DAILY = 'cron_daily';

	const MESSAGE_TYPE = 'memory_sample';

	/**
	 * Pre-scan baseline captured by on_scan_started, consumed by on_scan_completed.
	 *
	 * @var array{start_peak:int,start_current:int,start_ts:float}|null
	 */
	private static $scan_state = null;

	/**
	 * Wire the cron handler + scan-start / scan-complete listeners.
	 * Called from Segurium::register_hooks().
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( self::HOOK, array( __CLASS__, 'run_cron' ) );
		// Scan-started: arms the recorder, optionally resets peak.
		// Priority 20 so canonical scan-state seeding (prio 10) runs first.
		add_action( 'segurium_scan_started', array( __CLASS__, 'on_scan_started' ), 20, 1 );
		// Scan-completed: priority 50 — well after the default handler
		// (10) has emitted the scan_completed CTI message, so any
		// allocations from those handlers are included in our peak.
		add_action( 'segurium_scan_completed', array( __CLASS__, 'on_scan_completed' ), 50, 1 );
	}

	/**
	 * Schedule the daily cron event. Idempotent. Called on activation.
	 *
	 * @return void
	 */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::HOOK );
		}
	}

	/**
	 * Clear the daily cron event. Called on deactivation.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		$ts = wp_next_scheduled( self::HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::HOOK );
		}
		wp_clear_scheduled_hook( self::HOOK );
		self::$scan_state = null;
	}

	/**
	 * Reset internal state. For tests only.
	 *
	 * @return void
	 */
	public static function reset_for_tests(): void {
		self::$scan_state = null;
	}

	/**
	 * Daily cron handler. Records the current peak as a `cron_daily`
	 * sample. Wrapped in try/catch so a failure here can never break
	 * other cron events.
	 *
	 * @return void
	 */
	public static function run_cron(): void {
		try {
			self::record_sample( self::SCOPE_CRON_DAILY, null, array() );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] memory cron sample failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Capture pre-scan baseline so the post-scan peak reading reflects
	 * the scan itself (especially on PHP 8.2+ where we can reset peak).
	 *
	 * @param mixed $unused The Segurium_Scan instance (unused here).
	 * @return void
	 */
	public static function on_scan_started( $unused = null ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		try {
			if ( function_exists( 'memory_reset_peak_usage' ) ) {
				memory_reset_peak_usage();
			}
			self::$scan_state = array(
				'start_peak'    => memory_get_peak_usage( true ),
				'start_current' => memory_get_usage( true ),
				'start_ts'      => microtime( true ),
			);
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] memory recorder on_scan_started failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Send the post-scan sample. Tolerates a missing on_scan_started
	 * (e.g. recorder was loaded mid-scan after an upgrade): in that
	 * case start_* values are null and duration is omitted.
	 *
	 * @param mixed $unused The Segurium_Scan instance (unused here).
	 * @return void
	 */
	public static function on_scan_completed( $unused = null ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		try {
			$state            = self::$scan_state;
			self::$scan_state = null;
			$duration_ms      = null;
			$start_peak       = null;
			$start_current    = null;
			if ( is_array( $state ) ) {
				$duration_ms   = (int) round( ( microtime( true ) - $state['start_ts'] ) * 1000 );
				$start_peak    = (int) $state['start_peak'];
				$start_current = (int) $state['start_current'];
			}
			$tags = array(
				'has_baseline' => is_array( $state ),
			);
			if ( null !== $start_peak ) {
				$tags['start_peak_bytes']    = $start_peak;
				$tags['start_current_bytes'] = $start_current;
			}
			self::record_sample( self::SCOPE_SCAN_RUN, $duration_ms, $tags );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] memory recorder on_scan_completed failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Build and ship a single memory_sample message.
	 *
	 * @param string   $scope_id    One of the SCOPE_* constants.
	 * @param int|null $duration_ms Wall time in ms, or null if not measured.
	 * @param array    $extra_tags  Whitelisted scalar tags merged into payload.
	 * @return bool True if the request did not error.
	 */
	public static function record_sample( string $scope_id, $duration_ms, array $extra_tags = array() ): bool {
		// Hard consent gate — defence in depth on top of the IID
		// gate inside the CTI client. No telemetry leaves the site
		// before the user has accepted the External Service
		// Disclosure.
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return false;
		}
		if ( null === Segurium_IID::get_iid() ) {
			return false;
		}

		$payload = array(
			'scope_id'        => $scope_id,
			'ts'              => time(),
			'peak_bytes'      => (int) memory_get_peak_usage( true ),
			'current_bytes'   => (int) memory_get_usage( true ),
			'duration_ms'     => null === $duration_ms ? null : (int) $duration_ms,
			'peak_resettable' => function_exists( 'memory_reset_peak_usage' ),
			'php_version'     => PHP_VERSION,
			'php_sapi'        => (string) ( PHP_SAPI ?? '' ),
			'plan_tier'       => self::current_plan_tier(),
			'memory_limit_mb' => self::memory_limit_mb(),
			'tags'            => self::sanitize_tags( $extra_tags ),
		);

		return Segurium_Storage::cti_send_message( self::MESSAGE_TYPE, $payload );
	}

	/**
	 * Returns the current plan tier ('free' / 'pro') for the install,
	 * defaulting to 'free' if the entitlements layer is unreachable.
	 *
	 * @return string
	 */
	private static function current_plan_tier(): string {
		if ( class_exists( 'Segurium_Quota' ) && method_exists( 'Segurium_Quota', 'plan_tier' ) ) {
			$tier = (string) Segurium_Quota::plan_tier();
			if ( '' !== $tier ) {
				return $tier;
			}
		}
		return 'free';
	}

	/**
	 * Returns memory_limit in MB (0 for unlimited / unknown). Reuses
	 * the platform-snapshot parser for shape consistency.
	 *
	 * @return int
	 */
	private static function memory_limit_mb(): int {
		if ( class_exists( 'Segurium_Platform_Snapshot' ) ) {
			return (int) Segurium_Platform_Snapshot::parse_memory_limit_mb( (string) ini_get( 'memory_limit' ) );
		}
		return 0;
	}

	/**
	 * Drop anything that's not a scalar so the payload stays a flat
	 * map of well-typed values. Belt-and-braces against a future
	 * caller passing in an object or array.
	 *
	 * @param array $tags Caller-supplied extra tags to merge into the payload.
	 * @return array<string,scalar>
	 */
	private static function sanitize_tags( array $tags ): array {
		$out = array();
		foreach ( $tags as $k => $v ) {
			if ( ! is_string( $k ) ) {
				continue;
			}
			if ( is_bool( $v ) || is_int( $v ) || is_float( $v ) || is_string( $v ) ) {
				$out[ $k ] = $v;
			}
		}
		return $out;
	}
}

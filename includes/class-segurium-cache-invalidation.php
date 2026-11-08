<?php
/**
 * Page cache invalidation after a malware cleanup.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Asks the cloud which page caches to purge once a cleanup removed
 * malware, runs those purge routines, and reports the outcome.
 */
class Segurium_Cache_Invalidation {

	const HOOK = 'segurium_cache_invalidation_run';

	const SETTING_STATE = 'segurium_cache_invalidation_state';

	const MIN_INTERVAL_SECS = 300;

	/**
	 * Run time for a batch whose end never arrived, counted from its
	 * latest cleanup. A browser tab closed mid Fix All sends no end.
	 */
	const BATCH_FALLBACK_SECS = 600;

	const MAX_LOOKUP_ATTEMPTS = 3;

	const TRIGGER_MANUAL         = 'manual';
	const TRIGGER_FIX_ALL        = 'fix_all';
	const TRIGGER_AUTO_FIX       = 'auto_fix';
	const TRIGGER_INTEGRITY_FIX  = 'integrity_fix';
	const TRIGGER_REMOTE         = 'remote';
	const TRIGGER_STANDING_ORDER = 'standing_order';

	const OUTCOME_OK          = 'ok';
	const OUTCOME_NOT_ACTIVE  = 'not_active';
	const OUTCOME_UNSUPPORTED = 'unsupported';
	const OUTCOME_FAILED      = 'failed';

	const ROUTINES = array( 'litespeed-cache', 'wp-optimize', 'wp-fastest-cache', 'wp-super-cache' );

	/**
	 * Routine table a test put in place of the real one.
	 *
	 * @var array<string, array{available:callable, purge:callable}>|null
	 */
	private static $registry_override = null;

	/**
	 * Wire the scheduled run.
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( self::HOOK, array( __CLASS__, 'run_scheduled' ) );
	}

	/**
	 * Drop any queued run.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		wp_clear_scheduled_hook( self::HOOK );
	}

	/**
	 * Record that a cleanup removed malware and queue the purge.
	 *
	 * @param string $trigger  One of the TRIGGER_* constants.
	 * @param bool   $in_batch True for one file of a Fix All or Auto-fix run.
	 * @return void
	 */
	public static function cleaned( string $trigger, bool $in_batch = false ): void {
		$state             = self::state();
		$state['pending']  = true;
		$state['trigger']  = $trigger;
		$state['attempts'] = 0;
		self::save_state( $state );

		if ( $in_batch ) {
			self::reschedule( time() + self::BATCH_FALLBACK_SECS );
			return;
		}
		self::schedule_by( self::earliest_run( $state ) );
	}

	/**
	 * A batch ended: run as soon as the interval allows.
	 *
	 * @return void
	 */
	public static function batch_finished(): void {
		$state = self::state();
		if ( ! $state['pending'] ) {
			return;
		}
		self::reschedule( self::earliest_run( $state ) );
	}

	/**
	 * AJAX: the browser finished a Fix All batch.
	 *
	 * @return void
	 */
	public static function ajax_batch_done(): void {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}
		self::batch_finished();
		segurium_send_json_success( array() );
	}

	/**
	 * Cron callback: look up the routines and run them.
	 *
	 * @return void
	 */
	public static function run_scheduled(): void {
		$state = self::state();
		if ( ! $state['pending'] ) {
			return;
		}
		$due = self::earliest_run( $state );
		if ( $due > time() ) {
			self::schedule_by( $due );
			return;
		}

		$state['pending']  = false;
		$state['last_run'] = time();
		self::save_state( $state );

		$routines = Segurium_Storage::cti_cache_routines();
		if ( is_wp_error( $routines ) ) {
			self::lookup_failed( $state, $routines );
			return;
		}

		$results = self::run_routines( $routines );
		if ( ! empty( $results ) ) {
			self::report( $state['trigger'], $results );
		}
	}

	/**
	 * Remote action: run the routines the cloud named, now.
	 *
	 * @param string[] $ids Routine IDs.
	 * @return array<int, array<string, string>>
	 */
	public static function run_remote( array $ids ): array {
		$state             = self::state();
		$state['pending']  = false;
		$state['last_run'] = time();
		self::save_state( $state );
		self::unschedule();

		$results = self::run_routines( $ids );
		self::report( self::TRIGGER_REMOTE, $results );
		return $results;
	}

	/**
	 * Whether at least one of the routines can run on this site.
	 *
	 * @param string[] $ids Routine IDs.
	 * @return bool
	 */
	public static function any_available( array $ids ): bool {
		$registry = self::registry();
		foreach ( $ids as $id ) {
			if ( ! isset( $registry[ $id ] ) ) {
				continue;
			}
			try {
				if ( call_user_func( $registry[ $id ]['available'] ) ) {
					return true;
				}
			} catch ( Throwable $e ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Run each routine once, in order.
	 *
	 * @param string[] $ids Routine IDs.
	 * @return array<int, array<string, string>> One result per distinct ID.
	 */
	public static function run_routines( array $ids ): array {
		$registry = self::registry();
		$results  = array();
		foreach ( array_values( array_unique( array_map( 'strval', $ids ) ) ) as $id ) {
			if ( ! isset( $registry[ $id ] ) ) {
				$results[] = array(
					'id'      => $id,
					'outcome' => self::OUTCOME_UNSUPPORTED,
				);
				continue;
			}
			$results[] = self::run_one( $id, $registry[ $id ] );
		}
		return $results;
	}

	/**
	 * Replace the routine table. Tests only.
	 *
	 * @param array|null $registry Table, or null for the real one.
	 * @return void
	 */
	public static function set_registry_for_testing( $registry ): void {
		self::$registry_override = $registry;
	}

	/**
	 * Run one routine and turn what happened into a result row.
	 *
	 * @param string $id      Routine ID.
	 * @param array  $routine Its `available` and `purge` callables.
	 * @return array<string, string>
	 */
	private static function run_one( string $id, array $routine ): array {
		try {
			if ( ! call_user_func( $routine['available'] ) ) {
				return array(
					'id'      => $id,
					'outcome' => self::OUTCOME_NOT_ACTIVE,
				);
			}
			$error = (string) call_user_func( $routine['purge'] );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-cache] ' . $id . ' purge threw ' . get_class( $e ) . ': ' . $e->getMessage() );
			$error = 'exception';
		}

		if ( '' === $error ) {
			return array(
				'id'      => $id,
				'outcome' => self::OUTCOME_OK,
			);
		}
		return array(
			'id'         => $id,
			'outcome'    => self::OUTCOME_FAILED,
			'error_code' => $error,
		);
	}

	/**
	 * Purge routines, keyed by the cache plugin's wp.org slug. `purge`
	 * returns '' on success or an error code.
	 *
	 * @return array<string, array{available:callable, purge:callable}>
	 */
	private static function registry(): array {
		if ( null !== self::$registry_override ) {
			return self::$registry_override;
		}

		return array(
			'litespeed-cache'  => array(
				'available' => static function () {
					return has_action( 'litespeed_purge_all' );
				},
				'purge'     => static function () {
					do_action( 'litespeed_purge_all', 'Segurium cleanup' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- LiteSpeed Cache purge hook
					return '';
				},
			),
			'wp-optimize'      => array(
				'available' => static function () {
					return self::wpo_page_cache_on() || self::wpo_minify_on();
				},
				'purge'     => static function () {
					$error = '';
					if ( self::wpo_page_cache_on() && ! WP_Optimize()->get_page_cache()->purge() ) {
						$error = 'purge_refused';
					}
					if ( self::wpo_minify_on() && class_exists( 'WP_Optimize_Minify_Cache_Functions' ) ) {
						WP_Optimize_Minify_Cache_Functions::purge();
					}
					return $error;
				},
			),
			'wp-fastest-cache' => array(
				'available' => static function () {
					return function_exists( 'wpfc_clear_all_cache' );
				},
				'purge'     => static function () {
					$result = wpfc_clear_all_cache( true );
					return is_array( $result ) && isset( $result['success'] ) && false === $result['success'] ? 'hook_disabled' : '';
				},
			),
			'wp-super-cache'   => array(
				'available' => static function () {
					return function_exists( 'wp_cache_clear_cache' );
				},
				'purge'     => static function () {
					wp_cache_clear_cache( 0 );
					return '';
				},
			),
		);
	}

	/**
	 * Whether WP-Optimize serves cached pages.
	 *
	 * @return bool
	 */
	private static function wpo_page_cache_on(): bool {
		if ( ! function_exists( 'WP_Optimize' ) || ! method_exists( WP_Optimize(), 'get_page_cache' ) ) {
			return false;
		}
		$cache = WP_Optimize()->get_page_cache();
		return method_exists( $cache, 'is_enabled' ) && $cache->is_enabled();
	}

	/**
	 * Whether WP-Optimize serves minified CSS and JS.
	 *
	 * @return bool
	 */
	private static function wpo_minify_on(): bool {
		return function_exists( 'wp_optimize_minify_config' ) && wp_optimize_minify_config()->is_enabled();
	}

	/**
	 * Report a failed lookup, and queue a retry while the cause may pass.
	 *
	 * @param array    $state State saved at the start of the run.
	 * @param WP_Error $error What the lookup returned.
	 * @return void
	 */
	private static function lookup_failed( array $state, WP_Error $error ): void {
		$data  = $error->get_error_data();
		$cause = is_array( $data ) && ! empty( $data['error'] ) && is_string( $data['error'] )
			? sanitize_key( $data['error'] )
			: (string) $error->get_error_code();
		Segurium_Debug::log( '[segurium-cache] routine lookup failed: ' . $cause . ' ' . $error->get_error_message() );
		$attempt = $state['attempts'] + 1;
		self::report( $state['trigger'], array(), $cause, $attempt );

		$status    = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 0;
		$transient = 'http_request_failed' === $error->get_error_code() || 429 === $status || $status >= 500;
		if ( ! $transient || $attempt >= self::MAX_LOOKUP_ATTEMPTS ) {
			return;
		}

		$fresh = self::state();
		if ( $fresh['pending'] ) {
			return;
		}
		$fresh['pending']  = true;
		$fresh['trigger']  = $state['trigger'];
		$fresh['attempts'] = $attempt;
		self::save_state( $fresh );
		self::reschedule( self::earliest_run( $fresh ) );
	}

	/**
	 * Send one `cache_invalidation` message.
	 *
	 * @param string $trigger      What caused the run.
	 * @param array  $results      Result rows.
	 * @param string $lookup_error Code of a failed lookup, or ''.
	 * @param int    $attempt      Which lookup attempt failed, 1-based.
	 * @return void
	 */
	private static function report( string $trigger, array $results, string $lookup_error = '', int $attempt = 0 ): void {
		$payload = array(
			'trigger'  => $trigger,
			'routines' => $results,
		);
		if ( '' !== $lookup_error ) {
			$payload['lookup_error'] = $lookup_error;
			$payload['attempt']      = $attempt;
		}
		Segurium_Storage::cti_send_message( 'cache_invalidation', $payload );
	}

	/**
	 * Stored state with every key present.
	 *
	 * @return array{pending:bool, trigger:string, last_run:int, attempts:int}
	 */
	private static function state(): array {
		$raw = Segurium_Storage::setting_get_array( self::SETTING_STATE, array() );
		return array(
			'pending'  => ! empty( $raw['pending'] ),
			'trigger'  => isset( $raw['trigger'] ) ? (string) $raw['trigger'] : self::TRIGGER_MANUAL,
			'last_run' => isset( $raw['last_run'] ) ? (int) $raw['last_run'] : 0,
			'attempts' => isset( $raw['attempts'] ) ? (int) $raw['attempts'] : 0,
		);
	}

	/**
	 * Persist state.
	 *
	 * @param array $state State to store.
	 * @return void
	 */
	private static function save_state( array $state ): void {
		Segurium_Storage::setting_set( self::SETTING_STATE, $state );
	}

	/**
	 * First moment the interval allows a run.
	 *
	 * @param array $state Current state.
	 * @return int
	 */
	private static function earliest_run( array $state ): int {
		return max( time(), $state['last_run'] + self::MIN_INTERVAL_SECS );
	}

	/**
	 * Make sure a run happens no later than $when.
	 *
	 * @param int $when Unix time.
	 * @return void
	 */
	private static function schedule_by( int $when ): void {
		$next = wp_next_scheduled( self::HOOK );
		if ( false !== $next && $next <= $when ) {
			return;
		}
		self::reschedule( $when );
	}

	/**
	 * Replace any queued run with one at $when.
	 *
	 * @param int $when Unix time.
	 * @return void
	 */
	private static function reschedule( int $when ): void {
		wp_clear_scheduled_hook( self::HOOK );
		$scheduled = wp_schedule_single_event( $when, self::HOOK, array(), true );
		if ( is_wp_error( $scheduled ) ) {
			Segurium_Debug::log( '[segurium-cache] schedule failed: ' . $scheduled->get_error_code() );
		}
	}
}

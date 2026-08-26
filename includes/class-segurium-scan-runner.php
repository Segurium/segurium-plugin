<?php
/**
 * Hybrid scan runner driven by life_support_system().
 *
 * The runner has a single decision tree (life_support_system) called from
 * three trigger paths so a scan completes regardless of which mechanism the
 * host actually supports:
 *
 *   1. WP-cron — a recurring 60-second rescue event armed at scan start
 *      (SEGURIUM-419 + SEGURIUM-425, schedule key
 *      `segurium_every_60_seconds`); cleared on every termination path. The
 *      cron handler is also defensive: if it fires with no scan lock it
 *      self-heals by clearing the recurring entry. The chain advances via
 *      the mechanism V self-trigger between cron beats — cron is the
 *      "self-trigger got dropped" rescue, not a primary driver.
 *   2. Page load — registered on the `shutdown` action; calls
 *      fastcgi_finish_request() / litespeed_finish_request() to detach from
 *      the visitor request and runs life_support_system() afterwards.
 *      Skipped on bare mod_php hosts so visitor pageloads never block.
 *   3. Admin AJAX — `wp_ajax_segurium_scan_tick` returns the current status
 *      payload immediately. The actual chunk loop is driven by the same
 *      shutdown trigger (path 2): once the JSON response has been sent the
 *      shutdown handler detaches via fastcgi_finish_request() and runs the
 *      tick — the browser never blocks on chunk processing.
 *
 * Replaces the loopback + shutdown-handler + nudge_if_stale architecture
 * (SEGURIUM-249/-248) which proved unreliable on shared LiteSpeed hosts:
 * PHP shutdown handlers are suppressed when max_execution_time kills a
 * worker, non-blocking wp_remote_get to admin-ajax does not actually
 * deliver until the previous lsphp worker is reaped, and DISABLE_WP_CRON
 * breaks the cron fallback. life_support_system() does not rely on any of
 * those mechanisms — each tick is a self-contained PHP process that the
 * trigger paths fire opportunistically.
 *
 * Supports multiple scan types via a duck-typed engine contract. Each
 * engine must implement: initialize(), load_state(), process_chunk(),
 * get_progress_snapshot(), mark_cancelled(), mark_aborted(). Currently
 * supported: malware scans (Segurium_Scan) and integrity scans
 * (Segurium_Integrity_Scan_State). A shared lock ensures only one scan
 * of any kind runs at a time.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates browser-independent scan execution for any engine type.
 */
final class Segurium_Scan_Runner {

	/**
	 * WP-cron + AJAX action name used by the chained tick mechanism.
	 */
	const TICK_HOOK = 'segurium_scan_tick';

	/**
	 * SEGURIUM-419 + SEGURIUM-425: recurring rescue schedule registered via
	 * the `cron_schedules` filter. Drives `TICK_HOOK` every 60 seconds while
	 * a scan is active so progress survives a dropped self-trigger without
	 * adding a parallel beat to the chain (5s on the test site made cron a
	 * second producer racing the chain's mutex on every release window).
	 */
	const TICK_RECURRING_SCHEDULE = 'segurium_every_60_seconds';

	/**
	 * SEGURIUM-425: legacy schedule key superseded by
	 * {@see TICK_RECURRING_SCHEDULE}. Kept as a constant so the upgrade
	 * migration in `segurium.php` can clear orphaned events without typo
	 * risk. Do NOT register a `cron_schedules` entry for this key — we want
	 * any surviving event to drop on the next reschedule attempt.
	 */
	const TICK_RECURRING_SCHEDULE_LEGACY = 'segurium_every_5_seconds';

	/**
	 * Cron hook used by the stale-lock watchdog.
	 */
	const CRON_WATCHDOG_HOOK = 'segurium_scan_lock_watchdog';

	/**
	 * Legacy transient key for the cross-process tick mutex. Kept as a
	 * constant only so existing test cleanup paths that call
	 * delete_transient( TICK_MUTEX_TRANSIENT ) remain harmless. The active
	 * mutex is now an atomic runtime_kv row keyed by MUTEX_KV_KEY — see
	 * acquire_tick_mutex() / release_tick_mutex() (SEGURIUM-426). The
	 * previous get_transient + set_transient pair was a TOCTOU race that
	 * let multiple PHP-FPM workers run the chunk loop concurrently against
	 * the same scan, corrupting the verdict-queue counter blob.
	 */
	const TICK_MUTEX_TRANSIENT = 'segurium_scan_tick_mutex';

	/**
	 * Runtime_kv row name for the atomic tick mutex (SEGURIUM-426). The
	 * row's kv_value is the holder's unique acquisition token; expires_at
	 * carries the TTL self-heal stamp. Acquisition is one INSERT ... ON
	 * DUPLICATE KEY UPDATE statement gated by the existing row's
	 * expires_at, so two concurrent acquirers cannot both see "free" the
	 * way they could on the transient pair.
	 */
	const MUTEX_KV_KEY = 'mutex:scan_tick';

	/**
	 * Logical key in runtime_kv where the per-scan attempt counter lives.
	 * Scoped by scan_uuid so the counter resets cleanly when a fresh scan
	 * starts. Incremented at tick entry; reset as soon as a process_chunk()
	 * call returns successfully. Killed-mid-chunk ticks therefore count
	 * toward the abort threshold, which the prior post-loop counter design
	 * could not detect (SEGURIUM-252).
	 */
	const STUCK_COUNTER_KV_PREFIX = 'scan_stuck:';

	/**
	 * Maximum consecutive killed-or-no-progress ticks before the scan is
	 * force-aborted with a structured `scan_aborted_no_progress` error
	 * (instead of a silent stall via heartbeat staleness).
	 */
	const STUCK_MAX = 5;

	/**
	 * Safety margin (seconds) deducted from `max_execution_time` when
	 * computing the effective tick budget. Leaves room for the chunk
	 * loop to exit cleanly before PHP terminates the worker mid-iteration.
	 */
	const TICK_BUDGET_SAFETY_SEC = 10;

	/**
	 * Floor on the effective tick budget. A host with a very tight
	 * `max_execution_time` (e.g. 10s) still gets at least one chunk per
	 * trigger. The user-facing environment warning surfaces via
	 * `environment_warnings()` so the user can escalate to their host.
	 */
	const TICK_BUDGET_MIN_SEC = 5;

	/**
	 * Sentinel default budget when `max_execution_time = 0` (CLI / mod_php
	 * with no limit). The ticket spec calls for "no fixed ceiling" relative
	 * to max_execution_time; this only applies to the unbounded case.
	 */
	const TICK_BUDGET_UNLIMITED_SEC = 60;

	/**
	 * Delay (seconds) between chained wp-cron ticks while a scan lock is
	 * held. Kept short so the chained event picks up promptly when the
	 * mechanism V self-trigger (SEGURIUM-421) is dropped by the network.
	 */
	const NEXT_TICK_DELAY_SEC = 5;

	/**
	 * Wall-time safety margin (seconds) the chunk loop reserves at the end
	 * of each tick. Used by `time_left_in_tick()` so the engine can decide
	 * whether to start the next outbound CTI / neo-ray call or break early
	 * and let the next tick pick it up. SEGURIUM-252.
	 */
	const TICK_GRACEFUL_EXIT_SAFETY_SEC = 2;

	/**
	 * SEGURIUM-511: duty-cycle floor on tick wall time (seconds). Before
	 * firing the mechanism V self-trigger the runner sleeps the tick out
	 * to this value, capping dispatch rate to <= 1 / MIN_TICK_WALL_SEC.
	 * Replaces the SEGURIUM-426 counter-progress gate as the spin guard.
	 * Override via the `segurium_scan_min_tick_wall_sec` filter (tests only).
	 */
	const MIN_TICK_WALL_SEC = 5.0;

	/**
	 * Hard timeout (seconds) for the primary `wp_remote_post()` self-trigger.
	 * SEGURIUM-425: blocking call; if cURL connect/handshake/response can
	 * complete within this window the request is considered delivered (any
	 * 2xx/4xx/5xx — the response code does not matter to a fire-and-forget
	 * spawn). Only on `WP_Error` whose message is NOT a timeout do we fall
	 * back to fsockopen. Hosts behind a WAF that hold the request for the
	 * full window simply produce one delivered POST + one timeout-classed
	 * failure (no fallback) instead of doubling the dispatch rate.
	 */
	const SELF_TRIGGER_TIMEOUT_SEC = 1.0;

	/**
	 * Connect timeout (seconds) for the fsockopen fallback. Kept short so a
	 * misconfigured loopback (firewall / mod_security) cannot park the
	 * graceful-exit caller. SEGURIUM-421.
	 */
	const SELF_TRIGGER_SOCKET_CONNECT_TIMEOUT_SEC = 0.5;

	/**
	 * Tolerance window (seconds) for treating a wp-cron-scheduled scan as
	 * overdue. life_support_system() will start the scheduled scan inline
	 * once the schedule timestamp is older than this — keeps the schedule
	 * honored on hosts with broken wp-cron when admin/visitor traffic
	 * triggers life_support_system().
	 */
	const SCHEDULED_OVERDUE_TOLERANCE_SEC = 60;

	/**
	 * Window (seconds) within which a recent observer-driven tick suppresses
	 * the cron and pageload entry hooks. SEGURIUM-271: when an admin observer
	 * is actively driving the runner via `ajax_tick → shutdown → LSS('ajax')`,
	 * cron firings and visitor pageloads are redundant and pay full request
	 * cost for nothing. Setting this slightly above the JS slow-poll cadence
	 * (5s) gives one missed-poll buffer before pageload / cron resume their
	 * fallback role. Kept well under HEARTBEAT_MAX_AGE so a dead observer is
	 * detected long before the watchdog reclaims a stale lock.
	 */
	const OBSERVER_FRESH_SEC = 8;

	/**
	 * Per-request flag set by `ajax_tick()` so that `maybe_pageload_tick()`
	 * (which fires on `shutdown` for every request) can distinguish the
	 * observer's own AJAX request — which IS the privileged driver — from an
	 * unrelated visitor pageload that just happened to coincide with an
	 * active scan. Without this, the observer's own shutdown would be
	 * suppressed by the observer-fresh gate and the runner would stall
	 * (SEGURIUM-271).
	 *
	 * @var bool
	 */
	private static $is_observer_request = false;

	/**
	 * SEGURIUM-430: per-process record of the tick-mutex token this PHP
	 * process is currently holding plus the TTL it was acquired with. The
	 * runtime_kv mutex is a *lease* — the holder must renew it periodically
	 * for the duration of the chunk so a slow chunk can't be reclaimed by a
	 * concurrent worker just because the original TTL drifted past `now`.
	 * `renew_active_tick_mutex()` is the single chokepoint that pushes the
	 * row's `expires_at` forward; it reads from these two fields so callers
	 * (per-file heartbeat in verdict_queue, between-chunk heartbeat in
	 * life_support_system) don't have to thread the token through every
	 * signature.
	 *
	 * @var string|null
	 */
	private static $active_mutex_token = null;

	/**
	 * Renewal TTL (seconds) for the active mutex token. Set on acquire,
	 * used by every renewal. compute_mutex_ttl() owns the actual value —
	 * we just remember whatever the acquire call passed in.
	 *
	 * @var int
	 */
	private static $active_mutex_ttl = 0;

	/**
	 * Mark the current request as a runner-observer request so the
	 * shutdown handler treats it as the privileged driver — same flag
	 * `ajax_tick()` flips. Public for the REST controller in SEGURIUM-424
	 * (mechanisms III + VI) which has the same semantics: the request
	 * itself is observing/driving the runner.
	 *
	 * @return void
	 */
	public static function mark_request_as_observer() {
		self::$is_observer_request = true;
	}

	/**
	 * Test-only accessor for the per-request observer flag.
	 *
	 * @return bool
	 */
	public static function is_observer_request_for_test() {
		return self::$is_observer_request;
	}

	/**
	 * Test-only reset for the per-request observer flag so a negative
	 * assertion (rejected request must NOT flip it) starts from a clean
	 * baseline in a shared PHP process.
	 *
	 * @return void
	 */
	public static function reset_observer_request_for_test() {
		self::$is_observer_request = false;
	}

	/*
	 * SEGURIUM-405: scan termination reason codes.
	 *
	 * Every row in `wp_segurium_scan_history.error_code` is populated with one
	 * of these strings (no NULL after start). The `status` column stays binary
	 * (running / completed / cancelled / aborted) for dashboard compatibility;
	 * the reason code is the structured "why" alongside it.
	 */
	const REASON_RUNNING                    = 'RUNNING';
	const REASON_COMPLETED                  = 'COMPLETED';
	const REASON_USER_CANCEL                = 'USER_CANCEL';
	const REASON_ABORTED_STUCK_NO_PROGRESS  = 'ABORTED_STUCK_NO_PROGRESS';
	const REASON_ABORTED_HEARTBEAT_STALE    = 'ABORTED_HEARTBEAT_STALE';
	const REASON_ABORTED_WATCHDOG_SWEEP     = 'ABORTED_WATCHDOG_SWEEP';
	const REASON_ABORTED_ENGINE_LOAD_FAILED = 'ABORTED_ENGINE_LOAD_FAILED';
	const REASON_ABORTED_ORPHANED           = 'ABORTED_ORPHANED';
	const REASON_ABORTED_UPLOAD_CAPACITY    = 'ABORTED_UPLOAD_CAPACITY';

	/**
	 * The scan_history.status values that end a scan. One list for the terminal
	 * gate, the REST answer and the newest-terminal lookup.
	 */
	const TERMINAL_STATUSES    = array( 'completed', 'cancelled', 'aborted' );
	const REASON_RUNTIME_ERROR = 'RUNTIME_ERROR';

	/*
	 * SEGURIUM-414: cooperative cancel handshake.
	 *
	 * `terminate()` writes a `scan_cancel:<scan_id>` runtime_kv row whenever a
	 * tick mutex is held (i.e. a worker is mid-tick) and skips the synchronous
	 * workspace cleanup that previously raced the live worker into SIGSEGV.
	 * The chunk loop in `life_support_system()` polls this flag at the top of
	 * every iteration; on hit it runs the engine's `cleanup_state()` from the
	 * only process that is still touching the workspace, then clears the flag.
	 */
	const CANCEL_FLAG_KV_PREFIX = 'scan_cancel:';

	/**
	 * Register all hooks the runner needs.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_filter( 'cron_schedules', array( __CLASS__, 'register_cron_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval
		add_action( self::TICK_HOOK, array( __CLASS__, 'cron_tick' ) );
		// SEGURIUM-584: the browser-driven scan tick (wp_ajax_segurium_scan_tick)
		// is registered through the central AJAX dispatcher in Segurium::__construct()
		// (route table entry 'segurium_scan_tick' -> Segurium_Scan_Runner::ajax_tick),
		// so the dispatcher verifies the segurium_scan nonce + manage_options before
		// ajax_tick() runs. The cron tick (self::TICK_HOOK above) is unaffected.
		add_action( self::CRON_WATCHDOG_HOOK, array( __CLASS__, 'run_watchdog' ) );
		add_action( 'shutdown', array( __CLASS__, 'maybe_pageload_tick' ), PHP_INT_MAX );

		if ( ! wp_next_scheduled( self::CRON_WATCHDOG_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_WATCHDOG_HOOK );
		}
	}

	/**
	 * Register the recurring 60-second rescue schedule used by the scan tick.
	 * SEGURIUM-419 + SEGURIUM-425. The chain advances via the mechanism V
	 * self-trigger; this cron entry is the rescue path when the self-trigger
	 * is dropped (network error, fastcgi kill mid-call, etc.) — not a
	 * parallel beat.
	 *
	 * @param array $schedules Existing wp-cron schedules.
	 * @return array
	 */
	public static function register_cron_schedule( $schedules ) {
		if ( ! is_array( $schedules ) ) {
			$schedules = array();
		}
		// register_hooks() calls wp_schedule_event() at plugin-include time,
		// which applies `cron_schedules` before `after_setup_theme`. Translating
		// there trips WP 6.7's "translation triggered too early" notice, so the
		// label stays literal English until the textdomain may be loaded. The
		// display string is only ever rendered by cron viewers, long after init.
		$label = 'Every 60 seconds (Segurium scan rescue)';
		if ( did_action( 'after_setup_theme' ) ) {
			$label = __( 'Every 60 seconds (Segurium scan rescue)', 'segurium' );
		}
		$schedules[ self::TICK_RECURRING_SCHEDULE ] = array(
			'interval' => 60,
			'display'  => $label,
		);
		return $schedules;
	}

	/**
	 * Clear any scheduled runner events.
	 *
	 * @return void
	 */
	public static function unregister_hooks() {
		wp_clear_scheduled_hook( self::CRON_WATCHDOG_HOOK );
		wp_clear_scheduled_hook( self::TICK_HOOK );
	}

	/**
	 * Start a new scan. Returns either the scan id on success or a WP_Error
	 * describing why the start was refused.
	 *
	 * @param string $scan_type Scan type label ('manual', 'scheduled', ...).
	 * @return string|WP_Error
	 */
	public static function start( $scan_type = 'manual' ) {
		$scan_type = (string) $scan_type;
		if ( '' === $scan_type ) {
			return new WP_Error(
				'invalid_scan_type',
				__( 'A scan type is required.', 'segurium' )
			);
		}

		// SEGURIUM-546: pre-flight IID gate. Without a stored installation ID
		// every outbound CTI call would be unauthenticated and every progress
		// row would be a fake-failure. Refuse before touching schema, lock,
		// engine, filesystem, or network so a not-yet-activated install does
		// not waste work or pollute scan stats.
		if ( null === Segurium_IID::get_iid() ) {
			self::debug( 'scan_refused_no_iid', array( 'scan_type' => $scan_type ) );
			return new WP_Error(
				'no_iid',
				__( 'Activation with the Segurium cloud service is still pending. Please try again in a moment.', 'segurium' )
			);
		}

		$lock_acquired = false;
		$scan_id       = '';

		try {
			try {
				Segurium_Storage::ensure_schema();
			} catch ( Throwable $e ) {
				self::log_exception( 'ensure_schema', $e );
				return new WP_Error(
					'schema_unavailable',
					__( 'Scan storage is not ready. Please deactivate and reactivate the Segurium plugin, then try again.', 'segurium' ),
					array( 'detail' => $e->getMessage() )
				);
			}

			$existing = Segurium_Scan_Lock::get();
			if ( null !== $existing ) {
				if ( Segurium_Scan_Lock::is_running() ) {
					return new WP_Error(
						'scan_already_running',
						__( 'A scan is already in progress.', 'segurium' ),
						array( 'lock' => $existing )
					);
				}
				// SEGURIUM-871: the lock is past LOCK_MAX_AGE. Close the
				// abandoned scan before taking its slot; overwriting the lock
				// left the old row at RUNNING forever.
				self::debug(
					'start_closes_ancient_lock',
					array(
						'scan_id'  => $existing['scan_id'],
						'lock_age' => time() - (int) $existing['started_at'],
					)
				);
				self::close_ancient_lock( $existing );
			}

			$engine = self::create_engine( $scan_type );

			$scan_id = wp_generate_uuid4();

			if ( ! Segurium_Scan_Lock::acquire( $scan_id, $scan_type ) ) {
				$holder = Segurium_Scan_Lock::get();
				if ( null === $holder ) {
					return new WP_Error(
						'lock_write_failed',
						sprintf(
							/* translators: %s: underlying exception message */
							__( 'Unexpected error starting scan: %s', 'segurium' ),
							'scan lock write did not land'
						)
					);
				}
				return new WP_Error(
					'scan_already_running',
					__( 'A scan is already in progress.', 'segurium' ),
					array( 'lock' => $holder )
				);
			}
			$lock_acquired = true;

			try {
				$engine->initialize( $scan_id, $scan_type );
			} catch ( Throwable $e ) {
				Segurium_Scan_Lock::release();
				$lock_acquired = false;
				self::log_exception( 'initialize', $e );

				if ( $e instanceof Segurium_Storage_Exception ) {
					try {
						Segurium_Storage::ensure_schema( true );
					} catch ( Throwable $heal_exc ) {
						self::log_exception( 'ensure_schema_force', $heal_exc );
					}
					return new WP_Error(
						'schema_unavailable',
						__( 'Scan storage was not ready. It has been repaired automatically — please click "Start scan" again.', 'segurium' ),
						array( 'detail' => $e->getMessage() )
					);
				}

				return new WP_Error(
					'scan_initialize_failed',
					sprintf(
						/* translators: %s: underlying exception message */
						__( 'Failed to initialize scan: %s', 'segurium' ),
						$e->getMessage()
					)
				);
			}

			// Reset stuck-state for a fresh scan.
			self::clear_stuck_state( $scan_id );

			// Schedule the first wp-cron tick. Subsequent ticks chain
			// themselves from inside life_support_system() while the lock
			// is held; this seeds the chain so cron-healthy hosts make
			// progress even if no admin browser polls or visitors land.
			self::schedule_next_tick();

			self::debug(
				'scan_started',
				array(
					'scan_id'   => $scan_id,
					'scan_type' => $scan_type,
					'max_exec'  => self::max_execution_time(),
					'budget'    => (float) self::tick_budget(),
				)
			);

			return $scan_id;
		} catch ( Throwable $e ) {
			if ( $lock_acquired ) {
				try {
					Segurium_Scan_Lock::release();
				} catch ( Throwable $ignored ) {
					unset( $ignored );
				}
			}
			self::log_exception( 'start', $e );
			return new WP_Error(
				'unexpected_error',
				sprintf(
					/* translators: %s: underlying exception message */
					__( 'Unexpected error starting scan: %s', 'segurium' ),
					$e->getMessage()
				)
			);
		}
	}

	/**
	 * Forward a caught Throwable to the PHP error log. Always emits (no
	 * gate) so production stack traces are never silently dropped.
	 *
	 * @param string    $where Identifier for the call site.
	 * @param Throwable $e     Captured throwable.
	 * @return void
	 */
	private static function log_exception( $where, $e ) {
		Segurium_Debug::log(
			sprintf(
				'[segurium-scan-runner] %s: %s: %s at %s:%d',
				$where,
				get_class( $e ),
				$e->getMessage(),
				$e->getFile(),
				$e->getLine()
			)
		);
	}

	/**
	 * Whether structured runner debug events should be emitted. Toggled by a
	 * wp-config constant so production sites have zero log activity by
	 * default — the operator opts in only while diagnosing a stuck scan.
	 *
	 * Public so the CTI client and verdict queue can gate their own
	 * instrumentation on the same switch (SEGURIUM-256), without having to
	 * duplicate the constant check or call debug() unconditionally.
	 *
	 * @return bool
	 */
	public static function debug_enabled() {
		return defined( 'SEGURIUM_DEBUG_SCAN_RUNNER' ) && SEGURIUM_DEBUG_SCAN_RUNNER;
	}

	/**
	 * Emit one structured event line to the PHP error log when
	 * SEGURIUM_DEBUG_SCAN_RUNNER is enabled. No-op otherwise.
	 *
	 * Format: `[segurium-scan-runner] event=<name> key=value key=value …`.
	 * The PHP error log already prefixes each line with a timestamp; with
	 * `WP_DEBUG_LOG=true` in wp-config.php every line lands in
	 * `wp-content/debug.log`. Without it, the line goes to whatever path the
	 * host configured for `error_log` (typically the PHP-FPM / Apache log).
	 *
	 * Designed for grep / awk diagnostic use:
	 *   grep 'segurium-scan-runner' wp-content/debug.log \
	 *     | grep 'event=chunk_threw'
	 *
	 * Public so the CTI client and verdict queue can emit on the same prefix
	 * line (SEGURIUM-256) — one switch covers runner + transport + queue.
	 *
	 * @param string $event Event identifier (e.g. `tick_enter`, `inspect_send`).
	 * @param array  $ctx   Key → scalar/bool/float context.
	 * @return void
	 */
	public static function debug( $event, array $ctx = array() ) {
		/**
		 * SEGURIUM-483: fire a side-channel action so tests and external
		 * observers can subscribe without enabling the error_log gate.
		 * No-op in production when no listener is registered — WP's
		 * `do_action` is O(1) on an empty hook.
		 *
		 * @param string $event Event identifier.
		 * @param array  $ctx   Key → scalar/bool/float context.
		 */
		do_action( 'segurium_scan_runner_debug', (string) $event, $ctx );

		if ( ! self::debug_enabled() ) {
			return;
		}
		$parts = array();
		foreach ( $ctx as $key => $value ) {
			if ( is_bool( $value ) ) {
				$value = $value ? 'true' : 'false';
			} elseif ( is_array( $value ) || is_object( $value ) ) {
				$value = wp_json_encode( $value );
			} elseif ( is_float( $value ) ) {
				$value = sprintf( '%.3f', $value );
			} else {
				$value = (string) $value;
			}
			$parts[] = $key . '=' . $value;
		}
		Segurium_Debug::log(
			sprintf(
				'[segurium-scan-runner] event=%s%s',
				$event,
				$parts ? ' ' . implode( ' ', $parts ) : ''
			)
		);
	}

	/**
	 * Whether a scan currently holds the lock (SEGURIUM-870: true through a
	 * dead-worker stall; see {@see Segurium_Scan_Lock::is_running()}).
	 *
	 * @return bool
	 */
	public static function is_running() {
		return Segurium_Scan_Lock::is_running();
	}

	/**
	 * Whether the scan-runner lock currently holds the given scan id.
	 *
	 * SEGURIUM-262: cooperative cancellation signal for the verdict queue.
	 * When `Segurium_Scan_Runner::stop()` releases the lock, an in-flight
	 * tick (executing on `shutdown` after the response was detached) can
	 * read this and bail out of its current batch instead of running every
	 * remaining `VERDICT_UNKNOWN` through `/v1/neo-ray`. Returns false for
	 * an empty scan id so realtime/upload paths (which never acquire the
	 * lock) keep treating cancellation as opt-in.
	 *
	 * @param string $scan_id Scan UUID to test against the active lock.
	 * @return bool
	 */
	public static function is_scan_lock_held( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return false;
		}
		$lock = Segurium_Scan_Lock::get();
		if ( null === $lock || ! isset( $lock['scan_id'] ) ) {
			return false;
		}
		return (string) $lock['scan_id'] === $scan_id;
	}

	/**
	 * SEGURIUM-414: write the cooperative cancel flag for the given scan.
	 *
	 * @param string $scan_id Scan UUID being cancelled.
	 * @param string $reason  Reason code being recorded — kept as the row
	 *                        value so an operator inspecting runtime_kv can
	 *                        correlate the flag with the scan_history reason.
	 * @return void
	 */
	private static function set_cancel_flag( $scan_id, $reason ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		try {
			Segurium_Storage::table_upsert(
				'runtime_kv',
				array(
					'kv_key'     => self::CANCEL_FLAG_KV_PREFIX . $scan_id,
					'kv_value'   => (string) $reason,
					'updated_at' => time(),
				),
				array( 'kv_key' )
			);
		} catch ( Throwable $e ) {
			self::log_exception( 'set_cancel_flag', $e );
		}
	}

	/**
	 * SEGURIUM-414: whether the cooperative cancel flag is set for a scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return bool
	 */
	private static function cancel_flag_set( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return false;
		}
		try {
			$val = Segurium_Storage::table_get_var(
				'runtime_kv',
				'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
				array( self::CANCEL_FLAG_KV_PREFIX . $scan_id )
			);
		} catch ( Throwable $e ) {
			self::log_exception( 'cancel_flag_set', $e );
			return false;
		}
		return null !== $val;
	}

	/**
	 * SEGURIUM-414: clear the cooperative cancel flag for a scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	private static function clear_cancel_flag( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		try {
			Segurium_Storage::table_delete(
				'runtime_kv',
				array( 'kv_key' => self::CANCEL_FLAG_KV_PREFIX . $scan_id )
			);
		} catch ( Throwable $e ) {
			self::log_exception( 'clear_cancel_flag', $e );
		}
	}

	/**
	 * SEGURIUM-414: whether a tick mutex is currently held. When true, a
	 * worker is mid-tick and `terminate()` must defer the workspace cleanup
	 * to the cooperative cancel handshake — running `tmp_destroy()` /
	 * `verdict_queue->purge()` while a worker is reading the workspace caused
	 * SIGSEGV crashes (see SEGURIUM-414 evidence).
	 *
	 * @return bool
	 */
	private static function tick_mutex_held() {
		$held = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s AND expires_at >= %d',
			array( self::MUTEX_KV_KEY, time() )
		);
		return null !== $held && '' !== (string) $held;
	}

	/**
	 * SEGURIUM-426: atomic tick-mutex acquire backed by runtime_kv.
	 *
	 * Issues one INSERT ... ON DUPLICATE KEY UPDATE that overwrites the row
	 * only when the existing expires_at is in the past (TTL self-heal).
	 * Reads the row back; if the kv_value matches our token we hold the
	 * lock — otherwise another worker won and we bail. Single-row, one
	 * round-trip on the hot path; one extra SELECT to confirm.
	 *
	 * Replaces the get_transient + set_transient pair, which had a TOCTOU
	 * window wide enough for ~10 PHP-FPM workers to race past it on
	 * the test site under the SEGURIUM-421 self-trigger handoff load.
	 *
	 * @param int $ttl_seconds TTL for the lock; clamped to >=1 so the row
	 *                         is never written immediately expired.
	 * @return string|null Acquisition token if we hold the lock, null otherwise.
	 */
	public static function acquire_tick_mutex( $ttl_seconds ) {
		global $wpdb;
		$ttl   = max( 1, (int) $ttl_seconds );
		$token = self::mint_mutex_token();
		$tbl   = Segurium_Storage::table_name( 'runtime_kv' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- atomic mutex acquisition; cache layer would defeat correctness.
		$wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (kv_key, kv_value, expires_at, updated_at) '
				. 'VALUES (%s, %s, %d, %d) '
				. 'ON DUPLICATE KEY UPDATE '
				. '  kv_value   = IF(expires_at < UNIX_TIMESTAMP(), VALUES(kv_value),  kv_value), '
				. '  expires_at = IF(expires_at < UNIX_TIMESTAMP(), VALUES(expires_at), expires_at), '
				. '  updated_at = IF(expires_at < UNIX_TIMESTAMP(), VALUES(updated_at), updated_at)',
				$tbl,
				self::MUTEX_KV_KEY,
				$token,
				time() + $ttl,
				time()
			)
		);

		$current = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::MUTEX_KV_KEY )
		);
		if ( (string) $current !== $token ) {
			return null;
		}

		// SEGURIUM-430: remember our holder slot so renew_active_tick_mutex()
		// can extend the lease later without callers having to thread the
		// token through. Cleared on release_tick_mutex().
		self::$active_mutex_token = $token;
		self::$active_mutex_ttl   = $ttl;

		return $token;
	}

	/**
	 * SEGURIUM-430: extend the tick-mutex lease while we still own it.
	 *
	 * The mutex is a lease: the holder must keep renewing it for the
	 * duration of the chunk. Without renewal, the row's `expires_at` drifts
	 * past `now` and a concurrent worker can `acquire_tick_mutex()` past
	 * the TTL self-heal even though the original holder is still alive,
	 * producing two-workers-on-one-scan races (SEGURIUM-430 evidence).
	 *
	 * The token guard is critical: a worker whose lease was already
	 * reclaimed during a stall (its row deleted, a new acquirer in place)
	 * MUST NOT push the new holder's expiry around. We do an UPDATE bound
	 * by `kv_value = %s` and report whether any row matched — callers can
	 * detect "I no longer own the mutex" and bail.
	 *
	 * @param string $token       Token returned by acquire_tick_mutex().
	 * @param int    $ttl_seconds Renewal TTL; clamped to >=1 so a buggy
	 *                            caller can't write an immediately-expired
	 *                            row.
	 * @return bool True when our row was extended, false when the row no
	 *              longer belongs to us (or never did, or the token was
	 *              empty).
	 */
	public static function renew_tick_mutex( $token, $ttl_seconds ) {
		if ( ! is_string( $token ) || '' === $token ) {
			return false;
		}
		global $wpdb;
		$ttl = max( 1, (int) $ttl_seconds );
		$tbl = Segurium_Storage::table_name( 'runtime_kv' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- cache layer would mask the renewal.
		$rows = $wpdb->query(
			$wpdb->prepare(
				'UPDATE %i SET expires_at = %d, updated_at = %d WHERE kv_key = %s AND kv_value = %s',
				$tbl,
				time() + $ttl,
				time(),
				self::MUTEX_KV_KEY,
				$token
			)
		);
		if ( ( (int) $rows ) > 0 ) {
			return true;
		}
		// MySQL reports 0 affected rows when the UPDATE changed nothing —
		// a renewal inside the same second as the previous one. Tell that
		// apart from "the row is no longer ours" with one re-read.
		$current = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s AND expires_at >= %d',
			array( self::MUTEX_KV_KEY, time() )
		);
		return (string) $current === $token;
	}

	/**
	 * SEGURIUM-430: renew the lease using whichever token this PHP process
	 * acquired earlier. Called from per-file and per-chunk heartbeat sites
	 * inside the chunk loop / verdict_queue so the lease doesn't expire
	 * while we're still doing real work.
	 *
	 * No-op when this process never acquired (or already released) the
	 * mutex — that's the right behaviour for code paths that share helpers
	 * with non-tick callers (e.g., realtime scanner heartbeats).
	 *
	 * @return bool True when the lease was extended, false otherwise.
	 */
	public static function renew_active_tick_mutex() {
		if ( null === self::$active_mutex_token ) {
			return false;
		}
		return self::renew_tick_mutex( self::$active_mutex_token, self::$active_mutex_ttl );
	}

	/**
	 * SEGURIUM-870: refresh both liveness signals from inside a long loop
	 * (async results drain, integrity chunk, submit retry). Renews the
	 * tick-mutex lease first; when this process held the mutex and the row
	 * no longer carries its token, the lease lapsed and another driver has
	 * taken the scan over — the caller must stop touching the scan, and
	 * the heartbeat is NOT stamped (that would refresh the lock on behalf
	 * of the new owner and hide the takeover). A process that never held
	 * the mutex (realtime / upload / tests) only stamps the heartbeat.
	 *
	 * @param string $scan_id     Scan UUID to heartbeat; '' skips the heartbeat.
	 * @param bool   $is_observer Forwarded to {@see Segurium_Scan_Lock::heartbeat()}.
	 * @return bool True to continue, false when the lease is lost.
	 */
	public static function renew_liveness( $scan_id, $is_observer = false ) {
		if ( null !== self::$active_mutex_token && ! self::renew_active_tick_mutex() ) {
			self::debug( 'lease_lost', array( 'scan_id' => (string) $scan_id ) );
			return false;
		}
		if ( '' !== (string) $scan_id ) {
			Segurium_Scan_Lock::heartbeat( (string) $scan_id, (bool) $is_observer );
		}
		return true;
	}

	/**
	 * SEGURIUM-426: release the tick mutex iff we still own it.
	 *
	 * The token guard keeps a late release call from a worker whose lock
	 * was already TTL-stolen from deleting the new holder's row. Failing
	 * silently here is correct: in the steal case the new holder will
	 * release on its own exit.
	 *
	 * @param string $token Token returned by acquire_tick_mutex().
	 * @return void
	 */
	public static function release_tick_mutex( $token ) {
		if ( ! is_string( $token ) || '' === $token ) {
			return;
		}
		global $wpdb;
		$tbl = Segurium_Storage::table_name( 'runtime_kv' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- atomic mutex release; cache layer would defeat correctness.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE kv_key = %s AND kv_value = %s', $tbl, self::MUTEX_KV_KEY, $token ) );

		// SEGURIUM-430: only clear the active-token slot when WE were the
		// holder. A late release call from a worker whose lease was already
		// reclaimed must not wipe the new holder's slot in this process.
		if ( self::$active_mutex_token === $token ) {
			self::$active_mutex_token = null;
			self::$active_mutex_ttl   = 0;
		}
	}

	/**
	 * Test helper: drop the mutex row regardless of holder. Production code
	 * must never call this — it bypasses the token guard.
	 *
	 * @return void
	 */
	public static function reset_tick_mutex_for_test() {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::MUTEX_KV_KEY ) );
		// Defensive: any test still using the legacy transient gets cleaned
		// up too so a stale row in either store can't bleed across tests.
		delete_transient( self::TICK_MUTEX_TRANSIENT );
		self::clear_active_mutex_for_test();
	}

	/**
	 * SEGURIUM-430 test helper: clear the per-process active-token slot
	 * without touching the runtime_kv row. Tests use this to simulate a
	 * second PHP worker (one whose acquire failed) — after clearing,
	 * `renew_active_tick_mutex()` becomes a no-op as it would in that
	 * worker.
	 *
	 * @return void
	 */
	public static function clear_active_mutex_for_test() {
		self::$active_mutex_token = null;
		self::$active_mutex_ttl   = 0;
	}

	/**
	 * SEGURIUM-430 test helper: read the per-process active-token slot.
	 * Tests assert this matches the token returned by acquire_tick_mutex.
	 *
	 * @return string|null
	 */
	public static function active_mutex_token_for_test() {
		return self::$active_mutex_token;
	}

	/**
	 * Mint a unique mutex acquisition token. PID + microtime is enough on
	 * a single PHP-FPM pool; the random suffix protects against PID reuse
	 * inside a single second on busy hosts.
	 *
	 * @return string
	 */
	private static function mint_mutex_token() {
		return sprintf(
			'%d:%s:%s',
			function_exists( 'getmypid' ) ? (int) getmypid() : 0,
			(string) microtime( true ),
			(string) wp_generate_password( 8, false )
		);
	}

	/**
	 * Last terminal (completed | cancelled | aborted) malware scan.
	 *
	 * SEGURIUM-882 review: lives here rather than only on `Segurium` so a
	 * caller can read it without instantiating that class.
	 * `Segurium::__construct()` registers hooks and schedules cron events,
	 * so `get_instance()` is a write — which quietly made "the MainWP
	 * bridge's read-only actions write nothing" false as soon as the
	 * bridge used it.
	 *
	 * @return array|null Raw row, or null when no terminal scan exists.
	 */
	public static function last_terminal_scan() {
		$row = Segurium_Storage::table_get_row(
			'scan_history',
			"SELECT scan_uuid, scan_type, status, started_at, finished_at, files_found, files_scanned, files_failed, files_skipped, threats_found, threats_cleaned
			 FROM {{table}} WHERE status IN ('completed','cancelled','aborted')
			   AND scan_type IN ('manual','scheduled')
			 ORDER BY started_at DESC LIMIT 1",
			array(),
			ARRAY_A
		);

		return is_array( $row ) ? $row : null;
	}

	/**
	 * Return a combined status payload for the active scan, or null when
	 * no scan is in progress.
	 *
	 * The returned shape depends on the engine type: each engine provides
	 * its own progress snapshot, and the runner merges common lock fields.
	 *
	 * @param string|null $filter_type When non-null, only return status if
	 *                                 the running scan matches this type.
	 * @return array|null
	 */
	public static function get_status( $filter_type = null ) {
		$lock = Segurium_Scan_Lock::get();
		if ( null === $lock ) {
			return null;
		}

		if ( null !== $filter_type && $lock['scan_type'] !== $filter_type ) {
			return null;
		}

		// running = lock held (true through a dead-worker stall);
		// worker_alive / heartbeat_age carry the heartbeat state.
		$liveness = array(
			'running'       => Segurium_Scan_Lock::is_running( $lock ),
			'worker_alive'  => Segurium_Scan_Lock::is_worker_alive( $lock ),
			'heartbeat_age' => Segurium_Scan_Lock::heartbeat_age( $lock ),
			'scan_id'       => $lock['scan_id'],
			'scan_type'     => $lock['scan_type'],
			'started_at'    => $lock['started_at'],
			'heartbeat'     => $lock['heartbeat'],
		);

		$engine = self::create_engine( $lock['scan_type'] );
		if ( ! $engine->load_state() ) {
			return $liveness;
		}

		return array_merge( $engine->get_progress_snapshot(), $liveness );
	}

	/**
	 * Stop the currently running scan. Marks the in-flight history entry as
	 * cancelled and releases the lock.
	 *
	 * @return bool True if a scan was stopped, false if nothing was running.
	 */
	public static function stop() {
		return self::terminate( self::REASON_USER_CANCEL );
	}

	/**
	 * Single termination entry point for every non-success terminal transition
	 * (SEGURIUM-405). Cancellation, watchdog/heartbeat/stuck/engine aborts, and
	 * unexpected runtime errors all funnel through here so that:
	 *   - `wp_segurium_scan_history.error_code` is populated on every reason,
	 *   - the integrity-chain pending marker (`integrity:chain_pending`) is
	 *     cleared on every termination path — previously only the success and
	 *     explicit-cancel paths cleared it, so an aborted chained malware scan
	 *     left a stranded marker that kept the UI showing "running" forever,
	 *   - lock release / tick-clear / stuck-counter reset all happen exactly
	 *     once and in a consistent order.
	 *
	 * The success path is intentionally NOT routed through `terminate()` —
	 * it stays on `finalize_scan()` + the existing `segurium_scan_completed`
	 * action so listeners (server-state update, chain bookkeeping, workspace
	 * cleanup) keep firing in their established order. The success path now
	 * writes `error_code = 'COMPLETED'` directly from `Segurium_Scan::build_progress()`.
	 *
	 * @param string      $reason_code      One of the `REASON_*` constants.
	 * @param string|null $expected_scan_id SEGURIUM-871: when given, terminate
	 *                                      only if the lock still belongs to
	 *                                      this scan; a lock replaced in the
	 *                                      meantime is left alone.
	 * @return bool True when a scan was terminated, false when no lock was held
	 *              (or it belongs to another scan than expected).
	 */
	public static function terminate( $reason_code, $expected_scan_id = null ) {
		$lock = Segurium_Scan_Lock::get();
		if ( null === $lock ) {
			return false;
		}
		if ( null !== $expected_scan_id && (string) $lock['scan_id'] !== (string) $expected_scan_id ) {
			self::debug(
				'terminate_skipped_lock_replaced',
				array(
					'expected' => (string) $expected_scan_id,
					'current'  => (string) $lock['scan_id'],
				)
			);
			return false;
		}

		$status    = self::status_for_reason( $reason_code );
		$scan_id   = (string) $lock['scan_id'];
		$scan_type = (string) $lock['scan_type'];

		// SEGURIUM-414: when a worker is mid-tick, skip the synchronous
		// workspace cleanup the engine's mark_*() helpers would run and let
		// the cooperative cancel handshake do it from the worker's chunk
		// loop. The history row still reaches its terminal state immediately
		// so the user sees `Stop scan` reflected without waiting on the
		// worker to drain.
		$cleanup_synchronously = ! self::tick_mutex_held();
		if ( ! $cleanup_synchronously ) {
			self::set_cancel_flag( $scan_id, $reason_code );
		}

		$engine_finalized = false;
		try {
			$engine = self::create_engine( $scan_type );
			if ( $engine->load_state() ) {
				if ( 'cancelled' === $status ) {
					$engine->mark_cancelled( $reason_code, $cleanup_synchronously );
				} else {
					$engine->mark_aborted( $reason_code, $cleanup_synchronously );
				}
				$engine_finalized = true;
			}
		} catch ( Throwable $e ) {
			self::log_exception( 'terminate.engine.' . $reason_code, $e );
		}

		// Engine couldn't load (or threw mid-finalize). Update the
		// `scan_history` row directly so the row never sits at
		// `error_code = 'RUNNING'` after a terminal transition. Best-effort:
		// if the row doesn't exist (integrity scans don't write history),
		// `table_update` is a silent no-op. SEGURIUM-415: also emit the
		// terminal CTI message in this branch so analytics never sees a
		// scan_started without a matching terminal row.
		if ( ! $engine_finalized && '' !== $scan_id ) {
			try {
				Segurium_Storage::table_update(
					'scan_history',
					array(
						'status'      => $status,
						'finished_at' => time(),
						'error_code'  => $reason_code,
					),
					array(
						'scan_uuid' => $scan_id,
						'status'    => 'running',
					)
				);
			} catch ( Throwable $e ) {
				self::log_exception( 'terminate.history_fallback', $e );
			}

			$payload = array(
				'scan_id'          => $scan_id,
				'scan_type'        => $scan_type,
				'error_code'       => (string) $reason_code,
				'duration_seconds' => isset( $lock['started_at'] ) && (int) $lock['started_at'] > 0
					? max( 0, time() - (int) $lock['started_at'] )
					: 0,
			);
			if ( 'cancelled' === $status ) {
				$payload['cancelled_by'] = self::REASON_USER_CANCEL === $reason_code ? 'user' : 'system';
				Segurium_Storage::cti_send_message( 'scan_cancelled', $payload );
			} else {
				Segurium_Storage::cti_send_message( 'scan_aborted', $payload );
			}
		}

		// Diagnostic snapshot for STUCK_NO_PROGRESS — preserved from the old
		// `mark_scan_aborted_no_progress()` path so existing operators who grep
		// `scan_last_abort:*` keep getting the structured payload.
		if ( self::REASON_ABORTED_STUCK_NO_PROGRESS === $reason_code ) {
			try {
				$stuck = (int) Segurium_Storage::table_get_var(
					'runtime_kv',
					'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
					array( self::STUCK_COUNTER_KV_PREFIX . $scan_id )
				);
				Segurium_Storage::table_upsert(
					'runtime_kv',
					array(
						'kv_key'     => 'scan_last_abort:' . $scan_id,
						'kv_value'   => wp_json_encode(
							array(
								'code'    => $reason_code,
								'stuck'   => $stuck,
								'message' => 'Scan made no forward progress after ' . $stuck . ' consecutive ticks.',
								'at'      => time(),
							)
						),
						'updated_at' => time(),
					),
					array( 'kv_key' )
				);
				Segurium_Debug::log(
					sprintf(
						'[segurium-scan-runner] scan %s (%s) aborted: no forward progress after %d ticks',
						$scan_id,
						$scan_type,
						$stuck
					)
				);
			} catch ( Throwable $e ) {
				self::log_exception( 'terminate.stuck_diag', $e );
			}
		}

		Segurium_Scan_Lock::release();
		self::clear_stuck_state( $scan_id );
		wp_clear_scheduled_hook( self::TICK_HOOK );

		// SEGURIUM-405: clear the chain-pending marker on EVERY termination
		// path. Without this, an aborted chained malware scan left the
		// `integrity:chain_pending` runtime_kv key pointing at the dead UUID,
		// so any UI surface that read `is_chain_pending()` kept reporting
		// "running" until the user clicked another scan and the self-heal in
		// `Segurium_Integrity_Chain::start_or_chain()` finally ran.
		Segurium_Integrity_Chain::clear_pending();

		self::debug(
			'terminate',
			array(
				'scan_id'   => $scan_id,
				'scan_type' => $scan_type,
				'reason'    => $reason_code,
				'status'    => $status,
			)
		);

		return true;
	}

	/**
	 * Map a `REASON_*` code to its scan_history.status value. The binary
	 * status remains the source of truth for dashboards; the reason code is
	 * the additional "why" surfaced in `error_code`.
	 *
	 * @param string $reason_code One of the `REASON_*` constants.
	 * @return string A scan_history.status value: running|completed|cancelled|aborted.
	 */
	private static function status_for_reason( $reason_code ) {
		switch ( $reason_code ) {
			case self::REASON_RUNNING:
				return 'running';
			case self::REASON_COMPLETED:
				return 'completed';
			case self::REASON_USER_CANCEL:
				return 'cancelled';
			case self::REASON_ABORTED_STUCK_NO_PROGRESS:
			case self::REASON_ABORTED_HEARTBEAT_STALE:
			case self::REASON_ABORTED_WATCHDOG_SWEEP:
			case self::REASON_ABORTED_ENGINE_LOAD_FAILED:
			case self::REASON_ABORTED_ORPHANED:
			case self::REASON_ABORTED_UPLOAD_CAPACITY:
			case self::REASON_RUNTIME_ERROR:
				return 'aborted';
			default:
				return 'aborted';
		}
	}

	/**
	 * WP-cron entry point — drives life_support_system() under the
	 * `cron` caller label, unless a browser observer is actively driving the
	 * runner (SEGURIUM-271). When skipped, the cron chain is re-armed at the
	 * standard +5s delay so the next firing picks up if the observer dies.
	 *
	 * @return void
	 */
	public static function cron_tick() {
		// SEGURIUM-419: the recurring schedule is supposed to be torn down on
		// every termination path. If a tick fires anyway with no active scan,
		// short-circuit and self-heal by clearing the recurring entry — a
		// terminate() that raced a wp-cron worker, or a manual cleanup that
		// missed the hook, must not keep the runner spinning every 60s.
		if ( null === Segurium_Scan_Lock::get() ) {
			wp_clear_scheduled_hook( self::TICK_HOOK );
			return;
		}
		if ( self::observer_is_active() ) {
			self::debug( 'cron_skip_observer_active', array() );
			// Observer's ajax_tick → shutdown → LSS('ajax') is the active
			// driver. Re-arm the recurring chain (no-op when already
			// scheduled) so wp-cron remains the safety net if the observer
			// goes away.
			self::schedule_next_tick();
			return;
		}
		self::life_support_system( 'cron' );
	}

	/**
	 * AJAX entry point — returns the current status payload immediately. The
	 * actual life_support_system() work runs from `maybe_pageload_tick()` on
	 * the same request's `shutdown` action (after fastcgi_finish_request /
	 * litespeed_finish_request detaches the response) so the browser never
	 * blocks on the chunk loop.
	 *
	 * @return void
	 */
	public static function ajax_tick() {
		// SEGURIUM-271: this request IS the observer. Mark it so the
		// `shutdown` handler runs LSS instead of being suppressed by the
		// observer-fresh gate, and so LSS can stamp `observer_last_seen` for
		// the next round of cron / visitor pageloads to read.
		self::$is_observer_request = true;

		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'You do not have permission to manage scans.', 'segurium' ),
				),
				403
			);
		}

		$scope = isset( $_REQUEST['scope'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['scope'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended -- nonce verified above
		if ( 'integrity' !== $scope && 'malware' !== $scope ) {
			$scope = '';
		}

		try {
			if ( 'integrity' === $scope ) {
				$status = self::get_status( 'integrity' );
			} else {
				$status = self::get_status();
				if ( null !== $status && 'integrity' === ( $status['scan_type'] ?? '' ) ) {
					// Malware tab never shows integrity scan progress.
					$status = null;
				}
				// SEGURIUM-406 reverts the SEGURIUM-303 chain-driven
				// suppression: the malware tab is the canonical driver
				// for any non-integrity scan, regardless of whether a
				// chain marker is queued behind it.
			}
		} catch ( Throwable $e ) {
			self::log_exception( 'ajax_tick', $e );
			segurium_send_json_error(
				array(
					'code'    => 'ajax_tick_exception',
					'message' => __( 'Could not fetch scan status due to a server error.', 'segurium' ),
				)
			);
		}

		if ( null === $status ) {
			$payload  = array( 'running' => false );
			$terminal = Segurium::get_instance()->get_last_terminal_scan();
			if ( null !== $terminal ) {
				// SEGURIUM-413: hand the client whatever terminated last —
				// completed, cancelled, or aborted — so the JS can paint
				// honest copy. The legacy `last_completed` key is preserved
				// only when the run actually completed; older clients keep
				// working, newer ones branch on `last_terminal.status`.
				$payload['last_terminal'] = $terminal;
				if ( 'completed' === ( $terminal['status'] ?? '' ) ) {
					$payload['last_completed'] = $terminal;
				}
			}
		} else {
			$payload = $status;
		}
		self::debug(
			'ajax_tick',
			array(
				'pid'         => getmypid(),
				't'           => microtime( true ),
				'scope'       => $scope,
				'phase'       => (string) ( $payload['phase'] ?? '-' ),
				'running'     => ! empty( $payload['running'] ) ? '1' : '0',
				'completed'   => ! empty( $payload['completed'] ) ? '1' : '0',
				'files_found' => (int) ( $payload['files_found'] ?? 0 ),
				'submitted'   => (int) ( $payload['files_submitted'] ?? 0 ),
				'verdicted'   => (int) ( $payload['files_verdicted'] ?? 0 ),
				'failed'      => (int) ( $payload['files_failed'] ?? 0 ),
				'threats'     => (int) ( $payload['threats_found'] ?? 0 ),
				'hb'          => (int) ( $payload['heartbeat'] ?? 0 ),
			)
		);
		segurium_send_json_success( $payload );
	}

	/**
	 * Pageload shutdown handler — opportunistic trigger for visitor and
	 * admin requests (including the AJAX poller). Cheap pre-check so the
	 * vast majority of pageloads on idle sites cost nothing; on hosts with
	 * neither fastcgi_finish_request() nor litespeed_finish_request() we
	 * skip entirely so visitor pageloads never block on the chunk loop.
	 *
	 * SEGURIUM-271: when a browser observer is actively driving the runner
	 * (its own AJAX → shutdown → LSS('ajax') is the privileged path),
	 * unrelated visitor / admin pageloads should bail before detach_response
	 * to keep cost as close to zero as possible. The pageload remains the
	 * last-resort kicker for hosts where wp-cron is broken AND no observer
	 * is present — we ONLY suppress when observer freshness proves a worker
	 * is currently driving.
	 *
	 * @return void
	 */
	public static function maybe_pageload_tick() {
		// Cheap pre-check: only proceed when there is something for the
		// life-support system to do. The throttle gate inside
		// life_support_system() handles the duplicate-trigger case
		// (cron tick → shutdown → would-be second tick) by short-circuiting
		// any tick fired within the throttle window of the previous one.
		if ( ! self::has_work() ) {
			return;
		}

		// SEGURIUM-271: observer-fresh fast-path. The observer's own
		// request (`$is_observer_request === true`) IS the driver and must
		// fall through to LSS — otherwise the runner stalls. Every other
		// request that lands inside the observer-fresh window bails: the
		// observer's shutdown handler will drive the next chunk.
		if ( ! self::$is_observer_request && self::observer_is_active() ) {
			return;
		}

		// Need a way to detach from the user's request. fastcgi_finish_request
		// (PHP-FPM) and litespeed_finish_request (LSAPI) close the connection
		// to the client and let PHP keep running until max_execution_time.
		// Bare mod_php has no portable equivalent — skip so visitor pageloads
		// never block on the chunk loop.
		if ( ! self::detach_response() ) {
			return;
		}

		// Observer's own shutdown drives under the 'ajax' label so LSS
		// stamps `observer_last_seen` in the same heartbeat write the chunk
		// loop already does — zero extra DB writes vs. the pre-271 baseline.
		$caller = self::$is_observer_request ? 'ajax' : 'pageload';
		self::life_support_system( $caller );
	}

	/**
	 * Watchdog cron callback — last-resort sweep for sites with no traffic
	 * for hours.
	 *
	 * SEGURIUM-563: a merely-stale heartbeat is no longer treated as
	 * "abort". A killed worker on an execution-capped host leaves a stale
	 * heartbeat behind, but the scan resumes cleanly from persisted state.
	 * So the watchdog now *drives a tick* for a stale-but-not-ancient lock
	 * (life_support_system's Step 3 takes over and resumes), and only
	 * hard-aborts a lock held past the LOCK_MAX_AGE ceiling — a genuinely
	 * abandoned scan. A fresh lock (live worker mid-tick) is left untouched.
	 *
	 * @return void
	 */
	public static function run_watchdog() {
		self::sweep_orphaned_history();
		$lock = Segurium_Scan_Lock::get();
		if ( null === $lock ) {
			return;
		}
		$started_at = (int) $lock['started_at'];
		if ( $started_at > 0 && time() - $started_at > Segurium_Scan_Lock::LOCK_MAX_AGE ) {
			self::close_ancient_lock( $lock );
			return;
		}
		if ( Segurium_Scan_Lock::is_stale( $lock ) ) {
			// Stale heartbeat, within the age ceiling → resume, don't kill.
			self::life_support_system( 'watchdog' );
		}
	}

	/**
	 * SEGURIUM-871: close scan_history rows left at status=running by a scan
	 * that no longer holds the lock.
	 *
	 * Before SEGURIUM-871, start() could overwrite the lock of a scan whose
	 * worker had died; the previous scan's history row then stayed RUNNING
	 * forever, CTI never received a terminal message, and its workspace and
	 * runtime_kv rows were never freed. Every such row is closed here with
	 * status=aborted / error_code=ABORTED_ORPHANED, one scan_aborted message,
	 * and the same runtime teardown the engine's cleanup path performs.
	 * The scan that currently holds the lock (if any) is never touched.
	 * Idempotent: a second run finds no running row and does nothing.
	 *
	 * Called from run_watchdog() (hourly) and once from the plugin upgrade
	 * routine so pre-existing orphans close as soon as sites update.
	 *
	 * @return int|false Number of rows closed, or false when the history
	 *                   query itself failed (nothing was swept).
	 */
	public static function sweep_orphaned_history() {
		// Rows first, lock second, and only rows older than one heartbeat
		// window: a start() that lands between the two reads inserts a
		// younger row, and the per-row lock re-check below covers the rest.
		try {
			$rows = Segurium_Storage::table_get_results(
				'scan_history',
				"SELECT scan_uuid, scan_type, started_at FROM {{table}} WHERE status = 'running' AND started_at < %d",
				array( time() - Segurium_Scan_Lock::HEARTBEAT_MAX_AGE ),
				ARRAY_A
			);
		} catch ( Throwable $e ) {
			self::log_exception( 'sweep_orphaned_history', $e );
			return false;
		}

		$closed = 0;
		foreach ( $rows as $row ) {
			$scan_id = isset( $row['scan_uuid'] ) ? (string) $row['scan_uuid'] : '';
			if ( '' === $scan_id ) {
				continue;
			}
			$lock = Segurium_Scan_Lock::get();
			if ( null !== $lock && (string) $lock['scan_id'] === $scan_id ) {
				continue;
			}
			try {
				self::close_orphaned_scan( $scan_id, (string) $row['scan_type'], (int) $row['started_at'] );
				++$closed;
			} catch ( Throwable $e ) {
				self::log_exception( 'close_orphaned_scan:' . $scan_id, $e );
			}
		}

		if ( $closed > 0 ) {
			self::debug( 'orphan_sweep', array( 'closed' => $closed ) );
		}
		return $closed;
	}

	/**
	 * Close one orphaned scan: terminal history row, scan_aborted message
	 * (same payload shape as terminate()'s fallback branch), runtime teardown.
	 *
	 * @param string $scan_id    Orphaned scan UUID.
	 * @param string $scan_type  Its scan_history.scan_type.
	 * @param int    $started_at Its scan_history.started_at.
	 * @return void
	 */
	private static function close_orphaned_scan( $scan_id, $scan_type, $started_at ) {
		// Teardown first: if it throws, the row stays `running` and the next
		// sweep retries; a row flipped first would hide a half-cleaned scan.
		self::purge_scan_runtime( $scan_id );

		$now = time();
		Segurium_Storage::table_update(
			'scan_history',
			array(
				'status'      => 'aborted',
				'finished_at' => $now,
				'error_code'  => self::REASON_ABORTED_ORPHANED,
			),
			array(
				'scan_uuid' => $scan_id,
				'status'    => 'running',
			)
		);

		Segurium_Storage::cti_send_message(
			'scan_aborted',
			array(
				'scan_id'          => $scan_id,
				'scan_type'        => $scan_type,
				'error_code'       => self::REASON_ABORTED_ORPHANED,
				'duration_seconds' => $started_at > 0 ? max( 0, $now - $started_at ) : 0,
			)
		);
	}

	/**
	 * Drop everything a scan left behind outside scan_history: the engine
	 * runtime ({@see Segurium_Scan::purge_runtime()}) plus the runner's own
	 * stuck counter and cancel flag.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	private static function purge_scan_runtime( $scan_id ) {
		Segurium_Scan::purge_runtime( $scan_id );
		self::clear_stuck_state( $scan_id );
		self::clear_cancel_flag( $scan_id );
	}

	/**
	 * SEGURIUM-871: close a lock held past LOCK_MAX_AGE. A lock whose
	 * history row is already terminal (worker died between the terminal
	 * write and the release) is only dropped — the SEGURIUM-572 gate in
	 * life_support_system() — so a completed scan is never relabelled
	 * aborted and no duplicate terminal message goes out. Anything else is
	 * terminated with ABORTED_WATCHDOG_SWEEP, scoped to this lock's scan_id
	 * so a lock replaced in the meantime is left alone.
	 *
	 * @param array $lock Lock snapshot from Segurium_Scan_Lock::get().
	 * @return void
	 */
	private static function close_ancient_lock( array $lock ) {
		$scan_id = (string) $lock['scan_id'];
		if ( self::scan_history_is_terminal( $scan_id ) ) {
			$current = Segurium_Scan_Lock::get();
			if ( null !== $current && (string) $current['scan_id'] === $scan_id ) {
				Segurium_Scan_Lock::release();
				wp_clear_scheduled_hook( self::TICK_HOOK );
				self::clear_stuck_state( $scan_id );
			}
			return;
		}
		self::terminate( self::REASON_ABORTED_WATCHDOG_SWEEP, $scan_id );
	}

	/**
	 * Microtime when the current tick's chunk loop started. Read by
	 * `time_left_in_tick()` so the engine can decide whether to start the
	 * next outbound CTI / neo-ray call. Reset per tick.
	 *
	 * @var float
	 */
	private static $tick_started_at = 0.0;

	/**
	 * Effective tick budget (seconds) for the current tick. Read by
	 * `time_left_in_tick()`. Reset per tick.
	 *
	 * @var float
	 */
	private static $tick_budget_active = 0.0;

	/**
	 * Single decision tree shared by every trigger path. Idempotent and
	 * concurrency-safe via the tick mutex transient.
	 *
	 * @param string $caller Trigger label (cron / ajax / pageload / test).
	 * @return void
	 *
	 * @throws Throwable Engine process_chunk() exceptions are re-thrown from
	 *                   the inner try so the outer catch can log + re-arm
	 *                   the next tick. Never escapes this method — the
	 *                   outer try/catch in this same function captures it.
	 */
	public static function life_support_system( $caller = 'manual' ) {
		$tick_wall_start = microtime( true );

		/*
		 * Step 1 — acquire tick mutex. Held for the duration of this call so
		 * two concurrent triggers cannot run two workers against the same
		 * scan. The row is a lease (SEGURIUM-430): renewed per file, per
		 * chunk and per async-results iteration, with a TTL equal to
		 * HEARTBEAT_MAX_AGE (SEGURIUM-870) so a killed worker's row expires
		 * at the same moment its heartbeat reads as dead and the next driver
		 * tick can take the scan over in Step 3.
		 */
		$max_exec  = self::max_execution_time();
		$mutex_ttl = self::compute_mutex_ttl( $max_exec );

		// SEGURIUM-426: atomic acquire-or-skip via runtime_kv. Self-heals on
		// TTL expiry inside the same SQL statement, so no separate "stale
		// detect + delete + set" path is needed.
		$mutex_token = self::acquire_tick_mutex( $mutex_ttl );
		if ( null === $mutex_token ) {
			self::debug(
				'mutex_held_skip',
				array(
					'caller'    => $caller,
					'mutex_ttl' => $mutex_ttl,
				)
			);
			return;
		}

		self::debug(
			'tick_enter',
			array(
				'caller'    => $caller,
				'max_exec'  => $max_exec,
				'mutex_ttl' => $mutex_ttl,
			)
		);

		$lock_acquired_inline = false;
		$tick_outcome         = 'unknown';
		$scan_id_for_exit     = '';

		try {
			/*
			 * Step 2 — get the scan lock. None? See if a scheduled scan is
			 * overdue (cron-broken host) and start it inline; otherwise return.
			 */
			$lock = Segurium_Scan_Lock::get();
			if ( null === $lock ) {
				$started = self::maybe_start_overdue_scheduled_scan();
				if ( ! $started ) {
					self::debug( 'lock_missing_no_overdue', array( 'caller' => $caller ) );
					$tick_outcome = 'no_lock';
					return;
				}
				$lock = Segurium_Scan_Lock::get();
				if ( null === $lock ) {
					self::debug( 'lock_missing_overdue_failed', array( 'caller' => $caller ) );
					$tick_outcome = 'overdue_failed';
					return;
				}
				$lock_acquired_inline = true;
				self::debug(
					'lock_overdue_started',
					array(
						'caller'  => $caller,
						'scan_id' => $lock['scan_id'],
					)
				);
			}

			$scan_id_for_exit = $lock['scan_id'];

			/*
			 * SEGURIUM-572 — durable terminal gate. A lock whose scan_history
			 * row is already terminal (completed / cancelled / aborted) is a
			 * leftover: the finalize/release tail never ran, so each later driver
			 * tick (browser poll / wp-cron / CTI tick) used to rebuild the engine
			 * and re-emit. Close the scan out and release the lock so the tick
			 * becomes a no-op. Integrity scans write no history row, so they read
			 * as non-terminal here and fall through to their normal path.
			 *
			 * For a `completed` row whose engine state is still present — the
			 * worker died after finalize_completion()'s atomic claim but before
			 * finalize_scan() — drive the post-completion side-effects now
			 * (Auto-Fix cleanup, integrity chaining, realtime snapshot, chain
			 * marker clear, workspace teardown). The atomic claim keeps
			 * scan_completed exactly-once, so this recovery does not re-emit. If
			 * the state is already gone (crash between cleanup and release) the
			 * engine load fails and we simply drop the lock — no spurious
			 * scan_aborted, no `completed`→`aborted` relabel. cancelled/aborted
			 * rows had their side-effects run by terminate(), so they only need
			 * the lock dropped.
			 *
			 * Exception: a pending `scan_cancel:<id>` flag means terminate()
			 * wrote the terminal (cancelled) row but DEFERRED the workspace
			 * teardown to this very tick (SEGURIUM-414 cooperative cancel).
			 * Gating it out would strand the workspace, so fall through and let
			 * the chunk loop observe the flag and clean up; the next tick (flag
			 * cleared) takes the gate.
			 */
			if ( ! $lock_acquired_inline
				&& ! self::cancel_flag_set( $lock['scan_id'] )
				&& self::scan_history_is_terminal( $lock['scan_id'] ) ) {
				self::debug(
					'tick_terminal_gate',
					array(
						'caller'  => $caller,
						'scan_id' => $lock['scan_id'],
						'status'  => self::scan_history_status( $lock['scan_id'] ),
					)
				);
				if ( 'completed' === self::scan_history_status( $lock['scan_id'] ) ) {
					$recover = self::create_engine( $lock['scan_type'] );
					if ( $recover->load_state() ) {
						self::finalize_scan( $recover, $lock['scan_type'] );
					}
				}
				Segurium_Scan_Lock::release();
				wp_clear_scheduled_hook( self::TICK_HOOK );
				self::clear_stuck_state( $lock['scan_id'] );
				$tick_outcome = 'terminal_gate';
				return;
			}

			/*
			 * Step 3 — stale-lock handling (SEGURIUM-563).
			 *
			 * A stale heartbeat means the *previous worker* was killed
			 * mid-batch — typically PHP `max_execution_time` on an
			 * execution-capped shared host — and the next driver tick (cron,
			 * pageload, or the browser observer) lands more than
			 * HEARTBEAT_MAX_AGE later. It does NOT mean the scan is unhealthy:
			 * all scan state is persisted (Step 4 `load_state()` resumes from
			 * it), so the correct response is to take over this lock and keep
			 * scanning, not to hard-abort an otherwise-healthy scan. We hold
			 * the tick mutex (Step 1), so no other worker can race the
			 * takeover. The heartbeat is refreshed in Step 5's entry-time
			 * bookkeeping.
			 *
			 * The genuine "this scan is going nowhere" guard is the STUCK_MAX
			 * no-progress attempt counter in Step 5 (a worker that resumes but
			 * never advances a chunk still aborts). The LOCK_MAX_AGE ceiling
			 * below is the runaway backstop: a lock held past the hard ceiling
			 * is treated as genuinely abandoned and aborted, matching what the
			 * hourly watchdog would do.
			 *
			 * Before SEGURIUM-563 this path aborted any stale-heartbeat lock
			 * with ABORTED_HEARTBEAT_STALE, which killed large (>25k-file)
			 * scans on 30–60s execution-capped hosts before they could finish.
			 */
			$started_at = (int) $lock['started_at'];
			$lock_age   = time() - $started_at;
			// A 0/absent started_at (legacy or corrupt lock) must NOT read as
			// "ancient" — that would false-abort a healthy scan. Fall through
			// to the heartbeat-takeover path; STUCK_MAX still bounds a scan
			// that genuinely never progresses.
			if ( ! $lock_acquired_inline && $started_at > 0 && $lock_age > Segurium_Scan_Lock::LOCK_MAX_AGE ) {
				self::debug(
					'lock_age_ceiling_abort',
					array(
						'caller'    => $caller,
						'scan_id'   => $lock['scan_id'],
						'scan_type' => $lock['scan_type'],
						'lock_age'  => $lock_age,
						'lock_max'  => Segurium_Scan_Lock::LOCK_MAX_AGE,
					)
				);
				self::terminate( self::REASON_ABORTED_WATCHDOG_SWEEP );
				$tick_outcome = 'lock_age_abort';
				return;
			}

			$hb_age = time() - (int) $lock['heartbeat'];
			if ( ! $lock_acquired_inline && $hb_age > Segurium_Scan_Lock::HEARTBEAT_MAX_AGE ) {
				// Take over the dead worker's lock and resume; do NOT abort.
				self::debug(
					'lock_stale_takeover',
					array(
						'caller'    => $caller,
						'scan_id'   => $lock['scan_id'],
						'scan_type' => $lock['scan_type'],
						'hb_age'    => $hb_age,
						'hb_max'    => Segurium_Scan_Lock::HEARTBEAT_MAX_AGE,
					)
				);
			}

			/*
			 * Step 4 — load engine state. If load fails the worker has nothing
			 * to do; release the lock so the user can retry instead of waiting
			 * for the watchdog.
			 */
			$engine = self::create_engine( $lock['scan_type'] );
			if ( ! $engine->load_state() ) {
				self::debug(
					'engine_load_failed',
					array(
						'caller'    => $caller,
						'scan_id'   => $lock['scan_id'],
						'scan_type' => $lock['scan_type'],
					)
				);
				self::terminate( self::REASON_ABORTED_ENGINE_LOAD_FAILED );
				$tick_outcome = 'engine_load_failed';
				return;
			}

			$scan_id     = $lock['scan_id'];
			$scan_type   = $lock['scan_type'];
			$is_malware  = ( 'integrity' !== $scan_type );
			$is_observer = ( 'ajax' === $caller );

			/*
			 * Step 5 — entry-time bookkeeping (SEGURIUM-252). Observer-driven
			 * ticks also stamp `observer_last_seen` in the same write so the
			 * cron / visitor-pageload entry hooks can detect a live observer
			 * and bail (SEGURIUM-271). Zero extra DB writes vs. the pre-271
			 * baseline.
			 */
			Segurium_Scan_Lock::heartbeat( $scan_id, $is_observer );
			self::renew_active_tick_mutex();
			self::schedule_next_tick();
			$attempts = self::increment_stuck_counter( $scan_id );

			self::debug(
				'tick_init',
				array(
					'caller'    => $caller,
					'scan_id'   => $scan_id,
					'scan_type' => $scan_type,
					'attempts'  => $attempts,
					'stuck_max' => self::STUCK_MAX,
					'hb_age'    => $hb_age,
				)
			);

			if ( $attempts >= self::STUCK_MAX ) {
				self::debug(
					'attempt_abort',
					array(
						'scan_id'  => $scan_id,
						'attempts' => $attempts,
						'code'     => self::REASON_ABORTED_STUCK_NO_PROGRESS,
					)
				);
				self::terminate( self::REASON_ABORTED_STUCK_NO_PROGRESS );
				$tick_outcome = 'attempt_abort';
				return;
			}

			// Malware-only: drain CTI batches at full throughput while the
			// chunk loop is hot. Reset on every exit path.
			if ( $is_malware ) {
				add_filter( 'segurium_scan_verdict_single_batch', '__return_false' );
			}

			$budget                   = (float) apply_filters( 'segurium_scan_tick_budget', self::tick_budget() );
			$started                  = microtime( true );
			self::$tick_started_at    = $started;
			self::$tick_budget_active = $budget;
			$chunks_returned          = 0;
			$completed                = false;
			$cancel_observed          = false;

			self::debug(
				'chunk_loop_start',
				array(
					'scan_id' => $scan_id,
					'budget'  => $budget,
					'safety'  => self::TICK_GRACEFUL_EXIT_SAFETY_SEC,
				)
			);

			try {
				while ( true ) {
					$elapsed   = microtime( true ) - $started;
					$time_left = $budget - $elapsed;
					if ( $time_left <= self::TICK_GRACEFUL_EXIT_SAFETY_SEC ) {
						self::debug(
							'pre_chunk_break',
							array(
								'scan_id'   => $scan_id,
								'time_left' => $time_left,
								'safety'    => self::TICK_GRACEFUL_EXIT_SAFETY_SEC,
								'chunks'    => $chunks_returned,
							)
						);
						break;
					}

					// SEGURIUM-414: cooperative cancel poll. `terminate()`
					// writes `scan_cancel:<scan_id>` to runtime_kv when a
					// worker is mid-tick instead of running the workspace
					// teardown itself (the SIGSEGV race). Observing the flag
					// here is what closes the loop — we exit, run cleanup
					// from the only process still holding the workspace, and
					// clear the flag.
					if ( self::cancel_flag_set( $scan_id ) ) {
						self::debug(
							'chunk_loop_observed_cancel',
							array(
								'scan_id' => $scan_id,
								'chunks'  => $chunks_returned,
							)
						);
						$cancel_observed = true;
						break;
					}

					self::debug(
						'chunk_start',
						array(
							'scan_id'   => $scan_id,
							'time_left' => $time_left,
							'chunk_idx' => $chunks_returned,
						)
					);

					$chunk_t0 = microtime( true );
					try {
						$result = $engine->process_chunk();
					} catch ( Throwable $chunk_exc ) {
						self::debug(
							'chunk_threw',
							array(
								'scan_id' => $scan_id,
								'wall_ms' => ( microtime( true ) - $chunk_t0 ) * 1000.0,
								'class'   => get_class( $chunk_exc ),
								'message' => $chunk_exc->getMessage(),
							)
						);
						// Surface to the outer life_support_system catch so the
						// existing logging / next-tick-rearm path runs. The
						// attempt counter is left at its incremented value
						// because we did not reach reset_stuck_counter.
						throw $chunk_exc; // phpcs:ignore Squiz.Commenting.FunctionCommentThrowTag.Missing -- caught by the outer try/catch in this method
					}

					++$chunks_returned;

					if ( ! self::renew_liveness( $scan_id, $is_observer ) ) {
						// SEGURIUM-870: the lease lapsed during the chunk and
						// another driver owns the scan now. Leave without
						// finalize / release; the token guard in the outer
						// finally keeps the new owner's row intact.
						$tick_outcome = 'lease_lost';
						return;
					}
					self::reset_stuck_counter( $scan_id );

					self::debug(
						'chunk_returned',
						array(
							'scan_id'   => $scan_id,
							'wall_ms'   => ( microtime( true ) - $chunk_t0 ) * 1000.0,
							'completed' => ! empty( $result['completed'] ),
							'time_left' => self::time_left_in_tick(),
							'chunk_idx' => $chunks_returned,
						)
					);

					// SEGURIUM-481: Phase B — drain `/v1/scan/results`
					// in the same tick. Only the malware-scan path
					// submits to CTI's async pipeline, so the integrity
					// scan type stays out of this branch entirely.
					if ( $is_malware && class_exists( 'Segurium_Async_Scan_Results_Loop' ) ) {
						Segurium_Async_Scan_Results_Loop::run( $scan_id );
					}

					// SEGURIUM-917: the submitter flags a scan whose link
					// refused a batch at the floor ceiling. Terminate from
					// here, ahead of the completion branch, so an aborted
					// scan never fires `segurium_scan_completed`.
					if ( $is_malware && class_exists( 'Segurium_Async_Scan_Submitter' )
						&& Segurium_Async_Scan_Submitter::floor_reached_for( $scan_id ) ) {
						self::debug(
							'upload_capacity_abort',
							array(
								'scan_id' => $scan_id,
								'chunks'  => $chunks_returned,
								'code'    => self::REASON_ABORTED_UPLOAD_CAPACITY,
							)
						);
						self::terminate( self::REASON_ABORTED_UPLOAD_CAPACITY, $scan_id );
						$tick_outcome = 'upload_capacity_abort';
						return;
					}

					if ( ! empty( $result['completed'] ) ) {
						$completed = true;
						break;
					}

					// SEGURIUM-578: the head verdict batch is parked in a
					// transient-inspect backoff window (a 5xx/timeout that
					// will be retried on a later tick). There is nothing to
					// drain until it is due, so end the tick gracefully
					// rather than busy-spinning the budget re-polling a chunk
					// that cannot run yet. The async results loop above
					// already ran once this tick, the heartbeat + stuck
					// counter were reset on chunk return, and the graceful-
					// handoff path below self-triggers the next tick
					// (~MIN_TICK_WALL_SEC later) — the cadence at which the
					// backoff window is re-checked.
					if ( ! empty( $result['inspect_backoff'] ) ) {
						self::debug(
							'inspect_backoff_yield',
							array(
								'scan_id' => $scan_id,
								'chunks'  => $chunks_returned,
							)
						);
						break;
					}
				}

				if ( $completed ) {
					self::debug(
						'tick_complete_scan',
						array(
							'scan_id' => $scan_id,
							'chunks'  => $chunks_returned,
						)
					);
					self::renew_liveness( $scan_id, $is_observer );
					self::finalize_scan( $engine, $scan_type );
					Segurium_Scan_Lock::release();
					self::clear_stuck_state( $scan_id );
					wp_clear_scheduled_hook( self::TICK_HOOK );
					$tick_outcome = 'completed';
					return;
				}

				// SEGURIUM-414: worker-side cooperative cancel. Lock + tick
				// hook were already released by the parallel `terminate()`;
				// our job here is the workspace + runtime_kv teardown that
				// `terminate()` deferred to avoid the SIGSEGV race. The
				// second clause covers the narrow race where `terminate()`
				// set the flag after the chunk loop ended but before the
				// outer finally released the mutex — we are still the only
				// process holding the workspace, so run cleanup from here.
				if ( $cancel_observed || self::cancel_flag_set( $scan_id ) ) {
					try {
						$engine->cleanup_state();
					} catch ( Throwable $cleanup_exc ) {
						self::log_exception( 'cancel_cleanup', $cleanup_exc );
					}
					self::clear_cancel_flag( $scan_id );
					self::clear_stuck_state( $scan_id );
					$tick_outcome = 'cancel_observed';
					return;
				}

				// SEGURIUM-511: fire on every non-terminal tick exit;
				// MIN_TICK_WALL_SEC floor caps dispatch rate. The mutex
				// is released BEFORE firing so the receiving worker can
				// acquire it (outer finally is idempotent).
				$min_wall = (float) apply_filters(
					'segurium_scan_min_tick_wall_sec',
					self::MIN_TICK_WALL_SEC
				);
				$wall     = microtime( true ) - $started;
				if ( $wall < $min_wall ) {
					usleep( (int) ( ( $min_wall - $wall ) * 1e6 ) );
					$wall = microtime( true ) - $started;
				}
				self::debug(
					'graceful_exit_handoff',
					array(
						'scan_id'  => $scan_id,
						'chunks'   => $chunks_returned,
						'wall_ms'  => $wall * 1000.0,
						'floor_ms' => $min_wall * 1000.0,
					)
				);
				self::release_tick_mutex( $mutex_token );
				$mutex_token  = '';
				$fire_outcome = self::fire_self_trigger();
				self::debug(
					'graceful_exit_self_trigger',
					array(
						'scan_id' => $scan_id,
						'outcome' => $fire_outcome,
					)
				);
				$tick_outcome = 'graceful_handoff';
			} finally {
				if ( $is_malware ) {
					remove_filter( 'segurium_scan_verdict_single_batch', '__return_false' );
				}
				self::$tick_started_at    = 0.0;
				self::$tick_budget_active = 0.0;
			}
		} catch ( Throwable $e ) {
			self::log_exception( 'life_support_system:' . $caller, $e );
			$tick_outcome = 'threw';
			try {
				if ( null !== Segurium_Scan_Lock::get() ) {
					self::schedule_next_tick();
				}
			} catch ( Throwable $ignored ) {
				unset( $ignored );
			}
		} finally {
			if ( '' !== (string) $mutex_token ) {
				self::release_tick_mutex( $mutex_token );
			}
			self::debug(
				'tick_exit',
				array(
					'caller'  => $caller,
					'scan_id' => $scan_id_for_exit,
					'outcome' => $tick_outcome,
					'wall_ms' => ( microtime( true ) - $tick_wall_start ) * 1000.0,
				)
			);
		}
	}

	/**
	 * Wall-time remaining (seconds) inside the current tick's chunk loop.
	 * Returned as a float; the safety margin is NOT subtracted, so the
	 * engine layer can decide its own pre-call discipline (e.g.,
	 * `min(known_max_call_time, time_left_in_tick() - safety)` for an HTTP
	 * timeout). Returns 0.0 when called outside a tick.
	 *
	 * @return float
	 */
	public static function time_left_in_tick() {
		if ( self::$tick_started_at <= 0.0 ) {
			return 0.0;
		}
		$remaining = self::$tick_budget_active - ( microtime( true ) - self::$tick_started_at );
		return $remaining > 0.0 ? $remaining : 0.0;
	}

	/**
	 * SEGURIUM-745: whether a tick is currently driving the chunk loop.
	 *
	 * `time_left_in_tick()` clamps to 0.0, so on its own it cannot separate
	 * "no tick is running" from "the tick already overran its budget" — and
	 * those two want opposite treatment from a caller sizing an HTTP timeout.
	 * Outside a tick there is no budget to respect; inside an overrun one the
	 * caller must take the smallest window it can, not the most generous.
	 *
	 * @return bool
	 */
	public static function in_tick() {
		return self::$tick_started_at > 0.0;
	}

	/**
	 * Effective wall-clock budget per worker invocation, in seconds.
	 *
	 * SEGURIUM-250: removed the previous 60s ceiling so hosts with generous
	 * `max_execution_time` (300s+) can drive long chunk loops in a single
	 * tick. The plugin still must not call `set_time_limit()` (forbidden
	 * by wp.org plugin-check, ignored on LiteSpeed lsphp / mod_security
	 * setups anyway), so the budget cooperates with the host limit.
	 *
	 * @return float
	 */
	public static function tick_budget() {
		$max = self::max_execution_time();
		if ( $max <= 0 ) {
			return (float) self::TICK_BUDGET_UNLIMITED_SEC;
		}
		$budget = $max - self::TICK_BUDGET_SAFETY_SEC;
		if ( $budget < self::TICK_BUDGET_MIN_SEC ) {
			return (float) self::TICK_BUDGET_MIN_SEC;
		}
		return (float) $budget;
	}

	/**
	 * Detect host-environment conditions that prevent reliable scanning.
	 *
	 * @return string[]
	 */
	public static function environment_warnings() {
		$warnings = array();

		$max = self::max_execution_time();
		if ( $max > 0 && $max < 15 ) {
			$warnings[] = sprintf(
				/* translators: %d: max_execution_time in seconds */
				__( 'PHP max_execution_time is %ds — too short for reliable scanning. Ask your host to raise it to at least 30s.', 'segurium' ),
				$max
			);
		}

		$has_detach = function_exists( 'fastcgi_finish_request' )
			|| function_exists( 'litespeed_finish_request' );
		$cron_off   = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		if ( $cron_off && ! $has_detach ) {
			// Worst-case: WP-cron disabled AND no way to detach from a
			// pageload. Scans only progress while an admin browser polls.
			$warnings[] = __( 'WordPress cron is disabled (DISABLE_WP_CRON) and your PHP setup has no way to detach long tasks from page requests. Background scans will only progress while a Segurium admin tab stays open. Ask your host to either enable a real system cron job hitting wp-cron.php every minute, or to switch from mod_php to PHP-FPM / LiteSpeed.', 'segurium' );
		} elseif ( $cron_off ) {
			$warnings[] = __( 'WordPress cron is disabled (DISABLE_WP_CRON). Scheduled scans depend on a real system cron job hitting wp-cron.php every minute. Ask your host to set one up.', 'segurium' );
		}

		return $warnings;
	}

	/**
	 * Ensure the recurring scan tick is armed.
	 *
	 * SEGURIUM-419 replaced the per-tick lookahead schedule with a recurring
	 * wp-cron event seeded once at scan start (5s originally, slowed to 60s
	 * by SEGURIUM-425 — the self-trigger drives the chain between beats and
	 * cron is the rescue path). This helper is
	 * idempotent: when the recurring tick is already scheduled it returns
	 * without touching the cron array; otherwise it (re-)installs it. Used
	 * both at scan start and from the catch handler in life_support_system()
	 * so the chain self-heals if anything ever drops the recurring entry.
	 *
	 * @return void
	 */
	private static function schedule_next_tick() {
		if ( wp_next_scheduled( self::TICK_HOOK ) ) {
			return;
		}
		wp_schedule_event( time(), self::TICK_RECURRING_SCHEDULE, self::TICK_HOOK );
	}

	/**
	 * Mechanism V (SEGURIUM-421): self-trigger to the dedicated
	 * `/wp-json/segurium/v1/scan-spawn` route so a fresh PHP worker picks up
	 * the next chunk without waiting for the cron rescue beat.
	 *
	 * SEGURIUM-425: blocking POST with a {@see SELF_TRIGGER_TIMEOUT_SEC}
	 * timeout — was previously fire-and-forget with a fsockopen fallback
	 * that ran in parallel whenever wp_remote_post() took >0.2s, which
	 * doubled the dispatch rate on every WAF-fronted host (the WAF holds
	 * the connection past the threshold; both transports fire). The new
	 * contract:
	 *
	 *   1. `wp_remote_post()` blocking, 1 s hard timeout.
	 *   2. ANY HTTP response (2xx/4xx/5xx, including 508 Loop Detected and
	 *      WAF-challenge HTML) is treated as "delivered" — we do not retry.
	 *      The receiver may have bounced off the mutex; that is the chain's
	 *      problem, not ours.
	 *   3. `WP_Error` whose message indicates a timeout (cURL error 28 /
	 *      stream "timed out" / "Connection timed out") is also treated as
	 *      delivered — the host saw the bytes, it just didn't reply in
	 *      time. We return 'failed' for telemetry but do NOT retry via
	 *      fsockopen (that retry would just timeout again and double the
	 *      load on whatever upstream is sitting on the request).
	 *   4. `WP_Error` with any other message (DNS failure, connect refused,
	 *      TLS handshake failure) means the request never got off the box.
	 *      Fall through to a raw fsockopen + HTTP/1.1 POST + immediate
	 *      close as a transport-level rescue.
	 *
	 * Caller must release `TICK_MUTEX_TRANSIENT` BEFORE this fires — the
	 * receiving worker takes the same mutex and would skip otherwise.
	 *
	 * @return string One of: 'wp_remote', 'fallback', 'failed'. Returned
	 *                for testability + debug logging; the chunk handler
	 *                ignores the value.
	 */
	public static function fire_self_trigger() {
		$url    = rest_url( Segurium_Rest_Scan_Spawn::route_path() );
		$secret = self::self_trigger_secret();

		$resp = wp_remote_post(
			$url,
			array(
				'blocking'  => true,
				'timeout'   => self::SELF_TRIGGER_TIMEOUT_SEC,
				'sslverify' => false,
				'headers'   => array(
					'Content-Type' => 'application/json',
					Segurium_Scan_Trigger_Auth::HEADER_SECRET => $secret,
				),
				'body'      => '',
			)
		);

		if ( ! is_wp_error( $resp ) ) {
			return 'wp_remote';
		}

		if ( self::is_wp_remote_post_timeout( $resp ) ) {
			return 'failed';
		}

		$fallback_ok = self::fire_self_trigger_via_socket( $url );
		return $fallback_ok ? 'fallback' : 'failed';
	}

	/**
	 * Per-site shared secret proving the self-trigger POST came from this
	 * site (SEGURIUM-607). The scan-spawn route's permission_callback
	 * compares the `X-Segurium-Tick-Auth` header against the same option.
	 * Returns '' only when no CSPRNG is available, in which case the
	 * self-trigger degrades to the cron / pageload fallback.
	 *
	 * @return string
	 */
	private static function self_trigger_secret() {
		if ( class_exists( 'Segurium_Scan_Trigger_Auth' ) ) {
			return Segurium_Scan_Trigger_Auth::secret();
		}
		return '';
	}

	/**
	 * Best-effort timeout detection on a `WP_Error` returned by
	 * `wp_remote_post()`. WordPress doesn't expose a structured timeout
	 * code — every transport-layer failure shares `'http_request_failed'`
	 * — so we substring-match the message against the strings cURL and
	 * the Streams transport produce on connect/read timeout. Conservative:
	 * a non-timeout that happens to mention "timeout" in its message is
	 * still classified as a timeout (we err on the side of "do not
	 * retry"), which is the opposite of the failure mode this helper
	 * exists to prevent. SEGURIUM-425.
	 *
	 * @param WP_Error $err Error returned by the primary self-trigger.
	 * @return bool True if the message looks like a timeout.
	 */
	private static function is_wp_remote_post_timeout( $err ) {
		if ( ! is_wp_error( $err ) ) {
			return false;
		}
		$message = strtolower( (string) $err->get_error_message() );
		if ( '' === $message ) {
			return false;
		}
		if ( false !== strpos( $message, 'timed out' ) ) {
			return true;
		}
		if ( false !== strpos( $message, 'timeout was reached' ) ) {
			return true;
		}
		if ( false !== strpos( $message, 'curl error 28' ) ) {
			return true;
		}
		if ( false !== strpos( $message, 'operation timeout' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Mechanism V fallback transport: open a raw socket, write a minimal
	 * HTTP/1.1 POST, close. Used when `wp_remote_post()` errors or stalls.
	 *
	 * Tests can inject a deterministic outcome via the
	 * `segurium_scan_spawn_socket_override` filter (return null to use the
	 * real fsockopen, or true/false to short-circuit). SEGURIUM-421.
	 *
	 * @param string $url Full URL of the target route.
	 * @return bool True if the request was written; false on parse / open / write failure.
	 */
	private static function fire_self_trigger_via_socket( $url ) {
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return false;
		}
		$scheme = isset( $parts['scheme'] ) ? (string) $parts['scheme'] : 'http';
		$host   = (string) $parts['host'];
		$port   = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
		$path   = isset( $parts['path'] ) ? (string) $parts['path'] : '/';
		if ( isset( $parts['query'] ) && '' !== $parts['query'] ) {
			$path .= '?' . $parts['query'];
		}

		$override = apply_filters( 'segurium_scan_spawn_socket_override', null, $host, $port, $url );
		if ( null !== $override ) {
			return (bool) $override;
		}

		$transport = ( 'https' === $scheme ) ? 'ssl://' . $host : $host;
		$errno     = 0;
		$errstr    = '';
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fsockopen -- network socket, not a filesystem op; WP_Filesystem cannot speak HTTP.
		$fp = @fsockopen( $transport, $port, $errno, $errstr, self::SELF_TRIGGER_SOCKET_CONNECT_TIMEOUT_SEC );
		if ( ! $fp ) {
			return false;
		}
		stream_set_timeout( $fp, 0, 100000 );

		$secret = self::self_trigger_secret();
		$req    = "POST {$path} HTTP/1.1\r\n";
		$req   .= "Host: {$host}\r\n";
		$req   .= "Content-Type: application/json\r\n";
		if ( '' !== $secret ) {
			$req .= Segurium_Scan_Trigger_Auth::HEADER_SECRET . ": {$secret}\r\n";
		}
		$req .= "Content-Length: 0\r\n";
		$req .= "Connection: close\r\n\r\n";
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- network socket write; fire-and-forget, receiver may close before our write completes.
		$written = @fwrite( $fp, $req );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- network socket close.
		@fclose( $fp );
		return false !== $written;
	}

	/**
	 * Cheap "is a browser observer currently driving the runner?" check used
	 * by the cron and pageload entry hooks. Reads the lock option once
	 * (in-request memoized by WordPress's options cache after the first hit
	 * within a request) and compares `observer_last_seen` against the
	 * `OBSERVER_FRESH_SEC` window. Returns false when no scan is running, no
	 * observer has ever been seen, or the last observer ping is older than
	 * the freshness window. SEGURIUM-271.
	 *
	 * @return bool
	 */
	private static function observer_is_active() {
		$lock = Segurium_Scan_Lock::get();
		if ( null === $lock ) {
			return false;
		}
		$seen = (int) $lock['observer_last_seen'];
		if ( $seen <= 0 ) {
			return false;
		}
		return ( time() - $seen ) <= self::OBSERVER_FRESH_SEC;
	}

	/**
	 * Cheap "is there work to do?" check used by the pageload trigger so
	 * pageloads on idle sites cost nothing.
	 *
	 * @return bool
	 */
	private static function has_work() {
		if ( null !== Segurium_Scan_Lock::get() ) {
			return true;
		}
		if ( class_exists( 'Segurium_Scheduled_Scan' ) ) {
			$next = wp_next_scheduled( Segurium_Scheduled_Scan::CRON_HOOK );
			if ( $next && $next + self::SCHEDULED_OVERDUE_TOLERANCE_SEC <= time() ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Start an overdue scheduled scan inline if one is waiting. Returns
	 * whether a scan was started. Called from inside life_support_system()
	 * step 3 so cron-broken hosts still honor the schedule when admin /
	 * visitor traffic arrives.
	 *
	 * @return bool
	 */
	private static function maybe_start_overdue_scheduled_scan() {
		if ( ! class_exists( 'Segurium_Scheduled_Scan' ) ) {
			return false;
		}
		$next = wp_next_scheduled( Segurium_Scheduled_Scan::CRON_HOOK );
		if ( ! $next || $next + self::SCHEDULED_OVERDUE_TOLERANCE_SEC > time() ) {
			return false;
		}
		try {
			Segurium_Scheduled_Scan::run();
		} catch ( Throwable $e ) {
			self::log_exception( 'maybe_start_overdue_scheduled_scan', $e );
			return false;
		}
		return null !== Segurium_Scan_Lock::get();
	}

	/**
	 * Current scan_history status for $scan_id, or '' when there is no row
	 * (integrity scans) or the lookup fails. SEGURIUM-572.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return string
	 */
	private static function scan_history_status( $scan_id ) {
		if ( '' === (string) $scan_id ) {
			return '';
		}
		try {
			return (string) Segurium_Storage::table_get_var(
				'scan_history',
				'SELECT status FROM {{table}} WHERE scan_uuid = %s',
				array( (string) $scan_id )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-scan-runner] scan_history_status lookup failed: ' . $e->getMessage() );
			return '';
		}
	}

	/**
	 * Whether the scan_history row for $scan_id is in a terminal state.
	 *
	 * Integrity scans do not write a scan_history row, so a missing/empty
	 * status reads as non-terminal and the normal tick path runs. On a storage
	 * error scan_history_status() also returns '', which is non-terminal: a
	 * transient DB blip must never strand a live scan by gating it out.
	 * SEGURIUM-572.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return bool
	 */
	private static function scan_history_is_terminal( $scan_id ) {
		return in_array( self::scan_history_status( $scan_id ), self::TERMINAL_STATUSES, true );
	}

	/**
	 * Finalize a completed scan by firing the appropriate action for the
	 * engine type so listeners can persist results and update server state.
	 *
	 * @param object $engine    Completed scan engine instance.
	 * @param string $scan_type Lock scan_type value.
	 * @return void
	 */
	private static function finalize_scan( $engine, $scan_type ) {
		if ( 'integrity' === $scan_type ) {
			/**
			 * Fires when an integrity scan completes inside the runner.
			 *
			 * @param Segurium_Integrity_Scan_State $engine Completed engine.
			 */
			do_action( 'segurium_integrity_scan_completed', $engine );
		} else {
			// SEGURIUM-572: emit the terminal scan_completed (idempotent) on the
			// same path that releases the lock, and before the
			// `segurium_scan_completed` listener's cleanup tears down the verdict
			// queue this payload is built from.
			if ( $engine instanceof Segurium_Scan ) {
				$engine->emit_terminal_completion();
			}
			/**
			 * Fires when a malware scan completes inside the runner.
			 *
			 * @param Segurium_Scan $engine Completed scan instance.
			 */
			do_action( 'segurium_scan_completed', $engine );
		}
	}

	/**
	 * Increment the per-scan attempt counter and return the new value.
	 * SEGURIUM-252 reframed this as an attempt counter: incremented at tick
	 * entry, reset as soon as any process_chunk() call returns successfully.
	 * Killed-mid-chunk ticks therefore persist the counter into the next
	 * tick, and STUCK_MAX consecutive killed ticks abort the scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return int
	 */
	private static function increment_stuck_counter( $scan_id ) {
		$key   = self::STUCK_COUNTER_KV_PREFIX . $scan_id;
		$value = (int) Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $key )
		);
		++$value;
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $key,
				'kv_value'   => (string) $value,
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);
		return $value;
	}

	/**
	 * Reset the per-scan attempt counter. Called on every successful
	 * process_chunk() return inside the chunk loop.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	private static function reset_stuck_counter( $scan_id ) {
		Segurium_Storage::table_delete(
			'runtime_kv',
			array( 'kv_key' => self::STUCK_COUNTER_KV_PREFIX . $scan_id )
		);
	}

	/**
	 * Drop the attempt counter for a scan. Called on scan start (fresh
	 * slate), completion, abort, and cancellation so stale state never
	 * leaks into the next scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	private static function clear_stuck_state( $scan_id ) {
		Segurium_Storage::table_delete(
			'runtime_kv',
			array( 'kv_key' => self::STUCK_COUNTER_KV_PREFIX . $scan_id )
		);
	}

	/**
	 * Detach the current PHP request from the client connection so the
	 * worker can keep running without holding the user's browser. Returns
	 * whether detachment succeeded — bare mod_php has no portable
	 * equivalent so the caller skips on false.
	 *
	 * @return bool
	 */
	private static function detach_response() {
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			@fastcgi_finish_request(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort detach
			return true;
		}
		if ( function_exists( 'litespeed_finish_request' ) ) {
			@litespeed_finish_request(); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort detach
			return true;
		}
		return false;
	}

	/**
	 * Resolve the active host max_execution_time as an int. CLI / mod_php
	 * with no limit returns 0, which the budget / throttle logic treats
	 * as "unlimited".
	 *
	 * @return int
	 */
	private static function max_execution_time() {
		return (int) ini_get( 'max_execution_time' );
	}

	/**
	 * Scan-tick mutex lease TTL: always `HEARTBEAT_MAX_AGE`, so a dead
	 * worker's row expires the moment its heartbeat reads as dead
	 * (SEGURIUM-870). The lease is renewed per file / chunk / results
	 * iteration, so it only has to outlive one gap between renewals.
	 * `$max_exec` stays for signature stability and is ignored; see
	 * docs/features/scan-runner-recurring-tick.md for the history.
	 *
	 * @param mixed $max_exec Raw `ini_get('max_execution_time')` value (ignored).
	 * @return int Mutex TTL in seconds.
	 */
	public static function compute_mutex_ttl( $max_exec ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- kept for signature stability.
		return Segurium_Scan_Lock::HEARTBEAT_MAX_AGE;
	}

	/**
	 * Create the scan engine for the given type.
	 *
	 * Tests may inject an engine via the `segurium_runner_test_scan` filter
	 * (malware) or `segurium_runner_test_integrity_engine` filter (integrity).
	 *
	 * @param string $scan_type Scan type ('manual', 'scheduled', 'integrity', …).
	 * @return Segurium_Scan|Segurium_Integrity_Scan_State
	 */
	private static function create_engine( $scan_type = '' ) {
		if ( 'integrity' === $scan_type ) {
			$filtered = apply_filters( 'segurium_runner_test_integrity_engine', null );
			if ( is_object( $filtered ) ) {
				return $filtered;
			}
			return Segurium::get_instance()->build_integrity_scan_for_runner();
		}

		$filtered = apply_filters( 'segurium_runner_test_scan', null );
		if ( is_object( $filtered ) ) {
			return $filtered;
		}
		return Segurium::get_instance()->build_scan_for_runner();
	}
}

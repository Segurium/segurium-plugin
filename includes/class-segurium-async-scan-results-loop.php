<?php
/**
 * Phase B — in-tick `/v1/scan/results` poll loop.
 *
 * SEGURIUM-481: replaces the WP-Cron-driven
 * `Segurium_Async_Scan_Poller`. Polling now runs from
 * `Segurium_Scan_Runner::run_chunk` after each chunk so verdicts land
 * during the same tick that submitted them, capped by the existing
 * scan-tick budget instead of the 60 s cron cadence.
 *
 * Per `docs/features/async-submit-concurrency.md` §4 Phase B + §8.
 *
 * Each `run()` call iterates while
 *   - the IID-scoped results pause (`Segurium_Async_Scan_Pause::ENDPOINT_RESULTS`)
 *     is clear, AND
 *   - the active scan's first-poll ETA has elapsed
 *     ({@see Segurium_Async_Scan_First_Poll_Eta::is_eligible_to_poll()}), AND
 *   - the tick has budget (caller-supplied callback, defaulting to
 *     {@see Segurium_Scan_Runner::time_left_in_tick()}), AND
 *   - `iter < segurium_scan_poll_max_iters_per_tick` (default 8), AND
 *   - there is still unresolved work for the active scan.
 *
 * On `Retry-After` (429 / 503) the IID-scoped results pause is stamped
 * and the loop breaks. On an empty results page the cursor is advanced
 * and the loop breaks until the next tick.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * In-tick driver for `/v1/scan/results`.
 */
class Segurium_Async_Scan_Results_Loop {

	/**
	 * Retired global cursor option. Kept only so the one-shot
	 * {@see migrate_drop_legacy_cursor()} can locate it on upgrade.
	 */
	const OPTION_CURSOR = 'segurium_async_scan_cursor';

	/**
	 * One-shot migration sentinel for the legacy global cursor cleanup.
	 */
	const MIGRATION_FLAG_510 = 'segurium_migrated_510_drop_legacy_cursor';

	/**
	 * One-shot migration sentinel for the SEGURIUM-576 purge of the legacy
	 * `async_scan:pending:*` runtime_kv JSON blobs (superseded by the
	 * `async_pending` table). Clears the orphaned blobs left behind by scans
	 * that ran before the table existed.
	 */
	const MIGRATION_FLAG_576 = 'segurium_migrated_576_purge_pending_blobs';

	/**
	 * `wp_option` key holding the upper bound on Phase B loop
	 * iterations per scan tick.
	 */
	const OPTION_MAX_ITERS_PER_TICK = 'segurium_scan_poll_max_iters_per_tick';

	/**
	 * Default iteration cap when the option is unset.
	 */
	const DEFAULT_MAX_ITERS_PER_TICK = 8;

	/**
	 * Hard ceiling — a runaway "always more" CTI response must not be
	 * able to drive arbitrary iteration counts even if the option is
	 * set to a pathological value.
	 */
	const HARD_CAP_MAX_ITERS = 64;

	/**
	 * Soft minimum tick-budget remaining before we will start a fresh
	 * iteration. One full second covers the slowest expected
	 * `wp_remote_get` + JSON decode against a healthy CTI.
	 */
	const MIN_BUDGET_PER_ITER_SECS = 1.0;

	/**
	 * One-shot migration flag for the legacy poller's WP-Cron event +
	 * rate-limit transient. See {@see migrate_unschedule_legacy_cron()}.
	 */
	const MIGRATION_FLAG_OPTION = 'segurium_migrated_481_remove_poller_cron';

	/**
	 * Legacy WP-Cron hook name installed by the now-removed
	 * `Segurium_Async_Scan_Poller`. Migration unschedules it.
	 */
	const LEGACY_CRON_HOOK = 'segurium_async_scan_poll';

	/**
	 * Legacy `cron_schedules` key registered by the old poller. Migration
	 * does not remove the key from the filter (no API for that) but
	 * unschedules every event that used it.
	 */
	const LEGACY_CRON_SCHEDULE = 'segurium_async_scan_poll_interval';

	/**
	 * Legacy rate-gate transient. Migration deletes it so no stale row
	 * lingers in the options table.
	 */
	const LEGACY_RATE_TRANSIENT = 'segurium_async_scan_poll_rate';

	/**
	 * Max results pulled in one HTTP call. Server clamps to 500; we
	 * ask for 500 so a backlog drains in fewer round-trips.
	 */
	const POLL_LIMIT = 500;

	/**
	 * SEGURIUM-564: runtime_kv key prefix for the per-scan "submission
	 * sealed" flag. The scan engine sets it once listing is done and
	 * every Unknown has been handed to the submitter; the results loop
	 * reads it to know that no further hashes will ever be submitted, so
	 * a CTI `queue_depth == 0` on an empty results page is final.
	 */
	const SEAL_KV_PREFIX = 'async_scan:submit_sealed:';

	/**
	 * SEGURIUM-573: runtime_kv key prefix for the per-scan results cursor.
	 * Stored in its OWN key — NOT inside the pending-paths row — so the
	 * submit path (which rewrites the whole pending row) can never clobber
	 * the drain's advance, and draining every path (which deletes the
	 * pending row) can never destroy the cursor. Written only by the drain
	 * via {@see cursor_set()}; dropped on scan teardown via
	 * {@see clear_cursor()}. The `expires_at` stamp mirrors the sibling
	 * pending/seal rows (24 h) so an orphaned key from an abnormally-ended
	 * scan is bounded and harmless — a fresh-UUID scan never reads it back.
	 */
	const CURSOR_KV_PREFIX = 'async_scan:cursor:';

	/**
	 * CTI client used for outbound calls. Lazy-constructed so tests can
	 * inject a mock via {@see set_cti_client_for_tests()}.
	 *
	 * @var Segurium_CTI_Client|null
	 */
	private static $cti = null;

	/**
	 * Register the one-shot migration that retires the legacy WP-Cron
	 * driver. Safe to call multiple times.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'plugins_loaded', array( __CLASS__, 'migrate_unschedule_legacy_cron' ), 11 );
		add_action( 'plugins_loaded', array( __CLASS__, 'migrate_drop_legacy_cursor' ), 11 );
		add_action( 'plugins_loaded', array( __CLASS__, 'migrate_purge_legacy_pending_blobs' ), 11 );
	}

	/**
	 * Resolve the configured iter cap, clamped to a sane range.
	 *
	 * @return int
	 */
	public static function max_iters_per_tick() {
		$raw = (int) Segurium_Storage::setting_get( self::OPTION_MAX_ITERS_PER_TICK, self::DEFAULT_MAX_ITERS_PER_TICK );
		if ( $raw < 1 ) {
			return self::DEFAULT_MAX_ITERS_PER_TICK;
		}
		if ( $raw > self::HARD_CAP_MAX_ITERS ) {
			return self::HARD_CAP_MAX_ITERS;
		}
		return $raw;
	}

	/**
	 * Drive a Phase B iteration loop for one scan tick.
	 *
	 * @param string                   $scan_id        Active scan UUID. Empty string
	 *                                                 disables the per-scan first-poll
	 *                                                 ETA gate and the per-scan
	 *                                                 unresolved-count gate (used by
	 *                                                 tests / migration paths that want
	 *                                                 to drive the loop without an
	 *                                                 active scan context).
	 * @param Segurium_CTI_Client|null $cti            CTI client; defaults to a fresh
	 *                                                 instance.
	 * @param callable|null            $budget_check   Returns `true` while the tick
	 *                                                 still has budget. Defaults to
	 *                                                 `Segurium_Scan_Runner::time_left_in_tick()
	 *                                                  >= self::MIN_BUDGET_PER_ITER_SECS`.
	 * @return int Number of verdict rows applied this loop.
	 */
	public static function run( $scan_id = '', $cti = null, $budget_check = null ) {
		$scan_id      = (string) $scan_id;
		$cti          = $cti instanceof Segurium_CTI_Client ? $cti : self::get_cti();
		$budget_check = is_callable( $budget_check ) ? $budget_check : array( __CLASS__, 'default_budget_check' );

		$applied   = 0;
		$max_iters = self::max_iters_per_tick();
		$cursor    = self::cursor_get( $scan_id );
		$since     = (int) $cursor['next_seq'];

		for ( $iter = 0; $iter < $max_iters; $iter++ ) {
			if ( ! (bool) call_user_func( $budget_check ) ) {
				break;
			}
			if ( Segurium_Async_Scan_Pause::is_paused( Segurium_Async_Scan_Pause::ENDPOINT_RESULTS ) ) {
				break;
			}
			if ( '' !== $scan_id && ! Segurium_Async_Scan_First_Poll_Eta::is_eligible_to_poll( $scan_id ) ) {
				Segurium_Scan_Runner::debug(
					'scan_poll_first_wait',
					array(
						'eligible_at_unix' => Segurium_Async_Scan_First_Poll_Eta::get( $scan_id ),
						'eta_files'        => Segurium_Async_Scan_First_Poll_Eta::get_eta_files( $scan_id ),
						'eta_ms_per_file'  => Segurium_Async_Scan_First_Poll_Eta::avg_ms_per_file(),
					)
				);
				break;
			}
			if ( '' !== $scan_id && self::unresolved_count( $scan_id ) <= 0 ) {
				break;
			}

			// SEGURIUM-870: heartbeat + lease before each CTI call; a lost
			// lease means another driver owns the scan now.
			if ( class_exists( 'Segurium_Scan_Runner' ) && ! Segurium_Scan_Runner::renew_liveness( $scan_id ) ) {
				break;
			}

			$cursor_before = $since;
			$resp          = $cti->scan_results( $since, $scan_id, self::POLL_LIMIT );
			if ( is_wp_error( $resp ) ) {
				if ( 'cti_paused' === $resp->get_error_code() ) {
					$data        = $resp->get_error_data();
					$retry_after = is_array( $data ) && isset( $data['retry_after'] ) ? (int) $data['retry_after'] : 0;
					if ( $retry_after > 0 ) {
						// SEGURIUM-483: the `scan_submit_pause` event
						// is emitted from
						// {@see Segurium_CTI_Client::pause_error()} —
						// we only stamp the transient here.
						Segurium_Async_Scan_Pause::set_pause(
							Segurium_Async_Scan_Pause::ENDPOINT_RESULTS,
							$retry_after
						);
					}
				}
				break;
			}
			if ( ! is_array( $resp ) ) {
				break;
			}

			$results      = isset( $resp['results'] ) && is_array( $resp['results'] ) ? $resp['results'] : array();
			$cursor_after = isset( $resp['next_seq'] ) ? (int) $resp['next_seq'] : $cursor_before;
			Segurium_Scan_Runner::debug(
				'scan_poll_iter',
				array(
					'new_results'   => count( $results ),
					'cursor_before' => $cursor_before,
					'cursor_after'  => $cursor_after,
				)
			);
			if ( empty( $results ) ) {
				self::cursor_set( $scan_id, $cursor_after );
				// SEGURIUM-564: caught up to the server high-water. If CTI
				// reports nothing more is queued for this scan
				// (`pending === false`) and the plugin has finished
				// submitting (`submit_sealed`), any sha still pending will
				// never get a verdict — seal it instead of polling forever.
				// Pre-564 CTI omits `pending` (value null) → never seals,
				// so older server builds keep the previous behaviour.
				$pending = array_key_exists( 'pending', $resp ) ? $resp['pending'] : null;
				if ( false === $pending
					&& '' !== $scan_id
					&& self::is_submit_sealed( $scan_id )
					&& self::unresolved_count( $scan_id ) > 0
				) {
					$sealed = Segurium_Verdict_Queue::seal_unresolved_paths( $scan_id );
					Segurium_Scan_Runner::debug(
						'scan_poll_seal_unresolved',
						array(
							'scan_id' => $scan_id,
							'sealed'  => $sealed,
						)
					);
					self::clear_submit_sealed( $scan_id );
				}
				break;
			}

			$cleared_etas = array();
			foreach ( $results as $row ) {
				$applied    += self::apply_row( $row ) ? 1 : 0;
				$row_scan_id = isset( $row['scan_id'] ) ? (string) $row['scan_id'] : '';
				if ( '' !== $row_scan_id && empty( $cleared_etas[ $row_scan_id ] ) ) {
					Segurium_Async_Scan_First_Poll_Eta::clear( $row_scan_id );
					$cleared_etas[ $row_scan_id ] = true;
				}
			}
			self::cursor_set( $scan_id, $cursor_after );
			$since = $cursor_after;

			if ( empty( $resp['more'] ) ) {
				break;
			}
		}

		return $applied;
	}

	/**
	 * Default budget check — reads the scan-runner tick clock.
	 *
	 * @return bool
	 */
	public static function default_budget_check() {
		if ( ! class_exists( 'Segurium_Scan_Runner' ) ) {
			return true;
		}
		return Segurium_Scan_Runner::time_left_in_tick() >= self::MIN_BUDGET_PER_ITER_SECS;
	}

	/**
	 * SEGURIUM-564: mark a scan as done submitting. After this, no new
	 * hashes will be handed to the submitter, so a CTI `queue_depth == 0`
	 * on an empty results page is a final "nothing more will arrive"
	 * signal. Called by the scan engine when listing completes.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	public static function mark_submit_sealed( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::SEAL_KV_PREFIX . $scan_id,
				'kv_value'   => '1',
				'expires_at' => $now + 86400,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Whether {@see mark_submit_sealed()} has fired for this scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return bool
	 */
	public static function is_submit_sealed( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return false;
		}
		$val = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::SEAL_KV_PREFIX . $scan_id )
		);
		return '1' === (string) $val;
	}

	/**
	 * Drop the submit-sealed flag. Called after sealing so a tidy
	 * runtime_kv survives a scan_id collision (defensive — scan_ids are
	 * fresh UUIDs) and the row does not linger past the 24 h TTL.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	public static function clear_submit_sealed( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		Segurium_Storage::table_delete(
			'runtime_kv',
			array( 'kv_key' => self::SEAL_KV_PREFIX . $scan_id )
		);
	}

	/**
	 * Count unresolved (submitted-but-no-verdict) paths for a scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return int
	 */
	public static function unresolved_count( $scan_id ) {
		// SEGURIUM-576: a single indexed COUNT(*) on the async_pending table
		// instead of loading and summing the whole per-scan blob.
		return Segurium_Async_Scan_Submitter::count_pending( (string) $scan_id );
	}

	/**
	 * Apply one verdict row. Identical semantics to the retired
	 * poller's `apply_row()` — kept distinct from {@see run()} for
	 * unit testing.
	 *
	 * @param array $row Row as returned by `/v1/scan/results`.
	 * @return bool
	 */
	public static function apply_row( array $row ) {
		$scan_id = isset( $row['scan_id'] ) ? (string) $row['scan_id'] : '';
		$verdict = isset( $row['verdict'] ) ? (string) $row['verdict'] : '';
		$rhash   = isset( $row['hash'] ) ? strtolower( str_replace( 'sha256:', '', (string) $row['hash'] ) ) : '';
		if ( '' === $scan_id || '' === $verdict || '' === $rhash ) {
			return false;
		}
		// SEGURIUM-576: pull only this hash's pending rows (indexed by
		// (scan_uuid, sha256)), never the whole pending set. Fan the verdict
		// out to every path sharing the content hash, then drop just those
		// rows. apply_async_verdict() is at-most-once per (scan, file) via
		// scan_findings.uq_scan_file, so even a crash-induced re-fetch that
		// re-applies an already-applied page cannot inflate counts.
		$rows = Segurium_Async_Scan_Submitter::pending_rows_for_sha( $scan_id, $rhash );
		if ( empty( $rows ) ) {
			return false;
		}
		$applied = false;
		foreach ( $rows as $r ) {
			$path     = (string) $r['file_path'];
			$detector = (string) $r['detector'];
			if ( Segurium_Verdict_Queue::apply_async_verdict( $scan_id, $detector, $rhash, $path, $verdict ) ) {
				$applied = true;
			}
		}

		Segurium_Async_Scan_Submitter::delete_pending_sha( $scan_id, $rhash );
		return $applied;
	}

	/**
	 * Read the per-scan cursor from its dedicated `runtime_kv` key. Every
	 * new scan starts at zero; combined with the `?scan_id=` filter on
	 * `/v1/scan/results` this isolates verdicts across IID rotations.
	 * Empty `scan_id` returns the zero cursor (orphan/test drain paths).
	 *
	 * SEGURIUM-573: the cursor used to live inside the pending-paths row,
	 * where the submit path could clobber it and draining all paths
	 * destroyed it. It now has its own key. An in-flight scan upgraded
	 * mid-drain reads zero here once (no key yet) and re-drains from the
	 * start, then heals — same self-healing tradeoff as SEGURIUM-510.
	 *
	 * @param string $scan_id Active scan UUID.
	 * @return array `{next_seq:int, updated_at:int}`
	 */
	public static function cursor_get( $scan_id = '' ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return array(
				'next_seq'   => 0,
				'updated_at' => 0,
			);
		}
		$raw     = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::CURSOR_KV_PREFIX . $scan_id )
		);
		$decoded = ( null === $raw || '' === $raw ) ? null : json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) ) {
			return array(
				'next_seq'   => 0,
				'updated_at' => 0,
			);
		}
		return array(
			'next_seq'   => isset( $decoded['next_seq'] ) ? (int) $decoded['next_seq'] : 0,
			'updated_at' => isset( $decoded['updated_at'] ) ? (int) $decoded['updated_at'] : 0,
		);
	}

	/**
	 * Persist the per-scan cursor monotonically into its own key. Only the
	 * drain calls this; it never regresses (a stale or lower value is
	 * dropped), so no other writer can drag it backwards. Independent of
	 * the pending-paths row, so it survives that row being deleted.
	 *
	 * @param string $scan_id  Active scan UUID.
	 * @param int    $next_seq Next cursor value to persist.
	 * @return void
	 */
	public static function cursor_set( $scan_id, $next_seq ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		$next_seq = (int) $next_seq;
		$current  = (int) self::cursor_get( $scan_id )['next_seq'];
		if ( $next_seq <= $current ) {
			return;
		}
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::CURSOR_KV_PREFIX . $scan_id,
				'kv_value'   => (string) wp_json_encode(
					array(
						'next_seq'   => $next_seq,
						'updated_at' => $now,
					)
				),
				'expires_at' => $now + 86400,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * SEGURIUM-573: drop the per-scan cursor key. Called from the scan's
	 * teardown ({@see Segurium_Scan::cleanup_scan_state()}) so a finished
	 * scan leaves no row behind. Abnormal terminations that skip teardown
	 * leave a bounded, harmless orphan (see {@see CURSOR_KV_PREFIX}).
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	public static function clear_cursor( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		Segurium_Storage::table_delete(
			'runtime_kv',
			array( 'kv_key' => self::CURSOR_KV_PREFIX . $scan_id )
		);
	}

	/**
	 * One-shot teardown of the retired poller's WP-Cron event +
	 * rate-limit transient. Gated on a sentinel option so the body
	 * only runs once per upgrade. Stays around as a no-op afterwards.
	 *
	 * @return void
	 */
	public static function migrate_unschedule_legacy_cron() {
		if ( (bool) Segurium_Storage::setting_get( self::MIGRATION_FLAG_OPTION, false ) ) {
			return;
		}
		while ( false !== wp_next_scheduled( self::LEGACY_CRON_HOOK ) ) {
			wp_clear_scheduled_hook( self::LEGACY_CRON_HOOK );
		}
		delete_transient( self::LEGACY_RATE_TRANSIENT );
		Segurium_Storage::setting_set( self::MIGRATION_FLAG_OPTION, 1, false );
	}

	/**
	 * SEGURIUM-510 one-shot: drop the legacy global `wp_option` cursor
	 * unconditionally. Affected installs (IID rotated post-install,
	 * inheriting the old IID's high-water mark) heal on the next scan;
	 * unaffected installs are no worse off because the cursor is now
	 * scoped per scan_id and every new scan starts at `next_seq=0`.
	 *
	 * @return void
	 */
	public static function migrate_drop_legacy_cursor() {
		if ( (bool) Segurium_Storage::setting_get( self::MIGRATION_FLAG_510, false ) ) {
			return;
		}
		Segurium_Storage::setting_delete( self::OPTION_CURSOR );
		Segurium_Storage::setting_set( self::MIGRATION_FLAG_510, 1, false );
	}

	/**
	 * SEGURIUM-576 one-shot: drop the legacy `async_scan:pending:*` runtime_kv
	 * JSON blobs. The per-scan pending map now lives in the `async_pending`
	 * table; any blob still in runtime_kv is an orphan from a scan that ran
	 * before this change (the ticket measured 6.15 MB of dead blob rows with
	 * no background sweeper). Gated on a sentinel so the body runs once per
	 * upgrade, then stays a no-op.
	 *
	 * In-flight scans upgraded mid-drain lose their not-yet-applied pending
	 * blob here; those files self-heal on the next scan (same bounded,
	 * one-time tradeoff as SEGURIUM-510 / 573).
	 *
	 * @return void
	 */
	public static function migrate_purge_legacy_pending_blobs() {
		if ( (bool) Segurium_Storage::setting_get( self::MIGRATION_FLAG_576, false ) ) {
			return;
		}
		// The `%` in the bound value is a deliberate SQL LIKE wildcard, so do
		// NOT esc_like() it.
		foreach (
			Segurium_Storage::table_get_col(
				'runtime_kv',
				'SELECT kv_key FROM {{table}} WHERE kv_key LIKE %s',
				array( Segurium_Async_Scan_Submitter::PENDING_KV_PREFIX . '%' )
			) as $key
		) {
			Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => (string) $key ) );
		}
		Segurium_Storage::setting_set( self::MIGRATION_FLAG_576, 1, false );
	}

	/**
	 * Lazy CTI client accessor.
	 *
	 * @return Segurium_CTI_Client
	 */
	private static function get_cti() {
		if ( ! self::$cti instanceof Segurium_CTI_Client ) {
			self::$cti = new Segurium_CTI_Client();
		}
		return self::$cti;
	}

	/**
	 * Test-only hook for injecting a mock CTI client. Pass `null` to
	 * reset back to the lazy default.
	 *
	 * @param Segurium_CTI_Client|null $cti Client or null to reset.
	 * @return void
	 */
	public static function set_cti_client_for_tests( ?Segurium_CTI_Client $cti ) {
		self::$cti = $cti;
	}
}

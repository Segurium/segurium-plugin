<?php
/**
 * Scan orchestrator for the Segurium security plugin.
 *
 * Stage 4 storage redesign: scan runs are stored in the scan_history table,
 * malware findings in scan_findings, in-flight orchestration in runtime_kv,
 * and per-scan working state in a tmp workspace managed by the storage
 * façade. Nothing persistent lives under data_dir/.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Orchestrates a chunked malware scan: file listing + verdict submission.
 */
class Segurium_Scan {

	/**
	 * Runtime_kv marker identifying the active scan.
	 */
	const KV_ACTIVE = 'scan_active';

	/**
	 * Runtime_kv key prefix for per-scan orchestrator state.
	 */
	const KV_ORCH_PREFIX = 'scan:';

	/**
	 * Runtime_kv TTL for per-scan state (seconds).
	 */
	const KV_TTL = 86400;

	/**
	 * Absolute path to the WordPress root directory.
	 *
	 * @var string
	 */
	private $base_path;

	/**
	 * Absolute path to the plugin data directory (for façade layouts, not state).
	 *
	 * @var string
	 */
	private $data_dir;

	/**
	 * Maximum time in seconds allowed for a single chunk.
	 *
	 * @var int
	 */
	private $time_limit;

	/**
	 * Verdict queue instance for submitting hashes.
	 *
	 * @var Segurium_Verdict_Queue
	 */
	private $verdict_queue;

	/**
	 * Glob patterns for paths to exclude from scanning.
	 *
	 * @var array
	 */
	private $exclude_patterns;

	/**
	 * Active tmp workspace path, or null when no scan is loaded.
	 *
	 * @var string|null
	 */
	private $workspace = null;

	/**
	 * Timestamp when the current chunk started.
	 *
	 * @var float
	 */
	private $start_time = 0.0;

	/**
	 * Whether scan completion has already been reported for this in-memory
	 * instance.
	 *
	 * @var bool
	 */
	private $completion_reported = false;

	/**
	 * Current orchestrator state.
	 *
	 * @var array
	 */
	private $state = array(
		'scan_id'             => '',
		'scan_type'           => '',
		'workspace'           => '',
		'scanner_completed'   => false,
		'scanner_read_offset' => 0,
		'files_found'         => 0,
		'files_skipped'       => 0,
	);

	/**
	 * Constructor.
	 *
	 * @param string                      $base_path        Absolute path to WordPress root.
	 * @param string                      $data_dir         Absolute path to plugin data directory.
	 * @param int                         $time_limit       Maximum seconds per chunk.
	 * @param Segurium_Verdict_Queue|null $verdict_queue    Optional verdict queue instance.
	 * @param array                       $exclude_patterns Glob patterns to exclude from scanning.
	 */
	public function __construct( $base_path, $data_dir, $time_limit, $verdict_queue = null, $exclude_patterns = array() ) {
		$this->base_path        = rtrim( $base_path, '/' );
		$this->data_dir         = rtrim( $data_dir, '/' );
		$this->time_limit       = max( 1, (int) $time_limit );
		$this->verdict_queue    = $verdict_queue ? $verdict_queue : new Segurium_Verdict_Queue( '', $time_limit );
		$this->exclude_patterns = $exclude_patterns;
	}

	/**
	 * Start a new scan and drive the first chunk. Retained for
	 * backwards-compatible callers and tests; the runner uses
	 * {@see initialize()} + {@see process_chunk()}.
	 *
	 * @param string $scan_type Type of scan, e.g. 'manual' or 'scheduled'.
	 * @return array Progress data for the first chunk.
	 */
	public function start( $scan_type = 'manual' ) {
		$this->initialize( wp_generate_uuid4(), $scan_type );
		$scanner = $this->create_scanner();
		$scanner->load_state();
		return $this->run_chunk( $scanner );
	}

	/**
	 * Prepare a new scan: create workspace, insert the scan_history row,
	 * seed runtime_kv state and emit the scan_started CTI message.
	 *
	 * @param string $scan_id   Scan UUID. Pass empty to auto-generate.
	 * @param string $scan_type Scan type label.
	 * @return string The assigned scan UUID.
	 * @throws Segurium_Storage_Exception When the tmp workspace cannot be created.
	 */
	public function initialize( $scan_id = '', $scan_type = 'manual' ) {
		if ( empty( $scan_id ) ) {
			$scan_id = wp_generate_uuid4();
		}

		$workspace = Segurium_Storage::tmp_make_workspace( 'scan' );
		if ( false === $workspace ) {
			throw new Segurium_Storage_Exception( 'scan: failed to create tmp workspace' );
		}
		$this->workspace = $workspace;

		$this->state = array(
			'scan_id'             => (string) $scan_id,
			'scan_type'           => (string) $scan_type,
			'workspace'           => $workspace,
			'scanner_completed'   => false,
			'scanner_read_offset' => 0,
			'files_found'         => 0,
			'files_skipped'       => 0,
			'started_at'          => time(),
		);

		$scanner = $this->create_scanner();
		$scanner->start();
		$this->verdict_queue->attach( $scan_id );
		$this->verdict_queue->set_base_path( $this->base_path );
		$this->verdict_queue->init( $scan_id );

		$this->save_state();
		// Seed the listing row so load_state() reads a
		// well-formed payload even before the first chunk has run.
		$this->save_listing_state();

		$now = time();
		Segurium_Storage::table_insert(
			'scan_history',
			array(
				'scan_uuid'      => (string) $scan_id,
				'scan_type'      => (string) $scan_type,
				'status'         => 'running',
				// Same anchor as state['started_at'] so the frozen
				// duration_seconds == finished_at - started_at exactly.
				'started_at'     => (int) $this->state['started_at'],
				'finished_at'    => null,
				'files_found'    => 0,
				'files_scanned'  => 0,
				'trigger_source' => (string) $scan_type,
				// Every scan_history row carries a reason code.
				// 'RUNNING' covers the in-flight window; one of the terminal
				// REASON_* codes (COMPLETED / USER_CANCEL / ABORTED_*) replaces
				// it once the scan reaches a terminal state.
				'error_code'     => Segurium_Scan_Runner::REASON_RUNNING,
			)
		);

		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_ACTIVE,
				'kv_value'   => (string) wp_json_encode(
					array(
						'scan_id'   => (string) $scan_id,
						'scan_type' => (string) $scan_type,
						'workspace' => $workspace,
					)
				),
				'expires_at' => $now + self::KV_TTL,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);

		Segurium_Storage::cti_send_message(
			'scan_started',
			wp_json_encode(
				array(
					'scan_id'   => (string) $scan_id,
					'scan_type' => (string) $scan_type,
				)
			)
		);

		// Peer of `segurium_scan_completed`. Fired so cross-
		// cutting listeners (telemetry, instrumentation) can mark the
		// start of a scan without coupling to scan internals. Carries the
		// Segurium_Scan instance as the lone argument.
		do_action( 'segurium_scan_started', $this );

		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => 'scan_started',
					'severity'   => 0,
					'subject'    => (string) $scan_type,
					'data_json'  => (string) wp_json_encode(
						array(
							'scan_id'   => (string) $scan_id,
							'scan_type' => (string) $scan_type,
						)
					),
					'created_at' => $now,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-scan] activity_log scan_started failed: ' . $e->getMessage() );
		}

		return (string) $scan_id;
	}

	/**
	 * Restore orchestrator state from runtime_kv.
	 *
	 * @return bool True if state was loaded successfully.
	 */
	public function load_state() {
		$active = $this->read_active();
		if ( null === $active ) {
			return false;
		}
		$scan_id = isset( $active['scan_id'] ) ? (string) $active['scan_id'] : '';
		if ( '' === $scan_id ) {
			return false;
		}
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $this->orch_key_for( $scan_id ) )
		);
		if ( null === $raw ) {
			return false;
		}
		$decoded = json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) || empty( $decoded['scan_id'] ) ) {
			return false;
		}
		$this->state     = array_merge( $this->state, $decoded );
		$this->workspace = isset( $decoded['workspace'] ) ? (string) $decoded['workspace'] : '';
		// Listing counters live in the dedicated
		// scan:<id>:listing row. Merge them in last so they win over
		// anything the legacy orch row may still carry from before the
		// split landed (the orch upsert no longer writes them).
		$this->load_listing_state( $scan_id );
		$this->verdict_queue->attach( $scan_id );
		$this->verdict_queue->set_base_path( $this->base_path );
		return true;
	}

	/**
	 * Process the next chunk of scanning work.
	 *
	 * @return array Progress data after processing the chunk.
	 */
	public function process_chunk() {
		if ( $this->is_completed() ) {
			return $this->build_progress();
		}

		$scanner = $this->create_scanner();

		if ( ! $this->state['scanner_completed'] ) {
			if ( ! $scanner->load_state() ) {
				// An unreadable or corrupt state file leaves nothing to
				// resume from. The runner reads this marker and takes the
				// ENGINE_LOAD_FAILED terminal path; bare progress would read
				// as a healthy no-op chunk and spin until the lock ages out.
				$progress                       = $this->build_progress();
				$progress['engine_load_failed'] = true;
				return $progress;
			}
			$scanner_state = $scanner->get_state();
			if ( 'completed' === $scanner_state['status'] ) {
				$this->state['scanner_completed'] = true;
				$this->state['files_found']       = $scanner_state['files_found'];
			}
		}

		return $this->run_chunk( $scanner );
	}

	/**
	 * Return the orchestrator state array.
	 *
	 * @return array
	 */
	public function get_state() {
		return $this->state;
	}

	/**
	 * Return the plugin data directory (used by helpers that still accept it
	 * for façade compatibility).
	 *
	 * @return string
	 */
	public function get_data_dir() {
		return $this->data_dir;
	}

	/**
	 * Return the scanned root path.
	 *
	 * @return string
	 */
	public function get_base_path() {
		return $this->base_path;
	}

	/**
	 * Return the active workspace path, or empty string.
	 *
	 * @return string
	 */
	public function get_workspace() {
		return (string) $this->workspace;
	}

	/**
	 * Snapshot used by the runner's status endpoint.
	 *
	 * @return array
	 */
	public function get_progress_snapshot() {
		$scan_id   = (string) $this->state['scan_id'];
		$completed = $this->is_completed();
		$stats     = $this->verdict_queue->get_scan_stats( $scan_id );

		if ( $completed ) {
			$phase = 'completed';
		} elseif ( ! empty( $this->state['scanner_completed'] ) ) {
			$phase = 'scanning';
		} else {
			$phase = 'listing';
		}

		$neoray_skipped = isset( $stats['neoray_skipped'] ) ? (int) $stats['neoray_skipped'] : 0;

		return array(
			'scan_id'         => $scan_id,
			'scan_type'       => (string) $this->state['scan_type'],
			'phase'           => $phase,
			'completed'       => $completed,
			'files_found'     => (int) $this->state['files_found'],
			'files_skipped'   => (int) $this->state['files_skipped'] + $neoray_skipped,
			'files_submitted' => (int) $stats['submitted'],
			'files_verdicted' => (int) $stats['verdicted'],
			'files_failed'    => (int) $stats['failed'],
			'threats_found'   => (int) $stats['threats'],
			'neoray_errors'   => isset( $stats['neoray_errors'] ) ? (int) $stats['neoray_errors'] : 0,
			'neoray_pending'  => isset( $stats['unknowns'] ) ? count( $stats['unknowns'] ) : 0,
		);
	}

	/**
	 * Mark the current scan as cancelled. The reason code decides both
	 * `scan_history.error_code` and the `cancelled_by` the message
	 * carries: a site admin pressing Stop scan, or an analyst ending it
	 * over the CTI action channel.
	 *
	 * @param string $reason_code Reason code from `Segurium_Scan_Runner::REASON_*`.
	 * @param bool   $cleanup     When false, skip
	 *                            `cleanup_scan_state()` so a parallel worker
	 *                            mid-tick can run cleanup itself via the
	 *                            cooperative cancel handshake.
	 * @return void
	 */
	public function mark_cancelled( $reason_code = Segurium_Scan_Runner::REASON_USER_CANCEL, $cleanup = true ) {
		$this->finalize_history(
			'cancelled',
			array_merge(
				array( 'error_code' => (string) $reason_code ),
				$this->terminal_progress_columns()
			)
		);
		Segurium_Storage::cti_send_message(
			'scan_cancelled',
			$this->terminal_message_payload(
				(string) $reason_code,
				array( 'cancelled_by' => Segurium_Scan_Runner::cancelled_by( $reason_code ) )
			)
		);
		if ( $cleanup ) {
			$this->cleanup_scan_state();
		}
	}

	/**
	 * Mark the current scan as aborted. Callers must pass the
	 * specific reason (heartbeat-stale / watchdog / stuck-no-progress /
	 * engine-load-failed / runtime-error) so `scan_history.error_code` is
	 * populated unambiguously.
	 *
	 * @param string $reason_code Reason code from `Segurium_Scan_Runner::REASON_*`.
	 * @param bool   $cleanup     When false, skip
	 *                            `cleanup_scan_state()` so a parallel worker
	 *                            mid-tick can run cleanup itself via the
	 *                            cooperative cancel handshake.
	 * @return void
	 */
	public function mark_aborted( $reason_code = Segurium_Scan_Runner::REASON_RUNTIME_ERROR, $cleanup = true ) {
		$this->finalize_history(
			'aborted',
			array_merge(
				array( 'error_code' => (string) $reason_code ),
				$this->terminal_progress_columns()
			)
		);
		Segurium_Storage::cti_send_message(
			'scan_aborted',
			$this->terminal_message_payload( (string) $reason_code )
		);
		if ( $cleanup ) {
			$this->cleanup_scan_state();
		}
	}

	/**
	 * Idempotent workspace + runtime_kv teardown for the
	 * cooperative-cancel handshake. Called by the runner's chunk-loop cancel
	 * observer so cleanup runs from the only PHP process that is still
	 * actively reading the workspace, never from a parallel `terminate()`
	 * caller. Safe to call multiple times — `tmp_destroy()`,
	 * `verdict_queue->purge()`, and the runtime_kv deletes all no-op when
	 * their target is already gone.
	 *
	 * @return void
	 */
	public function cleanup_state() {
		$this->cleanup_scan_state();
	}

	/**
	 * Snapshot the discovery + verdict counters so the scan_history row can
	 * answer "X of Y scanned" for the cancelled/aborted/completed UI summary.
	 * Reads engine state for files_found and the verdict queue for verdicted.
	 *
	 * @return array{files_found:int,files_scanned:int,threats_found:int}
	 */
	private function terminal_progress_columns() {
		$scan_id   = (string) $this->state['scan_id'];
		$verdicted = 0;
		$threats   = 0;
		if ( '' !== $scan_id ) {
			try {
				$stats     = $this->verdict_queue->get_scan_stats( $scan_id );
				$verdicted = isset( $stats['verdicted'] ) ? (int) $stats['verdicted'] : 0;
				$threats   = isset( $stats['threats'] ) ? (int) $stats['threats'] : 0;
			} catch ( Throwable $e ) {
				$verdicted = 0;
				$threats   = 0;
			}
			// Cooperative-cancel handshake may
			// have purged the verdict queue before this method runs, so
			// $threats can read 0 even though scan_findings already holds
			// real rows for this scan. Fall back to a scan_findings COUNT
			// so the frozen threats_found column on cancelled / aborted
			// rows reflects the findings actually persisted, never the
			// race-emptied 0.
			if ( 0 === $threats ) {
				// Vulnerable rows are not threats. They live in
				// the same append-only log under a status no read path selects
				// on, so this COUNT must exclude them or a clean site with 40
				// outdated files reports "40 threats" on any cancelled scan.
				$fallback = (int) Segurium_Storage::table_get_var(
					'scan_findings',
					'SELECT COUNT(*) FROM {{table}} WHERE scan_uuid = %s AND status <> %s',
					array( $scan_id, Segurium_Verdict_Queue::STATUS_VULNERABLE )
				);
				if ( $fallback > 0 ) {
					$threats = $fallback;
				}
			}
		}
		return array(
			'files_found'   => (int) $this->state['files_found'],
			'files_scanned' => $verdicted,
			'threats_found' => $threats,
		);
	}

	/**
	 * Build the shared payload emitted alongside every terminal
	 * scan_history transition (scan_aborted / scan_cancelled). The
	 * scan_completed emitter intentionally hand-rolls a narrower payload
	 * (only the legacy fields plus duration_seconds) instead of reusing this
	 * helper, since CTI consumers depend on the historic field set.
	 *
	 * @param string $reason_code REASON_* constant for `error_code`.
	 * @param array  $extra       Per-message_type additions (e.g. cancelled_by).
	 * @return array
	 */
	private function terminal_message_payload( $reason_code, array $extra = array() ) {
		$scan_id   = (string) $this->state['scan_id'];
		$verdicted = 0;
		$failed    = 0;
		$threats   = 0;
		if ( '' !== $scan_id ) {
			try {
				$stats     = $this->verdict_queue->get_scan_stats( $scan_id );
				$verdicted = isset( $stats['verdicted'] ) ? (int) $stats['verdicted'] : 0;
				$failed    = isset( $stats['failed'] ) ? (int) $stats['failed'] : 0;
				$threats   = isset( $stats['threats'] ) ? (int) $stats['threats'] : 0;
			} catch ( Throwable $e ) {
				$verdicted = 0;
				$failed    = 0;
				$threats   = 0;
			}
		}
		$started  = isset( $this->state['started_at'] ) ? (int) $this->state['started_at'] : 0;
		$duration = $started > 0 ? max( 0, time() - $started ) : 0;
		return array_merge(
			array(
				'scan_id'          => $scan_id,
				'scan_type'        => isset( $this->state['scan_type'] ) ? (string) $this->state['scan_type'] : '',
				'error_code'       => (string) $reason_code,
				'files_found'      => (int) $this->state['files_found'],
				'files_verdicted'  => $verdicted,
				'files_failed'     => $failed,
				'threats_found'    => $threats,
				'duration_seconds' => $duration,
			),
			$extra
		);
	}

	/**
	 * Persist orchestrator coordination state into runtime_kv.
	 *
	 * This row carries scan_id, scan_type, workspace,
	 * scanner_completed, scanner_read_offset, started_at — i.e. anything
	 * the orchestrator owns. `files_found` and `files_skipped` are
	 * persisted via {@see save_listing_state()} into a separate
	 * `scan:<id>:listing` row so a slow worker writing the orch row at
	 * end-of-chunk can never overwrite a fresher listing snapshot.
	 *
	 * @return void
	 */
	public function save_state() {
		$scan_id = (string) $this->state['scan_id'];
		if ( '' === $scan_id ) {
			return;
		}
		$now     = time();
		$payload = $this->state;
		// Ownership: listing-side fields belong to scan:<id>:listing only.
		unset( $payload['files_found'], $payload['files_skipped'] );
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $this->orch_key_for( $scan_id ),
				'kv_value'   => (string) wp_json_encode( $payload ),
				'expires_at' => $now + self::KV_TTL,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Persist the listing-side counters (files_found,
	 * files_skipped) into runtime_kv at `scan:<id>:listing`. Called
	 * exactly once per chunk — right after `scanner->process_chunk()`
	 * has updated the in-memory counters from scanner state on disk.
	 *
	 * Single-writer-per-chunk semantics: the orchestrator's `save_state()`
	 * never touches this row, so even a stalled worker finishing its
	 * chunk after a concurrent worker has advanced listing cannot regress
	 * the persisted `files_found` value. Tick-mutex lease
	 * is the primary line of defense against concurrent workers; this
	 * split row is the architectural "no-mirror" cleanup that makes the
	 * back-jump impossible if the lease ever glitches.
	 *
	 * @return void
	 */
	public function save_listing_state() {
		$scan_id = (string) $this->state['scan_id'];
		if ( '' === $scan_id ) {
			return;
		}
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $this->listing_key_for( $scan_id ),
				'kv_value'   => (string) wp_json_encode(
					array(
						'files_found'   => (int) $this->state['files_found'],
						'files_skipped' => (int) $this->state['files_skipped'],
					)
				),
				'expires_at' => $now + self::KV_TTL,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Read the listing row and merge `files_found` /
	 * `files_skipped` into the in-memory state. Missing row is treated
	 * as "no listing progress yet" and leaves the in-memory defaults
	 * untouched — so callers (load_state(), test fixtures) get the same
	 * shape regardless of whether the listing row exists yet.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	private function load_listing_state( $scan_id ) {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $this->listing_key_for( $scan_id ) )
		);
		if ( null === $raw ) {
			return;
		}
		$decoded = json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) ) {
			return;
		}
		if ( isset( $decoded['files_found'] ) ) {
			$this->state['files_found'] = (int) $decoded['files_found'];
		}
		if ( isset( $decoded['files_skipped'] ) ) {
			$this->state['files_skipped'] = (int) $decoded['files_skipped'];
		}
	}

	/**
	 * Return the list of file paths recorded by the scanner for this scan.
	 *
	 * @param string|null $scanner_result_file Optional explicit result-file path.
	 * @param int         $limit               Max number of paths to return.
	 * @return array{paths: string[], total: int, truncated: bool}
	 */
	public function get_scanned_paths( $scanner_result_file = null, $limit = 1000 ) {
		$file   = $scanner_result_file ? $scanner_result_file : $this->scanner_result_file();
		$result = array(
			'paths'     => array(),
			'total'     => 0,
			'truncated' => false,
		);
		if ( '' === $file || ! file_exists( $file ) ) {
			return $result;
		}

		$handle = Segurium_Fs::open( $file, 'r' );
		if ( ! $handle ) {
			return $result;
		}
		// phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
		while ( ( $line = fgets( $handle ) ) !== false ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$record = json_decode( $line, true );
			if ( ! is_array( $record ) || ! isset( $record['path'] ) ) {
				continue;
			}
			++$result['total'];
			if ( count( $result['paths'] ) < $limit ) {
				$result['paths'][] = $this->make_relative_path( $record['path'] );
			} else {
				$result['truncated'] = true;
			}
		}
		Segurium_Fs::close( $handle );
		return $result;
	}

	/**
	 * Return the open threats for the current (or explicit) scan by querying
	 * the scan_findings table.
	 *
	 * @param string|null $scanner_result_file Retained for call-site compatibility; unused.
	 * @param string|null $verdict_result_file Retained for call-site compatibility; unused.
	 * @param string|null $scan_uuid           Optional scan UUID (overrides state).
	 * @return array
	 */
	public function get_threats( $scanner_result_file = null, $verdict_result_file = null, $scan_uuid = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		unset( $scanner_result_file, $verdict_result_file );
		return self::findings_for( $scan_uuid ? (string) $scan_uuid : (string) $this->state['scan_id'] );
	}

	/**
	 * Read the threat set of any scan by UUID, without an instance. The
	 * real-time path records findings under a UUID it generates itself and
	 * never builds a Segurium_Scan, so both it and Segurium_Auto_Fix read
	 * the canonical rows through here.
	 *
	 * Excludes vulnerable rows. This list is the cleanup API's threat set
	 * and is also consumed by update_server_state_from_scan(); an
	 * unrecognised status falls through to state='malware' in
	 * ajax_get_threats().
	 *
	 * @param string $scan_id Scan UUID.
	 * @return array
	 */
	public static function findings_for( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return array();
		}
		$rows = Segurium_Storage::table_get_results(
			'scan_findings',
			'SELECT file_path AS path, sha256, verdict, status, backup_id, created_at AS detected_at FROM {{table}} WHERE scan_uuid = %s AND status <> %s ORDER BY id ASC',
			array( $scan_id, Segurium_Verdict_Queue::STATUS_VULNERABLE ),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}
		foreach ( $rows as &$row ) {
			$row['verdict'] = (int) $row['verdict'];
		}
		unset( $row );
		return $rows;
	}

	/**
	 * Return every relative path verdicted in this scan (threats + clean).
	 *
	 * @return array
	 */
	public function get_verdicted_paths() {
		$paths = array();
		$this->stream_verdicted_paths(
			function ( $rel ) use ( &$paths ) {
				$paths[] = $rel;
			}
		);
		return $paths;
	}

	/**
	 * Stream every verdicted relative path to $cb without building the full
	 * list in memory. The realtime snapshot sync consumes this
	 * so a 100K+ file result set never materialises a 100K-element PHP array.
	 *
	 * @param callable $cb Receives each relative path.
	 * @return void
	 */
	public function stream_verdicted_paths( callable $cb ) {
		$file = $this->scanner_result_file();
		if ( '' === $file || ! file_exists( $file ) ) {
			return;
		}
		$handle = Segurium_Fs::open( $file, 'r' );
		if ( ! $handle ) {
			return;
		}
		// phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
		while ( ( $line = fgets( $handle ) ) !== false ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$record = json_decode( $line, true );
			if ( is_array( $record ) && ! empty( $record['path'] ) ) {
				call_user_func( $cb, $this->make_relative_path( $record['path'] ) );
			}
		}
		Segurium_Fs::close( $handle );
	}

	/**
	 * Return paginated scan history from the scan_history table.
	 *
	 * @param int $limit  Rows per page (max 200).
	 * @param int $offset Offset.
	 * @return array
	 */
	public static function get_history( $limit = 50, $offset = 0 ) {
		$limit  = max( 1, min( 200, (int) $limit ) );
		$offset = max( 0, (int) $offset );

		// threats_found and threats_cleaned are frozen columns
		// on scan_history; no JOIN to scan_findings required.
		$rows = Segurium_Storage::table_get_results(
			'scan_history',
			'SELECT scan_uuid, scan_type, status, error_code, started_at, finished_at, files_found, files_scanned, files_failed, files_skipped, threats_found, threats_cleaned'
				. ' FROM {{table}} ORDER BY started_at DESC LIMIT %d OFFSET %d',
			array( $limit, $offset ),
			ARRAY_A
		);
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$out[] = array(
				'id'              => $row['scan_uuid'],
				'scan_type'       => $row['scan_type'],
				'status'          => $row['status'],
				'error_code'      => isset( $row['error_code'] ) ? (string) $row['error_code'] : '',
				'started_at'      => (int) $row['started_at'],
				'completed_at'    => null !== $row['finished_at'] ? (int) $row['finished_at'] : null,
				'files_found'     => (int) $row['files_found'],
				'files_skipped'   => (int) $row['files_skipped'],
				'files_failed'    => (int) $row['files_failed'],
				'files_verdicted' => (int) $row['files_scanned'],
				'threats_found'   => (int) $row['threats_found'],
				'files_cleaned'   => (int) $row['threats_cleaned'],
			);
		}
		return $out;
	}

	/**
	 * Count of scan_history rows.
	 *
	 * @return int
	 */
	public static function count_history() {
		$val = Segurium_Storage::table_get_var(
			'scan_history',
			'SELECT COUNT(*) FROM {{table}}'
		);
		return (int) $val;
	}

	/**
	 * Process a chunk of listing/verdicting work.
	 *
	 * @param Segurium_Scanner $scanner Scanner instance.
	 * @return array
	 */
	private function run_chunk( $scanner ) {
		$this->start_time      = microtime( true );
		$listing_just_finished = false;

		if ( ! $this->state['scanner_completed'] ) {
			$result                       = $scanner->process_chunk();
			$this->state['files_found']   = (int) $result['files_found'];
			$this->state['files_skipped'] = isset( $result['files_skipped'] ) ? (int) $result['files_skipped'] : 0;
			if ( ! empty( $result['completed'] ) ) {
				$this->state['scanner_completed'] = true;
				$listing_just_finished            = true;
			}
		}

		$this->submit_new_scanner_results();

		// Persist the listing-side counters (files_found,
		// files_skipped) into their own runtime_kv row right after the
		// JSONL → verdict-queue handoff. Splitting them out of the orch
		// row removes the back-jump pattern observed in debug3.log: a
		// stalled worker finishing its chunk used to overwrite a
		// concurrent worker's already-advanced files_found because both
		// shared the same kv key. Now `save_state()` (orch only) and
		// `save_listing_state()` (listing only) write disjoint rows; the
		// orch save can never regress listing.
		$this->save_listing_state();

		if ( $this->state['scanner_completed'] ) {
			$this->verdict_queue->mark_submissions_complete( $this->state['scan_id'] );
			// Listing is done — no more hashes will be
			// submitted. Let the async results loop treat a CTI
			// `queue_depth == 0` as final and seal any sha that never got
			// a verdict, instead of polling an empty endpoint forever.
			if ( class_exists( 'Segurium_Async_Scan_Results_Loop' ) ) {
				Segurium_Async_Scan_Results_Loop::mark_submit_sealed( (string) $this->state['scan_id'] );
			}
		}

		if ( $listing_just_finished ) {
			$this->save_state();
			return $this->build_progress();
		}

		$single_batch = (bool) apply_filters( 'segurium_scan_verdict_single_batch', true );
		$this->verdict_queue->process( $single_batch );

		$this->save_state();
		return $this->build_progress();
	}

	/**
	 * Read new scanner results and enqueue them with the verdict queue.
	 *
	 * @return void
	 */
	private function submit_new_scanner_results() {
		$file = $this->scanner_result_file();
		if ( '' === $file || ! file_exists( $file ) ) {
			return;
		}
		$handle = Segurium_Fs::open( $file, 'r' );
		if ( ! $handle ) {
			return;
		}
		fseek( $handle, (int) $this->state['scanner_read_offset'] );
		$last_good_offset = (int) $this->state['scanner_read_offset'];
		$files            = array();
		// phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
		while ( ( $line = fgets( $handle ) ) !== false ) {
			if ( "\n" !== substr( $line, -1 ) ) {
				break;
			}
			$last_good_offset = ftell( $handle );
			$line             = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$record = json_decode( $line, true );
			if ( ! is_array( $record ) ) {
				continue;
			}
			$files[] = array(
				'path'   => $this->make_relative_path( $record['path'] ),
				'sha256' => $record['sha256'],
				'size'   => $record['size'],
				'mtime'  => $record['mtime'],
			);
		}
		$this->state['scanner_read_offset'] = $last_good_offset;
		Segurium_Fs::close( $handle );

		if ( empty( $files ) ) {
			return;
		}

		$ignore = new Segurium_Ignore_Lists( $this->data_dir );
		$ignore->load();
		$filtered = array();
		foreach ( $files as $f ) {
			if ( ! $ignore->is_hash_ignored( $f['path'], $f['sha256'] ) ) {
				$filtered[] = $f;
			}
		}
		if ( ! empty( $filtered ) ) {
			$this->verdict_queue->submit( $filtered, (string) $this->state['scan_id'] );
		}
	}

	/**
	 * Whether every submitted file has a final verdict.
	 *
	 * @return bool
	 */
	private function is_completed() {
		return $this->state['scanner_completed']
			&& $this->verdict_queue->is_scan_complete( (string) $this->state['scan_id'] );
	}

	/**
	 * Build a progress payload for the frontend.
	 *
	 * @return array
	 */
	private function build_progress() {
		$scan_id   = (string) $this->state['scan_id'];
		$completed = $this->is_completed();
		$stats     = $this->verdict_queue->get_scan_stats( $scan_id );

		$unknowns_pending = isset( $stats['unknowns'] ) ? count( $stats['unknowns'] ) : 0;
		$neoray_skipped   = isset( $stats['neoray_skipped'] ) ? (int) $stats['neoray_skipped'] : 0;
		$neoray_errors    = isset( $stats['neoray_errors'] ) ? (int) $stats['neoray_errors'] : 0;

		if ( $completed ) {
			$phase = 'completed';
		} elseif ( $this->state['scanner_completed'] && $unknowns_pending > 0 ) {
			$phase = 'escalating';
		} elseif ( $this->state['scanner_completed'] ) {
			$phase = 'scanning';
		} else {
			$phase = 'listing';
		}

		if ( $completed && ! $this->completion_reported ) {
			// The terminal emit is a durable, idempotent action,
			// not a side effect of building a status payload. Delegating keeps
			// build_progress() a read model and guarantees exactly-once.
			$this->finalize_completion( $stats, $neoray_skipped );
		}

		// `files_cleaned` is a frozen property of the scan and
		// only meaningful after the auto-fix listener has run. Read it from
		// the persisted column once the scan is completed; for in-flight
		// ticks it is always 0.
		// Never let this read throw out of build_progress. A
		// throw here lands after finalize_completion()'s atomic claim, so it
		// would block process_chunk() from returning completed=true and strand
		// the runner before it can release the lock — exactly the idle-loop
		// tail this ticket fixes. A failed read just reports 0.
		$files_cleaned = 0;
		if ( $completed && '' !== $scan_id ) {
			try {
				$files_cleaned = (int) Segurium_Storage::table_get_var(
					'scan_history',
					'SELECT threats_cleaned FROM {{table}} WHERE scan_uuid = %s',
					array( $scan_id )
				);
			} catch ( Segurium_Storage_Exception $e ) {
				Segurium_Debug::log( '[segurium-scan] files_cleaned read failed: ' . $e->getMessage() );
			}
		}

		return array(
			'scan_id'         => $scan_id,
			'phase'           => $phase,
			'completed'       => $completed,
			'files_found'     => (int) $this->state['files_found'],
			'files_skipped'   => (int) $this->state['files_skipped'] + $neoray_skipped,
			'files_submitted' => (int) $stats['submitted'],
			'files_verdicted' => (int) $stats['verdicted'],
			'files_failed'    => (int) $stats['failed'],
			'threats_found'   => (int) $stats['threats'],
			'files_cleaned'   => $files_cleaned,
			'neoray_errors'   => $neoray_errors,
			'neoray_pending'  => $unknowns_pending,
			// Signals the runner that the head batch is parked
			// in a transient-inspect backoff window — end the tick early.
			'inspect_backoff' => $this->verdict_queue->is_inspect_backoff_waiting(),
		);
	}

	/**
	 * Convert an absolute path to a path relative to the base directory.
	 *
	 * @param string $absolute_path Absolute filesystem path.
	 * @return string
	 */
	private function make_relative_path( $absolute_path ) {
		$base = $this->base_path . '/';
		if ( 0 === strpos( $absolute_path, $base ) ) {
			return substr( $absolute_path, strlen( $base ) );
		}
		return $absolute_path;
	}

	/**
	 * Build a scanner bound to the current workspace.
	 *
	 * @return Segurium_Scanner
	 */
	private function create_scanner() {
		$workspace = '' !== (string) $this->workspace ? (string) $this->workspace : $this->data_dir;
		// Seconds one listing pass may spend before it yields the request
		// back. Filterable so a constrained host can shorten it, and so a
		// test can force a listing to span more than one chunk without
		// racing a wall clock.
		$listing_budget = (float) apply_filters(
			'segurium_scan_listing_time_budget',
			$this->time_limit * 0.6
		);

		return new Segurium_Scanner(
			$this->base_path,
			$workspace,
			$listing_budget,
			$this->exclude_patterns
		);
	}

	/**
	 * Path to the scanner result file inside the workspace.
	 *
	 * @return string
	 */
	private function scanner_result_file() {
		if ( '' === (string) $this->workspace ) {
			return '';
		}
		return $this->workspace . '/scanner-results.jsonl';
	}

	/**
	 * Emit the terminal `scan_completed` event exactly once for this scan, then
	 * stay silent on every later attempt — across separate ticks and processes,
	 * not just within one engine instance.
	 *
	 * The emit used to live inline in build_progress() guarded
	 * only by the in-memory $completion_reported flag. Each driver tick rebuilds
	 * the engine from persisted state, resetting that flag to false, so the
	 * event re-fired on every poll with an ever-larger `now - started_at`
	 * duration (observed 310x on one scan, ~5x inflated). The authoritative
	 * guard is now an atomic UPDATE that flips scan_history `running -> completed`:
	 * only the worker whose UPDATE changes the row emits, and the duration is
	 * frozen at that instant.
	 *
	 * @param array $stats          Verdict-queue stats for this scan.
	 * @param int   $neoray_skipped Files skipped by the secondary scanner.
	 * @return bool Whether this call was the one that emitted the event.
	 */
	private function finalize_completion( array $stats, $neoray_skipped ) {
		if ( $this->completion_reported ) {
			return false;
		}
		$this->completion_reported = true;

		$scan_id       = (string) $this->state['scan_id'];
		$files_failed  = (int) $stats['failed'];
		$files_skipped = (int) $this->state['files_skipped'] + (int) $neoray_skipped;
		$started       = isset( $this->state['started_at'] ) ? (int) $this->state['started_at'] : 0;
		$now           = time();
		$duration      = $started > 0 ? max( 0, $now - $started ) : 0;

		$claimed = $this->finalize_history(
			'completed',
			array(
				'finished_at'   => $now,
				'files_found'   => (int) $this->state['files_found'],
				'files_scanned' => (int) $stats['verdicted'],
				'files_failed'  => $files_failed,
				'files_skipped' => $files_skipped,
				'threats_found' => (int) $stats['threats'],
				'error_code'    => Segurium_Scan_Runner::REASON_COMPLETED,
			),
			'running'
		);

		if ( 1 !== $claimed ) {
			// Another worker / an earlier tick already wrote the terminal row
			// (or the scan was cancelled/aborted first). Do not re-emit.
			return false;
		}

		Segurium_Storage::cti_send_message(
			'scan_completed',
			wp_json_encode(
				array(
					'scan_id'          => $scan_id,
					'files_found'      => (int) $this->state['files_found'],
					'files_verdicted'  => (int) $stats['verdicted'],
					'files_failed'     => $files_failed,
					'files_skipped'    => $files_skipped,
					'threats_found'    => (int) $stats['threats'],
					'duration_seconds' => $duration,
				)
			)
		);

		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => 'scan_finished',
					'severity'   => (int) $stats['threats'] > 0 ? 2 : 0,
					'subject'    => $scan_id,
					'data_json'  => (string) wp_json_encode(
						array(
							'scan_id'       => $scan_id,
							'files_scanned' => (int) $stats['verdicted'],
							'files_failed'  => $files_failed,
							'files_skipped' => $files_skipped,
							'threats_found' => (int) $stats['threats'],
						)
					),
					'created_at' => $now,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-scan] activity_log scan_finished failed: ' . $e->getMessage() );
		}

		return true;
	}

	/**
	 * Idempotent terminal-completion trigger for the runner's finalize path.
	 *
	 * Emitting the terminal event on the same path that releases
	 * the lock keeps emit-and-release coupled, so a tick can never emit without
	 * releasing. When build_progress() already emitted during the completing
	 * chunk this is a no-op (the in-memory flag short-circuits); when it did not
	 * — e.g. a read threw after the work finished — this is the safety net that
	 * emits before the lock is dropped.
	 *
	 * @return bool Whether this call emitted the event.
	 */
	public function emit_terminal_completion() {
		$scan_id = (string) $this->state['scan_id'];
		if ( '' === $scan_id ) {
			return false;
		}
		$stats          = $this->verdict_queue->get_scan_stats( $scan_id );
		$neoray_skipped = isset( $stats['neoray_skipped'] ) ? (int) $stats['neoray_skipped'] : 0;
		return $this->finalize_completion( $stats, $neoray_skipped );
	}

	/**
	 * Update the scan_history row for this run.
	 *
	 * When $expected_status is given the WHERE clause is narrowed to it, turning
	 * the UPDATE into an atomic "first finalizer wins" claim:
	 * only the worker whose UPDATE actually flips the row changes any rows and
	 * sees a non-zero return. Callers that pass it MUST act on the count.
	 *
	 * @param string      $status          Terminal status string.
	 * @param array       $extra           Extra column overrides.
	 * @param string|null $expected_status Current status to guard on, or null
	 *                                     for an unconditional update.
	 * @return int Rows changed (0 when a guarded claim was already lost).
	 */
	private function finalize_history( $status, array $extra = array(), $expected_status = null ) {
		$scan_id = (string) $this->state['scan_id'];
		if ( '' === $scan_id ) {
			return 0;
		}
		$data  = array_merge(
			array(
				'status'      => $status,
				'finished_at' => time(),
			),
			$extra
		);
		$where = array( 'scan_uuid' => $scan_id );
		if ( null !== $expected_status ) {
			$where['status'] = (string) $expected_status;
		}
		try {
			return (int) Segurium_Storage::table_update( 'scan_history', $data, $where );
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-scan] finalize_history failed: ' . $e->getMessage() );
			return 0;
		}
	}

	/**
	 * Destroy workspace and delete runtime_kv rows for this scan.
	 *
	 * @return void
	 */
	private function cleanup_scan_state() {
		$scan_id = (string) $this->state['scan_id'];
		self::purge_runtime( $scan_id, (string) $this->workspace );
		$this->workspace = null;
		if ( '' !== $scan_id ) {
			// purge_runtime() already deleted the queue rows; purge() here
			// resets the queue's in-memory persisted snapshot so a later
			// save_state() in this process cannot skip its write.
			$this->verdict_queue->attach( $scan_id );
			$this->verdict_queue->purge();
		}
	}

	/**
	 * Scan-id-addressable runtime teardown, shared by the
	 * engine's own cleanup and the runner's orphan sweep (which has no engine
	 * instance: `load_state()` only finds the scan behind `scan_active`).
	 *
	 * Drops the tmp workspace (lifting `scanner-skips.jsonl` first),
	 * every `scan:<id>:*` runtime_kv row (orchestrator,
	 * listing, verdict-queue state and chunks), the async results cursor /
	 * submit seal / first-poll ETA, the `async_pending` rows, and the
	 * `scan_active` marker — the marker only when it still points at this
	 * scan, so a cooperative-cancel cleanup from an old worker can never
	 * blank the marker of the scan that replaced it.
	 *
	 * @param string $scan_id   Scan UUID.
	 * @param string $workspace Workspace path when known; read from the
	 *                          `scan:<id>:orch` row when empty.
	 * @return void
	 */
	public static function purge_runtime( $scan_id, $workspace = '' ) {
		$scan_id   = (string) $scan_id;
		$workspace = (string) $workspace;
		if ( '' === $workspace && '' !== $scan_id ) {
			$orch_raw = Segurium_Storage::table_get_var(
				'runtime_kv',
				'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
				array( self::KV_ORCH_PREFIX . $scan_id . ':orch' )
			);
			$orch     = null !== $orch_raw ? json_decode( (string) $orch_raw, true ) : null;
			if ( is_array( $orch ) && ! empty( $orch['workspace'] ) ) {
				$workspace = (string) $orch['workspace'];
			}
		}
		if ( '' !== $workspace ) {
			// Lift the per-scan skip log out of the workspace
			// before `tmp_destroy()` wipes it. One file, overwritten per
			// scan — only the most recent run is inspectable.
			$skips_src = $workspace . '/scanner-skips.jsonl';
			if ( is_file( $skips_src ) ) {
				$skips_dst = Segurium_Storage_Fs::data_dir() . '/last-scan-skips.jsonl';
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				@copy( $skips_src, $skips_dst );
			}
			Segurium_Storage::tmp_destroy( $workspace );
		}
		if ( '' !== $scan_id ) {
			global $wpdb;
			$tbl = Segurium_Storage::table_name( 'runtime_kv' );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- bulk prefix delete; no cache layer for runtime_kv.
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE kv_key LIKE %s', $tbl, $wpdb->esc_like( self::KV_ORCH_PREFIX . $scan_id . ':' ) . '%' ) );
			if ( class_exists( 'Segurium_Async_Scan_Results_Loop' ) ) {
				Segurium_Async_Scan_Results_Loop::clear_cursor( $scan_id );
				Segurium_Async_Scan_Results_Loop::clear_submit_sealed( $scan_id );
			}
			if ( class_exists( 'Segurium_Async_Scan_First_Poll_Eta' ) ) {
				Segurium_Async_Scan_First_Poll_Eta::clear( $scan_id );
			}
			if ( class_exists( 'Segurium_Async_Scan_Submitter' ) ) {
				Segurium_Async_Scan_Submitter::delete_all_pending( $scan_id );
				Segurium_Async_Scan_Submitter::clear_ceiling( $scan_id );
			}
		}
		$active_raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_ACTIVE )
		);
		$active     = null !== $active_raw ? json_decode( (string) $active_raw, true ) : null;
		$marker     = is_array( $active ) && isset( $active['scan_id'] ) ? (string) $active['scan_id'] : '';
		if ( '' === $marker || $marker === $scan_id ) {
			Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_ACTIVE ) );
		}
	}

	/**
	 * Read the active-scan marker payload.
	 *
	 * @return array|null
	 */
	private function read_active() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_ACTIVE )
		);
		if ( null === $raw ) {
			return null;
		}
		$decoded = json_decode( (string) $raw, true );
		return is_array( $decoded ) ? $decoded : null;
	}

	/**
	 * Return the orchestrator runtime_kv key for the given scan id.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return string
	 */
	private function orch_key_for( $scan_id ) {
		return self::KV_ORCH_PREFIX . $scan_id . ':orch';
	}

	/**
	 * Return the listing-state runtime_kv key for the given scan id.
	 * Listing counters (files_found, files_skipped) live
	 * in this dedicated row so the orch save_state can never overwrite
	 * them.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return string
	 */
	private function listing_key_for( $scan_id ) {
		return self::KV_ORCH_PREFIX . $scan_id . ':listing';
	}

	/**
	 * Public hook for the runner to release scan state after completion.
	 *
	 * @return void
	 */
	public function cleanup() {
		$this->cleanup_scan_state();
	}
}

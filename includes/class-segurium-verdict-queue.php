<?php
/**
 * Verdict queue for batch CTI hash inspection.
 *
 * Unified pipeline: the per-chunk inspect+escalate+write logic
 * is implemented once in the static helper {@see resolve_and_record} and
 * reused by the malware scan (via this queue), realtime scan, and upload
 * scan. The queue itself is now a thin wrapper that handles chunking +
 * per-scan accounting + the wp-cron time budget.
 *
 * Stage 4 storage redesign: the queue holds no persistent filesystem state.
 * Pending batches and per-scan stats live in runtime_kv rows keyed by scan
 * UUID; threats are flushed to the scan_findings table at the moment each
 * verdict is resolved. Buckets are deleted when the scan finalizes.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Batched CTI verdict queue backed entirely by runtime_kv + scan_findings.
 */
class Segurium_Verdict_Queue {

	const MAX_QUEUE_SIZE = 50000;
	const BATCH_SIZE     = 100;
	const KV_TTL         = 86400;

	/**
	 * Cooperative bail-out from the inspect-batch loop when the
	 * runner's tick budget is about to expire. Projection is the rolling
	 * average of the last `INSPECT_BATCH_WALL_WINDOW` batches multiplied by
	 * `INSPECT_BATCH_PROJECTED_MULT`, floored at
	 * `INSPECT_BATCH_PROJECTED_FLOOR_SEC` so a single fast batch can't lure
	 * the loop into starting one more on a tight budget.
	 */
	const INSPECT_BATCH_WALL_WINDOW         = 3;
	const INSPECT_BATCH_PROJECTED_MULT      = 1.5;
	const INSPECT_BATCH_PROJECTED_FLOOR_SEC = 3.0;

	/**
	 * Cross-tick retry schedule for a transient `/v1/inspect`
	 * failure (transport error / timeout / 5xx). One entry per retry; the
	 * value is the minimum delay in seconds before the batch may be
	 * re-inspected. The first step is 0 — the next worker tick (~5s later,
	 * gated by {@see Segurium_Scan_Runner::MIN_TICK_WALL_SEC}) picks the
	 * batch up without any added wait. Later steps ramp and cap at 600s so a
	 * long CTI outage never delays a single batch more than ~10 minutes per
	 * round. The retry happens ACROSS ticks (the failed inspect just defers
	 * the chunk); we never block inside a tick or sleep, so behaviour does
	 * not depend on PHP's `max_execution_time`.
	 *
	 * After the last step is exhausted the batch is counted `failed` — the
	 * pre-578 behaviour, but only after bounded retries instead of on the
	 * first transient blip. The total span is ~0+30+60+120+300+600 ≈ 18min
	 * of wall-clock before a batch is abandoned.
	 */
	const INSPECT_RETRY_BACKOFF_SEC = array( 0, 30, 60, 120, 300, 600 );

	/**
	 * Verdict code returned by `/v1/inspect` for a hash that no tier could
	 * resolve. The pipeline reacts by sending the body to `/v1/neo-ray`.
	 */
	const VERDICT_UNKNOWN = 4;

	/**
	 * The file is clean, but its bytes belong to a component
	 * release with a known vulnerability. Handled exactly like a clean
	 * verdict here — no threat count, no file_state row, no UI change. The
	 * append-only `scan_findings` row is persistence for a later feature.
	 */
	const VERDICT_VULNERABLE = 5;

	/**
	 * `scan_findings.status` used for a vulnerable observation. Deliberately
	 * outside the status vocabulary every read path selects on ('open',
	 * 'ignored', 'cured', 'fixed', 'restored'), so the row stays invisible
	 * until something is built to read it.
	 */
	const STATUS_VULNERABLE = 'vulnerable';


	/**
	 * Upper bound on a file body sent to `/v1/neo-ray`. Must match the
	 * scanner's own MAX_FILE_SIZE so the two tiers agree on what can be
	 * escalated; anything above is counted as a skip at the scanner stage
	 * and so never reaches this queue.
	 */
	const NEO_RAY_MAX_BODY = 104857600;

	const MAX_WORKER_DEATHS_PER_FILE = 2;

	/**
	 * Mapping from the `/v1/neo-ray` verdict string to the numeric verdict
	 * codes used by the rest of the pipeline.
	 */
	const NEO_RAY_VERDICT_MAP = array(
		'clean'     => 0,
		'malicious' => 1,
		'injection' => 2,
	);

	/**
	 * CTI client instance.
	 *
	 * @var Segurium_CTI_Client
	 */
	private $cti_client;

	/**
	 * Scan UUID this queue is working for.
	 *
	 * @var string
	 */
	private $scan_id = '';

	/**
	 * Absolute filesystem root of the current scan. Needed so the Neo-Ray
	 * escalation phase can resolve the relative path stored alongside each
	 * hash back to on-disk bytes.
	 *
	 * @var string
	 */
	private $base_path = '';

	/**
	 * Maximum processing time in seconds.
	 *
	 * @var int
	 */
	private $time_limit;

	/**
	 * Effective batch size for this queue instance. Defaults to
	 * {@see BATCH_SIZE}; tests can override via the constructor to exercise
	 * chunking behaviour with smaller fixtures.
	 *
	 * @var int
	 */
	private $batch_size;

	/**
	 * Timestamp when processing started.
	 *
	 * @var float
	 */
	private $start_time = 0.0;

	/**
	 * Whether to process only a single batch.
	 *
	 * @var bool
	 */
	private $single_batch = false;

	/**
	 * Whether a batch has been processed in this run.
	 *
	 * @var bool
	 */
	private $batch_processed = false;

	/**
	 * Rolling window of recent `/v1/inspect` round-trip wall times (seconds).
	 * Used by {@see tick_will_exhaust_before_next_batch()} to project the
	 * cost of starting one more batch.
	 *
	 * @var float[]
	 */
	private $batch_wall_history = array();

	/**
	 * Count of files we have actually escalated to `/v1/neo-ray`
	 * inside the current {@see process()} call. Reset at the top of process().
	 * The tick-budget gate in {@see time_allows_next_unknown()} only fires
	 * when this is non-zero, so the first escalation in any call always
	 * runs and forward progress is guaranteed even on a tight tick.
	 *
	 * @var int
	 */
	private $files_processed_in_call = 0;

	/**
	 * Set true within a {@see process()} call when the head
	 * batch is held by a transient-inspect backoff window (a 5xx/timeout
	 * deferral whose `inspect_next_retry_at` has not yet arrived, or that
	 * was just scheduled). Read by {@see is_inspect_backoff_waiting()} so
	 * the scan engine/runner can end the tick early instead of busy-spinning
	 * the tick budget on a chunk that cannot run yet. Reset to false at the
	 * top of every `process()`.
	 *
	 * @var bool
	 */
	private $inspect_backoff_waiting = false;

	/**
	 * Latched at the start of {@see process()} when the
	 * scan-runner lock currently holds this queue's scan id. The
	 * cancellation checks (per-batch in {@see process_pending} and
	 * per-file via the cancel callable in {@see send_batch}) only fire
	 * when this is true, so realtime/upload paths and unit tests that
	 * never go through the runner keep their previous fire-and-finish
	 * behaviour.
	 *
	 * @var bool
	 */
	private $runner_owned = false;

	/**
	 * Internal state mirror (persisted to runtime_kv on save).
	 *
	 * @var array
	 */
	private $state = array(
		'chunk_in'   => 0,
		'chunk_out'  => 0,
		'scan_stats' => array(),
	);

	/**
	 * Cached JSON of the last state we successfully wrote to
	 * runtime_kv. {@see save_state()} short-circuits when the new payload
	 * is byte-identical, which both eliminates the spin-loop log flood
	 * (1.3M lines / 7 min on the test site) and avoids burning DB write
	 * cycles on no-progress ticks.
	 *
	 * @var string|null Null until the first successful save_state.
	 */
	private $last_persisted_json = null;

	/**
	 * Counters that the per-counter MAX guard refuses to
	 * regress. When a stale-snapshot writer would overwrite a higher value
	 * already in storage, save_state() pulls the row, bumps the in-memory
	 * counter to MAX(memory, storage), then writes — defense-in-depth in
	 * case the atomic mutex ever leaks.
	 */
	const PROTECTED_STAT_COUNTERS = array(
		'submitted',
		'verdicted',
		'failed',
		'threats',
		'neoray_errors',
		'neoray_skipped',
		'worker_deaths',
	);

	/**
	 * Constructor.
	 *
	 * Legacy signature retained so existing call sites do not need touching.
	 * `$data_dir` is ignored — the queue keeps all state in runtime_kv now.
	 *
	 * @param string              $data_dir   Unused; retained for API compatibility.
	 * @param int                 $time_limit Maximum processing time in seconds.
	 * @param Segurium_CTI_Client $cti_client Optional CTI client instance.
	 * @param int|null            $batch_size Override hashes-per-inspect-batch (default: {@see BATCH_SIZE}).
	 *                                        Intended for tests; production code should pass null.
	 */
	public function __construct( $data_dir = '', $time_limit = 25, $cti_client = null, $batch_size = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		unset( $data_dir );
		$this->time_limit = max( 1, (int) $time_limit );
		$this->cti_client = $cti_client;
		$this->batch_size = ( null === $batch_size ) ? self::BATCH_SIZE : max( 1, (int) $batch_size );
	}

	/**
	 * Tell the queue where on disk the scanned tree lives. Must be called
	 * after {@see attach()} (and before {@see process()}) for any scan that
	 * will resolve unknown hashes through the Neo-Ray tier — without it the
	 * escalation phase can't read the file body.
	 *
	 * @param string $path Absolute filesystem root.
	 */
	public function set_base_path( $path ) {
		$this->base_path = (string) $path;
	}

	/**
	 * Bind this queue instance to a scan id and load any persisted state.
	 *
	 * @param string $scan_id Scan UUID.
	 */
	public function attach( $scan_id ) {
		$this->scan_id = (string) $scan_id;
		$this->load_state();
	}

	/**
	 * Initialise a new queue session for a scan.
	 *
	 * @param string $scan_id Optional scan UUID. When empty the previously
	 *                        attached scan id is reused.
	 * @return void
	 */
	public function init( $scan_id = '' ) {
		if ( '' !== $scan_id ) {
			$this->scan_id = (string) $scan_id;
		}
		$this->state = array(
			'chunk_in'   => 0,
			'chunk_out'  => 0,
			'scan_stats' => array(),
		);
		$this->ensure_scan_stats( $this->scan_id );
		$this->save_state();
	}

	/**
	 * Submit files for verdict inspection.
	 *
	 * @param array  $files   Array of file records to inspect.
	 * @param string $scan_id Identifier for the scan session.
	 * @return bool True on success, false if queue is full.
	 */
	public function submit( $files, $scan_id ) {
		if ( empty( $files ) ) {
			return true;
		}
		$this->scan_id = (string) $scan_id;
		$buffered      = $this->load_pending_tail();
		$backlog       = ( $this->state['chunk_in'] - $this->state['chunk_out'] ) * $this->batch_size + count( $buffered );
		if ( $backlog + count( $files ) > static::MAX_QUEUE_SIZE ) {
			return false;
		}

		$this->ensure_scan_stats( $scan_id );
		foreach ( $files as $file ) {
			$file['scan_id'] = $scan_id;
			$buffered[]      = $file;
			if ( count( $buffered ) >= $this->batch_size ) {
				$this->store_chunk( $this->state['chunk_in'], $buffered );
				++$this->state['chunk_in'];
				$buffered = array();
			}
		}
		$this->store_chunk( $this->state['chunk_in'], $buffered );

		$this->state['scan_stats'][ $scan_id ]['submitted'] += count( $files );
		$this->save_state();
		return true;
	}

	/**
	 * Process pending batches within the time limit. Each chunk is routed
	 * through {@see resolve_and_record} so malware/realtime/upload scans
	 * share one verdict-handling code path.
	 *
	 * @param bool $single_batch Whether to stop after one batch.
	 * @return void
	 */
	public function process( $single_batch = false ) {
		if ( '' === $this->scan_id ) {
			return;
		}
		$this->start_time              = microtime( true );
		$this->single_batch            = (bool) $single_batch;
		$this->batch_processed         = false;
		$this->batch_wall_history      = array();
		$this->files_processed_in_call = 0;
		$this->inspect_backoff_waiting = false;
		$this->runner_owned            = class_exists( 'Segurium_Scan_Runner' )
			&& Segurium_Scan_Runner::is_scan_lock_held( $this->scan_id );

		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			$st0 = $this->state['scan_stats'][ $this->scan_id ] ?? array();
			Segurium_Scan_Runner::debug(
				'queue_process_in',
				array(
					'pid'       => getmypid(),
					't'         => microtime( true ),
					'scan'      => substr( $this->scan_id, 0, 8 ),
					'single'    => $this->single_batch ? 1 : 0,
					'submitted' => (int) ( $st0['submitted'] ?? 0 ),
					'verdicted' => (int) ( $st0['verdicted'] ?? 0 ),
					'chunk_in'  => (int) $this->state['chunk_in'],
					'chunk_out' => (int) $this->state['chunk_out'],
				)
			);
		}

		$this->process_pending();
		$this->save_state();

		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			$st1 = $this->state['scan_stats'][ $this->scan_id ] ?? array();
			Segurium_Scan_Runner::debug(
				'queue_process_out',
				array(
					'pid'       => getmypid(),
					't'         => microtime( true ),
					'scan'      => substr( $this->scan_id, 0, 8 ),
					'elapsed'   => microtime( true ) - $this->start_time,
					'verdicted' => (int) ( $st1['verdicted'] ?? 0 ),
					'chunk_out' => (int) $this->state['chunk_out'],
				)
			);
		}
	}

	/**
	 * Mark a scan as having all files submitted so the drain loop can flush
	 * partial buffers.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return void
	 */
	public function mark_submissions_complete( $scan_id ) {
		$this->ensure_scan_stats( $scan_id );
		$this->state['scan_stats'][ $scan_id ]['submissions_complete'] = true;
		$tail = $this->load_pending_tail();
		if ( ! empty( $tail ) ) {
			++$this->state['chunk_in'];
		}
		$this->save_state();
	}

	/**
	 * Whether the last {@see process()} call ended because the
	 * head batch is parked in a transient-inspect backoff window (nothing
	 * drainable until `inspect_next_retry_at`). The scan engine surfaces this
	 * to the runner so the tick ends early instead of spinning the budget.
	 *
	 * @return bool
	 */
	public function is_inspect_backoff_waiting() {
		return $this->inspect_backoff_waiting;
	}

	/**
	 * Get statistics for a given scan.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return array Scan statistics array.
	 */
	public function get_scan_stats( $scan_id ) {
		$base = isset( $this->state['scan_stats'][ $scan_id ] )
			? $this->state['scan_stats'][ $scan_id ]
			: $this->default_stats();

		// Fold async-poller verdicts into the chunk-loop
		// stat block so progress UI consumers (`files_verdicted`,
		// `threats_found`, etc.) catch up monotonically as the async
		// poller drains `/v1/scan/results`. `apply_async_verdict()`
		// maintains a per-scan runtime_kv tally row whose layout matches
		// the keys below; we only add the deltas the chunk loop itself
		// can't observe.
		if ( '' === (string) $scan_id ) {
			return $base;
		}
		$tally = self::load_async_tally( $scan_id );
		foreach ( array( 'verdicted', 'threats', 'failed', 'neoray_errors', 'neoray_skipped' ) as $key ) {
			$base[ $key ] = (int) ( $base[ $key ] ?? 0 ) + (int) ( $tally[ $key ] ?? 0 );
		}
		return $base;
	}

	/**
	 * Check whether all submitted files for a scan have been processed.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return bool True if the scan is complete.
	 */
	public function is_scan_complete( $scan_id ) {
		$stats = $this->get_scan_stats( $scan_id );
		if ( ! $stats['submissions_complete'] ) {
			return false;
		}
		if ( (int) $this->state['chunk_in'] !== (int) $this->state['chunk_out'] ) {
			return false;
		}
		// Structural drain test: trust the queue's data structures, not
		// per-scan counter arithmetic. That invariant proved fragile under
		// cancel / retry / dup response paths; the bitreverse-2026-05-08
		// incident showed it
		// can also break under cold-CAS workloads where every file
		// escalates to neo-ray. With submissions_complete + all sealed
		// chunks drained + an empty open tail, no path can produce
		// further verdicts from the queue side.
		if ( ! empty( $this->load_pending_tail() ) ) {
			return false;
		}
		// Async-batched malware scans hand Unknown files
		// off to the submitter, then return from the chunk pass before
		// the poller has applied verdicts. The pending table keeps
		// is_scan_complete() honest under the new flow — drained queue
		// + no async_pending rows means no more verdicts can arrive.
		// A cheap LIMIT 1 EXISTS probe, not a whole-blob load.
		return ! Segurium_Async_Scan_Submitter::has_pending( $scan_id );
	}

	/**
	 * Seal async-pending paths that can never receive a
	 * verdict.
	 *
	 * The async results loop calls this once CTI has confirmed its
	 * server-side queue for the scan is empty (`queue_depth == 0`) AND
	 * the plugin has finished submitting. At that point any sha still
	 * sitting in the pending-paths map will never produce a verdict
	 * (e.g. it was deduped server-side, or echoed as accepted in the
	 * submit reply but never enqueued as a distinct job). Leaving it
	 * there wedges {@see is_scan_complete()} forever and the results
	 * loop polls an empty endpoint indefinitely (the
	 * infinite-empty-poll).
	 *
	 * Each orphaned path is counted as `failed` (honest accounting — it
	 * was submitted but never verdicted) and the pending row is cleared
	 * so `is_scan_complete()` can return true on the next tick.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return int Number of orphaned paths sealed.
	 */
	public static function seal_unresolved_paths( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return 0;
		}
		// Count + delete the scan's pending rows by index
		// instead of loading the whole blob. Every pending row is one
		// submitted-but-unverdicted path, so the count is the seal total.
		$sealed = Segurium_Async_Scan_Submitter::count_pending( $scan_id );
		if ( $sealed <= 0 ) {
			return 0;
		}
		// Fold the whole orphan count into the tally in one shot — the per
		// path bump in the old blob loop was equivalent but O(rows) round
		// trips. Dropping all pending rows satisfies is_scan_complete()'s
		// async-pending gate on the next tick.
		self::bump_async_tally( $scan_id, array( 'failed' => $sealed ) );
		Segurium_Async_Scan_Submitter::delete_all_pending( $scan_id );
		return $sealed;
	}

	/**
	 * Files the next listing pass may add: a tenth of the cap, or 0 while the
	 * backlog leaves room for less than two passes. The second pass covers
	 * rows a crashed tick listed but never submitted.
	 *
	 * @return int
	 */
	public function listing_pass_size() {
		$pass    = (int) ceil( static::MAX_QUEUE_SIZE / 10 );
		$backlog = ( $this->state['chunk_in'] - $this->state['chunk_out'] + 1 ) * $this->batch_size;
		return $backlog + 2 * $pass <= static::MAX_QUEUE_SIZE ? $pass : 0;
	}

	/**
	 * Return the current public state snapshot. Used by the orchestrator for
	 * progress reporting.
	 *
	 * @return array
	 */
	public function get_state() {
		return array(
			'pending_chunks' => max( 0, (int) $this->state['chunk_in'] - (int) $this->state['chunk_out'] )
				+ ( count( $this->load_pending_tail() ) > 0 ? 1 : 0 ),
			'scan_stats'     => $this->state['scan_stats'],
			'result_file'    => '',
		);
	}

	/**
	 * Replace the internal state with the given array. Used by tests.
	 *
	 * @param array $state State snapshot.
	 */
	public function set_state( $state ) {
		$defaults    = array(
			'chunk_in'   => 0,
			'chunk_out'  => 0,
			'scan_stats' => array(),
		);
		$this->state = array_merge( $defaults, is_array( $state ) ? $state : array() );
	}

	/**
	 * Load queue state from runtime_kv.
	 *
	 * @return bool True on success, false when no state is persisted yet.
	 */
	public function load_state() {
		if ( '' === $this->scan_id ) {
			return false;
		}
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $this->kv_state_key() )
		);
		if ( null === $raw ) {
			return false;
		}
		$decoded = json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) ) {
			return false;
		}
		$this->set_state( $decoded );
		// Prime the no-op-skip cache so the first save_state()
		// after load doesn't write redundant rows when nothing changed.
		$this->last_persisted_json = (string) wp_json_encode( $this->state );
		return true;
	}

	/**
	 * Persist the current queue state to runtime_kv.
	 *
	 * @return void
	 */
	public function save_state() {
		if ( '' === $this->scan_id ) {
			return;
		}

		// Step 1 — per-counter MAX guard. Re-read the current
		// row and bump in-memory counters that fell behind storage. This
		// runs before the no-op check so a stale-snapshot caller still
		// reconciles silently with what the active writer has persisted.
		$this->reconcile_counters_from_storage();

		// Step 2 — no-op skip. After reconciliation, if the
		// resulting JSON matches what we last wrote, skip both the DB
		// upsert and the diagnostic log line. This is what kept
		// the test site's debug.log from a 655 MB flood once the runner
		// went into open-loop spin behind a stuck is_scan_complete().
		$payload = (string) wp_json_encode( $this->state );
		if ( null !== $this->last_persisted_json && $payload === $this->last_persisted_json ) {
			return;
		}

		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $this->kv_state_key(),
				'kv_value'   => $payload,
				'expires_at' => $now + self::KV_TTL,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
		$this->last_persisted_json = $payload;

		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			$st = $this->state['scan_stats'][ $this->scan_id ] ?? array();
			Segurium_Scan_Runner::debug(
				'queue_save_state',
				array(
					'pid'          => getmypid(),
					't'            => microtime( true ),
					'scan'         => substr( $this->scan_id, 0, 8 ),
					'submitted'    => (int) ( $st['submitted'] ?? 0 ),
					'verdicted'    => (int) ( $st['verdicted'] ?? 0 ),
					'failed'       => (int) ( $st['failed'] ?? 0 ),
					'threats'      => (int) ( $st['threats'] ?? 0 ),
					'ns'           => (int) ( $st['neoray_skipped'] ?? 0 ),
					'ne'           => (int) ( $st['neoray_errors'] ?? 0 ),
					'chunk_in'     => (int) $this->state['chunk_in'],
					'chunk_out'    => (int) $this->state['chunk_out'],
					'sub_complete' => ! empty( $st['submissions_complete'] ) ? '1' : '0',
				)
			);
		}
	}

	/**
	 * Per-counter MAX guard. Pulls the persisted state row
	 * and reconciles each in-memory counter to MAX(memory, storage). The
	 * `PROTECTED_STAT_COUNTERS` list covers everything the queue
	 * monotonically increments per-scan; chunk_in / chunk_out are
	 * reconciled too because they advance during submit() and
	 * process_pending() respectively. Booleans (submissions_complete) and
	 * arrays (unknowns) are left to the no-op check above — they don't
	 * count up.
	 *
	 * Reads the row even when we have a fresh `last_persisted_json` cached:
	 * another worker may have written after our last save, and we must not
	 * regress those increments. Falls back to a noop when the row is
	 * missing (first save in this scan's lifetime).
	 *
	 * @return void
	 */
	private function reconcile_counters_from_storage() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $this->kv_state_key() )
		);
		if ( null === $raw ) {
			return;
		}
		$persisted = json_decode( (string) $raw, true );
		if ( ! is_array( $persisted ) ) {
			return;
		}

		$persisted_in  = isset( $persisted['chunk_in'] ) ? (int) $persisted['chunk_in'] : 0;
		$persisted_out = isset( $persisted['chunk_out'] ) ? (int) $persisted['chunk_out'] : 0;
		if ( $persisted_in > (int) $this->state['chunk_in'] ) {
			$this->state['chunk_in'] = $persisted_in;
		}
		if ( $persisted_out > (int) $this->state['chunk_out'] ) {
			$this->state['chunk_out'] = $persisted_out;
		}

		if ( ! isset( $persisted['scan_stats'] ) || ! is_array( $persisted['scan_stats'] ) ) {
			return;
		}
		foreach ( $persisted['scan_stats'] as $sid => $persisted_stats ) {
			if ( ! is_array( $persisted_stats ) ) {
				continue;
			}
			if ( ! isset( $this->state['scan_stats'][ $sid ] ) ) {
				$this->state['scan_stats'][ $sid ] = $persisted_stats;
				continue;
			}
			$this->ensure_scan_stats( $sid );
			foreach ( self::PROTECTED_STAT_COUNTERS as $key ) {
				$persisted_value = isset( $persisted_stats[ $key ] ) ? (int) $persisted_stats[ $key ] : 0;
				$memory_value    = isset( $this->state['scan_stats'][ $sid ][ $key ] ) ? (int) $this->state['scan_stats'][ $sid ][ $key ] : 0;
				if ( $persisted_value > $memory_value ) {
					$this->state['scan_stats'][ $sid ][ $key ] = $persisted_value;
				}
			}
			// submissions_complete is a one-way switch: once any worker
			// flips it true, others must not flip it back to false on a
			// stale write.
			if ( ! empty( $persisted_stats['submissions_complete'] ) && empty( $this->state['scan_stats'][ $sid ]['submissions_complete'] ) ) {
				$this->state['scan_stats'][ $sid ]['submissions_complete'] = true;
			}
		}
	}

	/**
	 * Delete every runtime_kv row owned by this queue (state + chunks).
	 *
	 * @return void
	 */
	public function purge() {
		if ( '' === $this->scan_id ) {
			return;
		}
		global $wpdb;
		$table = Segurium_Storage::table_name( 'runtime_kv' );
		$like  = $wpdb->esc_like( 'scan:' . $this->scan_id . ':' ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE kv_key LIKE %s', $table, $like ) );
		// Row is gone, so the next save_state must write
		// (no-op skip would otherwise short-circuit if the in-memory state
		// was still byte-equal to what we last persisted in this process).
		$this->last_persisted_json = null;
	}

	/**
	 * Return the configured CTI client. Used by tests.
	 *
	 * @return Segurium_CTI_Client
	 */
	public function get_cti_client() {
		return $this->cti_client;
	}

	/**
	 * Resolve a batch of files in one synchronous pass and write findings.
	 *
	 * Single entry point shared by the malware queue (per chunk), realtime
	 * scan, and upload scan. Pipeline: `/v1/inspect` → for verdict=4 rows,
	 * `/v1/neo-ray` → write `scan_findings` for threats. No retries; on a
	 * `/v1/inspect` transport error every file in the batch is counted as
	 * `failed`.
	 *
	 * @param string                   $scan_id   Scan UUID to attribute findings to.
	 * @param string                   $scan_type Scan type; drives the `detector`
	 *                                             column on findings
	 *                                             (malware → `scanner`,
	 *                                             realtime → `realtime`,
	 *                                             upload → `upload`).
	 * @param array                    $files     Records `{path, sha256, size, mtime}`.
	 * @param string                   $base_path Absolute root used to read bodies
	 *                                             for Neo-Ray escalation. Empty
	 *                                             disables escalation (unknowns
	 *                                             are counted as `failed`).
	 * @param Segurium_CTI_Client|null $cti          Optional client; defaults to
	 *                                                the shared storage façade.
	 * @param callable|null            $cancel_check Optional cooperative
	 *                                                cancellation callable —
	 *                                                returns true once
	 *                                                processing should stop.
	 *                                                Evaluated at the top of
	 *                                                every per-file iteration
	 *                                                so the in-flight batch
	 *                                                can bail
	 *                                                without firing the
	 *                                                remaining `/v1/neo-ray`
	 *                                                escalations after the
	 *                                                user clicks Stop. Pass
	 *                                                `null` for synchronous
	 *                                                callers (realtime/upload).
	 * @return array Stat block `{submitted, verdicted, threats, failed,
	 *               neoray_errors, neoray_skipped, failed_paths}`.
	 *               `failed_paths` lists the submitted path of every file
	 *               that got no `/v1/inspect` verdict; a failed Neo-Ray
	 *               escalation counts in `failed` only.
	 *
	 * @throws RuntimeException When the tick lease was taken over by another
	 *                          worker mid-chunk; the runner ends the tick.
	 */
	public static function resolve_and_record(
		string $scan_id,
		string $scan_type,
		array $files,
		string $base_path = '',
		?Segurium_CTI_Client $cti = null,
		?callable $cancel_check = null
	): array {
		$stats = array(
			'submitted'      => count( $files ),
			'verdicted'      => 0,
			'threats'        => 0,
			'failed'         => 0,
			'neoray_errors'  => 0,
			'neoray_skipped' => 0,
			'failed_paths'   => array(),
		);
		if ( empty( $files ) ) {
			return $stats;
		}

		$detector = self::detector_for_scan_type( $scan_type );
		$payload  = array();
		foreach ( $files as $f ) {
			$rec = $f;
			unset( $rec['scan_id'] );
			$payload[] = $rec;
		}

		$result = self::dispatch_inspect_static( $cti, $payload, $scan_id );
		if ( is_wp_error( $result ) ) {
			Segurium_Debug::log(
				sprintf(
					'[segurium-verdict-queue] inspect failed (%s): %s',
					$result->get_error_code(),
					$result->get_error_message()
				)
			);
		}
		if ( is_wp_error( $result ) || ! is_array( $result ) ) {
			$stats['failed']       = $stats['submitted'];
			$stats['failed_paths'] = array_column( $payload, 'path' );
			return $stats;
		}

		// Index the inspect response by sha256 so that each
		// submitted file contributes exactly one increment to the stat
		// block — even if CTI returns duplicate or unrequested entries.
		// Iterating over the response directly used to allow `verdicted`
		// to overshoot `submitted`, which left `is_scan_complete()`
		// unreachable for the rest of the scan's lifetime.
		$verdict_by_sha = array();
		foreach ( $result as $item ) {
			$sha = isset( $item['sha256'] ) ? (string) $item['sha256'] : '';
			if ( '' === $sha || isset( $verdict_by_sha[ $sha ] ) ) {
				continue;
			}
			$verdict_by_sha[ $sha ] = $item;
		}

		$now = time();
		// Per-file heartbeat refresh. The chunk loop in
		// Segurium_Scan_Runner only stamps the lock heartbeat at chunk
		// boundaries, but a single chunk can spend tens of seconds inside
		// resolve_unknown() (one /v1/neo-ray RTT per Unknown file, capped at
		// ~30 s each). Stamping per file lets the watchdog reclaim a dead
		// worker within HEARTBEAT_MAX_AGE of the actual stall instead of
		// waiting for the next chunk boundary. The extra cost is one
		// option_get + (when the lock matches) one option_set per file —
		// dwarfed by the CTI/Neo-Ray HTTP round-trip already happening.
		// Gated to `malware` scans because realtime/upload paths don't hold
		// a Segurium_Scan_Lock; heartbeat() would just no-op for them.
		// Every per-file heartbeat ALSO renews the runtime_kv
		// tick-mutex lease. Without this the lease drifts past `expires_at`
		// during a long verdict_queue->process() pass and a concurrent
		// life_support_system call self-heals a still-live mutex, putting
		// two workers on one scan.
		$track_heartbeat = ( 'malware' === $scan_type );
		$async_submitter = null;
		foreach ( $files as $f ) {
			if ( $track_heartbeat && class_exists( 'Segurium_Scan_Runner' )
				&& ! Segurium_Scan_Runner::renew_liveness( $scan_id ) ) {
				// Another driver owns the scan now; abandon the
				// rest of this chunk so the cursor is not advanced twice.
				throw new RuntimeException( 'scan tick lost its lease mid-chunk; another worker took the scan over' );
			}
			$sha256 = isset( $f['sha256'] ) ? (string) $f['sha256'] : '';
			$path   = isset( $f['path'] ) ? (string) $f['path'] : '';
			if ( '' === $sha256 || ! isset( $verdict_by_sha[ $sha256 ] ) ) {
				++$stats['failed'];
				$stats['failed_paths'][] = $path;
				continue;
			}
			$item     = $verdict_by_sha[ $sha256 ];
			$verdict  = isset( $item['verdict'] ) ? (int) $item['verdict'] : 0;
			$resp_pth = isset( $item['path'] ) ? (string) $item['path'] : '';
			if ( '' !== $resp_pth ) {
				$path = $resp_pth;
			}

			if ( self::VERDICT_UNKNOWN === $verdict ) {
				// Cancellation skips the slow per-file
				// `/v1/neo-ray` escalation. Earlier this break sat at the
				// top of the loop, which silently dropped every remaining
				// file in the chunk — the chunk had already been deleted
				// and `chunk_out` advanced by `process_pending`, so those
				// files were never accounted in `verdicted/failed/
				// neoray_skipped`, leaving `is_scan_complete()` permanently
				// false and the scan stalled. Counting cancelled-unknowns
				// as `neoray_skipped` keeps the
				// `verdicted+failed+neoray_skipped == submitted` invariant
				// regardless of cancel timing.
				if ( null !== $cancel_check && (bool) call_user_func( $cancel_check ) ) {
					self::count_skip( $stats, 'cancelled' );
					continue;
				}
				// Malware scans dispatch Unknown files in
				// batches via the async submitter — one `/v1/scan/submit`
				// POST per ~100 files, verdicts collected later by the
				// async poller. Realtime / upload scans stay on the sync
				// facade because the caller needs the verdict before
				// returning to the user.
				if ( 'malware' === $scan_type ) {
					if ( null === $async_submitter ) {
						$async_submitter = new Segurium_Async_Scan_Submitter( $scan_id, $detector, $cti );
					}
					try {
						self::enqueue_unknown_async( $scan_id, $detector, $sha256, $path, $base_path, $async_submitter, $stats, $now );
					} catch ( Throwable $escalation_exc ) {
						self::count_skip( $stats, 'escalation_threw' );
						self::log_escalation_skip(
							$scan_id,
							array(
								'sha256' => $sha256,
								'path'   => $path,
							),
							'escalation_threw',
							get_class( $escalation_exc ) . ': ' . $escalation_exc->getMessage()
						);
					}
					continue;
				}
				// Realtime and upload stay unguarded on purpose: both gate
				// content the user is about to be served, and both callers
				// treat a raised error as "not cleared". Swallowing it here
				// would return an unscanned file as clean.
				self::resolve_unknown( $scan_id, $detector, $sha256, $path, $base_path, $cti, $stats, $now );
				continue;
			}
			self::apply_verdict( $scan_id, $detector, $sha256, $path, $verdict, $stats, $now );
		}

		if ( null !== $async_submitter ) {
			self::flush_submitter_guarded( $async_submitter, $stats, $scan_id );
		}

		return $stats;
	}

	/**
	 * Apply one async-pipeline verdict to local state.
	 *
	 * Hooked into by {@see Segurium_Async_Scan_Results_Loop::apply_row()}. The
	 * verdict string follows the `/v1/scan/results` contract
	 * (`clean`|`malware`|`error`); a per-scan async-tally row is bumped
	 * in `runtime_kv` so the scan-runner's completion check can see
	 * progress that crossed request boundaries. Errors are counted but
	 * never create a `scan_findings` row.
	 *
	 * @param string $scan_id  Scan UUID.
	 * @param string $detector Detector label (`scanner`/`realtime`/`upload`).
	 * @param string $sha256   File SHA-256 (lowercase hex).
	 * @param string $path     Site-relative path resolved from the pending map.
	 * @param string $verdict  Async verdict string.
	 * @return bool True when the verdict produced a state change
	 *              (scan_findings upsert or counter increment).
	 */
	public static function apply_async_verdict( $scan_id, $detector, $sha256, $path, $verdict ) {
		$scan_id  = (string) $scan_id;
		$detector = (string) $detector;
		$sha256   = strtolower( (string) $sha256 );
		$path     = (string) $path;
		$verdict  = strtolower( trim( (string) $verdict ) );
		if ( '' === $scan_id || '' === $sha256 ) {
			return false;
		}

		$now   = time();
		$stats = array(
			'submitted'      => 1,
			'verdicted'      => 0,
			'threats'        => 0,
			'failed'         => 0,
			'neoray_errors'  => 0,
			'neoray_skipped' => 0,
		);

		if ( 'clean' === $verdict ) {
			self::apply_verdict( $scan_id, $detector, $sha256, $path, 0, $stats, $now );
		} elseif ( 'malware' === $verdict ) {
			self::apply_verdict( $scan_id, $detector, $sha256, $path, 1, $stats, $now );
		} else {
			// 'error' or any unknown value — count as a Neo-Ray failure
			// so the operator surface mirrors the legacy semantics. Do
			// NOT write scan_findings; an erroring engine produced no
			// usable verdict.
			++$stats['failed'];
			++$stats['neoray_errors'];
		}

		self::bump_async_tally( $scan_id, $stats );
		return true;
	}

	/**
	 * Accumulate per-scan async-pipeline counters into a runtime_kv row
	 * keyed by `async_scan:tally:<scan_id>`. Read by the scan runner's
	 * completion check; ignored otherwise. Tiny payload — JSON object
	 * with the same stat keys as {@see resolve_and_record}.
	 *
	 * @param string $scan_id Scan UUID.
	 * @param array  $delta   Stat block to fold in.
	 * @return void
	 */
	private static function bump_async_tally( $scan_id, array $delta ) {
		$key  = 'async_scan:tally:' . $scan_id;
		$json = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $key )
		);
		$cur  = is_string( $json ) && '' !== $json ? json_decode( $json, true ) : array();
		if ( ! is_array( $cur ) ) {
			$cur = array();
		}
		foreach ( $delta as $k => $v ) {
			$cur[ $k ] = (int) ( isset( $cur[ $k ] ) ? $cur[ $k ] : 0 ) + (int) $v;
		}
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $key,
				'kv_value'   => (string) wp_json_encode( $cur ),
				'expires_at' => $now + 86400,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Read the per-scan async-pipeline tally. Returns an empty stat
	 * block when no row exists. Public so the scan runner can fold the
	 * counters into its progress UI / completion check without leaking
	 * runtime_kv layout details.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return array Stat block (`submitted`, `verdicted`, `threats`,
	 *               `failed`, `neoray_errors`, `neoray_skipped`).
	 */
	public static function load_async_tally( $scan_id ) {
		$key  = 'async_scan:tally:' . (string) $scan_id;
		$json = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $key )
		);
		$cur  = is_string( $json ) && '' !== $json ? json_decode( $json, true ) : array();
		if ( ! is_array( $cur ) ) {
			$cur = array();
		}
		return array(
			'submitted'      => isset( $cur['submitted'] ) ? (int) $cur['submitted'] : 0,
			'verdicted'      => isset( $cur['verdicted'] ) ? (int) $cur['verdicted'] : 0,
			'threats'        => isset( $cur['threats'] ) ? (int) $cur['threats'] : 0,
			'failed'         => isset( $cur['failed'] ) ? (int) $cur['failed'] : 0,
			'neoray_errors'  => isset( $cur['neoray_errors'] ) ? (int) $cur['neoray_errors'] : 0,
			'neoray_skipped' => isset( $cur['neoray_skipped'] ) ? (int) $cur['neoray_skipped'] : 0,
		);
	}

	/**
	 * Persist a vulnerable observation without surfacing it.
	 *
	 * `scan_findings` is an append-only event log; `file_state` is the only
	 * source the UI reads for current status per file. A row
	 * here with a status outside the read vocabulary is therefore invisible
	 * to every list, counter and tab, while still recording which file on
	 * which scan CTI reported as belonging to a vulnerable component.
	 *
	 * @param string $scan_id  Scan UUID.
	 * @param string $detector Detector label for the scan type.
	 * @param string $sha256   File hash.
	 * @param string $path     Relative file path.
	 * @param int    $now      Timestamp.
	 * @return void
	 */
	private static function record_vulnerable( $scan_id, $detector, $sha256, $path, $now ) {
		if ( '' === $path || '' === $sha256 ) {
			return;
		}
		$path_hash = hash( 'sha256', $path );
		try {
			// scan_findings is never pruned and the upsert key carries
			// scan_uuid, so without this a daily scan would add one row per
			// vulnerable file per scan forever. Only the newest observation
			// per file is useful, so drop every earlier one first. Growth is
			// then bounded by the number of vulnerable files, not by scan
			// count. Scoped to STATUS_VULNERABLE, so a real finding for the
			// same path is never touched.
			Segurium_Storage::table_delete(
				'scan_findings',
				array(
					'file_path_hash' => $path_hash,
					'status'         => self::STATUS_VULNERABLE,
				)
			);
			Segurium_Storage::table_upsert(
				'scan_findings',
				array(
					'scan_uuid'      => (string) $scan_id,
					'file_path'      => $path,
					'file_path_hash' => $path_hash,
					'sha256'         => $sha256,
					'verdict'        => (string) self::VERDICT_VULNERABLE,
					'severity'       => 0,
					'status'         => self::STATUS_VULNERABLE,
					'backup_id'      => null,
					'detector'       => $detector,
					'created_at'     => (int) $now,
					'resolved_at'    => null,
				),
				array( 'scan_uuid', 'file_path_hash' )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log(
				'[segurium-verdict-queue] vulnerable upsert failed: ' . $e->getMessage()
			);
		}
	}

	/**
	 * Route a normal (non-unknown) verdict into the stat block and, when
	 * malicious, into `scan_findings`.
	 *
	 * @param string $scan_id  Scan UUID.
	 * @param string $detector Detector column value.
	 * @param string $sha256   File SHA-256.
	 * @param string $path     Relative path.
	 * @param int    $verdict  CTI verdict code.
	 * @param array  $stats    Stat block (by reference).
	 * @param int    $now      Timestamp.
	 */
	private static function apply_verdict( $scan_id, $detector, $sha256, $path, $verdict, array &$stats, $now ) {
		++$stats['verdicted'];

		// A vulnerable file is a CLEAN file that happens to
		// belong to an outdated component. It takes the clean path below —
		// same reconciliation, no threat counter, no file_state row — and
		// only leaves an append-only trace in scan_findings.
		$is_vulnerable = ( self::VERDICT_VULNERABLE === (int) $verdict );
		if ( $is_vulnerable ) {
			self::record_vulnerable( $scan_id, $detector, $sha256, $path, $now );
		}

		if ( $is_vulnerable || $verdict <= 0 ) {
			// When CTI flips a previously-detected file to
			// Safe (scanner fix, false-positive correction, etc.),
			// reconcile the projection here so the row disappears from
			// the "still detected" UI without waiting for
			// finalize_scan reconciliation — which never runs when the
			// scan aborts (HEARTBEAT_STALE) or when the scheduled scan
			// loop hangs before completion. mark_fixed_by_hashes is
			// filtered on current_status='open', so ignored/cured rows
			// are preserved and never-flagged paths produce a no-op
			// single-row UPDATE on a unique index.
			if ( '' !== $path ) {
				Segurium_File_State::mark_fixed_by_hashes(
					array( hash( 'sha256', (string) $path ) ),
					(int) $now
				);
			}
			return;
		}
		++$stats['threats'];
		if ( '' === $path || '' === $sha256 ) {
			return;
		}
		$severity = $verdict > 1 ? 2 : 1;
		try {
			Segurium_Storage::table_upsert(
				'scan_findings',
				array(
					'scan_uuid'      => (string) $scan_id,
					'file_path'      => $path,
					'file_path_hash' => hash( 'sha256', $path ),
					'sha256'         => $sha256,
					'verdict'        => (string) $verdict,
					'severity'       => $severity,
					'status'         => 'open',
					'backup_id'      => null,
					'detector'       => $detector,
					'created_at'     => (int) $now,
					'resolved_at'    => null,
				),
				array( 'scan_uuid', 'file_path_hash' )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log(
				'[segurium-verdict-queue] finding upsert failed: ' . $e->getMessage()
			);
		}
		Segurium_File_State::record_finding(
			array(
				'scan_uuid' => (string) $scan_id,
				'file_path' => $path,
				'sha256'    => $sha256,
				'verdict'   => (int) $verdict,
				'severity'  => $severity,
				'detector'  => $detector,
				'timestamp' => (int) $now,
			)
		);
	}

	/**
	 * Shared validation gate for both Unknown escalation paths. Returns
	 * the file body to escalate, or null when the caller should bail
	 * because the stat block was already updated (failed / skipped) or
	 * the file was short-circuited to a clean verdict (log-file drift).
	 *
	 * @param string                             $scan_id   Scan UUID.
	 * @param string                             $detector  Detector label.
	 * @param string                             $sha256    File SHA-256.
	 * @param string                             $path      Relative path.
	 * @param string                             $base_path Absolute root.
	 * @param array                              $stats     Stat block (by reference).
	 * @param int                                $now       Timestamp.
	 * @param Segurium_Async_Scan_Submitter|null $submitter Batch submitter the
	 *                                                      body is bound for,
	 *                                                      whose ceiling judges
	 *                                                      the file before the
	 *                                                      read. Null on the
	 *                                                      sync path, which
	 *                                                      posts one body to
	 *                                                      `/v1/neo-ray` and
	 *                                                      has no batch.
	 * @return string|null Body to escalate, or null when handled.
	 */
	private static function load_unknown_body( $scan_id, $detector, $sha256, $path, $base_path, array &$stats, $now, ?Segurium_Async_Scan_Submitter $submitter = null ) {
		// On-premise means an Unknown hash stays unresolved.
		// Counted as `neoray_skipped` — the same bucket an oversize file
		// lands in — so `verdicted + failed + neoray_skipped == submitted`
		// holds and the scan settles instead of stalling on a verdict that
		// can never arrive. The body is never read off disk.
		if ( Segurium_Storage::on_premise_mode() ) {
			self::count_skip( $stats, 'on_premise' );
			// `neoray_skipped` also holds oversize files and cancelled
			// ones. The event is what tells an operator that a skip was
			// policy rather than a failure.
			Segurium_Scan_Runner::debug(
				'on_premise_unresolved',
				array(
					'scan_id'  => (string) $scan_id,
					'detector' => (string) $detector,
					'sha256'   => (string) $sha256,
					'path'     => (string) $path,
				)
			);
			return null;
		}

		if ( '' === $base_path || '' === $path || '' === $sha256 ) {
			++$stats['failed'];
			++$stats['neoray_errors'];
			return null;
		}

		$abs = rtrim( $base_path, '/' ) . '/' . ltrim( $path, '/' );
		if ( ! is_file( $abs ) || ! is_readable( $abs ) ) {
			++$stats['failed'];
			++$stats['neoray_errors'];
			return null;
		}

		$size = Segurium_Fs::size( $abs );
		if ( false === $size || 0 === $size ) {
			++$stats['failed'];
			++$stats['neoray_errors'];
			return null;
		}
		if ( $size > self::NEO_RAY_MAX_BODY ) {
			self::count_skip( $stats, 'too_large' );
			return null;
		}
		if ( null !== $submitter && ! Segurium_Async_Scan_Submitter::memory_allows( 0, $size ) ) {
			self::count_skip( $stats, 'low_memory' );
			self::log_escalation_skip(
				$scan_id,
				array(
					'sha256' => $sha256,
					'path'   => $path,
					'size'   => $size,
				),
				'low_memory',
				'memory_limit leaves no room to upload this file'
			);
			return null;
		}

		// Ask the batch ceiling before paying for the body. The submitter
		// reaches its verdict from the first WIRE_SAMPLE_BYTES, so the same
		// answer is available from a bounded read. A near-cap file that
		// compresses badly is refused either way; taken here, the refusal
		// costs a 256 KiB read instead of a whole-file allocation that can
		// exhaust memory_limit and kill the tick mid-chunk.
		//
		// Only for bodies the estimate would actually sample. At or below
		// WIRE_ESTIMATE_MIN_BYTES the estimate is the raw size, which
		// `add()` compares anyway, and a body that small threatens no
		// memory_limit — so sampling it first would buy a second read and a
		// second failure mode for every ordinary PHP file in the queue.
		if ( null !== $submitter && $size > Segurium_Async_Scan_Submitter::WIRE_ESTIMATE_MIN_BYTES ) {
			$sample = Segurium_Fs::read_prefix( $abs, Segurium_Async_Scan_Submitter::WIRE_SAMPLE_BYTES );
			if ( false === $sample ) {
				++$stats['failed'];
				++$stats['neoray_errors'];
				return null;
			}
			$refused = $submitter->refuse_before_read( $size, $sample, $path );
			if ( null !== $refused ) {
				self::count_skip( $stats, Segurium_Async_Scan_Submitter::SKIP_REASONS[ $refused->get_error_code() ] );
				return null;
			}
		}

		$body = Segurium_Fs::read( $abs );
		if ( false === $body || '' === $body ) {
			++$stats['failed'];
			++$stats['neoray_errors'];
			return null;
		}

		// Log files grow between the scanner pass and this escalation, so
		// their hash drifts and the server would reject the body. The
		// listing-time content was already vouched as Unknown (not
		// malicious); treat the drifted re-read as clean and re-evaluate
		// on the next scan with a fresh hash.
		if ( self::looks_like_log_file( $path ) && hash( 'sha256', $body ) !== $sha256 ) {
			self::apply_verdict( $scan_id, $detector, $sha256, $path, self::NEO_RAY_VERDICT_MAP['clean'], $stats, $now );
			return null;
		}

		return $body;
	}

	/**
	 * Hand an Unknown-verdict file to the batched async
	 * submitter instead of doing an inline-poll escalation. Counters
	 * keep their pre-async semantics for files that never reach the
	 * wire — see {@see load_unknown_body()}.
	 *
	 * @param string                        $scan_id   Scan UUID.
	 * @param string                        $detector  Detector label.
	 * @param string                        $sha256    File SHA-256.
	 * @param string                        $path      Relative path.
	 * @param string                        $base_path Absolute root.
	 * @param Segurium_Async_Scan_Submitter $submitter Submitter to enqueue into.
	 * @param array                         $stats     Stat block (by reference).
	 * @param int                           $now       Timestamp.
	 */
	private static function enqueue_unknown_async( $scan_id, $detector, $sha256, $path, $base_path, Segurium_Async_Scan_Submitter $submitter, array &$stats, $now ) {
		$body = self::load_unknown_body( $scan_id, $detector, $sha256, $path, $base_path, $stats, $now, $submitter );
		if ( null === $body ) {
			return;
		}
		$added = $submitter->add( $sha256, $path, $body );
		self::count_skip( $stats, 'upload_refused', $submitter->take_skipped() );
		if ( is_wp_error( $added ) ) {
			if ( isset( Segurium_Async_Scan_Submitter::SKIP_REASONS[ $added->get_error_code() ] ) ) {
				self::count_skip( $stats, Segurium_Async_Scan_Submitter::SKIP_REASONS[ $added->get_error_code() ] );
				return;
			}
			++$stats['failed'];
			++$stats['neoray_errors'];
			Segurium_Debug::log(
				sprintf(
					'[segurium-verdict-queue] async submit add failed for %s: %s (%s)',
					$sha256,
					$added->get_error_code(),
					$added->get_error_message()
				)
			);
		}
	}

	/**
	 * End-of-chunk flush. Drains whatever the submitter
	 * still has buffered and folds wire-level failures into the chunk's
	 * stat block. Files accepted by the server land in the per-scan
	 * pending-paths row — the async poller picks them up later.
	 *
	 * @param Segurium_Async_Scan_Submitter $submitter Submitter to drain.
	 * @param array                         $stats     Stat block (by reference).
	 */
	private static function flush_async_submitter( Segurium_Async_Scan_Submitter $submitter, array &$stats ) {
		$pending = $submitter->buffer_count();
		if ( 0 === $pending ) {
			return;
		}
		$result = $submitter->flush();
		// The submitter drops a batch the link refused and
		// halves its ceiling; the dropped files come back through the
		// tally, never through the buffer.
		self::count_skip( $stats, 'upload_refused', $submitter->take_skipped() );
		$rejected = array();
		if ( is_wp_error( $result ) ) {
			// flush() restores the buffer on a content rejection, but the
			// submitter is call-local so that buffer dies with it; the files
			// were already shifted off `unknown_queue`. Count them so the
			// chunk's completion accounting stays whole. Link failures never
			// reach this branch: the submitter drops those batches itself.
			// Sub-batches that shipped before
			// the rejection report their own rejected files in the error
			// data.
			$leftover                = $submitter->buffer_count();
			$stats['failed']        += $leftover;
			$stats['neoray_errors'] += $leftover;
			Segurium_Debug::log(
				sprintf(
					'[segurium-verdict-queue] async submit flush failed: %s (%s) — %d file(s) failed',
					$result->get_error_message(),
					$result->get_error_code(),
					$leftover
				)
			);
			$data = $result->get_error_data();
			if ( is_array( $data ) && isset( $data['rejected'] ) && is_array( $data['rejected'] ) ) {
				$rejected = $data['rejected'];
			}
		} elseif ( is_array( $result ) && isset( $result['rejected'] ) && is_array( $result['rejected'] ) ) {
			// Server-side rejected files (hash mismatch at CTI, etc.) will
			// never get a verdict via the async path. Count them locally.
			$rejected = $result['rejected'];
		}
		foreach ( $rejected as $r ) {
			++$stats['failed'];
			++$stats['neoray_errors'];
			$reason = isset( $r['reason'] ) ? (string) $r['reason'] : 'rejected';
			$hash   = isset( $r['hash'] ) ? (string) $r['hash'] : '';
			Segurium_Debug::log(
				sprintf( '[segurium-verdict-queue] async submit rejected %s: %s', $hash, $reason )
			);
		}
	}

	/**
	 * Escalate an Unknown-verdict file to `/v1/neo-ray` and apply the
	 * returned verdict. Terminal for this file in the current scan — no
	 * retries.
	 *
	 * @param string                   $scan_id   Scan UUID.
	 * @param string                   $detector  Detector label.
	 * @param string                   $sha256    File SHA-256.
	 * @param string                   $path      Relative path.
	 * @param string                   $base_path Absolute root.
	 * @param Segurium_CTI_Client|null $cti       Optional client.
	 * @param array                    $stats     Stat block (by reference).
	 * @param int                      $now       Timestamp.
	 */
	private static function resolve_unknown( $scan_id, $detector, $sha256, $path, $base_path, $cti, array &$stats, $now ) {
		$body = self::load_unknown_body( $scan_id, $detector, $sha256, $path, $base_path, $stats, $now );
		if ( null === $body ) {
			return;
		}

		$result = self::dispatch_neo_ray_static( $cti, $sha256, $body, $path );
		if ( is_wp_error( $result ) ) {
			++$stats['failed'];
			++$stats['neoray_errors'];
			Segurium_Debug::log(
				sprintf(
					'[segurium-verdict-queue] neo-ray escalation failed for %s: %s (%s)',
					$sha256,
					$result->get_error_code(),
					$result->get_error_message()
				)
			);
			// When CTI says the body's SHA didn't match the
			// header we declared, re-hash the body we just sent. If the
			// recomputed hash differs from the queue-recorded one, the file
			// changed on disk between the scanner pass that hashed it and
			// this escalation that re-read it. The "smoking gun" detail
			// goes to the gated debug log so production sites stay quiet.
			if ( 'cti_neoray_hash_mismatch' === $result->get_error_code() && Segurium_Scan_Runner::debug_enabled() ) {
				Segurium_Scan_Runner::debug(
					'neoray_hash_mismatch_detail',
					array(
						'declared_sha'   => $sha256,
						'recomputed_sha' => hash( 'sha256', $body ),
						'path'           => $path,
						'size_b'         => strlen( $body ),
						'changed'        => hash( 'sha256', $body ) !== $sha256,
					)
				);
			}
			return;
		}
		$label = isset( $result['verdict'] ) ? (string) $result['verdict'] : '';
		if ( ! array_key_exists( $label, self::NEO_RAY_VERDICT_MAP ) ) {
			++$stats['failed'];
			++$stats['neoray_errors'];
			Segurium_Debug::log(
				sprintf( '[segurium-verdict-queue] neo-ray returned unrecognised verdict %s for %s', $label, $sha256 )
			);
			return;
		}
		self::apply_verdict( $scan_id, $detector, $sha256, $path, self::NEO_RAY_VERDICT_MAP[ $label ], $stats, $now );
	}

	/**
	 * Proxy inspect through the provided client or the storage façade.
	 *
	 * @param Segurium_CTI_Client|null $cti     Optional client.
	 * @param array                    $files   Payload.
	 * @param string                   $scan_id Plugin-side scan UUID.
	 * @return array|WP_Error
	 */
	private static function dispatch_inspect_static( $cti, array $files, string $scan_id = '' ) {
		if ( null !== $cti ) {
			return $cti->inspect( $files, $scan_id );
		}
		return Segurium_Storage::cti_inspect_hashes( $files, $scan_id );
	}

	/**
	 * Proxy Neo-Ray scan through the provided client or the storage façade.
	 *
	 * @param Segurium_CTI_Client|null $cti           Optional client.
	 * @param string                   $sha256        SHA-256.
	 * @param string                   $body          Bytes.
	 * @param string                   $relative_path Site-relative path
	 *                                                 forwarded to CTI via
	 *                                                 the `X-Segurium-Filename`
	 *                                                 header for analytics and
	 *                                                 engine `__FILE__` fidelity.
	 * @return array|WP_Error
	 */
	private static function dispatch_neo_ray_static( $cti, $sha256, $body, $relative_path = '' ) {
		if ( null !== $cti ) {
			return $cti->neo_ray_scan( $sha256, $body, $relative_path );
		}
		return Segurium_Storage::cti_neo_ray_scan( $sha256, $body, $relative_path );
	}

	/**
	 * Whether a relative path looks like a rolling log file. Used to suppress
	 * neo-ray re-escalation on files whose content drifts between hash and
	 * fetch. Matches `*.log`, `*.log.<n>`, and gzipped rotations.
	 *
	 * @param string $path Site-relative path.
	 * @return bool
	 */
	private static function looks_like_log_file( $path ) {
		return (bool) preg_match( '#(^|/)[^/]+\.log(\.\d+)?(\.gz)?$#i', (string) $path );
	}

	/**
	 * Map a scan-type identifier to the detector label written into
	 * `scan_findings.detector`. Unknown types pass through verbatim so
	 * future scan sources can opt in without touching this class.
	 *
	 * @param string $scan_type Scan type.
	 * @return string
	 */
	private static function detector_for_scan_type( $scan_type ) {
		$map = array(
			'malware'  => 'scanner',
			'realtime' => 'realtime',
			'upload'   => 'upload',
		);
		return isset( $map[ $scan_type ] ) ? $map[ $scan_type ] : (string) $scan_type;
	}

	/**
	 * Consume pending runtime_kv chunks, run them through
	 * {@see resolve_and_record}, and fold the per-chunk stats back into the
	 * per-scan accounting.
	 *
	 * @return void
	 */
	private function process_pending() {
		$drain_partial = $this->should_drain_partial();
		while ( $this->state['chunk_out'] < $this->state['chunk_in'] && ! $this->is_time_up() ) {
			// Stop pulling new chunks once the runner lock
			// no longer holds this scan id (e.g. user clicked Stop or the
			// watchdog reclaimed a stale lock). The currently-running
			// resolve_and_record will also bail at the next file
			// boundary via the cancel callable in send_batch().
			if ( $this->scan_was_cancelled() ) {
				return;
			}
			$chunk_idx = (int) $this->state['chunk_out'];
			$chunk     = $this->load_chunk( $chunk_idx );
			if ( empty( $chunk ) ) {
				// An empty/sealed slot — sweep any leftover
				// cursor row (defensive; cursor only exists when chunk
				// content does) and advance past it.
				$this->delete_chunk_cursor( $chunk_idx );
				$this->delete_chunk( $chunk_idx );
				++$this->state['chunk_out'];
				$this->save_state();
				continue;
			}

			// Chunk + sibling cursor lifecycle. The chunk row
			// stays put across cursor saves so a mid-batch crash leaves the
			// next process() with enough state to resume without re-running
			// /v1/inspect or double-counting any verdict.
			$drained = $this->process_chunk_with_cursor( $chunk_idx, $chunk );
			if ( ! $drained ) {
				// Cooperative exit — cursor already saved, chunk row kept.
				return;
			}

			// Advance chunk_out only after a chunk is fully drained, so
			// `chunk_in == chunk_out` remains honest at every observation
			// point and `is_scan_complete()` can keep its structural test.
			++$this->state['chunk_out'];
			$this->save_state();
			if ( $this->is_time_up() ) {
				return;
			}
			if ( $this->tick_will_exhaust_before_next_batch() ) {
				return;
			}
		}
		if ( $drain_partial && ! $this->is_time_up() && ! $this->tick_will_exhaust_before_next_batch() && ! $this->scan_was_cancelled() ) {
			$tail = $this->load_pending_tail();
			if ( ! empty( $tail ) ) {
				$this->store_chunk( $this->state['chunk_in'], array() );
				$batch_t0 = microtime( true );
				$this->send_batch( $tail );
				$this->record_batch_wall( microtime( true ) - $batch_t0 );
				$this->save_state();
			}
		}
	}

	/**
	 * Drive one stored chunk through the inspect → classified
	 * apply → per-file Neo-Ray escalation pipeline, persisting a sibling
	 * cursor row after every file so a mid-loop kill never drops work.
	 *
	 * Returns true when the chunk fully drains (caller must advance
	 * `chunk_out` and clean up); false when the loop exits early because
	 * the runner tick is about to expire, the NRS predictor projects an
	 * overshoot, or the scan was cancelled — in which case the cursor
	 * holds the residual queue and partial counters for the next process()
	 * call to pick up.
	 *
	 * Idempotency on resume:
	 *  - `inspect_done`              — guards against a second /v1/inspect.
	 *  - `inspect_classified_applied` — guards against re-applying classified
	 *    verdicts (the DB upsert is also idempotent on
	 *    `(scan_uuid, file_path_hash)`, but counters would still double).
	 *  - `partial_stats`             — local accumulator; folded into
	 *    `state['scan_stats']` exactly once, when the chunk drains.
	 *
	 * @param int   $chunk_idx Chunk index in runtime_kv.
	 * @param array $chunk     File records in the chunk.
	 * @return bool True if the chunk drained; false on cooperative exit.
	 */
	private function process_chunk_with_cursor( $chunk_idx, array $chunk ) {
		$chunk_idx = (int) $chunk_idx;
		$scan_id   = isset( $chunk[0]['scan_id'] ) ? (string) $chunk[0]['scan_id'] : $this->scan_id;
		$cursor    = $this->load_chunk_cursor( $chunk_idx );

		if ( null === $cursor ) {
			$cursor = self::new_chunk_cursor();
		}

		if ( ! empty( $cursor['in_flight'] ) ) {
			$this->recover_dead_batch( $scan_id, $chunk_idx, $cursor );
		}

		// Run (or retry) the one-shot /v1/inspect step while it
		// has not completed. On a transient transport/5xx failure this defers
		// the chunk to a later tick instead of permanently failing its files;
		// `false` is a cooperative exit (cursor saved, chunk row kept,
		// chunk_out not advanced) just like the time-budget yield below.
		if ( empty( $cursor['inspect_done'] ) ) {
			if ( ! $this->run_inspect_step( $chunk_idx, $chunk, $scan_id, $cursor ) ) {
				return false;
			}
		}

		$detector  = self::detector_for_scan_type( 'malware' );
		$submitter = null;

		while ( ! empty( $cursor['unknown_queue'] ) ) {
			if ( $this->scan_was_cancelled()
				|| ! $this->time_allows_next_unknown()
				|| Segurium_Async_Scan_Pause::is_paused( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT ) ) {
				$this->settle_submitter( $submitter, $scan_id, $cursor );
				$this->save_chunk_cursor( $chunk_idx, $cursor );
				return false;
			}

			// Per-file heartbeat + tick-mutex renewal. Even
			// under the batched submitter path the loop still walks the
			// unknown_queue one file at a time (file IO + sha re-check
			// plus the occasional auto-flush HTTP POST), so stamping the
			// heartbeat per iteration keeps the watchdog accurate.
			if ( class_exists( 'Segurium_Scan_Runner' ) && ! Segurium_Scan_Runner::renew_liveness( $scan_id ) ) {
				// Lease gone — yield without flushing; the new
				// owner resumes from the last persisted cursor.
				return false;
			}

			$head    = array_shift( $cursor['unknown_queue'] );
			$partial = $cursor['partial_stats'];
			$sha256  = isset( $head['sha256'] ) ? (string) $head['sha256'] : '';
			$path    = isset( $head['path'] ) ? (string) $head['path'] : '';

			$cursor['in_flight'][] = $head;
			$cursor['memory']      = array( memory_get_usage( true ), Segurium_Async_Scan_Submitter::memory_limit_bytes() );
			$this->save_chunk_cursor( $chunk_idx, $cursor );

			if ( null === $submitter ) {
				$submitter = new Segurium_Async_Scan_Submitter( $scan_id, $detector, $this->cti_client );
			}

			// Queue the unknown for the next batched
			// `/v1/scan/submit`. The submitter auto-flushes when its
			// buffer crosses 100 files / 10 MiB; otherwise the tail
			// flush at end of chunk (or at cooperative exit) ships it.
			try {
				self::enqueue_unknown_async(
					$scan_id,
					$detector,
					$sha256,
					$path,
					$this->base_path,
					$submitter,
					$partial,
					time()
				);
			} catch ( Throwable $escalation_exc ) {
				// One file, one skip. `add()` pushes to the buffer last, so
				// the file named here provably never reached the wire.
				self::count_skip( $partial, 'escalation_threw' );
				self::log_escalation_skip(
					$scan_id,
					$head,
					'escalation_threw',
					get_class( $escalation_exc ) . ': ' . $escalation_exc->getMessage()
				);
			}

			$buffered                = array_flip( $submitter->buffered_paths() );
			$cursor['in_flight']     = array_values(
				array_filter(
					$cursor['in_flight'],
					static function ( $file ) use ( $buffered ) {
						return isset( $buffered[ $file['path'] ] );
					}
				)
			);
			$cursor['partial_stats'] = $partial;
			++$this->files_processed_in_call;

			$this->save_chunk_cursor( $chunk_idx, $cursor );
			$this->batch_processed = true;
		}

		// Drained: flush any tail batch the submitter still holds, then
		// fold partial_stats into state['scan_stats'] (single
		// authoritative point at which the chunk's verdicts become visible
		// to is_scan_complete and the progress UI), then delete the cursor
		// + chunk rows. The caller advances chunk_out and saves state.
		if ( ! $this->settle_submitter( $submitter, $scan_id, $cursor ) ) {
			$this->save_chunk_cursor( $chunk_idx, $cursor );
			return false;
		}
		$this->fold_partial_stats( $scan_id, $cursor['partial_stats'] );
		$this->delete_chunk_cursor( $chunk_idx );
		$this->delete_chunk( $chunk_idx );
		return true;
	}

	/**
	 * Ship the buffer, or requeue it while CTI asks for a pause (returns false).
	 *
	 * @param Segurium_Async_Scan_Submitter|null $submitter Active submitter.
	 * @param string                             $scan_id   Scan UUID.
	 * @param array                              $cursor    Active cursor.
	 * @return bool
	 */
	private function settle_submitter( $submitter, $scan_id, array &$cursor ) {
		if ( null !== $submitter && $submitter->buffer_count() > 0 ) {
			if ( Segurium_Async_Scan_Pause::is_paused( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT ) ) {
				$cursor['unknown_queue'] = array_merge( $cursor['in_flight'], $cursor['unknown_queue'] );
				$cursor['in_flight']     = array();
				return false;
			}
			$partial = $cursor['partial_stats'];
			self::flush_submitter_guarded( $submitter, $partial, $scan_id );
			$cursor['partial_stats'] = $partial;
		}
		$cursor['in_flight'] = array();
		return true;
	}

	/**
	 * Flush the submitter without letting a Throwable out. A
	 * chunk that yields on the tick budget flushes here, so an escaping
	 * throw would reach the runner as `chunk_threw` and count against
	 * STUCK_MAX — the abort this whole path exists to prevent.
	 *
	 * The buffered files are deliberately NOT charged as skips. `flush()`
	 * ships sub-batches one at a time, so an unknown number of them already
	 * reached CTI and will get verdicts from the async poller; counting them
	 * here would push `files_skipped` past `files_found` in the scan summary.
	 * The count goes to the log instead.
	 *
	 * @param Segurium_Async_Scan_Submitter $submitter Submitter to drain.
	 * @param array                         $stats     Stat block (by reference).
	 * @param string                        $scan_id   Scan UUID.
	 * @return void
	 */
	private static function flush_submitter_guarded( Segurium_Async_Scan_Submitter $submitter, array &$stats, $scan_id ) {
		$pending = $submitter->buffer_count();
		try {
			self::flush_async_submitter( $submitter, $stats );
		} catch ( Throwable $flush_exc ) {
			self::log_escalation_skip(
				$scan_id,
				array(),
				'tail_flush_threw',
				get_class( $flush_exc ) . ': ' . $flush_exc->getMessage()
					. ' (' . $pending . ' file(s) in flight)'
			);
		}
	}

	/**
	 * Requeue the files a dead worker held, or skip them after a second death.
	 *
	 * @param string $scan_id   Scan UUID.
	 * @param int    $chunk_idx Chunk index in runtime_kv.
	 * @param array  $cursor    Cursor data (by reference).
	 * @return void
	 */
	private function recover_dead_batch( $scan_id, $chunk_idx, array &$cursor ) {
		$dead  = isset( $cursor['in_flight']['path'] ) ? array( $cursor['in_flight'] ) : $cursor['in_flight'];
		$retry = array();
		foreach ( $dead as $file ) {
			$file['deaths'] = (int) ( $file['deaths'] ?? 0 ) + 1;
			if ( $file['deaths'] < self::MAX_WORKER_DEATHS_PER_FILE ) {
				$retry[] = $file;
				continue;
			}
			self::count_skip( $cursor['partial_stats'], 'worker_died' );
			self::log_escalation_skip( $scan_id, $file, 'worker_died', 'the worker died twice with this file in its upload batch' );
		}
		$cursor['unknown_queue'] = array_merge( $retry, $cursor['unknown_queue'] );
		$cursor['in_flight']     = array();
		$this->save_chunk_cursor( $chunk_idx, $cursor );

		( new Segurium_Async_Scan_Submitter( $scan_id, self::detector_for_scan_type( 'malware' ), $this->cti_client ) )->shrink_after_worker_death();

		$memory = isset( $cursor['memory'] ) ? $cursor['memory'] : array( 0, 0 );
		$this->ensure_scan_stats( $scan_id );
		++$this->state['scan_stats'][ $scan_id ]['worker_deaths'];
		$this->state['scan_stats'][ $scan_id ]['last_worker_death'] = array(
			'files'            => count( $dead ),
			'bytes'            => (int) array_sum( array_column( $dead, 'size' ) ),
			'memory_before_mb' => (int) round( $memory[0] / 1048576 ),
			'memory_limit_mb'  => (int) round( $memory[1] / 1048576 ),
		);
		$this->save_state();

		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			Segurium_Scan_Runner::reset_stuck_counter( $scan_id );
		}
	}

	/**
	 * Count skipped files under a reason.
	 *
	 * @param array  $stats  Stat block (by reference).
	 * @param string $reason Skip reason.
	 * @param int    $count  Files skipped.
	 * @return void
	 */
	private static function count_skip( array &$stats, $reason, $count = 1 ) {
		if ( $count <= 0 ) {
			return;
		}
		$stats['neoray_skipped']          = (int) ( $stats['neoray_skipped'] ?? 0 ) + $count;
		$stats['skip_reasons'][ $reason ] = (int) ( $stats['skip_reasons'][ $reason ] ?? 0 ) + $count;
	}

	/**
	 * Record a deep-scan upload the scan gave up on. The count
	 * reaches the user through `files_skipped` in the scan summary; the path
	 * and the reason go to the debug log so an operator can tell which file
	 * was not inspected and why.
	 *
	 * @param string $scan_id Scan UUID.
	 * @param array  $file    `{sha256, path, size}` of the abandoned file.
	 * @param string $reason  Short machine-readable reason.
	 * @param string $detail  Free-text detail for the log line.
	 * @return void
	 */
	private static function log_escalation_skip( $scan_id, array $file, $reason, $detail ) {
		$path   = isset( $file['path'] ) ? (string) $file['path'] : '';
		$sha256 = isset( $file['sha256'] ) ? (string) $file['sha256'] : '';
		$size   = isset( $file['size'] ) ? (int) $file['size'] : 0;

		Segurium_Debug::log(
			sprintf(
				'[segurium-verdict-queue] deep-scan upload skipped (%s) for %s (%d bytes): %s',
				$reason,
				'' !== $path ? $path : '(unknown path)',
				$size,
				$detail
			)
		);
		Segurium_Scan_Runner::debug(
			'unknown_escalation_skipped',
			array(
				'scan_id' => (string) $scan_id,
				'path'    => $path,
				'sha256'  => $sha256,
				'size'    => $size,
				'reason'  => (string) $reason,
				'detail'  => (string) $detail,
			)
		);
	}

	/**
	 * The zeroed cursor struct for a fresh
	 * chunk. The /v1/inspect call no longer happens here — it runs (and, on
	 * a transient failure, retries) in {@see run_inspect_step()} so the
	 * chunk can be deferred across ticks without losing this state.
	 *
	 * @return array Cursor.
	 */
	private static function new_chunk_cursor() {
		return array(
			'inspect_done'               => false,
			'inspect_classified_applied' => false,
			'unknown_queue'              => array(),
			'in_flight'                  => array(),
			'partial_stats'              => array(
				'verdicted'      => 0,
				'threats'        => 0,
				'failed'         => 0,
				'neoray_errors'  => 0,
				'neoray_skipped' => 0,
			),
		);
	}

	/**
	 * Run the chunk's one-shot /v1/inspect step.
	 * Calls inspect once, applies every non-Unknown verdict (idempotent DB
	 * upsert), and stages the Unknowns into `unknown_queue` for the per-file
	 * Neo-Ray loop.
	 *
	 * Retry model: a transient transport error / timeout / 5xx
	 * no longer fails the whole batch. Instead the chunk is DEFERRED — the
	 * cursor records `inspect_retries` + `inspect_next_retry_at` and the
	 * method returns false so the caller yields the tick (chunk row kept,
	 * `chunk_out` not advanced). A later tick re-enters, and once
	 * `inspect_next_retry_at` is due the call is retried. Backoff follows
	 * {@see INSPECT_RETRY_BACKOFF_SEC} (0s first, capped at 600s); only after
	 * the schedule is exhausted are the files counted `failed`. This is
	 * purely cross-tick — we never sleep or block inside a tick, so it does
	 * not depend on `max_execution_time`. A permanent error (4xx, malformed
	 * response) fails the batch immediately, as before.
	 *
	 * @param int    $chunk_idx Chunk index.
	 * @param array  $chunk     File records.
	 * @param string $scan_id   Scan UUID.
	 * @param array  $cursor    Cursor, updated in place.
	 * @return bool True when inspect resolved (success OR permanent fail) and
	 *              the caller may proceed to drain; false when the chunk is
	 *              deferred (transient retry scheduled, or not yet due).
	 */
	private function run_inspect_step( $chunk_idx, array $chunk, $scan_id, array &$cursor ) {
		$now = time();

		// Backoff gate: a prior transient failure scheduled the next attempt.
		// Until it is due, yield the tick WITHOUT touching CTI — this is what
		// keeps a CTI outage from drawing one request per tick, and the host
		// only pays a timestamp compare before exiting.
		if ( isset( $cursor['inspect_next_retry_at'] ) && $now < (int) $cursor['inspect_next_retry_at'] ) {
			$this->inspect_backoff_waiting = true;
			return false;
		}

		// Strip the per-record scan_id we attached in submit() — CTI
		// expects the bare {sha256, path, size, mtime} shape on each
		// file; the batch-level scan_id rides as a request-level field.
		$payload = array();
		foreach ( $chunk as $f ) {
			$rec = $f;
			unset( $rec['scan_id'] );
			$payload[] = $rec;
		}

		$batch_t0 = microtime( true );
		$result   = self::dispatch_inspect_static( $this->cti_client, $payload, (string) $scan_id );

		if ( is_wp_error( $result ) || ! is_array( $result ) ) {
			// Do NOT feed a failed/timed-out inspect into the
			// rolling wall-time window. An 8s timeout (or a string of them
			// during a backoff round) would inflate the next-batch cost
			// projection in {@see tick_will_exhaust_before_next_batch()} and
			// trip spurious yields on healthy batches once CTI recovers. Only
			// a completed round-trip is a meaningful cost sample.
			return $this->handle_inspect_failure( $chunk_idx, $chunk, $cursor, $result, $now );
		}
		$this->record_batch_wall( microtime( true ) - $batch_t0 );

		// Index inspect response by sha256 so each submitted file
		// contributes exactly one increment — duplicates / extras
		// from CTI are ignored.
		$verdict_by_sha = array();
		foreach ( $result as $item ) {
			$sha = isset( $item['sha256'] ) ? (string) $item['sha256'] : '';
			if ( '' === $sha || isset( $verdict_by_sha[ $sha ] ) ) {
				continue;
			}
			$verdict_by_sha[ $sha ] = $item;
		}

		$detector = self::detector_for_scan_type( 'malware' );
		$partial  = $cursor['partial_stats'];
		$unknown  = array();

		foreach ( $chunk as $f ) {
			$sha256 = isset( $f['sha256'] ) ? (string) $f['sha256'] : '';
			$path   = isset( $f['path'] ) ? (string) $f['path'] : '';
			if ( '' === $sha256 || ! isset( $verdict_by_sha[ $sha256 ] ) ) {
				++$partial['failed'];
				continue;
			}
			$item     = $verdict_by_sha[ $sha256 ];
			$verdict  = isset( $item['verdict'] ) ? (int) $item['verdict'] : 0;
			$resp_pth = isset( $item['path'] ) ? (string) $item['path'] : '';
			if ( '' !== $resp_pth ) {
				$path = $resp_pth;
			}

			if ( self::VERDICT_UNKNOWN === $verdict ) {
				$unknown[] = array(
					'sha256' => $sha256,
					'path'   => $path,
					'size'   => isset( $f['size'] ) ? (int) $f['size'] : 0,
					'mtime'  => isset( $f['mtime'] ) ? (int) $f['mtime'] : 0,
				);
				continue;
			}
			self::apply_verdict( $scan_id, $detector, $sha256, $path, $verdict, $partial, $now );
		}

		$cursor['inspect_done']               = true;
		$cursor['inspect_classified_applied'] = true;
		$cursor['unknown_queue']              = $unknown;
		$cursor['partial_stats']              = $partial;
		unset( $cursor['inspect_retries'], $cursor['inspect_next_retry_at'] );
		$this->save_chunk_cursor( $chunk_idx, $cursor );
		$this->batch_processed = true;
		return true;
	}

	/**
	 * React to a failed /v1/inspect call. A transient error
	 * (transport/timeout/5xx) schedules a bounded cross-tick retry and
	 * returns false (defer); a permanent error, or an exhausted retry
	 * schedule, counts every file `failed` and returns true (drain).
	 *
	 * @param int            $chunk_idx Chunk index.
	 * @param array          $chunk     File records.
	 * @param array          $cursor    Cursor, updated in place.
	 * @param array|WP_Error $result    The failing inspect result.
	 * @param int            $now       Wall-clock seconds for retry math.
	 * @return bool False when deferred for retry; true when the batch is
	 *              counted failed and ready to drain.
	 */
	private function handle_inspect_failure( $chunk_idx, array $chunk, array &$cursor, $result, $now ) {
		$code = is_wp_error( $result ) ? $result->get_error_code() : 'cti_invalid_response';
		$msg  = is_wp_error( $result ) ? $result->get_error_message() : 'inspect returned a non-array response';

		if ( self::is_transient_inspect_error( $result ) ) {
			$attempt  = isset( $cursor['inspect_retries'] ) ? (int) $cursor['inspect_retries'] : 0;
			$schedule = self::INSPECT_RETRY_BACKOFF_SEC;
			if ( $attempt < count( $schedule ) ) {
				$delay                           = (int) $schedule[ $attempt ];
				$cursor['inspect_retries']       = $attempt + 1;
				$cursor['inspect_next_retry_at'] = $now + $delay;
				// inspect_done stays false so the next due tick re-runs the call.
				Segurium_Debug::log(
					sprintf(
						'[segurium-verdict-queue] inspect transient (%s): %s — retry %d/%d in %ds (%d files held, not failed)',
						$code,
						$msg,
						$attempt + 1,
						count( $schedule ),
						$delay,
						count( $chunk )
					)
				);
				$this->save_chunk_cursor( $chunk_idx, $cursor );
				$this->batch_processed         = true;
				$this->inspect_backoff_waiting = true;
				return false;
			}
			Segurium_Debug::log(
				sprintf(
					'[segurium-verdict-queue] inspect transient (%s) exhausted %d retries; failing %d files: %s',
					$code,
					count( $schedule ),
					count( $chunk ),
					$msg
				)
			);
		} else {
			Segurium_Debug::log(
				sprintf(
					'[segurium-verdict-queue] inspect failed permanently (%s): %s',
					$code,
					$msg
				)
			);
		}

		// Permanent failure, or retries exhausted: count every file failed
		// and leave `unknown_queue` empty so the caller drains immediately.
		$cursor['partial_stats']['failed']    = count( $chunk );
		$cursor['inspect_done']               = true;
		$cursor['inspect_classified_applied'] = true;
		unset( $cursor['inspect_retries'], $cursor['inspect_next_retry_at'] );
		$this->save_chunk_cursor( $chunk_idx, $cursor );
		$this->batch_processed = true;
		return true;
	}

	/**
	 * Whether a failed inspect result is worth a bounded retry.
	 * Transient = a transport-layer failure (timeout, reset, DNS) or a 5xx
	 * (gateway/server). A 4xx is a permanent client error and a malformed
	 * (non-array) or `cti_invalid_response` shape is a CTI-side data fault —
	 * neither is retried, matching the pre-578 fail-fast behaviour.
	 *
	 * @param array|WP_Error $result Inspect result.
	 * @return bool
	 */
	private static function is_transient_inspect_error( $result ) {
		if ( ! is_wp_error( $result ) ) {
			return false;
		}
		$code = $result->get_error_code();
		if ( 'cti_http_error' === $code ) {
			$data   = $result->get_error_data();
			$status = ( is_array( $data ) && isset( $data['status'] ) ) ? (int) $data['status'] : 0;
			// 5xx is transient; a missing status (legacy gateway 504 with no
			// data) is treated as transient too. 4xx is a permanent client error.
			return 0 === $status || ( $status >= 500 && $status <= 599 );
		}
		// Transport-level failures from wp_remote_post surface as these codes.
		return in_array( $code, array( 'http_request_failed', 'cti_transport_error' ), true );
	}

	/**
	 * Hard tick-budget floor for the batched-submit
	 * variant of the chunk loop. Under the legacy sync-neoray path
	 * each iteration could spend tens of seconds in a single HTTP RTT,
	 * so the predictor projected per-file cost from a (size_b, wall_ms)
	 * history. With the async submitter, per-iteration cost is
	 * `file_get_contents()` + a buffer push, only occasionally a
	 * batched POST when the buffer auto-flushes at 100 files / 10 MiB —
	 * a deterministic and well-bounded cost. The simple safety-floor
	 * yield is enough; the predictor and its history window are gone.
	 *
	 * @return bool True if the loop may continue with the next file.
	 */
	private function time_allows_next_unknown() {
		if ( 0 === $this->files_processed_in_call ) {
			return true;
		}
		if ( ! class_exists( 'Segurium_Scan_Runner' ) ) {
			return true;
		}
		$time_left = (float) Segurium_Scan_Runner::time_left_in_tick();
		if ( $time_left <= 0.0 ) {
			return true;
		}
		$safety = (float) Segurium_Scan_Runner::TICK_GRACEFUL_EXIT_SAFETY_SEC;
		if ( $time_left <= $safety ) {
			Segurium_Scan_Runner::debug(
				'async_submit_yield',
				array(
					'time_left'     => $time_left,
					'safety'        => $safety,
					'reason'        => 'safety_floor',
					'files_in_call' => $this->files_processed_in_call,
				)
			);
			return false;
		}
		return true;
	}

	/**
	 * Fold a chunk's `partial_stats` into the persistent per-
	 * scan accounting. Called once per chunk, on full drain.
	 *
	 * @param string $scan_id Scan UUID.
	 * @param array  $partial Per-chunk accumulator.
	 * @return void
	 */
	private function fold_partial_stats( $scan_id, array $partial ) {
		$this->ensure_scan_stats( $scan_id );
		foreach ( array( 'verdicted', 'threats', 'failed', 'neoray_errors', 'neoray_skipped' ) as $k ) {
			$this->state['scan_stats'][ $scan_id ][ $k ] += (int) ( isset( $partial[ $k ] ) ? $partial[ $k ] : 0 );
		}
		foreach ( isset( $partial['skip_reasons'] ) ? $partial['skip_reasons'] : array() as $reason => $count ) {
			$this->state['scan_stats'][ $scan_id ]['skip_reasons'][ $reason ] = (int) ( $this->state['scan_stats'][ $scan_id ]['skip_reasons'][ $reason ] ?? 0 ) + (int) $count;
		}
	}

	/**
	 * Load the sibling cursor row for a chunk index. Returns
	 * null when no cursor is persisted yet.
	 *
	 * @param int $chunk_idx Chunk index.
	 * @return array|null
	 */
	private function load_chunk_cursor( $chunk_idx ) {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $this->kv_cursor_key( $chunk_idx ) )
		);
		if ( null === $raw ) {
			return null;
		}
		$decoded = json_decode( (string) $raw, true );
		return is_array( $decoded ) ? $decoded : null;
	}

	/**
	 * Persist the sibling cursor row. Tiny JSON, well under
	 * 1 ms — dwarfed by the Neo-Ray RTT it follows on every iteration.
	 *
	 * @param int   $chunk_idx Chunk index.
	 * @param array $cursor    Cursor data.
	 * @return void
	 */
	private function save_chunk_cursor( $chunk_idx, array $cursor ) {
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $this->kv_cursor_key( $chunk_idx ),
				'kv_value'   => (string) wp_json_encode( $cursor ),
				'expires_at' => $now + self::KV_TTL,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Delete the sibling cursor row. Called on chunk drain
	 * and when sweeping past empty/sealed slots.
	 *
	 * @param int $chunk_idx Chunk index.
	 * @return void
	 */
	private function delete_chunk_cursor( $chunk_idx ) {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => $this->kv_cursor_key( $chunk_idx ) ) );
	}

	/**
	 * Whether the runner lock no longer holds this queue's scan id.
	 *
	 * In unit tests and other no-runner contexts the static
	 * call resolves to "no lock", which would falsely look cancelled — so
	 * only treat it as cancelled when the lock actually exists and points
	 * at a different scan id (or is absent after having been held). The
	 * gate is the presence of a `Segurium_Scan_Runner` class plus a
	 * non-empty scan id.
	 *
	 * @return bool
	 */
	private function scan_was_cancelled() {
		if ( ! $this->runner_owned ) {
			return false;
		}
		return ! Segurium_Scan_Runner::is_scan_lock_held( $this->scan_id );
	}

	/**
	 * Push the wall time of a just-completed `/v1/inspect` round-trip onto
	 * the rolling window used by {@see tick_will_exhaust_before_next_batch()}.
	 *
	 * @param float $wall_seconds Wall time of the batch in seconds.
	 * @return void
	 */
	private function record_batch_wall( $wall_seconds ) {
		$this->batch_wall_history[] = (float) $wall_seconds;
		if ( count( $this->batch_wall_history ) > self::INSPECT_BATCH_WALL_WINDOW ) {
			array_shift( $this->batch_wall_history );
		}
	}

	/**
	 * Project the wall cost of starting one more `/v1/inspect` batch. Floors
	 * at {@see INSPECT_BATCH_PROJECTED_FLOOR_SEC} so a single fast response
	 * can't lure the loop into pushing one more batch on a tight tick.
	 *
	 * @return float Seconds.
	 */
	private function projected_next_batch_cost() {
		if ( empty( $this->batch_wall_history ) ) {
			return (float) self::INSPECT_BATCH_PROJECTED_FLOOR_SEC;
		}
		$avg       = array_sum( $this->batch_wall_history ) / count( $this->batch_wall_history );
		$projected = $avg * self::INSPECT_BATCH_PROJECTED_MULT;
		return (float) max( $projected, self::INSPECT_BATCH_PROJECTED_FLOOR_SEC );
	}

	/**
	 * Whether the runner's remaining tick budget is shorter than the projected
	 * cost of one more inspect batch. When called outside a
	 * runner tick (`time_left_in_tick()` returns 0.0), this is a no-op so the
	 * realtime / upload / test paths keep their previous behaviour and only
	 * the queue's internal `time_limit` gates the loop. Also a
	 * no-op when no batch has been processed yet in the current chunk — the
	 * runner is the source of truth for whether to enter, so the first batch
	 * always runs and the projected-cost guard only governs subsequent ones.
	 *
	 * @return bool
	 */
	private function tick_will_exhaust_before_next_batch() {
		if ( ! class_exists( 'Segurium_Scan_Runner' ) ) {
			return false;
		}
		if ( empty( $this->batch_wall_history ) ) {
			return false;
		}
		$time_left = (float) Segurium_Scan_Runner::time_left_in_tick();
		if ( $time_left <= 0.0 ) {
			return false;
		}
		$projected = $this->projected_next_batch_cost();
		if ( $time_left >= $projected ) {
			return false;
		}
		Segurium_Scan_Runner::debug(
			'inspect_yield',
			array(
				'time_left'      => $time_left,
				'projected_cost' => $projected,
				'batches_done'   => count( $this->batch_wall_history ),
				'chunk_out'      => (int) $this->state['chunk_out'],
				'chunk_in'       => (int) $this->state['chunk_in'],
			)
		);
		return true;
	}

	/**
	 * Whether pending buffers should be flushed even if not full.
	 *
	 * @return bool
	 */
	private function should_drain_partial() {
		foreach ( $this->state['scan_stats'] as $stats ) {
			if ( ! empty( $stats['submissions_complete'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Resolve one chunk via the shared helper and fold the result into the
	 * per-scan stats.
	 *
	 * @param array $files File records (with scan_id).
	 * @return void
	 */
	private function send_batch( array $files ) {
		if ( empty( $files ) ) {
			return;
		}
		$scan_id = isset( $files[0]['scan_id'] ) ? (string) $files[0]['scan_id'] : $this->scan_id;
		$this->ensure_scan_stats( $scan_id );

		// Hand the cancellation signal down to
		// resolve_and_record so a `Stop scan` click can short-circuit the
		// rest of this batch's neoray escalations. Only attach the check
		// when the runner lock was already holding this scan when
		// process() started — otherwise the test harness (and any
		// non-runner caller) would see "no lock" and falsely abort.
		$cancel_check = null;
		if ( $this->runner_owned ) {
			$cancel_check = static function () use ( $scan_id ) {
				return ! Segurium_Scan_Runner::is_scan_lock_held( $scan_id );
			};
		}

		$chunk_stats = self::resolve_and_record(
			$scan_id,
			'malware',
			$files,
			$this->base_path,
			$this->cti_client,
			$cancel_check
		);
		$this->fold_partial_stats( $scan_id, $chunk_stats );
		$this->batch_processed = true;
	}

	/**
	 * Default stat block. Kept here so {@see get_scan_stats} returns the
	 * same shape callers used before.
	 *
	 * @return array
	 */
	private function default_stats() {
		return array(
			'submitted'            => 0,
			'verdicted'            => 0,
			'failed'               => 0,
			'threats'              => 0,
			'submissions_complete' => false,
			'unknowns'             => array(),
			'neoray_errors'        => 0,
			'neoray_skipped'       => 0,
			'skip_reasons'         => array(),
			'worker_deaths'        => 0,
		);
	}

	/**
	 * Initialise the per-scan stats block if missing.
	 *
	 * @param string $scan_id Scan UUID.
	 */
	private function ensure_scan_stats( $scan_id ) {
		if ( ! isset( $this->state['scan_stats'][ $scan_id ] ) ) {
			$this->state['scan_stats'][ $scan_id ] = $this->default_stats();
			return;
		}
		foreach ( $this->default_stats() as $key => $default ) {
			if ( ! array_key_exists( $key, $this->state['scan_stats'][ $scan_id ] ) ) {
				$this->state['scan_stats'][ $scan_id ][ $key ] = $default;
			}
		}
	}

	/**
	 * Whether the processing time budget has been exhausted.
	 *
	 * @return bool
	 */
	private function is_time_up() {
		if ( $this->single_batch && $this->batch_processed ) {
			return true;
		}
		return ( microtime( true ) - $this->start_time ) >= $this->time_limit;
	}

	/**
	 * Persist a pending chunk into runtime_kv. An empty write "seals" the
	 * chunk so drain consumers skip past it.
	 *
	 * @param int   $index Chunk index.
	 * @param array $files File records.
	 * @return void
	 */
	private function store_chunk( $index, array $files ) {
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $this->kv_chunk_key( $index ),
				'kv_value'   => (string) wp_json_encode( $files ),
				'expires_at' => $now + self::KV_TTL,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Retrieve a chunk by index.
	 *
	 * @param int $index Chunk index.
	 * @return array
	 */
	private function load_chunk( $index ) {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $this->kv_chunk_key( $index ) )
		);
		if ( null === $raw ) {
			return array();
		}
		$decoded = json_decode( (string) $raw, true );
		return is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * Delete a chunk after it has been consumed.
	 *
	 * @param int $index Chunk index.
	 * @return void
	 */
	private function delete_chunk( $index ) {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => $this->kv_chunk_key( $index ) ) );
	}

	/**
	 * Read the currently open (not yet sealed) chunk used for appends.
	 *
	 * @return array
	 */
	private function load_pending_tail() {
		return $this->load_chunk( $this->state['chunk_in'] );
	}

	/**
	 * Compose the runtime_kv key for this queue's serialized state.
	 *
	 * @return string
	 */
	private function kv_state_key() {
		return 'scan:' . $this->scan_id . ':vq_state';
	}

	/**
	 * Compose the runtime_kv key for a pending chunk.
	 *
	 * @param int $index Chunk index.
	 * @return string
	 */
	private function kv_chunk_key( $index ) {
		return 'scan:' . $this->scan_id . ':vq_chunk:' . (int) $index;
	}

	/**
	 * Compose the runtime_kv key for a chunk's sibling cursor
	 * row. Lives next to the chunk row keyed by `kv_chunk_key` so `purge()`
	 * sweeps both via its single `LIKE 'scan:<id>:%'` delete.
	 *
	 * @param int $index Chunk index.
	 * @return string
	 */
	private function kv_cursor_key( $index ) {
		return 'scan:' . $this->scan_id . ':vq_cursor:' . (int) $index;
	}
}

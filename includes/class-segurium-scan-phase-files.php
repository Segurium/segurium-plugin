<?php
/**
 * Files phase of a scan run: the malware scan engine behind the phase contract.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wraps {@see Segurium_Scan}. The run ID is the engine's scan ID.
 */
final class Segurium_Scan_Phase_Files implements Segurium_Scan_Phase {

	const ID = 'files';

	/**
	 * Run ID.
	 *
	 * @var string
	 */
	private $run_id;

	/**
	 * Run trigger.
	 *
	 * @var string
	 */
	private $trigger;

	/**
	 * Engine, built on first use.
	 *
	 * @var object|null
	 */
	private $engine = null;

	/**
	 * Whether the engine holds loaded or freshly created state.
	 *
	 * @var bool
	 */
	private $loaded = false;

	/**
	 * Constructor.
	 *
	 * @param string $run_id  Run ID.
	 * @param string $trigger Run trigger.
	 */
	public function __construct( $run_id, $trigger ) {
		$this->run_id  = (string) $run_id;
		$this->trigger = (string) $trigger;
	}

	/**
	 * Phase ID.
	 *
	 * @return string
	 */
	public function id() {
		return self::ID;
	}

	/**
	 * History row type of the file scan. The three full-scan queries read
	 * `manual`, `scheduled` and `rescan` only.
	 *
	 * @return string
	 */
	public function scan_type() {
		return in_array( $this->trigger, array( 'scheduled', 'rescan' ), true ) ? $this->trigger : 'manual';
	}

	/**
	 * Create the file scan state.
	 *
	 * @return void
	 */
	public function initialize() {
		$this->engine()->initialize( $this->run_id, $this->scan_type() );
		$this->loaded = true;
	}

	/**
	 * Load the file scan state.
	 *
	 * @return bool
	 */
	public function load_state() {
		$this->loaded = (bool) $this->engine()->load_state();
		return $this->loaded;
	}

	/**
	 * One chunk, with verdict batches drained at full throughput.
	 *
	 * @return array
	 */
	public function process_chunk() {
		add_filter( 'segurium_scan_verdict_single_batch', '__return_false' );
		try {
			return (array) $this->engine()->process_chunk();
		} finally {
			remove_filter( 'segurium_scan_verdict_single_batch', '__return_false' );
		}
	}

	/**
	 * Drain upload verdicts, then read the upload floor.
	 *
	 * @return string
	 */
	public function after_chunk() {
		if ( class_exists( 'Segurium_Async_Scan_Results_Loop' ) ) {
			Segurium_Async_Scan_Results_Loop::run( $this->run_id );
		}
		if ( class_exists( 'Segurium_Async_Scan_Submitter' ) && Segurium_Async_Scan_Submitter::floor_reached_for( $this->run_id ) ) {
			return Segurium_Scan_Runner::REASON_ABORTED_UPLOAD_CAPACITY;
		}
		return '';
	}

	/**
	 * Fire `segurium_scan_completed`. The listeners remove the engine state.
	 *
	 * @return void
	 */
	public function report_completion() {
		$engine = $this->engine();
		if ( $engine instanceof Segurium_Scan ) {
			$engine->emit_terminal_completion();
		}
		/**
		 * Fires when the file scan of a run completes, with the lock held.
		 *
		 * @param Segurium_Scan $engine Completed scan instance.
		 */
		do_action( 'segurium_scan_completed', $engine );
	}

	/**
	 * End the file scan as cancelled.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @return void
	 */
	public function mark_cancelled( $reason_code, $cleanup ) {
		$this->engine()->mark_cancelled( $reason_code, $cleanup );
	}

	/**
	 * End the file scan as aborted.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @param array  $detail      Extra `scan_aborted` fields.
	 * @return void
	 */
	public function mark_aborted( $reason_code, $cleanup, array $detail ) {
		$this->engine()->mark_aborted( $reason_code, $cleanup, $detail );
	}

	/**
	 * Remove the workspace and the engine rows.
	 *
	 * @return void
	 */
	public function cleanup_state() {
		if ( $this->loaded && method_exists( $this->engine(), 'cleanup_state' ) ) {
			$this->engine()->cleanup_state();
			return;
		}
		Segurium_Scan::purge_runtime( $this->run_id, $this->active_workspace() );
	}

	/**
	 * Engine progress.
	 *
	 * @return array
	 */
	public function get_progress_snapshot() {
		return (array) $this->engine()->get_progress_snapshot();
	}

	/**
	 * End of the file scan as the history row states it.
	 *
	 * @return array{status:string,error_code:string}|null
	 */
	public function settled() {
		$row = Segurium_Storage::table_get_row(
			'scan_history',
			'SELECT status, error_code FROM {{table}} WHERE scan_uuid = %s',
			array( $this->run_id ),
			ARRAY_A
		);
		$map = array(
			'completed' => Segurium_Scan_Run::PHASE_DONE,
			'cancelled' => Segurium_Scan_Run::PHASE_CANCELLED,
			'aborted'   => Segurium_Scan_Run::PHASE_FAILED,
		);
		if ( ! is_array( $row ) || ! isset( $map[ $row['status'] ] ) ) {
			return null;
		}
		return array(
			'status'     => $map[ $row['status'] ],
			'error_code' => (string) $row['error_code'],
		);
	}

	/**
	 * Counters frozen on the history row.
	 *
	 * @return array<string,int>
	 */
	public function counters() {
		$row = Segurium_Storage::table_get_row(
			'scan_history',
			'SELECT files_found, files_scanned, files_failed, files_skipped, threats_found FROM {{table}} WHERE scan_uuid = %s',
			array( $this->run_id ),
			ARRAY_A
		);
		return is_array( $row ) ? array_map( 'intval', $row ) : array();
	}

	/**
	 * Workspace named by the active-scan marker, when the marker names this run.
	 *
	 * @return string
	 */
	private function active_workspace() {
		$raw    = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( Segurium_Scan::KV_ACTIVE )
		);
		$active = null === $raw ? null : json_decode( (string) $raw, true );
		if ( ! is_array( $active ) || ! isset( $active['scan_id'], $active['workspace'] ) || (string) $active['scan_id'] !== $this->run_id ) {
			return '';
		}
		return (string) $active['workspace'];
	}

	/**
	 * Engine instance. Tests inject one through `segurium_runner_test_scan`.
	 *
	 * @return object
	 */
	private function engine() {
		if ( null === $this->engine ) {
			$filtered     = apply_filters( 'segurium_runner_test_scan', null );
			$this->engine = is_object( $filtered ) ? $filtered : Segurium::get_instance()->build_scan_for_runner();
		}
		return $this->engine;
	}
}

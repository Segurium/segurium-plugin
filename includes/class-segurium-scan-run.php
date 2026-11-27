<?php
/**
 * A scan run: one lock holder that walks an ordered phase list.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The engine {@see Segurium_Scan_Runner} drives. Delegates chunk work to the
 * current phase and keeps the run row in `scan_runs`.
 */
final class Segurium_Scan_Run {

	const STATUS_RUNNING   = 'running';
	const STATUS_COMPLETED = 'completed';
	const STATUS_CANCELLED = 'cancelled';
	const STATUS_ABORTED   = 'aborted';

	const PHASE_PENDING   = 'pending';
	const PHASE_RUNNING   = 'running';
	const PHASE_DONE      = 'done';
	const PHASE_FAILED    = 'failed';
	const PHASE_SKIPPED   = 'skipped';
	const PHASE_CANCELLED = 'cancelled';

	const REASON_SKIPPED_NEEDS = 'SKIPPED_NEEDS_FAILED_PHASE';

	const FAULT_PHASE_INITIALIZE = 'phase_initialize';
	const FAULT_START_DIED       = 'start_died';
	const FAULT_LOCK_PHASE       = 'lock_phase';

	const WRITE_ATTEMPTS = 3;

	const CONTENT_SWITCHES = array(
		'scan_crons'     => array(
			'phase'  => 'cron',
			'option' => 'segurium_scan_crons',
		),
		'scan_databases' => array(
			'phase'  => 'database',
			'option' => 'segurium_scan_databases',
		),
	);

	/**
	 * Run row, `phases` decoded.
	 *
	 * @var array
	 */
	private $row;

	/**
	 * Whether the row exists in the table.
	 *
	 * @var bool
	 */
	private $stored;

	/**
	 * Current phase, built on first use.
	 *
	 * @var Segurium_Scan_Phase|null
	 */
	private $phase = null;

	/**
	 * Why the last load_state() failed.
	 *
	 * @var array
	 */
	private $load_fault = array();

	/**
	 * Constructor.
	 *
	 * @param array $row    Run row with `phases` decoded.
	 * @param bool  $stored Whether the row exists in the table.
	 */
	private function __construct( array $row, $stored ) {
		$this->row    = $row;
		$this->stored = (bool) $stored;
	}

	/**
	 * The ordered phase list. A phase is one class implementing
	 * {@see Segurium_Scan_Phase} plus one entry here. `needs` names the phases
	 * whose failure inside the same run skips this one. A content phase
	 * joins only while {@see content_phase_enabled()} holds for it, unless
	 * `$every` asks for the phases a running run may already hold. The
	 * Self-Check entry is last whatever the filter adds.
	 *
	 * @param bool $every Whether the content phases join whatever their switch.
	 * @return array<string,array{class:string,needs:string[]}>
	 */
	public static function registry( $every = false ) {
		$phases = array(
			Segurium_Scan_Phase_Files::ID     => array(
				'class' => 'Segurium_Scan_Phase_Files',
				'needs' => array(),
			),
			Segurium_Scan_Phase_Integrity::ID => array(
				'class' => 'Segurium_Scan_Phase_Integrity',
				'needs' => array( Segurium_Scan_Phase_Files::ID ),
			),
		);
		if ( $every || self::content_phase_enabled( Segurium_Scan_Phase_Cron::ID ) ) {
			$phases[ Segurium_Scan_Phase_Cron::ID ] = array(
				'class' => 'Segurium_Scan_Phase_Cron',
				'needs' => array(),
			);
		}
		if ( $every || self::content_phase_enabled( Segurium_Scan_Phase_Database::ID ) ) {
			$phases[ Segurium_Scan_Phase_Database::ID ] = array(
				'class' => 'Segurium_Scan_Phase_Database',
				'needs' => array(),
			);
		}
		$phases[ Segurium_Scan_Phase_Self_Check::ID ] = array(
			'class' => 'Segurium_Scan_Phase_Self_Check',
			'needs' => array(),
		);

		$registry = (array) apply_filters( 'segurium_scan_run_phases', $phases );
		$last     = array( Segurium_Scan_Phase_Self_Check::ID => true );
		return array_diff_key( $registry, $last ) + array_intersect_key( $registry, $last );
	}

	/**
	 * Whether a phase that sends content other than files joins the
	 * registry. The switch CTI sets is the default; the filter answers last.
	 *
	 * @param string $phase Phase ID: `cron` or `database`.
	 * @return bool
	 */
	public static function content_phase_enabled( $phase ) {
		$on = false;
		foreach ( self::CONTENT_SWITCHES as $switch ) {
			if ( $phase === $switch['phase'] ) {
				$on = 1 === Segurium_Storage::setting_get_int( $switch['option'], 0 );
			}
		}
		return true === apply_filters( 'segurium_scan_content_phases', $on, (string) $phase );
	}

	/**
	 * Whether any phase that sends content other than files joins the registry.
	 *
	 * @return bool
	 */
	public static function content_phases_enabled() {
		return self::content_phase_enabled( Segurium_Scan_Phase_Cron::ID ) || self::content_phase_enabled( Segurium_Scan_Phase_Database::ID );
	}

	/**
	 * The stored value of each switch, by the setting name CTI uses.
	 *
	 * @return array<string,string> `on` or `off`.
	 */
	public static function content_switches() {
		$out = array();
		foreach ( self::CONTENT_SWITCHES as $name => $switch ) {
			$out[ $name ] = 1 === Segurium_Storage::setting_get_int( $switch['option'], 0 ) ? 'on' : 'off';
		}
		return $out;
	}

	/**
	 * Every registered phase ID, in run order.
	 *
	 * @return string[]
	 */
	public static function all_phases() {
		return array_keys( self::registry() );
	}

	/**
	 * Check a requested phase list against the registry.
	 *
	 * @param array $phase_ids Requested phase IDs, any order.
	 * @return string[]|null The list in run order, or null for an empty list or an unknown ID.
	 */
	public static function order_phases( array $phase_ids ) {
		$known     = self::all_phases();
		$phase_ids = array_unique( array_map( 'strval', $phase_ids ) );
		if ( empty( $phase_ids ) || array_diff( $phase_ids, $known ) ) {
			return null;
		}
		return array_values( array_intersect( $known, $phase_ids ) );
	}

	/**
	 * Insert the row of a new run. Every phase starts as pending.
	 *
	 * @param string   $run_id    Run ID.
	 * @param string[] $phase_ids Phase IDs from {@see order_phases()}.
	 * @param string   $trigger   What started the run.
	 * @return self
	 * @throws Segurium_Storage_Exception When the insert fails.
	 */
	public static function create( $run_id, array $phase_ids, $trigger ) {
		$run = new self( self::new_row( $run_id, $phase_ids, $trigger, time(), 0 ), true );
		Segurium_Storage::table_insert( 'scan_runs', self::encode( $run->row ) );
		return $run;
	}

	/**
	 * Read a run row.
	 *
	 * @param string $run_id Run ID.
	 * @return self|null Null when no row exists.
	 * @throws Segurium_Storage_Exception When the read fails.
	 */
	public static function load( $run_id ) {
		global $wpdb;
		$wpdb->last_error = '';
		$row              = Segurium_Storage::table_get_row(
			'scan_runs',
			'SELECT run_uuid, trigger_source, phase_list, status, error_code, current_phase, phases, announced, rev, started_at, finished_at FROM {{table}} WHERE run_uuid = %s',
			array( (string) $run_id ),
			ARRAY_A
		);
		if ( '' !== (string) $wpdb->last_error ) {
			throw new Segurium_Storage_Exception( 'scan_runs read failed: ' . esc_html( $wpdb->last_error ) );
		}
		if ( ! is_array( $row ) ) {
			return null;
		}
		$phases        = json_decode( (string) $row['phases'], true );
		$row['phases'] = is_array( $phases ) ? $phases : array();
		return new self( $row, true );
	}

	/**
	 * The run behind a lock. A lock with no phase field comes from a plugin
	 * version without run rows: the run is built from the lock, so a scan in
	 * flight during the update finishes under the same engine. A marker of
	 * that version naming the scan puts the integrity phase behind it.
	 *
	 * @param array $lock Lock payload from Segurium_Scan_Lock::get().
	 * @return self|null Null when a lock that names a phase has lost its row.
	 * @throws Segurium_Storage_Exception When the read fails.
	 */
	public static function for_lock( array $lock ) {
		$run = self::load( $lock['scan_id'] );
		if ( null !== $run || '' !== (string) $lock['phase'] ) {
			return $run;
		}

		$phase_ids = array( self::lock_phase_id( $lock ) );
		$trigger   = 'integrity' === $lock['scan_type'] ? 'manual' : (string) $lock['scan_type'];
		$chained   = Segurium_Scan_Phase_Files::ID === $phase_ids[0] ? Segurium_Integrity_Chain::legacy_marker_trigger( $lock['scan_id'] ) : '';
		if ( '' !== $chained ) {
			$phase_ids[] = Segurium_Scan_Phase_Integrity::ID;
			$trigger     = $chained;
		}

		$row                            = self::new_row( $lock['scan_id'], $phase_ids, $trigger, (int) $lock['started_at'], 0 );
		$row['phases'][0]['status']     = self::PHASE_RUNNING;
		$row['phases'][0]['started_at'] = (int) $lock['started_at'];
		try {
			Segurium_Storage::table_insert( 'scan_runs', self::encode( $row ) );
		} catch ( Segurium_Storage_Exception $e ) {
			$raced = self::load( $lock['scan_id'] );
			return null !== $raced ? $raced : new self( $row, false );
		}
		Segurium_Integrity_Chain::clear_legacy_marker();
		return new self( $row, true );
	}

	/**
	 * The run as the lock alone describes it: the lock's phase, running.
	 * Reads and writes no row. Serves the status polls, and stands in for a
	 * row that is gone or cannot be read.
	 *
	 * @param array $lock     Lock payload.
	 * @param bool  $announce True when the row is gone: ending the stand-in sends the run's end message.
	 * @return self
	 */
	public static function of_lock( array $lock, $announce = false ) {
		$row                        = self::new_row( $lock['scan_id'], array( self::lock_phase_id( $lock ) ), '', (int) $lock['started_at'], $announce ? 1 : 0 );
		$row['phases'][0]['status'] = self::PHASE_RUNNING;
		return new self( $row, false );
	}

	/**
	 * Phase a lock names. A lock without the phase field names its scan type.
	 *
	 * @param array $lock Lock payload.
	 * @return string
	 */
	private static function lock_phase_id( array $lock ) {
		if ( '' !== (string) $lock['phase'] ) {
			return (string) $lock['phase'];
		}
		return 'integrity' === $lock['scan_type'] ? Segurium_Scan_Phase_Integrity::ID : Segurium_Scan_Phase_Files::ID;
	}

	/**
	 * Delete the row of a run that never started.
	 *
	 * @return void
	 */
	public function discard() {
		Segurium_Storage::table_delete( 'scan_runs', array( 'run_uuid' => $this->run_id() ) );
	}

	/**
	 * Outcome of the phase in the newest run where the phase ended or was skipped, a run still going included.
	 *
	 * @param string $phase_id Phase ID.
	 * @return array{status:string,error_code:string,finished_at:int}|null Null when no run row holds one.
	 */
	public static function last_phase_result( $phase_id ) {
		$rows = Segurium_Storage::table_get_col(
			'scan_runs',
			'SELECT phases FROM {{table}} WHERE FIND_IN_SET( %s, phase_list ) > 0 ORDER BY started_at DESC, id DESC LIMIT 20',
			array( (string) $phase_id )
		);
		foreach ( $rows as $json ) {
			foreach ( (array) json_decode( (string) $json, true ) as $entry ) {
				if ( isset( $entry['id'], $entry['status'] ) && $entry['id'] === $phase_id
					&& in_array( $entry['status'], array( self::PHASE_DONE, self::PHASE_FAILED, self::PHASE_CANCELLED, self::PHASE_SKIPPED ), true ) ) {
					return array(
						'status'      => (string) $entry['status'],
						'error_code'  => (string) $entry['error_code'],
						'finished_at' => (int) $entry['finished_at'],
					);
				}
			}
		}
		return null;
	}

	/**
	 * Close run rows left at running by a run that lost the lock. A current
	 * phase whose own record says done keeps that end.
	 *
	 * @param string $lock_run_id Run ID holding the lock, '' for none.
	 * @return int Rows closed.
	 */
	public static function sweep_orphans( $lock_run_id ) {
		$ids    = Segurium_Storage::table_get_col(
			'scan_runs',
			'SELECT run_uuid FROM {{table}} WHERE status = %s AND started_at < %d',
			array( self::STATUS_RUNNING, time() - Segurium_Scan_Lock::HEARTBEAT_MAX_AGE )
		);
		$closed = 0;
		foreach ( $ids as $run_id ) {
			if ( (string) $run_id === (string) $lock_run_id ) {
				continue;
			}
			$run = self::load( $run_id );
			if ( null === $run ) {
				continue;
			}
			$ended = $run->phase_settled();
			if ( null !== $ended && self::PHASE_DONE === $ended['status'] ) {
				$run->complete_phase( false );
			}
			if ( $run->is_over() || $run->abort( Segurium_Scan_Runner::REASON_ABORTED_ORPHANED ) ) {
				++$closed;
			}
		}
		return $closed;
	}

	/**
	 * Run ID. Equals the scan ID of the files phase and the lock's scan ID.
	 *
	 * @return string
	 */
	public function run_id() {
		return (string) $this->row['run_uuid'];
	}

	/**
	 * What started the run.
	 *
	 * @return string
	 */
	public function trigger() {
		return (string) $this->row['trigger_source'];
	}

	/**
	 * Run status.
	 *
	 * @return string
	 */
	public function status() {
		return (string) $this->row['status'];
	}

	/**
	 * Whether the run reached completed, cancelled or aborted.
	 *
	 * @return bool
	 */
	public function is_over() {
		return self::STATUS_RUNNING !== $this->status();
	}

	/**
	 * Current phase ID. Stays on the last phase after the run ends.
	 *
	 * @return string
	 */
	public function phase_id() {
		return (string) $this->row['current_phase'];
	}

	/**
	 * Lock scan type of the current phase.
	 *
	 * @return string
	 */
	public function scan_type() {
		$phase = $this->phase();
		return null === $phase ? '' : $phase->scan_type();
	}

	/**
	 * Name the current phase on the lock. The 6-hour ceiling restarts.
	 *
	 * @return bool False when the lock write did not land.
	 */
	public function point_lock() {
		return Segurium_Scan_Lock::set_phase( $this->run_id(), $this->phase_id(), $this->scan_type() );
	}

	/**
	 * Per-phase rows, in run order.
	 *
	 * @return array<int,array>
	 */
	public function phases() {
		return $this->row['phases'];
	}

	/**
	 * Status of one phase.
	 *
	 * @param string|null $phase_id Phase ID; the current phase when null.
	 * @return string '' when the run has no such phase.
	 */
	public function phase_status( $phase_id = null ) {
		$index = $this->phase_index( null === $phase_id ? $this->phase_id() : (string) $phase_id );
		return null === $index ? '' : (string) $this->row['phases'][ $index ]['status'];
	}

	/**
	 * Why the last load_state() failed, for the `scan_aborted` payload.
	 *
	 * @return array
	 */
	public function load_fault() {
		return $this->load_fault;
	}

	/**
	 * Whether the first phase has no state yet. Only start_run() creates it.
	 *
	 * @return bool
	 */
	public function awaits_start() {
		return ! $this->is_over()
			&& 0 === $this->phase_index( $this->phase_id() )
			&& self::PHASE_PENDING === $this->phase_status();
	}

	/**
	 * Create the state of the first phase and tell the cloud the run started.
	 * Called by start_run(), which holds the lock. A phase that cannot start throws.
	 *
	 * @return bool False when a stop or a tick moved the run during the start:
	 *              the row and the lock are theirs, the phase state is closed here.
	 */
	public function begin() {
		$phase = $this->phase();
		$phase->initialize();
		if ( ! $this->mark_phase_running( true ) ) {
			$this->refresh();
			$reason = (string) $this->row['error_code'];
			$reason = '' === $reason ? Segurium_Scan_Runner::REASON_ABORTED_ENGINE_LOAD_FAILED : $reason;
			if ( null !== $phase->settled() ) {
				$phase->cleanup_state();
			} elseif ( self::STATUS_CANCELLED === $this->status() ) {
				$phase->mark_cancelled( $reason, true );
			} else {
				$phase->mark_aborted( $reason, true, array() );
			}
			return false;
		}
		Segurium_Storage::cti_send_message(
			'scan_run_started',
			array(
				'run_id'  => $this->run_id(),
				'trigger' => $this->trigger(),
				'phases'  => array_column( $this->phases(), 'id' ),
			)
		);
		return true;
	}

	/**
	 * Load the state of the current phase.
	 *
	 * @param bool $start_pending True inside a tick: a pending phase after the first is started.
	 * @return bool
	 */
	public function load_state( $start_pending = false ) {
		$this->load_fault = array( 'fault' => Segurium_Scan_Runner::FAULT_ORCHESTRATOR_STATE );
		$phase            = $this->phase();
		if ( null === $phase ) {
			return false;
		}
		if ( ! $start_pending || $this->is_over() || self::PHASE_PENDING !== $this->phase_status() || $this->awaits_start() ) {
			return $phase->load_state();
		}

		if ( ! $this->point_lock() ) {
			$this->load_fault = array( 'fault' => self::FAULT_LOCK_PHASE );
			return false;
		}
		try {
			$phase->initialize();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( sprintf( '[segurium-scan-run] %s phase did not start: %s: %s', $phase->id(), get_class( $e ), $e->getMessage() ) );
			$this->load_fault = array(
				'fault' => self::FAULT_PHASE_INITIALIZE,
				'error' => get_class( $e ),
			);
			$phase->cleanup_state();
			return false;
		}
		if ( ! $this->mark_phase_running() ) {
			$phase->cleanup_state();
			return false;
		}
		return true;
	}

	/**
	 * One chunk of the current phase.
	 *
	 * @return array
	 */
	public function process_chunk() {
		return $this->phase()->process_chunk();
	}

	/**
	 * Post-chunk work of the current phase.
	 *
	 * @return string A reason code that fails the phase, or ''.
	 */
	public function after_chunk() {
		return $this->phase()->after_chunk();
	}

	/**
	 * Progress of the current phase.
	 *
	 * @return array
	 */
	public function get_progress_snapshot() {
		return $this->phase()->get_progress_snapshot();
	}

	/**
	 * End the current phase's engine as cancelled.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @return void
	 */
	public function mark_cancelled( $reason_code, $cleanup ) {
		$this->phase()->mark_cancelled( $reason_code, $cleanup );
	}

	/**
	 * End the current phase's engine as aborted.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @param array  $detail      Extra fields for the phase's end message.
	 * @return void
	 */
	public function mark_aborted( $reason_code, $cleanup, array $detail = array() ) {
		$this->phase()->mark_aborted( $reason_code, $cleanup, $detail );
	}

	/**
	 * Remove the state of a phase.
	 *
	 * @param string|null $phase_id Phase ID; the current phase when null.
	 * @return void
	 */
	public function cleanup_state( $phase_id = null ) {
		$phase = null === $phase_id || $phase_id === $this->phase_id() ? $this->phase() : $this->build_phase( $phase_id );
		if ( null !== $phase ) {
			$phase->cleanup_state();
		}
	}

	/**
	 * End of a phase the run row still shows as running, as its own record states it.
	 *
	 * @return array{status:string,error_code:string}|null
	 */
	public function phase_settled() {
		$phase = $this->phase();
		if ( null === $phase || $this->is_over() || self::PHASE_RUNNING !== $this->phase_status() ) {
			return null;
		}
		return $phase->settled();
	}

	/**
	 * The current phase ended: fire its completion listeners, then advance.
	 * A phase that ended itself as skipped fires none.
	 *
	 * @param bool   $with_listeners False when the phase state is gone.
	 * @param string $skip_reason    Reason code of a phase that ended itself as skipped.
	 * @return bool False when another writer moved the run first.
	 */
	public function complete_phase( $with_listeners = true, $skip_reason = '' ) {
		if ( '' !== (string) $skip_reason ) {
			return $this->settle( self::PHASE_SKIPPED, (string) $skip_reason );
		}
		if ( $with_listeners ) {
			$this->phase()->report_completion();
		}
		return $this->settle( self::PHASE_DONE, '' );
	}

	/**
	 * The current phase failed. Phases needing a failed phase are skipped;
	 * the run goes on with the next phase, or ends as completed.
	 *
	 * @param string $reason_code Reason code of the failure.
	 * @return bool False when another writer moved the run first.
	 */
	public function fail_phase( $reason_code ) {
		return $this->settle( self::PHASE_FAILED, (string) $reason_code );
	}

	/**
	 * Stop: the current phase ends as cancelled, the rest as skipped.
	 *
	 * @param string $reason_code USER_CANCEL or REMOTE_CANCEL.
	 * @return bool False when the run ended otherwise first.
	 */
	public function cancel( $reason_code ) {
		return $this->settle( self::PHASE_CANCELLED, (string) $reason_code, self::STATUS_CANCELLED );
	}

	/**
	 * The run cannot go on: its row or its lock is gone. The current phase
	 * ends as failed, the rest as skipped.
	 *
	 * @param string $reason_code Reason code.
	 * @return bool False when the run ended otherwise first.
	 */
	public function abort( $reason_code ) {
		return $this->settle( self::PHASE_FAILED, (string) $reason_code, self::STATUS_ABORTED );
	}

	/**
	 * Read the row again.
	 *
	 * @return bool True while the run is still running.
	 */
	public function refresh() {
		$fresh = self::load( $this->run_id() );
		if ( null === $fresh ) {
			return false;
		}
		if ( $fresh->phase_id() !== $this->phase_id() ) {
			$this->phase = null;
		}
		$this->row = $fresh->row;
		return ! $this->is_over();
	}

	/**
	 * Run fields for the status endpoints.
	 *
	 * @return array
	 */
	public function status_fields() {
		$phases = array();
		foreach ( $this->phases() as $entry ) {
			$phases[] = array(
				'id'     => (string) $entry['id'],
				'status' => (string) $entry['status'],
			);
		}
		return array(
			'run_id'      => $this->run_id(),
			'run_trigger' => $this->trigger(),
			'run_phase'   => $this->phase_id(),
			'run_phases'  => $phases,
		);
	}

	/**
	 * End the current phase and move the run on, in one conditional write.
	 *
	 * @param string      $phase_status End status of the current phase.
	 * @param string      $error_code   Reason code of the phase.
	 * @param string|null $end_run      Run status that ends the run now; null lets the phase list decide.
	 * @return bool False when another writer moved the run first.
	 */
	private function settle( $phase_status, $error_code, $end_run = null ) {
		$phase_id = $this->phase_id();
		for ( $attempt = 0; $attempt < self::WRITE_ATTEMPTS; $attempt++ ) {
			if ( $this->write( $this->settled_row( $phase_status, $error_code, $end_run ) ) ) {
				if ( $this->is_over() && ! empty( $this->row['announced'] ) ) {
					$this->send_finished();
				}
				return true;
			}
			if ( ! $this->refresh() || ( null === $end_run && $this->phase_id() !== $phase_id ) ) {
				return false;
			}
		}
		return false;
	}

	/**
	 * Column values that end the current phase.
	 *
	 * @param string      $phase_status End status of the current phase.
	 * @param string      $error_code   Reason code of the phase.
	 * @param string|null $end_run      Run status that ends the run now, or null.
	 * @return array
	 */
	private function settled_row( $phase_status, $error_code, $end_run ) {
		$now    = time();
		$index  = (int) $this->phase_index( $this->phase_id() );
		$phases = $this->row['phases'];

		if ( null !== $end_run && self::PHASE_PENDING === $phases[ $index ]['status'] ) {
			$phase_status = self::PHASE_SKIPPED;
		} else {
			$phases[ $index ]['counters'] = $this->counters();
		}
		$phases[ $index ]['status']      = $phase_status;
		$phases[ $index ]['error_code']  = $error_code;
		$phases[ $index ]['finished_at'] = $now;

		$registry = self::registry( true );
		$next     = '';
		$count    = count( $phases );
		for ( $i = $index + 1; $i < $count; $i++ ) {
			if ( self::PHASE_PENDING !== $phases[ $i ]['status'] ) {
				continue;
			}
			$skip = null !== $end_run ? $error_code : '';
			if ( '' === $skip && self::needs_unmet( $phases, $registry, $phases[ $i ]['id'] ) ) {
				$skip = self::REASON_SKIPPED_NEEDS;
			}
			if ( '' !== $skip ) {
				$phases[ $i ]['status']     = self::PHASE_SKIPPED;
				$phases[ $i ]['error_code'] = $skip;
			} elseif ( '' === $next ) {
				$next = (string) $phases[ $i ]['id'];
			}
		}

		$changes = array( 'phases' => $phases );
		if ( '' !== $next ) {
			$changes['current_phase'] = $next;
			return $changes;
		}
		$changes['status']      = null === $end_run ? self::STATUS_COMPLETED : $end_run;
		$changes['error_code']  = null === $end_run ? '' : $error_code;
		$changes['finished_at'] = $now;
		return $changes;
	}

	/**
	 * Counters of the current phase. A failed read leaves them empty.
	 *
	 * @return array
	 */
	private function counters() {
		$phase = $this->phase();
		try {
			return null === $phase ? array() : (array) $phase->counters();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-scan-run] counters read failed: ' . $e->getMessage() );
			return array();
		}
	}

	/**
	 * Whether a phase needs one that failed, was skipped or was cancelled in this run.
	 *
	 * @param array  $phases   Per-phase rows.
	 * @param array  $registry Phase registry.
	 * @param string $phase_id Phase to check.
	 * @return bool
	 */
	private static function needs_unmet( array $phases, array $registry, $phase_id ) {
		$needs = isset( $registry[ $phase_id ]['needs'] ) ? (array) $registry[ $phase_id ]['needs'] : array();
		foreach ( $phases as $entry ) {
			if ( in_array( $entry['id'], $needs, true )
				&& in_array( $entry['status'], array( self::PHASE_FAILED, self::PHASE_SKIPPED, self::PHASE_CANCELLED ), true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Record that the current phase runs.
	 *
	 * @param bool $announce True for the first phase: the run sends its start message next.
	 * @return bool False when another writer changed the row first.
	 */
	private function mark_phase_running( $announce = false ) {
		$index = $this->phase_index( $this->phase_id() );
		if ( null === $index ) {
			return false;
		}
		$phases                         = $this->row['phases'];
		$phases[ $index ]['status']     = self::PHASE_RUNNING;
		$phases[ $index ]['started_at'] = time();
		$changes                        = array( 'phases' => $phases );
		if ( $announce ) {
			$changes['announced'] = 1;
		}
		return $this->write( $changes );
	}

	/**
	 * Tell the cloud the run ended. Only the writer that ended the run sends.
	 *
	 * @return void
	 */
	private function send_finished() {
		$phases = array();
		foreach ( $this->phases() as $entry ) {
			$started  = (int) $entry['started_at'];
			$finished = (int) $entry['finished_at'];
			$phases[] = array(
				'id'               => (string) $entry['id'],
				'status'           => (string) $entry['status'],
				'error_code'       => (string) $entry['error_code'],
				'counters'         => (object) $entry['counters'],
				'duration_seconds' => $started > 0 && $finished >= $started ? $finished - $started : 0,
			);
		}
		Segurium_Storage::cti_send_message(
			'scan_run_finished',
			array(
				'run_id'     => $this->run_id(),
				'trigger'    => $this->trigger(),
				'status'     => $this->status(),
				'error_code' => (string) $this->row['error_code'],
				'phases'     => $phases,
			)
		);
	}

	/**
	 * Write changes, guarded by the row revision this object read.
	 *
	 * @param array $changes Column values, `phases` decoded.
	 * @return bool False when the revision moved on.
	 */
	private function write( array $changes ) {
		$rev            = (int) $this->row['rev'];
		$changes['rev'] = $rev + 1;
		if ( $this->stored ) {
			$updated = Segurium_Storage::table_update(
				'scan_runs',
				self::encode( $changes ),
				array(
					'run_uuid' => $this->run_id(),
					'rev'      => $rev,
				)
			);
			if ( 1 !== $updated ) {
				return false;
			}
		}
		if ( isset( $changes['current_phase'] ) && $changes['current_phase'] !== $this->phase_id() ) {
			$this->phase = null;
		}
		$this->row = array_merge( $this->row, $changes );
		return true;
	}

	/**
	 * Position of a phase in the run.
	 *
	 * @param string $phase_id Phase ID.
	 * @return int|null
	 */
	private function phase_index( $phase_id ) {
		foreach ( $this->row['phases'] as $index => $entry ) {
			if ( $entry['id'] === $phase_id ) {
				return $index;
			}
		}
		return null;
	}

	/**
	 * Current phase object.
	 *
	 * @return Segurium_Scan_Phase|null Null when the registry no longer lists the phase.
	 */
	private function phase() {
		if ( null === $this->phase ) {
			$this->phase = $this->build_phase( $this->phase_id() );
		}
		return $this->phase;
	}

	/**
	 * Build a phase of this run from the registry.
	 *
	 * @param string $phase_id Phase ID.
	 * @return Segurium_Scan_Phase|null
	 */
	private function build_phase( $phase_id ) {
		$registry = self::registry( true );
		if ( ! isset( $registry[ $phase_id ]['class'] ) || ! class_exists( $registry[ $phase_id ]['class'] ) ) {
			return null;
		}
		$class = $registry[ $phase_id ]['class'];
		$phase = new $class( $this->run_id(), $this->trigger() );
		return $phase instanceof Segurium_Scan_Phase ? $phase : null;
	}

	/**
	 * Row of a new run.
	 *
	 * @param string   $run_id     Run ID.
	 * @param string[] $phase_ids  Phase IDs in run order.
	 * @param string   $trigger    What started the run.
	 * @param int      $started_at Run start time.
	 * @param int      $announced  1 when the cloud is told about the run.
	 * @return array
	 */
	private static function new_row( $run_id, array $phase_ids, $trigger, $started_at, $announced ) {
		$phases = array();
		foreach ( $phase_ids as $phase_id ) {
			$phases[] = array(
				'id'          => (string) $phase_id,
				'status'      => self::PHASE_PENDING,
				'error_code'  => '',
				'counters'    => array(),
				'started_at'  => 0,
				'finished_at' => 0,
			);
		}
		return array(
			'run_uuid'       => (string) $run_id,
			'trigger_source' => substr( (string) $trigger, 0, 20 ),
			'phase_list'     => implode( ',', $phase_ids ),
			'status'         => self::STATUS_RUNNING,
			'error_code'     => '',
			'current_phase'  => (string) $phase_ids[0],
			'phases'         => $phases,
			'announced'      => (int) $announced,
			'rev'            => 0,
			'started_at'     => (int) $started_at,
			'finished_at'    => null,
		);
	}

	/**
	 * Column values for the table: `phases` as JSON.
	 *
	 * @param array $row Row or partial row.
	 * @return array
	 */
	private static function encode( array $row ) {
		if ( isset( $row['phases'] ) ) {
			$row['phases'] = (string) wp_json_encode( $row['phases'] );
		}
		return $row;
	}
}

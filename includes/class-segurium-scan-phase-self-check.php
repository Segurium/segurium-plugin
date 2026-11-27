<?php
/**
 * Self-Check phase of a scan run: the check battery behind the phase contract.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wraps {@see Segurium_Self_Check} as the last phase of a run.
 */
final class Segurium_Scan_Phase_Self_Check implements Segurium_Scan_Phase {

	const ID        = 'self_check';
	const KV_PREFIX = 'self_check_phase:';

	/**
	 * Run ID.
	 *
	 * @var string
	 */
	private $run_id;

	/**
	 * Phase state of this run, null when none is loaded.
	 *
	 * @var array|null
	 */
	private $state = null;

	/**
	 * Whether the battery of this request stored a grade.
	 *
	 * @var bool
	 */
	private $grade_stored = false;

	/**
	 * Constructor.
	 *
	 * @param string $run_id  Run ID.
	 * @param string $trigger Run trigger, unused.
	 */
	public function __construct( $run_id, $trigger ) {
		unset( $trigger );
		$this->run_id = (string) $run_id;
	}

	/**
	 * Whether the run that holds the lock still has this phase to run.
	 *
	 * @return bool
	 */
	public static function ahead() {
		$lock = Segurium_Scan_Lock::get();
		if ( null === $lock ) {
			return false;
		}
		try {
			$run = Segurium_Scan_Run::load( $lock['scan_id'] );
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-scan-phase-self-check] SELF_CHECK_PHASE_RUN_READ_FAILED: ' . $e->getMessage() );
			return false;
		}
		return null !== $run && ! $run->is_over()
			&& in_array( $run->phase_status( self::ID ), array( Segurium_Scan_Run::PHASE_PENDING, Segurium_Scan_Run::PHASE_RUNNING ), true );
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
	 * Lock scan type of the phase.
	 *
	 * @return string
	 */
	public function scan_type() {
		return self::ID;
	}

	/**
	 * Create the phase state. A repeat keeps the state the run already holds.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the state row cannot be written.
	 */
	public function initialize() {
		if ( $this->load_state() ) {
			return;
		}
		$this->drop_rows_of_other_runs();
		$this->state = array(
			'yielded'  => false,
			'counters' => null,
		);
		$this->save();
	}

	/**
	 * Load the phase state of this run.
	 *
	 * @return bool
	 */
	public function load_state() {
		$state       = json_decode(
			(string) Segurium_Storage::table_get_var(
				'runtime_kv',
				'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
				array( $this->state_key() )
			),
			true
		);
		$this->state = is_array( $state ) && array_key_exists( 'counters', $state ) ? $state : null;
		return null !== $this->state;
	}

	/**
	 * The whole battery in one chunk.
	 *
	 * @return array
	 */
	public function process_chunk() {
		if ( null === $this->state() ) {
			return array(
				'completed'          => false,
				'engine_load_failed' => true,
			);
		}
		if ( null === $this->state['counters'] ) {
			if ( $this->tick_is_too_short() ) {
				$this->state['yielded'] = true;
				$this->save();
				return array(
					'completed' => false,
					'yield'     => true,
				);
			}
			$this->run_battery();
		}
		return array( 'completed' => true );
	}

	/**
	 * Nothing follows the chunk.
	 *
	 * @return string
	 */
	public function after_chunk() {
		return '';
	}

	/**
	 * Nothing to fire.
	 *
	 * @return void
	 */
	public function report_completion() {
	}

	/**
	 * End the phase as cancelled.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @return void
	 */
	public function mark_cancelled( $reason_code, $cleanup ) {
		unset( $reason_code );
		if ( $cleanup ) {
			$this->cleanup_state();
		}
	}

	/**
	 * End the phase as failed.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @param array  $detail      Unused.
	 * @return void
	 */
	public function mark_aborted( $reason_code, $cleanup, array $detail ) {
		unset( $reason_code, $detail );
		if ( $cleanup ) {
			$this->cleanup_state();
		}
	}

	/**
	 * Remove the state row of this run.
	 *
	 * @return void
	 */
	public function cleanup_state() {
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => $this->state_key() ) );
		$this->state = null;
	}

	/**
	 * No tab shows progress of the phase.
	 *
	 * @return array
	 */
	public function get_progress_snapshot() {
		return array();
	}

	/**
	 * Done once the state row holds the counters.
	 *
	 * @return array{status:string,error_code:string}|null
	 */
	public function settled() {
		if ( array() === $this->counters() ) {
			return null;
		}
		return array(
			'status'     => Segurium_Scan_Run::PHASE_DONE,
			'error_code' => '',
		);
	}

	/**
	 * Grade, score and check counts. Empty until the battery ran.
	 *
	 * @return array<string,int|string>
	 */
	public function counters() {
		$state = $this->state();
		return null !== $state && is_array( $state['counters'] ) ? $state['counters'] : array();
	}

	/**
	 * Keep the counters of the grade the battery just stored. Listens to the
	 * grade write, so a worker that dies after the write does not grade twice.
	 *
	 * @param array $result Stored battery result.
	 * @return void
	 */
	public function record_grade( $result ) {
		$this->grade_stored = true;
		$this->keep_counters( $result );
	}

	/**
	 * Put the counters of a battery result on record. A write that fails is
	 * logged: the counters in memory still reach the run row.
	 *
	 * @param array|null $result Battery result, null when the battery threw.
	 * @return void
	 */
	private function keep_counters( $result ) {
		$this->state['counters'] = Segurium_Self_Check::summary( $result );
		try {
			$this->save();
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( sprintf( '[segurium-scan-phase-self-check] SELF_CHECK_PHASE_STATE_WRITE_FAILED run=%s: %s', $this->run_id, $e->getMessage() ) );
		}
	}

	/**
	 * Loaded state, read on first use.
	 *
	 * @return array|null
	 */
	private function state() {
		if ( null === $this->state ) {
			$this->load_state();
		}
		return $this->state;
	}

	/**
	 * Key of the state row. The row outlives the run as the end record of the phase.
	 *
	 * @return string
	 */
	private function state_key() {
		return self::KV_PREFIX . $this->run_id;
	}

	/**
	 * Remove the end records earlier runs left.
	 *
	 * @return void
	 */
	private function drop_rows_of_other_runs() {
		global $wpdb;
		$left = Segurium_Storage::table_get_col(
			'runtime_kv',
			'SELECT kv_key FROM {{table}} WHERE kv_key LIKE %s AND kv_key <> %s',
			array( $wpdb->esc_like( self::KV_PREFIX ) . '%', $this->state_key() )
		);
		foreach ( $left as $key ) {
			Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => (string) $key ) );
		}
	}

	/**
	 * Write the state row.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the write fails.
	 */
	private function save() {
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $this->state_key(),
				'kv_value'   => (string) wp_json_encode( $this->state ),
				'expires_at' => null,
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Whether the tick has less budget left than the loopback request may
	 * take. The phase hands back one tick at most.
	 *
	 * @return bool
	 */
	private function tick_is_too_short() {
		return empty( $this->state['yielded'] )
			&& Segurium_Scan_Runner::in_tick()
			&& Segurium_Scan_Runner::time_left_in_tick() < Segurium_Self_Check::SELF_PING_TIMEOUT;
	}

	/**
	 * Run the battery once. A battery that throws ends the phase as done.
	 *
	 * @return void
	 */
	private function run_battery() {
		$stored = 'set_transient_' . Segurium_Self_Check::CACHE_KEY;
		$result = null;
		add_action( $stored, array( $this, 'record_grade' ) );
		try {
			$result = Segurium_Self_Check::get_instance()->run_checks( true );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( sprintf( '[segurium-scan-phase-self-check] SELF_CHECK_PHASE_BATTERY_THREW run=%s: %s: %s', $this->run_id, get_class( $e ), $e->getMessage() ) );
		} finally {
			remove_action( $stored, array( $this, 'record_grade' ) );
		}
		if ( null === $this->state['counters'] ) {
			$this->keep_counters( $result );
		}
		if ( $this->grade_stored ) {
			Segurium_Self_Check::drop_refresh();
		}
	}
}

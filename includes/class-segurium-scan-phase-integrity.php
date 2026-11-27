<?php
/**
 * Integrity phase of a scan run: the integrity engine behind the phase contract.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wraps {@see Segurium_Integrity_Scan_State}.
 */
final class Segurium_Scan_Phase_Integrity implements Segurium_Scan_Phase {

	const ID = 'integrity';

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
	 * Lock scan type of the phase.
	 *
	 * @return string
	 */
	public function scan_type() {
		return 'integrity';
	}

	/**
	 * Create the integrity scan state. A failure leaves a notice for the Integrity tab.
	 *
	 * @return void
	 * @throws Throwable When the engine cannot start.
	 */
	public function initialize() {
		$engine = $this->engine();
		if ( method_exists( $engine, 'set_trigger' ) ) {
			$engine->set_trigger( Segurium_Integrity_Chain::TRIGGER === $this->trigger ? 'manual' : $this->trigger );
		}
		try {
			$engine->initialize( $this->run_id, 'integrity' );
		} catch ( Throwable $e ) {
			Segurium_Integrity_Chain::note_integrity_start_failed( $e->getMessage() );
			throw $e;
		}
	}

	/**
	 * Load the integrity scan state.
	 *
	 * @return bool
	 */
	public function load_state() {
		return (bool) $this->engine()->load_state();
	}

	/**
	 * One chunk of components.
	 *
	 * @return array
	 */
	public function process_chunk() {
		return (array) $this->engine()->process_chunk();
	}

	/**
	 * Nothing follows an integrity chunk.
	 *
	 * @return string
	 */
	public function after_chunk() {
		return '';
	}

	/**
	 * Fire `segurium_integrity_scan_completed`, then remove the completed state.
	 *
	 * @return void
	 */
	public function report_completion() {
		/**
		 * Fires when the integrity scan of a run completes, with the lock held.
		 *
		 * @param Segurium_Integrity_Scan_State $engine Completed engine.
		 */
		do_action( 'segurium_integrity_scan_completed', $this->engine() );
		$this->cleanup_state();
	}

	/**
	 * End the integrity scan as cancelled.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @return void
	 */
	public function mark_cancelled( $reason_code, $cleanup ) {
		$this->engine()->mark_cancelled( $reason_code, $cleanup );
	}

	/**
	 * End the integrity scan as aborted.
	 *
	 * @param string $reason_code Reason code.
	 * @param bool   $cleanup     Whether to remove the state now.
	 * @param array  $detail      Unused: the engine's message carries no extra fields.
	 * @return void
	 */
	public function mark_aborted( $reason_code, $cleanup, array $detail ) {
		unset( $detail );
		$this->engine()->mark_aborted( $reason_code, $cleanup );
	}

	/**
	 * Remove the workspace and the active-scan row.
	 *
	 * @return void
	 */
	public function cleanup_state() {
		if ( method_exists( $this->engine(), 'cleanup_state' ) ) {
			$this->engine()->cleanup_state();
		}
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
	 * The end record the engine writes in its last chunk, once the listeners
	 * removed the state. While the state is there the next chunk ends the phase.
	 *
	 * @return array{status:string,error_code:string}|null
	 */
	public function settled() {
		$ended  = Segurium_Storage::table_get_var( 'runtime_kv', 'SELECT kv_value FROM {{table}} WHERE kv_key = %s', array( Segurium_Integrity_Scan_State::KV_ENDED ) );
		$active = json_decode( (string) Segurium_Storage::table_get_var( 'runtime_kv', 'SELECT kv_value FROM {{table}} WHERE kv_key = %s', array( 'integrity_scan_active' ) ), true );
		$owner  = is_array( $active ) && isset( $active['scan_id'] ) ? (string) $active['scan_id'] : '';
		if ( $this->run_id !== (string) $ended || $this->run_id === $owner ) {
			return null;
		}
		return array(
			'status'     => Segurium_Scan_Run::PHASE_DONE,
			'error_code' => '',
		);
	}

	/**
	 * Component counts of the loaded state.
	 *
	 * @return array<string,int>
	 */
	public function counters() {
		$engine = $this->engine();
		if ( ! method_exists( $engine, 'get_state' ) ) {
			return array();
		}
		$state = (array) $engine->get_state();
		return array(
			'components' => isset( $state['total'] ) ? (int) $state['total'] : 0,
			'checked'    => isset( $state['processed'] ) ? (int) $state['processed'] : 0,
			'unverified' => isset( $state['unverified'] ) ? count( (array) $state['unverified'] ) : 0,
		);
	}

	/**
	 * Engine instance. Tests inject one through `segurium_runner_test_integrity_engine`.
	 *
	 * @return object
	 */
	private function engine() {
		if ( null === $this->engine ) {
			$filtered     = apply_filters( 'segurium_runner_test_integrity_engine', null );
			$this->engine = is_object( $filtered ) ? $filtered : Segurium::get_instance()->build_integrity_scan_for_runner();
		}
		return $this->engine;
	}
}

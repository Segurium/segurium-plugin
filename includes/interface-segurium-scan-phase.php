<?php
/**
 * One phase of a scan run.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * What {@see Segurium_Scan_Run} calls on the phase that holds the lock.
 * A phase is built with the run ID and the run trigger.
 */
interface Segurium_Scan_Phase {

	/**
	 * Phase ID, as listed in {@see Segurium_Scan_Run::registry()}.
	 *
	 * @return string
	 */
	public function id();

	/**
	 * Value of the lock's `scan_type` while the phase runs.
	 *
	 * @return string
	 */
	public function scan_type();

	/**
	 * Create the phase state.
	 *
	 * @return void
	 * @throws Throwable When the state cannot be created.
	 */
	public function initialize();

	/**
	 * Read the phase state saved by an earlier request.
	 *
	 * @return bool False when no state loads.
	 */
	public function load_state();

	/**
	 * Do one chunk of work.
	 *
	 * @return array Progress. `completed` true ends the phase. `skipped` with
	 *               a reason code next to `completed` ends the phase as
	 *               skipped. `yield` true ends the tick, and the next tick
	 *               calls the phase again.
	 */
	public function process_chunk();

	/**
	 * Work that follows each returned chunk.
	 *
	 * @return string A `Segurium_Scan_Runner::REASON_*` code that fails the phase, or ''.
	 */
	public function after_chunk();

	/**
	 * Fire the completion listeners. A worker death can repeat the call.
	 *
	 * @return void
	 */
	public function report_completion();

	/**
	 * End the phase as cancelled.
	 *
	 * @param string $reason_code `Segurium_Scan_Runner::REASON_*` code.
	 * @param bool   $cleanup     False leaves the state to the worker inside a tick.
	 * @return void
	 */
	public function mark_cancelled( $reason_code, $cleanup );

	/**
	 * End the phase as failed.
	 *
	 * @param string $reason_code `Segurium_Scan_Runner::REASON_*` code.
	 * @param bool   $cleanup     False leaves the state to the worker inside a tick.
	 * @param array  $detail      Extra fields for the phase's end message.
	 * @return void
	 */
	public function mark_aborted( $reason_code, $cleanup, array $detail );

	/**
	 * Remove the phase state. Works with no state loaded.
	 *
	 * @return void
	 */
	public function cleanup_state();

	/**
	 * Progress of the loaded state, for the status endpoints.
	 *
	 * @return array
	 */
	public function get_progress_snapshot();

	/**
	 * End of the phase as stored outside its state, for a phase whose worker
	 * died between the end and the run row update.
	 *
	 * @return array{status:string,error_code:string}|null Null when no record says the phase ended.
	 */
	public function settled();

	/**
	 * Counts for the run row and the run's end message.
	 *
	 * @return array<string,int|string>
	 */
	public function counters();
}

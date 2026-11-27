<?php
/**
 * Cron jobs phase of a scan run: every WP-Cron event as a content item.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Feeds the events of {@see Segurium_Cron_Reader} to the item pipeline. A
 * completed phase hands its threats to {@see Segurium_Content_Findings}.
 */
final class Segurium_Scan_Phase_Cron implements Segurium_Scan_Phase {

	const ID                = 'cron';
	const CAP               = 500;
	const DEFER_SEC         = 30;
	const SKIP_NO_CONSENT   = 'SKIPPED_NO_CONSENT';
	const SKIP_SWITCHED_OFF = 'SKIPPED_SWITCHED_OFF';

	/**
	 * Run ID.
	 *
	 * @var string
	 */
	private $run_id;

	/**
	 * Item pipeline of this run, built on first use.
	 *
	 * @var Segurium_Content_Items|null
	 */
	private $items = null;

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
	 * Phase ID.
	 *
	 * @return string
	 */
	public function id() {
		return self::ID;
	}

	/**
	 * Lock scan type of the phase. No tab and no status reader knows the value,
	 * so none shows a file or integrity scan in progress.
	 *
	 * @return string
	 */
	public function scan_type() {
		return self::ID;
	}

	/**
	 * Create the pipeline state. Reads no event and sends no request.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the state row cannot be written.
	 */
	public function initialize() {
		$this->items()->start();
	}

	/**
	 * Load the pipeline state of this run.
	 *
	 * @return bool
	 */
	public function load_state() {
		return $this->items()->load();
	}

	/**
	 * One unit of pipeline work, behind the consent gate.
	 *
	 * @return array
	 */
	public function process_chunk() {
		$items = $this->items();
		if ( ! $items->loaded() && ! $items->load() ) {
			return array(
				'completed'          => false,
				'engine_load_failed' => true,
			);
		}
		if ( ! Segurium_Consent::given() ) {
			$items->skip( self::SKIP_NO_CONSENT );
		} elseif ( ! Segurium_Scan_Run::content_phase_enabled( self::ID ) ) {
			$items->skip( self::SKIP_SWITCHED_OFF );
		} elseif ( $items->reads_next() && self::defers_read( $this->run_id ) ) {
			return array(
				'completed' => false,
				'yield'     => true,
			);
		}

		$outcome = $items->step();
		$end     = $items->ended();
		if ( null === $end ) {
			return array(
				'completed' => false,
				'yield'     => Segurium_Content_Items::WAIT === $outcome,
			);
		}
		if ( Segurium_Scan_Run::PHASE_SKIPPED === $end['status'] ) {
			return array(
				'completed' => true,
				'skipped'   => $end['error_code'],
			);
		}
		return array( 'completed' => Segurium_Scan_Run::PHASE_DONE === $end['status'] );
	}

	/**
	 * The reason code of a pipeline that failed.
	 *
	 * @return string
	 */
	public function after_chunk() {
		$end = $this->items()->ended();
		return null !== $end && Segurium_Scan_Run::PHASE_FAILED === $end['status'] ? $end['error_code'] : '';
	}

	/**
	 * Record the findings of the run; Auto-Fix cleans them when it is on.
	 *
	 * @return void
	 */
	public function report_completion() {
		Segurium_Content_Findings::complete_run( Segurium_Cron_Reader::KIND, $this->run_id, $this->items()->verdicts() );
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
	 * Remove the pipeline state and the stored bodies.
	 *
	 * @return void
	 */
	public function cleanup_state() {
		$this->items()->drop();
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
	 * End of the phase as the pipeline state records it.
	 *
	 * @return array{status:string,error_code:string}|null
	 */
	public function settled() {
		$items = $this->items();
		if ( ! $items->loaded() ) {
			$items->load();
		}
		return $items->ended();
	}

	/**
	 * Item counts. `threats_found` counts the events with a Malware or an Injection verdict.
	 *
	 * @return array<string,int>
	 */
	public function counters() {
		return $this->items()->counters();
	}

	/**
	 * Whether this request leaves the read to a later tick. WordPress and
	 * plugins register fewer cron callbacks inside an admin or AJAX request,
	 * so a read there gives other bodies than a read in a background request.
	 * A phase waits DEFER_SEC from its start at most.
	 *
	 * @param string $run_id Run ID.
	 * @return bool
	 */
	public static function defers_read( $run_id ) {
		if ( ! is_admin() ) {
			return false;
		}
		$lock = Segurium_Scan_Lock::get();
		return null !== $lock && $lock['scan_id'] === (string) $run_id
			&& time() - Segurium_Scan_Lock::phase_started_at( $lock ) < self::DEFER_SEC;
	}

	/**
	 * Item pipeline of this run.
	 *
	 * @return Segurium_Content_Items
	 */
	private function items() {
		if ( null === $this->items ) {
			$this->items = new Segurium_Content_Items( $this->run_id, Segurium_Cron_Reader::KIND, array( 'Segurium_Cron_Reader', 'read' ), self::CAP );
		}
		return $this->items;
	}
}

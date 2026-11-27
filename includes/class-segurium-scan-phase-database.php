<?php
/**
 * Database phase of a scan run: database rows as content items.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One item pipeline per part, one part after the other. A completed phase opens the findings of its verdicts.
 */
final class Segurium_Scan_Phase_Database implements Segurium_Scan_Phase {

	const ID = 'database';

	/**
	 * The parts in run order. The key is the prefix of the counters of the
	 * part. A part with a `walk` reads ahead across ticks before its
	 * pipeline collects, and the walk is the reader of the pipeline.
	 */
	const PARTS = array(
		'accounts'       => array(
			'kind'   => Segurium_Account_Reader::KIND_USER,
			'reader' => array( 'Segurium_Account_Reader', 'accounts' ),
			'cap'    => Segurium_Activity_Tracker::MAX_PRIVILEGED_ROWS + Segurium_Account_Lock::MAX_HIDDEN,
		),
		'sessions'       => array(
			'kind'   => Segurium_Account_Reader::KIND_SESSION,
			'reader' => array( 'Segurium_Account_Reader', 'sessions' ),
			'cap'    => 1000,
		),
		'scripts'        => array(
			'kind'     => Segurium_Db_Script_Walk::KIND,
			'walk'     => 'Segurium_Db_Script_Walk',
			'cap'      => Segurium_Db_Script_Walk::CAP,
			'max_body' => Segurium_Db_Script_Walk::MAX_SCRIPT_BYTES,
		),
		'script_sources' => array(
			'kind'     => Segurium_Db_Script_Walk::KIND_SRC,
			'walk_of'  => 'scripts',
			'cap'      => Segurium_Db_Script_Walk::CAP,
			'max_body' => Segurium_Db_Script_Walk::MAX_SCRIPT_BYTES,
		),
	);

	/**
	 * Run ID.
	 *
	 * @var string
	 */
	private $run_id;

	/**
	 * Item pipeline of each part, built on first use.
	 *
	 * @var array<string,Segurium_Content_Items>|null
	 */
	private $parts = null;

	/**
	 * Walk of each part that owns one, built with the pipelines.
	 *
	 * @var array<string,Segurium_Db_Script_Walk>
	 */
	private $walks = array();

	/**
	 * Walk each part reads: its own, or the one of `walk_of`.
	 *
	 * @var array<string,Segurium_Db_Script_Walk>
	 */
	private $readers = array();

	/**
	 * Reason code of each part, kept for the counters once the state is removed.
	 *
	 * @var array<string,string>
	 */
	private $codes = array();

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
	 * Lock scan type of the phase.
	 *
	 * @return string
	 */
	public function scan_type() {
		return self::ID;
	}

	/**
	 * Create the state of every part. Reads no row and sends no request.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When a state row cannot be written.
	 */
	public function initialize() {
		foreach ( $this->parts() as $items ) {
			$items->start();
		}
		foreach ( $this->walks as $walk ) {
			$walk->start();
		}
	}

	/**
	 * Load the state of every part.
	 *
	 * @return bool
	 */
	public function load_state() {
		$loaded = true;
		foreach ( $this->parts() as $items ) {
			$loaded = $items->load() && $loaded;
		}
		foreach ( $this->walks as $walk ) {
			$loaded = $walk->load() && $loaded;
		}
		return $loaded;
	}

	/**
	 * One unit of work of the first part that has not ended, behind the consent gate.
	 *
	 * @return array
	 */
	public function process_chunk() {
		$consent = Segurium_Consent::given();
		$on      = Segurium_Scan_Run::content_phase_enabled( self::ID );
		$open    = null;
		$walk    = null;
		$kind    = '';
		foreach ( $this->parts() as $name => $items ) {
			$part_walk = isset( $this->readers[ $name ] ) ? $this->readers[ $name ] : null;
			if ( ( ! $items->loaded() && ! $items->load() ) || ( null !== $part_walk && ! $part_walk->loaded() && ! $part_walk->load() ) ) {
				return array(
					'completed'          => false,
					'engine_load_failed' => true,
				);
			}
			if ( ! $consent ) {
				$items->skip( Segurium_Scan_Phase_Cron::SKIP_NO_CONSENT );
			} elseif ( ! $on ) {
				$items->skip( Segurium_Scan_Phase_Cron::SKIP_SWITCHED_OFF );
			}
			if ( null === $open && null === $items->ended() ) {
				$open = $items;
				$walk = $part_walk;
				$kind = self::PARTS[ $name ]['kind'];
			}
		}

		if ( null !== $open && $open->reads_next() && null !== $walk && ! $walk->finished() ) {
			return array(
				'completed' => false,
				'yield'     => Segurium_Content_Items::WAIT === $walk->step(),
			);
		}
		if ( null !== $open ) {
			// Code that hides an account can run in admin requests only, so a
			// read in a background request keeps the hidden flag stable.
			if ( $open->reads_next() && Segurium_Scan_Phase_Cron::defers_read( $this->run_id ) ) {
				return array(
					'completed' => false,
					'yield'     => true,
				);
			}
			$reading = $open->reads_next();
			$outcome = $open->step();
			if ( null !== $walk && ( $reading || null !== $open->ended() ) && ! $open->reads_next() ) {
				$walk->drop_bodies( $kind );
			}
			if ( null === $open->ended() ) {
				return array(
					'completed' => false,
					'yield'     => Segurium_Content_Items::WAIT === $outcome,
				);
			}
		}

		$end = $this->end();
		if ( null === $end ) {
			return array( 'completed' => false );
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
	 * The reason code of a phase whose parts all ended, one of them as failed.
	 *
	 * @return string
	 */
	public function after_chunk() {
		$end = $this->end();
		return null !== $end && Segurium_Scan_Run::PHASE_FAILED === $end['status'] ? $end['error_code'] : '';
	}

	/**
	 * Hand the verdicts of each part to the findings; the scripts take their places from the walk.
	 *
	 * @return void
	 */
	public function report_completion() {
		foreach ( $this->loaded_parts() as $name => $items ) {
			$verdicts = $items->verdicts();
			if ( isset( $this->readers[ $name ] ) ) {
				$verdicts = Segurium_Db_Script_Finding::with_places( $verdicts, $this->readers[ $name ], self::PARTS[ $name ]['kind'] );
			}
			Segurium_Content_Findings::complete_run( self::PARTS[ $name ]['kind'], $this->run_id, $verdicts );
		}
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
	 * Remove the state and the stored bodies of every part.
	 *
	 * @return void
	 */
	public function cleanup_state() {
		foreach ( $this->loaded_parts() as $name => $items ) {
			$end = $this->part_end( $name );
			if ( null !== $end ) {
				$this->codes[ $name ] = $end['error_code'];
			}
			$items->drop();
			if ( isset( $this->walks[ $name ] ) ) {
				$this->walks[ $name ]->drop();
			}
		}
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
	 * End of the phase as the state rows of its parts record it.
	 *
	 * @return array{status:string,error_code:string}|null
	 */
	public function settled() {
		$this->loaded_parts();
		return $this->end();
	}

	/**
	 * Counters of each part under its prefix, and `threats_found` over all parts.
	 *
	 * @return array<string,int|string>
	 */
	public function counters() {
		$counters = array();
		$threats  = null;
		foreach ( $this->parts() as $name => $items ) {
			$walked = isset( $this->walks[ $name ] ) ? $this->walks[ $name ]->counters() : array();
			foreach ( $walked + $items->counters() as $key => $count ) {
				$counters[ $name . '_' . $key ] = $count;
				if ( 'threats_found' === $key ) {
					$threats = (int) $threats + $count;
				}
			}
			$end  = $this->part_end( $name );
			$code = null !== $end ? $end['error_code'] : ( isset( $this->codes[ $name ] ) ? $this->codes[ $name ] : '' );
			if ( '' !== $code ) {
				$counters[ $name . '_error_code' ] = $code;
			}
		}
		return null === $threats ? $counters : $counters + array( 'threats_found' => $threats );
	}

	/**
	 * Totals over the parts of the counters: `objects` for the found items, then the item ends.
	 *
	 * @param array $counters Counters of the phase.
	 * @return array<string,int> Empty when no part read.
	 */
	public static function totals( array $counters ) {
		$read = array_filter(
			array_keys( self::PARTS ),
			static function ( $part ) use ( $counters ) {
				return isset( $counters[ $part . '_found' ] );
			}
		);
		if ( array() === $read ) {
			return array();
		}
		$total  = array(
			'objects'                            => 0,
			Segurium_Content_Items::ITEM_CLEAN   => 0,
			Segurium_Content_Items::ITEM_SKIPPED => 0,
			Segurium_Content_Items::ITEM_FAILED  => 0,
		);
		$reason = '/^(' . Segurium_Content_Items::ITEM_SKIPPED . '|' . Segurium_Content_Items::ITEM_FAILED . ')_/';
		$why    = array();
		$open   = 0;
		foreach ( $read as $part ) {
			foreach ( $counters as $key => $value ) {
				if ( 0 !== strpos( $key, $part . '_' ) ) {
					continue;
				}
				$name = substr( $key, strlen( $part ) + 1 );
				$name = 'found' === $name ? 'objects' : $name;
				if ( isset( $total[ $name ] ) ) {
					$total[ $name ] += $value;
				} elseif ( 'open' === $name ) {
					$open += $value;
				} elseif ( 1 === preg_match( $reason, $name ) ) {
					$why[ $name ] = ( $why[ $name ] ?? 0 ) + $value;
				}
			}
		}
		ksort( $why );
		$threats = isset( $counters['threats_found'] ) ? array( 'threats_found' => (int) $counters['threats_found'] ) : array();
		return array_merge( $total, $why, $open > 0 ? array( 'open' => $open ) : array(), $threats );
	}

	/**
	 * The worst end of the parts, failed before skipped before done.
	 *
	 * @return array{status:string,error_code:string}|null Null while a part is open.
	 */
	private function end() {
		$rank  = array(
			Segurium_Scan_Run::PHASE_DONE    => 0,
			Segurium_Scan_Run::PHASE_SKIPPED => 1,
		);
		$worst = array(
			'status'     => Segurium_Scan_Run::PHASE_DONE,
			'error_code' => '',
		);
		$top   = 0;
		foreach ( array_keys( $this->parts() ) as $name ) {
			$end = $this->part_end( $name );
			if ( null === $end ) {
				return null;
			}
			$level = isset( $rank[ $end['status'] ] ) ? $rank[ $end['status'] ] : 2;
			if ( $level > $top ) {
				$top   = $level;
				$worst = $end;
			}
		}
		return $worst;
	}

	/**
	 * End of one part: the end of its pipeline, or the fault of its walk
	 * once the pipeline is done with the scripts the walk found.
	 *
	 * @param string $name Part name.
	 * @return array{status:string,error_code:string}|null Null while the part is open.
	 */
	private function part_end( $name ) {
		$end   = $this->parts()[ $name ]->ended();
		$fault = isset( $this->readers[ $name ] ) ? $this->readers[ $name ]->fault() : '';
		if ( null !== $end && '' !== $fault && Segurium_Scan_Run::PHASE_DONE === $end['status'] ) {
			return array(
				'status'     => Segurium_Scan_Run::PHASE_FAILED,
				'error_code' => $fault,
			);
		}
		return $end;
	}

	/**
	 * Item pipeline of each part, with the state loaded where a row exists.
	 *
	 * @return array<string,Segurium_Content_Items>
	 */
	private function loaded_parts() {
		foreach ( $this->parts() as $items ) {
			if ( ! $items->loaded() ) {
				$items->load();
			}
		}
		foreach ( $this->walks as $walk ) {
			if ( ! $walk->loaded() ) {
				$walk->load();
			}
		}
		return $this->parts;
	}

	/**
	 * Item pipeline of each part of this run.
	 *
	 * @return array<string,Segurium_Content_Items>
	 */
	private function parts() {
		if ( null === $this->parts ) {
			$this->parts = array();
			foreach ( self::PARTS as $name => $part ) {
				$reader = isset( $part['reader'] ) ? $part['reader'] : null;
				if ( isset( $part['walk'] ) ) {
					$class                  = $part['walk'];
					$this->walks[ $name ]   = new $class( $this->run_id );
					$this->readers[ $name ] = $this->walks[ $name ];
				} elseif ( isset( $part['walk_of'] ) ) {
					$this->readers[ $name ] = $this->walks[ $part['walk_of'] ];
				}
				if ( isset( $this->readers[ $name ] ) ) {
					$walk   = $this->readers[ $name ];
					$kind   = $part['kind'];
					$reader = static function ( $cap ) use ( $walk, $kind ) {
						return $walk->items( $cap, $kind );
					};
				}
				$max_body             = isset( $part['max_body'] ) ? $part['max_body'] : Segurium_Content_Items::MAX_BODY_BYTES;
				$this->parts[ $name ] = new Segurium_Content_Items( $this->run_id, $part['kind'], $reader, $part['cap'], $max_body );
			}
		}
		return $this->parts;
	}
}

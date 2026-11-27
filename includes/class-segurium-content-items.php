<?php
/**
 * Item pipeline for content that is not a file: cron events, database rows.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Takes the items of one content kind through collection, hash lookup,
 * upload of the bodies the cloud does not know, and the wait for their
 * verdicts. One call of {@see step()} is one unit of work.
 */
final class Segurium_Content_Items {

	const KV_PREFIX = 'content_items:';

	const GO   = 'go';
	const WAIT = 'wait';
	const END  = 'end';

	const STEP_CAPABILITY = 'capability';
	const STEP_COLLECT    = 'collect';
	const STEP_LOOKUP     = 'lookup';
	const STEP_UPLOAD     = 'upload';
	const STEP_RESULTS    = 'results';
	const STEP_ENDED      = 'ended';

	const ITEM_NEW     = 'new';
	const ITEM_UNKNOWN = 'unknown';
	const ITEM_SENT    = 'sent';
	const ITEM_CLEAN   = 'clean';
	const ITEM_THREAT  = 'threat';
	const ITEM_SKIPPED = 'skipped';
	const ITEM_FAILED  = 'failed';

	const WHY_ON_PREMISE  = 'on_premise';
	const WHY_TOO_LARGE   = 'too_large';
	const WHY_OVER_CAP    = 'over_cap';
	const WHY_ELSEWHERE   = 'elsewhere';
	const WHY_BODY_LOST   = 'body_lost';
	const WHY_REJECTED    = 'rejected';
	const WHY_CLOUD_ERROR = 'cloud_error';
	const WHY_NO_VERDICT  = 'no_verdict';
	const WHY_TIMEOUT     = 'timeout';

	const SKIP_KIND_UNSUPPORTED = 'SKIPPED_CONTENT_KIND_UNSUPPORTED';
	const FAIL_CAPABILITY       = 'ABORTED_CONTENT_CAPABILITY_FAILED';
	const FAIL_READ             = 'ABORTED_CONTENT_READ_FAILED';
	const FAIL_STORAGE          = 'ABORTED_CONTENT_STORAGE_FAILED';
	const FAIL_LOOKUP           = 'ABORTED_CONTENT_LOOKUP_FAILED';
	const FAIL_UPLOAD           = 'ABORTED_CONTENT_UPLOAD_FAILED';
	const FAIL_REFUSED          = 'ABORTED_CONTENT_UPLOAD_REFUSED';
	const FAIL_RESULTS          = 'ABORTED_CONTENT_RESULTS_FAILED';

	const VERDICT_SAFE      = 0;
	const VERDICT_MALWARE   = 1;
	const VERDICT_INJECTION = 2;
	const VERDICT_UNKNOWN   = 4;

	const INJECTION_KINDS = array( 'db_js', 'db_user', 'db_session' );

	const LOOKUP_BATCH       = 100;
	const UPLOAD_BATCH       = 50;
	const UPLOAD_BATCH_BYTES = 4194304;
	const MAX_BODY_BYTES     = 1048576;
	const MAX_LOCATOR_BYTES  = 500;
	const RESULT_PAGES       = 4;
	const WAIT_CEILING_SEC   = 600;
	const RETRY_GAPS_SEC     = array( 15, 45, 120 );

	const PERMANENT_ERRORS  = array( 'cti_no_consent', 'cti_no_iid', 'cti_invalid_args', 'cti_invalid_hash', 'cti_empty_body', 'cti_file_too_large', 'cti_batch_too_large' );
	const REFUSED_BY_REASON = array( 'bad_kind', 'kind_unavailable' );

	/**
	 * Run ID.
	 *
	 * @var string
	 */
	private $run_id;

	/**
	 * Content kind.
	 *
	 * @var string
	 */
	private $kind;

	/**
	 * Returns the items: a list or a generator of `{locator, body}`, or of
	 * `{locator, sha256, size}` for an item over the body limit. Takes the
	 * cap and yields null for each item past the cap.
	 *
	 * @var callable
	 */
	private $reader;

	/**
	 * Most distinct items one run takes.
	 *
	 * @var int
	 */
	private $cap;

	/**
	 * Largest body the pipeline uploads.
	 *
	 * @var int
	 */
	private $max_body;

	/**
	 * Pipeline state, null when none is loaded.
	 *
	 * @var array|null
	 */
	private $state = null;

	/**
	 * State as last seen, kept for the counters after {@see drop()}.
	 *
	 * @var array|null
	 */
	private $last = null;

	/**
	 * JSON of the state row as stored.
	 *
	 * @var string
	 */
	private $stored = '';

	/**
	 * Constructor.
	 *
	 * @param string   $run_id Run ID.
	 * @param string   $kind   Content kind.
	 * @param callable $reader Item reader.
	 * @param int      $cap      Most distinct items of one run.
	 * @param int      $max_body Largest body to upload, up to the limit of the cloud.
	 */
	public function __construct( $run_id, $kind, callable $reader, $cap, $max_body = self::MAX_BODY_BYTES ) {
		$this->run_id   = (string) $run_id;
		$this->kind     = (string) $kind;
		$this->reader   = $reader;
		$this->cap      = max( 1, (int) $cap );
		$this->max_body = min( self::MAX_BODY_BYTES, max( 1, (int) $max_body ) );
	}

	/**
	 * Scan ID the items carry on the wire. Differs from the run ID, so the
	 * results of the items and the results of the files never share a stream.
	 *
	 * @return string
	 */
	public function scan_id() {
		return $this->run_id . ':' . $this->kind;
	}

	/**
	 * Create the state. A repeat keeps the state the run already holds.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the state row cannot be written.
	 */
	public function start() {
		if ( $this->load() ) {
			return;
		}
		$this->drop_other_runs();
		$this->state = array(
			'step'        => self::STEP_CAPABILITY,
			'end'         => null,
			'read'        => false,
			'items'       => array(),
			'found'       => 0,
			'over_cap'    => 0,
			'uploaded'    => 0,
			'workspace'   => '',
			'cursor'      => 0,
			'progress_at' => time(),
			'faults'      => array(),
			'retry_at'    => 0,
		);
		$this->save();
	}

	/**
	 * Read the state an earlier request saved.
	 *
	 * @return bool
	 */
	public function load() {
		$raw          = (string) Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( $this->key() )
		);
		$state        = json_decode( $raw, true );
		$this->state  = is_array( $state ) && isset( $state['step'], $state['items'] ) && is_array( $state['items'] ) ? $state : null;
		$this->stored = null === $this->state ? '' : $raw;
		return null !== $this->state;
	}

	/**
	 * Whether a state is loaded.
	 *
	 * @return bool
	 */
	public function loaded() {
		return null !== $this->state;
	}

	/**
	 * Whether the next step calls the reader.
	 *
	 * @return bool
	 */
	public function reads_next() {
		return null !== $this->state && self::STEP_COLLECT === $this->state['step'];
	}

	/**
	 * How the pipeline ended.
	 *
	 * @return array{status:string,error_code:string}|null Null while items are open.
	 *         The status is a phase status of {@see Segurium_Scan_Run}.
	 */
	public function ended() {
		return null !== $this->state && is_array( $this->state['end'] ) ? $this->state['end'] : null;
	}

	/**
	 * End the pipeline as skipped for a reason the caller found.
	 *
	 * @param string $reason_code Reason code.
	 * @return void
	 */
	public function skip( $reason_code ) {
		if ( null !== $this->state && null === $this->ended() ) {
			$this->finish( Segurium_Scan_Run::PHASE_SKIPPED, (string) $reason_code );
		}
	}

	/**
	 * One unit of work: one read, or one request to the cloud.
	 *
	 * @return string GO when more work can follow at once, WAIT when the
	 *                next unit belongs to a later tick, END when the pipeline ended.
	 */
	public function step() {
		if ( ( null === $this->state && ! $this->load() ) || null !== $this->ended() ) {
			return self::END;
		}
		if ( time() < (int) $this->state['retry_at'] || ! Segurium_Scan_Runner::renew_liveness( $this->run_id ) ) {
			return self::WAIT;
		}
		switch ( $this->state['step'] ) {
			case self::STEP_CAPABILITY:
				return $this->check_capability();
			case self::STEP_COLLECT:
				return $this->collect();
			case self::STEP_LOOKUP:
				return $this->lookup();
			case self::STEP_UPLOAD:
				return $this->upload();
			default:
				return $this->results();
		}
	}

	/**
	 * Counts for the run row. Empty until the reader ran.
	 *
	 * @return array<string,int>
	 */
	public function counters() {
		if ( null === $this->state && null === $this->last ) {
			$this->load();
		}
		$state = null === $this->state ? $this->last : $this->state;
		if ( null === $state || empty( $state['read'] ) ) {
			return array();
		}
		$ends = array_fill_keys( array( self::ITEM_CLEAN, self::ITEM_THREAT, self::ITEM_SKIPPED, self::ITEM_FAILED ), 0 );
		$why  = (int) $state['over_cap'] > 0 ? array( self::ITEM_SKIPPED . '_' . self::WHY_OVER_CAP => (int) $state['over_cap'] ) : array();
		$away = isset( $state['elsewhere'] ) ? (int) $state['elsewhere'] : 0;
		if ( $away > 0 ) {
			$why[ self::ITEM_SKIPPED . '_' . self::WHY_ELSEWHERE ] = $away;
		}
		$open = 0;
		foreach ( $state['items'] as $item ) {
			if ( ! isset( $ends[ $item['s'] ] ) ) {
				++$open;
				continue;
			}
			++$ends[ $item['s'] ];
			if ( '' !== $item['w'] ) {
				$key         = $item['s'] . '_' . $item['w'];
				$why[ $key ] = isset( $why[ $key ] ) ? $why[ $key ] + 1 : 1;
			}
		}
		ksort( $why );
		return array_merge(
			array(
				'found'    => (int) $state['found'],
				'items'    => count( $state['items'] ),
				'uploaded' => (int) $state['uploaded'],
				'clean'    => $ends[ self::ITEM_CLEAN ],
				'skipped'  => $ends[ self::ITEM_SKIPPED ] + (int) $state['over_cap'] + $away,
				'failed'   => $ends[ self::ITEM_FAILED ],
			),
			$why,
			$open > 0 ? array( 'open' => $open ) : array(),
			array( 'threats_found' => $ends[ self::ITEM_THREAT ] )
		);
	}

	/**
	 * Every item that ended with a verdict. An upload verdict `malware`
	 * stands for Malware or Injection and reads as Malware.
	 *
	 * @return array<int, array{sha256:string,locator:string,state:string,verdict:int,ref:string}>
	 */
	public function verdicts() {
		if ( null === $this->state && ! $this->load() ) {
			return array();
		}
		$out = array();
		foreach ( $this->state['items'] as $sha => $item ) {
			if ( self::ITEM_CLEAN === $item['s'] || self::ITEM_THREAT === $item['s'] ) {
				$out[] = array(
					'sha256'  => (string) $sha,
					'locator' => (string) $item['p'],
					'state'   => (string) $item['s'],
					'verdict' => self::ITEM_CLEAN === $item['s'] ? self::VERDICT_SAFE : ( isset( $item['v'] ) ? (int) $item['v'] : self::VERDICT_MALWARE ),
					'ref'     => isset( $item['r'] ) ? (string) $item['r'] : '',
				);
			}
		}
		return $out;
	}

	/**
	 * Remove the state row and the stored bodies. The counters stay readable.
	 *
	 * @return void
	 */
	public function drop() {
		if ( null !== $this->state || $this->load() ) {
			$this->last = $this->state;
			self::destroy_workspace( $this->state );
		}
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => $this->key() ) );
		$this->state  = null;
		$this->stored = '';
	}

	/**
	 * Ask the cloud whether the kind is accepted.
	 *
	 * @return string
	 */
	private function check_capability() {
		$kinds = Segurium_Storage::cti_content_kinds();
		if ( is_wp_error( $kinds ) ) {
			return $this->fault( self::FAIL_CAPABILITY, $kinds );
		}
		if ( ! in_array( $this->kind, $kinds, true ) ) {
			return $this->finish( Segurium_Scan_Run::PHASE_SKIPPED, self::SKIP_KIND_UNSUPPORTED );
		}
		$this->state['step'] = self::STEP_COLLECT;
		unset( $this->state['faults'][ self::FAIL_CAPABILITY ] );
		$this->save();
		return self::GO;
	}

	/**
	 * Read the items, hash them, drop repeats and keep the bodies for the upload.
	 *
	 * @return string
	 */
	private function collect() {
		$this->state['read']      = true;
		$this->state['items']     = array();
		$this->state['found']     = 0;
		$this->state['over_cap']  = 0;
		$this->state['elsewhere'] = 0;
		$keep                     = ! Segurium_Storage::on_premise_mode();
		$fault                    = 'the reader returned no list';
		if ( $keep ) {
			$this->open_workspace();
		}
		try {
			$items = call_user_func( $this->reader, $this->cap );
			if ( is_iterable( $items ) ) {
				$fault = '';
				foreach ( $items as $item ) {
					$this->take( $item, $keep );
				}
			}
		} catch ( Throwable $e ) {
			$fault = get_class( $e ) . ': ' . $e->getMessage();
		}
		if ( '' !== $fault ) {
			Segurium_Debug::log( sprintf( '[segurium-content-items] %s kind=%s: %s', self::FAIL_READ, $this->kind, $fault ) );
			return $this->finish( Segurium_Scan_Run::PHASE_FAILED, self::FAIL_READ );
		}
		return $this->advance();
	}

	/**
	 * Make sure the workspace for the bodies exists. The state row names the
	 * workspace before the first body lands, so a later tick finds the folder.
	 * Without a workspace no body is stored, and each item records that.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the state row cannot be written.
	 */
	private function open_workspace() {
		if ( '' !== $this->state['workspace'] && is_dir( $this->state['workspace'] ) ) {
			return;
		}
		$workspace                = Segurium_Storage::tmp_make_workspace( 'content' );
		$this->state['workspace'] = false === $workspace ? '' : (string) $workspace;
		$this->save();
	}

	/**
	 * Put one read item on the list.
	 *
	 * @param mixed $item `{locator, body}`, `{locator, sha256, size}` over the body limit, null for an item past the cap,
	 *                    or `{elsewhere: true}` for an item the reader counts and cannot read.
	 *                    An optional `ref` names the target of the item for {@see verdicts()}.
	 * @param bool  $keep Whether to store the body for the upload.
	 * @return void
	 */
	private function take( $item, $keep ) {
		if ( is_array( $item ) && ! empty( $item['elsewhere'] ) ) {
			++$this->state['found'];
			$this->state['elsewhere'] = ( isset( $this->state['elsewhere'] ) ? (int) $this->state['elsewhere'] : 0 ) + 1;
			return;
		}
		$body  = is_array( $item ) && isset( $item['body'] ) && is_string( $item['body'] ) ? $item['body'] : '';
		$given = '' === $body && is_array( $item ) && isset( $item['sha256'], $item['size'] )
			&& preg_match( '/^[0-9a-f]{64}$/', (string) $item['sha256'] ) && (int) $item['size'] > $this->max_body;
		if ( null !== $item && '' === $body && ! $given ) {
			return;
		}
		++$this->state['found'];
		if ( null === $item ) {
			++$this->state['over_cap'];
			return;
		}
		$sha = $given ? (string) $item['sha256'] : hash( 'sha256', $body );
		if ( isset( $this->state['items'][ $sha ] ) ) {
			return;
		}
		if ( count( $this->state['items'] ) >= $this->cap ) {
			++$this->state['over_cap'];
			return;
		}
		$size                         = $given ? (int) $item['size'] : strlen( $body );
		$locator                      = isset( $item['locator'] ) ? substr( (string) $item['locator'], 0, self::MAX_LOCATOR_BYTES ) : '';
		$this->state['items'][ $sha ] = array(
			'p' => wp_check_invalid_utf8( $locator, true ),
			'n' => $size,
			's' => self::ITEM_NEW,
			'w' => '',
		);
		if ( isset( $item['ref'] ) && is_string( $item['ref'] ) && preg_match( '/^[0-9a-f]{32,64}$/', $item['ref'] ) ) {
			$this->state['items'][ $sha ]['r'] = $item['ref'];
		}
		if ( $keep && $size <= $this->max_body && ! Segurium_Storage::tmp_write( $this->state['workspace'], $sha, $body ) ) {
			$this->state['items'][ $sha ]['u'] = 1;
		}
	}

	/**
	 * Look up one batch of new items by hash.
	 *
	 * @return string
	 */
	private function lookup() {
		$batch = array();
		foreach ( $this->state['items'] as $sha => $item ) {
			if ( self::ITEM_NEW === $item['s'] ) {
				$batch[] = array(
					'sha256' => (string) $sha,
					'path'   => $item['p'],
					'size'   => $item['n'],
				);
				if ( count( $batch ) >= self::LOOKUP_BATCH ) {
					break;
				}
			}
		}
		if ( empty( $batch ) ) {
			return $this->advance();
		}
		$rows = Segurium_Storage::cti_inspect_content( $this->kind, $batch, $this->scan_id() );
		if ( is_wp_error( $rows ) ) {
			return $this->fault( self::FAIL_LOOKUP, $rows );
		}
		$verdicts = array();
		foreach ( (array) $rows as $row ) {
			if ( is_array( $row ) && isset( $row['sha256'], $row['verdict'] ) ) {
				$verdicts[ strtolower( (string) $row['sha256'] ) ] = (int) $row['verdict'];
			}
		}
		foreach ( $batch as $entry ) {
			$verdict = isset( $verdicts[ $entry['sha256'] ] ) ? $verdicts[ $entry['sha256'] ] : self::VERDICT_UNKNOWN;
			if ( self::VERDICT_UNKNOWN === $verdict ) {
				$this->settle( $entry['sha256'], self::ITEM_UNKNOWN );
			} elseif ( self::VERDICT_MALWARE === $verdict || ( self::VERDICT_INJECTION === $verdict && in_array( $this->kind, self::INJECTION_KINDS, true ) ) ) {
				$this->settle( $entry['sha256'], self::ITEM_THREAT );
				$this->state['items'][ $entry['sha256'] ]['v'] = $verdict;
			} else {
				if ( self::VERDICT_SAFE !== $verdict ) {
					Segurium_Debug::log( sprintf( '[segurium-content-items] unsupported_verdict kind=%s sha256=%s verdict=%d: read as safe', $this->kind, $entry['sha256'], $verdict ) );
				}
				$this->settle( $entry['sha256'], self::ITEM_CLEAN );
			}
		}
		return $this->progressed( self::FAIL_LOOKUP );
	}

	/**
	 * Upload one batch of the bodies the cloud does not know.
	 *
	 * @return string
	 */
	private function upload() {
		if ( Segurium_Storage::on_premise_mode() ) {
			$this->settle_all( self::ITEM_UNKNOWN, self::ITEM_SKIPPED, self::WHY_ON_PREMISE );
			return $this->advance();
		}
		$ready    = $this->unknown( false );
		$unstored = $this->unknown( true );
		if ( 0 === $ready && 0 === $unstored ) {
			return $this->advance();
		}
		if ( 0 === $ready && ! $this->has( self::ITEM_SENT ) ) {
			Segurium_Debug::log( sprintf( '[segurium-content-items] %s kind=%s: %d bodies were not stored at the read', self::FAIL_STORAGE, $this->kind, $unstored ) );
			return $this->finish( Segurium_Scan_Run::PHASE_FAILED, self::FAIL_STORAGE );
		}
		if ( 0 === $ready || Segurium_Async_Scan_Pause::is_paused( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT ) ) {
			return $this->has( self::ITEM_SENT ) ? $this->results() : $this->idle();
		}
		$files = array();
		$bytes = 0;
		foreach ( $this->state['items'] as $sha => $item ) {
			if ( self::ITEM_UNKNOWN !== $item['s'] || ! empty( $item['u'] ) ) {
				continue;
			}
			if ( $item['n'] > $this->max_body ) {
				$this->settle( $sha, self::ITEM_SKIPPED, self::WHY_TOO_LARGE );
				continue;
			}
			$body = Segurium_Storage::tmp_read( $this->state['workspace'], (string) $sha );
			if ( null === $body || hash( 'sha256', $body ) !== (string) $sha ) {
				$this->settle( $sha, self::ITEM_FAILED, self::WHY_BODY_LOST );
				continue;
			}
			if ( ! empty( $files ) && $bytes + $item['n'] > self::UPLOAD_BATCH_BYTES ) {
				break;
			}
			$bytes  += $item['n'];
			$files[] = array(
				'sha256' => (string) $sha,
				'path'   => $item['p'],
				'body'   => $body,
			);
			if ( count( $files ) >= self::UPLOAD_BATCH ) {
				break;
			}
		}
		if ( empty( $files ) ) {
			return $this->advance();
		}

		$shas     = array_column( $files, 'sha256' );
		$response = Segurium_Storage::cti_submit_content( $this->kind, $this->scan_id(), hash( 'sha256', $this->scan_id() . implode( '', $shas ) ), $files );
		if ( is_wp_error( $response ) ) {
			if ( 'cti_on_premise_blocked' === $response->get_error_code() ) {
				$this->settle_all( self::ITEM_UNKNOWN, self::ITEM_SKIPPED, self::WHY_ON_PREMISE );
				return $this->advance();
			}
			return $this->paused_by( $response, Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT ) ? $this->idle() : $this->fault( self::FAIL_UPLOAD, $response );
		}

		$accepted = array_flip( array_map( array( __CLASS__, 'bare_hash' ), (array) $response['accepted'] ) );
		$rejected = array();
		foreach ( (array) $response['rejected'] as $entry ) {
			if ( is_array( $entry ) && isset( $entry['hash'] ) ) {
				$rejected[ self::bare_hash( $entry['hash'] ) ] = isset( $entry['reason'] ) ? (string) $entry['reason'] : '';
			}
		}
		$refused = false;
		foreach ( $shas as $sha ) {
			if ( isset( $rejected[ $sha ] ) && in_array( $rejected[ $sha ], self::REFUSED_BY_REASON, true ) ) {
				$refused = true;
			} elseif ( isset( $rejected[ $sha ] ) && self::WHY_TOO_LARGE === $rejected[ $sha ] ) {
				$this->settle( $sha, self::ITEM_SKIPPED, self::WHY_TOO_LARGE );
			} elseif ( isset( $rejected[ $sha ] ) || ! isset( $accepted[ $sha ] ) ) {
				$this->settle( $sha, self::ITEM_FAILED, self::WHY_REJECTED );
			} else {
				$this->settle( $sha, self::ITEM_SENT );
				++$this->state['uploaded'];
			}
		}
		if ( $refused ) {
			Segurium_Debug::log( sprintf( '[segurium-content-items] %s kind=%s: the cloud refuses the kind', self::FAIL_REFUSED, $this->kind ) );
			return $this->finish( Segurium_Scan_Run::PHASE_FAILED, self::FAIL_REFUSED );
		}
		if ( ! empty( $response['retry_after'] ) ) {
			Segurium_Async_Scan_Pause::set_pause( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT, (int) $response['retry_after'] );
		}
		unset( $this->state['faults'][ self::FAIL_RESULTS ] );
		return $this->progressed( self::FAIL_UPLOAD );
	}

	/**
	 * Pull the verdicts of the uploaded items.
	 *
	 * @return string
	 */
	private function results() {
		if ( Segurium_Async_Scan_Pause::is_paused( Segurium_Async_Scan_Pause::ENDPOINT_RESULTS ) ) {
			return $this->idle();
		}
		$drained = false;
		for ( $page = 0; $page < self::RESULT_PAGES; $page++ ) {
			if ( $page > 0 && ! Segurium_Scan_Runner::renew_liveness( $this->run_id ) ) {
				// Another worker owns the run: this object lets go of what it changed.
				$this->state  = null;
				$this->stored = '';
				return self::WAIT;
			}
			$response = Segurium_Storage::cti_content_results( (int) $this->state['cursor'], $this->scan_id() );
			if ( is_wp_error( $response ) ) {
				return $this->paused_by( $response, Segurium_Async_Scan_Pause::ENDPOINT_RESULTS ) ? $this->idle() : $this->fault( self::FAIL_RESULTS, $response );
			}
			foreach ( $response['results'] as $row ) {
				$this->state['progress_at'] = is_array( $row ) && $this->apply( $row ) ? time() : $this->state['progress_at'];
			}
			$this->state['cursor'] = max( (int) $this->state['cursor'], (int) $response['next_seq'] );
			if ( ! $this->has( self::ITEM_SENT ) ) {
				break;
			}
			if ( empty( $response['results'] ) ) {
				if ( false !== $response['pending'] ) {
					break;
				}
				// A verdict written between the two reads of one answer shows in the next answer.
				if ( $drained ) {
					$this->settle_all( self::ITEM_SENT, self::ITEM_FAILED, self::WHY_NO_VERDICT );
					break;
				}
				$drained = true;
			} elseif ( empty( $response['more'] ) ) {
				break;
			}
		}
		unset( $this->state['faults'][ self::FAIL_RESULTS ] );
		return $this->has( self::ITEM_SENT ) ? $this->idle() : $this->advance();
	}

	/**
	 * Settle the item a results row names. A row of a file or of another kind settles nothing.
	 *
	 * @param array $row Row of `/v1/scan/results`.
	 * @return bool
	 */
	private function apply( array $row ) {
		$sha = isset( $row['hash'] ) ? self::bare_hash( $row['hash'] ) : '';
		if ( ! isset( $row['kind'] ) || $row['kind'] !== $this->kind
			|| ! isset( $this->state['items'][ $sha ] ) || self::ITEM_SENT !== $this->state['items'][ $sha ]['s'] ) {
			return false;
		}
		$verdict = isset( $row['verdict'] ) ? (string) $row['verdict'] : '';
		if ( 'clean' === $verdict ) {
			$this->settle( $sha, self::ITEM_CLEAN );
		} elseif ( 'malware' === $verdict ) {
			$this->settle( $sha, self::ITEM_THREAT );
		} else {
			$this->settle( $sha, self::ITEM_FAILED, self::WHY_CLOUD_ERROR );
		}
		return true;
	}

	/**
	 * Wait for a later tick. Past the wait ceiling the open items end as
	 * failed. An unknown item whose body was not stored keeps its cause: the
	 * pipeline fails for the storage.
	 *
	 * @return string
	 */
	private function idle() {
		if ( time() - (int) $this->state['progress_at'] <= self::WAIT_CEILING_SEC ) {
			$this->save();
			return self::WAIT;
		}
		$this->settle_all( self::ITEM_SENT, self::ITEM_FAILED, self::WHY_TIMEOUT );
		if ( $this->unknown( true ) > 0 ) {
			return $this->finish( Segurium_Scan_Run::PHASE_FAILED, self::FAIL_STORAGE );
		}
		$this->settle_all( self::ITEM_UNKNOWN, self::ITEM_FAILED, self::WHY_TIMEOUT );
		return $this->advance();
	}

	/**
	 * Count a failed request. The request repeats after a gap; past the
	 * last gap, or on an answer that cannot change, the pipeline fails.
	 * Each kind of request has a count of its own, so a request that works
	 * clears no failure of another kind.
	 *
	 * @param string   $reason_code Reason code of the failed pipeline.
	 * @param WP_Error $error       What the client returned.
	 * @return string
	 */
	private function fault( $reason_code, WP_Error $error ) {
		$tries = isset( $this->state['faults'][ $reason_code ] ) ? (int) $this->state['faults'][ $reason_code ] : 0;
		$data  = $error->get_error_data();
		$http  = is_array( $data ) && isset( $data['status'] ) ? (int) $data['status'] : 0;
		$again = ! in_array( $error->get_error_code(), self::PERMANENT_ERRORS, true )
			&& ( 0 === $http || $http >= 500 || 408 === $http || 429 === $http );
		Segurium_Debug::log( sprintf( '[segurium-content-items] %s kind=%s try=%d http=%d: %s: %s', $reason_code, $this->kind, $tries + 1, $http, $error->get_error_code(), $error->get_error_message() ) );
		if ( ! $again || $tries >= count( self::RETRY_GAPS_SEC ) ) {
			return $this->finish( Segurium_Scan_Run::PHASE_FAILED, $reason_code );
		}
		$this->state['faults'][ $reason_code ] = $tries + 1;
		$this->state['retry_at']               = time() + self::RETRY_GAPS_SEC[ $tries ];
		$this->save();
		return self::WAIT;
	}

	/**
	 * Store the pause a `Retry-After` answer asks for.
	 *
	 * @param WP_Error $error    What the client returned.
	 * @param string   $endpoint Endpoint label of {@see Segurium_Async_Scan_Pause}.
	 * @return bool True when the answer named a pause. An answer that asks
	 *              for a pause of no length counts as a failed request.
	 */
	private function paused_by( WP_Error $error, $endpoint ) {
		$data    = $error->get_error_data();
		$seconds = is_array( $data ) && isset( $data['retry_after'] ) ? (int) $data['retry_after'] : 0;
		if ( 'cti_paused' !== $error->get_error_code() || $seconds <= 0 ) {
			return false;
		}
		Segurium_Async_Scan_Pause::set_pause( $endpoint, $seconds );
		return true;
	}

	/**
	 * Record a request that worked.
	 *
	 * @param string $reason_code Reason code whose failure count the request clears.
	 * @return string
	 */
	private function progressed( $reason_code ) {
		unset( $this->state['faults'][ $reason_code ] );
		$this->state['progress_at'] = time();
		return $this->advance();
	}

	/**
	 * Pick the step the open items need. With no open item the pipeline ends as done.
	 *
	 * @return string
	 */
	private function advance() {
		$steps = array(
			self::ITEM_NEW     => self::STEP_LOOKUP,
			self::ITEM_UNKNOWN => self::STEP_UPLOAD,
			self::ITEM_SENT    => self::STEP_RESULTS,
		);
		foreach ( $steps as $open => $step ) {
			if ( $this->has( $open ) ) {
				$this->state['step'] = $step;
				$this->save();
				return self::GO;
			}
		}
		return $this->finish( Segurium_Scan_Run::PHASE_DONE, '' );
	}

	/**
	 * End the pipeline.
	 *
	 * @param string $status      Phase status the pipeline ends with.
	 * @param string $reason_code Reason code, '' for done.
	 * @return string
	 */
	private function finish( $status, $reason_code ) {
		self::destroy_workspace( $this->state );
		$this->state['workspace'] = '';
		$this->state['step']      = self::STEP_ENDED;
		$this->state['end']       = array(
			'status'     => (string) $status,
			'error_code' => (string) $reason_code,
		);
		$this->save();
		return self::END;
	}

	/**
	 * Count the unknown items by whether their body was stored at the read.
	 *
	 * @param bool $unstored True counts the items whose body was not stored.
	 * @return int
	 */
	private function unknown( $unstored ) {
		$count = 0;
		foreach ( $this->state['items'] as $item ) {
			if ( self::ITEM_UNKNOWN === $item['s'] && empty( $item['u'] ) !== (bool) $unstored ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * Whether an item is in the given state.
	 *
	 * @param string $state Item state.
	 * @return bool
	 */
	private function has( $state ) {
		foreach ( $this->state['items'] as $item ) {
			if ( $state === $item['s'] ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Move one item to a state.
	 *
	 * @param string $sha   SHA-256 of the item.
	 * @param string $state New item state.
	 * @param string $why   Reason of a skipped or failed item.
	 * @return void
	 */
	private function settle( $sha, $state, $why = '' ) {
		$this->state['items'][ $sha ]['s'] = $state;
		$this->state['items'][ $sha ]['w'] = $why;
	}

	/**
	 * Move every item of one state to another.
	 *
	 * @param string $from  Current item state.
	 * @param string $state New item state.
	 * @param string $why   Reason.
	 * @return void
	 */
	private function settle_all( $from, $state, $why ) {
		foreach ( $this->state['items'] as $sha => $item ) {
			if ( $from === $item['s'] ) {
				$this->settle( $sha, $state, $why );
			}
		}
	}

	/**
	 * Hash without the `sha256:` prefix, lower case.
	 *
	 * @param mixed $hash Hash as the cloud writes it.
	 * @return string
	 */
	private static function bare_hash( $hash ) {
		return strtolower( str_replace( 'sha256:', '', (string) $hash ) );
	}

	/**
	 * Key of the state row.
	 *
	 * @return string
	 */
	private function key() {
		return self::KV_PREFIX . $this->run_id . ':' . $this->kind;
	}

	/**
	 * Write the state row when the state changed.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the write fails.
	 */
	private function save() {
		$json = (string) wp_json_encode( $this->state );
		if ( $json === $this->stored ) {
			return;
		}
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $this->key(),
				'kv_value'   => $json,
				'expires_at' => $now + DAY_IN_SECONDS,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
		$this->stored = $json;
	}

	/**
	 * Remove the rows and the stored bodies earlier runs left.
	 *
	 * @return void
	 */
	private function drop_other_runs() {
		global $wpdb;
		$rows = Segurium_Storage::table_get_results(
			'runtime_kv',
			'SELECT kv_key, kv_value FROM {{table}} WHERE kv_key LIKE %s AND kv_key NOT LIKE %s',
			array( $wpdb->esc_like( self::KV_PREFIX ) . '%', $wpdb->esc_like( self::KV_PREFIX . $this->run_id . ':' ) . '%' ),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			self::destroy_workspace( json_decode( (string) $row['kv_value'], true ) );
			Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => (string) $row['kv_key'] ) );
		}
	}

	/**
	 * Remove the stored bodies a state names.
	 *
	 * @param mixed $state Pipeline state.
	 * @return void
	 */
	private static function destroy_workspace( $state ) {
		if ( is_array( $state ) && ! empty( $state['workspace'] ) ) {
			Segurium_Storage::tmp_destroy( (string) $state['workspace'] );
		}
	}
}

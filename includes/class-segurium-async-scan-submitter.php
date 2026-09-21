<?php
/**
 * Async scan submitter — batches files for `/v1/scan/submit`.
 *
 * Replaces the per-file synchronous Neo-Ray escalation.
 * The malware scan loop feeds unknowns into {@see add()}; when a
 * pending buffer crosses one of the wire limits (10 MiB body, 200
 * files, 100 MiB single file) the submitter POSTs a batch. Files that
 * the server accepted are recorded in the runtime_kv "pending verdicts"
 * map so {@see Segurium_Async_Scan_Results_Loop} can apply verdicts as
 * they arrive.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Buffered submitter for `/v1/scan/submit`.
 */
class Segurium_Async_Scan_Submitter {

	const MAX_BATCH_BYTES      = 10485760;
	const MAX_FILES_PER_BATCH  = 100;
	const MAX_SINGLE_FILE_SIZE = 104857600;

	/**
	 * Bodies at or below this size go on the wire at their raw
	 * length as far as the ceiling is concerned. Sampling a small file to
	 * learn a ratio costs more than the ceiling headroom it could win back.
	 */
	const WIRE_ESTIMATE_MIN_BYTES = 1048576;

	/**
	 * Prefix gzipped to learn a body's compression ratio.
	 */
	const WIRE_SAMPLE_BYTES = 262144;

	/**
	 * Chunk fed to the deflate stream when a refused batch is
	 * re-measured exactly. Bounds the memory the measurement needs to the
	 * chunk plus its output, never a second copy of the body.
	 */
	const WIRE_CHUNK_BYTES = 1048576;

	/**
	 * Lowest batch byte ceiling the halving walks down to. A
	 * link that cannot carry 100 KiB inside a tick is broken; a failure at
	 * this ceiling terminates the scan instead of shrinking further.
	 */
	const BATCH_CEILING_FLOOR_BYTES = 102400;

	/**
	 * Consecutive clean submits after which a lowered ceiling
	 * doubles back toward {@see MAX_BATCH_BYTES}.
	 */
	const CEILING_RECOVERY_CLEAN_SUBMITS = 20;

	/**
	 * Key prefix in runtime_kv for the per-scan ceiling row.
	 */
	const CEILING_KV_PREFIX = 'async_scan:ceiling:';

	/**
	 * `scan_submit()` error codes that mean "this link could
	 * not carry this batch". Mirrors
	 * {@see Segurium_Verdict_Queue::UPLOAD_CAPACITY_ERROR_CODES}; kept here
	 * so the submitter can react without depending on the queue class.
	 *
	 * @var string[]
	 */
	const UPLOAD_CAPACITY_ERROR_CODES = array(
		'cti_transport_error',
		'cti_scan_submit_body_incomplete',
		'cti_scan_submit_payload_too_large',
	);

	const SKIP_REASONS = array(
		'cti_file_exceeds_batch_ceiling'   => 'batch_ceiling',
		'cti_upload_ceiling_floor'         => 'ceiling_floor',
		'cti_file_exceeds_memory_headroom' => 'low_memory',
	);

	// Measured at 2.3 per buffered byte: the multipart copy and the gzip copy coexist.
	const FLUSH_MEMORY_FACTOR  = 2.5;
	const MEMORY_RESERVE_BYTES = 4194304;

	/**
	 * Legacy runtime_kv key prefix under which the per-scan pending-verdicts
	 * map used to be stored as one JSON blob. Retained only so the
	 * one-shot purge migration
	 * ({@see Segurium_Async_Scan_Results_Loop::migrate_purge_legacy_pending_blobs()})
	 * can find and drop the orphaned blobs. The live store is now the
	 * `async_pending` table — one indexed row per submitted file.
	 */
	const PENDING_KV_PREFIX = 'async_scan:pending:';

	/**
	 * Logical name of the dedicated pending-verdicts table.
	 */
	const PENDING_TABLE = 'async_pending';

	/**
	 * CTI client used for outbound calls.
	 *
	 * @var Segurium_CTI_Client
	 */
	private $cti;

	/**
	 * Scan UUID this submitter is attached to.
	 *
	 * @var string
	 */
	private $scan_id;

	/**
	 * Per-scan detector label written into `scan_findings.detector`
	 * when a verdict eventually arrives.
	 *
	 * @var string
	 */
	private $detector;

	/**
	 * In-flight files waiting to be POSTed. Each entry:
	 * `{sha256, path, body, size, wire}`, where `wire` is the estimated
	 * on-the-wire length after transport compression.
	 *
	 * @var array
	 */
	private $buffer = array();

	/**
	 * Running total of estimated wire bytes in the buffer;
	 * mirrored from sum( $buffer[*].wire ) so we don't recompute on every
	 * add(). The ceiling bounds what the link carries, so every comparison
	 * against it uses wire bytes, never raw ones.
	 *
	 * @var int
	 */
	private $buffer_wire_bytes = 0;

	/**
	 * Running total of raw buffered body bytes. The wire total
	 * above bounds what the link carries; this one bounds what
	 * `scan_submit()` accepts — its multi-file cap is
	 * {@see MAX_BATCH_BYTES} of raw payload — and with it the memory the
	 * buffer holds.
	 *
	 * @var int
	 */
	private $buffer_raw_bytes = 0;

	/**
	 * Current batch byte ceiling. Starts at MAX_BATCH_BYTES,
	 * halves on each upload-capacity failure, recovers after a run of
	 * clean submits. Scan-scoped: persisted in runtime_kv so every
	 * submitter instance within one scan shares it.
	 *
	 * @var int
	 */
	private $ceiling_bytes = self::MAX_BATCH_BYTES;

	/**
	 * Consecutive successful submits since the last halving.
	 *
	 * @var int
	 */
	private $clean_submits = 0;

	/**
	 * Whether a batch failed at the floor ceiling. Once set, add() refuses
	 * every file with `cti_upload_ceiling_floor`.
	 *
	 * @var bool
	 */
	private $floor_reached = false;

	/**
	 * Files dropped from batches the link refused, not yet folded into a
	 * stat block by the caller. Drained by {@see take_skipped()}.
	 *
	 * @var int
	 */
	private $skipped_tally = 0;

	/**
	 * Constructor.
	 *
	 * @param string                   $scan_id  Plugin-side scan-run UUID.
	 * @param string                   $detector Detector label (`scanner`,
	 *                                           `realtime`, `upload`).
	 * @param Segurium_CTI_Client|null $cti      Optional client; defaults to
	 *                                            the storage façade.
	 */
	public function __construct( $scan_id, $detector = 'scanner', ?Segurium_CTI_Client $cti = null ) {
		$this->scan_id  = (string) $scan_id;
		$this->detector = (string) $detector;
		$this->cti      = $cti instanceof Segurium_CTI_Client ? $cti : new Segurium_CTI_Client();
		$this->load_ceiling();
	}

	/**
	 * Current batch byte ceiling.
	 *
	 * @return int
	 */
	public function batch_ceiling() {
		return $this->ceiling_bytes;
	}

	/**
	 * File-count cap scaled with the byte ceiling.
	 *
	 * @return int
	 */
	public function batch_file_cap() {
		return max( 1, (int) floor( self::MAX_FILES_PER_BATCH * $this->ceiling_bytes / self::MAX_BATCH_BYTES ) );
	}

	/**
	 * Whether a batch failed at the floor ceiling.
	 *
	 * @return bool
	 */
	public function floor_reached() {
		return $this->floor_reached;
	}

	/**
	 * Whether the persisted ceiling row for a scan records a
	 * failure at the floor. The runner reads this after every chunk and
	 * terminates the scan with `ABORTED_UPLOAD_CAPACITY` from its own tick,
	 * so the termination never races the chunk's completion branch.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return bool
	 */
	public static function floor_reached_for( $scan_id ) {
		$row = self::read_ceiling_row( (string) $scan_id );
		return is_array( $row ) && ! empty( $row['floor'] );
	}

	/**
	 * Read the persisted ceiling row for a scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return array|null Decoded row or null.
	 */
	private static function read_ceiling_row( $scan_id ) {
		if ( '' === $scan_id ) {
			return null;
		}
		try {
			$raw = Segurium_Storage::table_get_var(
				'runtime_kv',
				'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
				array( self::CEILING_KV_PREFIX . $scan_id )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-async-submit] ceiling read failed for ' . $scan_id . ': ' . $e->getMessage() );
			return null;
		}
		$row = null !== $raw ? json_decode( (string) $raw, true ) : null;
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Return and reset the count of files the submitter
	 * dropped from batches the link refused. Callers fold the number into
	 * `neoray_skipped`.
	 *
	 * @return int
	 */
	public function take_skipped() {
		$n                   = $this->skipped_tally;
		$this->skipped_tally = 0;
		return $n;
	}

	/**
	 * Drop the per-scan ceiling row. Called on scan teardown.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return void
	 */
	public static function clear_ceiling( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		try {
			Segurium_Storage::table_delete(
				'runtime_kv',
				array( 'kv_key' => self::CEILING_KV_PREFIX . $scan_id )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-async-submit] ceiling delete failed for ' . $scan_id . ': ' . $e->getMessage() );
		}
	}

	/**
	 * Read the persisted per-scan ceiling row, if any.
	 *
	 * @return void
	 */
	private function load_ceiling() {
		$row = self::read_ceiling_row( $this->scan_id );
		if ( null === $row ) {
			return;
		}
		$ceiling = isset( $row['ceiling'] ) ? (int) $row['ceiling'] : 0;
		if ( $ceiling >= self::BATCH_CEILING_FLOOR_BYTES && $ceiling <= self::MAX_BATCH_BYTES ) {
			$this->ceiling_bytes = $ceiling;
		}
		$this->clean_submits = isset( $row['clean'] ) ? max( 0, (int) $row['clean'] ) : 0;
		$this->floor_reached = ! empty( $row['floor'] );
	}

	/**
	 * Persist the ceiling row for this scan.
	 *
	 * @return void
	 */
	private function save_ceiling() {
		if ( '' === $this->scan_id ) {
			return;
		}
		$now = time();
		try {
			Segurium_Storage::table_upsert(
				'runtime_kv',
				array(
					'kv_key'     => self::CEILING_KV_PREFIX . $this->scan_id,
					'kv_value'   => wp_json_encode(
						array(
							'ceiling' => $this->ceiling_bytes,
							'clean'   => $this->clean_submits,
							'floor'   => $this->floor_reached,
						)
					),
					'expires_at' => $now + DAY_IN_SECONDS,
					'updated_at' => $now,
				),
				array( 'kv_key' )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-async-submit] ceiling save failed for ' . $this->scan_id . ': ' . $e->getMessage() );
		}
	}

	/**
	 * A batch the link refused. The ceiling halves so the
	 * caller can re-cut and resend; a failure at the floor drops the files
	 * and flags the scan for termination.
	 *
	 * @param array    $batch Files that were in the failed batch.
	 * @param WP_Error $error The scan_submit() error.
	 * @return void
	 */
	private function on_capacity_failure( array $batch, WP_Error $error ) {
		$dropped             = count( $batch );
		$this->clean_submits = 0;
		$old                 = $this->ceiling_bytes;

		if ( $old <= self::BATCH_CEILING_FLOOR_BYTES ) {
			$this->floor_reached  = true;
			$this->skipped_tally += $dropped;
			$this->save_ceiling();
			Segurium_Scan_Runner::debug(
				'async_submit_ceiling_floor',
				array(
					'scan_id'       => $this->scan_id,
					'ceiling'       => $old,
					'files_dropped' => $dropped,
					'error_code'    => $error->get_error_code(),
				)
			);
			Segurium_Debug::log(
				sprintf(
					'[segurium-async-submit] scan %s: a %d-byte batch failed at the %d-byte floor (%s); the runner terminates the scan after this chunk',
					$this->scan_id,
					array_sum( array_column( $batch, 'size' ) ),
					$old,
					$error->get_error_code()
				)
			);
			return;
		}

		$this->ceiling_bytes = max( self::BATCH_CEILING_FLOOR_BYTES, (int) floor( $old / 2 ) );
		$this->save_ceiling();
		Segurium_Scan_Runner::debug(
			'async_submit_ceiling_halved',
			array(
				'scan_id'     => $this->scan_id,
				'old_ceiling' => $old,
				'new_ceiling' => $this->ceiling_bytes,
				'files'       => $dropped,
				'error_code'  => $error->get_error_code(),
			)
		);
		Segurium_Debug::log(
			sprintf(
				'[segurium-async-submit] scan %s: batch of %d file(s) refused by the link (%s); ceiling %d -> %d bytes, resending',
				$this->scan_id,
				$dropped,
				$error->get_error_code(),
				$old,
				$this->ceiling_bytes
			)
		);
	}

	/**
	 * Count a clean submit; double a lowered ceiling back
	 * after a full run of them.
	 *
	 * @return void
	 */
	private function on_clean_submit() {
		if ( $this->ceiling_bytes >= self::MAX_BATCH_BYTES ) {
			return;
		}
		++$this->clean_submits;
		if ( $this->clean_submits < self::CEILING_RECOVERY_CLEAN_SUBMITS ) {
			$this->save_ceiling();
			return;
		}
		$old                 = $this->ceiling_bytes;
		$this->ceiling_bytes = min( self::MAX_BATCH_BYTES, $old * 2 );
		$this->clean_submits = 0;
		$this->save_ceiling();
		Segurium_Scan_Runner::debug(
			'async_submit_ceiling_restored',
			array(
				'scan_id'     => $this->scan_id,
				'old_ceiling' => $old,
				'new_ceiling' => $this->ceiling_bytes,
			)
		);
	}

	/**
	 * Queue a file for the next batch. Flushes automatically when one
	 * of the wire-size limits would be crossed by the addition.
	 *
	 * @param string $sha256        Lowercase hex SHA-256.
	 * @param string $relative_path Site-relative path.
	 * @param string $body          Raw file bytes.
	 * @return true|WP_Error True on accept (queued and possibly flushed);
	 *                       WP_Error for invalid args or a submit failure
	 *                       surfaced on the auto-flush path.
	 */
	public function add( $sha256, $relative_path, $body ) {
		$sha256 = strtolower( (string) $sha256 );
		if ( ! preg_match( '/^[0-9a-f]{64}$/', $sha256 ) ) {
			return new WP_Error( 'cti_invalid_hash', 'async submit requires a 64-char hex SHA-256' );
		}
		if ( ! is_string( $body ) || '' === $body ) {
			return new WP_Error( 'cti_empty_body', 'async submit requires a non-empty body' );
		}
		$size = strlen( $body );
		if ( $size > self::MAX_SINGLE_FILE_SIZE ) {
			return new WP_Error( 'cti_file_too_large', 'async submit single-file cap is 100 MiB' );
		}
		$wire = $this->estimate_wire_size( $body );

		// The gate runs before the flush. Its verdict does not depend on
		// the buffer, so flushing first could only cost a POST — and the
		// hard-cap flush below bypasses the submit pause, which a file
		// we are about to skip has no right to do.
		$refused = $this->refuse_for_ceiling( $size, $wire, (string) $relative_path );
		if ( null !== $refused ) {
			return $refused;
		}

		// Would the new file push us past a limit? Flush what we have
		// first, then queue this one. Net effect: the new file always
		// lands in a fresh batch, never spills across two, and a file
		// too big for any batch is only ever judged against an empty
		// buffer.
		//
		// Two byte limits, both binding: the learned ceiling bounds
		// what the link carries, in wire bytes; MAX_BATCH_BYTES bounds
		// what scan_submit() accepts from a multi-file batch, in raw
		// bytes. A lone file may exceed the raw one — the client
		// exempts a single file up to MAX_SINGLE_FILE_SIZE — which is
		// why the raw check needs a non-empty buffer to bite.
		//
		// A hard-cap flush ignores the submit-pause transient because
		// we cannot accept this file without shipping the buffer
		// first. End-of-chunk flushes go through the soft path
		// (flush() honours the IID-scoped pause).
		if ( ! empty( $this->buffer )
			&& ( $this->buffer_wire_bytes + $wire > $this->ceiling_bytes
				|| $this->buffer_raw_bytes + $size > self::MAX_BATCH_BYTES
				|| count( $this->buffer ) >= $this->batch_file_cap()
				|| ! self::memory_allows( $this->buffer_raw_bytes + $size ) )
		) {
			$flushed = $this->flush( true );
			if ( is_wp_error( $flushed ) ) {
				return $flushed;
			}
			// The flush may have lowered the ceiling under this file.
			$refused = $this->refuse_for_ceiling( $size, $wire, (string) $relative_path );
			if ( null !== $refused ) {
				return $refused;
			}
		}
		if ( ! self::memory_allows( $this->buffer_raw_bytes + $size ) ) {
			return new WP_Error(
				'cti_file_exceeds_memory_headroom',
				'not enough free memory to upload this file',
				array( 'size' => $size )
			);
		}

		$this->buffer[]           = array(
			'sha256' => $sha256,
			'path'   => (string) $relative_path,
			'body'   => $body,
			'size'   => $size,
			'wire'   => $wire,
		);
		$this->buffer_wire_bytes += $wire;
		$this->buffer_raw_bytes  += $size;
		return true;
	}

	/**
	 * How many bytes a body is expected to occupy on the wire.
	 * `Segurium_CTI_Client::scan_submit()` gzips the whole multipart body
	 * and keeps the result only when it is smaller, so the estimate is
	 * capped at the raw length.
	 *
	 * Bodies at or below {@see WIRE_ESTIMATE_MIN_BYTES} report their raw
	 * length. Larger ones are sampled: the first
	 * {@see WIRE_SAMPLE_BYTES} are gzipped and the resulting ratio is
	 * applied to the whole file. A sample cannot know what the tail
	 * compresses to, so the estimate is approximate by construction —
	 * the halving still catches a batch the link refuses anyway.
	 *
	 * @param string $body Raw file bytes.
	 * @return int Estimated wire length in bytes.
	 */
	private function estimate_wire_size( $body ) {
		return self::wire_size_from_sample( strlen( $body ), substr( $body, 0, self::WIRE_SAMPLE_BYTES ) );
	}

	/**
	 * The estimate proper, over a size and a prefix of the body. Split out
	 * so a caller holding only the file on disk reaches the same verdict
	 * from a {@see WIRE_SAMPLE_BYTES} read, without materialising the body
	 * to sample it.
	 *
	 * @param int    $size   Full body length in bytes.
	 * @param string $sample First {@see WIRE_SAMPLE_BYTES} of the body.
	 * @return int Estimated wire length in bytes.
	 */
	public static function wire_size_from_sample( $size, $sample ) {
		$size = (int) $size;
		if ( $size <= self::WIRE_ESTIMATE_MIN_BYTES || ! function_exists( 'gzencode' ) ) {
			return $size;
		}
		if ( '0' === (string) Segurium_Storage::setting_get( Segurium_CTI_Client::OPTION_NEO_RAY_GZIP, '1' ) ) {
			return $size;
		}
		$packed = gzencode( $sample, 6 );
		if ( ! is_string( $packed ) || '' === $packed ) {
			return $size;
		}
		$ratio = strlen( $packed ) / max( 1, strlen( $sample ) );
		return (int) min( $size, ceil( $size * $ratio ) );
	}

	/**
	 * Ask the ceiling about a file still on disk. Same verdict {@see add()}
	 * would reach, taken before the body is read, so a body the link
	 * refuses is never paid for in memory.
	 *
	 * @param int    $size   Full file size in bytes.
	 * @param string $sample First {@see WIRE_SAMPLE_BYTES} of the file.
	 * @param string $path   Site-relative path, for the skip event.
	 * @return WP_Error|null WP_Error when the file must be skipped.
	 */
	public function refuse_before_read( $size, $sample, $path ) {
		return $this->refuse_for_ceiling( (int) $size, self::wire_size_from_sample( $size, $sample ), (string) $path );
	}

	/**
	 * Replace a refused batch's sampled estimates with the
	 * measured wire length. Every file the sample judged is re-measured,
	 * whichever way it erred: a low guess would otherwise keep the file
	 * in every resend down to the floor, and a high one — a body whose
	 * first 256 KiB resist gzip and whose tail does not — would skip a
	 * file the link can carry. Bodies at or below
	 * {@see WIRE_ESTIMATE_MIN_BYTES} were never sampled and keep their
	 * raw length.
	 *
	 * @param array $batch Files of the refused batch.
	 * @return array The same files with exact `wire` values.
	 */
	private function refine_wire_sizes( array $batch ) {
		foreach ( $batch as $i => $f ) {
			if ( ! empty( $f['wire_exact'] ) || $f['size'] <= self::WIRE_ESTIMATE_MIN_BYTES ) {
				continue;
			}
			$batch[ $i ]['wire']       = $this->exact_wire_size( $f['body'] );
			$batch[ $i ]['wire_exact'] = true;
		}
		return $batch;
	}

	/**
	 * Measured gzip length of a body, streamed so the whole
	 * compressed copy is never held. Falls back to the raw length when
	 * the stream is unavailable or fails, which can only make the gate
	 * stricter.
	 *
	 * @param string $body Raw file bytes.
	 * @return int Wire length in bytes.
	 */
	private function exact_wire_size( $body ) {
		$len = strlen( $body );
		if ( ! function_exists( 'deflate_init' ) ) {
			return $len;
		}
		$ctx = deflate_init( ZLIB_ENCODING_GZIP, array( 'level' => 6 ) );
		if ( false === $ctx ) {
			return $len;
		}
		$total = 0;
		for ( $off = 0; $off < $len; $off += self::WIRE_CHUNK_BYTES ) {
			$out = deflate_add( $ctx, substr( $body, $off, self::WIRE_CHUNK_BYTES ), ZLIB_NO_FLUSH );
			if ( false === $out ) {
				return $len;
			}
			$total += strlen( $out );
		}
		$tail = deflate_add( $ctx, '', ZLIB_FINISH );
		if ( false === $tail ) {
			return $len;
		}
		return (int) min( $len, $total + strlen( $tail ) );
	}

	/**
	 * The ceiling gate a file passes before it may enter the
	 * buffer, judged on estimated wire bytes against an empty buffer. A
	 * file the link cannot carry inside one POST is skipped here rather
	 * than burning three attempts and the tick budget proving it.
	 *
	 * @param int    $size Raw body size in bytes.
	 * @param int    $wire Estimated wire size in bytes.
	 * @param string $path Site-relative path, for the log line.
	 * @return WP_Error|null Error to hand back from add(), or null to accept.
	 */
	private function refuse_for_ceiling( $size, $wire, $path ) {
		if ( $this->floor_reached ) {
			return new WP_Error( 'cti_upload_ceiling_floor', 'async submit ceiling hit the floor; the scan is terminating' );
		}
		if ( $wire <= $this->ceiling_bytes ) {
			return null;
		}
		Segurium_Scan_Runner::debug(
			'async_submit_ceiling_skip',
			array(
				'scan_id' => $this->scan_id,
				'path'    => $path,
				'size'    => $size,
				'wire'    => $wire,
				'ceiling' => $this->ceiling_bytes,
			)
		);
		Segurium_Debug::log(
			sprintf(
				'[segurium-async-submit] scan %s: skipping %s (%d bytes, ~%d on the wire) above the %d-byte ceiling',
				$this->scan_id,
				$path,
				$size,
				$wire,
				$this->ceiling_bytes
			)
		);
		return new WP_Error(
			'cti_file_exceeds_batch_ceiling',
			'file is larger than the current submit batch ceiling',
			array(
				'size'    => $size,
				'wire'    => $wire,
				'ceiling' => $this->ceiling_bytes,
			)
		);
	}

	/**
	 * Force-send any buffered files. Returns the merged submit response
	 * (per-call, with the latest `next_seq` server-side). No-op when
	 * empty.
	 *
	 * @param bool $force Skip the IID-scoped submit-pause check. Used by
	 *                    the hard-cap auto-flush in add() — we cannot
	 *                    accept the next file without making room, so
	 *                    the buffer must ship regardless of the pause.
	 * @return array|WP_Error|null `{accepted_count, rejected, next_seq}` on
	 *                              successful flush, WP_Error on submit
	 *                              failure, null when nothing to send.
	 */
	public function flush( $force = false ) {
		if ( empty( $this->buffer ) ) {
			return null;
		}

		// Honour the IID-scoped submit pause stamped by an earlier
		// Retry-After response. `$force = true` is used on the
		// hard-cap auto-flush in add().
		if ( ! $force && Segurium_Async_Scan_Pause::is_paused( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT ) ) {
			return array(
				'accepted_count' => 0,
				'rejected'       => array(),
				'next_seq'       => 0,
				'deferred'       => true,
				'retry_after'    => Segurium_Async_Scan_Pause::pause_remaining( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT ),
			);
		}

		$batch                   = $this->buffer;
		$this->buffer            = array();
		$this->buffer_wire_bytes = 0;
		$this->buffer_raw_bytes  = 0;

		// A batch the link refuses is split under the halved
		// ceiling and sent again; files above the new ceiling drop out as
		// skips. Each halving happens at most once per scan level, so the
		// number of resends is bounded by the walk from MAX_BATCH_BYTES to
		// the floor, and by the runner's tick budget. A batch that fails
		// at the floor flags the scan for termination.
		$queue    = array( $batch );
		$accepted = 0;
		$rejected = array();
		$next_seq = 0;
		while ( ! empty( $queue ) ) {
			$current = array_shift( $queue );
			$result  = $this->send_batch( $current );
			if ( is_wp_error( $result ) ) {
				if ( ! in_array( $result->get_error_code(), self::UPLOAD_CAPACITY_ERROR_CODES, true ) ) {
					// A content rejection: restore what has not shipped so
					// the caller's WP_Error path can count it. Rejections
					// from sub-batches that did ship travel in the error
					// data so they are not lost.
					array_unshift( $queue, $current );
					$this->buffer            = array_merge( ...$queue );
					$this->buffer_wire_bytes = array_sum( array_column( $this->buffer, 'wire' ) );
					$this->buffer_raw_bytes  = array_sum( array_column( $this->buffer, 'size' ) );
					$data                    = $result->get_error_data();
					$data                    = is_array( $data ) ? $data : array();
					$data['rejected']        = $rejected;
					return new WP_Error( $result->get_error_code(), $result->get_error_message(), $data );
				}
				$current       = $this->refine_wire_sizes( $current );
				$current_bytes = array_sum( array_column( $current, 'wire' ) );
				if ( $current_bytes > $this->ceiling_bytes ) {
					// A batch above the ceiling says nothing
					// about the link's capacity for a regular batch. The
					// gate in add() keeps one out of the buffer, so this
					// only fires when a sampled estimate came in low. The
					// re-cut below drops the file as a skip.
					//
					// The link did refuse a batch, so the clean-submit
					// run breaks even though the ceiling stays: a
					// lowered ceiling must not double back on a streak
					// that contained a real failure.
					$this->clean_submits = 0;
					$this->save_ceiling();
					Segurium_Scan_Runner::debug(
						'async_submit_oversize_batch_refused',
						array(
							'scan_id'    => $this->scan_id,
							'bytes'      => $current_bytes,
							'ceiling'    => $this->ceiling_bytes,
							'error_code' => $result->get_error_code(),
						)
					);
				} else {
					$this->on_capacity_failure( $current, $result );
				}
				if ( $this->floor_reached ) {
					foreach ( $queue as $rest ) {
						$this->skipped_tally += count( $rest );
					}
					break;
				}
				// Re-cut everything still unsent: batches cut for the old
				// ceiling would fail again under the new one.
				$queue = $this->split_under_ceiling( array_merge( $current, ...$queue ) );
				if ( ! empty( $queue ) && ! $this->tick_allows_resend() ) {
					foreach ( $queue as $rest ) {
						$this->skipped_tally += count( $rest );
					}
					Segurium_Scan_Runner::debug(
						'async_submit_resend_deferred',
						array(
							'scan_id' => $this->scan_id,
							'ceiling' => $this->ceiling_bytes,
							'files'   => $this->skipped_tally,
						)
					);
					break;
				}
				continue;
			}
			$accepted += (int) $result['accepted_count'];
			$rejected  = array_merge( $rejected, $result['rejected'] );
			$next_seq  = (int) $result['next_seq'];
		}

		return array(
			'accepted_count' => $accepted,
			'rejected'       => $rejected,
			'next_seq'       => $next_seq,
		);
	}

	/**
	 * Whether the runner tick can afford another upload.
	 * Outside a tick (realtime, upload, tests) always true. Inside one,
	 * the heartbeat is renewed first so the watchdog does not reclaim a
	 * scan that is resending, and the remaining budget must still hold
	 * the client's minimum upload window; the ceiling is persisted, so
	 * the next tick starts small without re-learning anything.
	 *
	 * @return bool
	 */
	private function tick_allows_resend() {
		if ( ! class_exists( 'Segurium_Scan_Runner' ) || ! Segurium_Scan_Runner::in_tick() ) {
			return true;
		}
		if ( '' !== $this->scan_id && ! Segurium_Scan_Runner::renew_liveness( $this->scan_id ) ) {
			return false;
		}
		$usable = (float) Segurium_Scan_Runner::time_left_in_tick()
			- (float) Segurium_Scan_Runner::TICK_GRACEFUL_EXIT_SAFETY_SEC;
		return $usable >= (float) Segurium_CTI_Client::SUBMIT_TIMEOUT_MIN_SEC;
	}

	/**
	 * Re-cut a refused batch into batches that fit the
	 * current ceiling. Files larger than the ceiling can never ship and
	 * are counted as skips here.
	 *
	 * @param array $batch Files of the refused batch.
	 * @return array[] Batches, each within the byte and file caps.
	 */
	private function split_under_ceiling( array $batch ) {
		$out   = array();
		$cur   = array();
		$bytes = 0;
		$raw   = 0;
		foreach ( $batch as $f ) {
			if ( $f['wire'] > $this->ceiling_bytes ) {
				++$this->skipped_tally;
				Segurium_Scan_Runner::debug(
					'async_submit_ceiling_skip',
					array(
						'scan_id' => $this->scan_id,
						'path'    => $f['path'],
						'size'    => $f['size'],
						'wire'    => $f['wire'],
						'ceiling' => $this->ceiling_bytes,
					)
				);
				continue;
			}
			if ( ! empty( $cur )
				&& ( $bytes + $f['wire'] > $this->ceiling_bytes
					|| $raw + $f['size'] > self::MAX_BATCH_BYTES
					|| count( $cur ) >= $this->batch_file_cap() )
			) {
				$out[] = $cur;
				$cur   = array();
				$bytes = 0;
				$raw   = 0;
			}
			$cur[]  = $f;
			$bytes += $f['wire'];
			$raw   += $f['size'];
		}
		if ( ! empty( $cur ) ) {
			$out[] = $cur;
		}
		return $out;
	}

	/**
	 * One `/v1/scan/submit` POST. Records accepted files as pending and
	 * maintains the IID-scoped pause. The buffer is not touched here.
	 *
	 * @param array $batch Files to send.
	 * @return array|WP_Error `{accepted_count, rejected, next_seq}` or the
	 *                        client's error.
	 */
	private function send_batch( array $batch ) {
		$client_batch_id = wp_generate_uuid4();
		$result          = $this->cti->scan_submit(
			$this->scan_id,
			$client_batch_id,
			array_map(
				static function ( $f ) {
					return array(
						'sha256' => $f['sha256'],
						'path'   => $f['path'],
						'body'   => $f['body'],
					);
				},
				$batch
			)
		);
		if ( is_wp_error( $result ) ) {
			// A `cti_paused` WP_Error carries the
			// Retry-After value parsed off a 429 / 503 response. Stamp
			// the IID-scoped submit pause so the next tick (and any
			// concurrent scan sharing this IID's bucket) defers too.
			if ( 'cti_paused' === $result->get_error_code() ) {
				$data        = $result->get_error_data();
				$retry_after = is_array( $data ) && isset( $data['retry_after'] ) ? (int) $data['retry_after'] : 0;
				if ( $retry_after > 0 ) {
					// The `scan_submit_pause` observability
					// event is emitted from {@see Segurium_CTI_Client::pause_error()}
					// for both the submit and results endpoints — we only
					// stamp the transient here.
					Segurium_Async_Scan_Pause::set_pause(
						Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT,
						$retry_after
					);
				}
			}
			return $result;
		}

		// A 200 with Retry-After is CTI's pre-emptive
		// pacing for NRS-queue backpressure. Stamp the IID-scoped
		// pause so a fresh submitter in the next scan tick still
		// defers; clear it on the next clean 200 so a one-off slow
		// response does not keep pausing forever.
		$retry_after = isset( $result['retry_after'] ) ? (int) $result['retry_after'] : 0;
		if ( $retry_after > 0 ) {
			Segurium_Async_Scan_Pause::set_pause(
				Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT,
				$retry_after
			);
			Segurium_Scan_Runner::debug(
				'scan_submit_pause',
				array(
					'endpoint'           => Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT,
					'retry_after_secs'   => $retry_after,
					'reason_http_status' => 200,
				)
			);
		} else {
			// Emit `scan_submit_resume` if we're clearing
			// an actually-active pause — the elapsed-time clock comes
			// from the sibling `_set_at` transient.
			$set_at = Segurium_Async_Scan_Pause::pause_set_at( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT );
			if ( $set_at > 0 ) {
				Segurium_Scan_Runner::debug(
					'scan_submit_resume',
					array(
						'endpoint'        => Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT,
						'paused_for_secs' => max( 0, time() - $set_at ),
					)
				);
			}
			Segurium_Async_Scan_Pause::clear( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT );
		}
		$this->on_clean_submit();

		// Bucket per sha — identical-content files (vendored stubs,
		// duplicate cached assets) each need their own pending entry so
		// the verdict can fan out to every path when it arrives.
		$by_sha = array();
		foreach ( $batch as $f ) {
			$by_sha[ $f['sha256'] ][] = $f['path'];
		}

		$accepted_paths = array();
		foreach ( $result['accepted'] as $hash ) {
			$plain = strtolower( str_replace( 'sha256:', '', (string) $hash ) );
			if ( isset( $by_sha[ $plain ] ) ) {
				$accepted_paths[ $plain ] = $by_sha[ $plain ];
			}
		}

		if ( ! empty( $accepted_paths ) ) {
			self::store_pending_paths( $this->scan_id, $this->detector, $accepted_paths );
		}

		/**
		 * Hand-off for the first-poll ETA stamping. Fires on
		 * every successful 200 (including 200-with-Retry-After). The
		 * listener is idempotent on scan_id
		 * so a re-fire from a second submitter instance is a no-op.
		 *
		 * @param string $scan_id      Plugin-side scan UUID.
		 * @param int    $batch_files  Number of files in the batch that just
		 *                             returned 200.
		 * @param int    $submit_unix  Wall-clock unix ts of the successful
		 *                             submit.
		 */
		do_action(
			'segurium_async_scan_submit_first_success',
			$this->scan_id,
			count( $batch ),
			time()
		);

		return array(
			'accepted_count' => count( $result['accepted'] ),
			'rejected'       => $result['rejected'],
			'next_seq'       => (int) $result['next_seq'],
		);
	}

	/**
	 * Record a `{sha256 => path|[path,...]}` map into the `async_pending`
	 * table — one row per (scan, file). Idempotent: the
	 * `(scan_uuid, file_path_hash)` primary key means a re-submitted path is
	 * a no-op upsert, never a duplicate, and two paths that share a content
	 * hash become two rows so a single verdict can fan out to both.
	 *
	 * Replaces the load-whole-blob + merge + save-whole-blob
	 * runtime_kv rewrite, which was O(n) per call (O(n²) across a scan) and
	 * capped at the 16 MB MEDIUMBLOB limit.
	 *
	 * @param string $scan_id  Scan UUID.
	 * @param string $detector Detector label.
	 * @param array  $paths    `[sha256 => string|string[]]` to record.
	 * @return void
	 */
	public static function store_pending_paths( $scan_id, $detector, array $paths ) {
		$scan_id  = (string) $scan_id;
		$detector = '' === (string) $detector ? 'scanner' : (string) $detector;
		if ( '' === $scan_id ) {
			return;
		}
		$now = time();
		foreach ( $paths as $sha => $p ) {
			$sha_lc   = strtolower( (string) $sha );
			$incoming = is_array( $p ) ? array_map( 'strval', $p ) : array( (string) $p );
			foreach ( $incoming as $path_str ) {
				if ( '' === $path_str ) {
					continue;
				}
				try {
					Segurium_Storage::table_upsert(
						self::PENDING_TABLE,
						array(
							'scan_uuid'      => $scan_id,
							'sha256'         => $sha_lc,
							'file_path'      => $path_str,
							'file_path_hash' => hash( 'sha256', $path_str ),
							'detector'       => $detector,
							'created_at'     => $now,
						),
						array( 'scan_uuid', 'file_path_hash' )
					);
				} catch ( Segurium_Storage_Exception $e ) {
					Segurium_Debug::log(
						'[segurium-async-submit] pending upsert failed for ' . $scan_id . ': ' . $e->getMessage()
					);
				}
			}
		}
	}

	/**
	 * Return every pending row for one content hash within a scan. Each
	 * element is `{file_path, detector}`. The drain fans a single verdict
	 * out to each returned path. Empty array when the sha has no pending
	 * rows (already drained, or never submitted).
	 *
	 * @param string $scan_id Scan UUID.
	 * @param string $sha256  Lowercase hex SHA-256.
	 * @return array<int, array{file_path:string, detector:string}>
	 */
	public static function pending_rows_for_sha( $scan_id, $sha256 ) {
		$scan_id = (string) $scan_id;
		$sha256  = strtolower( (string) $sha256 );
		if ( '' === $scan_id || '' === $sha256 ) {
			return array();
		}
		$rows = Segurium_Storage::table_get_results(
			self::PENDING_TABLE,
			'SELECT file_path, detector FROM {{table}} WHERE scan_uuid = %s AND sha256 = %s',
			array( $scan_id, $sha256 ),
			ARRAY_A
		);
		$out  = array();
		foreach ( $rows as $r ) {
			$out[] = array(
				'file_path' => isset( $r['file_path'] ) ? (string) $r['file_path'] : '',
				'detector'  => isset( $r['detector'] ) && '' !== (string) $r['detector'] ? (string) $r['detector'] : 'scanner',
			);
		}
		return $out;
	}

	/**
	 * Drop every pending row for one content hash within a scan. Called by
	 * the drain after a verdict has been applied to all paths sharing the
	 * hash. O(log n) indexed delete (no whole-blob rewrite).
	 *
	 * @param string $scan_id Scan UUID.
	 * @param string $sha256  Lowercase hex SHA-256.
	 * @return void
	 */
	public static function delete_pending_sha( $scan_id, $sha256 ) {
		$scan_id = (string) $scan_id;
		$sha256  = strtolower( (string) $sha256 );
		if ( '' === $scan_id || '' === $sha256 ) {
			return;
		}
		try {
			Segurium_Storage::table_delete(
				self::PENDING_TABLE,
				array(
					'scan_uuid' => $scan_id,
					'sha256'    => $sha256,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log(
				'[segurium-async-submit] pending delete failed for ' . $scan_id . ': ' . $e->getMessage()
			);
		}
	}

	/**
	 * Count pending (submitted-but-unverdicted) paths for a scan.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return int
	 */
	public static function count_pending( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return 0;
		}
		return (int) Segurium_Storage::table_get_var(
			self::PENDING_TABLE,
			'SELECT COUNT(*) FROM {{table}} WHERE scan_uuid = %s',
			array( $scan_id )
		);
	}

	/**
	 * Whether the scan still has any pending path. Cheap `LIMIT 1` probe so
	 * `is_scan_complete()` does not count a potentially huge set.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return bool
	 */
	public static function has_pending( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return false;
		}
		$hit = Segurium_Storage::table_get_var(
			self::PENDING_TABLE,
			'SELECT 1 FROM {{table}} WHERE scan_uuid = %s LIMIT 1',
			array( $scan_id )
		);
		return null !== $hit;
	}

	/**
	 * Delete every pending row for a scan, in bounded batches. Used by scan
	 * teardown and by the seal path. Returns the number of rows removed.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return int
	 */
	public static function delete_all_pending( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return 0;
		}
		return Segurium_Storage::table_delete_chunked( self::PENDING_TABLE, 'scan_uuid', $scan_id );
	}

	/**
	 * Compatibility view of the legacy pending-paths row, reconstructed from
	 * the `async_pending` table: `{detector, paths: {sha=>[paths]}}`. Kept so
	 * older call sites and tests keep working. NOT used on
	 * the per-verdict hot path — the drain uses the granular accessors above.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return array
	 */
	public static function load_pending_row( $scan_id ) {
		$scan_id = (string) $scan_id;
		$out     = array(
			'detector' => 'scanner',
			'paths'    => array(),
		);
		if ( '' === $scan_id ) {
			return $out;
		}
		$rows = Segurium_Storage::table_get_results(
			self::PENDING_TABLE,
			'SELECT sha256, file_path, detector FROM {{table}} WHERE scan_uuid = %s',
			array( $scan_id ),
			ARRAY_A
		);
		foreach ( $rows as $r ) {
			$sha  = strtolower( (string) ( $r['sha256'] ?? '' ) );
			$path = (string) ( $r['file_path'] ?? '' );
			if ( '' === $sha || '' === $path ) {
				continue;
			}
			$out['paths'][ $sha ][] = $path;
			if ( isset( $r['detector'] ) && '' !== (string) $r['detector'] ) {
				$out['detector'] = (string) $r['detector'];
			}
		}
		return $out;
	}

	/**
	 * Compatibility writer mirroring the legacy whole-row replace: clears the
	 * scan's pending rows and re-records whatever `$row['paths']` holds. Kept
	 * for legacy call sites / tests. The hot path no longer rewrites
	 * the whole set; it deletes per-sha via {@see delete_pending_sha()}.
	 *
	 * @param string $scan_id Scan UUID.
	 * @param array  $row     Row data (`detector`, `paths`).
	 * @return void
	 */
	public static function save_pending_row( $scan_id, array $row ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return;
		}
		self::delete_all_pending( $scan_id );
		if ( empty( $row['paths'] ) || ! is_array( $row['paths'] ) ) {
			return;
		}
		$detector = isset( $row['detector'] ) ? (string) $row['detector'] : 'scanner';
		self::store_pending_paths( $scan_id, $detector, $row['paths'] );
	}

	/**
	 * Number of files currently buffered, awaiting auto- or manual flush.
	 *
	 * @return int
	 */
	public function buffer_count() {
		return count( $this->buffer );
	}

	/**
	 * Raw body bytes currently buffered. This is what
	 * `scan_submit()` caps for a multi-file batch.
	 *
	 * @return int
	 */
	public function buffer_bytes() {
		return $this->buffer_raw_bytes;
	}

	/**
	 * Estimated wire bytes currently buffered. This is what the
	 * ceiling bounds.
	 *
	 * @return int
	 */
	public function buffer_wire_bytes() {
		return $this->buffer_wire_bytes;
	}

	/**
	 * Paths currently buffered, in order.
	 *
	 * @return string[]
	 */
	public function buffered_paths() {
		return array_column( $this->buffer, 'path' );
	}

	/**
	 * Halve the batch ceiling after a worker died holding a batch.
	 *
	 * @return void
	 */
	public function shrink_after_worker_death() {
		$this->clean_submits = 0;
		$this->ceiling_bytes = max( self::BATCH_CEILING_FLOOR_BYTES, (int) floor( $this->ceiling_bytes / 2 ) );
		$this->save_ceiling();
	}

	/**
	 * Whether memory_limit leaves room to upload the given bytes.
	 *
	 * @param int $buffered_bytes Body bytes already held in memory.
	 * @param int $unread_bytes   Body bytes the caller is about to read.
	 * @return bool
	 */
	public static function memory_allows( $buffered_bytes, $unread_bytes = 0 ) {
		$limit = self::memory_limit_bytes();
		if ( $limit <= 0 ) {
			return true;
		}
		$needed = memory_get_usage( true ) + $unread_bytes + self::MEMORY_RESERVE_BYTES
			+ ( $buffered_bytes + $unread_bytes ) * self::FLUSH_MEMORY_FACTOR;
		return $needed <= $limit;
	}

	/**
	 * The live memory_limit in bytes; -1 when unlimited.
	 *
	 * @return int
	 */
	public static function memory_limit_bytes() {
		return wp_convert_hr_to_bytes( (string) ini_get( 'memory_limit' ) );
	}
}

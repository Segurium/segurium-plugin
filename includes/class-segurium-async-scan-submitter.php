<?php
/**
 * Async scan submitter — batches files for `/v1/scan/submit`.
 *
 * SEGURIUM-456: replaces the per-file synchronous Neo-Ray escalation.
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
	 * Legacy runtime_kv key prefix under which the per-scan pending-verdicts
	 * map used to be stored as one JSON blob (pre-SEGURIUM-576). Retained only
	 * so the one-shot purge migration
	 * ({@see Segurium_Async_Scan_Results_Loop::migrate_purge_legacy_pending_blobs()})
	 * can find and drop the orphaned blobs. The live store is now the
	 * `async_pending` table — one indexed row per submitted file.
	 */
	const PENDING_KV_PREFIX = 'async_scan:pending:';

	/**
	 * Logical name of the dedicated pending-verdicts table (SEGURIUM-576).
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
	 * In-flight files waiting to be POSTed. Each entry: `{sha256, path, body, size}`.
	 *
	 * @var array
	 */
	private $buffer = array();

	/**
	 * Running total of buffered body bytes; mirrored from
	 * sum( $buffer[*].size ) so we don't recompute on every add().
	 *
	 * @var int
	 */
	private $buffer_bytes = 0;

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

		// Would the new file push us past a wire limit? Flush what we
		// have first, then queue this one. Net effect: the new file
		// always lands in a fresh batch, never spills across two.
		//
		// A hard-cap flush ignores the submit-pause transient because
		// we cannot accept this file without shipping the buffer
		// first. End-of-chunk flushes go through the soft path
		// (flush() honours the IID-scoped pause).
		if ( ! empty( $this->buffer )
			&& ( $this->buffer_bytes + $size > self::MAX_BATCH_BYTES
				|| count( $this->buffer ) >= self::MAX_FILES_PER_BATCH )
		) {
			$flushed = $this->flush( true );
			if ( is_wp_error( $flushed ) ) {
				return $flushed;
			}
		}

		$this->buffer[]      = array(
			'sha256' => $sha256,
			'path'   => (string) $relative_path,
			'body'   => $body,
			'size'   => $size,
		);
		$this->buffer_bytes += $size;
		return true;
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

		$client_batch_id    = wp_generate_uuid4();
		$batch              = $this->buffer;
		$this->buffer       = array();
		$this->buffer_bytes = 0;

		$result = $this->cti->scan_submit(
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
			// Restore the buffer so a follow-up flush or the next add()
			// can retry. The caller's WP_Error path decides whether to
			// surface or to swallow as `neoray_errors`.
			$this->buffer       = $batch;
			$this->buffer_bytes = array_sum( array_column( $batch, 'size' ) );

			// SEGURIUM-478: a `cti_paused` WP_Error carries the
			// Retry-After value parsed off a 429 / 503 response. Stamp
			// the IID-scoped submit pause so the next tick (and any
			// concurrent scan sharing this IID's bucket) defers too.
			if ( 'cti_paused' === $result->get_error_code() ) {
				$data        = $result->get_error_data();
				$retry_after = is_array( $data ) && isset( $data['retry_after'] ) ? (int) $data['retry_after'] : 0;
				if ( $retry_after > 0 ) {
					// SEGURIUM-483: the `scan_submit_pause` observability
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

		// SEGURIUM-478: a 200 with Retry-After is CTI's pre-emptive
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
			// SEGURIUM-483: emit `scan_submit_resume` if we're clearing
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
		 * SEGURIUM-479: hand-off for the first-poll ETA stamping. Fires on
		 * every successful 200 (including 200-with-Retry-After). The
		 * listener — installed by SEGURIUM-480 — is idempotent on scan_id
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
	 * SEGURIUM-576: replaces the load-whole-blob + merge + save-whole-blob
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
	 * call sites and tests that predate SEGURIUM-576 keep working. NOT used on
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
	 * for pre-SEGURIUM-576 call sites / tests. The hot path no longer rewrites
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
	 * Bytes currently buffered.
	 *
	 * @return int
	 */
	public function buffer_bytes() {
		return $this->buffer_bytes;
	}
}

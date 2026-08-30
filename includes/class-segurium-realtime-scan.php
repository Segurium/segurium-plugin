<?php
/**
 * Hourly realtime filesystem change detection and threat scanning.
 *
 * Storage redesign: the file-integrity baseline lives in the
 * dedicated indexed `realtime_snapshot` table — one row per path — instead of
 * a single `realtime:snapshot` runtime_kv JSON blob. The reconcile streams the
 * filesystem walk (never holding the whole tree in PHP), upserts in chunks,
 * and mark-and-sweeps deleted files by generation. This removes the
 * max_allowed_packet write ceiling and the build/read OOM that broke realtime
 * FIM on 100K+ file sites. Mirrors the async_pending redesign.
 *
 * Ingress batches live in a tmp/realtime-<uuid>/ workspace (auto-destroyed
 * after each run); scan history / findings land in the scan_history +
 * scan_findings tables.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Detects file changes between snapshots and submits new/modified files to CTI.
 */
class Segurium_Realtime_Scan {

	const CRON_HOOK            = 'segurium_realtime_scan';
	const CRON_INTERVAL        = 'hourly';
	const CUSTOM_SCHEDULE_SLUG = 'segurium_realtime_custom';
	const SNAPSHOT_TABLE       = 'realtime_snapshot';

	// Legacy single-blob key, kept only so the one-shot purge migration can
	// find and delete it. No longer written.
	const KV_SNAPSHOT        = 'realtime:snapshot';
	const KV_GENERATION      = 'realtime:snapshot_gen';
	const KV_BASELINE_DONE   = 'realtime:baseline_done';
	const MIGRATION_FLAG_577 = 'segurium_migrated_577_purge_snapshot_blob';

	// Streaming/chunk sizes. WALK_CHUNK files are classified per indexed
	// SELECT; UPSERT_CHUNK rows go in one INSERT…ON DUPLICATE statement;
	// DELETE_CHUNK bounds the mark-and-sweep DELETE.
	const WALK_CHUNK   = 1000;
	const UPSERT_CHUNK = 500;
	const DELETE_CHUNK = 5000;

	/**
	 * WordPress installation root path.
	 *
	 * @var string
	 */
	private $base_path;

	/**
	 * Plugin data directory path.
	 *
	 * @var string
	 */
	private $data_dir;

	/**
	 * File modification snapshot keyed by path.
	 *
	 * @var array
	 */
	private $snapshot = array();

	/**
	 * Constructor.
	 *
	 * @param string $base_path WordPress installation root.
	 * @param string $data_dir  Plugin data directory (retained for façade compatibility).
	 */
	public function __construct( $base_path, $data_dir ) {
		$this->base_path = rtrim( $base_path, '/' );
		$this->data_dir  = rtrim( $data_dir, '/' );
	}

	/**
	 * Schedule the realtime scan cron event. Re-aligns to the desired cadence
	 * if a previously scheduled event uses a different interval (e.g. the
	 * SEGURIUM_REALTIME_SCAN_INTERVAL dev override was added or changed).
	 */
	public static function schedule() {
		// Ensure the custom schedule is registered before wp_schedule_event
		// validates the slug against wp_get_schedules(). Idempotent — register_hooks()
		// adds the same callback elsewhere and add_filter dedupes by callback identity.
		add_filter( 'cron_schedules', array( __CLASS__, 'filter_cron_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected -- override only active when SEGURIUM_REALTIME_SCAN_INTERVAL is defined (dev).
		$slug = self::get_schedule_slug();
		$next = wp_next_scheduled( self::CRON_HOOK );
		if ( $next ) {
			if ( wp_get_schedule( self::CRON_HOOK ) === $slug ) {
				return;
			}
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
		wp_schedule_event( time(), $slug, self::CRON_HOOK );
	}

	/**
	 * Remove the scheduled realtime scan cron event.
	 */
	public static function unschedule() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/**
	 * Register the completion hook listener. Runs before Segurium::on_scan_completed
	 * (priority 10) so the scan workspace still exists when we read verdicted paths.
	 */
	public static function register_hooks() {
		add_action( 'segurium_scan_completed', array( __CLASS__, 'on_scan_completed' ), 5, 1 );
		add_filter( 'cron_schedules', array( __CLASS__, 'filter_cron_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected -- override only active when SEGURIUM_REALTIME_SCAN_INTERVAL is defined (dev).
		add_action( 'plugins_loaded', array( __CLASS__, 'migrate_purge_legacy_snapshot_blob' ), 11 );
	}

	/**
	 * One-shot purge of the legacy `realtime:snapshot` runtime_kv blob.
	 *
	 * The baseline lives in the indexed realtime_snapshot table.
	 * The old single-row blob (up to ~19 MB on large sites) is dead weight and
	 * is dropped on the first load after upgrade, then this stays a no-op. The
	 * next realtime tick rebuilds the baseline into the table.
	 *
	 * @return void
	 */
	public static function migrate_purge_legacy_snapshot_blob() {
		if ( (bool) Segurium_Storage::setting_get( self::MIGRATION_FLAG_577, false ) ) {
			return;
		}
		try {
			Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_SNAPSHOT ) );
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-realtime] legacy snapshot purge failed: ' . $e->getMessage() );
			return;
		}
		Segurium_Storage::setting_set( self::MIGRATION_FLAG_577, 1, false );
	}

	/**
	 * Resolve the cron schedule slug to use for the realtime scan event.
	 * Returns the dev-override slug when SEGURIUM_REALTIME_SCAN_INTERVAL is
	 * defined to a positive integer (seconds); otherwise the default 'hourly'.
	 */
	public static function get_schedule_slug() {
		if ( defined( 'SEGURIUM_REALTIME_SCAN_INTERVAL' ) && (int) SEGURIUM_REALTIME_SCAN_INTERVAL > 0 ) {
			return self::CUSTOM_SCHEDULE_SLUG;
		}
		return self::CRON_INTERVAL;
	}

	/**
	 * Register the custom 'segurium_realtime_custom' cron schedule when the
	 * SEGURIUM_REALTIME_SCAN_INTERVAL dev constant is defined. No-op otherwise,
	 * so production runs with no extra schedules registered.
	 *
	 * @param array $schedules Existing schedules.
	 * @return array
	 */
	public static function filter_cron_schedules( $schedules ) {
		if ( ! defined( 'SEGURIUM_REALTIME_SCAN_INTERVAL' ) ) {
			return $schedules;
		}
		$seconds = (int) SEGURIUM_REALTIME_SCAN_INTERVAL;
		if ( $seconds <= 0 ) {
			return $schedules;
		}
		$schedules[ self::CUSTOM_SCHEDULE_SLUG ] = array(
			'interval' => $seconds,
			'display'  => sprintf(
				/* translators: %d: interval in seconds. */
				__( 'Segurium realtime scan (every %d seconds, dev override)', 'segurium' ),
				$seconds
			),
		);
		return $schedules;
	}

	/**
	 * Sync realtime snapshot entries for every path verdicted by a completed
	 * malware scan so the next realtime tick does not re-scan them.
	 *
	 * @param mixed $scan Completed scan instance.
	 */
	public static function on_scan_completed( $scan ) {
		if ( ! $scan instanceof Segurium_Scan ) {
			return;
		}
		$rt = new self( $scan->get_base_path(), $scan->get_data_dir() );
		$rt->sync_verdicted_stream( $scan );
	}

	/**
	 * Execute a realtime scan cycle: detect changes, submit to CTI, record results.
	 *
	 * @return array Summary with files_checked and threats_found counts.
	 */
	public function run() {
		if ( class_exists( 'Segurium_Scan_Lock' ) && Segurium_Scan_Lock::is_running() ) {
			return array(
				'files_checked' => 0,
				'threats_found' => 0,
				'skipped'       => 'scan_running',
			);
		}

		// Pre-flight IID gate. Without a stored installation ID
		// the realtime path would walk the filesystem, hash files, and POST to
		// CTI unauthenticated, producing fake-failure rows. Direct call (no
		// class_exists wrapper) so a missing-class fault fails loud, the same
		// way Segurium_Scan_Runner::start() does — fail-open here would defeat
		// the entire purpose of the gate.
		if ( null === Segurium_IID::get_iid() ) {
			return array(
				'files_checked' => 0,
				'threats_found' => 0,
				'skipped'       => 'no_iid',
			);
		}

		$reconcile = $this->reconcile_snapshot();

		if ( $reconcile['first_run'] ) {
			return array(
				'files_checked' => 0,
				'threats_found' => 0,
			);
		}

		$changed_files = array_merge( $reconcile['new'], $reconcile['modified'] );
		if ( empty( $changed_files ) ) {
			return array(
				'files_checked' => 0,
				'threats_found' => 0,
			);
		}

		$scan_id = wp_generate_uuid4();
		$now     = time();

		$workspace = Segurium_Storage::tmp_make_workspace( 'realtime' );
		if ( false === $workspace ) {
			Segurium_Debug::log( '[segurium-realtime] failed to create tmp workspace' );
			$workspace = null;
		}

		$files = array();
		foreach ( $changed_files as $path ) {
			if ( ! file_exists( $path ) ) {
				continue;
			}
			$sha256 = Segurium_Fs::hash_file( 'sha256', $path );
			if ( false === $sha256 ) {
				continue;
			}
			$stat    = Segurium_Fs::stat( $path );
			$files[] = array(
				'path'   => $this->make_relative_path( $path ),
				'sha256' => $sha256,
				'size'   => $stat ? $stat['size'] : 0,
				'mtime'  => $stat ? $stat['mtime'] : 0,
			);
		}

		if ( $workspace ) {
			Segurium_Storage::tmp_write( $workspace, 'ingress.jsonl', $this->encode_jsonl( $files ) );
		}

		if ( empty( $files ) ) {
			if ( $workspace ) {
				Segurium_Storage::tmp_destroy( $workspace );
			}
			return array(
				'files_checked' => 0,
				'threats_found' => 0,
			);
		}

		$stats   = Segurium_Verdict_Queue::resolve_and_record(
			$scan_id,
			'realtime',
			$files,
			$this->base_path
		);
		$threats = (int) $stats['threats'];

		// On-premise leaves every unknown hash unresolved.
		// Without this the history row is byte-identical to a pass where
		// every file came back clean.
		$this->record_history( $scan_id, $now, count( $files ), $threats, (int) $stats['neoray_skipped'] );

		if ( $threats > 0 ) {
			Segurium_Storage::cti_send_message(
				'realtime_threats',
				wp_json_encode(
					array(
						'scan_id'       => $scan_id,
						'files_checked' => count( $files ),
						'threats_found' => $threats,
					)
				)
			);
		}

		$this->finalize_findings( $scan_id, $threats, $now );

		if ( $workspace ) {
			Segurium_Storage::tmp_destroy( $workspace );
		}

		return array(
			'files_checked' => count( $files ),
			'threats_found' => $threats,
		);
	}

	/**
	 * Close a realtime cycle the way Segurium_Scan_Runner closes a
	 * runner-driven one: reconcile the server-state projection, then hand
	 * the findings to the auto-fix orchestrator. Realtime constructs no
	 * Segurium_Scan and fires no `segurium_scan_completed`, so neither
	 * listener would ever run on this path.
	 *
	 * Ordering mirrors the action's priorities — state at 10, auto-fix at
	 * 15 — so the cure writes the last word on each row.
	 *
	 * The scanned-path set stays empty on purpose. Segurium_Verdict_Queue
	 * already flips each individually verdicted clean file to `fixed`, so
	 * the only work left is the sweep for flagged files that have left the
	 * disk. Handing the submitted set to that first pass instead would flip
	 * a still-infected file to `fixed` whenever `/v1/inspect` failed: the
	 * file was submitted but never verdicted, and an empty threat list then
	 * reads as "scanned, came back clean".
	 *
	 * @param string $scan_id Scan UUID of this cycle.
	 * @param int    $threats Threat count reported by the verdict queue.
	 * @param int    $now     Cycle timestamp.
	 * @return void
	 */
	private function finalize_findings( $scan_id, $threats, $now ) {
		$threats      = (int) $threats;
		$threat_paths = array();
		if ( $threats > 0 ) {
			foreach ( Segurium_Scan::findings_for( $scan_id ) as $row ) {
				if ( ! empty( $row['path'] ) ) {
					$threat_paths[] = (string) $row['path'];
				}
			}
		}

		try {
			$state = new Segurium_Server_State();
			$state->mark_fixed_after_scan( $threat_paths, array(), (int) $now );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-realtime] server state reconcile failed: ' . $e->getMessage() );
		}

		if ( $threats < 1 ) {
			return;
		}

		try {
			Segurium_Auto_Fix::run_for_scan( $scan_id, $this->base_path, $this->data_dir );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-realtime] auto-fix failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Number of files currently tracked in the snapshot table.
	 *
	 * @return int
	 */
	public function snapshot_count() {
		return (int) Segurium_Storage::table_get_var(
			self::SNAPSHOT_TABLE,
			'SELECT COUNT(*) FROM {{table}}'
		);
	}

	/**
	 * Streaming reconcile of the on-disk tree against the snapshot table.
	 *
	 * Walks the filesystem without ever holding the whole tree
	 * in PHP, classifies each chunk against an indexed SELECT, upserts the
	 * chunk stamped with a fresh generation, then mark-and-sweeps every row of
	 * an older generation (the files that no longer exist). This is the
	 * production change-detection path; it replaces the load-whole-blob /
	 * rewrite-whole-blob runtime_kv cycle that OOM'd and tripped
	 * max_allowed_packet at scale.
	 *
	 * Until the baseline has been seeded by ONE fully-completed reconcile, every
	 * run is treated as a first run: it only seeds (chunked upsert) and never
	 * accumulates change lists, so nothing is submitted to CTI. The completion
	 * flag is keyed off a fully-finished reconcile, NOT off row presence — a
	 * first reconcile interrupted by a timeout mid-walk leaves a partial table,
	 * and keying first_run on `snapshot_count() > 0` would then classify every
	 * not-yet-persisted file as "new" and flood CTI. The flag restores the old
	 * atomic-first-run guarantee while keeping the streaming writes.
	 *
	 * @return array{new: string[], modified: string[], first_run: bool}
	 */
	private function reconcile_snapshot() {
		$first_run  = ! $this->baseline_complete();
		$generation = $this->next_generation();
		$now        = time();

		$result = array(
			'new'       => array(),
			'modified'  => array(),
			'first_run' => $first_run,
		);

		// Buffer maps an absolute path to its mtime and size for the chunk.
		$buffer = array();
		$flush  = function () use ( &$buffer, &$result, $generation, $now, $first_run ) {
			if ( empty( $buffer ) ) {
				return;
			}
			$by_hash = array();
			foreach ( $buffer as $abs => $meta ) {
				$by_hash[ hash( 'sha256', (string) $abs ) ] = array(
					'abs'   => (string) $abs,
					'mtime' => (int) $meta['mtime'],
					'size'  => (int) $meta['size'],
				);
			}
			$existing = $first_run ? array() : $this->select_existing( array_keys( $by_hash ) );

			$rows = array();
			foreach ( $by_hash as $h => $info ) {
				if ( ! $first_run ) {
					if ( ! isset( $existing[ $h ] ) ) {
						$result['new'][] = $info['abs'];
					} elseif ( $existing[ $h ]['mtime'] !== $info['mtime'] || $existing[ $h ]['size'] !== $info['size'] ) {
						$result['modified'][] = $info['abs'];
					}
				}
				$rows[] = $this->snapshot_row( $info['abs'], $info['mtime'], $info['size'], $generation, $now );
			}
			Segurium_Storage::table_upsert_bulk( self::SNAPSHOT_TABLE, $rows, array( 'file_path_hash' ), self::UPSERT_CHUNK );
			$buffer = array();
		};

		$this->walk_directory_streaming(
			$this->base_path,
			function ( $abs, $mtime, $size ) use ( &$buffer, $flush ) {
				$buffer[ $abs ] = array(
					'mtime' => $mtime,
					'size'  => $size,
				);
				if ( count( $buffer ) >= self::WALK_CHUNK ) {
					$flush();
				}
			}
		);
		$flush();

		// Any row not re-stamped with this generation is a file that vanished
		// since the previous run → sweep it out in bounded batches.
		Segurium_Storage::table_delete_chunked(
			self::SNAPSHOT_TABLE,
			'generation',
			(string) $generation,
			self::DELETE_CHUNK,
			'<>'
		);

		// Only now — after a full walk + sweep — is the baseline trustworthy.
		// Marking it here (not on row presence) is what makes an interrupted
		// first run safe: the next tick stays a seed-only first run.
		if ( $first_run ) {
			$this->mark_baseline_complete();
		}

		return $result;
	}

	/**
	 * Whether at least one reconcile has fully seeded the baseline.
	 *
	 * @return bool
	 */
	private function baseline_complete() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_BASELINE_DONE )
		);
		return null !== $raw && '0' !== (string) $raw;
	}

	/**
	 * Record that the baseline has been fully seeded by a completed reconcile.
	 * Tiny fixed-size runtime_kv flag — no blob, no size ceiling.
	 */
	private function mark_baseline_complete() {
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_BASELINE_DONE,
				'kv_value'   => '1',
				'expires_at' => null,
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Refresh snapshot rows for paths verdicted by a completed full scan.
	 *
	 * Chunked + table-backed. No-op when no baseline exists yet,
	 * so we never half-seed state. Input is consumed in WALK_CHUNK batches so
	 * the path list never has to be diffed against the whole baseline at once.
	 *
	 * @param array $relative_paths Paths relative to base_path.
	 * @return int Number of snapshot rows updated or removed.
	 */
	public function sync_snapshot_paths( array $relative_paths ) {
		if ( 0 === $this->snapshot_count() ) {
			return 0;
		}
		$generation = $this->current_generation();
		$now        = time();
		$changed    = 0;
		$buffer     = array();
		foreach ( $relative_paths as $rel ) {
			$buffer[] = (string) $rel;
			if ( count( $buffer ) >= self::WALK_CHUNK ) {
				$changed += $this->sync_chunk( $buffer, $generation, $now );
				$buffer   = array();
			}
		}
		if ( ! empty( $buffer ) ) {
			$changed += $this->sync_chunk( $buffer, $generation, $now );
		}
		return $changed;
	}

	/**
	 * Stream a completed scan's verdicted paths straight into the snapshot
	 * table without ever materialising the full path list in PHP.
	 *
	 * @param Segurium_Scan $scan Completed scan.
	 * @return int Rows updated or removed.
	 */
	public function sync_verdicted_stream( Segurium_Scan $scan ) {
		if ( 0 === $this->snapshot_count() ) {
			return 0;
		}
		$generation = $this->current_generation();
		$now        = time();
		$changed    = 0;
		$buffer     = array();
		$flush      = function () use ( &$buffer, &$changed, $generation, $now ) {
			if ( empty( $buffer ) ) {
				return;
			}
			$changed += $this->sync_chunk( $buffer, $generation, $now );
			$buffer   = array();
		};
		$scan->stream_verdicted_paths(
			function ( $rel ) use ( &$buffer, $flush ) {
				$buffer[] = (string) $rel;
				if ( count( $buffer ) >= self::WALK_CHUNK ) {
					$flush();
				}
			}
		);
		$flush();
		return $changed;
	}

	/**
	 * Apply one chunk of relative paths to the snapshot table: upsert the
	 * still-present files whose mtime/size changed (or that are new), delete
	 * rows for files that vanished. Returns the number of rows touched.
	 *
	 * @param array $rels       Relative paths.
	 * @param int   $generation Generation marker to stamp on upserts.
	 * @param int   $now        Timestamp.
	 * @return int
	 */
	private function sync_chunk( array $rels, $generation, $now ) {
		// Maps each path hash to its absolute path plus mtime and size, where a
		// null mtime means the file no longer exists on disk.
		$want = array();
		foreach ( $rels as $rel ) {
			$rel = ltrim( (string) $rel, '/' );
			if ( '' === $rel ) {
				continue;
			}
			$abs  = $this->base_path . '/' . $rel;
			$hash = hash( 'sha256', $abs );
			if ( isset( $want[ $hash ] ) ) {
				continue;
			}
			$stat          = file_exists( $abs ) ? Segurium_Fs::stat( $abs ) : false;
			$want[ $hash ] = array(
				'abs'   => $abs,
				'mtime' => $stat ? (int) $stat['mtime'] : null,
				'size'  => $stat ? (int) $stat['size'] : null,
			);
		}
		if ( empty( $want ) ) {
			return 0;
		}

		$existing = $this->select_existing( array_keys( $want ) );

		$changed   = 0;
		$to_upsert = array();
		$to_delete = array();
		foreach ( $want as $hash => $info ) {
			$in_db = isset( $existing[ $hash ] );
			if ( null === $info['mtime'] ) {
				if ( $in_db ) {
					$to_delete[] = $hash;
					++$changed;
				}
				continue;
			}
			if ( ! $in_db
				|| $existing[ $hash ]['mtime'] !== $info['mtime']
				|| $existing[ $hash ]['size'] !== $info['size'] ) {
				$to_upsert[] = $this->snapshot_row( $info['abs'], $info['mtime'], $info['size'], $generation, $now );
				++$changed;
			}
		}
		if ( ! empty( $to_upsert ) ) {
			Segurium_Storage::table_upsert_bulk( self::SNAPSHOT_TABLE, $to_upsert, array( 'file_path_hash' ), self::UPSERT_CHUNK );
		}
		foreach ( $to_delete as $hash ) {
			Segurium_Storage::table_delete( self::SNAPSHOT_TABLE, array( 'file_path_hash' => $hash ) );
		}
		return $changed;
	}

	/**
	 * Fetch mtime/size for a chunk of path hashes in one indexed SELECT.
	 *
	 * @param array $hashes file_path_hash values.
	 * @return array<string, array{mtime:int, size:int}> Keyed by file_path_hash.
	 */
	private function select_existing( array $hashes ) {
		if ( empty( $hashes ) ) {
			return array();
		}
		$placeholders = implode( ',', array_fill( 0, count( $hashes ), '%s' ) );
		$rows         = Segurium_Storage::table_get_results(
			self::SNAPSHOT_TABLE,
			// $placeholders is a hard-coded list of %s marks, not user data.
			'SELECT file_path_hash, mtime, size FROM {{table}} WHERE file_path_hash IN (' . $placeholders . ')', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- only %s placeholders interpolated; values bound via prepare().
			$hashes,
			ARRAY_A
		);
		$out = array();
		foreach ( $rows as $row ) {
			$out[ $row['file_path_hash'] ] = array(
				'mtime' => (int) $row['mtime'],
				'size'  => (int) $row['size'],
			);
		}
		return $out;
	}

	/**
	 * Build a snapshot-table row for one file.
	 *
	 * @param string $abs        Absolute path.
	 * @param int    $mtime      Modification time.
	 * @param int    $size       File size in bytes.
	 * @param int    $generation Generation marker.
	 * @param int    $now        Timestamp.
	 * @return array<string, mixed>
	 */
	private function snapshot_row( $abs, $mtime, $size, $generation, $now ) {
		return array(
			'file_path_hash' => hash( 'sha256', (string) $abs ),
			'file_path'      => (string) $abs,
			'mtime'          => (int) $mtime,
			'size'           => (int) $size,
			'generation'     => (int) $generation,
			'updated_at'     => (int) $now,
		);
	}

	/**
	 * Read the current generation marker (0 when none recorded yet).
	 *
	 * @return int
	 */
	private function current_generation() {
		$raw = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_GENERATION )
		);
		return null === $raw ? 0 : (int) $raw;
	}

	/**
	 * Bump and persist the generation marker, returning the new value. The
	 * marker is a tiny fixed-size runtime_kv int — no blob, no size ceiling.
	 *
	 * @return int
	 */
	private function next_generation() {
		$next = $this->current_generation() + 1;
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_GENERATION,
				'kv_value'   => (string) $next,
				'expires_at' => null,
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);
		return $next;
	}

	/**
	 * Build a full in-memory filesystem snapshot (absolute path => "mtime:size").
	 *
	 * Back-compat / test helper. The production path is reconcile_snapshot(),
	 * which streams instead of materialising the whole tree.
	 *
	 * @return array Snapshot keyed by absolute path.
	 */
	public function build_snapshot() {
		$this->snapshot = array();
		$this->walk_directory( $this->base_path );
		return $this->snapshot;
	}

	/**
	 * Detect new, modified, and deleted files vs the in-memory snapshot.
	 *
	 * Back-compat / test helper (compares full in-memory sets). Production uses
	 * reconcile_snapshot(), which streams and never holds the whole tree.
	 *
	 * @return array Arrays of new, modified, and deleted file paths.
	 */
	public function detect_changes() {
		$current = array();
		$this->walk_directory( $this->base_path, $current );

		$changes = array(
			'new'      => array(),
			'modified' => array(),
			'deleted'  => array(),
		);

		foreach ( $current as $path => $mtime ) {
			if ( ! isset( $this->snapshot[ $path ] ) ) {
				$changes['new'][] = $path;
			} elseif ( $this->snapshot[ $path ] !== $mtime ) {
				$changes['modified'][] = $path;
			}
		}
		foreach ( $this->snapshot as $path => $mtime ) {
			if ( ! isset( $current[ $path ] ) ) {
				$changes['deleted'][] = $path;
			}
		}
		return $changes;
	}

	/**
	 * Persist the in-memory snapshot into the snapshot table (chunked upsert +
	 * stale-generation sweep). Back-compat / test helper — production seeds the
	 * table through reconcile_snapshot().
	 */
	public function save_snapshot() {
		$generation = $this->next_generation();
		$now        = time();
		$rows       = array();
		foreach ( $this->snapshot as $abs => $entry ) {
			list( $mtime, $size ) = $this->split_entry( $entry );
			$rows[]               = $this->snapshot_row( (string) $abs, $mtime, $size, $generation, $now );
			if ( count( $rows ) >= self::UPSERT_CHUNK ) {
				Segurium_Storage::table_upsert_bulk( self::SNAPSHOT_TABLE, $rows, array( 'file_path_hash' ), self::UPSERT_CHUNK );
				$rows = array();
			}
		}
		if ( ! empty( $rows ) ) {
			Segurium_Storage::table_upsert_bulk( self::SNAPSHOT_TABLE, $rows, array( 'file_path_hash' ), self::UPSERT_CHUNK );
		}
		Segurium_Storage::table_delete_chunked(
			self::SNAPSHOT_TABLE,
			'generation',
			(string) $generation,
			self::DELETE_CHUNK,
			'<>'
		);
		// A full in-memory snapshot was just persisted, so the baseline is
		// complete — keeps the build_snapshot()+save_snapshot() seeding path
		// equivalent to a completed reconcile.
		$this->mark_baseline_complete();
	}

	/**
	 * Load the snapshot from the table into the in-memory map. Back-compat /
	 * test helper — production never materialises the whole baseline.
	 */
	public function load_snapshot() {
		$this->snapshot = array();
		$rows           = Segurium_Storage::table_get_results(
			self::SNAPSHOT_TABLE,
			'SELECT file_path, mtime, size FROM {{table}}',
			array(),
			ARRAY_A
		);
		foreach ( $rows as $row ) {
			$this->snapshot[ $row['file_path'] ] = $row['mtime'] . ':' . $row['size'];
		}
	}

	/**
	 * Return the current in-memory snapshot.
	 *
	 * @return array
	 */
	public function get_snapshot() {
		return $this->snapshot;
	}

	/**
	 * Split a stored "mtime:size" entry into its int parts.
	 *
	 * @param string $entry Entry string.
	 * @return array{0:int,1:int}
	 */
	private function split_entry( $entry ) {
		$parts = explode( ':', (string) $entry, 2 );
		return array(
			(int) $parts[0],
			isset( $parts[1] ) ? (int) $parts[1] : 0,
		);
	}

	/**
	 * Stream a directory tree, invoking $on_file($abs, $mtime, $size) per file.
	 * Never accumulates the tree, so memory stays flat regardless of file
	 * count. The plugin data dir is skipped (its churn is not site content).
	 *
	 * @param string   $dir     Directory to walk.
	 * @param callable $on_file Per-file callback.
	 */
	private function walk_directory_streaming( $dir, callable $on_file ) {
		$handle = Segurium_Fs::opendir( $dir );
		if ( ! $handle ) {
			return;
		}
		while ( false !== ( $entry = readdir( $handle ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $dir . '/' . $entry;
			if ( is_dir( $path ) ) {
				if ( rtrim( $path, '/' ) === $this->data_dir ) {
					continue;
				}
				$this->walk_directory_streaming( $path, $on_file );
			} elseif ( is_file( $path ) ) {
				$stat = Segurium_Fs::stat( $path );
				if ( $stat ) {
					call_user_func( $on_file, $path, (int) $stat['mtime'], (int) $stat['size'] );
				}
			}
		}
		closedir( $handle );
	}

	/**
	 * In-memory walk shim used by build_snapshot()/detect_changes() (test
	 * helpers). Delegates to the streaming walker.
	 *
	 * @param string     $dir    Directory to walk.
	 * @param array|null $target Target array to populate (by reference).
	 */
	private function walk_directory( $dir, &$target = null ) {
		if ( null === $target ) {
			$target = &$this->snapshot;
		}
		$this->walk_directory_streaming(
			$dir,
			function ( $path, $mtime, $size ) use ( &$target ) {
				$target[ $path ] = $mtime . ':' . $size;
			}
		);
	}

	/**
	 * Convert an absolute path to a path relative to the base.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	private function make_relative_path( $path ) {
		if ( 0 === strpos( $path, $this->base_path . '/' ) ) {
			return substr( $path, strlen( $this->base_path ) + 1 );
		}
		return $path;
	}

	/**
	 * Render an array of records as newline-delimited JSON for workspace storage.
	 *
	 * @param array $records Records to encode.
	 * @return string
	 */
	private function encode_jsonl( array $records ) {
		$out = '';
		foreach ( $records as $record ) {
			$out .= wp_json_encode( $record ) . "\n";
		}
		return $out;
	}

	/**
	 * Record the realtime scan into scan_history. Findings are written by
	 * {@see Segurium_Verdict_Queue::resolve_and_record} directly.
	 *
	 * @param string $scan_id       Unique scan identifier.
	 * @param int    $now           Timestamp of the scan.
	 * @param int    $files_checked Number of files checked.
	 * @param int    $threats_found Threats found in this realtime pass.
	 * @param int    $files_skipped Files left unresolved, e.g. an unknown hash
	 *                              on-premise or a body over the size cap.
	 */
	private function record_history( $scan_id, $now, $files_checked, $threats_found = 0, $files_skipped = 0 ) {
		try {
			Segurium_Storage::table_insert(
				'scan_history',
				array(
					'scan_uuid'      => (string) $scan_id,
					'scan_type'      => 'realtime',
					'status'         => 'completed',
					'started_at'     => (int) $now,
					'finished_at'    => (int) $now,
					'files_scanned'  => (int) $files_checked,
					'files_skipped'  => (int) $files_skipped,
					'threats_found'  => (int) $threats_found,
					'trigger_source' => 'realtime',
					'error_code'     => null,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-realtime] history insert failed: ' . $e->getMessage() );
		}
	}
}

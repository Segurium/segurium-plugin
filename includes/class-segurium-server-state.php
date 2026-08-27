<?php
/**
 * Per-file malware detection state helper.
 *
 * The scan_findings table is append-only. All "current state per
 * file" reads and writes funnel through {@see Segurium_File_State}. This
 * class retains the existing admin UI / scan runner / realtime API
 * surface and delegates to the projection.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Latest-state-per-file view backed by scan_findings.
 */
class Segurium_Server_State {

	const RECENT_DAYS = 14;

	/**
	 * Plugin data directory path (retained for legacy constructor compatibility).
	 *
	 * @var string
	 */
	private $data_dir;

	/**
	 * Constructor.
	 *
	 * @param string $data_dir Unused; kept for API compatibility.
	 */
	public function __construct( $data_dir = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$this->data_dir = (string) $data_dir;
	}

	/**
	 * No-op: state lives in the database now.
	 *
	 * @return bool
	 */
	public function load() {
		return true;
	}

	/**
	 * No-op: writes are performed immediately by the mutator methods.
	 *
	 * @return void
	 */
	public function save() {
	}

	/**
	 * Run a callable inside a "transaction". Kept as a named helper so the
	 * existing call sites that wrap mutations in it keep working; no
	 * additional locking is needed because every mutator is a single
	 * SQL statement.
	 *
	 * @param string   $data_dir Plugin data directory (unused).
	 * @param callable $callback Callback receiving a fresh instance.
	 * @return mixed
	 */
	public static function transact( $data_dir, callable $callback ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		return $callback( new self( $data_dir ) );
	}

	/**
	 * Record a file as malicious. Primary writer (the verdict queue) persists
	 * findings inline as CTI responses arrive, so this helper is only used
	 * by the realtime scanner which wants to persist findings that bypass
	 * the verdict queue.
	 *
	 * @param string   $path      Relative file path.
	 * @param string   $sha256    SHA-256 hash.
	 * @param int|null $timestamp Detection timestamp.
	 * @param int      $verdict   CTI verdict code.
	 * @return void
	 */
	public function add_malicious( $path, $sha256, $timestamp = null, $verdict = 0 ) {
		if ( '' === (string) $path || '' === (string) $sha256 ) {
			return;
		}
		// Respect the user's "ignored" decision even when the realtime
		// detector sees the file again.
		if ( 'ignored' === Segurium_File_State::get_status( (string) $path ) ) {
			return;
		}
		$scan_uuid = $this->default_scan_uuid();
		$ts        = null === $timestamp ? time() : (int) $timestamp;
		try {
			Segurium_Storage::table_upsert(
				'scan_findings',
				array(
					'scan_uuid'      => $scan_uuid,
					'file_path'      => (string) $path,
					'file_path_hash' => hash( 'sha256', $path ),
					'sha256'         => (string) $sha256,
					'verdict'        => (string) (int) $verdict,
					'severity'       => (int) $verdict > 1 ? 2 : 1,
					'status'         => 'open',
					'backup_id'      => null,
					'detector'       => 'realtime',
					'created_at'     => $ts,
					'resolved_at'    => null,
				),
				array( 'scan_uuid', 'file_path_hash' )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-server-state] add_malicious failed: ' . $e->getMessage() );
		}
		Segurium_File_State::record_finding(
			array(
				'scan_uuid' => $scan_uuid,
				'file_path' => (string) $path,
				'sha256'    => (string) $sha256,
				'verdict'   => (int) $verdict,
				'severity'  => (int) $verdict > 1 ? 2 : 1,
				'detector'  => 'realtime',
				'timestamp' => $ts,
			)
		);
	}

	/**
	 * Record multiple files as malicious.
	 *
	 * @param array $files Array of file descriptors.
	 * @return void
	 */
	public function add_malicious_batch( $files ) {
		foreach ( $files as $f ) {
			$this->add_malicious(
				$f['path'] ?? '',
				$f['sha256'] ?? '',
				$f['timestamp'] ?? null,
				$f['verdict'] ?? 0
			);
		}
	}

	/**
	 * Update the state of a tracked file across every scan it appears in.
	 *
	 * @param string   $path      Relative file path.
	 * @param string   $state     New state value.
	 * @param int|null $timestamp Timestamp for the state change.
	 * @param string   $backup_id Optional backup identifier.
	 * @return void
	 */
	public function update_file_state( $path, $state, $timestamp = null, $backup_id = '' ) {
		if ( '' === (string) $path ) {
			return;
		}
		$status = $this->map_state( $state );
		$ts     = null === $timestamp ? time() : (int) $timestamp;
		$bkp    = '' !== (string) $backup_id ? (string) $backup_id : null;
		Segurium_File_State::set_status( (string) $path, $status, $ts, $bkp );
	}

	/**
	 * Mark a file as ignored.
	 *
	 * @param string   $path        Relative file path.
	 * @param string   $ignore_type Ignore type (path or hash), unused.
	 * @param int|null $timestamp   Timestamp.
	 * @return void
	 */
	public function ignore_file( $path, $ignore_type, $timestamp = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$this->update_file_state( $path, 'ignored', $timestamp );
	}

	/**
	 * Mark previously open findings as fixed when they no longer appear as a
	 * threat after the latest scan.
	 *
	 * Two reconciliation passes:
	 * 1. Files that were scanned in this run and came back clean.
	 * 2. Files that were previously flagged but no longer exist on disk
	 *    (deleted out-of-band before this scan ran).
	 *
	 * @param array    $threat_paths  Paths still flagged as threats.
	 * @param array    $scanned_paths All paths scanned in this run.
	 * @param int|null $timestamp     Resolution timestamp.
	 * @return void
	 */
	public function mark_fixed_after_scan( $threat_paths, $scanned_paths, $timestamp = null ) {
		$scanned_set = array_flip( array_map( 'strval', $scanned_paths ) );
		$threat_set  = array_flip( array_map( 'strval', $threat_paths ) );
		$ts          = null === $timestamp ? time() : (int) $timestamp;

		// Pass 1: scanned-but-clean files → fixed.
		$hashes = array();
		foreach ( array_keys( $scanned_set ) as $path ) {
			if ( isset( $threat_set[ $path ] ) ) {
				continue;
			}
			$hashes[] = hash( 'sha256', (string) $path );
		}
		if ( ! empty( $hashes ) ) {
			Segurium_File_State::mark_fixed_by_hashes( $hashes, $ts );
		}

		// Pass 2: previously-flagged files deleted from disk → fixed.
		$open_rows = Segurium_File_State::list_open_paths();
		if ( empty( $open_rows ) ) {
			return;
		}

		$deleted_hashes = array();
		foreach ( $open_rows as $row ) {
			if ( isset( $threat_set[ $row['file_path'] ] ) ) {
				continue;
			}
			$abs = wp_normalize_path( Segurium_Path_Helpers::wp_root() . $row['file_path'] );
			if ( ! file_exists( $abs ) ) {
				$deleted_hashes[] = $row['file_path_hash'];
			}
		}
		if ( ! empty( $deleted_hashes ) ) {
			Segurium_File_State::mark_fixed_by_hashes( $deleted_hashes, $ts );
		}
	}

	/**
	 * Retrieve a paginated list of state items (latest status per file).
	 *
	 * @param int    $page        Page number.
	 * @param int    $per_page    Items per page.
	 * @param bool   $recent_only Whether to limit to recent items.
	 * @param string $filter      One of Segurium_File_State::FILTER_* constants.
	 * @return array
	 */
	public function get_items( $page = 1, $per_page = 20, $recent_only = false, $filter = Segurium_File_State::FILTER_ALL ) {
		$rows = Segurium_File_State::get_page( (int) $page, (int) $per_page, (bool) $recent_only, (string) $filter );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[] = array(
				'path'      => (string) $row['path'],
				'sha256'    => (string) $row['sha256'],
				'state'     => $this->unmap_state( (string) $row['status'] ),
				'timestamp' => (int) $row['timestamp'],
				'verdict'   => (int) $row['verdict'],
				'backup_id' => $row['backup_id'],
			);
		}
		return $out;
	}

	/**
	 * Return the total count of distinct files tracked.
	 *
	 * @param bool   $recent_only Whether to count only recent entries.
	 * @param string $filter      One of Segurium_File_State::FILTER_* constants.
	 * @return int
	 */
	public function get_total( $recent_only = false, $filter = Segurium_File_State::FILTER_ALL ) {
		return Segurium_File_State::get_total( (bool) $recent_only, (string) $filter );
	}

	/**
	 * Per-tab count breakdown for the Malware Scanner tabs UI.
	 *
	 * @param bool $recent_only Whether to restrict counts to recent entries.
	 * @return array<string, int>
	 */
	public function get_counts( $recent_only = false ) {
		return Segurium_File_State::get_counts( (bool) $recent_only );
	}

	/**
	 * Generate a placeholder scan UUID for realtime detections that don't
	 * have a scan_history row. Real scan_history rows are owned by
	 * {@see Segurium_Realtime_Scan}.
	 *
	 * @return string
	 */
	private function default_scan_uuid() {
		return 'realtime-' . substr( md5( uniqid( '', true ) ), 0, 30 );
	}

	/**
	 * Translate a legacy state label into the scan_findings status vocabulary.
	 *
	 * @param string $state Legacy state label.
	 * @return string
	 */
	private function map_state( $state ) {
		switch ( (string) $state ) {
			case 'malicious':
				return 'open';
			case 'cleaned':
				return 'cured';
			case 'restored':
				return 'open';
			case 'fixed':
				return 'fixed';
			case 'ignored':
				return 'ignored';
			default:
				return (string) $state;
		}
	}

	/**
	 * Translate a scan_findings status back to the legacy state label.
	 *
	 * @param string $status scan_findings.status value.
	 * @return string
	 */
	private function unmap_state( $status ) {
		switch ( $status ) {
			case 'open':
				return 'malicious';
			case 'cured':
				return 'cleaned';
			case 'fixed':
				return 'fixed';
			case 'ignored':
				return 'ignored';
			case 'restored':
				return 'restored';
			default:
				return $status;
		}
	}
}

<?php
/**
 * Filesystem scanner for the Segurium security plugin.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Walks the filesystem, hashes files, and records results in a JSONL file.
 */
class Segurium_Scanner {

	/**
	 * Maximum file size in bytes (100 MB).
	 */
	const MAX_FILE_SIZE = 104857600;

	/**
	 * Skip reason: file is unreadable.
	 */
	const SKIP_UNREADABLE = 1;

	/**
	 * Skip reason: hash computation failed.
	 */
	const SKIP_HASH_FAILED = 2;

	/**
	 * Skip reason: file exceeds maximum size.
	 */
	const SKIP_TOO_LARGE = 3;

	/**
	 * Skip reason: file matches an exclude pattern.
	 */
	const SKIP_EXCLUDED = 6;

	/**
	 * Skip reason: broken symbolic link.
	 */
	const SKIP_BROKEN_SYMLINK = 8;

	/**
	 * Skip reason: directory is unreadable.
	 */
	const SKIP_DIR_UNREADABLE = 9;

	/**
	 * Skip reason: path restricted by open_basedir.
	 */
	const SKIP_OPEN_BASEDIR = 10;

	/**
	 * Skip reason: stat() call failed.
	 */
	const SKIP_STAT_FAILED = 11;

	/**
	 * Absolute path to the WordPress root directory.
	 *
	 * @var string
	 */
	private $base_path;

	/**
	 * Absolute path to the plugin data directory.
	 *
	 * @var string
	 */
	private $data_dir;

	/**
	 * Maximum time in seconds allowed for a single chunk.
	 *
	 * @var float
	 */
	private $time_limit;

	/**
	 * Compiled regex patterns for excluded paths.
	 *
	 * @var array
	 */
	private $exclude_patterns = array();

	/**
	 * Current scanner state.
	 *
	 * @var array
	 */
	private $state = array(
		'status'        => 'idle',
		'started_at'    => 0,
		'updated_at'    => 0,
		'files_found'   => 0,
		'files_skipped' => 0,
		'skip_reasons'  => array(),
		'warnings'      => array(),
		'dirs_stack'    => array(),
		'pending_files' => array(),
		'result_file'   => '',
		'result_bytes'  => 0,
		'skips_bytes'   => 0,
		'visited_bytes' => 0,
	);

	/**
	 * Realpaths of directories already enumerated, as a lookup map.
	 *
	 * Held in memory and backed by `$this->visited_file`, never by the
	 * state record: one absolute path per directory turns the state into
	 * a payload that grows with the site, and the state is rewritten on
	 * every checkpoint.
	 *
	 * @var array<string,bool>
	 */
	private $visited = array();

	/**
	 * Timestamp when the current chunk started.
	 *
	 * @var float
	 */
	private $start_time;

	/**
	 * Path to the scanner state JSON file.
	 *
	 * @var string
	 */
	private $state_file;

	/**
	 * Path to the per-scan skips JSONL log (one `{ts, reason, path}` per line).
	 *
	 * @var string
	 */
	private $skips_file;

	/**
	 * Path to the per-scan visited-directory log (one realpath per line).
	 *
	 * @var string
	 */
	private $visited_file;

	/**
	 * Constructor.
	 *
	 * @param string $base_path        Absolute path to WordPress root.
	 * @param string $data_dir         Absolute path to plugin data directory.
	 * @param float  $time_limit       Maximum seconds per chunk.
	 * @param array  $exclude_patterns Glob patterns to exclude from scanning.
	 */
	public function __construct( $base_path, $data_dir, $time_limit = 25, $exclude_patterns = array() ) {
		$this->base_path        = rtrim( $base_path, '/' );
		$this->data_dir         = rtrim( $data_dir, '/' );
		$this->time_limit       = $time_limit;
		$this->state_file       = $this->data_dir . '/scanner-state.json';
		$this->skips_file       = $this->data_dir . '/scanner-skips.jsonl';
		$this->visited_file     = $this->data_dir . '/scanner-visited.jsonl';
		$this->exclude_patterns = $this->compile_patterns( $exclude_patterns );
	}

	/**
	 * Absolute path to the per-scan skips JSONL log. Exposed so the
	 * orchestrator can move it out of the workspace before
	 * `tmp_destroy()` wipes the dir.
	 *
	 * @return string
	 */
	public function get_skips_file() {
		return $this->skips_file;
	}

	/**
	 * Compile glob patterns into regex patterns.
	 *
	 * @param array $patterns Raw glob patterns.
	 * @return array Compiled regex patterns.
	 */
	private function compile_patterns( $patterns ) {
		$compiled = array();
		foreach ( $patterns as $pattern ) {
			$pattern = trim( $pattern );
			if ( '' === $pattern || '*' === $pattern ) {
				continue;
			}
			$regex      = preg_quote( $pattern, '#' );
			$regex      = str_replace( '\\*', '.*', $regex );
			$compiled[] = '#(?:^|/)' . $regex . '$#i';
		}
		return $compiled;
	}

	/**
	 * Check whether a path matches any exclude pattern.
	 *
	 * @param string $path Filesystem path to check.
	 * @return bool True if the path should be excluded.
	 */
	private function is_excluded( $path ) {
		if ( empty( $this->exclude_patterns ) ) {
			return false;
		}
		$relative = $path;
		if ( 0 === strpos( $path, $this->base_path . '/' ) ) {
			$relative = substr( $path, strlen( $this->base_path ) + 1 );
		}
		foreach ( $this->exclude_patterns as $regex ) {
			if ( preg_match( $regex, $relative ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Record a skipped file with the given reason.
	 *
	 * Also appends a JSONL row to `$this->skips_file` so the path can be
	 * surfaced after the run completes — `$this->state['skip_reasons']` only
	 * carries a count per reason ID.
	 *
	 * @param int    $reason_id Skip reason constant.
	 * @param string $path      Absolute path that was skipped (file, dir, or
	 *                          symlink). Empty string allowed so old call
	 *                          sites without path context still compile.
	 * @return void
	 */
	private function record_skip( $reason_id, $path = '' ) {
		++$this->state['files_skipped'];
		$key = (string) $reason_id;
		if ( ! isset( $this->state['skip_reasons'][ $key ] ) ) {
			$this->state['skip_reasons'][ $key ] = 0;
		}
		++$this->state['skip_reasons'][ $key ];

		if ( '' === (string) $path || '' === (string) $this->skips_file ) {
			return;
		}
		$safe_path = $path;
		if ( ! mb_check_encoding( $path, 'UTF-8' ) ) {
			$safe_path = preg_replace_callback(
				'/[\x80-\xff]/',
				function ( $m ) {
					return sprintf( '\\x%02x', ord( $m[0] ) );
				},
				$path
			);
		}
		$line = wp_json_encode(
			array(
				'ts'     => time(),
				'reason' => (int) $reason_id,
				'path'   => $safe_path,
			)
		);
		if ( false === $line ) {
			return;
		}
		// Best-effort append; never throw — a skip-log write failure must
		// not abort the scan or mask the underlying skip we're trying to
		// surface.
		Segurium_Fs::write( $this->skips_file, $line . "\n", FILE_APPEND | LOCK_EX );
	}

	/**
	 * Detect PHP environment warnings that may affect scanning.
	 *
	 * @return void
	 */
	private function detect_warnings() {
		$open_basedir = ini_get( 'open_basedir' );
		if ( ! empty( $open_basedir ) ) {
			$this->state['warnings'][] = 'open_basedir_active';
		}
	}

	/**
	 * Initialize and start a new filesystem scan.
	 *
	 * @return void
	 */
	public function start() {
		$this->ensure_data_dir();

		$now           = time();
		$result_file   = $this->data_dir . '/scanner-results.jsonl';
		$this->state   = array(
			'status'        => 'running',
			'started_at'    => $now,
			'updated_at'    => $now,
			'files_found'   => 0,
			'files_skipped' => 0,
			'skip_reasons'  => array(),
			'warnings'      => array(),
			'dirs_stack'    => array( $this->base_path ),
			'pending_files' => array(),
			'result_file'   => $result_file,
			'result_bytes'  => 0,
			'skips_bytes'   => 0,
			'visited_bytes' => 0,
		);
		$this->visited = array();

		$this->detect_warnings();

		touch( $result_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		// Truncate any leftover logs from the previous run.
		Segurium_Fs::write( $this->skips_file, '' );
		Segurium_Fs::write( $this->visited_file, '' );
		$this->save_state();
	}

	/**
	 * Load the scanner state from disk.
	 *
	 * @return bool True if state was loaded successfully.
	 */
	public function load_state() {
		$data = Segurium_State_File::read_json_with_retry( $this->state_file );
		if ( ! is_array( $data ) || empty( $data['status'] ) ) {
			return false;
		}

		// A state record written before the visited log existed carries
		// its directory list inline and knows no byte offsets. Seed the
		// in-memory set from it and adopt whatever the output files hold,
		// so an upgrade landing mid-scan keeps both its cycle guard and
		// the rows it already committed.
		$legacy = array();
		if ( isset( $data['visited_real'] ) && is_array( $data['visited_real'] ) ) {
			$legacy = $data['visited_real'];
			unset( $data['visited_real'] );
		}
		if ( ! isset( $data['result_file'] ) ) {
			$data['result_file'] = '';
		}
		$offsets = array(
			'result_bytes'  => (string) $data['result_file'],
			'skips_bytes'   => $this->skips_file,
			'visited_bytes' => $this->visited_file,
		);
		foreach ( $offsets as $key => $path ) {
			if ( ! isset( $data[ $key ] ) ) {
				$data[ $key ] = $this->byte_length( $path );
			}
		}

		$this->state = $data;
		if ( ! $this->rewind_outputs() ) {
			return false;
		}
		// Through mark_visited(), not straight into the map: the inline
		// list is dropped from the state here, so a set that only lived in
		// memory would leave the walker with no cycle guard for the
		// directories it had already seen from the next chunk on.
		foreach ( $legacy as $real ) {
			if ( ! isset( $this->visited[ (string) $real ] ) ) {
				$this->mark_visited( (string) $real );
			}
		}
		return true;
	}

	/**
	 * Cut every append-only output back to the byte offset the last
	 * checkpoint recorded, then reload the visited set from what
	 * survives.
	 *
	 * A chunk appends result, skip and visited rows as it works and only
	 * records their lengths when the state save succeeds. Anything past
	 * those offsets belongs to a chunk that never committed: replaying it
	 * would duplicate result rows, and a stale visited row would make the
	 * walker skip a directory it still owes.
	 *
	 * Only ever shrinks. A log shorter than its recorded offset means the
	 * bytes never reached the disk or something outside the scan removed
	 * them; padding it back up to length would hand the verdict queue a
	 * run of NULs to parse as results.
	 *
	 * @return bool False when a log could not be cut back, which leaves
	 *               uncommitted rows in place and voids the rollback.
	 */
	private function rewind_outputs() {
		$targets = array(
			(string) $this->state['result_file'] => (int) $this->state['result_bytes'],
			$this->skips_file                    => (int) $this->state['skips_bytes'],
			$this->visited_file                  => (int) $this->state['visited_bytes'],
		);
		$ok      = true;
		foreach ( $targets as $path => $bytes ) {
			if ( '' === $path || $this->byte_length( $path ) <= $bytes ) {
				continue;
			}
			if ( Segurium_Fs::truncate( $path, $bytes ) ) {
				continue;
			}
			$ok = false;
			if ( class_exists( 'Segurium_Scan_Runner' ) ) {
				Segurium_Scan_Runner::debug(
					'scanner_rewind_failed',
					array(
						'path'  => $path,
						'bytes' => $bytes,
						'size'  => $this->byte_length( $path ),
					)
				);
			}
		}
		$this->load_visited();
		return $ok;
	}

	/**
	 * Read the visited-directory log into the in-memory lookup map.
	 *
	 * @return void
	 */
	private function load_visited() {
		$this->visited = array();
		$raw           = Segurium_Fs::read( $this->visited_file );
		if ( false === $raw || '' === $raw ) {
			return;
		}
		foreach ( explode( "\n", $raw ) as $line ) {
			if ( '' === $line ) {
				continue;
			}
			$row = json_decode( $line, true );
			if ( is_array( $row ) && isset( $row['path'] ) ) {
				$this->visited[ (string) $row['path'] ] = true;
			}
		}
	}

	/**
	 * Current byte length of a path, zero when it does not exist.
	 *
	 * @param string $path Absolute path.
	 * @return int
	 */
	private function byte_length( $path ) {
		$size = Segurium_Fs::size( (string) $path );
		return false === $size ? 0 : (int) $size;
	}

	/**
	 * Process a chunk of the filesystem scan within the time limit.
	 *
	 * @return array Progress data after the chunk.
	 */
	public function process_chunk() {
		$this->start_time = microtime( true );
		$checkpoint       = $this->state;
		$did_work         = false;
		$completed        = false;

		while ( true ) {
			if ( $did_work && $this->is_time_up() ) {
				break;
			}

			if ( ! empty( $this->state['pending_files'] ) ) {
				$file = array_shift( $this->state['pending_files'] );
				$this->process_file( $file );
				$did_work = true;
				continue;
			}

			if ( empty( $this->state['dirs_stack'] ) ) {
				$completed = true;
				break;
			}

			$dir = array_pop( $this->state['dirs_stack'] );
			$this->enumerate_directory( $dir );
			$did_work = true;
		}

		if ( $completed ) {
			$this->state['status']        = 'completed';
			$this->state['dirs_stack']    = array();
			$this->state['pending_files'] = array();
		}
		$this->state['updated_at'] = time();
		$this->commit( $checkpoint );

		$progress = $this->build_progress();
		if ( $completed ) {
			$progress['completed']   = true;
			$progress['result_file'] = $this->state['result_file'];
		}
		return $progress;
	}

	/**
	 * Seal the work this chunk did: flush every append-only output,
	 * record their lengths, and persist the state record once.
	 *
	 * This is the scan's only durability point. The rows a chunk appends
	 * become committed the moment the state naming their offsets lands;
	 * until then `rewind_outputs()` can discard them wholesale. That is
	 * what lets the walker append thousands of result rows per chunk
	 * while rewriting the state exactly once.
	 *
	 * @param array $checkpoint State as it stood when the chunk started.
	 * @return void
	 * @throws RuntimeException When the state save fails; the chunk's
	 *                          appends are rolled back first so the
	 *                          outputs match the restored counters.
	 */
	private function commit( array $checkpoint ) {
		$result_file = (string) $this->state['result_file'];
		if ( '' !== $result_file ) {
			Segurium_Fs::sync( $result_file );
		}
		Segurium_Fs::sync( $this->skips_file );
		Segurium_Fs::sync( $this->visited_file );

		$this->state['result_bytes']  = $this->byte_length( $result_file );
		$this->state['skips_bytes']   = $this->byte_length( $this->skips_file );
		$this->state['visited_bytes'] = $this->byte_length( $this->visited_file );

		if ( Segurium_State_File::atomic_write_json( $this->state_file, $this->state ) ) {
			return;
		}

		// Never let a silently-failed state save leave the outputs ahead
		// of the counters: rewind to the last committed offsets and
		// surface the failure so the runner stops instead of walking on
		// with state it could not persist.
		$uncommitted = (int) $this->state['files_found'];
		$this->state = $checkpoint;
		$this->rewind_outputs();

		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			Segurium_Scan_Runner::debug(
				'scanner_save_state_failed',
				array(
					'state_file'  => (string) $this->state_file,
					'files_found' => $uncommitted,
					'rolled_back' => (int) $this->state['files_found'],
				)
			);
		}
		throw new RuntimeException( 'Segurium_Scanner::save_state failed for ' . esc_html( (string) $this->state_file ) );
	}

	/**
	 * Return the current scanner state array.
	 *
	 * @return array Current state.
	 */
	public function get_state() {
		return $this->state;
	}

	/**
	 * Persist the scanner state to disk via an atomic write so the
	 * orchestrator poller can never observe a partial JSON payload.
	 *
	 * @return void
	 * @throws RuntimeException When the underlying atomic_write_json fails
	 *                          and the caller must not continue with stale
	 *                          state.
	 */
	public function save_state() {
		$ok = Segurium_State_File::atomic_write_json( $this->state_file, $this->state );
		if ( ! $ok ) {
			if ( class_exists( 'Segurium_Scan_Runner' ) ) {
				Segurium_Scan_Runner::debug(
					'scanner_save_state_failed',
					array(
						'state_file'  => (string) $this->state_file,
						'files_found' => isset( $this->state['files_found'] ) ? (int) $this->state['files_found'] : 0,
					)
				);
			}
			throw new RuntimeException( 'Segurium_Scanner::save_state failed for ' . esc_html( (string) $this->state_file ) );
		}
	}

	/**
	 * List files and subdirectories within a directory.
	 *
	 * @param string $dir Absolute directory path to enumerate.
	 * @return void
	 */
	private function enumerate_directory( $dir ) {
		$real = Segurium_Fs::realpath( $dir );
		if ( false === $real ) {
			$this->record_skip( self::SKIP_OPEN_BASEDIR, $dir );
			return;
		}

		if ( isset( $this->visited[ $real ] ) ) {
			return;
		}
		$this->mark_visited( $real );

		// Skip the plugin data directory.
		$data_real = Segurium_Fs::realpath( $this->data_dir );
		if ( false !== $data_real && 0 === strpos( $real, $data_real ) ) {
			return;
		}

		$handle = Segurium_Fs::opendir( $dir );
		if ( false === $handle ) {
			$this->record_skip( self::SKIP_DIR_UNREADABLE, $dir );
			return;
		}

		$subdirs = array();
		$files   = array();

		// phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
		while ( false !== ( $entry = readdir( $handle ) ) ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $dir . '/' . $entry;
			if ( is_dir( $path ) ) {
				$subdirs[] = $path;
			} elseif ( is_file( $path ) ) {
				$files[] = $path;
			} elseif ( is_link( $path ) ) {
				$this->record_skip( self::SKIP_BROKEN_SYMLINK, $path );
			}
		}
		closedir( $handle );

		foreach ( array_reverse( $subdirs ) as $subdir ) {
			if ( $this->is_excluded( $subdir ) ) {
				$this->record_skip( self::SKIP_EXCLUDED, $subdir );
				continue;
			}
			$subdir_real = Segurium_Fs::realpath( $subdir );
			if ( false !== $subdir_real && isset( $this->visited[ $subdir_real ] ) ) {
				continue;
			}
			$this->state['dirs_stack'][] = $subdir;
		}

		$this->state['pending_files'] = $files;
	}

	/**
	 * Hash a single file and record the result.
	 *
	 * @param string $filepath Absolute path to the file.
	 * @return void
	 */
	private function process_file( $filepath ) {
		if ( $this->is_excluded( $filepath ) ) {
			$this->record_skip( self::SKIP_EXCLUDED, $filepath );
			return;
		}

		if ( ! is_readable( $filepath ) ) {
			$this->record_skip( self::SKIP_UNREADABLE, $filepath );
			return;
		}

		$size = Segurium_Fs::size( $filepath );
		if ( false !== $size && $size > self::MAX_FILE_SIZE ) {
			$this->record_skip( self::SKIP_TOO_LARGE, $filepath );
			return;
		}

		$hash = Segurium_Fs::hash_file( 'sha256', $filepath );
		if ( false === $hash ) {
			$this->record_skip( self::SKIP_HASH_FAILED, $filepath );
			return;
		}

		$stat = Segurium_Fs::stat( $filepath );
		if ( false === $stat ) {
			$this->record_skip( self::SKIP_STAT_FAILED, $filepath );
			return;
		}

		$safe_path = $filepath;
		if ( ! mb_check_encoding( $filepath, 'UTF-8' ) ) {
			$safe_path = preg_replace_callback(
				'/[\x80-\xff]/',
				function ( $m ) {
					return sprintf( '\\x%02x', ord( $m[0] ) );
				},
				$filepath
			);
		}

		$record = wp_json_encode(
			array(
				'path'   => $safe_path,
				'sha256' => $hash,
				'ctime'  => $stat['ctime'],
				'mtime'  => $stat['mtime'],
				'size'   => $stat['size'],
			)
		);

		$this->record_append( $record . "\n" );
	}

	/**
	 * Append one JSONL result row and count it.
	 *
	 * The row is not durable yet: `commit()` flushes the file and records
	 * its length at the end of the chunk, and `rewind_outputs()` discards
	 * anything past that offset. A short write is rolled back here so the
	 * file never carries a torn row.
	 *
	 * @param string $line One full JSONL line, including the trailing newline.
	 * @return void
	 * @throws RuntimeException When the JSONL fopen / flock / fwrite / ftell fails.
	 */
	private function record_append( $line ) {
		$result_file = $this->state['result_file'];

		$fh = Segurium_Fs::open( $result_file, 'cb' );
		if ( false === $fh ) {
			throw new RuntimeException( 'Segurium_Scanner: failed to open result file ' . esc_html( (string) $result_file ) );
		}

		try {
			if ( ! Segurium_Fs::flock( $fh, LOCK_EX ) ) {
				throw new RuntimeException( 'Segurium_Scanner: failed to lock result file ' . esc_html( (string) $result_file ) );
			}
			fseek( $fh, 0, SEEK_END );
			$pre_size = ftell( $fh );
			if ( false === $pre_size ) {
				throw new RuntimeException( 'Segurium_Scanner: ftell failed on ' . esc_html( (string) $result_file ) );
			}

			$written = Segurium_Fs::put( $fh, $line );
			if ( false === $written || strlen( $line ) !== $written ) {
				ftruncate( $fh, $pre_size );
				throw new RuntimeException( 'Segurium_Scanner: short write on result file ' . esc_html( (string) $result_file ) );
			}

			++$this->state['files_found'];
		} finally {
			Segurium_Fs::flock( $fh, LOCK_UN );
			Segurium_Fs::close( $fh );
		}
	}

	/**
	 * Record a directory realpath as enumerated, in memory and in the
	 * per-scan visited log.
	 *
	 * @param string $real Directory realpath.
	 * @return void
	 */
	private function mark_visited( $real ) {
		$this->visited[ $real ] = true;
		$line                   = wp_json_encode( array( 'path' => $real ) );
		if ( false === $line ) {
			return;
		}
		if ( false !== Segurium_Fs::write( $this->visited_file, $line . "\n", FILE_APPEND | LOCK_EX ) ) {
			return;
		}
		// The in-memory set carries this chunk regardless. Surfacing the
		// failed append is what tells you why a later chunk re-walked a
		// subtree: the reload rebuilds the set from this log alone.
		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			Segurium_Scan_Runner::debug(
				'scanner_visited_append_failed',
				array( 'path' => $real )
			);
		}
	}

	/**
	 * Build the progress response array.
	 *
	 * @return array Progress data including counts and timing.
	 */
	private function build_progress() {
		$elapsed = microtime( true ) - $this->start_time;
		$total   = $this->state['updated_at'] > 0
			? $this->state['updated_at'] - $this->state['started_at']
			: 0;

		return array(
			'completed'     => false,
			'status'        => $this->state['status'],
			'files_found'   => $this->state['files_found'],
			'files_skipped' => $this->state['files_skipped'],
			'elapsed'       => round( $elapsed, 2 ),
			'total_elapsed' => $total,
			'result_file'   => $this->state['result_file'],
		);
	}

	/**
	 * Check whether the time limit for the current chunk has been reached.
	 *
	 * @return bool True if time limit exceeded.
	 */
	private function is_time_up() {
		return ( microtime( true ) - $this->start_time ) >= $this->time_limit;
	}

	/**
	 * Ensure the data directory exists and is protected.
	 *
	 * @return void
	 */
	private function ensure_data_dir() {
		if ( ! is_dir( $this->data_dir ) ) {
			wp_mkdir_p( $this->data_dir );
		}

		// Guard files (.htaccess + index.php) come from the shared Layer-3
		// helper so the data dir under wp_upload_dir()/segurium-data is hardened
		// uniformly and the raw guard writes live in exactly one place.
		Segurium_Storage_Fs::write_guards( $this->data_dir );
	}
}

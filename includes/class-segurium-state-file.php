<?php
/**
 * Atomic JSON state-file helpers.
 *
 * The scan orchestrator, scanner, and verdict queue all persist JSON
 * state files that are concurrently read by the admin-side status
 * poller while being written by the background worker. A naive
 * `file_put_contents` + `file_get_contents` pair lets readers observe
 * a partial write — `json_decode` then returns null, `load_state()`
 * returns false, and the chunk engine clobbers the in-memory state
 * with zeros. This is what produced the "progress jumps between 0
 * and 1000" bug.
 *
 * `atomic_write_json` writes to `$path.tmp.<pid>.<uniq>` and then
 * renames onto the target. `rename()` is atomic on POSIX filesystems,
 * so readers either see the old file or the new one — never a torn
 * write. `read_json_with_retry` wraps the read side with a tiny
 * backoff so any filesystem that briefly observes the rename gap
 * (NFS, some FUSE overlays) still gets a valid payload.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tiny value-object style helper for crash-safe JSON state files.
 */
final class Segurium_State_File {

	/**
	 * How many times `read_json_with_retry` will re-attempt a
	 * json_decode on a non-empty file that failed to parse.
	 */
	const READ_RETRIES = 3;

	/**
	 * Sleep between retries, in microseconds (default 20 ms).
	 */
	const READ_RETRY_SLEEP_US = 20000;

	/**
	 * Write $data as JSON to $path atomically.
	 *
	 * @param string $path Absolute target path.
	 * @param mixed  $data Data to JSON-encode.
	 * @return bool True on success.
	 */
	public static function atomic_write_json( $path, $data ) {
		$json = wp_json_encode( $data );
		if ( false === $json ) {
			self::log_atomic_write_failure( $path, 'json_encode' );
			return false;
		}

		$dir = dirname( $path );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		// Keep the temp file in the target directory so rename() stays
		// on the same filesystem (and therefore atomic). Include the
		// PID + a uuid so concurrent writers can't clobber each other's
		// temp files mid-flight.
		$tmp = $path . '.tmp.' . getmypid() . '.' . wp_generate_uuid4();

		// SEGURIUM-428: write via fopen so we can fsync before the rename.
		// `file_put_contents` does not expose an fsync hook, and a missing
		// fsync is exactly what lets a state-file rename reach the
		// directory entry while the inode's data is still buffered — the
		// next reader sees zero bytes and load_state() silently rolls
		// back to defaults.
		$fh = Segurium_Fs::open( $tmp, 'wb' );
		if ( false === $fh ) {
			self::log_atomic_write_failure( $path, 'fopen_tmp' );
			return false;
		}
		if ( ! Segurium_Fs::flock( $fh, LOCK_EX ) ) {
			Segurium_Fs::close( $fh );
			Segurium_Fs::delete( $tmp );
			self::log_atomic_write_failure( $path, 'flock_tmp' );
			return false;
		}
		$bytes = Segurium_Fs::put( $fh, $json );
		if ( false === $bytes || strlen( $json ) !== $bytes ) {
			Segurium_Fs::flock( $fh, LOCK_UN );
			Segurium_Fs::close( $fh );
			Segurium_Fs::delete( $tmp );
			self::log_atomic_write_failure( $path, 'short_write' );
			return false;
		}
		fflush( $fh );
		// fsync() is PHP 8.1+. On older runtimes we only get fflush, which
		// at least drains userspace buffers — POSIX rename atomicity then
		// guarantees readers see either old or new content, even if the
		// crash window for partial-data-after-rename is a hair wider.
		if ( function_exists( 'fsync' ) ) {
			fsync( $fh );
		}
		Segurium_Fs::flock( $fh, LOCK_UN );
		Segurium_Fs::close( $fh );

		// rename() is deliberate here: WP_Filesystem::move() is not
		// guaranteed to be atomic, but POSIX rename(2) on the same
		// filesystem is — that's the entire point of this helper. The
		// admin-side status poller must never observe a partial write,
		// and that's only achievable via a rename-based swap.
		if ( ! Segurium_Fs::rename( $tmp, $path ) ) {
			Segurium_Fs::delete( $tmp );
			self::log_atomic_write_failure( $path, 'rename' );
			return false;
		}

		return true;
	}

	/**
	 * Surface an atomic_write_json failure on the runner debug channel.
	 *
	 * Kept separate so the call sites stay tight and so we degrade
	 * cleanly when the runner class is not loaded yet (e.g. from the
	 * plugin bootstrap path).
	 *
	 * @param string $path  Target state-file path.
	 * @param string $stage Short identifier of which step failed.
	 * @return void
	 */
	private static function log_atomic_write_failure( $path, $stage ) {
		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			Segurium_Scan_Runner::debug(
				'atomic_write_failed',
				array(
					'path'  => (string) $path,
					'stage' => (string) $stage,
				)
			);
		}
		Segurium_Debug::log(
			sprintf( '[segurium-state-file] atomic_write_json failed at stage=%s path=%s', $stage, $path )
		);
	}

	/**
	 * Run a callable inside a process-wide critical section keyed on a
	 * lock file. Used to serialize read-modify-write sequences against
	 * shared state files (scan history, server state) when multiple
	 * scan flavors (manual, scheduled, realtime) might be writing
	 * concurrently.
	 *
	 * The lock file is created on demand. flock() is process-level on
	 * Linux, so concurrent PHP-FPM workers serialize correctly. The
	 * callback receives no arguments and its return value is forwarded
	 * to the caller.
	 *
	 * @param string   $lock_path Absolute path to the lock file (will
	 *                            be created if missing).
	 * @param callable $callback        Critical section body.
	 * @return mixed Return value of $fn, or null on lock acquire
	 *               failure.
	 */
	public static function with_lock( $lock_path, callable $callback ) {
		$dir = dirname( $lock_path );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$fp = Segurium_Fs::open( $lock_path, 'c' );
		if ( ! $fp ) {
			// Last-resort fall through: still run the callback so the
			// caller never silently no-ops, but log the lock failure.
			Segurium_Debug::log( '[segurium-state-file] could not open lock file ' . $lock_path );
			return $callback();
		}

		if ( ! Segurium_Fs::flock( $fp, LOCK_EX ) ) {
			Segurium_Fs::close( $fp );
			Segurium_Debug::log( '[segurium-state-file] could not flock lock file ' . $lock_path );
			return $callback();
		}

		try {
			return $callback();
		} finally {
			Segurium_Fs::flock( $fp, LOCK_UN );
			Segurium_Fs::close( $fp );
		}
	}

	/**
	 * Read and JSON-decode a state file, retrying on transient
	 * partial-read failures.
	 *
	 * @param string $path Absolute source path.
	 * @return mixed Decoded value, or null when the file is missing,
	 *               empty, or cannot be parsed after all retries.
	 */
	public static function read_json_with_retry( $path ) {
		if ( ! file_exists( $path ) ) {
			return null;
		}
		$attempts = max( 1, self::READ_RETRIES );
		for ( $i = 0; $i < $attempts; $i++ ) {
			$raw = Segurium_Fs::read( $path );
			if ( false === $raw || '' === $raw ) {
				usleep( self::READ_RETRY_SLEEP_US );
				continue;
			}
			$data = json_decode( $raw, true );
			if ( null !== $data ) {
				return $data;
			}
			usleep( self::READ_RETRY_SLEEP_US );
		}
		return null;
	}
}

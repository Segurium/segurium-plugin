<?php
/**
 * Layer 3 — per-scan ephemeral workspaces.
 *
 * Features allocate an isolated directory, write files atomically, read them
 * back with a size bound, then either destroy the workspace explicitly or let
 * the daily GC sweep remove it once all files are stale.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ephemeral workspace API.
 */
class Segurium_Storage_Tmp {

	const DEFAULT_MAX_READ_BYTES = 32 * 1048576; // 32 MB.

	/**
	 * Create a fresh workspace.
	 *
	 * @param string $purpose Short alphanumeric tag used in the directory name.
	 * @return string|false Absolute path to the workspace, or false on failure.
	 */
	public static function make_workspace( string $purpose ) {
		if ( ! self::is_valid_purpose( $purpose ) ) {
			Segurium_Debug::log( 'Segurium: tmp_make_workspace: invalid purpose "' . $purpose . '"' );
			return false;
		}
		if ( ! Segurium_Storage_Fs::ensure_layout() ) {
			self::record_unwritable();
			return false;
		}
		$root = Segurium_Storage_Fs::tmp_dir();
		if ( ! is_writable( $root ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			self::record_unwritable();
			return false;
		}
		try {
			$suffix = bin2hex( random_bytes( 8 ) );
		} catch ( Exception $e ) {
			Segurium_Debug::log( 'Segurium: tmp_make_workspace: random_bytes failed: ' . $e->getMessage() );
			return false;
		}
		$dir = $root . '/' . $purpose . '-' . $suffix;
		if ( ! Segurium_Storage_Fs::ensure_dir( $dir, 0700 ) ) {
			return false;
		}
		Segurium_Storage_Fs::write_guards( $dir );
		return $dir;
	}

	/**
	 * Atomically write a file inside a workspace.
	 *
	 * Writes `<path>.tmp`, flushes, and renames over the final path. On
	 * Windows the rename() will fail if the destination exists, so we remove
	 * the old file first after a successful temp write.
	 *
	 * @param string $workspace Absolute path returned by {@see make_workspace}.
	 * @param string $relpath   Relative path inside the workspace.
	 * @param string $data      Bytes to write.
	 */
	public static function write( string $workspace, string $relpath, string $data ): bool {
		if ( ! self::is_valid_workspace( $workspace ) ) {
			return false;
		}
		if ( ! Segurium_Storage_Fs::is_safe_relpath( $relpath ) ) {
			Segurium_Debug::log( 'Segurium: tmp_write: refused relpath (len=' . strlen( $relpath ) . ')' );
			return false;
		}
		$target = $workspace . '/' . $relpath;
		$dir    = dirname( $target );
		if ( ! Segurium_Storage_Fs::ensure_dir( $dir, 0700 ) ) {
			return false;
		}
		return Segurium_Storage_Fs::atomic_put( $target, $data );
	}

	/**
	 * Read a file inside a workspace, capped by a filterable byte limit.
	 *
	 * @param string $workspace Absolute workspace path.
	 * @param string $relpath   Relative path.
	 * @return string|null Bytes, or null on any error / oversized file.
	 */
	public static function read( string $workspace, string $relpath ): ?string {
		if ( ! self::is_valid_workspace( $workspace ) ) {
			return null;
		}
		if ( ! Segurium_Storage_Fs::is_safe_relpath( $relpath ) ) {
			return null;
		}
		$path = $workspace . '/' . $relpath;
		if ( ! is_file( $path ) ) {
			return null;
		}
		$max = (int) apply_filters( 'segurium_storage_tmp_max_read_bytes', self::DEFAULT_MAX_READ_BYTES );
		if ( $max > 0 && Segurium_Fs::size( $path ) > $max ) {
			Segurium_Debug::log( 'Segurium: tmp_read: file exceeds max read bytes: ' . $path );
			return null;
		}
		$data = Segurium_Fs::read( $path );
		return false === $data ? null : $data;
	}

	/**
	 * Delete a workspace tree.
	 *
	 * @param string $workspace Absolute workspace path.
	 */
	public static function destroy( string $workspace ): bool {
		if ( ! self::is_valid_workspace( $workspace ) ) {
			return false;
		}
		return Segurium_Storage_Fs::recursive_delete( $workspace );
	}

	/**
	 * Remove every workspace whose files are all older than $max_age seconds.
	 *
	 * @param int $max_age Age threshold in seconds (0 = remove all).
	 * @return int Number of workspaces removed.
	 */
	public static function gc( int $max_age = DAY_IN_SECONDS ): int {
		$root = Segurium_Storage_Fs::tmp_dir();
		if ( ! is_dir( $root ) ) {
			return 0;
		}
		$cutoff  = time() - max( 0, $max_age );
		$removed = 0;
		foreach ( self::scandir( $root ) as $entry ) {
			$path = $root . '/' . $entry;
			if ( ! is_dir( $path ) || is_link( $path ) ) {
				continue;
			}
			if ( self::is_all_stale( $path, $cutoff ) && Segurium_Storage_Fs::recursive_delete( $path ) ) {
				++$removed;
			}
		}
		return $removed;
	}

	/**
	 * True when every regular file under $dir has mtime <= $cutoff.
	 *
	 * Guard files (`.htaccess` / `index.php`) are written once at workspace
	 * creation and never rewritten, so their mtime reflects the *directory*
	 * age rather than the data age — checking the workspace dir's own mtime
	 * captures that. A 0-cutoff trivially passes (used by tests to wipe
	 * everything).
	 *
	 * @param string $dir    Directory to inspect.
	 * @param int    $cutoff Unix timestamp; files with mtime > $cutoff block removal.
	 */
	private static function is_all_stale( string $dir, int $cutoff ): bool {
		if ( (int) filemtime( $dir ) > $cutoff ) {
			return false;
		}
		$iter = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS )
		);
		foreach ( $iter as $entry ) {
			if ( ! $entry->isFile() ) {
				continue;
			}
			$name = $entry->getFilename();
			if ( '.htaccess' === $name || 'index.php' === $name ) {
				continue;
			}
			if ( $entry->getMTime() > $cutoff ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * List directory entries without '.' / '..'.
	 *
	 * @param string $dir Directory to list.
	 * @return array<string>
	 */
	private static function scandir( string $dir ): array {
		$entries = Segurium_Fs::scandir( $dir );
		if ( false === $entries ) {
			return array();
		}
		return array_values(
			array_filter(
				$entries,
				static function ( $e ) {
					return '.' !== $e && '..' !== $e;
				}
			)
		);
	}

	/**
	 * True when $workspace is a directory under tmp_dir().
	 *
	 * @param string $workspace Absolute path.
	 */
	private static function is_valid_workspace( string $workspace ): bool {
		if ( '' === $workspace ) {
			return false;
		}
		if ( ! is_dir( $workspace ) ) {
			return false;
		}
		return Segurium_Storage_Fs::is_under( $workspace, Segurium_Storage_Fs::tmp_dir() );
	}

	/**
	 * Reject purposes that would escape the workspace root or look weird in logs.
	 *
	 * @param string $purpose Candidate value.
	 */
	private static function is_valid_purpose( string $purpose ): bool {
		return (bool) preg_match( '/^[a-z0-9_]{1,32}$/i', $purpose );
	}

	/**
	 * Admin-notice breadcrumb when tmp/ isn't writable. Tracked via runtime_kv
	 * so we don't re-notify for an hour.
	 */
	private static function record_unwritable(): void {
		try {
			$now = time();
			Segurium_Storage::table_upsert(
				'runtime_kv',
				array(
					'kv_key'     => 'storage:tmp_unwritable',
					'kv_value'   => '1',
					'expires_at' => $now + HOUR_IN_SECONDS,
					'updated_at' => $now,
				),
				array( 'kv_key' )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( 'Segurium: failed to record tmp_unwritable: ' . $e->getMessage() );
		}
	}
}

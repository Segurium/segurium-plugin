<?php
/**
 * Layer 3 filesystem helpers shared by the tmp and backup subsystems.
 *
 * Centralises access to the plugin data directory, guard-file installation
 * (`.htaccess` + `index.php`), path canonicalisation, and recursive deletion.
 * Callers outside `plugin/includes/storage/` must go through
 * {@see Segurium_Storage_Tmp} and {@see Segurium_Storage_Backup}; this class
 * is an internal collaborator.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Private helpers for Layer 3.
 */
class Segurium_Storage_Fs {

	const SUBDIR_TMP     = 'tmp';
	const SUBDIR_BACKUPS = 'backups';
	const SUBDIR_CACHE   = 'cache';

	const HTACCESS_GUARD  = "Deny from all\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n";
	const INDEX_PHP_GUARD = "<?php\n// Silence is golden.\n";

	/**
	 * True once {@see ensure_layout()} has created + guarded the root dirs.
	 * Keeps repeat callers on the backup_store hot path from re-statting them.
	 *
	 * @var bool
	 */
	private static $layout_ready = false;

	/**
	 * Absolute path of the plugin data directory.
	 *
	 * Lives under the uploads dir (writeable on every hosting layout WP
	 * supports) rather than wp-content/, per the wp.org reviewer's
	 * guidance that plugin data belongs in wp_upload_dir(). Kept aligned
	 * with Segurium::get_data_dir() — moved here so storage code never
	 * depends on the main plugin class.
	 */
	public static function data_dir(): string {
		$upload_dir = wp_upload_dir();
		$basedir    = $upload_dir['basedir'] ?? '';
		return $basedir . '/segurium-data';
	}

	/** Absolute path of the ephemeral workspace root. */
	public static function tmp_dir(): string {
		return self::data_dir() . '/' . self::SUBDIR_TMP;
	}

	/** Absolute path of the encrypted-backup root. */
	public static function backups_dir(): string {
		return self::data_dir() . '/' . self::SUBDIR_BACKUPS;
	}

	/**
	 * Absolute path of the on-disk hot-path cache (PHP-include files
	 * for IP lists etc.). Idempotent / safe to call before
	 * ensure_layout() — callers that write here MUST first ensure
	 * the directory exists.
	 */
	public static function cache_dir(): string {
		return self::data_dir() . '/' . self::SUBDIR_CACHE;
	}

	/**
	 * Create tmp/ and backups/ with guard files. Idempotent; the fast path
	 * after the first success is a single boolean check.
	 *
	 * @return bool True if everything is in place; false on I/O failure.
	 */
	public static function ensure_layout(): bool {
		if ( self::$layout_ready && is_dir( self::tmp_dir() ) && is_dir( self::backups_dir() ) ) {
			return true;
		}
		self::$layout_ready = false;
		$data               = self::data_dir();
		if ( ! self::ensure_dir( $data, 0755 ) ) {
			return false;
		}
		self::write_guards( $data );
		foreach ( array( self::tmp_dir(), self::backups_dir(), self::cache_dir() ) as $sub ) {
			if ( ! self::ensure_dir( $sub, 0755 ) ) {
				return false;
			}
			self::write_guards( $sub );
		}
		self::$layout_ready = true;
		return true;
	}

	/**
	 * Reset the ensure_layout() cache. Tests that toggle writability or
	 * wipe data_dir between cases call this so the next invocation re-stats.
	 */
	public static function reset_layout_cache(): void {
		self::$layout_ready = false;
	}

	/**
	 * Create a directory (recursive) and apply the given mode.
	 *
	 * @param string $path Absolute path.
	 * @param int    $mode Unix permission bits.
	 */
	public static function ensure_dir( string $path, int $mode ): bool {
		if ( is_dir( $path ) ) {
			return true;
		}
		if ( ! wp_mkdir_p( $path ) ) {
			Segurium_Debug::log( 'Segurium: failed to create directory ' . $path );
			return false;
		}
		@chmod( $path, $mode ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		return true;
	}

	/**
	 * Drop an `.htaccess` + `index.php` guard pair into $dir when missing.
	 *
	 * @param string $dir Directory to guard.
	 */
	public static function write_guards( string $dir ): void {
		$guards = array(
			'/.htaccess' => self::HTACCESS_GUARD,
			'/index.php' => self::INDEX_PHP_GUARD,
		);
		foreach ( $guards as $name => $content ) {
			$target = $dir . $name;
			if ( ! file_exists( $target ) ) {
				Segurium_Fs::write( $target, $content );
			}
		}
	}

	/**
	 * Check that $candidate lies within $root.
	 *
	 * Both paths are resolved with realpath when possible so a symlink cannot
	 * sneak a write outside the intended root.
	 *
	 * @param string $candidate Path to check.
	 * @param string $root      Ancestor directory.
	 */
	public static function is_under( string $candidate, string $root ): bool {
		$real_root = Segurium_Fs::realpath( $root );
		if ( false === $real_root ) {
			return false;
		}
		$real_root = rtrim( $real_root, '/\\' ) . DIRECTORY_SEPARATOR;
		$real      = Segurium_Fs::realpath( $candidate );
		if ( false === $real ) {
			// For a not-yet-existing path, compare the parent.
			$parent = Segurium_Fs::realpath( dirname( $candidate ) );
			if ( false === $parent ) {
				return false;
			}
			$real = $parent . DIRECTORY_SEPARATOR . basename( $candidate );
		}
		$real = rtrim( $real, '/\\' );
		return 0 === strpos( $real . DIRECTORY_SEPARATOR, $real_root );
	}

	/**
	 * Atomic write: fopen+fwrite to a unique `<path>.tmp.<rand>`, fflush,
	 * rename onto final path. On POSIX rename is atomic; on Windows we unlink
	 * the destination first because rename() errors when it exists.
	 *
	 * The temp name carries a random suffix so two callers writing the SAME
	 * destination concurrently never share a staging file — without it they
	 * would both open `<path>.tmp` and interleave into a torn rename source.
	 *
	 * Used by both the tmp workspace writer and the backup store, so the
	 * short-write / cleanup dance lives in one place.
	 *
	 * @param string $path Final destination.
	 * @param string $data Bytes to write.
	 */
	public static function atomic_put( string $path, string $data ): bool {
		$tmp = $path . '.tmp.' . wp_generate_password( 8, false, false );
		$fp  = Segurium_Fs::open( $tmp, 'wb' );
		if ( false === $fp ) {
			Segurium_Debug::log( 'Segurium: atomic_put: fopen failed on ' . $tmp );
			return false;
		}
		$bytes = Segurium_Fs::put( $fp, $data );
		if ( false === $bytes || strlen( $data ) !== $bytes ) {
			Segurium_Fs::close( $fp );
			Segurium_Fs::delete( $tmp );
			Segurium_Debug::log( 'Segurium: atomic_put: short write on ' . $tmp );
			return false;
		}
		fflush( $fp );
		Segurium_Fs::close( $fp );
		if ( '\\' === DIRECTORY_SEPARATOR && file_exists( $path ) ) {
			Segurium_Fs::delete( $path );
		}
		if ( ! Segurium_Fs::rename( $tmp, $path ) ) {
			Segurium_Debug::log( 'Segurium: atomic_put: rename failed ' . $tmp . ' -> ' . $path );
			Segurium_Fs::delete( $tmp );
			return false;
		}
		return true;
	}

	/**
	 * Read a file's full contents through the storage façade.
	 *
	 * Symmetric counterpart to {@see atomic_put()}: callers outside the
	 * façade (e.g. the ignore-list loader) read here instead of touching
	 * the filesystem directly, keeping all data-layer I/O in one place.
	 *
	 * @param string $path Absolute path to read.
	 * @return string|false File bytes, or false when missing/unreadable.
	 */
	public static function get_contents( string $path ) {
		return Segurium_Fs::read( $path );
	}

	/**
	 * Recursively delete a directory tree.
	 *
	 * Refuses to touch anything that isn't under {@see data_dir()}.
	 *
	 * @param string $dir Absolute path to remove.
	 * @return bool True when the tree (or a non-existent path) is gone.
	 */
	public static function recursive_delete( string $dir ): bool {
		if ( ! file_exists( $dir ) ) {
			return true;
		}
		if ( ! self::is_under( $dir, self::data_dir() ) ) {
			Segurium_Debug::log( 'Segurium: refused recursive_delete outside data_dir: ' . $dir );
			return false;
		}
		if ( is_file( $dir ) || is_link( $dir ) ) {
			return (bool) Segurium_Fs::delete( $dir );
		}
		$iter = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $iter as $entry ) {
			$path = $entry->getPathname();
			if ( $entry->isDir() && ! $entry->isLink() ) {
				Segurium_Fs::rmdir( $path );
			} else {
				Segurium_Fs::delete( $path );
			}
		}
		return Segurium_Fs::rmdir( $dir );
	}

	/**
	 * Reject relative paths that can escape their workspace.
	 *
	 * @param string $relpath Candidate relative path.
	 */
	public static function is_safe_relpath( string $relpath ): bool {
		if ( '' === $relpath ) {
			return false;
		}
		if ( '/' === $relpath[0] || '\\' === $relpath[0] ) {
			return false;
		}
		if ( preg_match( '#^[a-zA-Z]:#', $relpath ) ) {
			return false;
		}
		$parts = preg_split( '#[/\\\\]+#', $relpath );
		foreach ( $parts as $part ) {
			if ( '' === $part || '.' === $part || '..' === $part ) {
				return false;
			}
		}
		return true;
	}
}

<?php
/**
 * Centralized raw-filesystem chokepoint.
 *
 * Segurium is a malware scanner: it must read arbitrary (often hostile or
 * locked) files, write quarantine/temp data, and probe metadata on paths
 * that may vanish mid-operation. WP_Filesystem cannot do this — it needs FS
 * credentials on non-direct hosts and offers no streaming or @-silenced
 * stat — so the plugin uses the raw PHP file functions directly.
 *
 * Rather than scatter `// phpcs:ignore WordPress.WP.AlternativeFunctions`
 * and `WordPress.PHP.NoSilencedErrors` across ~25 files, every raw file
 * operation is funnelled through this one class. Two layers
 * of suppression are needed, because they are honoured by different tools:
 *   - `phpcs.xml` excludes this file from both sniffs — this covers
 *     `composer lint` (which loads the project ruleset).
 *   - each raw call below also carries an inline `// phpcs:ignore` with a
 *     per-site justification — this covers the wp.org `wp plugin check`
 *     scanner, which runs PHPCS with its OWN ruleset and never loads
 *     phpcs.xml, so the exclude-pattern alone would leave these findings
 *     visible to the WP.org reviewer.
 *
 * Each method encapsulates the error-suppression and returns a handled
 * result (false / empty), never emitting a PHP warning to the caller.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin, audited wrappers over the raw PHP filesystem functions.
 */
class Segurium_Fs {

	/**
	 * Read a whole file.
	 *
	 * @param string $path Absolute path.
	 * @return string|false Bytes, or false when missing/unreadable.
	 */
	public static function read( string $path ) {
		if ( ! is_file( $path ) || ! is_readable( $path ) ) {
			return false;
		}
		return @file_get_contents( $path );
	}

	/**
	 * Write a whole file. Truncates by default; pass FILE_APPEND / LOCK_EX
	 * via $flags for append or exclusive-lock semantics.
	 *
	 * @param string $path  Absolute path.
	 * @param string $data  Bytes to write.
	 * @param int    $flags file_put_contents() flags (FILE_APPEND, LOCK_EX).
	 * @return int|false Bytes written, or false on failure.
	 */
	public static function write( string $path, string $data, int $flags = 0 ) {
		return @file_put_contents( $path, $data, $flags ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- central FS write chokepoint; callers pass paths under wp_upload_dir()/segurium-data or a WP-root in-place repair target, never the plugin folder.
	}

	/**
	 * Stream a file through a callback in fixed-size chunks, so large or
	 * hostile files never have to be materialised whole in memory.
	 *
	 * @param string   $path     Absolute path.
	 * @param callable $on_chunk Receives each chunk (string) in order.
	 * @param int      $chunk    Chunk size in bytes.
	 * @return bool True when the whole file was read, false on open/read error.
	 */
	public static function read_stream( string $path, callable $on_chunk, int $chunk = 1048576 ): bool {
		if ( $chunk < 1 ) {
			$chunk = 1048576;
		}
		$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- streaming read handle; WP_Filesystem has no chunked read and would load a hostile/multi-GB scan target whole into memory.
		if ( false === $handle ) {
			return false;
		}
		$ok = true;
		while ( ! feof( $handle ) ) {
			$buf = fread( $handle, $chunk ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads the next fixed-size chunk from the streaming handle above; WP_Filesystem offers no streaming equivalent.
			if ( false === $buf ) {
				$ok = false;
				break;
			}
			if ( '' !== $buf ) {
				$on_chunk( $buf );
			}
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- closes the streaming read handle opened above.
		return $ok;
	}

	/**
	 * Open a file handle.
	 *
	 * @param string $path Absolute path.
	 * @param string $mode fopen() mode.
	 * @return resource|false
	 */
	public static function open( string $path, string $mode ) {
		return @fopen( $path, $mode ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- raw handle for incremental/locked writes to quarantine/temp under uploads; WP_Filesystem exposes no file-handle API.
	}

	/**
	 * Write to an open handle.
	 *
	 * @param resource $handle Open file handle.
	 * @param string   $data   Bytes to write.
	 * @return int|false Bytes written, or false on failure.
	 */
	public static function put( $handle, string $data ) {
		return fwrite( $handle, $data ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- writes to a handle from self::open(); WP_Filesystem has no handle-write API.
	}

	/**
	 * Read from an open handle.
	 *
	 * @param resource $handle Open file handle.
	 * @param int      $length Max bytes to read.
	 * @return string|false
	 */
	public static function get( $handle, int $length ) {
		return fread( $handle, $length ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reads from a handle from self::open(); WP_Filesystem has no handle-read API.
	}

	/**
	 * Close an open handle.
	 *
	 * @param resource $handle Open file handle.
	 */
	public static function close( $handle ): bool {
		return fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- closes a handle from self::open().
	}

	/**
	 * Advisory lock on an open handle.
	 *
	 * @param resource $handle Open file handle.
	 * @param int      $op     LOCK_* operation.
	 */
	public static function flock( $handle, int $op ): bool {
		return (bool) @flock( $handle, $op );
	}

	/**
	 * Delete a file.
	 *
	 * @param string $path Absolute path.
	 * @return bool True when the file was removed.
	 */
	public static function delete( string $path ): bool {
		return @unlink( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- raw unlink returns the bool the cleanup pipeline reports on; wp_delete_file() returns void and gives no success/failure signal.
	}

	/**
	 * Rename / move a path.
	 *
	 * @param string $from Source path.
	 * @param string $to   Destination path.
	 */
	public static function rename( string $from, string $to ): bool {
		return @rename( $from, $to ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- atomic rename for quarantine/temp swaps; WP_Filesystem::move() requires FS credentials unavailable during unattended scans.
	}

	/**
	 * Remove an (empty) directory.
	 *
	 * @param string $path Absolute path.
	 */
	public static function rmdir( string $path ): bool {
		return @rmdir( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- removes an emptied quarantine/temp dir and returns a bool; WP_Filesystem::rmdir() requires FS credentials unavailable during unattended scans.
	}

	/**
	 * File size in bytes.
	 *
	 * @param string $path Absolute path.
	 * @return int|false
	 */
	public static function size( string $path ) {
		return @filesize( $path );
	}

	/**
	 * Cut a file back to $size bytes and flush the change to storage.
	 *
	 * @param string $path Absolute path.
	 * @param int    $size Target length in bytes.
	 * @return bool True when the file now measures $size bytes.
	 */
	public static function truncate( string $path, int $size ): bool {
		$handle = self::open( $path, 'cb' );
		if ( false === $handle ) {
			return false;
		}
		// Same LOCK_EX the append path takes, so a truncate can never land
		// between another writer's seek and its write.
		if ( ! self::flock( $handle, LOCK_EX ) ) {
			self::close( $handle );
			return false;
		}
		$ok = ftruncate( $handle, max( 0, $size ) );
		if ( $ok ) {
			fflush( $handle );
			if ( function_exists( 'fsync' ) ) {
				fsync( $handle );
			}
		}
		self::flock( $handle, LOCK_UN );
		self::close( $handle );
		return (bool) $ok;
	}

	/**
	 * Flush a path's buffered contents to storage.
	 *
	 * @param string $path Absolute path.
	 * @return bool True when the bytes reached the device.
	 */
	public static function sync( string $path ): bool {
		if ( ! function_exists( 'fsync' ) ) {
			return false;
		}
		$handle = self::open( $path, 'cb' );
		if ( false === $handle ) {
			return false;
		}
		$ok = fsync( $handle );
		self::close( $handle );
		return (bool) $ok;
	}

	/**
	 * Filesystem stat() metadata.
	 *
	 * @param string $path Absolute path.
	 * @return array|false
	 */
	public static function stat( string $path ) {
		return @stat( $path );
	}

	/**
	 * Hash of a file's contents.
	 *
	 * @param string $algo Hash algorithm.
	 * @param string $path Absolute path.
	 * @return string|false
	 */
	public static function hash_file( string $algo, string $path ) {
		return @hash_file( $algo, $path );
	}

	/**
	 * Canonicalised absolute path.
	 *
	 * @param string $path Path to resolve.
	 * @return string|false
	 */
	public static function realpath( string $path ) {
		return @realpath( $path );
	}

	/**
	 * List directory entries (raw, includes dot entries).
	 *
	 * @param string $path Absolute path.
	 * @return array|false
	 */
	public static function scandir( string $path ) {
		return @scandir( $path );
	}

	/**
	 * Open a directory handle.
	 *
	 * @param string $path Absolute path.
	 * @return resource|false
	 */
	public static function opendir( string $path ) {
		return @opendir( $path );
	}
}

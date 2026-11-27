<?php
/**
 * Encrypted backups of entire plugin/theme components.
 *
 * A component (plugin or theme) is packed into an uncompressed tar with
 * PHP's bundled PharData (no shell, no external `tar` binary, so it works
 * on hosts where shell execution is disabled), size-gated, then handed to the
 * Layer-3 backup store which gzips + AES-256-GCM-encrypts it into the
 * `component` bucket.
 *
 * Fidelity note: PharData archives regular files only. Symlinks and empty
 * directories within a component are not preserved (a symlink whose target
 * escapes the component dir makes the backup fail safe — the destructive
 * delete is then skipped). This is acceptable for WordPress plugin/theme
 * trees, which are plain file sets.
 *
 * Size gate — we cap the uncompressed tar at 100 MB because that is the
 * peak memory footprint during encryption. Larger components are refused
 * with a `too_large` WP_Error so we never silently OOM the site.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encrypt-before-delete helper for component-wide backups.
 */
class Segurium_Component_Backup {

	const BUCKET                = 'component';
	const DEFAULT_MAX_TAR_BYTES = 104857600; // 100 MB — gate on uncompressed tar size.
	const GZIP_SPEED_LEVEL      = 1;         // Ratio traded for throughput; encryption dominates CPU anyway.

	// PharData exception texts on PHP 7.4 to 8.3. Quoted paths come from the component, so only the fixed parts match.
	const PACK_ERROR_PATTERNS = array(
		'backup_name_too_long'   => '/^tar-based phar ".*" cannot be created, filename ".*" is too long for tar file format\z/s',
		'backup_symlink_escape'  => '/^Iterator \S+ returned a path ".*" that is not in the base directory "/s',
		'backup_unreadable_file' => '/^Iterator \S+ returned a file that could not be opened "|^RecursiveDirectoryIterator::__construct\(.*\): failed to open dir/is',
		'backup_tmp_unwritable'  => '/^unable to open new phar "|^Cannot create phar \'.*\', file extension \(or combination\) not recognised or the directory does not exist\z/s',
		'backup_write_failed'    => '/^tar-based phar ".*" cannot be created, (contents of|header for) file ".*" could not be written\z|^unable to create temporary file\z/s',
	);

	/**
	 * Pack + encrypt a component directory into the `component` bucket.
	 *
	 * @param string $type     Component type: 'plugin' or 'theme'.
	 * @param string $slug     Component slug.
	 * @param string $abs_path Absolute path to the component directory.
	 * @return array|WP_Error  On success: `[backup_id, path, size]`. `path` points at
	 *                         the encrypted `.sgbk` envelope, never a plaintext archive.
	 */
	public function create( $type, $slug, $abs_path ) {
		if ( ! is_string( $abs_path ) || ! is_dir( $abs_path ) ) {
			return new WP_Error( 'not_found', __( 'Component directory not found.', 'segurium' ) );
		}
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			return new WP_Error( 'invalid_type', __( 'Invalid component type.', 'segurium' ) );
		}
		if ( ! is_string( $slug ) || '' === $slug ) {
			return new WP_Error( 'invalid_slug', __( 'Invalid component slug.', 'segurium' ) );
		}
		if ( ! class_exists( 'PharData' ) ) {
			return new WP_Error( 'phar_unavailable', __( 'The PHP Phar extension is required for component backups.', 'segurium' ) );
		}

		$tar_path = self::allocate_tmp_path( 'tar' );
		if ( is_wp_error( $tar_path ) ) {
			return $tar_path;
		}

		// Pack the component into an uncompressed tar with PharData (no shell,
		// no external `tar` binary). Entries are stored relative to the
		// component root; restore() extracts straight back into the target.
		try {
			$archive = new PharData( $tar_path );
			$archive->buildFromDirectory( $abs_path );
			unset( $archive );
		} catch ( Exception $e ) {
			Segurium_Fs::delete( $tar_path );
			return new WP_Error(
				$this->failure_code( $e->getMessage(), $abs_path, dirname( $tar_path ) ),
				sprintf(
					/* translators: %s: underlying error message. */
					__( 'Backup failed: %s', 'segurium' ),
					$e->getMessage()
				)
			);
		}

		if ( ! file_exists( $tar_path ) ) {
			// PharData writes nothing for a component that contains no files
			// (empty dir, or only empty sub-dirs). Emit a valid empty tar —
			// two 512-byte zero blocks — so the encrypt/store pipeline and a
			// later PharData restore still round-trip an empty component.
			if ( ! Segurium_Storage_Fs::atomic_put( $tar_path, str_repeat( "\0", 1024 ) ) ) {
				return new WP_Error( 'backup_empty_write_failed', __( 'Backup archive was not created.', 'segurium' ) );
			}
		}

		$tar_size = (int) Segurium_Fs::size( $tar_path );
		$cap      = self::max_tar_bytes();
		if ( $tar_size > $cap ) {
			Segurium_Fs::delete( $tar_path );
			return new WP_Error(
				'too_large',
				sprintf(
					/* translators: 1: component size in MB, 2: cap in MB. */
					__( 'Component is %1$.1f MB, which exceeds the %2$d MB encrypted-backup limit. Delete skipped so your site does not lose uncovered data.', 'segurium' ),
					$tar_size / 1048576,
					(int) round( $cap / 1048576 )
				),
				array(
					'tar_bytes' => $tar_size,
					'max_bytes' => $cap,
				)
			);
		}

		$payload = Segurium_Fs::read( $tar_path );
		Segurium_Fs::delete( $tar_path );

		if ( false === $payload ) {
			return new WP_Error( 'read_failed', __( 'Failed to read packed component archive.', 'segurium' ) );
		}

		try {
			$backup_id = Segurium_Storage::backup_store(
				self::BUCKET,
				$type . '/' . $slug,
				$payload,
				array(
					'component_type' => $type,
					'component_slug' => $slug,
					'tar_bytes'      => $tar_size,
					'archive_format' => 'tar',
					'action'         => 'component_deleted',
				),
				self::GZIP_SPEED_LEVEL
			);
		} catch ( Segurium_Storage_Exception $e ) {
			return new WP_Error(
				'encrypt_failed',
				sprintf(
					/* translators: %s: underlying error message. */
					__( 'Failed to encrypt component backup: %s', 'segurium' ),
					$e->getMessage()
				)
			);
		}

		$sgbk_path = Segurium_Storage_Backup::file_path( self::BUCKET, $backup_id );

		return array(
			'backup_id' => $backup_id,
			'path'      => $sgbk_path,
			'size'      => file_exists( $sgbk_path ) ? (int) Segurium_Fs::size( $sgbk_path ) : 0,
		);
	}

	/**
	 * Decrypt an archive and extract it to $restore_to's parent directory.
	 *
	 * @param string $backup_id  Identifier returned by {@see create()}.
	 * @param string $restore_to Absolute path where the component should reappear.
	 * @return true|WP_Error
	 */
	public function restore( $backup_id, $restore_to ) {
		if ( ! is_string( $backup_id ) || '' === $backup_id ) {
			return new WP_Error( 'invalid_backup_id', __( 'Invalid backup identifier.', 'segurium' ) );
		}
		if ( ! class_exists( 'PharData' ) ) {
			return new WP_Error( 'phar_unavailable', __( 'The PHP Phar extension is required for component backups.', 'segurium' ) );
		}

		$plaintext = Segurium_Storage::backup_restore( self::BUCKET, $backup_id );
		if ( null === $plaintext ) {
			return new WP_Error(
				'backup_not_found',
				__( 'Backup archive not found or failed integrity check.', 'segurium' )
			);
		}

		$tar_path = self::allocate_tmp_path( 'tar' );
		if ( is_wp_error( $tar_path ) ) {
			return $tar_path;
		}
		// Stage via the shared atomic writer: the short-lived tar lands in
		// wp_upload_dir()/segurium-data/tmp (allocate_tmp_path), never the
		// plugin folder, and is removed before return.
		if ( ! Segurium_Storage_Fs::atomic_put( $tar_path, $plaintext ) ) {
			Segurium_Fs::delete( $tar_path );
			return new WP_Error( 'write_failed', __( 'Failed to stage backup for extraction.', 'segurium' ) );
		}

		if ( ! is_dir( $restore_to ) && ! wp_mkdir_p( $restore_to ) ) {
			Segurium_Fs::delete( $tar_path );
			return new WP_Error( 'mkdir_failed', __( 'Restore target directory is not writable.', 'segurium' ) );
		}

		// Extract straight into the component directory (entries were stored
		// relative to the component root at create() time). overwrite=true so
		// a partial leftover from a failed attempt does not block the restore.
		try {
			$archive = new PharData( $tar_path );
			$archive->extractTo( $restore_to, null, true );
			unset( $archive );
		} catch ( Exception $e ) {
			Segurium_Fs::delete( $tar_path );
			return new WP_Error(
				'restore_failed',
				sprintf(
					/* translators: %s: underlying error message. */
					__( 'Restore failed: %s', 'segurium' ),
					$e->getMessage()
				)
			);
		}

		Segurium_Fs::delete( $tar_path );

		return true;
	}

	/**
	 * Map a PharData exception text to a backup error code. A failed write is
	 * disk_full when a temp filesystem lacks room: PharData holds two plaintext
	 * copies in sys_temp_dir at once before it writes the tar.
	 *
	 * @param string $message  Exception message.
	 * @param string $abs_path Component directory.
	 * @param string $tar_dir  Directory the tar was written to.
	 */
	protected function failure_code( string $message, string $abs_path, string $tar_dir ): string {
		$code = 'backup_failed';
		foreach ( self::PACK_ERROR_PATTERNS as $candidate => $pattern ) {
			if ( preg_match( $pattern, $message ) ) {
				$code = $candidate;
				break;
			}
		}
		if ( 'backup_write_failed' !== $code ) {
			return $code;
		}
		$bytes = 0;
		try {
			$files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $abs_path, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $files as $file ) {
				if ( $file->isFile() && ! $file->isLink() ) {
					$bytes += (int) $file->getSize();
				}
			}
		} catch ( Exception $e ) {
			Segurium_Debug::log( '[segurium] component backup size walk failed: ' . $e->getMessage() );
			return $code;
		}
		$checks = array(
			array( sys_get_temp_dir(), 2 * $bytes ),
			array( $tar_dir, $bytes ),
		);
		foreach ( $checks as $check ) {
			$free = $this->free_bytes( $check[0] );
			if ( null !== $free && $free < $check[1] ) {
				return 'backup_disk_full';
			}
		}
		return $code;
	}

	/**
	 * Free bytes on the filesystem that holds $dir, or null when the host does not report it.
	 *
	 * @param string $dir Directory to measure.
	 */
	protected function free_bytes( string $dir ) {
		if ( ! function_exists( 'disk_free_space' ) ) {
			return null;
		}
		$free = disk_free_space( $dir );
		return false === $free ? null : (float) $free;
	}

	/**
	 * Effective size cap. Tests override via the `segurium_component_backup_max_bytes`
	 * filter so they don't have to allocate 100 MB of fixture data.
	 */
	private static function max_tar_bytes(): int {
		$cap = (int) apply_filters( 'segurium_component_backup_max_bytes', self::DEFAULT_MAX_TAR_BYTES );
		return $cap > 0 ? $cap : self::DEFAULT_MAX_TAR_BYTES;
	}

	/**
	 * Reserve a unique temp path for the tar intermediate.
	 *
	 * Uses the Layer-3 tmp workspace when available (uploads/segurium-data/tmp)
	 * so it shares the plugin's cleanup semantics, falling back to the system
	 * tmpdir when storage layout init failed.
	 *
	 * @param string $ext File extension (no leading dot).
	 * @return string|WP_Error
	 */
	private static function allocate_tmp_path( string $ext ) {
		try {
			$random = bin2hex( random_bytes( 8 ) );
		} catch ( Exception $e ) {
			return new WP_Error( 'random_bytes_failed', __( 'Secure randomness is unavailable on this host.', 'segurium' ) );
		}

		$base = '';
		if ( class_exists( 'Segurium_Storage_Fs' ) && Segurium_Storage_Fs::ensure_layout() ) {
			$base = Segurium_Storage_Fs::tmp_dir();
		}
		if ( '' === $base || ! is_dir( $base ) ) {
			$base = rtrim( sys_get_temp_dir(), '/\\' );
		}

		return $base . '/segurium-component-' . $random . '.' . $ext;
	}
}

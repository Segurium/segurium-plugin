<?php
/**
 * Encrypted backups of entire plugin/theme components.
 *
 * A component (plugin or theme) is packed into an uncompressed tar with
 * PHP's bundled PharData (no shell, no external `tar` binary, so it works
 * on hosts where shell execution is disabled), size-gated, then handed to the
 * Layer-3 backup store which gzips + AES-256-GCM-encrypts it into the
 * `component` bucket. The plaintext tar only ever lives in a short-lived
 * temp file under `segurium-data/tmp/`; it is removed before `create()`
 * returns.
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
				'backup_failed',
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
				return new WP_Error( 'backup_failed', __( 'Backup archive was not created.', 'segurium' ) );
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

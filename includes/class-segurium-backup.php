<?php
/**
 * Legacy malware-cleanup backup wrapper.
 *
 * Stage 4 storage redesign: backups are now owned by the `malware` bucket of
 * the Segurium_Storage façade (gzip + AES-256-GCM envelope, sidecar metadata,
 * rotation). This class is kept as a thin adapter so the existing admin AJAX
 * handlers can call `Segurium_Backup::backup_file()` etc. without being rewritten.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin adapter around Segurium_Storage backup bucket 'malware'.
 */
class Segurium_Backup {

	const BUCKET = 'malware';
	const TTL    = 2592000; // 30 days (soft — rotation enforces caps).

	/**
	 * Constructor kept for callers that still pass $data_dir. Unused now.
	 *
	 * @param string $data_dir Plugin data directory.
	 */
	public function __construct( $data_dir = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		unset( $data_dir );
	}

	/**
	 * Create an encrypted backup of a file inside the `malware` bucket.
	 *
	 * @param string $file_path Absolute path to the file.
	 * @param string $sha256    SHA-256 hash of the file.
	 * @param mixed  $verdict   CTI verdict value.
	 * @param string $action    Action taken (e.g. 'cleaned').
	 * @param string $scan_id   Optional scan identifier.
	 * @return string|false Backup ID or false on failure.
	 */
	public function backup_file( $file_path, $sha256, $verdict, $action, $scan_id = '' ) {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return false;
		}
		$content = Segurium_Fs::read( $file_path );
		if ( false === $content ) {
			return false;
		}
		try {
			return Segurium_Storage::backup_store(
				self::BUCKET,
				$file_path,
				$content,
				array(
					'original_path' => $file_path,
					'sha256'        => (string) $sha256,
					'verdict'       => $verdict,
					'action'        => (string) $action,
					'scan_id'       => (string) $scan_id,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-backup] store failed: ' . $e->getMessage() );
			return false;
		}
	}

	/**
	 * Restore a file from its encrypted backup and write it back to disk.
	 *
	 * @param string $backup_id Backup identifier.
	 * @return bool
	 */
	public function restore_file( $backup_id ) {
		$meta = $this->find_meta( $backup_id );
		if ( null === $meta ) {
			return false;
		}
		$content = Segurium_Storage::backup_restore( self::BUCKET, (string) $backup_id );
		if ( null === $content ) {
			return false;
		}
		$target = isset( $meta['original_path'] ) ? (string) $meta['original_path'] : '';
		if ( '' === $target ) {
			return false;
		}
		$dir = dirname( $target );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		// In-place restore to the file's recorded original_path; the original file IS the destination, never the plugin folder.
		return false !== Segurium_Fs::write( $target, $content );
	}

	/**
	 * Flag a backup as restored. Backup metadata is append-only in the new
	 * store, so we persist the annotation through scan_findings
	 * (status='restored') rather than mutating the sidecar.
	 *
	 * @param string $backup_id Backup identifier.
	 * @return bool
	 */
	public function mark_restored( $backup_id ) {
		$meta = $this->find_meta( $backup_id );
		if ( null === $meta ) {
			return false;
		}
		return true;
	}

	/**
	 * Return the decrypted plaintext of a backup.
	 *
	 * @param string $backup_id Backup identifier.
	 * @return string|false
	 */
	public function get_content( $backup_id ) {
		$content = Segurium_Storage::backup_restore( self::BUCKET, (string) $backup_id );
		return null === $content ? false : $content;
	}

	/**
	 * Trigger a rotation sweep of the malware bucket.
	 *
	 * @return int Number of backups removed by the sweep.
	 */
	public function cleanup_expired() {
		return Segurium_Storage::backup_rotate( self::BUCKET );
	}

	/**
	 * Return every backup sidecar in the malware bucket, shaped like the
	 * legacy manifest rows the admin UI expects.
	 *
	 * @return array
	 */
	public function get_backups() {
		$metas   = Segurium_Storage::backup_list( self::BUCKET );
		$entries = array();
		foreach ( $metas as $meta ) {
			$entries[] = $this->shape_entry( $meta );
		}
		return $entries;
	}

	/**
	 * Locate a single meta entry by id.
	 *
	 * @param string $backup_id Backup identifier.
	 * @return array|null
	 */
	private function find_meta( $backup_id ) {
		foreach ( Segurium_Storage::backup_list( self::BUCKET ) as $meta ) {
			if ( ( $meta['backup_id'] ?? '' ) === (string) $backup_id ) {
				return $meta;
			}
		}
		return null;
	}

	/**
	 * Shape a raw meta dict into the admin-UI compatible row.
	 *
	 * @param array $meta Raw sidecar metadata.
	 * @return array
	 */
	private function shape_entry( array $meta ) {
		$ts        = isset( $meta['created_at'] ) ? (int) $meta['created_at'] : 0;
		$backup_id = isset( $meta['backup_id'] ) ? (string) $meta['backup_id'] : '';
		return array(
			'id'            => $backup_id,
			'original_path' => isset( $meta['original_path'] ) ? (string) $meta['original_path'] : (string) ( $meta['ref'] ?? '' ),
			'sha256'        => isset( $meta['sha256'] ) ? (string) $meta['sha256'] : '',
			'backup_file'   => $backup_id . '.sgbk',
			'action'        => isset( $meta['action'] ) ? (string) $meta['action'] : '',
			'verdict'       => $meta['verdict'] ?? 0,
			'timestamp'     => $ts,
			'expires_at'    => $ts > 0 ? $ts + self::TTL : 0,
			'scan_id'       => isset( $meta['scan_id'] ) ? (string) $meta['scan_id'] : '',
			'restored_at'   => null,
		);
	}
}

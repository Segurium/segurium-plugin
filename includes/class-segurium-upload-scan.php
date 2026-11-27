<?php
/**
 * Upload scan handler for the Segurium security plugin.
 *
 * Stage 4 storage redesign: uploads that survive media-library inspection
 * (or are blocked by it) are logged to the scan_history table rather than
 * appended to the retired scan-history JSON file.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scans uploaded files for malware before they are saved to the media library.
 */
class Segurium_Upload_Scan {

	/**
	 * Absolute path to the plugin data directory.
	 *
	 * @var string
	 */
	private $data_dir;

	/**
	 * Constructor.
	 *
	 * @param string $data_dir Absolute path to plugin data directory.
	 */
	public function __construct( $data_dir ) {
		$this->data_dir = $data_dir;
	}

	/**
	 * Inspect an uploaded file for malware and block it if a threat is detected.
	 *
	 * @param array $upload Upload data array from WordPress.
	 * @return array Modified upload data, or error if malware found.
	 */
	public function handle_upload( $upload ) {
		if ( ! isset( $upload['file'] ) || ! file_exists( $upload['file'] ) ) {
			return $upload;
		}

		$file_path = $upload['file'];
		$sha256    = Segurium_Fs::hash_file( 'sha256', $file_path );
		if ( false === $sha256 ) {
			return $upload;
		}

		$stat      = Segurium_Fs::stat( $file_path );
		$rel_path  = str_replace( Segurium_Path_Helpers::wp_root(), '', $file_path );
		$scan_id   = wp_generate_uuid4();
		$now       = time();
		$installer = $this->is_installer_upload( $file_path );

		$stats = Segurium_Verdict_Queue::resolve_and_record(
			$scan_id,
			'upload',
			array(
				array(
					'path'   => $rel_path,
					'sha256' => $sha256,
					'size'   => $stat ? $stat['size'] : 0,
					'mtime'  => $stat ? $stat['mtime'] : 0,
				),
			),
			$installer ? '' : rtrim( Segurium_Path_Helpers::wp_root(), '/' )
		);

		// The queue counts an unknown hash it was told not to escalate as
		// failed; only a missing lookup verdict lands in failed_paths.
		$failed  = (int) $stats['failed'];
		$skipped = (int) $stats['neoray_skipped'];
		if ( $installer ) {
			$unresolved = $failed - count( $stats['failed_paths'] );
			$skipped   += $unresolved;
			$failed    -= $unresolved;
		}
		$this->record_scan( $scan_id, $now, $skipped, $failed );

		if ( (int) $stats['threats'] > 0 ) {
			Segurium_Fs::delete( $file_path );

			try {
				Segurium_Storage::cti_send_message(
					'upload_blocked',
					wp_json_encode(
						array(
							'scan_id' => $scan_id,
							'sha256'  => $sha256,
							'path'    => $rel_path,
						)
					)
				);
			} catch ( Throwable $e ) {
				Segurium_Debug::log( '[segurium-upload-scan] upload_blocked_message_failed: ' . get_class( $e ) . ': ' . $e->getMessage() );
			}

			return array(
				'error' => __( 'This file was identified as malware and has been blocked.', 'segurium' ),
			);
		}

		return $upload;
	}

	/**
	 * Whether the plugin or theme installer posted this ZIP. The install
	 * scan checks every file it unpacks, so the archive gets the hash
	 * lookup only and its body never goes to the deep scan.
	 *
	 * @param string $file_path Absolute path of the stored upload.
	 * @return bool
	 */
	private function is_installer_upload( $file_path ) {
		global $pagenow, $action;
		return isset( $pagenow, $action )
			&& 'update.php' === $pagenow
			&& in_array( $action, array( 'upload-plugin', 'upload-theme' ), true )
			&& 'zip' === strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
	}

	/**
	 * Record the upload scan into scan_history. Findings are written by
	 * {@see Segurium_Verdict_Queue::resolve_and_record} directly.
	 *
	 * @param string $scan_id       Scan UUID.
	 * @param int    $now           Current Unix timestamp.
	 * @param int    $files_skipped 1 when policy left an unknown hash
	 *                              unresolved: on-premise, or an installer ZIP.
	 * @param int    $files_failed  1 when the lookup or the deep scan failed.
	 * @return void
	 */
	private function record_scan( $scan_id, $now, $files_skipped = 0, $files_failed = 0 ) {
		try {
			Segurium_Storage::table_insert(
				'scan_history',
				array(
					'scan_uuid'      => (string) $scan_id,
					'scan_type'      => 'upload',
					'status'         => 'completed',
					'started_at'     => (int) $now,
					'finished_at'    => (int) $now,
					'files_scanned'  => 1,
					'files_skipped'  => (int) $files_skipped,
					'files_failed'   => (int) $files_failed,
					'trigger_source' => 'upload',
					'error_code'     => null,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-upload-scan] history insert failed: ' . $e->getMessage() );
		}
	}
}

<?php
/**
 * Geo database updater via the CTI service.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Downloads and installs geo-IP database updates from the CTI service.
 */
class Segurium_Geo_Updater {

	const CRON_HOOK       = 'segurium_geo_db_update';
	const RETRY_CRON_HOOK = 'segurium_geo_db_retry';

	/**
	 * Path to the plugin data directory.
	 *
	 * @var string
	 */
	private $data_dir;

	/**
	 * Constructor.
	 *
	 * @param string $data_dir Path to the plugin data directory.
	 */
	public function __construct( $data_dir ) {
		$this->data_dir = rtrim( $data_dir, '/' );
	}

	/**
	 * Schedule the daily geo database update cron event.
	 *
	 * @return void
	 */
	public static function schedule() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Remove the daily geo database update cron event.
	 *
	 * @return void
	 */
	public static function unschedule() {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}

	/**
	 * Schedule a one-time retry for a failed update.
	 *
	 * @return void
	 */
	public static function schedule_retry() {
		if ( ! wp_next_scheduled( self::RETRY_CRON_HOOK ) ) {
			wp_schedule_single_event( time() + 4 * HOUR_IN_SECONDS, self::RETRY_CRON_HOOK );
		}
	}

	/**
	 * Clear any scheduled retry event.
	 *
	 * @return void
	 */
	public static function unschedule_retry() {
		wp_clear_scheduled_hook( self::RETRY_CRON_HOOK );
	}

	/**
	 * Download geo DB from the CTI server and atomically replace the local copy.
	 *
	 * @return true|WP_Error
	 */
	public function trigger_update() {
		$geo_dir  = $this->data_dir . '/geo';
		$tmp_path = $geo_dir . '/geo.bin.tmp';
		$dst_path = $geo_dir . '/geo.bin';

		if ( ! is_dir( $geo_dir ) ) {
			wp_mkdir_p( $geo_dir );
		}

		$etag    = Segurium_Storage::setting_get_string( 'segurium_geo_etag' );
		$headers = array();
		if ( '' !== $etag ) {
			$headers['If-None-Match'] = $etag;
		}
		$iid = Segurium_IID::get_iid();
		if ( $iid ) {
			$headers['X-Segurium-IID'] = $iid;
		}

		// CTI listens on TCP/8901 — see Segurium_CTI_Client class docblock for why wp_safe_remote_* cannot be used here.
		$response = wp_remote_get(
			Segurium_Storage::cti_endpoint( 'geo_db' ),
			array(
				'headers' => $headers,
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );

		if ( 304 === $code ) {
			// A successful conditional GET means the local copy is still
			// authoritative; bump the freshness stamp so the status sidebar
			// reflects "checked today", not the date of the last full body.
			Segurium_Storage::setting_set( 'segurium_geo_updated_at', time() );
			return true;
		}

		if ( 200 !== $code ) {
			return new WP_Error( 'geo_db_http_error', 'Geo DB endpoint returned HTTP ' . $code );
		}

		// SEGURIUM-192: refuse a MITM-tampered geo DB blob before we
		// persist it. Ed25519 signature covers the whole response body;
		// the magic-byte check below is still useful because a CTI-side
		// bug could serve a structurally-invalid but authentically-
		// signed blob, and we'd rather fail cleanly than corrupt the
		// on-disk DB.
		$verified = Segurium_CTI_Signature::verify_response( $response, 'geo/db' );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}

		$body = wp_remote_retrieve_body( $response );

		if ( Segurium_Geo_DB::MAGIC !== substr( $body, 0, 4 ) ) {
			return new WP_Error( 'geo_db_invalid', __( 'Downloaded geo DB has invalid format.', 'segurium' ) );
		}

		if ( false === Segurium_Fs::write( $tmp_path, $body ) ) {
			return new WP_Error( 'geo_db_write_error', __( 'Failed to write geo DB to disk.', 'segurium' ) );
		}

		if ( ! Segurium_Fs::rename( $tmp_path, $dst_path ) ) {
			Segurium_Fs::delete( $tmp_path );
			return new WP_Error( 'geo_db_rename_error', __( 'Failed to install geo DB.', 'segurium' ) );
		}

		$new_etag = wp_remote_retrieve_header( $response, 'etag' );
		if ( $new_etag ) {
			Segurium_Storage::setting_set( 'segurium_geo_etag', $new_etag );
		}
		Segurium_Storage::setting_set( 'segurium_geo_updated_at', time() );

		// Reset open file handle so next lookup re-opens the new file.
		Segurium_Geo_DB::set_db_path( null );

		return true;
	}

	/**
	 * Get the current status of the local geo database file.
	 *
	 * @return array Database status including path, existence, size, and metadata.
	 */
	public function get_db_status() {
		$path   = $this->data_dir . '/geo/geo.bin';
		$exists = file_exists( $path );
		return array(
			'path'       => $path,
			'exists'     => $exists,
			'size'       => $exists ? Segurium_Fs::size( $path ) : null,
			'updated_at' => Segurium_Storage::setting_get_int( 'segurium_geo_updated_at' ) > 0 ? Segurium_Storage::setting_get_int( 'segurium_geo_updated_at' ) : null,
			'etag'       => '' !== Segurium_Storage::setting_get_string( 'segurium_geo_etag' ) ? Segurium_Storage::setting_get_string( 'segurium_geo_etag' ) : null,
		);
	}
}

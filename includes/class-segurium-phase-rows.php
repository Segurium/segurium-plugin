<?php
/**
 * Phase rows on the Scanner tab.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Answers the newest run row, which the phase rows show.
 */
class Segurium_Phase_Rows {

	const THREATS_KEY = 'threats_found';

	/**
	 * Singleton instance.
	 *
	 * @var Segurium_Phase_Rows|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return Segurium_Phase_Rows
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire all hooks. Called once at plugin load.
	 *
	 * @return void
	 */
	public function register() {
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ), 20 );
	}

	/**
	 * Enqueue the script that adds the rows to the Scanner tab.
	 *
	 * @param string $hook Current admin page hook suffix.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( 'toplevel_page_segurium' !== $hook ) {
			return;
		}
		wp_enqueue_style(
			'segurium-phase-rows',
			SEGURIUM_PLUGIN_URL . 'assets/css/segurium-phase-rows.css',
			array( 'segurium-admin' ),
			$this->asset_version( SEGURIUM_PLUGIN_DIR . 'assets/css/segurium-phase-rows.css' )
		);
		wp_enqueue_script(
			'segurium-phase-rows',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-phase-rows.js',
			array( 'segurium-scan' ),
			$this->asset_version( SEGURIUM_PLUGIN_DIR . 'assets/js/segurium-phase-rows.js' ),
			true
		);
		wp_localize_script(
			'segurium-phase-rows',
			'seguriumPhaseRows',
			array(
				'phaseLabels' => array(
					'files'      => __( 'Files', 'segurium' ),
					'integrity'  => __( 'Integrity', 'segurium' ),
					'cron'       => __( 'Cron jobs', 'segurium' ),
					'database'   => __( 'Database', 'segurium' ),
					'self_check' => __( 'Self-Check', 'segurium' ),
				),
				'stateLabels' => array(
					Segurium_Scan_Run::PHASE_PENDING   => __( 'Waiting', 'segurium' ),
					Segurium_Scan_Run::PHASE_RUNNING   => __( 'Running', 'segurium' ),
					Segurium_Scan_Run::PHASE_DONE      => __( 'Done', 'segurium' ),
					Segurium_Scan_Run::PHASE_FAILED    => __( 'Failed', 'segurium' ),
					Segurium_Scan_Run::PHASE_SKIPPED   => __( 'Skipped', 'segurium' ),
					Segurium_Scan_Run::PHASE_CANCELLED => __( 'Cancelled', 'segurium' ),
				),
				'threatsKey'  => self::THREATS_KEY,
			)
		);
	}

	/**
	 * Cache-busting asset version: SEGURIUM_VERSION + file mtime.
	 *
	 * @param string $abs_path Absolute path to the asset.
	 * @return string
	 */
	private function asset_version( $abs_path ) {
		$version = defined( 'SEGURIUM_VERSION' ) ? SEGURIUM_VERSION : '0';
		return file_exists( $abs_path ) ? $version . '.' . filemtime( $abs_path ) : $version;
	}

	/**
	 * AJAX handler: the newest run row, running or over.
	 *
	 * @return void
	 */
	public function ajax_status() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			$this->refuse_unauthorized();
			return;
		}

		try {
			$run = $this->newest_run();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( sprintf( '[segurium-phase-rows] run read threw %s: %s', get_class( $e ), $e->getMessage() ) );
			segurium_send_json_error(
				array(
					'code'    => 'run_read_failed',
					/* translators: %s: error code */
					'message' => sprintf( __( 'Unexpected error: %s', 'segurium' ), 'run_read_failed' ),
				)
			);
			return;
		}

		segurium_send_json_success( array( 'run' => $run ) );
	}

	/**
	 * Answer a caller that may not manage scans.
	 *
	 * @return void
	 */
	private function refuse_unauthorized() {
		segurium_send_json_error(
			array(
				'code'    => 'unauthorized',
				'message' => __( 'You do not have permission to manage scans.', 'segurium' ),
			),
			403
		);
	}

	/**
	 * Read the newest run row.
	 *
	 * @return array|null Null when no run row exists.
	 * @throws Segurium_Storage_Exception When the read fails.
	 */
	private function newest_run() {
		global $wpdb;
		$wpdb->last_error = '';
		$run_id           = Segurium_Storage::table_get_var(
			'scan_runs',
			'SELECT run_uuid FROM {{table}} ORDER BY started_at DESC, id DESC LIMIT 1'
		);
		if ( '' !== (string) $wpdb->last_error ) {
			throw new Segurium_Storage_Exception( 'scan_runs read failed: ' . esc_html( $wpdb->last_error ) );
		}
		$run = null === $run_id ? null : Segurium_Scan_Run::load( $run_id );
		if ( null === $run ) {
			return null;
		}

		$phases = $run->phases();
		foreach ( $phases as $i => $phase ) {
			if ( Segurium_Scan_Phase_Cron::ID === $phase['id'] ) {
				unset( $phases[ $i ]['counters']['items'], $phases[ $i ]['counters']['uploaded'] );
			} elseif ( Segurium_Scan_Phase_Database::ID === $phase['id'] ) {
				$phases[ $i ]['counters'] = Segurium_Scan_Phase_Database::totals( (array) $phase['counters'] );
			}
		}

		$lock = Segurium_Scan_Lock::get();
		return array(
			'run_id'  => $run->run_id(),
			'trigger' => $run->trigger(),
			'status'  => $run->status(),
			'phase'   => $run->phase_id(),
			'active'  => null !== $lock && $lock['scan_id'] === $run->run_id() && Segurium_Scan_Lock::is_running( $lock ),
			'phases'  => $phases,
		);
	}
}

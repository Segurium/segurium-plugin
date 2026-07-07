<?php
/**
 * Unattended malware auto-fix orchestrator (SEGURIUM-64).
 *
 * Listens on the `segurium_scan_completed` action that every malware scan
 * (manual, real-time, scheduled) fires through Segurium_Scan_Runner. When
 * the operator has opted in, every finding with a defined cleanup recipe
 * (verdict ∈ {1, 2}) is run through the shared Segurium_Cleanup primitive,
 * skipping anything the user has explicitly ignored by path or by hash.
 * Plan-tier rate limiting is enforced inside CTI's quota service — there
 * is no local entitlement gate (SEGURIUM-341).
 *
 * Suspicious / unknown verdicts (4) are left for the human operator —
 * auto-fix is strictly malicious + injection only.
 *
 * @package Segurium
 * @since   SEGURIUM-64
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hook listener that turns scan findings into cleanup actions.
 */
final class Segurium_Auto_Fix {

	/**
	 * Action hook priority. Runs after the default state-update listener
	 * (Segurium::on_scan_completed at priority 10) so the canonical
	 * scan_findings rows are already persisted, but before scan workspace
	 * cleanup so absolute paths still resolve.
	 */
	const HOOK_PRIORITY = 15;

	/**
	 * Wire the listener. Idempotent — safe to call from the bootstrap.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'segurium_scan_completed', array( __CLASS__, 'on_scan_completed' ), self::HOOK_PRIORITY, 1 );
	}

	/**
	 * Process every cleanable finding in the just-completed scan. Bails
	 * before touching anything if the operator hasn't opted in. Plan-tier
	 * limits (Free 3/30d, Pro unbounded) are enforced inside the per-file
	 * cleanup primitive's CTI quota call, not here (SEGURIUM-341).
	 *
	 * @param mixed $scan Completed scan instance (Segurium_Scan).
	 * @return array{processed:int,cleaned:int,skipped:int,failed:int}
	 */
	public static function on_scan_completed( $scan ) {
		$summary = array(
			'processed' => 0,
			'cleaned'   => 0,
			'skipped'   => 0,
			'failed'    => 0,
		);

		if ( ! $scan instanceof Segurium_Scan ) {
			return $summary;
		}
		if ( ! Segurium_Auto_Fix_Settings::is_enabled() ) {
			return $summary;
		}

		$threats = $scan->get_threats();
		if ( empty( $threats ) ) {
			return $summary;
		}

		$base_path = (string) $scan->get_base_path();
		if ( '' === $base_path ) {
			return $summary;
		}

		$state   = $scan->get_state();
		$scan_id = isset( $state['scan_id'] ) ? (string) $state['scan_id'] : '';
		$ignore  = self::load_ignore_lists( $scan );

		foreach ( $threats as $row ) {
			++$summary['processed'];

			$verdict = isset( $row['verdict'] ) ? (int) $row['verdict'] : 0;
			if ( ! in_array( $verdict, Segurium_Cleanup::cleanable_verdicts(), true ) ) {
				++$summary['skipped'];
				continue;
			}

			$rel_path = isset( $row['path'] ) ? (string) $row['path'] : '';
			$sha256   = isset( $row['sha256'] ) ? (string) $row['sha256'] : '';
			if ( '' === $rel_path || '' === $sha256 ) {
				++$summary['skipped'];
				continue;
			}

			if ( null !== $ignore && ( $ignore->is_path_ignored( $rel_path ) || $ignore->is_hash_ignored( $rel_path, $sha256 ) ) ) {
				++$summary['skipped'];
				continue;
			}

			$abs_path = $base_path . '/' . ltrim( $rel_path, '/' );

			$result = Segurium_Cleanup::cleanup_file(
				$abs_path,
				$rel_path,
				$sha256,
				$verdict,
				$scan_id,
				Segurium_Cleanup::ACTOR_AUTO
			);

			if ( $result['ok'] ) {
				++$summary['cleaned'];
			} else {
				++$summary['failed'];
			}
		}

		// SEGURIUM-548: freeze the auto-cleanup count into scan_history so
		// later display reads return a stable "X threats, Y cleaned" line
		// regardless of subsequent manual Fix-All clicks.
		self::persist_scan_cleaned_count( $scan_id, $summary );

		return $summary;
	}

	/**
	 * SEGURIUM-548: write the auto-fix `cleaned` count into the
	 * scan_history.threats_cleaned column. No-op for empty scan_id (caller
	 * bailed before any cleanup ran).
	 *
	 * @param string $scan_id Scan UUID; empty string skips persistence.
	 * @param array  $summary Result array from on_scan_completed().
	 * @return void
	 */
	public static function persist_scan_cleaned_count( $scan_id, array $summary ) {
		if ( '' === (string) $scan_id ) {
			return;
		}
		$cleaned = isset( $summary['cleaned'] ) ? (int) $summary['cleaned'] : 0;
		try {
			Segurium_Storage::table_update(
				'scan_history',
				array( 'threats_cleaned' => $cleaned ),
				array( 'scan_uuid' => (string) $scan_id )
			);
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-auto-fix] persist threats_cleaned failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Load the path/hash ignore lists for this scan. We use the scan's own
	 * data dir (mirroring Segurium_Scan::submit_for_verdict, the only other
	 * site that consults ignore-lists during scan processing) so the
	 * exclusion scope follows the scan rather than the plugin singleton.
	 *
	 * @param Segurium_Scan $scan Completed scan.
	 * @return Segurium_Ignore_Lists|null
	 */
	private static function load_ignore_lists( $scan ) {
		if ( ! class_exists( 'Segurium_Ignore_Lists' ) ) {
			return null;
		}
		try {
			$data_dir = (string) $scan->get_data_dir();
			if ( '' === $data_dir ) {
				return null;
			}
			$ignore = new Segurium_Ignore_Lists( $data_dir );
			$ignore->load();
			return $ignore;
		} catch ( Throwable $e ) {
			return null;
		}
	}
}

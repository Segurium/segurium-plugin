<?php
/**
 * Shared malware cleanup primitive.
 *
 * Both the AJAX manual-cleanup handler (Segurium::ajax_cleanup_file) and the
 * unattended auto-fix path (Segurium_Auto_Fix) funnel through
 * this class so that backup, TOCTOU re-verification, activity-log entries
 * and the CTI `file_cleaned` notification are byte-identical regardless of
 * actor.
 *
 * Inputs are assumed already validated by the caller — the AJAX handler does
 * nonce + capability + path-resolution + Free-tier quota; the auto-fix
 * orchestrator does entitlement + setting + ignore-list. Centralising those
 * up-stream keeps this primitive a thin "do the cleanup" function.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stateless cleanup primitive shared by manual + auto-fix paths.
 */
final class Segurium_Cleanup {

	const ACTOR_MANUAL = 'manual';
	const ACTOR_AUTO   = 'auto';

	const VERDICT_MALICIOUS = 1;
	const VERDICT_INJECTION = 2;

	/**
	 * Verdict codes the plugin will hand to {@see cleanup_file()}.
	 *
	 * The malicious-vs-injection split no longer drives
	 * the *behaviour* (CTI's verdict cache decides server-side whether
	 * to serve cured bytes or an empty body), but the constants stay
	 * because callers still pass them to record what was scanned and
	 * the auto-fix orchestrator filters its threat queue with them.
	 *
	 * @return int[]
	 */
	public static function cleanable_verdicts() {
		return array( self::VERDICT_MALICIOUS, self::VERDICT_INJECTION );
	}

	/**
	 * Run the cleanup pipeline against an already-validated finding.
	 *
	 * Every cleanup goes through `/v1/cleanup` on CTI,
	 * regardless of local verdict. CTI consults its verdict cache and
	 * returns either:
	 *
	 *   - cured bytes (Injection) — written back over the file;
	 *   - an empty body (Malware) — truncates the file;
	 *   - HTTP 402 with a paywall envelope — surfaced here as
	 *     `error_code = 'paywall_quota_exceeded'`, fires
	 *     `segurium_cleanup_paywalled`, with the envelope on
	 *     the result's `paywall` field so the AJAX handler can render
	 *     the modal without a second hop;
	 *   - an `error_code` >= 4 from CTI (verdict not cached / not
	 *     cleanable) — bubbled up so the caller can refuse rather than
	 *     truncate blind.
	 *
	 * Slot accounting happens server-side as part of the cleanup hop:
	 * by the time we get here, the IID has either paid the slot or hit
	 * the cap. There is no way for the plugin to ask twice.
	 *
	 * @param string $abs_path Absolute on-disk path. The caller MUST have
	 *                         resolved this safely (e.g. through
	 *                         Segurium::resolve_abs_within_wp_root() for
	 *                         user-supplied input). Auto-fix can pass an
	 *                         ABSPATH-prefixed scan finding directly.
	 * @param string $path     Relative path stored alongside the finding.
	 *                         Used for activity-log + CTI message body.
	 * @param string $sha256   Pre-cleanup hash, as recorded in scan_findings.
	 * @param int    $verdict  One of self::VERDICT_*.
	 * @param string $scan_id  Originating scan UUID.
	 * @param string $actor    self::ACTOR_MANUAL or self::ACTOR_AUTO.
	 * @return array{ok:bool,backup_id:?string,clean_hash:?string,error:?string,error_code:?string,paywall:?array,quota:?array}
	 */
	public static function cleanup_file( $abs_path, $path, $sha256, $verdict, $scan_id, $actor ) {
		$verdict = (int) $verdict;
		$actor   = self::ACTOR_AUTO === $actor ? self::ACTOR_AUTO : self::ACTOR_MANUAL;

		if ( ! in_array( $verdict, self::cleanable_verdicts(), true ) ) {
			return self::fail( 'verdict_not_cleanable', __( 'Verdict has no defined cleanup recipe.', 'segurium' ) );
		}

		if ( ! is_string( $abs_path ) || '' === $abs_path || ! is_file( $abs_path ) ) {
			return self::fail( 'file_not_found', __( 'File not found.', 'segurium' ) );
		}

		$current_hash = Segurium_Fs::hash_file( 'sha256', $abs_path );
		if ( $current_hash !== $sha256 ) {
			return self::fail( 'hash_mismatch', __( 'File has been modified since scan. Re-scan first.', 'segurium' ) );
		}

		$original_content = Segurium_Fs::read( $abs_path );
		if ( false === $original_content ) {
			return self::fail( 'backup_read_failed', __( 'Failed to read file for backup.', 'segurium' ) );
		}

		try {
			$backup_id = Segurium_Storage::backup_store(
				'malware',
				$abs_path,
				$original_content,
				array(
					'original_path' => $abs_path,
					'sha256'        => $sha256,
					'verdict'       => $verdict,
					'action'        => 'cleaned',
					'scan_id'       => $scan_id,
					'actor'         => $actor,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			return self::fail( 'backup_store_failed', __( 'Failed to create backup.', 'segurium' ), $e );
		}

		// Ask CTI for the cleaned body. Paywall + other
		// CTI errors propagate up — we never silently truncate when
		// CTI refused or failed. Empty bytes (Malware verdict) are a
		// *successful* return: CTI confirmed nothing is salvageable
		// and charged the slot.
		// `/v1/cleanup` requires `filename` + `ctime` in
		// the JSON body for the per-attempt ClickHouse telemetry row;
		// `filectime` mirrors the field name on the wire and is the
		// closest POSIX analogue to file creation time on Linux.
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$ft      = @filectime( $abs_path );
		$ctime   = (int) ( false === $ft ? 0 : $ft );
		$fetched = Segurium_Storage::cti_fetch_cleanup_file( $sha256, (string) $path, $ctime, $original_content );
		if ( is_wp_error( $fetched ) ) {
			$code    = (string) $fetched->get_error_code();
			$data    = $fetched->get_error_data();
			$paywall = ( 'paywall_quota_exceeded' === $code && is_array( $data ) ) ? $data : null;

			if ( 'paywall_quota_exceeded' === $code ) {
				/**
				 * Fires once per cleanup the cloud refused
				 * for quota, whatever the actor. Emitted here rather than
				 * in the AJAX handlers so manual, fix-all, integrity-fix
				 * and auto-fix denials all reach listeners identically.
				 *
				 * @param string $path  Path relative to the WordPress root.
				 * @param string $actor ACTOR_MANUAL | ACTOR_AUTO.
				 */
				do_action( 'segurium_cleanup_paywalled', (string) $path, $actor );
			}

			return self::fail(
				$code,
				$fetched->get_error_message(),
				null,
				(string) $backup_id,
				$paywall
			);
		}

		// The fetch returns the cleaned bytes plus the
		// post-charge quota envelope CTI echoes in its 200 body. The
		// envelope lets the caller refresh the readout authoritatively
		// (`null` when an older CTI build omits it).
		$content    = (string) $fetched['content'];
		$quota_echo = ( isset( $fetched['quota'] ) && is_array( $fetched['quota'] ) ) ? $fetched['quota'] : null;

		// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- in-place clean: writes the cleaned bytes back over the original infected file ($abs_path), which IS the destination, never the plugin folder.
		if ( false === Segurium_Fs::write( $abs_path, $content ) ) {
			return self::fail(
				'write_failed',
				__( 'Failed to clean file.', 'segurium' ),
				null,
				(string) $backup_id
			);
		}

		$clean_hash = Segurium_Fs::hash_file( 'sha256', $abs_path );
		if ( false === $clean_hash ) {
			$clean_hash = hash( 'sha256', '' );
		}

		try {
			Segurium_Storage::backup_update_meta(
				'malware',
				(string) $backup_id,
				array( 'sha256_clean' => $clean_hash )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			self::log_exception( 'backup_update_meta', $e );
		}

		self::record_cure(
			(string) $path,
			(string) $sha256,
			(string) $backup_id,
			(string) $clean_hash,
			$actor,
			array( 'scan_id' => (string) $scan_id )
		);

		/**
		 * Fires once per successful cleanup, whatever the
		 * actor. Emitted here so manual, fix-all and auto-fix paths all
		 * reach listeners identically.
		 *
		 * @param string $path  Path relative to the WordPress root.
		 * @param string $actor ACTOR_MANUAL | ACTOR_AUTO.
		 */
		do_action( 'segurium_cleanup_succeeded', (string) $path, $actor );

		return array(
			'ok'         => true,
			'backup_id'  => (string) $backup_id,
			'clean_hash' => (string) $clean_hash,
			'error'      => null,
			'error_code' => null,
			'paywall'    => null,
			// Post-charge quota envelope echoed by CTI
			// (null on older builds — caller falls back to a local bump).
			'quota'      => $quota_echo,
		);
	}

	/**
	 * Write caller-supplied bytes over a file with the backup, history and
	 * report of {@see cleanup_file()}. An identical copy of the same path
	 * already in the bucket is reused instead of stored again.
	 *
	 * @param string     $abs_path     Absolute, already-resolved path.
	 * @param string     $path         Path relative to the WordPress root.
	 * @param string     $sha256       Hash the caller read; a file that moved on is refused.
	 * @param int        $verdict      One of self::VERDICT_*.
	 * @param string     $content      Replacement bytes; '' truncates.
	 * @param string     $actor        Actor on the backup, history row and report.
	 * @param array      $extra        Extra fields for the backup sidecar and the history row.
	 * @param array|null $backup_index Index of the bucket shared across calls; built when null.
	 * @return array{ok:bool,backup_id:?string,clean_hash:?string,error:?string,error_code:?string,paywall:?array,quota:?array}
	 */
	public static function remediate( $abs_path, $path, $sha256, $verdict, $content, $actor, array $extra = array(), &$backup_index = null ) {
		if ( ! in_array( (int) $verdict, self::cleanable_verdicts(), true ) ) {
			return self::fail( 'verdict_not_cleanable', __( 'Verdict has no defined cleanup recipe.', 'segurium' ) );
		}

		$original = Segurium_Fs::read( $abs_path );
		if ( false === $original ) {
			return self::fail( 'backup_read_failed', __( 'Failed to read file for backup.', 'segurium' ) );
		}
		if ( ! hash_equals( (string) $sha256, hash( 'sha256', $original ) ) ) {
			return self::fail( 'hash_mismatch', __( 'File has been modified since scan. Re-scan first.', 'segurium' ) );
		}

		if ( null === $backup_index ) {
			$backup_index = array();
			foreach ( Segurium_Storage::backup_list( 'malware' ) as $meta ) {
				$backup_index[ ( $meta['original_path'] ?? '' ) . '|' . ( $meta['sha256_plain'] ?? '' ) ] = (string) ( $meta['backup_id'] ?? '' );
			}
		}
		$index_key = $abs_path . '|' . $sha256;
		$backup_id = $backup_index[ $index_key ] ?? '';
		if ( '' === $backup_id || ! Segurium_Storage::backup_exists( 'malware', $backup_id ) ) {
			try {
				$backup_id = Segurium_Storage::backup_store(
					'malware',
					$abs_path,
					$original,
					array_merge(
						$extra,
						array(
							'original_path' => $abs_path,
							'sha256'        => (string) $sha256,
							'verdict'       => (int) $verdict,
							'action'        => 'cleaned',
							'actor'         => (string) $actor,
						)
					)
				);
			} catch ( Segurium_Storage_Exception $e ) {
				return self::fail( 'backup_store_failed', __( 'Failed to create backup.', 'segurium' ), $e );
			}
			$backup_index[ $index_key ] = (string) $backup_id;
		}

		// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- in-place cure: the infected file is the destination, never the plugin folder.
		if ( false === Segurium_Fs::write( $abs_path, (string) $content ) ) {
			return self::fail( 'write_failed', __( 'Failed to clean file.', 'segurium' ), null, (string) $backup_id );
		}

		$clean_hash = hash( 'sha256', (string) $content );
		try {
			Segurium_Storage::backup_update_meta( 'malware', (string) $backup_id, array( 'sha256_clean' => $clean_hash ) );
		} catch ( Segurium_Storage_Exception $e ) {
			self::log_exception( 'backup_update_meta', $e );
		}

		self::record_cure( (string) $path, (string) $sha256, (string) $backup_id, $clean_hash, (string) $actor, $extra );

		return array(
			'ok'         => true,
			'backup_id'  => (string) $backup_id,
			'clean_hash' => $clean_hash,
			'error'      => null,
			'error_code' => null,
			'paywall'    => null,
			'quota'      => null,
		);
	}

	/**
	 * Projection row, history row and `file_cleaned` report of one cure.
	 *
	 * @param string $path       Path relative to the WordPress root.
	 * @param string $sha256     Hash before the cure.
	 * @param string $backup_id  Backup of the pre-cure bytes.
	 * @param string $clean_hash Hash after the cure.
	 * @param string $actor      Who cured.
	 * @param array  $extra      Extra fields for the history row.
	 * @return void
	 */
	private static function record_cure( $path, $sha256, $backup_id, $clean_hash, $actor, array $extra ) {
		Segurium_File_State::mark_cured( $path, $backup_id, $clean_hash, time() );

		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => 'malware_cured',
					'severity'   => 2,
					'subject'    => substr( $path, 0, 191 ),
					'data_json'  => (string) wp_json_encode(
						array_merge(
							array( 'scan_id' => '' ),
							$extra,
							array(
								'path'      => $path,
								'sha256'    => $sha256,
								'backup_id' => $backup_id,
								'actor'     => $actor,
							)
						)
					),
					'created_at' => time(),
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			self::log_exception( 'activity_log', $e );
		}

		Segurium_Storage::cti_send_message(
			'file_cleaned',
			(string) wp_json_encode(
				array(
					'sha256'    => $sha256,
					'path'      => $path,
					'backup_id' => $backup_id,
					'actor'     => $actor,
				)
			)
		);
	}

	/**
	 * Build a uniformly-shaped failure result.
	 *
	 * @param string         $code      Stable machine-readable code.
	 * @param string         $message   Translated human-readable message.
	 * @param Throwable|null $exception Optional underlying exception (logged).
	 * @param string|null    $backup_id Optional backup id captured before the
	 *                                  failure point.
	 * @param array|null     $paywall   Optional `quota` envelope when the
	 *                                  failure is `paywall_quota_exceeded`.
	 * @return array{ok:bool,backup_id:?string,clean_hash:?string,error:?string,error_code:?string,paywall:?array,quota:?array}
	 */
	private static function fail( $code, $message, $exception = null, $backup_id = null, $paywall = null ) {
		if ( null !== $exception ) {
			self::log_exception( $code, $exception );
		}
		return array(
			'ok'         => false,
			'backup_id'  => null === $backup_id ? null : (string) $backup_id,
			'clean_hash' => null,
			'error'      => (string) $message,
			'error_code' => (string) $code,
			'paywall'    => $paywall,
			'quota'      => null,
		);
	}

	/**
	 * Surface a swallowed exception into PHP's error log so postmortem has
	 * something to grep. We mirror Segurium::log_runner_exception's prefix
	 * so log readers don't need to learn a second pattern.
	 *
	 * @param string    $where Short tag identifying the failing step.
	 * @param Throwable $e     Exception to log.
	 * @return void
	 */
	private static function log_exception( $where, $e ) {
		Segurium_Debug::log( '[segurium-cleanup] ' . $where . ': ' . $e->getMessage() );
	}
}

<?php
/**
 * Findings that are no file: a cron event or a database row with a bad verdict.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Table, states, cleanup, Restore and rows of the content findings.
 */
final class Segurium_Content_Findings {

	const TABLE       = 'content_findings';
	const BUCKET      = 'content';
	const AJAX_ACTION = 'segurium_content_finding';

	const STATUS_OPEN    = 'open';
	const STATUS_CURED   = 'cured';
	const STATUS_IGNORED = 'ignored';
	const STATUS_FIXED   = 'fixed';

	const ACTOR_MANUAL = 'manual';
	const ACTOR_AUTO   = 'auto';

	const PAYWALL = 'paywall_quota_exceeded';
	const BUSY    = 'finding_busy';

	const AUTO_FIX_MIN_SEC = 20;

	const LOCK_PREFIX = 'content_lock:';
	const LOCK_SEC    = 300;

	const EVENT_OPENED   = 'content_finding_opened';
	const EVENT_CURED    = 'content_cured';
	const EVENT_RESTORED = 'content_restored';
	const EVENT_IGNORED  = 'content_ignored';

	const ROW_STATES = array(
		self::STATUS_OPEN    => 'malicious',
		self::STATUS_CURED   => 'cleaned',
		self::STATUS_FIXED   => 'fixed',
		self::STATUS_IGNORED => 'ignored',
	);

	/**
	 * Kind handlers by kind, whether or not the phase of the kind runs.
	 *
	 * @return array<string, Segurium_Content_Finding_Kind>
	 */
	public static function kinds() {
		$out      = array();
		$defaults = array(
			Segurium_Cron_Finding::KIND          => new Segurium_Cron_Finding(),
			Segurium_Db_Account_Finding::KIND    => new Segurium_Db_Account_Finding(),
			Segurium_Db_Session_Finding::KIND    => new Segurium_Db_Session_Finding(),
			Segurium_Db_Script_Finding::KIND     => new Segurium_Db_Script_Finding(),
			Segurium_Db_Script_Finding::KIND_SRC => new Segurium_Db_Script_Finding( Segurium_Db_Script_Finding::KIND_SRC ),
		);
		foreach ( (array) apply_filters( 'segurium_content_finding_kinds', $defaults ) as $kind => $handler ) {
			if ( $handler instanceof Segurium_Content_Finding_Kind && $handler->kind() === $kind ) {
				$out[ (string) $kind ] = $handler;
			}
		}
		return $out;
	}

	/**
	 * Record the findings of a completed content phase, then run Auto-Fix.
	 *
	 * @param string $kind     Content kind.
	 * @param string $run_id   Run ID.
	 * @param array  $verdicts Items with a verdict, as {@see Segurium_Content_Items::verdicts()} returns them.
	 * @return void
	 */
	public static function complete_run( $kind, $run_id, array $verdicts ) {
		$handler = self::handler( (string) $kind );
		if ( null === $handler ) {
			return;
		}
		$found = $handler->detections( $verdicts );
		self::record( $handler, (string) $run_id, (array) $found['threats'], (array) $found['clean'] );
		if ( Segurium_Auto_Fix_Settings::is_enabled() ) {
			self::auto_fix( (string) $kind, (string) $run_id );
			Segurium_Cache_Invalidation::batch_finished();
		}
	}

	/**
	 * Clean one open finding: back up, verify the backup, ask the cloud, apply.
	 * One action at a time holds a finding.
	 *
	 * @param int    $id    Finding ID.
	 * @param string $actor ACTOR_MANUAL or ACTOR_AUTO.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	public static function clean( $id, $actor ) {
		$actor = self::ACTOR_AUTO === $actor ? self::ACTOR_AUTO : self::ACTOR_MANUAL;
		$fault = self::fault( self::load( (int) $id ), self::STATUS_OPEN );
		if ( '' !== $fault ) {
			return self::result( $fault );
		}
		if ( ! Segurium_Consent::given() ) {
			return self::result( 'cti_no_consent' );
		}
		$code  = '';
		$token = self::lock( (int) $id, $code );
		if ( '' === $token ) {
			return self::result( $code );
		}
		try {
			return self::clean_locked( (int) $id, $actor, $token );
		} finally {
			self::unlock( (int) $id, $token );
		}
	}

	/**
	 * Record what a handler is about to write, so a worker that dies inside
	 * the writes leaves them to be undone by the next cleanup.
	 *
	 * @param array $finding Finding as {@see Segurium_Content_Finding_Kind::apply()} got it.
	 * @param array $applied What Restore needs to undo the writes.
	 * @return bool False when the record did not stick; the handler writes nothing then.
	 */
	public static function stage( array $finding, array $applied ) {
		$detail                      = $finding['detail'];
		$detail['staged']['applied'] = $applied;
		return 0 < (int) self::update( $finding, array( 'detail' => self::encode( $detail ) ) );
	}

	/**
	 * Backups the rotation of the bucket keeps: those of cured findings and of staged cleanups.
	 *
	 * @return string[]
	 */
	public static function pinned_backups() {
		global $wpdb;
		$ids = (array) Segurium_Storage::table_get_col( self::TABLE, "SELECT DISTINCT backup_id FROM {{table}} WHERE status = 'cured' AND backup_id IS NOT NULL AND backup_id <> ''", array() );
		foreach ( (array) Segurium_Storage::table_get_col( self::TABLE, 'SELECT detail FROM {{table}} WHERE status IN (%s, %s) AND detail LIKE %s', array( self::STATUS_OPEN, self::STATUS_IGNORED, '%' . $wpdb->esc_like( '"staged":' ) . '%' ) ) as $raw ) {
			$detail = json_decode( (string) $raw, true );
			if ( isset( $detail['staged']['backup_id'] ) ) {
				$ids[] = (string) $detail['staged']['backup_id'];
			}
		}
		return array_values( array_unique( array_filter( array_map( 'strval', $ids ) ) ) );
	}

	/**
	 * The cleanup under the lock of the finding.
	 *
	 * @param int    $id    Finding ID.
	 * @param string $actor ACTOR_MANUAL or ACTOR_AUTO.
	 * @param string $token Token of the claim of the finding.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	private static function clean_locked( $id, $actor, $token ) {
		$row   = self::load( $id );
		$fault = self::fault( $row, self::STATUS_OPEN );
		if ( '' !== $fault ) {
			return self::result( $fault );
		}
		$handler      = self::handler( $row['kind'] );
		$row['actor'] = $actor;
		if ( isset( $row['detail']['staged'] ) ) {
			$undone = self::undo_staged( $handler, $row );
			$fresh  = self::load( $id );
			$row    = array( 'actor' => $actor ) + ( null === $fresh ? $row : $fresh );
			if ( '' !== $undone ) {
				return self::refuse( $row, $undone );
			}
		}
		$snapshot = $handler->snapshot( $row );
		if ( is_wp_error( $snapshot ) ) {
			return self::refuse( $row, $snapshot->get_error_code() );
		}
		try {
			$backup_id = Segurium_Storage::backup_store(
				self::BUCKET,
				$row['kind'] . ':' . $row['locator'],
				$snapshot,
				array(
					'kind'       => $row['kind'],
					'locator'    => $row['locator'],
					'sha256'     => $row['sha256'],
					'finding_id' => (int) $row['id'],
					'action'     => 'cleaned',
					'actor'      => $actor,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-content-findings] backup_store_failed: ' . $e->getMessage() );
			return self::refuse( $row, 'backup_store_failed' );
		}
		$stored = Segurium_Storage::backup_restore_detailed( self::BUCKET, $backup_id );
		if ( $stored['content'] !== $snapshot ) {
			Segurium_Storage::backup_delete( self::BUCKET, $backup_id );
			return self::refuse( $row, 'backup_verify_failed' );
		}

		$fetched = Segurium_Storage::cti_fetch_cleanup_content( $row['kind'], $row['locator'], $row['sha256'] );
		$quota   = ! is_wp_error( $fetched ) && is_array( $fetched['quota'] ) ? $fetched['quota'] : null;
		$charged = ! is_wp_error( $fetched ) || ! empty( ( (array) $fetched->get_error_data() )['served'] );
		if ( $charged && null === $quota ) {
			Segurium_Quota::instance()->record_consumed_slot();
		} elseif ( $charged ) {
			Segurium_Quota::instance()->apply_cleanup_envelope( $quota );
		}
		if ( ! is_wp_error( $fetched ) && ! self::renew( $id, $token ) ) {
			Segurium_Storage::backup_delete( self::BUCKET, $backup_id );
			Segurium_Debug::log( sprintf( '[segurium-content-findings] finding_lock_lost kind=%s id=%d: another action holds the finding', $row['kind'], $id ) );
			return self::result( 'finding_lock_lost' );
		}
		if ( is_wp_error( $fetched ) ) {
			$applied = $fetched;
		} else {
			$staged                     = $row;
			$staged['detail']['staged'] = array( 'backup_id' => $backup_id );
			$applied                    = $handler->apply( $staged, $snapshot, (string) $fetched['content'] );
		}
		if ( is_wp_error( $applied ) ) {
			$kept = ! empty( ( (array) $applied->get_error_data() )['staged'] ) ? self::load( $id ) : null;
			if ( null === $kept ) {
				Segurium_Storage::backup_delete( self::BUCKET, $backup_id );
			}
			$result = self::refuse( null === $kept ? $row : $kept, $applied->get_error_code(), $charged );
			if ( self::PAYWALL === $result['code'] ) {
				do_action( 'segurium_cleanup_paywalled', $row['locator'], $actor );
				$result['paywall'] = (array) $applied->get_error_data();
			}
			return $result;
		}
		if ( ! $handler->restorable() ) {
			Segurium_Storage::backup_delete( self::BUCKET, $backup_id );
			$backup_id = '';
		}

		$detail                 = self::without_reason( $row['detail'] );
		$detail['applied']      = (array) $applied;
		$detail['sha256_clean'] = hash( 'sha256', (string) $fetched['content'] );
		$cured                  = array(
			'status'     => self::STATUS_CURED,
			'backup_id'  => '' === $backup_id ? null : $backup_id,
			'detail'     => self::encode( $detail ),
			'updated_at' => time(),
		);
		if ( false === self::update( $row, $cured, false ) && false === self::update( $row, $cured, false ) ) {
			return self::unwind( $handler, $row, (array) $applied, $snapshot, $backup_id );
		}
		self::log(
			self::EVENT_CURED,
			$row,
			array(
				'backup_id' => $backup_id,
				'actor'     => $actor,
			)
		);
		self::report(
			'file_cleaned',
			$row,
			array(
				'backup_id' => $backup_id,
				'actor'     => $actor,
			)
		);
		do_action( 'segurium_cleanup_succeeded', $row['locator'], $actor );

		$result              = self::result( '' );
		$result['backup_id'] = $backup_id;
		$result['quota']     = $quota;
		return $result;
	}

	/**
	 * The row did not take `cured`: undo the cleanup, so the site matches the open row.
	 *
	 * @param Segurium_Content_Finding_Kind $handler   Kind handler.
	 * @param array                         $row       Finding.
	 * @param array                         $applied   What the handler wrote.
	 * @param string                        $snapshot  Backup bytes.
	 * @param string                        $backup_id Backup of the cleanup, '' when gone.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	private static function unwind( Segurium_Content_Finding_Kind $handler, array $row, array $applied, $snapshot, $backup_id ) {
		$row['detail']['applied'] = $applied;
		$undone                   = $handler->restorable() ? $handler->restore( $row, $snapshot ) : new WP_Error( 'not_restorable', 'the cleanup cannot be undone' );
		$staged                   = self::load( (int) $row['id'] );
		if ( ! is_wp_error( $undone ) && '' !== $backup_id && ! isset( $staged['detail']['staged'] ) ) {
			Segurium_Storage::backup_delete( self::BUCKET, $backup_id );
		}
		Segurium_Debug::log( sprintf( '[segurium-content-findings] finding_write_failed kind=%s id=%d: undo %s', $row['kind'], (int) $row['id'], is_wp_error( $undone ) ? $undone->get_error_code() : 'done' ) );
		return self::result( 'finding_write_failed' );
	}

	/**
	 * Put a cured finding back from its backup. The finding opens again.
	 *
	 * @param int    $id    Finding ID.
	 * @param string $actor Who asked.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	public static function restore( $id, $actor = self::ACTOR_MANUAL ) {
		$row   = self::load( (int) $id );
		$fault = self::fault( $row, self::STATUS_CURED );
		if ( '' !== $fault ) {
			return self::result( $fault );
		}
		if ( ! self::handler( $row['kind'] )->restorable() ) {
			return self::result( 'not_restorable' );
		}
		$code  = '';
		$token = self::lock( (int) $id, $code );
		if ( '' === $token ) {
			return self::result( $code );
		}
		try {
			return self::restore_locked( (int) $id, $actor );
		} finally {
			self::unlock( (int) $id, $token );
		}
	}

	/**
	 * The Restore under the lock of the finding.
	 *
	 * @param int    $id    Finding ID.
	 * @param string $actor Who asked.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	private static function restore_locked( $id, $actor ) {
		$row   = self::load( $id );
		$fault = self::fault( $row, self::STATUS_CURED );
		if ( '' !== $fault ) {
			return self::result( $fault );
		}
		$backup = Segurium_Storage::backup_restore_detailed( self::BUCKET, (string) $row['backup_id'] );
		$done   = self::handler( $row['kind'] )->restore( $row, null === $backup['content'] ? '' : $backup['content'] );
		if ( is_wp_error( $done ) ) {
			$code = $done->get_error_code();
			return self::result( null === $backup['content'] && 'backup_unreadable' === $code ? 'backup_' . (string) $backup['reason'] : $code );
		}
		$detail = $row['detail'];
		unset( $detail['applied'], $detail['sha256_clean'] );
		$opened = self::update(
			$row,
			array(
				'status'     => self::STATUS_OPEN,
				'backup_id'  => null,
				'detail'     => self::encode( $detail ),
				'updated_at' => time(),
			),
			false
		);
		if ( false !== $opened && '' !== (string) $row['backup_id'] ) {
			Segurium_Storage::backup_delete( self::BUCKET, (string) $row['backup_id'] );
		}
		self::log(
			self::EVENT_RESTORED,
			$row,
			array(
				'backup_id' => $row['backup_id'],
				'actor'     => $actor,
			)
		);
		self::report(
			'file_restored',
			$row,
			array(
				'backup_id' => $row['backup_id'],
				'actor'     => $actor,
			)
		);
		return self::result( '' );
	}

	/**
	 * Ignore an open finding. A later detection keeps it ignored.
	 *
	 * @param int $id Finding ID.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	public static function ignore( $id ) {
		return self::claimed(
			(int) $id,
			self::STATUS_OPEN,
			static function ( array $row ) {
				self::update(
					$row,
					array(
						'status'     => self::STATUS_IGNORED,
						'updated_at' => time(),
					)
				);
				self::log( self::EVENT_IGNORED, $row, array() );
				self::report( 'file_ignored', $row, array( 'ignore_type' => 'path' ) );
			}
		);
	}

	/**
	 * Open an ignored finding again.
	 *
	 * @param int $id Finding ID.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	public static function unignore( $id ) {
		return self::claimed(
			(int) $id,
			self::STATUS_IGNORED,
			static function ( array $row ) {
				self::update(
					$row,
					array(
						'status'     => self::STATUS_OPEN,
						'updated_at' => time(),
					)
				);
			}
		);
	}

	/**
	 * Run a status action on a finding under its claim.
	 *
	 * @param int      $id    Finding ID.
	 * @param string   $need  Status the action needs.
	 * @param callable $write Gets the finding as read under the claim.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	private static function claimed( $id, $need, callable $write ) {
		$fault = self::fault( self::load( $id ), $need );
		if ( '' !== $fault ) {
			return self::result( $fault );
		}
		$code  = '';
		$token = self::lock( $id, $code );
		if ( '' === $token ) {
			return self::result( $code );
		}
		try {
			$row   = self::load( $id );
			$fault = self::fault( $row, $need );
			if ( '' === $fault ) {
				$write( $row );
			}
			return self::result( $fault );
		} finally {
			self::unlock( $id, $token );
		}
	}

	/**
	 * Findings as rows of the Malware Scanner list, open ones first.
	 *
	 * @param bool   $recent_only Only rows changed inside the recent window.
	 * @param string $filter      One of the Segurium_File_State::FILTER_* constants.
	 * @return array<int, array<string, mixed>>
	 */
	public static function rows( $recent_only, $filter ) {
		$map      = array(
			Segurium_File_State::FILTER_MALICIOUS => array( self::STATUS_OPEN ),
			Segurium_File_State::FILTER_CLEANED   => array( self::STATUS_CURED ),
			Segurium_File_State::FILTER_FIXED     => array( self::STATUS_FIXED ),
			Segurium_File_State::FILTER_IGNORED   => array( self::STATUS_IGNORED ),
		);
		$statuses = isset( $map[ $filter ] ) ? $map[ $filter ] : array_keys( self::ROW_STATES );
		$kinds    = self::kinds();
		if ( empty( $kinds ) ) {
			return array();
		}
		list( $where, $args ) = self::scope( array_keys( $kinds ), $recent_only );
		$rows                 = Segurium_Storage::table_get_results(
			self::TABLE,
			'SELECT * FROM {{table}} WHERE ' . $where . ' AND status IN (' . implode( ',', array_fill( 0, count( $statuses ), '%s' ) ) . ') '
				. "ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'cured' THEN 1 WHEN 'fixed' THEN 2 ELSE 3 END, id",
			array_merge( $args, $statuses ),
			ARRAY_A
		);
		$out                  = array();
		foreach ( $rows as $row ) {
			$row   = self::hydrate( $row );
			$kind  = $kinds[ $row['kind'] ];
			$out[] = array(
				'kind'         => 'content',
				'content_kind' => $row['kind'],
				'id'           => (int) $row['id'],
				'path'         => 'content:' . (int) $row['id'],
				'label'        => $kind->label( $row ),
				'location'     => $kind->location( $row ),
				'sha256'       => $row['sha256'],
				'state'        => self::ROW_STATES[ $row['status'] ],
				'timestamp'    => (int) $row['updated_at'],
				'verdict'      => (int) $row['verdict'],
				'backup_id'    => self::STATUS_CURED === $row['status'] && $kind->restorable() ? $row['backup_id'] : null,
				'restorable'   => $kind->restorable(),
			);
		}
		return $out;
	}

	/**
	 * Counts per scanner bucket.
	 *
	 * @param bool $recent_only Only rows changed inside the recent window.
	 * @return array{all:int,malicious:int,cleaned:int,fixed:int,ignored:int}
	 */
	public static function counts( $recent_only ) {
		$out   = array_fill_keys( array( 'all', 'malicious', 'cleaned', 'fixed', 'ignored' ), 0 );
		$kinds = array_keys( self::kinds() );
		if ( empty( $kinds ) ) {
			return $out;
		}
		list( $where, $args ) = self::scope( $kinds, $recent_only );
		foreach ( Segurium_Storage::table_get_results( self::TABLE, 'SELECT status, COUNT(*) AS n FROM {{table}} WHERE ' . $where . ' GROUP BY status', $args, ARRAY_A ) as $row ) {
			if ( isset( self::ROW_STATES[ $row['status'] ] ) ) {
				$out[ self::ROW_STATES[ $row['status'] ] ] += (int) $row['n'];
				$out['all']                                += (int) $row['n'];
			}
		}
		return $out;
	}

	/**
	 * Rows one scanner filter holds.
	 *
	 * @param bool   $recent_only Only rows changed inside the recent window.
	 * @param string $filter      One of the Segurium_File_State::FILTER_* constants.
	 * @return int
	 */
	public static function total( $recent_only, $filter ) {
		$counts = self::counts( $recent_only );
		return isset( $counts[ $filter ] ) ? $counts[ $filter ] : $counts['all'];
	}

	/**
	 * AJAX: Clean, Restore, Ignore and Remove from ignore on a finding row.
	 *
	 * @return void
	 */
	public static function ajax_action() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}
		$op  = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$id  = isset( $_POST['id'] ) ? absint( wp_unslash( $_POST['id'] ) ) : 0;
		$ops = array(
			'clean'    => array( 'clean', 'cleaned', __( 'Cleanup unavailable.', 'segurium' ) ),
			'restore'  => array( 'restore', 'malicious', __( 'Restore failed', 'segurium' ) ),
			'ignore'   => array( 'ignore', 'ignored', __( 'Invalid parameters', 'segurium' ) ),
			'unignore' => array( 'unignore', 'malicious', __( 'Invalid parameters', 'segurium' ) ),
		);
		if ( ! isset( $ops[ $op ] ) || $id <= 0 ) {
			segurium_send_json_error(
				array(
					'code'    => 'bad_args',
					'message' => __( 'Invalid parameters', 'segurium' ),
				)
			);
			return;
		}
		$result = 'clean' === $op ? self::clean( $id, self::ACTOR_MANUAL ) : call_user_func( array( __CLASS__, $ops[ $op ][0] ), $id );
		if ( $result['ok'] ) {
			segurium_send_json_success(
				array(
					'state'     => $ops[ $op ][1],
					'backup_id' => $result['backup_id'],
					'quota'     => 'clean' === $op ? Segurium_Quota::instance()->state() : null,
				)
			);
			return;
		}
		if ( self::PAYWALL === $result['code'] ) {
			$envelope = isset( $result['paywall']['quota'] ) && is_array( $result['paywall']['quota'] ) ? $result['paywall']['quota'] : array();
			Segurium_Paywall_Telemetry::stamp_wall( $envelope );
			segurium_send_json_error(
				array_merge(
					array( 'message' => __( 'Cleanup quota reached. Upgrade to Pro for an unbounded cloud cleanup quota.', 'segurium' ) ),
					Segurium_Quota::paywall_payload( $envelope, Segurium_Paywall_Telemetry::ACTION_CLEANUP )
				),
				402
			);
			return;
		}
		segurium_send_json_error(
			array(
				'code'    => $result['code'],
				'message' => $ops[ $op ][2],
			)
		);
	}

	/**
	 * Write the threats of a run and settle the open findings it cleared.
	 *
	 * @param Segurium_Content_Finding_Kind $handler Kind handler.
	 * @param string                        $run_id  Run ID.
	 * @param array                         $threats Threats from {@see Segurium_Content_Finding_Kind::detections()}.
	 * @param array                         $clean   Keys of the items that ended clean.
	 * @return void
	 */
	private static function record( Segurium_Content_Finding_Kind $handler, $run_id, array $threats, array $clean ) {
		$kind = $handler->kind();
		$now  = time();
		$seen = array();
		foreach ( $threats as $threat ) {
			$hash          = hash( 'sha256', (string) $threat['key'] );
			$seen[ $hash ] = true;
			$row           = self::hydrate(
				Segurium_Storage::table_get_row( self::TABLE, 'SELECT * FROM {{table}} WHERE kind = %s AND locator_hash = %s', array( $kind, $hash ), ARRAY_A )
			);
			$fields        = array(
				'sha256'     => (string) $threat['sha256'],
				'verdict'    => (int) $threat['verdict'],
				'detail'     => array( 'key' => (string) $threat['key'] ) + (array) $threat['detail'],
				'run_uuid'   => $run_id,
				'seen_at'    => $now,
				'updated_at' => $now,
			);
			if ( null === $row ) {
				self::insert( $kind, $hash, (string) $threat['locator'], $fields );
				continue;
			}
			self::under_lock(
				(int) $row['id'],
				static function ( array $held ) use ( $fields, $run_id ) {
					self::detected( $held, $fields, $run_id );
				}
			);
		}

		$cleared = array_flip( array_map( 'strval', $clean ) );
		foreach ( Segurium_Storage::table_get_results( self::TABLE, 'SELECT * FROM {{table}} WHERE kind = %s AND status = %s', array( $kind, self::STATUS_OPEN ), ARRAY_A ) as $row ) {
			$row = self::hydrate( $row );
			if ( isset( $seen[ $row['locator_hash'] ] ) ) {
				continue;
			}
			$key = isset( $row['detail']['key'] ) ? (string) $row['detail']['key'] : '';
			if ( isset( $cleared[ $key ] ) || ! $handler->exists( $row ) ) {
				self::under_lock(
					(int) $row['id'],
					static function ( array $held ) use ( $now ) {
						self::fixed( $held, $now );
					}
				);
			}
		}
	}

	/**
	 * Run a write of the state rules on a finding while no action holds it.
	 * A finding an action holds keeps what the action writes.
	 *
	 * @param int      $id    Finding ID.
	 * @param callable $write Gets the finding as read under the claim.
	 * @return void
	 */
	private static function under_lock( $id, callable $write ) {
		$code  = '';
		$token = self::lock( $id, $code );
		if ( '' === $token ) {
			Segurium_Debug::log( sprintf( '[segurium-content-findings] state write skipped id=%d: %s', $id, $code ) );
			return;
		}
		try {
			$row = self::load( $id );
			if ( null !== $row ) {
				$write( $row );
			}
		} finally {
			self::unlock( $id, $token );
		}
	}

	/**
	 * A detection of a finding that exists.
	 *
	 * @param array  $row    Finding.
	 * @param array  $fields Values of the detection.
	 * @param string $run_id Run ID.
	 * @return void
	 */
	private static function detected( array $row, array $fields, $run_id ) {
		if ( self::STATUS_OPEN === $row['status'] && $row['sha256'] === $fields['sha256'] ) {
			$fields['detail'] += array_intersect_key( $row['detail'], array_flip( array( 'reason', 'reason_sha', 'charged' ) ) );
		}
		if ( self::STATUS_OPEN === $row['status'] && isset( $row['detail']['staged'] ) ) {
			$fields['detail'] = $row['detail'];
		}
		$fields['status'] = self::STATUS_IGNORED === $row['status'] ? self::STATUS_IGNORED : self::STATUS_OPEN;
		$fields['detail'] = self::encode( $fields['detail'] );
		self::update( $row, $fields );
		if ( $fields['status'] !== $row['status'] ) {
			self::log( self::EVENT_OPENED, $row, array( 'run_id' => $run_id ) );
		}
	}

	/**
	 * An open finding whose item ended clean or whose target is gone.
	 *
	 * @param array $row Finding.
	 * @param int   $now Time of the run.
	 * @return void
	 */
	private static function fixed( array $row, $now ) {
		if ( self::STATUS_OPEN === $row['status'] ) {
			self::update(
				$row,
				array(
					'status'     => self::STATUS_FIXED,
					'updated_at' => $now,
				)
			);
		}
	}

	/**
	 * Clean the open findings of the run while Auto-Fix is on.
	 *
	 * @param string $kind   Content kind.
	 * @param string $run_id Run ID.
	 * @return void
	 */
	private static function auto_fix( $kind, $run_id ) {
		$rows  = Segurium_Storage::table_get_results(
			self::TABLE,
			'SELECT * FROM {{table}} WHERE kind = %s AND status = %s AND run_uuid = %s ORDER BY id',
			array( $kind, self::STATUS_OPEN, $run_id ),
			ARRAY_A
		);
		$asked = 0;
		foreach ( $rows as $row ) {
			$row = self::hydrate( $row );
			if ( ! empty( $row['detail']['charged'] ) && isset( $row['detail']['reason_sha'] ) && $row['detail']['reason_sha'] === $row['sha256'] ) {
				continue;
			}
			$late = $asked > 0 && Segurium_Scan_Runner::in_tick() && Segurium_Scan_Runner::time_left_in_tick() < self::AUTO_FIX_MIN_SEC;
			if ( $late || ! Segurium_Scan_Runner::renew_liveness( $run_id ) ) {
				Segurium_Debug::log( sprintf( '[segurium-content-findings] %s kind=%s run=%s: %d findings wait for the next run', $late ? 'AUTO_FIX_DEFERRED_TICK_BUDGET' : 'AUTO_FIX_DEFERRED_LEASE_LOST', $kind, $run_id, count( $rows ) - $asked ) );
				return;
			}
			++$asked;
			if ( self::PAYWALL === self::clean( (int) $row['id'], self::ACTOR_AUTO )['code'] ) {
				return;
			}
		}
	}

	/**
	 * Why an action cannot run on a finding, or ''.
	 *
	 * @param array|null $row  Finding.
	 * @param string     $need Status the action needs.
	 * @return string
	 */
	private static function fault( $row, $need ) {
		if ( null === $row ) {
			return 'not_found';
		}
		if ( null === self::handler( $row['kind'] ) ) {
			return 'kind_unavailable';
		}
		return $need === $row['status'] ? '' : 'wrong_status';
	}

	/**
	 * Keep the finding open and record why the cleanup changed nothing.
	 *
	 * @param array  $row     Finding.
	 * @param string $code    Reason code.
	 * @param bool   $charged Whether the cloud served a cleaned version first.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	private static function refuse( array $row, $code, $charged = false ) {
		$detail               = $row['detail'];
		$detail['reason']     = (string) $code;
		$detail['reason_sha'] = $row['sha256'];
		$detail['charged']    = (bool) $charged;
		self::update( $row, array( 'detail' => self::encode( $detail ) ) );
		Segurium_Debug::log( sprintf( '[segurium-content-findings] cleanup refused kind=%s id=%d: %s', $row['kind'], (int) $row['id'], $code ) );
		return self::result( (string) $code );
	}

	/**
	 * Outcome of an action.
	 *
	 * @param string $code Reason code, '' for success.
	 * @return array{ok:bool,code:string,backup_id:string,paywall:array,quota:?array}
	 */
	private static function result( $code ) {
		return array(
			'ok'        => '' === $code,
			'code'      => (string) $code,
			'backup_id' => '',
			'paywall'   => array(),
			'quota'     => null,
		);
	}

	/**
	 * Handler of a kind, or null.
	 *
	 * @param string $kind Content kind.
	 * @return Segurium_Content_Finding_Kind|null
	 */
	private static function handler( $kind ) {
		$kinds = self::kinds();
		return isset( $kinds[ $kind ] ) ? $kinds[ $kind ] : null;
	}

	/**
	 * One finding by ID.
	 *
	 * @param int $id Finding ID.
	 * @return array|null
	 */
	private static function load( $id ) {
		return $id > 0 ? self::hydrate( Segurium_Storage::table_get_row( self::TABLE, 'SELECT * FROM {{table}} WHERE id = %d', array( $id ), ARRAY_A ) ) : null;
	}

	/**
	 * A table row with `detail` decoded.
	 *
	 * @param mixed $row Row as read.
	 * @return array|null
	 */
	private static function hydrate( $row ) {
		if ( ! is_array( $row ) || ! isset( $row['id'], $row['kind'], $row['status'] ) ) {
			return null;
		}
		$detail        = json_decode( (string) $row['detail'], true );
		$row['detail'] = is_array( $detail ) ? $detail : array();
		$row['sha256'] = (string) $row['sha256'];
		return $row;
	}

	/**
	 * WHERE clause over the kinds and the recent window.
	 *
	 * @param string[] $kinds       Kinds.
	 * @param bool     $recent_only Only rows changed inside the recent window.
	 * @return array{0:string,1:array}
	 */
	private static function scope( array $kinds, $recent_only ) {
		$where = 'kind IN (' . implode( ',', array_fill( 0, count( $kinds ), '%s' ) ) . ')';
		if ( $recent_only ) {
			$where  .= ' AND updated_at >= %d';
			$kinds[] = time() - Segurium_File_State::RECENT_DAYS * DAY_IN_SECONDS;
		}
		return array( $where, $kinds );
	}

	/**
	 * Insert a new open finding.
	 *
	 * @param string $kind    Content kind.
	 * @param string $hash    Hash of the finding key.
	 * @param string $locator Locator.
	 * @param array  $fields  Values of a detection.
	 * @return void
	 */
	private static function insert( $kind, $hash, $locator, array $fields ) {
		$row           = array(
			'kind'         => $kind,
			'locator'      => substr( $locator, 0, 500 ),
			'locator_hash' => $hash,
			'status'       => self::STATUS_OPEN,
			'backup_id'    => null,
			'created_at'   => $fields['updated_at'],
		) + $fields;
		$row['detail'] = self::encode( $row['detail'] );
		try {
			$row['id'] = Segurium_Storage::table_insert( self::TABLE, $row );
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-content-findings] CONTENT_FINDING_WRITE_FAILED insert: ' . $e->getMessage() );
			return;
		}
		Segurium_Issue_Indicator::mark_stale();
		self::log( self::EVENT_OPENED, $row, array( 'run_id' => $fields['run_uuid'] ) );
	}

	/**
	 * Update one finding.
	 *
	 * @param array $row   Finding as read.
	 * @param array $data  Columns to write.
	 * @param bool  $guard Write only while the row holds the status it was read with.
	 * @return int|false Rows changed, false when the write failed.
	 */
	private static function update( array $row, array $data, $guard = true ) {
		$where = array( 'id' => (int) $row['id'] );
		if ( $guard ) {
			$where['status'] = (string) $row['status'];
		}
		try {
			$changed = Segurium_Storage::table_update( self::TABLE, $data, $where );
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-content-findings] CONTENT_FINDING_WRITE_FAILED update id=' . (int) $row['id'] . ': ' . $e->getMessage() );
			return false;
		}
		if ( isset( $data['status'] ) ) {
			Segurium_Issue_Indicator::mark_stale();
		}
		return $changed;
	}

	/**
	 * Undo the writes a cleanup staged and could not finish, from its backup.
	 *
	 * @param Segurium_Content_Finding_Kind $handler Kind handler.
	 * @param array                         $row     Finding with `detail.staged`.
	 * @return string Reason code, '' once the staged writes are undone.
	 */
	private static function undo_staged( Segurium_Content_Finding_Kind $handler, array $row ) {
		$staged = (array) $row['detail']['staged'];
		$id     = isset( $staged['backup_id'] ) ? (string) $staged['backup_id'] : '';
		$code   = '';
		if ( ! empty( $staged['applied'] ) ) {
			$backup = Segurium_Storage::backup_restore_detailed( self::BUCKET, $id );
			if ( null === $backup['content'] ) {
				$code = 'staged_backup_' . (string) $backup['reason'];
			} else {
				$row['detail']['applied'] = (array) $staged['applied'];
				$row['staged_undo']       = true;
				$done                     = $handler->restore( $row, $backup['content'] );
				$code                     = is_wp_error( $done ) ? 'staged_' . $done->get_error_code() : '';
			}
			if ( '' !== $code && 0 !== strpos( $code, 'staged_backup_' ) ) {
				return $code;
			}
			Segurium_Debug::log( sprintf( '[segurium-content-findings] staged cleanup closed kind=%s id=%d: %s', $row['kind'], (int) $row['id'], '' === $code ? 'undone' : $code ) );
		}
		$detail = $row['detail'];
		unset( $detail['staged'], $detail['applied'] );
		if ( false === self::update( $row, array( 'detail' => self::encode( $detail ) ) ) ) {
			return 'staging_failed';
		}
		if ( '' !== $id ) {
			Segurium_Storage::backup_delete( self::BUCKET, $id );
		}
		return $code;
	}

	/**
	 * Claim a finding for one action. A claim a dead worker left lapses after LOCK_SEC.
	 *
	 * @param int    $id   Finding ID.
	 * @param string $code Set to `finding_busy` while another action holds the finding, `finding_lock_failed` when the claim cannot be read or written.
	 * @return string Token, '' without the claim.
	 */
	private static function lock( $id, &$code ) {
		global $wpdb;
		$token = wp_generate_password( 32, false );
		$now   = time();
		$key   = self::LOCK_PREFIX . (int) $id;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- an atomic claim; a cache layer would defeat it.
		$claimed = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i (kv_key, kv_value, expires_at, updated_at) VALUES (%s, %s, %d, %d) ON DUPLICATE KEY UPDATE '
				. 'kv_value = IF(expires_at < %d, VALUES(kv_value), kv_value), updated_at = IF(expires_at < %d, VALUES(updated_at), updated_at), '
				. 'expires_at = IF(expires_at < %d, VALUES(expires_at), expires_at)',
				Segurium_Storage::table_name( 'runtime_kv' ),
				$key,
				$token,
				$now + self::LOCK_SEC,
				$now,
				$now,
				$now,
				$now
			)
		);

		$held = Segurium_Storage::table_get_var( 'runtime_kv', 'SELECT kv_value FROM {{table}} WHERE kv_key = %s', array( $key ) );
		if ( false === $claimed || null === $held ) {
			$code = 'finding_lock_failed';
			Segurium_Debug::log( sprintf( '[segurium-content-findings] finding_lock_failed id=%d: %s', (int) $id, substr( (string) $wpdb->last_error, 0, 200 ) ) );
			return '';
		}
		$code = (string) $held === $token ? '' : self::BUSY;
		return '' === $code ? $token : '';
	}

	/**
	 * Extend a claim this request holds.
	 *
	 * @param int    $id    Finding ID.
	 * @param string $token Token of the claim.
	 * @return bool False when the claim is no longer this request's.
	 */
	private static function renew( $id, $token ) {
		global $wpdb;
		$key = self::LOCK_PREFIX . (int) $id;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- extends only the claim this request holds.
		$done = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET expires_at = %d, updated_at = %d WHERE kv_key = %s AND kv_value = %s', Segurium_Storage::table_name( 'runtime_kv' ), time() + self::LOCK_SEC, time(), $key, $token ) );
		return false !== $done && (string) Segurium_Storage::table_get_var( 'runtime_kv', 'SELECT kv_value FROM {{table}} WHERE kv_key = %s', array( $key ) ) === $token;
	}

	/**
	 * Let go of a claim this request holds.
	 *
	 * @param int    $id    Finding ID.
	 * @param string $token Token of the claim.
	 * @return void
	 */
	private static function unlock( $id, $token ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- releases only the claim this request holds.
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE kv_key = %s AND kv_value = %s', Segurium_Storage::table_name( 'runtime_kv' ), self::LOCK_PREFIX . (int) $id, $token ) );
	}

	/**
	 * Activity log entry of a finding.
	 *
	 * @param string $event Event type.
	 * @param array  $row   Finding.
	 * @param array  $extra Extra fields.
	 * @return void
	 */
	private static function log( $event, array $row, array $extra ) {
		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => $event,
					'severity'   => self::EVENT_IGNORED === $event ? 1 : 2,
					'subject'    => substr( (string) $row['locator'], 0, 191 ),
					'data_json'  => self::encode(
						array(
							'kind'       => (string) $row['kind'],
							'locator'    => (string) $row['locator'],
							'sha256'     => (string) $row['sha256'],
							'finding_id' => (int) $row['id'],
						) + $extra
					),
					'created_at' => time(),
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-content-findings] activity_log: ' . $e->getMessage() );
		}
	}

	/**
	 * Tell the cloud about a cleanup, restore or ignore, with the kind.
	 *
	 * @param string $type  Message type.
	 * @param array  $row   Finding.
	 * @param array  $extra Extra fields.
	 * @return void
	 */
	private static function report( $type, array $row, array $extra ) {
		Segurium_Storage::cti_send_message(
			$type,
			array(
				'kind'   => (string) $row['kind'],
				'sha256' => (string) $row['sha256'],
				'path'   => (string) $row['locator'],
			) + $extra
		);
	}

	/**
	 * Detail without the reason of the last refusal.
	 *
	 * @param array $detail Detail.
	 * @return array
	 */
	private static function without_reason( array $detail ) {
		unset( $detail['reason'], $detail['reason_sha'], $detail['charged'] );
		return $detail;
	}

	/**
	 * JSON of a detail or log document.
	 *
	 * @param array $document Document.
	 * @return string
	 */
	private static function encode( array $document ) {
		return (string) wp_json_encode( $document, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );
	}
}

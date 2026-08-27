<?php
/**
 * Canonical current-state-per-file projection.
 *
 * The `scan_findings` table is an append-only event log — every finding
 * that ever appeared in a scan is preserved there. `file_state` is the
 * projection the admin UI reads and the cleanup / restore / ignore /
 * mark_fixed mutators write to. Having a single keyed-by-file_path_hash
 * row per file makes these semantics obvious and keeps historical scan
 * rows immutable.
 *
 * Nothing in this class ever updates `scan_findings`.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * File-state projection mutators and read helpers.
 */
class Segurium_File_State {

	const RECENT_DAYS = 14;

	/**
	 * Record a new finding arriving from the scan / realtime / upload pipelines.
	 *
	 * Semantics:
	 *  - First detection: insert with current_status='open'.
	 *  - Subsequent detection:
	 *      * 'ignored' is always preserved (explicit admin opt-out).
	 *      * 'cured' is preserved only when the newly observed sha256 still
	 *        matches sha256_clean — i.e. the clean replacement is intact on
	 *        disk. A cured path re-appearing with a different sha256 means
	 *        the cure has been overwritten (re-infection); flip back to
	 *        'open' and clear resolved_at so the UI surfaces it again.
	 *      * otherwise bump the row to 'open' (same as "still malicious").
	 *    last_scan_uuid, sha256, verdict, severity, detector and timestamps
	 *    always refresh.
	 *
	 * @param array $args {
	 *     Finding descriptor.
	 *
	 *     @type string $scan_uuid Scan UUID that produced the finding.
	 *     @type string $file_path Relative file path.
	 *     @type string $sha256    File content hash.
	 *     @type int    $verdict   CTI verdict code.
	 *     @type int    $severity  CTI severity (defaults derived from verdict).
	 *     @type string $detector  Detector label (scanner|realtime|upload|...).
	 *     @type int    $timestamp Unix timestamp of detection.
	 * }
	 * @return void
	 */
	public static function record_finding( array $args ) {
		$path = isset( $args['file_path'] ) ? (string) $args['file_path'] : '';
		if ( '' === $path ) {
			return;
		}
		$hash = hash( 'sha256', $path );
		$ts   = isset( $args['timestamp'] ) ? (int) $args['timestamp'] : time();
		$row  = array(
			'file_path'      => $path,
			'file_path_hash' => $hash,
			'current_status' => 'open',
			'current_sha256' => isset( $args['sha256'] ) ? (string) $args['sha256'] : '',
			'verdict'        => isset( $args['verdict'] ) ? (string) $args['verdict'] : '',
			'severity'       => isset( $args['severity'] ) ? (int) $args['severity'] : 0,
			'detector'       => isset( $args['detector'] ) ? (string) $args['detector'] : '',
			'last_scan_uuid' => isset( $args['scan_uuid'] ) ? (string) $args['scan_uuid'] : null,
			'last_seen_at'   => $ts,
			'created_at'     => $ts,
			'updated_at'     => $ts,
		);

		global $wpdb;
		$table = Segurium_Storage::table_name( 'file_state' );
		// NOTE: assignment order matters — MySQL evaluates ON DUPLICATE KEY
		// UPDATE expressions left-to-right, and later expressions see values
		// written by earlier ones. resolved_at is assigned BEFORE
		// current_status so its CASE can read the pre-update status.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->query(
			$wpdb->prepare(
				'INSERT INTO %i '
					. '(file_path, file_path_hash, current_status, current_sha256, verdict, severity, detector, last_scan_uuid, last_seen_at, created_at, updated_at) '
					. 'VALUES (%s, %s, %s, %s, %s, %d, %s, %s, %d, %d, %d) '
					. 'ON DUPLICATE KEY UPDATE '
					. 'resolved_at    = CASE '
						. "WHEN current_status = 'ignored' THEN resolved_at "
						. "WHEN current_status = 'cured' AND sha256_clean IS NOT NULL AND sha256_clean = VALUES(current_sha256) THEN resolved_at "
						. 'ELSE NULL END, '
					. 'current_status = CASE '
						. "WHEN current_status = 'ignored' THEN 'ignored' "
						. "WHEN current_status = 'cured' AND sha256_clean IS NOT NULL AND sha256_clean = VALUES(current_sha256) THEN 'cured' "
						. "ELSE 'open' END, "
					. 'current_sha256 = VALUES(current_sha256), '
					. 'verdict        = VALUES(verdict), '
					. 'severity       = VALUES(severity), '
					. 'detector       = VALUES(detector), '
					. 'last_scan_uuid = VALUES(last_scan_uuid), '
					. 'last_seen_at   = VALUES(last_seen_at), '
					. 'updated_at     = VALUES(updated_at)',
				$table,
				$row['file_path'],
				$row['file_path_hash'],
				$row['current_status'],
				$row['current_sha256'],
				$row['verdict'],
				$row['severity'],
				$row['detector'],
				null === $row['last_scan_uuid'] ? '' : $row['last_scan_uuid'],
				$row['last_seen_at'],
				$row['created_at'],
				$row['updated_at']
			)
		);
		if ( false === $result ) {
			Segurium_Debug::log( '[segurium-file-state] record_finding failed: ' . $wpdb->last_error );
		}
	}

	/**
	 * Flip every currently-open projection row whose file_path_hash is in
	 * the supplied list to current_status='fixed'. Other statuses (cured,
	 * ignored) are preserved verbatim.
	 *
	 * @param array<string> $file_path_hashes File path SHA-256 hex strings.
	 * @param int           $timestamp        Resolution timestamp.
	 * @return int Rows affected.
	 */
	public static function mark_fixed_by_hashes( array $file_path_hashes, int $timestamp ) {
		if ( empty( $file_path_hashes ) ) {
			return 0;
		}
		global $wpdb;
		$table = Segurium_Storage::table_name( 'file_state' );
		$in    = implode( ',', array_fill( 0, count( $file_path_hashes ), '%s' ) );
		$args  = array_merge( array( $table, 'fixed', $timestamp, $timestamp ), $file_path_hashes, array( 'open' ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- SQL template uses %i for table; placeholders dynamically generated for variable-length IN-list; splat unpacks every value into a separate prepare() arg at runtime — plugin-check counts the splat statically as 1.
		$affected = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET current_status = %s, resolved_at = %d, updated_at = %d WHERE file_path_hash IN (' . $in . ') AND current_status = %s', ...$args ) );
		return false === $affected ? 0 : (int) $affected;
	}

	/**
	 * Return every relative file_path whose projection row is currently open.
	 * Used by Segurium_Server_State::mark_fixed_after_scan to find files
	 * that disappeared from disk between scans.
	 *
	 * @return array<array{file_path:string,file_path_hash:string}>
	 */
	public static function list_open_paths() {
		$rows = Segurium_Storage::table_get_results(
			'file_state',
			"SELECT file_path, file_path_hash FROM {{table}} WHERE current_status = 'open'",
			array(),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Mark a file as cured (malware scrubbed, original backed up).
	 *
	 * @param string $file_path    Relative file path.
	 * @param string $backup_id    Backup identifier of the replaced content.
	 * @param string $sha256_clean SHA-256 of the cleaned replacement.
	 * @param int    $timestamp    Unix timestamp of the cure.
	 * @return void
	 */
	public static function mark_cured( string $file_path, string $backup_id, string $sha256_clean, int $timestamp ) {
		self::ensure_row( $file_path, $timestamp );
		self::update_by_hash(
			$file_path,
			array(
				'current_status' => 'cured',
				'backup_id'      => $backup_id,
				'sha256_clean'   => $sha256_clean,
				'resolved_at'    => $timestamp,
				'updated_at'     => $timestamp,
			)
		);
	}

	/**
	 * Mark a file as ignored by the administrator.
	 *
	 * @param string $file_path Relative file path.
	 * @param int    $timestamp Unix timestamp.
	 * @return void
	 */
	public static function mark_ignored( string $file_path, int $timestamp ) {
		self::ensure_row( $file_path, $timestamp );
		self::update_by_hash(
			$file_path,
			array(
				'current_status' => 'ignored',
				'updated_at'     => $timestamp,
			)
		);
	}

	/**
	 * Mark a file as restored from backup (returns to open, since the
	 * malicious payload has been re-placed on disk).
	 *
	 * @param string $file_path Relative file path.
	 * @param int    $timestamp Unix timestamp.
	 * @return void
	 */
	public static function mark_restored( string $file_path, int $timestamp ) {
		self::ensure_row( $file_path, $timestamp );
		self::update_by_hash(
			$file_path,
			array(
				'current_status' => 'open',
				'resolved_at'    => null,
				'updated_at'     => $timestamp,
			)
		);
	}

	/**
	 * Directly set the status for a file. Used by legacy code paths that
	 * still call update_file_state with a raw status string — prefer the
	 * purpose-specific helpers above when possible.
	 *
	 * @param string      $file_path Relative file path.
	 * @param string      $status    New current_status value.
	 * @param int         $timestamp Unix timestamp.
	 * @param string|null $backup_id Optional backup identifier.
	 * @return void
	 */
	public static function set_status( string $file_path, string $status, int $timestamp, $backup_id = null ) {
		self::ensure_row( $file_path, $timestamp );
		$data = array(
			'current_status' => $status,
			'updated_at'     => $timestamp,
		);
		if ( in_array( $status, array( 'cured', 'fixed' ), true ) ) {
			$data['resolved_at'] = $timestamp;
		} elseif ( 'open' === $status || 'restored' === $status ) {
			$data['resolved_at'] = null;
		}
		if ( null !== $backup_id && '' !== (string) $backup_id ) {
			$data['backup_id'] = (string) $backup_id;
		}
		self::update_by_hash( $file_path, $data );
	}

	/**
	 * Status-filter tokens accepted by {@see self::get_page()} /
	 * {@see self::get_total()}. 'malicious' selects the two statuses that
	 * still require admin attention ('open' + 'restored'); the rest map
	 * 1:1 onto the projection's stored status.
	 */
	const FILTER_ALL       = 'all';
	const FILTER_MALICIOUS = 'malicious';
	const FILTER_CLEANED   = 'cleaned';
	const FILTER_IGNORED   = 'ignored';
	const FILTER_FIXED     = 'fixed';

	/**
	 * Return a paginated list of projection rows.
	 *
	 * Sort order: items that still need attention first
	 * (`open`, then `restored`), then `cured`, `fixed`, `ignored`. Within
	 * each bucket rows are stably ordered by `file_path` ASC so acting on
	 * one row never shuffles its neighbours under the cursor.
	 *
	 * @param int    $page        One-based page number.
	 * @param int    $per_page    Page size (1..1000).
	 * @param bool   $recent_only Restrict to rows updated within RECENT_DAYS.
	 * @param string $filter      One of the FILTER_* constants.
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_page( int $page, int $per_page, bool $recent_only, string $filter = self::FILTER_ALL ) {
		$page     = max( 1, $page );
		$per_page = max( 1, min( 1000, $per_page ) );
		$offset   = ( $page - 1 ) * $per_page;

		list( $extra_cond, $args ) = self::build_filter_clause( $recent_only, $filter );
		$args[]                    = $per_page;
		$args[]                    = $offset;

		$rows = Segurium_Storage::table_get_results(
			'file_state',
			'SELECT file_path AS path, current_sha256 AS sha256, current_status AS status, verdict, updated_at AS timestamp, backup_id '
				. 'FROM {{table}} WHERE 1=1' . $extra_cond . ' ORDER BY '
				. "CASE current_status WHEN 'open' THEN 0 WHEN 'restored' THEN 1 WHEN 'cured' THEN 2 WHEN 'fixed' THEN 3 WHEN 'ignored' THEN 4 ELSE 5 END, "
				. 'file_path ASC '
				. 'LIMIT %d OFFSET %d',
			$args,
			ARRAY_A
		);

		$out = array();
		foreach ( $rows as $row ) {
			$out[] = array(
				'path'      => (string) $row['path'],
				'sha256'    => (string) $row['sha256'],
				'status'    => (string) $row['status'],
				'timestamp' => (int) $row['timestamp'],
				'verdict'   => (int) $row['verdict'],
				'backup_id' => $row['backup_id'],
			);
		}
		return $out;
	}

	/**
	 * Count projection rows matching the given filter.
	 *
	 * @param bool   $recent_only Restrict to rows updated within RECENT_DAYS.
	 * @param string $filter      One of the FILTER_* constants.
	 * @return int
	 */
	public static function get_total( bool $recent_only, string $filter = self::FILTER_ALL ) {
		list( $extra_cond, $args ) = self::build_filter_clause( $recent_only, $filter );
		return (int) Segurium_Storage::table_get_var(
			'file_state',
			'SELECT COUNT(*) FROM {{table}} WHERE 1=1' . $extra_cond,
			$args
		);
	}

	/**
	 * Return a per-tab count breakdown in a single query.
	 *
	 * Keys: 'all', 'malicious', 'cleaned', 'fixed', 'ignored'. 'malicious'
	 * sums 'open' + 'restored' — see FILTER_* constants.
	 *
	 * @param bool $recent_only Restrict to rows updated within RECENT_DAYS.
	 * @return array<string, int>
	 */
	public static function get_counts( bool $recent_only ) {
		$args = array();
		$sql  = 'SELECT current_status AS s, COUNT(*) AS n FROM {{table}}';
		if ( $recent_only ) {
			$sql   .= ' WHERE updated_at >= %d';
			$args[] = time() - self::RECENT_DAYS * DAY_IN_SECONDS;
		}
		$sql .= ' GROUP BY current_status';

		$rows = Segurium_Storage::table_get_results( 'file_state', $sql, $args, ARRAY_A );

		$by_status = array();
		$all       = 0;
		foreach ( $rows as $row ) {
			$status               = (string) $row['s'];
			$count                = (int) $row['n'];
			$by_status[ $status ] = $count;
			$all                 += $count;
		}
		return array(
			'all'       => $all,
			'malicious' => ( $by_status['open'] ?? 0 ) + ( $by_status['restored'] ?? 0 ),
			'cleaned'   => $by_status['cured'] ?? 0,
			'fixed'     => $by_status['fixed'] ?? 0,
			'ignored'   => $by_status['ignored'] ?? 0,
		);
	}

	/**
	 * Build the trailing WHERE clause + args for the filter applied by
	 * {@see self::get_page()} / {@see self::get_total()}. Unknown filter
	 * tokens are treated as FILTER_ALL.
	 *
	 * @param bool   $recent_only Restrict to rows updated within RECENT_DAYS.
	 * @param string $filter      One of the FILTER_* constants.
	 * @return array{0:string,1:array<int,mixed>} [SQL fragment, args]
	 */
	private static function build_filter_clause( bool $recent_only, string $filter ) {
		$clause = '';
		$args   = array();
		if ( $recent_only ) {
			$clause .= ' AND updated_at >= %d';
			$args[]  = time() - self::RECENT_DAYS * DAY_IN_SECONDS;
		}
		switch ( $filter ) {
			case self::FILTER_MALICIOUS:
				$clause .= " AND current_status IN ('open', 'restored')";
				break;
			case self::FILTER_CLEANED:
				$clause .= " AND current_status = 'cured'";
				break;
			case self::FILTER_FIXED:
				$clause .= " AND current_status = 'fixed'";
				break;
			case self::FILTER_IGNORED:
				$clause .= " AND current_status = 'ignored'";
				break;
			case self::FILTER_ALL:
			default:
				break;
		}
		return array( $clause, $args );
	}

	/**
	 * Fetch current_status for a batch of file_path_hash values. Missing
	 * hashes are simply absent from the returned map.
	 *
	 * @param array<string> $file_path_hashes SHA-256 hex strings.
	 * @return array<string, string> hash → current_status.
	 */
	public static function get_status_map( array $file_path_hashes ) {
		if ( empty( $file_path_hashes ) ) {
			return array();
		}
		$in   = implode( ',', array_fill( 0, count( $file_path_hashes ), '%s' ) );
		$rows = Segurium_Storage::table_get_results(
			'file_state',
			'SELECT file_path_hash, current_status FROM {{table}} WHERE file_path_hash IN (' . $in . ')',
			$file_path_hashes,
			ARRAY_A
		);
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ (string) $row['file_path_hash'] ] = (string) $row['current_status'];
		}
		return $out;
	}

	/**
	 * Read the current_status for a single file path.
	 *
	 * @param string $file_path Relative file path.
	 * @return string|null Current status, or null when the projection has
	 *                     no row for this path.
	 */
	public static function get_status( string $file_path ) {
		$val = Segurium_Storage::table_get_var(
			'file_state',
			'SELECT current_status FROM {{table}} WHERE file_path_hash = %s LIMIT 1',
			array( hash( 'sha256', $file_path ) )
		);
		return null === $val ? null : (string) $val;
	}

	/**
	 * Ensure a projection row exists for $file_path. Used by the
	 * mark_* / set_status helpers so callers that act before any scan
	 * has seen the file still produce a usable UI row.
	 *
	 * @param string $file_path Relative file path.
	 * @param int    $timestamp Unix timestamp used for created_at /
	 *                          updated_at on fresh rows.
	 * @return void
	 */
	private static function ensure_row( string $file_path, int $timestamp ) {
		$hash     = hash( 'sha256', $file_path );
		$existing = Segurium_Storage::table_get_var(
			'file_state',
			'SELECT id FROM {{table}} WHERE file_path_hash = %s LIMIT 1',
			array( $hash )
		);
		if ( null !== $existing ) {
			return;
		}
		try {
			Segurium_Storage::table_insert(
				'file_state',
				array(
					'file_path'      => $file_path,
					'file_path_hash' => $hash,
					'current_status' => 'open',
					'current_sha256' => '',
					'verdict'        => '',
					'severity'       => 0,
					'detector'       => '',
					'last_scan_uuid' => null,
					'backup_id'      => null,
					'sha256_clean'   => null,
					'last_seen_at'   => $timestamp,
					'resolved_at'    => null,
					'created_at'     => $timestamp,
					'updated_at'     => $timestamp,
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-file-state] ensure_row failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Narrow update helper keyed by file_path_hash. All state mutators
	 * funnel through here so the update predicate is consistent.
	 *
	 * @param string               $file_path Relative file path.
	 * @param array<string, mixed> $data      Columns → values to set.
	 * @return void
	 */
	private static function update_by_hash( string $file_path, array $data ) {
		try {
			Segurium_Storage::table_update(
				'file_state',
				$data,
				array( 'file_path_hash' => hash( 'sha256', $file_path ) )
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-file-state] update failed: ' . $e->getMessage() );
		}
	}
}

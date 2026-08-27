<?php
/**
 * Layer 2 storage: custom InnoDB tables.
 *
 * Provides the schema installer (dbDelta), CRUD helpers, query helpers, and
 * prune helper used by every feature stage. All access to $wpdb in plugin
 * code goes through this class — the PHPCS ruleset enforces it.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tables backend.
 */
class Segurium_Storage_Tables {

	const VERSION_OPTION = 'segurium_schema_versions';

	const INSTALL_ERRORS_TRANSIENT = 'segurium_schema_install_errors';

	/**
	 * Resolve logical → physical table name.
	 *
	 * @param string $logical Logical name (e.g. "activity_log").
	 * @return string Fully prefixed table name.
	 */
	public static function name( string $logical ): string {
		global $wpdb;
		return $wpdb->prefix . 'segurium_' . $logical;
	}

	/**
	 * Run a callable with $wpdb->suppress_errors(true) so WPDB does not echo
	 * raw HTML `<div id="error">…</div>` blocks for failed queries (which
	 * corrupts JSON AJAX responses when WP_DEBUG is on). Callers still read
	 * `$wpdb->last_error` to throw a typed Segurium_Storage_Exception.
	 *
	 * @template T
	 * @param callable(): T $callback Callback to execute with errors suppressed.
	 * @return T
	 */
	private static function with_suppressed_errors( callable $callback ) {
		global $wpdb;
		$prev = $wpdb->suppress_errors( true );
		try {
			return $callback();
		} finally {
			$wpdb->suppress_errors( $prev );
		}
	}

	/**
	 * Return true if the physical table for $logical exists in the current DB.
	 *
	 * Cheap (one SHOW TABLES LIKE against a prefix-scoped name) so install_all()
	 * can call it per-table without noticeable overhead.
	 *
	 * @param string $logical Logical name (e.g. "runtime_kv").
	 * @return bool
	 */
	public static function table_exists( string $logical ): bool {
		global $wpdb;
		$table = self::name( $logical );
		$found = self::with_suppressed_errors(
			static function () use ( $wpdb, $table ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
			}
		);
		return is_string( $found ) && $found === $table;
	}

	/**
	 * Install / upgrade every registered table whose version is behind.
	 *
	 * Runs dbDelta per table, updates the stored version map, and stashes any
	 * dbDelta errors into a transient so the admin dashboard can surface them.
	 *
	 * @return array<string, array<string>> Map of logical name → dbDelta messages.
	 */
	public static function install_all(): array {
		Segurium_Path_Helpers::wp_admin_include( 'upgrade.php' );

		global $wpdb;
		$prefix  = $wpdb->prefix;
		$charset = $wpdb->get_charset_collate();

		$stored = Segurium_Storage_Settings::get_array( self::VERSION_OPTION );
		$errors = array();
		$notes  = array();

		foreach ( Segurium_Storage_Schema_Registry::all() as $logical => $entry ) {
			$registered = (int) $entry['version'];
			$current    = isset( $stored[ $logical ] ) ? (int) $stored[ $logical ] : 0;

			// A stored version is only trustworthy if the table actually exists.
			// Manual DROPs, half-applied migrations, DB restore from an older
			// dump, etc., can leave the version map ahead of reality. Force
			// reinstall in that case so ensure_schema() genuinely self-heals.
			if ( $current >= $registered && ! self::table_exists( $logical ) ) {
				$current = 0;
			}

			if ( $current >= $registered ) {
				continue;
			}

			self::run_pre_migration( $logical, $current, $registered );

			$sql  = str_replace( '{prefix}', $prefix, (string) $entry['sql'] );
			$sql  = rtrim( trim( $sql ), ';' ) . ' ' . $charset . ';';
			$msgs = self::with_suppressed_errors(
				static function () use ( $sql ) {
					return dbDelta( $sql );
				}
			);

			$db_error = $wpdb->last_error;
			if ( '' !== $db_error ) {
				$errors[ $logical ] = array( $db_error );
				continue;
			}

			// Only commit the version bump if the table is actually there
			// post-dbDelta — defends against silent dbDelta-no-op edge cases.
			if ( ! self::table_exists( $logical ) ) {
				$errors[ $logical ] = array( 'dbDelta completed but table is still missing' );
				continue;
			}

			$stored[ $logical ] = $registered;
			$notes[ $logical ]  = is_array( $msgs ) ? array_values( $msgs ) : array();

			self::run_post_migration( $logical, $current, $registered );
		}

		Segurium_Storage_Settings::set( self::VERSION_OPTION, $stored, true );

		if ( ! empty( $errors ) ) {
			set_transient( self::INSTALL_ERRORS_TRANSIENT, $errors, DAY_IN_SECONDS );
		} else {
			delete_transient( self::INSTALL_ERRORS_TRANSIENT );
		}

		return $notes;
	}

	/**
	 * Run any inline data-fix needed before dbDelta adds a new constraint.
	 * dbDelta does not execute DML, so a UNIQUE index added to a table that
	 * already contains duplicates would fail silently without this hook.
	 *
	 * @param string $logical  Logical table name.
	 * @param int    $from     Currently stored schema version (0 if never installed).
	 * @param int    $to       Target schema version being installed.
	 * @return void
	 */
	private static function run_pre_migration( string $logical, int $from, int $to ): void {
		global $wpdb;

		if ( 'scan_history' === $logical && $from > 0 && $from < 2 && $to >= 2 ) {
			if ( self::table_exists( 'scan_history' ) ) {
				// findings_count removed — derived from scan_findings now. dbDelta
				// does not drop columns, so do it explicitly.
				self::with_suppressed_errors(
					static function () use ( $wpdb ) {
						// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
						return $wpdb->query( "ALTER TABLE `{$wpdb->prefix}segurium_scan_history` DROP COLUMN findings_count" );
					}
				);
			}
		}

		if ( 'scan_findings' === $logical && $from > 0 && $from < 3 && $to >= 3 ) {
			if ( ! self::table_exists( 'scan_findings' ) ) {
				return;
			}
			// Delete duplicates keeping the highest id for each
			// (scan_uuid, file_path_hash) pair. The UNIQUE index
			// that follows would fail to apply otherwise.
			self::with_suppressed_errors(
				static function () use ( $wpdb ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
					return $wpdb->query( "DELETE a FROM `{$wpdb->prefix}segurium_scan_findings` a INNER JOIN `{$wpdb->prefix}segurium_scan_findings` b ON a.scan_uuid = b.scan_uuid AND a.file_path_hash = b.file_path_hash AND a.id < b.id" );
				}
			);
		}
	}

	/**
	 * Run any inline data-fix needed after dbDelta has applied the target
	 * schema — typically a backfill when a new projection table is being
	 * introduced.
	 *
	 * @param string $logical Logical table name.
	 * @param int    $from    Previously stored version (0 if never installed).
	 * @param int    $to      Target version just installed.
	 * @return void
	 */
	private static function run_post_migration( string $logical, int $from, int $to ): void {
		global $wpdb;

		if ( 'integrity_issues' === $logical && $from > 0 && $from < 2 && $to >= 2 ) {
			if ( ! self::table_exists( 'integrity_issues' ) || ! self::table_exists( 'scan_findings' ) ) {
				return;
			}
			// Backfill: any open integrity row whose sha256 matches a still-open
			// malicious/injection finding gets is_malicious=1. Verdict 1 =
			// malicious, 2 = injection (Segurium_Verdict_Queue::NEO_RAY_VERDICT_MAP).
			self::with_suppressed_errors(
				static function () use ( $wpdb ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
					return $wpdb->query( "UPDATE `{$wpdb->prefix}segurium_integrity_issues` i INNER JOIN `{$wpdb->prefix}segurium_scan_findings` f ON f.sha256 = i.sha256 SET i.is_malicious = 1 WHERE i.sha256 <> '' AND i.status = 'open' AND f.verdict IN (1, 2) AND f.status = 'open'" );
				}
			);
		}

		// scan_history grew a separate `files_found` column so
		// the cancel/abort summary can show "X of Y scanned" honestly. For
		// existing rows there's no recorded discovery total, so backfill
		// files_found = files_scanned as the best approximation — a previously
		// completed scan had files_found == files_scanned by definition.
		if ( 'scan_history' === $logical && $from > 0 && $from < 3 && $to >= 3 ) {
			if ( ! self::table_exists( 'scan_history' ) ) {
				return;
			}
			self::with_suppressed_errors(
				static function () use ( $wpdb ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
					return $wpdb->query( "UPDATE `{$wpdb->prefix}segurium_scan_history` SET files_found = files_scanned WHERE files_found = 0 AND files_scanned > 0" );
				}
			);
		}

		// scan_history grew `threats_found` + `threats_cleaned`
		// columns so the scan-summary line is a frozen property of the scan,
		// not recomputed at read time. Backfill historical rows from the
		// scan_findings COUNT + JOIN-to-file_state logic that previously
		// answered "X threats, Y cleaned" at display time.
		if ( 'scan_history' === $logical && $from > 0 && $from < 5 && $to >= 5 ) {
			self::run_scan_history_v5_backfill();
		}

		if ( 'file_state' === $logical && 0 === $from && $to >= 1 ) {
			if ( ! self::table_exists( 'scan_findings' ) || ! self::table_exists( 'file_state' ) ) {
				return;
			}
			// Backfill: one row per file_path_hash, taking the latest
			// scan_findings row. INSERT IGNORE so a partial rerun is safe.
			self::with_suppressed_errors(
				static function () use ( $wpdb ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
					return $wpdb->query( "INSERT IGNORE INTO `{$wpdb->prefix}segurium_file_state` (file_path, file_path_hash, current_status, current_sha256, verdict, severity, detector, last_scan_uuid, backup_id, sha256_clean, last_seen_at, resolved_at, created_at, updated_at) SELECT f.file_path, f.file_path_hash, f.status, f.sha256, f.verdict, f.severity, f.detector, f.scan_uuid, f.backup_id, f.sha256_clean, f.created_at, f.resolved_at, f.created_at, f.created_at FROM `{$wpdb->prefix}segurium_scan_findings` f INNER JOIN (SELECT file_path_hash, MAX(id) AS max_id FROM `{$wpdb->prefix}segurium_scan_findings` GROUP BY file_path_hash) m ON m.max_id = f.id" );
				}
			);
		}
	}

	/**
	 * Backfill the v5 scan_history counters from the legacy
	 * read-time logic (COUNT scan_findings; JOIN cured file_state). Public
	 * so tests can exercise it without re-running the full migration.
	 *
	 * @return int Number of rows updated.
	 */
	public static function run_scan_history_v5_backfill(): int {
		global $wpdb;
		if ( ! self::table_exists( 'scan_history' ) || ! self::table_exists( 'scan_findings' ) ) {
			return 0;
		}
		$sh = $wpdb->prefix . 'segurium_scan_history';
		$sf = $wpdb->prefix . 'segurium_scan_findings';
		$fs = $wpdb->prefix . 'segurium_file_state';

		$has_file_state = self::table_exists( 'file_state' );

		// One-shot transition: gated by `from > 0 && from < 5 && to >= 5`
		// in run_post_migration(), so this runs at most once per install
		// (the v4 → v5 boundary). No WHERE guard on h.* — guarding on
		// "both columns are 0" would silently skip rows where finalize_history
		// already raced in to populate threats_found during the same
		// upgrade request, leaving threats_cleaned stuck at the DEFAULT 0.
		// Table identifiers are bound through the %i placeholder (WP 6.2+)
		// so each call site stays prepared — no interpolation,
		// no last-resort phpcs:ignore. prepare() is inlined into query() so
		// the wporg prepared-SQL classifier can trace the call.
		if ( $has_file_state ) {
			$result = self::with_suppressed_errors(
				static function () use ( $wpdb, $sh, $sf, $fs ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
					return $wpdb->query(
						$wpdb->prepare(
							'UPDATE %i h SET '
								. ' h.threats_found = (SELECT COUNT(*) FROM %i f WHERE f.scan_uuid = h.scan_uuid), '
								. ' h.threats_cleaned = (SELECT COUNT(*) FROM %i f INNER JOIN %i s '
								. '  ON s.file_path_hash = f.file_path_hash WHERE f.scan_uuid = h.scan_uuid AND s.current_status = %s)',
							$sh,
							$sf,
							$sf,
							$fs,
							'cured'
						)
					);
				}
			);
		} else {
			$result = self::with_suppressed_errors(
				static function () use ( $wpdb, $sh, $sf ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
					return $wpdb->query(
						$wpdb->prepare(
							'UPDATE %i h SET '
								. ' h.threats_found = (SELECT COUNT(*) FROM %i f WHERE f.scan_uuid = h.scan_uuid)',
							$sh,
							$sf
						)
					);
				}
			);
		}

		return false === $result ? 0 : (int) $result;
	}

	/**
	 * Drop every registered table + clear the schema-version map.
	 *
	 * Only called from uninstall.php.
	 *
	 * @return int Number of tables dropped.
	 */
	public static function drop_all(): int {
		global $wpdb;
		$dropped = 0;
		foreach ( Segurium_Storage_Schema_Registry::logical_names() as $logical ) {
			$result = self::drop_logical_table( (string) $logical );
			if ( false !== $result ) {
				++$dropped;
			}
		}
		Segurium_Storage_Settings::delete( self::VERSION_OPTION );
		return $dropped;
	}

	/**
	 * DROP TABLE IF EXISTS for a single logical table.
	 *
	 * Hard-coded per-logical dispatch so the SQL strings remain
	 * literal interpolations of `$wpdb->prefix` + a fixed suffix.
	 * Unknown logicals (not registered in the schema registry) yield
	 * `false` so the caller can detect the miss without firing an
	 * unsafe dynamic DROP TABLE.
	 *
	 * @param string $logical Logical table name.
	 * @return mixed Result of $wpdb->query, or false when unknown.
	 */
	private static function drop_logical_table( string $logical ) {
		global $wpdb;
		switch ( $logical ) {
			case 'integrity_issues':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_integrity_issues`" );
			case 'scan_history':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_scan_history`" );
			case 'scan_findings':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_scan_findings`" );
			case 'file_state':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_file_state`" );
			case 'activity_log':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_activity_log`" );
			case 'ip_list':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_ip_list`" );
			case 'stats_daily':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_stats_daily`" );
			case 'runtime_kv':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_runtime_kv`" );
			case 'async_pending':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_async_pending`" );
			case 'self_check_history':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_self_check_history`" );
			case 'scheduled_scan_log':
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
				return $wpdb->query( "DROP TABLE IF EXISTS `{$wpdb->prefix}segurium_scheduled_scan_log`" );
		}
		return false;
	}

	/**
	 * Insert a row.
	 *
	 * @param string               $logical Logical table.
	 * @param array<string, mixed> $data    Column values.
	 * @return int Inserted id.
	 * @throws Segurium_Storage_Exception When the insert fails.
	 */
	public static function insert( string $logical, array $data ): int {
		global $wpdb;
		$result = self::with_suppressed_errors(
			static function () use ( $wpdb, $logical, $data ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				return $wpdb->insert( self::name( $logical ), $data );
			}
		);
		if ( false === $result ) {
			throw new Segurium_Storage_Exception( 'insert failed for ' . esc_html( $logical ) . ': ' . esc_html( $wpdb->last_error ) );
		}
		return (int) $wpdb->insert_id;
	}

	/**
	 * Update rows matching $where.
	 *
	 * @param string               $logical Logical table.
	 * @param array<string, mixed> $data    New column values.
	 * @param array<string, mixed> $where   WHERE criteria.
	 * @return int Rows affected.
	 * @throws Segurium_Storage_Exception When the update fails.
	 */
	public static function update( string $logical, array $data, array $where ): int {
		global $wpdb;
		$result = self::with_suppressed_errors(
			static function () use ( $wpdb, $logical, $data, $where ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				return $wpdb->update( self::name( $logical ), $data, $where );
			}
		);
		if ( false === $result ) {
			throw new Segurium_Storage_Exception( 'update failed for ' . esc_html( $logical ) . ': ' . esc_html( $wpdb->last_error ) );
		}
		return (int) $result;
	}

	/**
	 * Delete rows matching $where.
	 *
	 * @param string               $logical Logical table.
	 * @param array<string, mixed> $where   WHERE criteria.
	 * @return int Rows deleted.
	 * @throws Segurium_Storage_Exception When the delete fails.
	 */
	public static function delete( string $logical, array $where ): int {
		global $wpdb;
		$result = self::with_suppressed_errors(
			static function () use ( $wpdb, $logical, $where ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
				return $wpdb->delete( self::name( $logical ), $where );
			}
		);
		if ( false === $result ) {
			throw new Segurium_Storage_Exception( 'delete failed for ' . esc_html( $logical ) . ': ' . esc_html( $wpdb->last_error ) );
		}
		return (int) $result;
	}

	/**
	 * INSERT … ON DUPLICATE KEY UPDATE using a unique-key tuple.
	 *
	 * $unique_by must be keys present in $data that together form a UNIQUE
	 * index on the target table. The matching rows are updated with every
	 * non-key column in $data.
	 *
	 * @param string               $logical   Logical table.
	 * @param array<string, mixed> $data      Row to upsert.
	 * @param array<string>        $unique_by Column names forming the unique key.
	 * @return int Inserted id on insert, 0 on update.
	 * @throws Segurium_Storage_Exception When the upsert fails.
	 */
	public static function upsert( string $logical, array $data, array $unique_by ): int {
		global $wpdb;

		if ( empty( $data ) || empty( $unique_by ) ) {
			throw new Segurium_Storage_Exception( 'upsert requires data and unique_by' );
		}
		foreach ( $unique_by as $key ) {
			if ( ! array_key_exists( $key, $data ) ) {
				throw new Segurium_Storage_Exception( 'upsert unique_by column missing from data: ' . esc_html( $key ) );
			}
		}

		$cols         = array_keys( $data );
		$placeholders = array();
		$values       = array();
		foreach ( $cols as $col ) {
			$placeholders[] = self::placeholder_for( $data[ $col ] );
			$values[]       = $data[ $col ];
		}

		$update_cols = array_values( array_diff( $cols, $unique_by ) );
		$table       = self::name( $logical );
		if ( empty( $update_cols ) ) {
			// Nothing to update — fall back to INSERT IGNORE semantics.
			$insert_sql = 'INSERT IGNORE INTO %i (`' . implode( '`,`', $cols ) . '`) VALUES (' . implode( ',', $placeholders ) . ')';
			$result     = self::with_suppressed_errors(
				static function () use ( $wpdb, $insert_sql, $table, $values ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL template uses %i for table and hard-coded column names; values + table go through $wpdb->prepare().
					return $wpdb->query( $wpdb->prepare( $insert_sql, array_merge( array( $table ), $values ) ) );
				}
			);
			if ( false === $result ) {
				throw new Segurium_Storage_Exception( 'upsert failed for ' . esc_html( $logical ) . ': ' . esc_html( $wpdb->last_error ) );
			}
			return (int) $wpdb->insert_id;
		}

		$update_frags = array();
		foreach ( $update_cols as $col ) {
			$update_frags[] = '`' . $col . '` = VALUES(`' . $col . '`)';
		}

		$sql = 'INSERT INTO %i (`' . implode( '`,`', $cols ) . '`) VALUES ('
			. implode( ',', $placeholders ) . ') ON DUPLICATE KEY UPDATE ' . implode( ',', $update_frags );

		$result = self::with_suppressed_errors(
			static function () use ( $wpdb, $sql, $table, $values ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL template uses %i for table and hard-coded column names; values + table go through $wpdb->prepare().
				return $wpdb->query( $wpdb->prepare( $sql, array_merge( array( $table ), $values ) ) );
			}
		);
		if ( false === $result ) {
			throw new Segurium_Storage_Exception( 'upsert failed for ' . esc_html( $logical ) . ': ' . esc_html( $wpdb->last_error ) );
		}
		return (int) $wpdb->insert_id;
	}

	/**
	 * Multi-row INSERT … ON DUPLICATE KEY UPDATE in bounded statements.
	 *
	 * Lets the realtime snapshot reconcile persist a whole
	 * chunk of files in one statement (≈100× fewer queries than per-row
	 * upsert at 100K+ files). Every row must carry the same columns in the
	 * same order. Non-unique columns are refreshed from VALUES() on conflict.
	 *
	 * @param string                           $logical   Logical table.
	 * @param array<int, array<string, mixed>> $rows      Rows (uniform keys).
	 * @param array<string>                    $unique_by Columns forming the unique key.
	 * @param int                              $chunk     Max rows per statement.
	 * @return int Sum of affected-row counts.
	 * @throws Segurium_Storage_Exception When a batch fails or rows are malformed.
	 */
	public static function upsert_bulk( string $logical, array $rows, array $unique_by, int $chunk = 500 ): int {
		global $wpdb;

		if ( empty( $rows ) ) {
			return 0;
		}
		if ( empty( $unique_by ) ) {
			throw new Segurium_Storage_Exception( 'upsert_bulk requires unique_by' );
		}
		if ( $chunk < 1 ) {
			$chunk = 1;
		}

		$cols = array_keys( reset( $rows ) );
		foreach ( $unique_by as $key ) {
			if ( ! in_array( $key, $cols, true ) ) {
				throw new Segurium_Storage_Exception( 'upsert_bulk unique_by column missing from rows: ' . esc_html( $key ) );
			}
		}
		$update_cols = array_values( array_diff( $cols, $unique_by ) );
		if ( empty( $update_cols ) ) {
			$update_cols = $cols; // No non-key columns — make conflicts a harmless self-update.
		}

		$col_list     = '`' . implode( '`,`', $cols ) . '`';
		$update_frags = array();
		foreach ( $update_cols as $col ) {
			$update_frags[] = '`' . $col . '` = VALUES(`' . $col . '`)';
		}
		$table = self::name( $logical );

		$total = 0;
		foreach ( array_chunk( $rows, $chunk ) as $batch ) {
			$row_placeholders = array();
			$values           = array();
			foreach ( $batch as $row ) {
				$marks = array();
				foreach ( $cols as $col ) {
					if ( ! array_key_exists( $col, $row ) ) {
						throw new Segurium_Storage_Exception( 'upsert_bulk row missing column: ' . esc_html( $col ) );
					}
					$marks[]  = self::placeholder_for( $row[ $col ] );
					$values[] = $row[ $col ];
				}
				$row_placeholders[] = '(' . implode( ',', $marks ) . ')';
			}

			$sql = 'INSERT INTO %i (' . $col_list . ') VALUES '
				. implode( ',', $row_placeholders )
				. ' ON DUPLICATE KEY UPDATE ' . implode( ',', $update_frags );

			$result = self::with_suppressed_errors(
				static function () use ( $wpdb, $sql, $table, $values ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL template uses %i for table and hard-coded column names; values + table go through $wpdb->prepare().
					return $wpdb->query( $wpdb->prepare( $sql, array_merge( array( $table ), $values ) ) );
				}
			);
			if ( false === $result ) {
				throw new Segurium_Storage_Exception( 'upsert_bulk failed for ' . esc_html( $logical ) . ': ' . esc_html( $wpdb->last_error ) );
			}
			$total += (int) $result;
		}
		return $total;
	}

	/**
	 * Run a SELECT with {{table}} placeholder replaced by the physical name.
	 *
	 * Caller owns the query body (WHERE / ORDER BY / LIMIT) — we don't wrap a
	 * DSL around $wpdb. Values in $args are bound via $wpdb->prepare.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query with {{table}} placeholder and %s/%d/%f marks.
	 * @param array<mixed> $args     prepare() args.
	 * @param string       $output   OBJECT|ARRAY_A|ARRAY_N.
	 * @return array<mixed>
	 */
	public static function get_results( string $logical, string $sql_body, array $args = array(), string $output = OBJECT ): array {
		$runner = new Segurium_Storage_Tables_Query( self::substitute_table( $sql_body ), self::name( $logical ) );
		$result = self::with_suppressed_errors(
			static function () use ( $runner, $args, $output ) {
				return $runner->run_get_results( $args, $output );
			}
		);
		return is_array( $result ) ? $result : array();
	}

	/**
	 * SELECT a single row.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query with {{table}} placeholder.
	 * @param array<mixed> $args     prepare() args.
	 * @param string       $output   OBJECT|ARRAY_A|ARRAY_N.
	 * @return mixed Row or null.
	 */
	public static function get_row( string $logical, string $sql_body, array $args = array(), string $output = OBJECT ) {
		$runner = new Segurium_Storage_Tables_Query( self::substitute_table( $sql_body ), self::name( $logical ) );
		return self::with_suppressed_errors(
			static function () use ( $runner, $args, $output ) {
				return $runner->run_get_row( $args, $output );
			}
		);
	}

	/**
	 * SELECT a single scalar.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query with {{table}} placeholder.
	 * @param array<mixed> $args     prepare() args.
	 * @return mixed
	 */
	public static function get_var( string $logical, string $sql_body, array $args = array() ) {
		$runner = new Segurium_Storage_Tables_Query( self::substitute_table( $sql_body ), self::name( $logical ) );
		return self::with_suppressed_errors(
			static function () use ( $runner, $args ) {
				return $runner->run_get_var( $args );
			}
		);
	}

	/**
	 * SELECT a single column.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query with {{table}} placeholder.
	 * @param array<mixed> $args     prepare() args.
	 * @return array<mixed>
	 */
	public static function get_col( string $logical, string $sql_body, array $args = array() ): array {
		$runner = new Segurium_Storage_Tables_Query( self::substitute_table( $sql_body ), self::name( $logical ) );
		$result = self::with_suppressed_errors(
			static function () use ( $runner, $args ) {
				return $runner->run_get_col( $args );
			}
		);
		return is_array( $result ) ? $result : array();
	}

	/**
	 * Remove rows older than $ts on the given column.
	 *
	 * @param string $logical Logical table.
	 * @param int    $ts      Unix cutoff. Rows with $col < $ts are deleted.
	 * @param string $col     Column name; defaults to the registered prune column.
	 * @return int Rows affected.
	 */
	public static function prune_older_than( string $logical, int $ts, string $col = '' ): int {
		global $wpdb;
		if ( '' === $col ) {
			$entry = Segurium_Storage_Schema_Registry::get( $logical );
			$col   = null !== $entry ? (string) $entry['prune_column'] : 'created_at';
		}
		$table  = self::name( $logical );
		$sql    = 'DELETE FROM %i WHERE `' . $col . '` < %d';
		$result = self::with_suppressed_errors(
			static function () use ( $wpdb, $sql, $table, $ts ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL template uses %i for table and hard-coded column name; values + table go through $wpdb->prepare().
				return $wpdb->query( $wpdb->prepare( $sql, array( $table, $ts ) ) );
			}
		);
		return false === $result ? 0 : (int) $result;
	}

	/**
	 * Delete every row matching `$col = $val`, in `$chunk`-sized batches.
	 *
	 * A scan teardown / seal can have up to ~1M pending rows
	 * to remove. A single unbounded `DELETE` would build one giant
	 * transaction (huge undo log, long row-lock window). Looping a
	 * `LIMIT`-bounded delete keeps each statement small and lets InnoDB
	 * reclaim space between batches.
	 *
	 * Both the table and the column go through the `%i` identifier
	 * placeholder and the value through `%s`, so the whole statement is
	 * `$wpdb->prepare()`d — no string interpolation.
	 *
	 * @param string $logical Logical table.
	 * @param string $col     Column to match (bound as a `%i` identifier).
	 * @param string $val     Value the column is compared against.
	 * @param int    $chunk   Max rows per statement (clamped to 1..100000).
	 * @param string $op      Comparison operator: `<>` selects the inequality
	 *                        template (generation sweep); any other
	 *                        value uses equality. Each maps to a fixed literal
	 *                        template, so the operator is never interpolated.
	 * @return int Total rows deleted.
	 */
	public static function delete_chunked( string $logical, string $col, string $val, int $chunk = 5000, string $op = '=' ): int {
		global $wpdb;
		if ( '' === $col ) {
			return 0;
		}
		if ( $chunk < 1 ) {
			$chunk = 1;
		} elseif ( $chunk > 100000 ) {
			$chunk = 100000;
		}
		$table  = self::name( $logical );
		$is_neq = ( '<>' === $op );
		$total  = 0;
		do {
			// Each branch passes a fully-literal template straight into
			// prepare() (the `<>` variant is the generation
			// sweep; anything else uses equality). Keeping the operator out
			// of any variable means prepare()'s first argument is always a
			// string literal — provably prepared, no NotPrepared /
			// UnescapedDBParameter exposure, no need for a PreparedSQL pragma.
			$affected = self::with_suppressed_errors(
				static function () use ( $wpdb, $is_neq, $table, $col, $val, $chunk ) {
					if ( $is_neq ) {
						// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table + column bound via %i, value via %s, all through $wpdb->prepare().
						return $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE %i <> %s LIMIT %d', array( $table, $col, $val, $chunk ) ) );
					}
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- table + column bound via %i, value via %s, all through $wpdb->prepare().
					return $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE %i = %s LIMIT %d', array( $table, $col, $val, $chunk ) ) );
				}
			);
			if ( false === $affected ) {
				break;
			}
			$affected = (int) $affected;
			$total   += $affected;
		} while ( $affected >= $chunk );
		return $total;
	}

	/**
	 * Pick a safe prepare() placeholder for a PHP value.
	 *
	 * @param mixed $value Value that will be bound.
	 * @return string Placeholder token.
	 */
	private static function placeholder_for( $value ): string {
		if ( is_int( $value ) ) {
			return '%d';
		}
		if ( is_float( $value ) ) {
			return '%f';
		}
		return '%s';
	}

	/**
	 * Substitute the {{table}} placeholder with the `%i` identifier
	 * placeholder for $wpdb->prepare(). The runner then prepends the
	 * physical table name to the args list once per placeholder.
	 *
	 * Note: `%i` is a WP 6.2+ feature; readme.txt 'Requires at least' is
	 * pinned to 6.2 for this reason.
	 *
	 * @param string $sql_body SQL body.
	 * @return string
	 */
	private static function substitute_table( string $sql_body ): string {
		return str_replace( '{{table}}', '%i', $sql_body );
	}
}

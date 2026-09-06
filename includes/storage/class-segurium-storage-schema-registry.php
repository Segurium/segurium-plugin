<?php
/**
 * Schema registry for custom tables.
 *
 * Stores per-table CREATE SQL, current version, and the column used for
 * `table_prune_older_than`. The installer (Segurium_Storage_Tables) compares
 * registered versions against the stored versions in the segurium_schema_versions
 * option and runs dbDelta when they differ.
 *
 * SQL templates follow dbDelta's parsing rules: single-space column definitions,
 * `PRIMARY KEY  (…)` with two spaces, one column per line.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Table schema registry.
 */
class Segurium_Storage_Schema_Registry {

	/**
	 * Registered tables.
	 *
	 * Each entry: [ 'sql' => $create_sql_template, 'version' => int,
	 *               'prune_column' => string ].
	 *
	 * The SQL template uses the {prefix} placeholder in place of $wpdb->prefix.
	 * Charset/collation are appended by the installer so table_install_all()
	 * doesn't have to know the target MySQL version.
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private static $tables = array();

	/**
	 * Register a single logical table.
	 *
	 * @param string $logical      Logical name (without the segurium_ prefix).
	 * @param string $sql_template CREATE TABLE SQL with {prefix} placeholder.
	 * @param int    $version      Schema version (monotonically increasing).
	 * @param string $prune_column Column used by table_prune_older_than.
	 */
	public static function register( string $logical, string $sql_template, int $version, string $prune_column = 'created_at' ): void {
		self::$tables[ $logical ] = array(
			'sql'          => $sql_template,
			'version'      => $version,
			'prune_column' => $prune_column,
		);
	}

	/**
	 * Return the registered logical names.
	 *
	 * @return array<string>
	 */
	public static function logical_names(): array {
		return array_keys( self::$tables );
	}

	/**
	 * Return all registered entries.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function all(): array {
		return self::$tables;
	}

	/**
	 * Return one entry or null if unknown.
	 *
	 * @param string $logical Logical name.
	 * @return array<string, mixed>|null
	 */
	public static function get( string $logical ): ?array {
		return self::$tables[ $logical ] ?? null;
	}

	/**
	 * Wipe the registry. Used by tests that need a fresh state.
	 */
	public static function reset(): void {
		self::$tables = array();
	}

	/**
	 * Register every Stage-1 table. Called once by the main façade boot().
	 */
	public static function boot(): void {
		self::register( 'integrity_issues', self::sql_integrity_issues(), 2, 'created_at' );
		self::register( 'scan_history', self::sql_scan_history(), 5, 'started_at' );
		self::register( 'scan_findings', self::sql_scan_findings(), 3, 'created_at' );
		self::register( 'file_state', self::sql_file_state(), 1, 'updated_at' );
		self::register( 'activity_log', self::sql_activity_log(), 1, 'created_at' );
		self::register( 'ip_list', self::sql_ip_list(), 2, 'created_at' );
		self::register( 'stats_daily', self::sql_stats_daily(), 1, 'day' );
		self::register( 'runtime_kv', self::sql_runtime_kv(), 1, 'updated_at' );
		self::register( 'async_pending', self::sql_async_pending(), 1, 'created_at' );
		self::register( 'realtime_snapshot', self::sql_realtime_snapshot(), 2, 'updated_at' );
		self::register( 'self_check_history', self::sql_self_check_history(), 1, 'created_at' );
		self::register( 'scheduled_scan_log', self::sql_scheduled_scan_log(), 1, 'created_at' );
	}

	/** SQL for the integrity_issues table. */
	private static function sql_integrity_issues(): string {
		return "CREATE TABLE {prefix}segurium_integrity_issues (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			comp_type VARCHAR(10) NOT NULL,
			comp_slug VARCHAR(191) NOT NULL,
			comp_version VARCHAR(50) NOT NULL,
			comp_name VARCHAR(191) NOT NULL,
			file_path VARCHAR(500) NOT NULL,
			file_path_hash CHAR(64) NOT NULL,
			verdict VARCHAR(20) NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'open',
			sha256 CHAR(64) NOT NULL DEFAULT '',
			is_malicious TINYINT UNSIGNED NOT NULL DEFAULT 0,
			backup_id VARCHAR(191) DEFAULT NULL,
			created_at INT UNSIGNED NOT NULL,
			fixed_at INT UNSIGNED DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_comp_file (comp_type, comp_slug, file_path_hash),
			KEY idx_status (status, created_at),
			KEY idx_comp (comp_type, comp_slug),
			KEY idx_created (created_at)
		)";
	}

	/** SQL for the scan_history table. */
	private static function sql_scan_history(): string {
		return 'CREATE TABLE {prefix}segurium_scan_history (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			scan_uuid CHAR(36) NOT NULL,
			scan_type VARCHAR(20) NOT NULL,
			status VARCHAR(20) NOT NULL,
			started_at INT UNSIGNED NOT NULL,
			finished_at INT UNSIGNED DEFAULT NULL,
			files_found INT UNSIGNED NOT NULL DEFAULT 0,
			files_scanned INT UNSIGNED NOT NULL DEFAULT 0,
			files_failed INT UNSIGNED NOT NULL DEFAULT 0,
			files_skipped INT UNSIGNED NOT NULL DEFAULT 0,
			threats_found INT UNSIGNED NOT NULL DEFAULT 0,
			threats_cleaned INT UNSIGNED NOT NULL DEFAULT 0,
			trigger_source VARCHAR(20) NOT NULL,
			error_code VARCHAR(40) DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_scan_uuid (scan_uuid),
			KEY idx_started (started_at),
			KEY idx_status (status, started_at)
		)';
	}

	/** SQL for the scan_findings table. */
	private static function sql_scan_findings(): string {
		return 'CREATE TABLE {prefix}segurium_scan_findings (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			scan_uuid CHAR(36) NOT NULL,
			file_path VARCHAR(500) NOT NULL,
			file_path_hash CHAR(64) NOT NULL,
			sha256 CHAR(64) NOT NULL,
			verdict VARCHAR(20) NOT NULL,
			severity TINYINT NOT NULL DEFAULT 0,
			status VARCHAR(20) NOT NULL DEFAULT \'open\',
			backup_id VARCHAR(191) DEFAULT NULL,
			sha256_clean CHAR(64) DEFAULT NULL,
			detector VARCHAR(40) NOT NULL,
			created_at INT UNSIGNED NOT NULL,
			resolved_at INT UNSIGNED DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_scan_file (scan_uuid, file_path_hash),
			KEY idx_scan (scan_uuid),
			KEY idx_status (status, created_at),
			KEY idx_sha256 (sha256),
			KEY idx_file_hash (file_path_hash)
		)';
	}

	/**
	 * SQL for the file_state table.
	 *
	 * Canonical current-state projection keyed by file_path_hash. The
	 * scan_findings table is an append-only event log; file_state is the
	 * only source UI reads for "current status per file" and the only
	 * source the cleanup/restore/ignore mutators write to.
	 */
	private static function sql_file_state(): string {
		return "CREATE TABLE {prefix}segurium_file_state (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			file_path VARCHAR(500) NOT NULL,
			file_path_hash CHAR(64) NOT NULL,
			current_status VARCHAR(20) NOT NULL DEFAULT 'open',
			current_sha256 CHAR(64) NOT NULL DEFAULT '',
			verdict VARCHAR(20) NOT NULL DEFAULT '',
			severity TINYINT NOT NULL DEFAULT 0,
			detector VARCHAR(40) NOT NULL DEFAULT '',
			last_scan_uuid CHAR(36) DEFAULT NULL,
			backup_id VARCHAR(191) DEFAULT NULL,
			sha256_clean CHAR(64) DEFAULT NULL,
			last_seen_at INT UNSIGNED NOT NULL,
			resolved_at INT UNSIGNED DEFAULT NULL,
			created_at INT UNSIGNED NOT NULL,
			updated_at INT UNSIGNED NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_file_hash (file_path_hash),
			KEY idx_status_updated (current_status, updated_at),
			KEY idx_updated (updated_at)
		)";
	}

	/** SQL for the activity_log table. */
	private static function sql_activity_log(): string {
		return 'CREATE TABLE {prefix}segurium_activity_log (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			event_type VARCHAR(40) NOT NULL,
			severity TINYINT NOT NULL DEFAULT 0,
			actor_ip BINARY(16) DEFAULT NULL,
			actor_user BIGINT UNSIGNED DEFAULT NULL,
			subject VARCHAR(191) DEFAULT NULL,
			data_json MEDIUMTEXT,
			created_at INT UNSIGNED NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_type_time (event_type, created_at),
			KEY idx_time (created_at),
			KEY idx_ip_time (actor_ip, created_at)
		)';
	}

	/** SQL for the ip_list table. */
	private static function sql_ip_list(): string {
		return "CREATE TABLE {prefix}segurium_ip_list (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip BINARY(16) NOT NULL,
			cidr_bits TINYINT UNSIGNED NOT NULL DEFAULT 128,
			list_type VARCHAR(20) NOT NULL,
			reason VARCHAR(191) DEFAULT NULL,
			source VARCHAR(40) NOT NULL DEFAULT 'manual',
			hits INT UNSIGNED NOT NULL DEFAULT 0,
			created_at INT UNSIGNED NOT NULL,
			expires_at INT UNSIGNED DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_ip_cidr_type (ip, cidr_bits, list_type),
			KEY idx_type_exp (list_type, expires_at),
			KEY idx_exp (expires_at)
		)";
	}

	/** SQL for the stats_daily table. */
	private static function sql_stats_daily(): string {
		return 'CREATE TABLE {prefix}segurium_stats_daily (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			day DATE NOT NULL,
			scope VARCHAR(40) NOT NULL,
			metric_key VARCHAR(191) NOT NULL,
			value BIGINT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_day_scope_key (day, scope, metric_key),
			KEY idx_day (day),
			KEY idx_scope_day (scope, day)
		)';
	}

	/** SQL for the runtime_kv table. */
	private static function sql_runtime_kv(): string {
		return 'CREATE TABLE {prefix}segurium_runtime_kv (
			kv_key VARCHAR(191) NOT NULL,
			kv_value MEDIUMBLOB NOT NULL,
			expires_at INT UNSIGNED DEFAULT NULL,
			updated_at INT UNSIGNED NOT NULL,
			PRIMARY KEY  (kv_key),
			KEY idx_expires (expires_at)
		)';
	}

	/**
	 * SQL for the async_pending table.
	 *
	 * One row per submitted-but-unverdicted file, replacing
	 * the per-scan `async_scan:pending:{scan_id}` runtime_kv JSON blob. The
	 * blob was rewritten whole on every submit batch and every drained
	 * verdict row (O(n²) on the unknown-file count) and capped at the 16 MB
	 * MEDIUMBLOB limit (~100-160K files), so it could never reach the 1M-file
	 * target. With a dedicated indexed table every submit / fan-out / delete
	 * is an O(log n) B-tree access and PHP never loads the whole set.
	 *
	 * PRIMARY KEY (scan_uuid, file_path_hash) makes submit idempotent (a
	 * re-submitted path is a no-op upsert, never a duplicate) and lets the
	 * drain delete by sha without a row scan. KEY (scan_uuid, sha256) fans a
	 * single content verdict out to every path that shares that hash.
	 */
	private static function sql_async_pending(): string {
		return "CREATE TABLE {prefix}segurium_async_pending (
			scan_uuid CHAR(36) NOT NULL,
			sha256 CHAR(64) NOT NULL,
			file_path VARCHAR(500) NOT NULL,
			file_path_hash CHAR(64) NOT NULL,
			detector VARCHAR(40) NOT NULL DEFAULT 'scanner',
			created_at INT UNSIGNED NOT NULL,
			PRIMARY KEY  (scan_uuid, file_path_hash),
			KEY idx_scan_sha (scan_uuid, sha256)
		)";
	}

	/**
	 * SQL for the realtime_snapshot table.
	 *
	 * The realtime FIM baseline is one row per file, keyed by
	 * file_path_hash, instead of a single `realtime:snapshot` runtime_kv JSON
	 * blob. `generation` is a per-reconcile run marker: each cron tick stamps
	 * every surviving file with the current generation, then mark-and-sweeps
	 * rows of any other generation (the deleted files). No whole-set load, no
	 * MEDIUMBLOB / max_allowed_packet ceiling.
	 */
	private static function sql_realtime_snapshot(): string {
		return 'CREATE TABLE {prefix}segurium_realtime_snapshot (
			file_path_hash CHAR(64) NOT NULL,
			file_path VARCHAR(500) NOT NULL,
			mtime INT UNSIGNED NOT NULL,
			size BIGINT UNSIGNED NOT NULL DEFAULT 0,
			generation INT UNSIGNED NOT NULL,
			updated_at INT UNSIGNED NOT NULL,
			seen_mtime INT UNSIGNED NOT NULL DEFAULT 0,
			churn TINYINT UNSIGNED NOT NULL DEFAULT 0,
			next_check_at INT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY  (file_path_hash),
			KEY idx_generation (generation)
		)';
	}

	/** SQL for the self_check_history table. */
	private static function sql_self_check_history(): string {
		return 'CREATE TABLE {prefix}segurium_self_check_history (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			check_type VARCHAR(40) NOT NULL,
			status VARCHAR(20) NOT NULL,
			result_json MEDIUMTEXT,
			created_at INT UNSIGNED NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_type_time (check_type, created_at),
			KEY idx_time (created_at)
		)';
	}

	/** SQL for the scheduled_scan_log table. */
	private static function sql_scheduled_scan_log(): string {
		return 'CREATE TABLE {prefix}segurium_scheduled_scan_log (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			scan_uuid CHAR(36) DEFAULT NULL,
			level VARCHAR(10) NOT NULL,
			message TEXT NOT NULL,
			created_at INT UNSIGNED NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_time (created_at),
			KEY idx_scan (scan_uuid)
		)';
	}
}

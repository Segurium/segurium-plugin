<?php
/**
 * Segurium storage façade.
 *
 * Single entry point for every data operation. Feature code must never touch
 * wp_options, $wpdb, the filesystem, or the CTI client directly — everything
 * goes through Segurium_Storage::*.
 *
 * Stage 1 ships Layers 1 (settings) + 2 (custom tables). Layers 3 (filesystem
 * tmp + encrypted backups) and 4 (CTI) arrive in Stages 2 and 7 respectively.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin static façade that delegates to the per-layer backends.
 */
class Segurium_Storage {

	/**
	 * Option holding the fingerprint of the last installed schema set. Used by
	 * ensure_schema() to detect drift introduced by in-place plugin updates,
	 * which bypass register_activation_hook().
	 */
	const SCHEMA_FINGERPRINT_OPTION = 'segurium_schema_fingerprint';

	/**
	 * Whether boot() has registered the schema registry.
	 *
	 * @var bool
	 */
	private static $booted = false;

	/**
	 * Whether ensure_schema() has already run in the current request. Prevents
	 * redundant fingerprint/dbDelta work on later calls.
	 *
	 * @var bool
	 */
	private static $schema_ensured = false;

	/**
	 * Register schemas and do any cheap one-time setup. Safe to call twice.
	 */
	public static function boot(): void {
		if ( self::$booted ) {
			return;
		}
		Segurium_Storage_Schema_Registry::boot();
		Segurium_Storage_GC::boot();
		self::$booted = true;
	}

	/**
	 * Install / upgrade every registered table when the on-disk schema drifts
	 * from the code-registered schema.
	 *
	 * The register_activation_hook only fires on admin-triggered activation,
	 * so sites that update the plugin in place (the default WordPress path)
	 * never get newly-registered tables. This method self-heals that gap by
	 * comparing a fingerprint of the current schema registry against the one
	 * stored in options and invoking dbDelta when they differ.
	 *
	 * Idempotent within a single request (guarded by a static flag). Safe to
	 * call before WordPress finishes loading — the installer lazy-includes
	 * wp-admin/includes/upgrade.php.
	 *
	 * @param bool $force When true, install regardless of fingerprint match. Used by tests.
	 * @return array<string, array<string>> Per-table dbDelta messages (empty when no-op).
	 * @throws Segurium_Storage_Exception When installation fails irrecoverably.
	 */
	public static function ensure_schema( bool $force = false ): array {
		if ( self::$schema_ensured && ! $force ) {
			return array();
		}

		// boot() is required before ensure_schema() — it populates the schema
		// registry. Calling boot() directly keeps callers from forgetting.
		self::boot();

		$expected = self::schema_fingerprint();
		$stored   = (string) get_option( self::SCHEMA_FINGERPRINT_OPTION, '' );

		// Fast path: fingerprint matches AND a representative table is
		// physically present. The latter guards against DB restores or manual
		// DROPs that would otherwise leave the fingerprint lying about reality.
		if ( ! $force && $stored === $expected && '' !== $expected ) {
			$names = Segurium_Storage_Schema_Registry::logical_names();
			if ( empty( $names ) || Segurium_Storage_Tables::table_exists( (string) reset( $names ) ) ) {
				self::$schema_ensured = true;
				return array();
			}
			// Fingerprint matched but the table vanished — force reinstall.
		}

		try {
			$notes = Segurium_Storage_Tables::install_all();
		} catch ( Throwable $e ) {
			Segurium_Debug::log(
				'[segurium] ensure_schema: install_all failed: ' . esc_html( $e->getMessage() )
			);
			throw new Segurium_Storage_Exception(
				'ensure_schema: ' . esc_html( $e->getMessage() ),
				0,
				$e // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- $previous is a Throwable chain, not output.
			);
		}

		update_option( self::SCHEMA_FINGERPRINT_OPTION, $expected, true );
		self::$schema_ensured = true;

		return is_array( $notes ) ? $notes : array();
	}

	/**
	 * Reset the ensure_schema() idempotency guard. Tests only.
	 */
	public static function reset_schema_ensured(): void {
		self::$schema_ensured = false;
	}

	/**
	 * Deterministic fingerprint of the registered schema set. Changes whenever
	 * any logical table is added, removed, or version-bumped.
	 *
	 * @return string Hex-encoded SHA-256 of the sorted logical=>version map.
	 */
	private static function schema_fingerprint(): string {
		$map = array();
		foreach ( Segurium_Storage_Schema_Registry::all() as $logical => $entry ) {
			$map[ $logical ] = isset( $entry['version'] ) ? (int) $entry['version'] : 0;
		}
		ksort( $map );
		$json = wp_json_encode( $map );
		if ( false === $json ) {
			// Fallback if JSON encoding fails — still deterministic for the
			// set of logical names, losing only the version numbers.
			$json = implode( ',', array_keys( $map ) );
		}
		return hash( 'sha256', (string) $json );
	}

	// -- Layer 1: wp_options ------------------------------------------------

	/**
	 * Get an option value.
	 *
	 * @param string $key     Option name.
	 * @param mixed  $fallback Default when missing.
	 * @return mixed
	 */
	public static function setting_get( string $key, $fallback = null ) {
		return Segurium_Storage_Settings::get( $key, $fallback );
	}

	/**
	 * Set an option value. Autoload defaults to no — the allowlist in
	 * Segurium_Storage_Settings::HOT_AUTOLOAD_KEYS is the only way to opt in.
	 *
	 * @param string $key      Option name.
	 * @param mixed  $value    Value.
	 * @param bool   $autoload Hot-key override.
	 * @return bool
	 */
	public static function setting_set( string $key, $value, bool $autoload = false ): bool {
		return Segurium_Storage_Settings::set( $key, $value, $autoload );
	}

	/**
	 * Delete an option.
	 *
	 * @param string $key Option name.
	 * @return bool
	 */
	public static function setting_delete( string $key ): bool {
		return Segurium_Storage_Settings::delete( $key );
	}

	/**
	 * Typed int getter.
	 *
	 * @param string $key     Option name.
	 * @param int    $fallback Default.
	 * @return int
	 */
	public static function setting_get_int( string $key, int $fallback = 0 ): int {
		return Segurium_Storage_Settings::get_int( $key, $fallback );
	}

	/**
	 * Typed bool getter.
	 *
	 * @param string $key     Option name.
	 * @param bool   $fallback Default.
	 * @return bool
	 */
	public static function setting_get_bool( string $key, bool $fallback = false ): bool {
		return Segurium_Storage_Settings::get_bool( $key, $fallback );
	}

	/**
	 * SEGURIUM-689: whether file bodies must stay on this server.
	 *
	 * Lives on the storage façade rather than on `Segurium` because the
	 * CTI client gates `scan_submit()` on it and ships in every request
	 * tier, including the lightweight ones that never load
	 * `class-segurium.php`. Reading it through the singleton there would
	 * turn a blocked upload into a fatal.
	 *
	 * The option is semantically inverted (cloud on = on-premise off) and
	 * defaults to absent, so a site that never touched the setting keeps
	 * its file contents local. {@see Segurium::is_on_premise()} is the
	 * public accessor and delegates here.
	 *
	 * @return bool True when file bodies must not leave the server.
	 */
	public static function on_premise_mode(): bool {
		return ! self::setting_get_bool( 'segurium_cloud_detection_enabled', false );
	}

	/**
	 * Typed string getter.
	 *
	 * @param string $key     Option name.
	 * @param string $fallback Default.
	 * @return string
	 */
	public static function setting_get_string( string $key, string $fallback = '' ): string {
		return Segurium_Storage_Settings::get_string( $key, $fallback );
	}

	/**
	 * Typed array getter.
	 *
	 * @param string $key     Option name.
	 * @param array  $fallback Default.
	 * @return array
	 */
	public static function setting_get_array( string $key, array $fallback = array() ): array {
		return Segurium_Storage_Settings::get_array( $key, $fallback );
	}

	/**
	 * Delete every Segurium option. Used by uninstall.php.
	 *
	 * @return int Number of options removed.
	 */
	public static function setting_delete_all(): int {
		return Segurium_Storage_Settings::delete_all();
	}

	// -- Layer 2: custom tables ---------------------------------------------

	/**
	 * Resolve a logical table name to its physical (prefixed) name.
	 *
	 * @param string $logical Logical name.
	 * @return string
	 */
	public static function table_name( string $logical ): string {
		return Segurium_Storage_Tables::name( $logical );
	}

	/**
	 * Register a custom table. Normally only used by tests — the default
	 * schema set is registered by Segurium_Storage_Schema_Registry::boot().
	 *
	 * @param string $logical      Logical name.
	 * @param string $sql_template CREATE TABLE SQL with {prefix} placeholder.
	 * @param int    $version      Monotonic schema version.
	 * @param string $prune_column Default column for prune_older_than.
	 */
	public static function table_register( string $logical, string $sql_template, int $version, string $prune_column = 'created_at' ): void {
		Segurium_Storage_Schema_Registry::register( $logical, $sql_template, $version, $prune_column );
	}

	/**
	 * Install / upgrade every registered table.
	 *
	 * @return array<string, array<string>> Per-table dbDelta messages.
	 */
	public static function table_install_all(): array {
		self::boot();
		return Segurium_Storage_Tables::install_all();
	}

	/**
	 * Drop every registered table. Called only from uninstall.php.
	 *
	 * @return int Tables dropped.
	 */
	public static function table_drop_all(): int {
		self::boot();
		return Segurium_Storage_Tables::drop_all();
	}

	/**
	 * Insert a row.
	 *
	 * @param string               $logical Logical table.
	 * @param array<string, mixed> $data    Columns → values.
	 * @return int
	 */
	public static function table_insert( string $logical, array $data ): int {
		return Segurium_Storage_Tables::insert( $logical, $data );
	}

	/**
	 * Update rows matching $where.
	 *
	 * @param string               $logical Logical table.
	 * @param array<string, mixed> $data    New values.
	 * @param array<string, mixed> $where   WHERE criteria.
	 * @return int
	 */
	public static function table_update( string $logical, array $data, array $where ): int {
		return Segurium_Storage_Tables::update( $logical, $data, $where );
	}

	/**
	 * Delete rows matching $where.
	 *
	 * @param string               $logical Logical table.
	 * @param array<string, mixed> $where   WHERE criteria.
	 * @return int
	 */
	public static function table_delete( string $logical, array $where ): int {
		return Segurium_Storage_Tables::delete( $logical, $where );
	}

	/**
	 * Delete every row matching `$col = $val` in `$chunk`-sized batches.
	 *
	 * SEGURIUM-576: bounded-statement teardown for tables that can hold up
	 * to ~1M rows for a single scan (`async_pending`). Avoids one giant
	 * unbounded DELETE transaction.
	 *
	 * @param string $logical Logical table.
	 * @param string $col     Column to match (bound as a `%i` identifier).
	 * @param string $val     Value the column is compared against.
	 * @param int    $chunk   Max rows per statement.
	 * @param string $op      Comparison operator: `=` (default) or `<>`.
	 *                        SEGURIUM-577 uses `<>` for the generation sweep.
	 * @return int Total rows deleted.
	 */
	public static function table_delete_chunked( string $logical, string $col, string $val, int $chunk = 5000, string $op = '=' ): int {
		return Segurium_Storage_Tables::delete_chunked( $logical, $col, $val, $chunk, $op );
	}

	/**
	 * INSERT … ON DUPLICATE KEY UPDATE using $unique_by columns.
	 *
	 * @param string               $logical   Logical table.
	 * @param array<string, mixed> $data      Row.
	 * @param array<string>        $unique_by Columns forming the unique key.
	 * @return int
	 */
	public static function table_upsert( string $logical, array $data, array $unique_by ): int {
		return Segurium_Storage_Tables::upsert( $logical, $data, $unique_by );
	}

	/**
	 * Multi-row INSERT … ON DUPLICATE KEY UPDATE in bounded statements.
	 *
	 * SEGURIUM-577: one indexed write for a whole chunk of snapshot rows
	 * instead of one statement per file. Every row must share the same column
	 * set. Non-unique columns are refreshed from the incoming values on a
	 * primary/unique-key conflict.
	 *
	 * @param string                           $logical   Logical table.
	 * @param array<int, array<string, mixed>> $rows Rows to upsert (uniform keys).
	 * @param array<string>                    $unique_by Columns forming the unique key.
	 * @param int                              $chunk     Max rows per statement.
	 * @return int Rows processed (sum of affected-row counts).
	 */
	public static function table_upsert_bulk( string $logical, array $rows, array $unique_by, int $chunk = 500 ): int {
		return Segurium_Storage_Tables::upsert_bulk( $logical, $rows, $unique_by, $chunk );
	}

	/**
	 * Run a SELECT with {{table}} substituted.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query with {{table}} + %s/%d/%f marks.
	 * @param array<mixed> $args     prepare() args.
	 * @param string       $output   OBJECT|ARRAY_A|ARRAY_N.
	 * @return array<mixed>
	 */
	public static function table_get_results( string $logical, string $sql_body, array $args = array(), string $output = OBJECT ): array {
		return Segurium_Storage_Tables::get_results( $logical, $sql_body, $args, $output );
	}

	/**
	 * Single-row SELECT.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query body.
	 * @param array<mixed> $args     prepare() args.
	 * @param string       $output   OBJECT|ARRAY_A|ARRAY_N.
	 * @return mixed
	 */
	public static function table_get_row( string $logical, string $sql_body, array $args = array(), string $output = OBJECT ) {
		return Segurium_Storage_Tables::get_row( $logical, $sql_body, $args, $output );
	}

	/**
	 * Scalar SELECT.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query body.
	 * @param array<mixed> $args     prepare() args.
	 * @return mixed
	 */
	public static function table_get_var( string $logical, string $sql_body, array $args = array() ) {
		return Segurium_Storage_Tables::get_var( $logical, $sql_body, $args );
	}

	/**
	 * Single-column SELECT.
	 *
	 * @param string       $logical  Logical table.
	 * @param string       $sql_body Query body.
	 * @param array<mixed> $args     prepare() args.
	 * @return array<mixed>
	 */
	public static function table_get_col( string $logical, string $sql_body, array $args = array() ): array {
		return Segurium_Storage_Tables::get_col( $logical, $sql_body, $args );
	}

	/**
	 * Delete rows with prune column older than $ts.
	 *
	 * @param string $logical Logical table.
	 * @param int    $ts      Cutoff epoch seconds.
	 * @param string $col     Column name (defaults to registered prune column).
	 * @return int
	 */
	public static function table_prune_older_than( string $logical, int $ts, string $col = '' ): int {
		return Segurium_Storage_Tables::prune_older_than( $logical, $ts, $col );
	}

	// -- Layer 3: filesystem (tmp + encrypted rotating backups) -------------

	/**
	 * Create a fresh per-scan workspace under data_dir/tmp/.
	 *
	 * @param string $purpose Short alphanumeric/underscore tag (max 32 chars).
	 * @return string|false Absolute workspace path, or false on validation or I/O failure.
	 */
	public static function tmp_make_workspace( string $purpose ) {
		return Segurium_Storage_Tmp::make_workspace( $purpose );
	}

	/**
	 * Atomically write $data to $relpath inside an existing workspace.
	 *
	 * @param string $workspace Path returned by {@see tmp_make_workspace()}.
	 * @param string $relpath   Relative path (no absolute prefix, no ..).
	 * @param string $data      Bytes to write.
	 */
	public static function tmp_write( string $workspace, string $relpath, string $data ): bool {
		return Segurium_Storage_Tmp::write( $workspace, $relpath, $data );
	}

	/**
	 * Read a file from a workspace, bounded by the filterable max-read size.
	 *
	 * @param string $workspace Workspace path.
	 * @param string $relpath   Relative path.
	 * @return string|null Contents or null on any error / oversized file.
	 */
	public static function tmp_read( string $workspace, string $relpath ): ?string {
		return Segurium_Storage_Tmp::read( $workspace, $relpath );
	}

	/**
	 * Destroy a workspace (recursive unlink).
	 *
	 * @param string $workspace Absolute workspace path.
	 */
	public static function tmp_destroy( string $workspace ): bool {
		return Segurium_Storage_Tmp::destroy( $workspace );
	}

	/**
	 * Remove workspaces whose files are all older than $max_age seconds.
	 *
	 * @param int $max_age Age threshold; 0 removes every workspace.
	 * @return int Number of workspaces removed.
	 */
	public static function tmp_gc( int $max_age = DAY_IN_SECONDS ): int {
		return Segurium_Storage_Tmp::gc( $max_age );
	}

	/**
	 * Register (or update) a backup bucket with rotation caps.
	 *
	 * @param string               $bucket Bucket name (1..40 chars, [a-z0-9_]).
	 * @param array<string, mixed> $caps   Accepts `max_count` and `max_bytes`.
	 */
	public static function backup_register_bucket( string $bucket, array $caps = array() ): bool {
		return Segurium_Storage_Backup::register_bucket( $bucket, $caps );
	}

	/**
	 * Store a gzipped + AES-256-GCM-encrypted snapshot in a bucket.
	 *
	 * @param string               $bucket            Bucket name.
	 * @param string               $ref               Free-form identifier of the backed-up object.
	 * @param string               $content           Plaintext bytes.
	 * @param array<string, mixed> $extra_meta        Caller-provided metadata written to the sidecar.
	 * @param int                  $compression_level gzencode level, 1..9 (default 6).
	 * @return string backup_id.
	 * @throws Segurium_Storage_Exception On I/O / encryption failure.
	 */
	public static function backup_store( string $bucket, string $ref, string $content, array $extra_meta = array(), int $compression_level = 6 ): string {
		return Segurium_Storage_Backup::store( $bucket, $ref, $content, $extra_meta, $compression_level );
	}

	/**
	 * Decrypt and return the plaintext of a stored backup. Null on any failure.
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier returned by {@see backup_store()}.
	 */
	public static function backup_restore( string $bucket, string $backup_id ): ?string {
		return Segurium_Storage_Backup::restore( $bucket, $backup_id );
	}

	/**
	 * Decrypt-and-return with a structured failure reason. See
	 * {@see Segurium_Storage_Backup::restore_detailed()} for the reason tag set.
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier returned by {@see backup_store()}.
	 * @return array{content: ?string, reason: ?string}
	 */
	public static function backup_restore_detailed( string $bucket, string $backup_id ): array {
		return Segurium_Storage_Backup::restore_detailed( $bucket, $backup_id );
	}

	/**
	 * True iff the backup is still on disk (envelope + sidecar both present).
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier returned by {@see backup_store()}.
	 */
	public static function backup_exists( string $bucket, string $backup_id ): bool {
		return Segurium_Storage_Backup::exists( $bucket, $backup_id );
	}

	/**
	 * List sidecars (meta.json contents) in a bucket, newest first.
	 *
	 * @param string $bucket Bucket name.
	 * @return array<int, array<string, mixed>>
	 */
	public static function backup_list( string $bucket ): array {
		return Segurium_Storage_Backup::list_backups( $bucket );
	}

	/**
	 * Merge extra key/value pairs into a backup's sidecar metadata.
	 *
	 * @param string               $bucket    Bucket name.
	 * @param string               $backup_id Identifier returned by {@see backup_store()}.
	 * @param array<string, mixed> $extra     Key/value pairs to merge.
	 * @throws Segurium_Storage_Exception On I/O failure.
	 */
	public static function backup_update_meta( string $bucket, string $backup_id, array $extra ): void {
		Segurium_Storage_Backup::update_meta( $bucket, $backup_id, $extra );
	}

	/**
	 * Delete a single backup (envelope + sidecar).
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier returned by {@see backup_store()}.
	 */
	public static function backup_delete( string $bucket, string $backup_id ): bool {
		return Segurium_Storage_Backup::delete( $bucket, $backup_id );
	}

	/**
	 * Rotate a single bucket against its registered caps.
	 *
	 * @param string $bucket Bucket name.
	 * @return int Number of backups removed.
	 */
	public static function backup_rotate( string $bucket ): int {
		return Segurium_Storage_Backup::rotate( $bucket );
	}

	/**
	 * Rotate every registered bucket and stray on-disk buckets. Called by the
	 * daily Layer 3 GC cron.
	 *
	 * @return int Total backups removed.
	 */
	public static function backup_gc(): int {
		return Segurium_Storage_Backup::gc();
	}

	/**
	 * Dry-run a rotation that would happen if `$pending_sizes` envelopes were
	 * added to the bucket. Used by the Integrity Fix-all preflight modal
	 * (SEGURIUM-279) to warn the operator before older backups get rotated out.
	 *
	 * @param string         $bucket        Bucket name.
	 * @param array<int,int> $pending_sizes Plaintext byte sizes of pending stores.
	 * @return array<string, int> See {@see Segurium_Storage_Backup::simulate_rotation()}.
	 */
	public static function backup_simulate_rotation( string $bucket, array $pending_sizes ): array {
		return Segurium_Storage_Backup::simulate_rotation( $bucket, $pending_sizes );
	}

	// -- Layer 2 helper: IP list -------------------------------------------

	/**
	 * Insert or refresh a row in the unified `ip_list` table.
	 *
	 * @param string   $ip         Printable IP.
	 * @param string   $list_type  List type tag.
	 * @param int|null $expires_at Unix seconds; null for permanent.
	 * @param string   $reason     Optional reason.
	 * @param string   $source     Source tag.
	 * @param int      $cidr_bits  Prefix length.
	 */
	public static function ip_add( string $ip, string $list_type, ?int $expires_at = null, string $reason = '', string $source = 'manual', int $cidr_bits = 128 ): bool {
		return Segurium_Storage_IP_List::add( $ip, $list_type, $expires_at, $reason, $source, $cidr_bits );
	}

	/**
	 * Remove a row from `ip_list`.
	 *
	 * @param string $ip         Printable IP.
	 * @param string $list_type  List type.
	 * @param int    $cidr_bits  Prefix length.
	 */
	public static function ip_remove( string $ip, string $list_type, int $cidr_bits = 128 ): bool {
		return Segurium_Storage_IP_List::remove( $ip, $list_type, $cidr_bits );
	}

	/**
	 * Match an IP against a list_type honouring CIDR entries.
	 *
	 * @param string $ip        Printable IP.
	 * @param string $list_type List type.
	 */
	public static function ip_match( string $ip, string $list_type ): ?array {
		return Segurium_Storage_IP_List::match( $ip, $list_type );
	}

	/**
	 * Paginated active entries of a list_type.
	 *
	 * @param string $list_type List type.
	 * @param int    $limit     Rows per page.
	 * @param int    $offset    Offset.
	 */
	public static function ip_list( string $list_type, int $limit = 100, int $offset = 0 ): array {
		return Segurium_Storage_IP_List::list_rows( $list_type, $limit, $offset );
	}

	/**
	 * Count active entries of a list_type.
	 *
	 * @param string $list_type List type.
	 */
	public static function ip_count( string $list_type ): int {
		return Segurium_Storage_IP_List::count( $list_type );
	}

	/**
	 * Delete expired rows.
	 */
	public static function ip_gc(): int {
		return Segurium_Storage_IP_List::gc();
	}

	/**
	 * Atomic feed replacement (for trusted-proxies, geo_feed, etc).
	 *
	 * @param string $list_type List type.
	 * @param string $source    Source tag (must be a feed identifier).
	 * @param array  $entries   Array of `[ip, cidr_bits, reason, expires_at]`.
	 */
	public static function ip_replace_feed( string $list_type, string $source, array $entries ): int {
		return Segurium_Storage_IP_List::replace_feed( $list_type, $source, $entries );
	}

	// -- Layer 4: CTI remote ------------------------------------------------

	/**
	 * Lazily-constructed CTI HTTP client. Tests may inject one via
	 * {@see set_cti_client()}.
	 *
	 * @var Segurium_CTI_Client|null
	 */
	private static $cti_client = null;

	/**
	 * Return the shared CTI client, creating one on first use.
	 *
	 * @return Segurium_CTI_Client
	 */
	private static function cti_client(): Segurium_CTI_Client {
		if ( null === self::$cti_client ) {
			self::$cti_client = new Segurium_CTI_Client();
		}
		return self::$cti_client;
	}

	/**
	 * Inject a test double. Tests only.
	 *
	 * @param Segurium_CTI_Client|null $client Client instance or null to reset.
	 */
	public static function set_cti_client( $client ): void {
		self::$cti_client = $client;
	}

	/**
	 * Batch SHA-256 hash inspection.
	 *
	 * @param array  $files   Array of `[path, sha256, size, mtime]` records.
	 * @param string $scan_id Plugin-side scan UUID. Forwarded to CTI so
	 *                        per-scan analytics work; safe to omit.
	 * @return array|WP_Error Verdict rows or WP_Error on transport failure.
	 */
	public static function cti_inspect_hashes( array $files, string $scan_id = '' ) {
		return self::cti_client()->inspect( $files, $scan_id );
	}

	/**
	 * Escalate a single file body to Neo-Ray when `/v1/inspect` returned
	 * verdict 4 (Unknown).
	 *
	 * @param string $sha256        Lowercase hex SHA-256 of the body.
	 * @param string $body          Raw bytes.
	 * @param string $relative_path Site-relative path for the
	 *                               `X-Segurium-Filename` header; empty
	 *                               string suppresses the header.
	 * @return array|WP_Error Response array `{sha256, verdict}` on success,
	 *                        WP_Error otherwise.
	 */
	public static function cti_neo_ray_scan( string $sha256, string $body, string $relative_path = '' ) {
		return self::cti_client()->neo_ray_scan( $sha256, $body, $relative_path );
	}

	/**
	 * Fetch the replacement (cleaned) bytes for a malicious file by SHA-256.
	 *
	 * SEGURIUM-353: `/v1/cleanup` is now the single quota-charging point
	 * and decides server-side whether to serve cured bytes (Injection
	 * verdict) or an empty body (Malware verdict). The plugin always
	 * asks; the server picks. Paywall denial surfaces as `WP_Error`
	 * with code `paywall_quota_exceeded` (and `data` carrying the
	 * envelope) so the AJAX handler can render the modal without
	 * re-deriving the envelope shape.
	 *
	 * @param string $sha256   SHA-256 of the infected file.
	 * @param string $filename Site-relative path of the infected file
	 *                          (required by `/v1/cleanup` body schema —
	 *                          SEGURIUM-356).
	 * @param int    $ctime    Inode change time of the file
	 *                          (required by `/v1/cleanup` body schema —
	 *                          SEGURIUM-356).
	 * @return array|WP_Error On success, `array{content:string,quota:?array}`
	 *                         where `content` is the plaintext bytes (possibly
	 *                         empty for fully-malicious files) and `quota` is
	 *                         the post-charge envelope CTI echoes in the 200
	 *                         body (SEGURIUM-549; `null` when an older CTI
	 *                         build omits it). `WP_Error` on paywall /
	 *                         transport / signature / unknown-verdict failure.
	 */
	public static function cti_fetch_cleanup_file( string $sha256, string $filename, int $ctime ) {
		$result = self::cti_client()->clean( $sha256, $filename, $ctime );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		if ( ! is_array( $result ) || ! isset( $result['content'] ) ) {
			return new WP_Error( 'cti_invalid_response', __( 'Invalid cleanup response from Segurium Cloud.', 'segurium' ) );
		}

		// SEGURIUM-353: `error_code` is the wire-level status returned
		// by `/v1/cleanup`. Anything non-zero means we got *no* bytes
		// to write back and the slot was *not* charged. Surface it as
		// a typed `WP_Error` so the cleanup primitive can fail loudly
		// instead of truncating an unknown file.
		$error_code = isset( $result['error_code'] ) ? (int) $result['error_code'] : 0;
		if ( 0 !== $error_code ) {
			return new WP_Error(
				'cti_cleanup_error_' . $error_code,
				isset( $result['error'] ) ? (string) $result['error'] : __( 'Cleanup unavailable.', 'segurium' ),
				array( 'error_code' => $error_code )
			);
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$decoded = base64_decode( (string) $result['content'], true );
		if ( false === $decoded ) {
			return new WP_Error( 'cti_invalid_response', __( 'Segurium Cloud returned cleanup content that is not valid base64.', 'segurium' ) );
		}

		// SEGURIUM-192: the JSON envelope is Ed25519-signed (verified in
		// Segurium_CTI_Client::clean()) but as defence-in-depth we also
		// confirm the CTI-advertised hash of the cleaned bytes matches
		// what we just decoded. A mismatch here means either CTI
		// mis-reported the hash (bug) or a same-origin middleware
		// produced inconsistent bytes. Empty bytes (Malware verdict)
		// must still match — the well-known SHA-256 of "" is part of
		// the signed envelope.
		$expected = isset( $result['sha256_clean'] ) ? strtolower( (string) $result['sha256_clean'] ) : '';
		if ( '' === $expected ) {
			return new WP_Error( 'cti_invalid_response', __( 'Cleanup response is missing the checksum of the cleaned file.', 'segurium' ) );
		}
		$actual = hash( 'sha256', $decoded );
		if ( ! hash_equals( $expected, $actual ) ) {
			return new WP_Error( 'cti_hash_mismatch', __( 'Cleaned file does not match the checksum in the cleanup response.', 'segurium' ) );
		}

		// SEGURIUM-549: surface the post-charge quota envelope so the
		// caller can update the cached readout authoritatively instead
		// of bumping `used` locally and leaving `next_slot_at = 0`.
		$quota = ( isset( $result['quota'] ) && is_array( $result['quota'] ) ) ? $result['quota'] : null;

		return array(
			'content' => $decoded,
			'quota'   => $quota,
		);
	}

	/**
	 * Fetch (and cache) an integrity manifest for a single component.
	 *
	 * Caches the per-component verdict payload in runtime_kv keyed by
	 * `cti_manifest:<type>:<slug>:<version>` with a conservative default
	 * TTL (15 min). Callers that need a fresh fetch should pass `$force`.
	 *
	 * @param string $comp_type `core|plugin|theme`.
	 * @param string $slug      Component slug (or `wordpress` for core).
	 * @param string $version   Component version.
	 * @param bool   $force     Skip cache on read.
	 * @return array|null
	 */
	public static function cti_fetch_integrity_manifest( string $comp_type, string $slug, string $version, bool $force = false ): ?array {
		$cache_key = 'cti_manifest:' . $comp_type . ':' . $slug . ':' . $version;
		if ( ! $force ) {
			$cached = self::table_get_var(
				'runtime_kv',
				'SELECT kv_value FROM {{table}} WHERE kv_key = %s AND (expires_at IS NULL OR expires_at > %d)',
				array( $cache_key, time() )
			);
			if ( null !== $cached ) {
				$decoded = json_decode( (string) $cached, true );
				if ( is_array( $decoded ) ) {
					return $decoded;
				}
			}
		}

		$result = self::cti_client()->integrity_check(
			array(
				array(
					'component_type' => $comp_type,
					'name'           => $slug,
					'version'        => $version,
					'path'           => $slug,
					'files'          => array(),
				),
			)
		);
		if ( is_wp_error( $result ) || ! is_array( $result ) || empty( $result[0] ) ) {
			return null;
		}

		$ttl = (int) apply_filters( 'segurium_cti_manifest_cache_ttl', 15 * MINUTE_IN_SECONDS );
		$now = time();
		self::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $cache_key,
				'kv_value'   => (string) wp_json_encode( $result[0] ),
				'expires_at' => $now + $ttl,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
		return $result[0];
	}

	/**
	 * Run the multi-component integrity check without caching. Used by the
	 * chunked scan path which has its own state machine.
	 *
	 * @param array  $components Component descriptors.
	 * @param string $trigger    Optional scan trigger ('scheduled', 'manual',
	 *                           'post_update', 'unspecified') forwarded to CTI
	 *                           via `X-Segurium-Integrity-Trigger`.
	 * @return array|WP_Error
	 */
	public static function cti_integrity_check( array $components, string $trigger = '' ) {
		return self::cti_client()->integrity_check( $components, $trigger );
	}

	/**
	 * Queue an asynchronous CTI message.
	 *
	 * @param string       $type    Message type.
	 * @param string|array $payload JSON string or associative array.
	 * @return bool
	 */
	public static function cti_send_message( string $type, $payload = '' ): bool {
		if ( is_array( $payload ) ) {
			$payload = wp_json_encode( $payload );
		}
		return (bool) self::cti_client()->send_message( $type, (string) $payload );
	}

	/**
	 * Standard settings-snapshot emission. Every settings module should use
	 * this instead of hand-rolling the message payload so the CTI side can
	 * rely on a stable contract.
	 *
	 * @param string $area     Settings area identifier (`geo`, `firewall`, `bf`, …).
	 * @param array  $settings Full settings snapshot.
	 * @return bool
	 */
	public static function cti_send_settings_snapshot( string $area, array $settings ): bool {
		return self::cti_send_message(
			'settings_snapshot',
			array(
				'area'     => $area,
				'settings' => $settings,
				'at'       => time(),
			)
		);
	}

	/**
	 * Submit a support ticket through the CTI proxy.
	 *
	 * @param array $data        Ticket data.
	 * @param array $attachments Optional list of attachments
	 *                           (each item: [filename, data]).
	 * @return array|WP_Error
	 */
	public static function cti_submit_support_ticket( array $data, array $attachments = array() ) {
		return self::cti_client()->submit_support_ticket( $data, $attachments );
	}

	/**
	 * Log an integrity action with the CTI for cross-site telemetry.
	 *
	 * @param array $data Log payload.
	 * @return array|WP_Error
	 */
	public static function cti_log_integrity_action( array $data ) {
		return self::cti_client()->log_integrity_action( $data );
	}

	/**
	 * Report a whole-component action (delete/restore/ignore/unignore) to CTI.
	 * The call is non-blocking; invalid actions are dropped with an error_log
	 * note rather than thrown, so a bad caller can't break the admin UI.
	 *
	 * Required keys: component_type (plugin|theme|core), slug, version,
	 * action (delete|restore|ignore|unignore), success (0|1).
	 * Optional keys: files_count, bytes, backup_id, error, duration_ms.
	 *
	 * @param array $data Action payload.
	 * @return void
	 */
	public static function cti_log_component_action( array $data ): void {
		$allowed = array( 'delete', 'restore', 'ignore', 'unignore' );
		$action  = $data['action'] ?? '';
		if ( ! in_array( $action, $allowed, true ) ) {
			Segurium_Debug::log( '[segurium] cti_log_component_action: invalid action "' . $action . '"' );
			return;
		}
		self::cti_client()->log_component_action( $data );
	}

	/**
	 * Push the site's full component inventory to CTI. Empty lists are
	 * skipped (no point burning an HTTP round-trip). The call is non-blocking.
	 *
	 * @param array $components Array of { component_type, slug, version, status }.
	 * @return void
	 */
	public static function cti_log_components_inventory( array $components ): void {
		if ( empty( $components ) ) {
			return;
		}
		self::cti_client()->log_components_inventory( $components );
	}

	/**
	 * Push a hosting-platform snapshot to CTI (SEGURIUM-329).
	 *
	 * @param array $payload Snapshot fields plus `snapshot_hash`.
	 * @return bool
	 */
	public static function cti_send_platform_snapshot( array $payload ): bool {
		return (bool) self::cti_client()->send_platform_snapshot( $payload );
	}

	/**
	 * Retrieve the original contents of a core/plugin/theme file.
	 *
	 * Returns the raw JSON envelope as a string. Callers that want the
	 * decoded, signature- and hash-verified bytes should use
	 * {@see self::cti_fetch_original_content_bytes()} instead — that
	 * path also enforces the SEGURIUM-192 integrity gate.
	 *
	 * @param string $type    core|plugin|theme.
	 * @param string $path    Relative path.
	 * @param string $slug    Component slug.
	 * @param string $version Version.
	 * @return array|WP_Error
	 */
	public static function cti_fetch_original_content( string $type, string $path, string $slug = '', string $version = '' ) {
		return self::cti_client()->get_original_content( $type, $path, $slug, $version );
	}

	/**
	 * Fetch the original bytes of a core/plugin/theme file, verified
	 * end-to-end. Ed25519 signature verification runs inside the CTI
	 * client; here we additionally hash_equals the decoded bytes
	 * against the `sha256` field CTI puts in the signed envelope — a
	 * defence-in-depth check against a CTI-internal content mismatch
	 * (SEGURIUM-192).
	 *
	 * @param string $type    core|plugin|theme.
	 * @param string $path    Relative path within the component.
	 * @param string $slug    Component slug.
	 * @param string $version Component version.
	 * @return string|WP_Error Decoded original bytes or a descriptive error.
	 */
	public static function cti_fetch_original_content_bytes( string $type, string $path, string $slug = '', string $version = '' ) {
		$raw = self::cti_client()->get_original_content( $type, $path, $slug, $version );
		if ( is_wp_error( $raw ) ) {
			return $raw;
		}
		$body = json_decode( (string) $raw, true );
		if ( ! is_array( $body ) || ! isset( $body['error_code'] ) ) {
			return new WP_Error(
				'cti_invalid_response',
				__( 'Invalid response from Segurium Cloud.', 'segurium' )
			);
		}
		if ( 0 !== (int) $body['error_code'] ) {
			$msg = isset( $body['error'] ) && '' !== (string) $body['error']
				? (string) $body['error']
				: sprintf(
					/* translators: %d: numeric error code returned by the service */
					__( 'Segurium Cloud returned error %d.', 'segurium' ),
					(int) $body['error_code']
				);
			return new WP_Error( 'cti_upstream_error', $msg );
		}
		if ( ! isset( $body['content'] ) ) {
			return new WP_Error(
				'cti_invalid_response',
				__( 'Segurium Cloud response is missing the file content.', 'segurium' )
			);
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$decoded = base64_decode( (string) $body['content'], true );
		if ( false === $decoded ) {
			return new WP_Error(
				'cti_invalid_response',
				__( 'Segurium Cloud returned file content that is not valid base64.', 'segurium' )
			);
		}
		$expected = isset( $body['sha256'] ) ? strtolower( (string) $body['sha256'] ) : '';
		if ( '' === $expected ) {
			return new WP_Error(
				'cti_invalid_response',
				__( 'Segurium Cloud response is missing the file checksum.', 'segurium' )
			);
		}
		$actual = hash( 'sha256', $decoded );
		if ( ! hash_equals( $expected, $actual ) ) {
			return new WP_Error(
				'cti_hash_mismatch',
				__( 'Downloaded file does not match the checksum in the response.', 'segurium' )
			);
		}
		return $decoded;
	}

	/**
	 * CTI health probe.
	 *
	 * @return bool
	 */
	public static function cti_health(): bool {
		return (bool) self::cti_client()->health();
	}

	/**
	 * CTI endpoint URL lookup. Callers that talk HTTP directly (IID register,
	 * trusted-proxies feed, geo-DB download) use this instead of reaching
	 * into Segurium_CTI_Client constants.
	 *
	 * @param string $name Endpoint name: `base`, `iid_register`,
	 *                     `trusted_proxies`, `geo_db`, `support`.
	 * @return string
	 */
	public static function cti_endpoint( string $name ): string {
		switch ( $name ) {
			case 'base':
				return Segurium_CTI_Client::BASE_URL;
			case 'trusted_proxies':
				return Segurium_CTI_Client::TRUSTED_PROXIES_ENDPOINT;
			case 'geo_db':
				return Segurium_CTI_Client::GEO_DB_ENDPOINT;
			case 'support':
				return Segurium_CTI_Client::SUPPORT_ENDPOINT;
		}
		return '';
	}
}

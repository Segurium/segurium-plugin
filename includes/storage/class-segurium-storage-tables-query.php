<?php
/**
 * Internal query runner used by Segurium_Storage_Tables generic SELECT helpers.
 *
 * Holds the SQL fragment with `%i` placeholders where the table identifier
 * appears, plus the resolved physical table name as a separate field. Each
 * getter inlines `$wpdb->prepare()` so the only sniff to silence is the
 * inner NotPrepared on `$this->sql` (a fully literal SQL template after
 * substitute_table()); the outer `$wpdb->{get_*}` call's first argument is
 * a `$wpdb->prepare(...)` expression, so the in-house wporg classifier
 * recognises it as `prepare` and plugin-check passes.
 *
 * See SEGURIUM-531.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Query runner.
 */
final class Segurium_Storage_Tables_Query {

	/**
	 * SQL with every `{{table}}` replaced by `%i`.
	 *
	 * @var string
	 */
	private $sql;

	/**
	 * Physical table name (already prefixed). Passed once per `%i`
	 * placeholder through $wpdb->prepare().
	 *
	 * @var string
	 */
	private $table;

	/**
	 * How many `%i` placeholders the SQL contains (i.e. how many times
	 * `{{table}}` appeared in the original body).
	 *
	 * @var int
	 */
	private $table_placeholders;

	/**
	 * Constructor.
	 *
	 * @param string $sql   SQL with `%i` placeholders for the table.
	 * @param string $table Physical table name.
	 */
	public function __construct( string $sql, string $table ) {
		$this->sql                = $sql;
		$this->table              = $table;
		$this->table_placeholders = substr_count( $sql, '%i' );
	}

	/**
	 * Run get_results.
	 *
	 * @param array<mixed> $args   prepare() args (values only, table is added automatically).
	 * @param string       $output OBJECT|ARRAY_A|ARRAY_N.
	 * @return mixed
	 */
	public function run_get_results( array $args, string $output ) {
		global $wpdb;
		$bound = $this->bind_args( $args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $this->sql is built from substitute_table() which only injects %i; values + identifiers bound via prepare().
		return $wpdb->get_results( $wpdb->prepare( $this->sql, $bound ), $output );
	}

	/**
	 * Run get_row.
	 *
	 * @param array<mixed> $args   prepare() args.
	 * @param string       $output OBJECT|ARRAY_A|ARRAY_N.
	 * @return mixed
	 */
	public function run_get_row( array $args, string $output ) {
		global $wpdb;
		$bound = $this->bind_args( $args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- see run_get_results().
		return $wpdb->get_row( $wpdb->prepare( $this->sql, $bound ), $output );
	}

	/**
	 * Run get_var.
	 *
	 * @param array<mixed> $args prepare() args.
	 * @return mixed
	 */
	public function run_get_var( array $args ) {
		global $wpdb;
		$bound = $this->bind_args( $args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- see run_get_results().
		return $wpdb->get_var( $wpdb->prepare( $this->sql, $bound ) );
	}

	/**
	 * Run get_col.
	 *
	 * @param array<mixed> $args prepare() args.
	 * @return mixed
	 */
	public function run_get_col( array $args ) {
		global $wpdb;
		$bound = $this->bind_args( $args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- see run_get_results().
		return $wpdb->get_col( $wpdb->prepare( $this->sql, $bound ) );
	}

	/**
	 * Build the prepare() arg list: one `$this->table` per `%i` in the
	 * template, followed by the caller's value args.
	 *
	 * @param array<mixed> $args Value args from the caller.
	 * @return array<mixed>
	 */
	private function bind_args( array $args ): array {
		$ident_args = array_fill( 0, $this->table_placeholders, $this->table );
		return array_merge( $ident_args, $args );
	}
}

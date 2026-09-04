<?php
/**
 * Accumulated integrity state for the "Integrity" tab.
 *
 * Persists component-level integrity results across scans so deleted
 * components remain visible and actions (fix/restore/delete) are tracked.
 *
 * Stage 3: backing store migrated from integrity-server-state.json to:
 *   - integrity_issues table  — one row per file-level finding
 *   - runtime_kv['integrity:comp_meta'] — component metadata JSON blob
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages accumulated integrity scan state backed by the storage facade.
 */
class Segurium_Integrity_Server_State {

	/**
	 * Component-level states that hide a component from the integrity tab
	 * (and any callers that mirror its bucketing). The user has explicitly
	 * acted on these — they no longer need a verdict.
	 */
	const INACTIVE_COMPONENT_STATES = array( 'deleted', 'not_found', 'ignored' );

	/**
	 * Component metadata keyed by "{type}:{slug}".
	 * Does NOT contain `files` — those are loaded from integrity_issues on demand.
	 *
	 * @var array
	 */
	private $comp_meta = array();

	/**
	 * Pending updates keyed "{type}:{slug}", or null until first read.
	 *
	 * @var array|null
	 */
	private $update_map = null;

	/**
	 * Constructor.
	 *
	 * @param string $data_dir Accepted for call-site compatibility; unused.
	 */
	public function __construct( $data_dir = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		// data_dir is no longer used — storage goes through Segurium_Storage facade.
	}

	/**
	 * Whether a file with this SHA-256 is currently flagged malicious by the
	 * malware scanner (verdict = malicious | injection, finding still open).
	 *
	 * Used to set `integrity_issues.is_malicious` so the integrity-fix AJAX
	 * handler knows whether the action consumes the shared cleanup quota
	 * (corrected axis: infected vs clean, not modified vs new).
	 *
	 * Empty / unresolved hash → 0 (treat as clean for quota; missing files
	 * have no body to scan and are always free).
	 *
	 * @param string $sha256 64-char hex digest of the on-disk file.
	 * @return int 1 when a malicious open finding exists, 0 otherwise.
	 */
	public static function lookup_is_malicious( $sha256 ) {
		$sha256 = (string) $sha256;
		if ( '' === $sha256 || 64 !== strlen( $sha256 ) ) {
			return 0;
		}
		$hit = Segurium_Storage::table_get_var(
			'scan_findings',
			'SELECT 1 FROM {{table}} WHERE sha256 = %s AND verdict IN (1, 2) AND status = %s LIMIT 1',
			array( $sha256, 'open' )
		);
		return null === $hit ? 0 : 1;
	}

	/**
	 * Inject the pending-update map instead of reading WordPress' own
	 * transients. Tests and callers that already hold the map use this.
	 *
	 * @param array $map Map of "{type}:{slug}" to update entry.
	 * @return void
	 */
	public function set_update_map( array $map ) {
		$this->update_map = $map;
	}

	/**
	 * Pending updates for the installed components.
	 *
	 * @return array
	 */
	public function get_update_map() {
		if ( null === $this->update_map ) {
			$this->update_map = class_exists( 'Segurium_Component_Updates' )
				? Segurium_Component_Updates::available()
				: array();
		}
		return $this->update_map;
	}

	/**
	 * Whether the stored metadata flags this component's release as
	 * vulnerable. Reads the metadata only — no file issues, no update
	 * transients — because callers that want the boolean do not want the
	 * work `find_component()` does around it.
	 *
	 * @param string $slug Component slug.
	 * @param string $type Component type.
	 * @return bool
	 */
	public function is_vulnerable( $slug, $type ) {
		return ! empty( $this->comp_meta[ $type . ':' . $slug ]['vulnerable'] );
	}

	/**
	 * Load component metadata from runtime_kv.
	 *
	 * @return bool True if data was found and loaded.
	 */
	public function load() {
		$json            = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( 'integrity:comp_meta' )
		);
		$this->comp_meta = array();
		if ( $json ) {
			$data = json_decode( $json, true );
			if ( is_array( $data ) ) {
				$this->comp_meta = $data;
			}
		}
		return ! empty( $this->comp_meta );
	}

	/**
	 * Persist component metadata to runtime_kv.
	 *
	 * File issues are written directly via table_upsert during update_component()
	 * and update_file_state(); save() only handles the metadata blob.
	 *
	 * @return void
	 */
	public function save() {
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => 'integrity:comp_meta',
				'kv_value'   => wp_json_encode( $this->comp_meta ),
				'expires_at' => null,
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);
		if ( class_exists( 'Segurium_Issue_Indicator' ) ) {
			Segurium_Issue_Indicator::mark_stale();
		}
	}

	/**
	 * Merge a single component's scan results into accumulated state.
	 *
	 * @param array $scan_component Component data from a completed scan.
	 * @return void
	 */
	public function update_component( $scan_component ) {
		$key      = $scan_component['type'] . ':' . $scan_component['slug'];
		$existing = $this->comp_meta[ $key ] ?? null;

		// Deleted components are preserved — don't overwrite.
		if ( $existing && 'deleted' === ( $existing['state'] ?? '' ) ) {
			return;
		}

		$now = time();

		// Update component metadata.
		$this->comp_meta[ $key ] = array(
			'slug'             => $scan_component['slug'],
			'type'             => $scan_component['type'],
			'version'          => $scan_component['version'],
			'path'             => $scan_component['path'] ?? '',
			'comp_name'        => $scan_component['name'] ?? $scan_component['slug'],
			'component_status' => $scan_component['component_status'] ?? 'listed',
			'last_updated'     => $scan_component['last_updated'] ?? null,
			'latest_version'   => $scan_component['latest_version'] ?? null,
			'vulnerable'       => ! empty( $scan_component['vulnerable'] ),
			'state'            => $existing['state'] ?? 'active',
			'timestamp'        => $now,
			'ok_count'         => (int) ( $scan_component['ok_count'] ?? 0 ),
			'backup_id'        => $existing['backup_id'] ?? null,
		);

		$type = $scan_component['type'];
		$slug = $scan_component['slug'];

		// Upsert each file issue into integrity_issues table.
		$new_file_hashes = array();
		foreach ( $scan_component['files'] as $f ) {
			$path_hash         = hash( 'sha256', $f['path'] );
			$new_file_hashes[] = $path_hash;

			// Preserve existing status for ignored files.
			$existing_status = Segurium_Storage::table_get_var(
				'integrity_issues',
				'SELECT status FROM {{table}} WHERE comp_type = %s AND comp_slug = %s AND file_path_hash = %s',
				array( $type, $slug, $path_hash )
			);

			$status    = 'open';
			$backup_id = $f['backup_id'] ?? null;
			if ( $existing_status && 'ignored' === $existing_status ) {
				$status = 'ignored';
			}

			$file_sha256 = (string) ( $f['sha256'] ?? '' );
			Segurium_Storage::table_upsert(
				'integrity_issues',
				array(
					'comp_type'      => $type,
					'comp_slug'      => $slug,
					'comp_version'   => $scan_component['version'],
					'comp_name'      => $scan_component['name'] ?? $slug,
					'file_path'      => $f['path'],
					'file_path_hash' => $path_hash,
					'verdict'        => $f['verdict'],
					'status'         => $status,
					'sha256'         => $file_sha256,
					'is_malicious'   => self::lookup_is_malicious( $file_sha256 ),
					'backup_id'      => $backup_id,
					'created_at'     => $now,
					'fixed_at'       => null,
				),
				array( 'comp_type', 'comp_slug', 'file_path_hash' )
			);
		}

		// Files that were open in the DB but are no longer flagged by CTI
		// (i.e. the issue was resolved by a plugin/WP update) → mark fixed.
		if ( ! empty( $new_file_hashes ) ) {
			global $wpdb;
			$table        = Segurium_Storage::table_name( 'integrity_issues' );
			$placeholders = implode( ', ', array_fill( 0, count( $new_file_hashes ), '%s' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- {$placeholders} is a static `%s,%s,...` string built locally; all values bound via prepare()
			$sql = "UPDATE %i SET status = 'fixed', fixed_at = %d WHERE comp_type = %s AND comp_slug = %s AND status = 'open' AND file_path_hash NOT IN ({$placeholders})";
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL template uses %i for table; IN-list placeholders dynamically generated, all values + table bound via prepare()
			$wpdb->query( $wpdb->prepare( $sql, ...array_merge( array( $table, $now, $type, $slug ), $new_file_hashes ) ) );
		} else {
			// No new issues: mark all previously-open rows as fixed.
			Segurium_Storage::table_update(
				'integrity_issues',
				array(
					'status'   => 'fixed',
					'fixed_at' => $now,
				),
				array(
					'comp_type' => $type,
					'comp_slug' => $slug,
					'status'    => 'open',
				)
			);
		}
	}

	/**
	 * Get paginated list of components.
	 *
	 * Bucket order is fixed: Issues → Delisted → Abandoned → Vulnerable →
	 * Outdated → Clean/Deleted/Ignored. Within the first five the rows are
	 * alphanumeric by slug; within the rest they are by last-scanned
	 * timestamp DESC.
	 *
	 * If a non-empty $snapshot_id is supplied, the sorted key order is cached in
	 * runtime_kv (1 h TTL) and reused on subsequent calls so component rows do
	 * NOT jump after fix/ignore/restore actions. A fresh page load generates a
	 * new id and therefore a fresh order.
	 *
	 * @param int    $page        Page number (1-based).
	 * @param int    $per_page    Items per page.
	 * @param string $snapshot_id Opaque per-page-load id; '' disables caching.
	 * @return array
	 */
	public function get_components( $page = 1, $per_page = 20, $snapshot_id = '' ) {
		$sorted_keys = $this->get_sorted_component_keys( $snapshot_id );
		$offset      = ( $page - 1 ) * $per_page;
		$page_keys   = array_slice( $sorted_keys, $offset, $per_page );

		$result = array();
		foreach ( $page_keys as $key ) {
			if ( ! isset( $this->comp_meta[ $key ] ) ) {
				continue;
			}
			$meta                = $this->comp_meta[ $key ];
			list( $type, $slug ) = explode( ':', $key, 2 );
			$result[]            = array_merge(
				$meta,
				array(
					'files'  => $this->load_files_for_component( $type, $slug ),
					'update' => $this->pending_update( $key ),
				)
			);
		}

		return $result;
	}

	/**
	 * Get total number of components.
	 *
	 * @return int
	 */
	public function get_total() {
		return count( $this->comp_meta );
	}

	/**
	 * Update a single file's status in the integrity_issues table.
	 *
	 * @param string      $slug      Component slug.
	 * @param string      $type      Component type (plugin/theme/core).
	 * @param string      $file_path Relative file path.
	 * @param string      $state     New status value.
	 * @param string|null $backup_id Backup identifier.
	 * @return void
	 */
	public function update_file_state( $slug, $type, $file_path, $state, $backup_id = null ) {
		$data = array(
			'status'   => $state,
			'fixed_at' => 'open' !== $state ? time() : null,
		);
		if ( null !== $backup_id ) {
			$data['backup_id'] = $backup_id;
		}
		Segurium_Storage::table_update(
			'integrity_issues',
			$data,
			array(
				'comp_type'      => $type,
				'comp_slug'      => $slug,
				'file_path_hash' => hash( 'sha256', ltrim( $file_path, '/' ) ),
			)
		);
	}

	/**
	 * Update component-level state (active/deleted/ignored).
	 *
	 * @param string      $slug      Component slug.
	 * @param string      $type      Component type (plugin/theme/core).
	 * @param string      $state     New state.
	 * @param string|null $backup_id Backup identifier.
	 * @return void
	 */
	public function update_component_state( $slug, $type, $state, $backup_id = null ) {
		$key = $type . ':' . $slug;
		if ( ! isset( $this->comp_meta[ $key ] ) ) {
			return;
		}
		$this->comp_meta[ $key ]['state']     = $state;
		$this->comp_meta[ $key ]['timestamp'] = time();
		if ( null !== $backup_id ) {
			$this->comp_meta[ $key ]['backup_id'] = $backup_id;
		}
	}

	/**
	 * Mark components not found in the latest scan as "not_found".
	 *
	 * @param array $scanned_keys Array of "type:slug" keys from the scan.
	 * @return void
	 */
	public function mark_not_found( $scanned_keys ) {
		$scanned_set = array_flip( $scanned_keys );
		foreach ( $this->comp_meta as $key => &$comp ) {
			if ( isset( $scanned_set[ $key ] ) ) {
				continue;
			}
			if ( in_array( $comp['state'] ?? '', array( 'deleted', 'not_found' ), true ) ) {
				continue;
			}
			$comp['state'] = 'not_found';
		}
		unset( $comp );
	}

	/**
	 * Find a component entry by slug and type, with its file issues.
	 *
	 * @param string $slug Component slug.
	 * @param string $type Component type.
	 * @return array|null
	 */
	public function find_component( $slug, $type ) {
		$key = $type . ':' . $slug;
		if ( ! isset( $this->comp_meta[ $key ] ) ) {
			return null;
		}
		return array_merge(
			$this->comp_meta[ $key ],
			array(
				'files'  => $this->load_files_for_component( $type, $slug ),
				'update' => $this->pending_update( $key ),
			)
		);
	}

	/**
	 * Return plugin-side state overrides for components — only entries whose
	 * state differs from what WP itself reports (currently `ignored` and
	 * `deleted`). Used by the CTI inventory reporter to attach authoritative
	 * per-component status regardless of WP's active/inactive flag.
	 *
	 * @return array List of { type, slug, status } rows.
	 */
	public function get_component_status_overrides(): array {
		$out = array();
		foreach ( $this->comp_meta as $key => $meta ) {
			$state = $meta['state'] ?? '';
			if ( 'ignored' !== $state && 'deleted' !== $state ) {
				continue;
			}
			if ( false === strpos( $key, ':' ) ) {
				continue;
			}
			list( $type, $slug ) = explode( ':', $key, 2 );
			$out[]               = array(
				'type'   => $type,
				'slug'   => $slug,
				'status' => $state,
			);
		}
		return $out;
	}

	/**
	 * Set of component keys ("{type}:{slug}") whose state hides the
	 * component from the integrity tab. Lazy O(n) scan over comp_meta
	 * with the result keyed for O(1) membership tests.
	 *
	 * @return array<string,bool>
	 */
	public function get_inactive_component_key_set() {
		$set = array();
		foreach ( $this->comp_meta as $key => $meta ) {
			$state = $meta['state'] ?? 'active';
			if ( in_array( $state, self::INACTIVE_COMPONENT_STATES, true ) ) {
				$set[ $key ] = true;
			}
		}
		return $set;
	}

	/**
	 * Count the open integrity findings the Integrity tab would still show.
	 *
	 * Scoped to rows touched by the latest scan, so an `open` row left by an
	 * earlier scan whose component is no longer flagged cannot keep a clean
	 * site red forever. Components the user has already acted on (deleted /
	 * not_found / ignored) drop out, mirroring `bucket_for()`.
	 *
	 * Aggregates in SQL: a core-compromised site can carry thousands of open
	 * rows, and the count only needs one row per component.
	 *
	 * Shared with the MainWP bridge so a fleet dashboard and
	 * the site's own posture score never disagree about the same number.
	 *
	 * @param int        $scan_ts  Timestamp of the most recent integrity scan.
	 * @param array|null $inactive Pre-loaded inactive component key set;
	 *                             loaded here when null.
	 * @return int
	 */
	public static function count_open_issues( $scan_ts, $inactive = null ) {
		$scan_ts = (int) $scan_ts;
		if ( $scan_ts <= 0 ) {
			return 0;
		}

		$rows = Segurium_Storage::table_get_results(
			'integrity_issues',
			'SELECT comp_type, comp_slug, COUNT(*) AS n FROM {{table}}
			 WHERE status = %s AND created_at >= %d
			 GROUP BY comp_type, comp_slug',
			array( 'open', $scan_ts ),
			ARRAY_A
		);
		if ( empty( $rows ) ) {
			return 0;
		}

		if ( null === $inactive ) {
			$inactive = self::inactive_key_set();
		}

		$count = 0;
		foreach ( $rows as $row ) {
			if ( isset( $inactive[ $row['comp_type'] . ':' . $row['comp_slug'] ] ) ) {
				continue;
			}
			$count += (int) $row['n'];
		}
		return $count;
	}

	/**
	 * Installed components whose stored release carries a vulnerability
	 * the cloud flagged, excluding the ones the user already acted on.
	 *
	 * Independent of {@see self::count_open_issues()}: a flagged release
	 * with every file matching the vendor's own hashes produces no issue
	 * row, and is still the thing an attacker walks in through.
	 *
	 * @return int
	 */
	public static function count_vulnerable_components() {
		$json = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( 'integrity:comp_meta' )
		);
		if ( ! $json ) {
			return 0;
		}
		$meta = json_decode( (string) $json, true );
		if ( ! is_array( $meta ) ) {
			return 0;
		}

		$count = 0;
		foreach ( $meta as $entry ) {
			if ( ! is_array( $entry ) || empty( $entry['vulnerable'] ) ) {
				continue;
			}
			if ( in_array( $entry['state'] ?? 'active', self::INACTIVE_COMPONENT_STATES, true ) ) {
				continue;
			}
			++$count;
		}
		return $count;
	}

	/**
	 * The same finding set as {@see self::count_open_issues()}, capped and
	 * ordered newest first. Callers render these; the honest total comes
	 * from the counter above.
	 *
	 * The inactive-component exclusion goes into the WHERE clause, not into
	 * a PHP filter after the LIMIT. Filtering afterwards silently produced
	 * an empty list whenever the newest rows all belonged to a component the
	 * user had ignored, so the dashboard rendered a non-zero total with no
	 * items under it. The exclusion list is bounded by the number of
	 * installed components, not by the number of findings.
	 *
	 * @param int        $scan_ts  Timestamp of the most recent integrity scan.
	 * @param int        $limit    Maximum rows to return.
	 * @param array|null $inactive Pre-loaded inactive component key set;
	 *                             loaded here when null.
	 * @return array<int, array<string, mixed>>
	 */
	public static function list_open_issues( $scan_ts, $limit, $inactive = null ) {
		$scan_ts = (int) $scan_ts;
		$limit   = max( 1, min( 500, (int) $limit ) );
		if ( $scan_ts <= 0 ) {
			return array();
		}

		if ( null === $inactive ) {
			$inactive = self::inactive_key_set();
		}

		$where = 'status = %s AND created_at >= %d';
		$args  = array( 'open', $scan_ts );
		foreach ( array_keys( $inactive ) as $key ) {
			$parts = explode( ':', (string) $key, 2 );
			if ( 2 !== count( $parts ) ) {
				continue;
			}
			$where .= ' AND NOT ( comp_type = %s AND comp_slug = %s )';
			$args[] = $parts[0];
			$args[] = $parts[1];
		}
		$args[] = $limit;

		$rows = Segurium_Storage::table_get_results(
			'integrity_issues',
			'SELECT comp_type, comp_slug, file_path, created_at FROM {{table}}
			 WHERE ' . $where . '
			 ORDER BY created_at DESC, id DESC LIMIT %d',
			$args,
			ARRAY_A
		);

		return empty( $rows ) ? array() : $rows;
	}

	/**
	 * Component keys the user has already acted on, loaded once.
	 *
	 * Public so a caller needing both the count and the list pays a single
	 * `integrity:comp_meta` decode instead of one per query.
	 *
	 * @return array<string,bool>
	 */
	public static function inactive_key_set() {
		$state = new self();
		$state->load();
		return $state->get_inactive_component_key_set();
	}

	/**
	 * Return all active components with their file issues. Components in
	 * `deleted` or `ignored` state are excluded — callers driving bulk actions
	 * (Fix All) must not touch items the user has explicitly opted out of.
	 *
	 * @return array
	 */
	public function get_all_active_components() {
		$out = array();
		foreach ( $this->comp_meta as $key => $meta ) {
			$state = $meta['state'] ?? '';
			if ( 'deleted' === $state || 'ignored' === $state ) {
				continue;
			}
			list( $type, $slug ) = explode( ':', $key, 2 );
			$out[]               = array_merge( $meta, array( 'files' => $this->load_files_for_component( $type, $slug ) ) );
		}
		return $out;
	}

	/**
	 * Count files with "open" status for a component.
	 *
	 * If the component array already contains a `files` key (loaded by
	 * get_components), count from it directly. Otherwise query the DB.
	 *
	 * @param array $component Component data.
	 * @return int
	 */
	public function count_open_files( $component ) {
		if ( isset( $component['files'] ) ) {
			$count = 0;
			foreach ( $component['files'] as $f ) {
				if ( 'open' === ( $f['state'] ?? 'open' ) ) {
					++$count;
				}
			}
			return $count;
		}

		return (int) Segurium_Storage::table_get_var(
			'integrity_issues',
			"SELECT COUNT(*) FROM {{table}} WHERE comp_type = %s AND comp_slug = %s AND status = 'open'",
			array( $component['type'] ?? '', $component['slug'] ?? '' )
		);
	}

	/**
	 * Snapshot TTL in seconds. The snapshot freezes the row order across
	 * fix/ignore/restore actions; a fresh page-load yields a new id and
	 * therefore a fresh order. 1 h is plenty for one tab session and short
	 * enough that abandoned ids self-evict.
	 */
	const SORT_SNAPSHOT_TTL = 3600;

	/**
	 * Bucket id used to group components for sorting. Lower = closer to top.
	 *  0 — Issues       (active components with open file findings or "not_in_repository")
	 *  1 — Delisted     (component_status = delisted, not deleted/ignored)
	 *  2 — Abandoned    (component_status = abandoned, not deleted/ignored)
	 *  3 — Vulnerable   (a release the cloud flags, otherwise clean)
	 *  4 — Outdated     (otherwise clean, with a pending update)
	 *  5 — Clean/Deleted/Ignored (everything else)
	 *
	 * @param string $key Component key "{type}:{slug}".
	 * @param array  $count_map Map of "{type}:{slug}" → open issue count.
	 * @return int
	 */
	private function bucket_for( $key, $count_map ) {
		$meta  = $this->comp_meta[ $key ] ?? array();
		$state = $meta['state'] ?? 'active';
		if ( in_array( $state, self::INACTIVE_COMPONENT_STATES, true ) ) {
			return 5;
		}
		$cs = $meta['component_status'] ?? 'listed';
		if ( 'delisted' === $cs ) {
			return 1;
		}
		if ( 'abandoned' === $cs ) {
			return 2;
		}
		if ( 'not_in_repository' === $cs ) {
			return 0;
		}
		$has_open = ( $count_map[ $key ] ?? 0 ) > 0;
		if ( $has_open ) {
			return 0;
		}
		if ( ! empty( $meta['vulnerable'] ) ) {
			return 3;
		}
		return array() === $this->pending_update( $key ) ? 5 : 4;
	}

	/**
	 * Pending update entry for a component key, or an empty array.
	 *
	 * @param string $key Component key "{type}:{slug}".
	 * @return array
	 */
	private function pending_update( $key ) {
		$map   = $this->get_update_map();
		$entry = $map[ $key ] ?? array();
		if ( ! is_array( $entry ) || '' === (string) ( $entry['new_version'] ?? '' ) ) {
			return array();
		}
		return $entry;
	}

	/**
	 * Return sorted component keys.
	 *
	 * Order: Issues → Delisted → Abandoned → Vulnerable → Outdated (each
	 * alphanumeric by slug), then Clean/Deleted/Ignored by last-scanned
	 * timestamp DESC.
	 *
	 * If $snapshot_id is non-empty, the order is cached in runtime_kv and
	 * subsequent calls return the same order until the cache expires. New
	 * components that did not exist at snapshot time are appended at the end
	 * sorted by the same rule, so pagination after a scan still works.
	 *
	 * @param string $snapshot_id Per-page-load id; '' = no caching.
	 * @return array
	 */
	private function get_sorted_component_keys( $snapshot_id = '' ) {
		if ( '' !== $snapshot_id ) {
			$cached_keys = $this->load_sort_snapshot( $snapshot_id );
			if ( null !== $cached_keys ) {
				$current     = array_keys( $this->comp_meta );
				$current_set = array_flip( $current );
				$kept        = array();
				foreach ( $cached_keys as $k ) {
					if ( isset( $current_set[ $k ] ) ) {
						$kept[] = $k;
					}
				}
				$missing = array_values( array_diff( $current, $kept ) );
				if ( ! empty( $missing ) ) {
					$kept = array_merge( $kept, $this->compute_sorted_keys( $missing ) );
					$this->save_sort_snapshot( $snapshot_id, $kept );
				}
				return $kept;
			}
		}

		$sorted = $this->compute_sorted_keys( array_keys( $this->comp_meta ) );
		if ( '' !== $snapshot_id ) {
			$this->save_sort_snapshot( $snapshot_id, $sorted );
		}
		return $sorted;
	}

	/**
	 * Compute the bucket+alpha+timestamp ordering for the given key set.
	 *
	 * @param array $keys Component keys to sort.
	 * @return array
	 */
	private function compute_sorted_keys( $keys ) {
		$count_rows = Segurium_Storage::table_get_results(
			'integrity_issues',
			"SELECT comp_type, comp_slug, COUNT(*) as cnt FROM {{table}} WHERE status = 'open' GROUP BY comp_type, comp_slug",
			array(),
			ARRAY_A
		);
		$count_map  = array();
		foreach ( $count_rows as $row ) {
			$count_map[ $row['comp_type'] . ':' . $row['comp_slug'] ] = (int) $row['cnt'];
		}

		usort(
			$keys,
			function ( $a, $b ) use ( $count_map ) {
				$ba = $this->bucket_for( $a, $count_map );
				$bb = $this->bucket_for( $b, $count_map );
				if ( $ba !== $bb ) {
					return $ba - $bb;
				}
				$a_meta = $this->comp_meta[ $a ];
				$b_meta = $this->comp_meta[ $b ];
				if ( 5 === $ba ) {
					// Clean/Deleted/Ignored — most-recently-scanned first.
					return ( $b_meta['timestamp'] ?? 0 ) <=> ( $a_meta['timestamp'] ?? 0 );
				}
				// Issues / Delisted / Abandoned / Vulnerable / Outdated —
				// alphanumeric by slug.
				return strnatcasecmp( $a_meta['slug'] ?? '', $b_meta['slug'] ?? '' );
			}
		);

		return $keys;
	}

	/**
	 * Load a previously-cached snapshot of sorted keys.
	 *
	 * @param string $snapshot_id Snapshot id.
	 * @return array|null Array of keys when fresh, null when missing/expired.
	 */
	private function load_sort_snapshot( $snapshot_id ) {
		$json = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s AND ( expires_at IS NULL OR expires_at > %d )',
			array( 'integrity:sort_snapshot:' . $snapshot_id, time() )
		);
		if ( ! $json ) {
			return null;
		}
		$data = json_decode( $json, true );
		return is_array( $data ) ? $data : null;
	}

	/**
	 * Persist the snapshot of sorted keys.
	 *
	 * @param string $snapshot_id Snapshot id.
	 * @param array  $keys        Ordered list of "{type}:{slug}" keys.
	 * @return void
	 */
	private function save_sort_snapshot( $snapshot_id, $keys ) {
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => 'integrity:sort_snapshot:' . $snapshot_id,
				'kv_value'   => wp_json_encode( $keys ),
				'expires_at' => time() + self::SORT_SNAPSHOT_TTL,
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Load all file issues for a component from integrity_issues table.
	 *
	 * @param string $type Component type.
	 * @param string $slug Component slug.
	 * @return array
	 */
	private function load_files_for_component( $type, $slug ) {
		$rows = Segurium_Storage::table_get_results(
			'integrity_issues',
			"SELECT file_path, verdict, status, sha256, backup_id, fixed_at, created_at FROM {{table}} WHERE comp_type = %s AND comp_slug = %s ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'ignored' THEN 1 ELSE 2 END, file_path ASC",
			array( $type, $slug ),
			ARRAY_A
		);

		$malicious_set = $this->lookup_malicious_set(
			array_filter( array_unique( array_column( $rows, 'sha256' ) ) )
		);

		$files = array();
		foreach ( $rows as $row ) {
			$sha         = (string) $row['sha256'];
			$has_malware = ( '' !== $sha ) && isset( $malicious_set[ $sha ] );
			// A backup_id whose envelope is no longer on disk
			// must not be advertised as restorable to the UI — older sites
			// can carry rows pinned to backups that were rotated out before
			// the pinning guard landed. Drop it so the JS never offers
			// Restore for an unrecoverable file.
			$backup_id = (string) ( $row['backup_id'] ?? '' );
			if ( '' !== $backup_id && ! Segurium_Storage::backup_exists( 'integrity', $backup_id ) ) {
				$backup_id = '';
			}
			$files[] = array(
				'path'        => $row['file_path'],
				'verdict'     => $row['verdict'],
				'state'       => $row['status'],
				'sha256'      => $sha,
				'backup_id'   => $backup_id,
				'timestamp'   => (int) $row['created_at'],
				'has_malware' => $has_malware,
			);
		}
		return $files;
	}

	/**
	 * Return the set of SHA-256 hashes that currently have an open malicious
	 * scan finding. Used to flag integrity rows whose file body is also
	 * malware-positive, so the UI can suffix the verdict with "(!) malware".
	 *
	 * @param array $sha_list List of 64-char hex SHA-256 digests.
	 * @return array<string,bool> Map of sha256 → true.
	 */
	private function lookup_malicious_set( $sha_list ) {
		if ( empty( $sha_list ) ) {
			return array();
		}
		$placeholders = implode( ', ', array_fill( 0, count( $sha_list ), '%s' ) );
		$rows         = Segurium_Storage::table_get_results(
			'scan_findings',
			"SELECT DISTINCT sha256 FROM {{table}} WHERE verdict IN (1, 2) AND status = 'open' AND sha256 IN ({$placeholders})",
			$sha_list,
			ARRAY_A
		);
		$set          = array();
		foreach ( $rows as $r ) {
			$set[ $r['sha256'] ] = true;
		}
		return $set;
	}
}

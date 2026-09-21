<?php
/**
 * Chunked async backend for the Integrity tab's progress bar.
 *
 * The Integrity scan used to be a single synchronous AJAX call that walked
 * every plugin/theme/core, gathered hashes, called CTI in one big payload,
 * and returned. On a site with hundreds of plugins that hit
 * max_execution_time and gave the user no progress feedback. This class
 * splits the work into start → continue → continue → done, persisting
 * progress in a per-scan tmp workspace so the JS can render a
 * dynamic progress bar and resume across page reloads.
 *
 * In-flight state lives in a Segurium_Storage tmp workspace
 * (tmp/integrity-<uuid>/state.json) tracked via
 * runtime_kv['integrity_scan_active']. Completed results are written to
 * the integrity_issues table.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages chunked async integrity scan progress and state persistence.
 */
class Segurium_Integrity_Scan_State {

	const CHUNK_SIZE = 10;

	/**
	 * Upper bound on the serialized request body per CTI integrity_check call.
	 * Kept below CTI's `integrity_max_body_bytes` (10 MiB) so a
	 * large component's file list can never overflow the server limit and get
	 * rejected.
	 */
	const MAX_CHUNK_BYTES = 8388608; // 8 MiB.

	/**
	 * Total attempts a chunk gets across transient failures at the same cursor
	 * before it is skipped so the scan advances instead of looping forever.
	 */
	const MAX_CHUNK_RETRIES = 3;

	const EMPTY_FILE_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

	/**
	 * Effective per-request byte cap. Defaults to MAX_CHUNK_BYTES; tests lower
	 * it to exercise splitting without allocating megabytes.
	 *
	 * @var int
	 */
	private $max_chunk_bytes = self::MAX_CHUNK_BYTES;

	/**
	 * WordPress installation root path.
	 *
	 * @var string
	 */
	private $base_path;

	/**
	 * CTI client instance for integrity checks.
	 *
	 * @var object
	 */
	private $cti_client;

	/**
	 * Component discovery instance.
	 *
	 * @var object
	 */
	private $discovery;

	/**
	 * Absolute path to the active tmp workspace, or null.
	 *
	 * @var string|null
	 */
	private $workspace = null;

	/**
	 * Trigger the runner handed down for this run, forwarded to CTI on
	 * every chunk. Set before initialize(); ignored on a resumed scan,
	 * which reads the trigger back from persisted state.
	 *
	 * @var string
	 */
	private $pending_trigger = 'manual';

	/**
	 * Per-request memoization of the saved status map. Loaded lazily on the
	 * first chunk and reused across subsequent chunks within the same HTTP
	 * request, even though most chunks today live in their own request.
	 *
	 * @var array|null
	 */
	private $saved_status_map = null;

	/**
	 * Current scan state array.
	 *
	 * @var array
	 */
	private $state = array(
		'scan_id'      => '',
		'started_at'   => 0,
		'queue'        => array(),
		'cursor'       => 0,
		'total'        => 0,
		'processed'    => 0,
		'currently'    => null,
		'results'      => array(),
		'trigger'      => 'unspecified',
		'retry_cursor' => -1,
		'retry_count'  => 0,
		'unverified'   => array(),
	);

	/**
	 * Constructor.
	 *
	 * @param string      $base_path  WordPress install root.
	 * @param string      $data_dir   Accepted for call-site compatibility; unused (storage
	 *                                is managed by Segurium_Storage facade).
	 * @param object|null $cti_client Anything with `integrity_check( array $components )`.
	 *                                Defaults to a real Segurium_CTI_Client. Tests inject a stub.
	 * @param object|null $discovery  Anything with `discover()` and `collect_hashes( $type, $slug )`.
	 *                                Defaults to a real WordPress component scanner. Tests inject a stub.
	 */
	public function __construct( $base_path, $data_dir = '', $cti_client = null, $discovery = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$this->base_path  = rtrim( $base_path, '/' );
		$this->cti_client = $cti_client;
		$this->discovery  = $discovery ? $discovery : new Segurium_Integrity_Component_Discovery( $this->base_path );
	}

	/**
	 * Override the per-request byte cap. Test seam so splitting can be
	 * exercised without building multi-megabyte payloads.
	 *
	 * @param int $bytes Maximum serialized body size per CTI call.
	 * @return void
	 */
	public function set_max_chunk_bytes( $bytes ) {
		$this->max_chunk_bytes = max( 1, (int) $bytes );
	}

	/**
	 * Declare where this run came from before initialize() persists it.
	 * Callers that skip it get 'manual', which is what an operator pressing
	 * the button produces.
	 *
	 * @param string $trigger One of scheduled|manual|post_update|unspecified.
	 * @return void
	 */
	public function set_trigger( $trigger ) {
		$this->pending_trigger = (string) $trigger;
	}

	/**
	 * Discover all components, persist the queue, and return the initial
	 * progress shape. Does NOT collect file hashes — that happens lazily
	 * inside process_chunk so start() stays fast.
	 *
	 * @param string $scan_id Optional scan UUID; generated when empty.
	 * @param string $trigger Scan trigger (scheduled|manual|post_update|unspecified).
	 *                        Forwarded to CTI as X-Segurium-Integrity-Trigger header
	 *                        on every chunk's integrity_check call.
	 * @return array Initial progress shape.
	 */
	public function start( $scan_id = '', $trigger = 'manual' ) {
		$queue = $this->discovery->discover();

		if ( empty( $scan_id ) ) {
			$scan_id = wp_generate_uuid4();
		}

		$allowed_triggers = array( 'scheduled', 'manual', 'post_update', 'unspecified' );
		if ( ! in_array( $trigger, $allowed_triggers, true ) ) {
			Segurium_Debug::log(
				sprintf(
					'[segurium-integrity] unknown scan trigger %s reported as unspecified',
					wp_json_encode( $trigger )
				)
			);
			$trigger = 'unspecified';
		}

		$this->state = array(
			'scan_id'      => $scan_id,
			'started_at'   => time(),
			'queue'        => $queue,
			'cursor'       => 0,
			'total'        => count( $queue ),
			'processed'    => 0,
			'currently'    => null,
			'results'      => array(),
			'trigger'      => $trigger,
			'retry_cursor' => -1,
			'retry_count'  => 0,
			'unverified'   => array(),
		);

		$this->push_components_inventory();

		$this->workspace = Segurium_Storage::tmp_make_workspace( 'integrity' );
		if ( false === $this->workspace ) {
			// Non-fatal: continue without workspace — state will not be resumable
			// across requests, but the current request can still process in memory.
			Segurium_Debug::log( '[segurium] integrity scan: failed to create tmp workspace' );
			$this->workspace = null;
		}

		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => 'integrity_scan_active',
				'kv_value'   => wp_json_encode(
					array(
						'scan_id'   => $scan_id,
						'workspace' => $this->workspace,
					)
				),
				'expires_at' => time() + 2 * HOUR_IN_SECONDS,
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);

		$this->save_state();

		return $this->build_progress( false );
	}

	/**
	 * Initialize the scan with a runner-supplied scan ID.
	 *
	 * The $scan_type parameter is accepted for duck-type compatibility with
	 * the runner's engine contract but is unused — integrity scans have a
	 * single type.
	 *
	 * @param string $scan_id   Runner-generated UUID.
	 * @param string $scan_type Scan type label for contract compatibility.
	 * @return void
	 */
	public function initialize( $scan_id, $scan_type = 'integrity' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$this->start( $scan_id, $this->pending_trigger );
	}

	/**
	 * Enumerate the site's full component inventory and push it to CTI. Runs
	 * non-blocking; failures are swallowed so they can't stall the scan.
	 *
	 * @return void
	 */
	private function push_components_inventory() {
		try {
			$data_dir  = class_exists( 'Segurium_Storage_Fs' ) ? (string) Segurium_Storage_Fs::data_dir() : '';
			$inventory = Segurium_Integrity_Component_Discovery::enumerate_inventory( $data_dir );
			if ( ! empty( $inventory ) ) {
				Segurium_Storage::cti_log_components_inventory( $inventory );
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] push_components_inventory: ' . $e->getMessage() );
		}
	}

	/**
	 * Process up to CHUNK_SIZE components from the queue, calling CTI once
	 * per chunk. On the chunk that drains the queue, persist results to
	 * the integrity_issues table and clean up the workspace.
	 *
	 * @throws RuntimeException When the tick lease was taken over by another
	 *                          worker before the chunk's CTI call;
	 *                          life_support_system() catches it and ends the tick.
	 */
	public function process_chunk() {
		if ( $this->state['cursor'] >= $this->state['total'] ) {
			return $this->build_progress( true );
		}

		list( $slice, $cti_payload, $component_meta ) = $this->build_chunk( $this->state['cursor'] );

		// `currently` reflects the first component of the in-flight batch;
		// the JS shows it for the whole chunk's duration.
		if ( ! empty( $slice ) ) {
			$first_in_chunk           = $slice[0];
			$this->state['currently'] = trim(
				( $first_in_chunk['name'] ?? $first_in_chunk['slug'] ?? '' )
				. ' '
				. ( $first_in_chunk['version'] ?? '' )
			);
		}

		// Heartbeat + lease before the integrity_check POST
		// (up to INTEGRITY_TICK_TIMEOUT_SEC inside a tick). A lost lease
		// means another driver already owns this scan: stop here instead
		// of posting the same chunk twice.
		if ( class_exists( 'Segurium_Scan_Runner' )
			&& ! Segurium_Scan_Runner::renew_liveness( (string) $this->state['scan_id'] ) ) {
			throw new RuntimeException( 'integrity scan tick lost its lease; another worker took the scan over' );
		}

		$trigger    = (string) ( $this->state['trigger'] ?? 'unspecified' );
		$cti_result = null !== $this->cti_client
			? $this->cti_client->integrity_check( $cti_payload, $trigger )
			: Segurium_Storage::cti_integrity_check( $cti_payload, $trigger );
		if ( is_wp_error( $cti_result ) || ! is_array( $cti_result ) ) {
			return $this->handle_chunk_failure( $cti_result, $slice, $component_meta );
		}

		$cti_by_key = array();
		foreach ( $cti_result as $row ) {
			$key                = ( $row['component_type'] ?? '' ) . ':' . ( $row['name'] ?? '' );
			$cti_by_key[ $key ] = $row;
		}

		$saved_status_map = $this->load_saved_status_map();

		foreach ( $component_meta as $meta ) {
			$comp = $meta['component'];
			$key  = $comp['type'] . ':' . $comp['slug'];

			$cti_row          = $cti_by_key[ $key ] ?? array();
			$component_status = $cti_row['component_status'] ?? 'listed';

			// A version the cloud catalogue has not indexed yet carries no
			// verdict at all: every file comes back "version_not_found".
			// Recording that as a result row is wrong in both directions —
			// the rows are not findings, and an empty row reconciles as
			// verified-clean and resolves whatever the last real scan left
			// open. `unverified` keeps the component out of the not-found
			// sweep and leaves its persisted state alone until a scan
			// actually checks it.
			if ( 'version_not_indexed' === $component_status ) {
				$this->state['unverified'][] = $key;
				continue;
			}

			$ui_entry = array(
				'type'             => $comp['type'],
				'slug'             => $comp['slug'],
				'name'             => $comp['name'],
				'version'          => $comp['version'],
				'files'            => count( $meta['hashes'] ),
				'issues'           => array(),
				'component_status' => $component_status,
				'last_updated'     => $cti_row['last_updated'] ?? null,
				'latest_version'   => $cti_row['latest_version'] ?? null,
				'vulnerable'       => self::has_vulnerable_file( $cti_row ),
			);

			// Unknown components (not from WP.org) — skip file-level issues.
			$skip_file_issues = ( 'not_in_repository' === $component_status );

			if ( ! $skip_file_issues && isset( $cti_row['files'] ) && is_array( $cti_row['files'] ) ) {
				$hash_map = array();
				foreach ( $meta['hashes'] as $h ) {
					$hash_map[ $h['path'] ] = $h['sha256'];
				}
				foreach ( $cti_row['files'] as $f ) {
					$f       = (array) $f;
					$verdict = self::file_verdict( $f, $key );
					if ( null === $verdict ) {
						$ui_entry['unverified_paths'][] = (string) ( $f['path'] ?? '' );
						continue;
					}
					if ( 'ok' === $verdict ) {
						continue;
					}
					if ( ! isset( $f['sha256'] ) && isset( $hash_map[ $f['path'] ] ) ) {
						$f['sha256'] = $hash_map[ $f['path'] ];
					}
					if ( 'unknown' === $verdict && self::EMPTY_FILE_SHA256 === ( $f['sha256'] ?? '' ) ) {
						continue;
					}
					$ui_entry['issues'][] = $this->merge_saved_status( $key, $f, $saved_status_map );
				}
			}

			$this->state['results'][] = $ui_entry;
		}

		$this->state['cursor']   += count( $slice );
		$this->state['processed'] = $this->state['cursor'];

		if ( $this->state['cursor'] >= $this->state['total'] ) {
			$this->complete();
			return $this->build_progress( true );
		}

		$this->save_state();
		return $this->build_progress( false );
	}

	/**
	 * Assemble the next request chunk starting at $cursor, bounded by both
	 * CHUNK_SIZE (component count) and max_chunk_bytes (serialized body size).
	 * A component whose file list alone exceeds the byte cap is isolated into
	 * its own request so it can never drag a neighbour over the server limit.
	 *
	 * @param int $cursor Queue offset to start from.
	 * @return array{0:array,1:array,2:array} [slice, cti_payload, component_meta].
	 */
	private function build_chunk( $cursor ) {
		$slice          = array();
		$cti_payload    = array();
		$component_meta = array();
		$accum_bytes    = 0;
		$start          = (int) $cursor;
		$idx            = $start;
		$total          = (int) $this->state['total'];

		// Every iteration pushes exactly one component (or breaks before it),
		// so the running chunk size is $idx - $start.
		while ( $idx < $total && ( $idx - $start ) < self::CHUNK_SIZE ) {
			$component = $this->state['queue'][ $idx ];
			$hashes    = $this->discovery->collect_hashes( $component['type'], $component['slug'] );
			$entry     = array(
				'component_type' => $component['type'],
				'name'           => $component['slug'],
				'version'        => $component['version'],
				'path'           => $this->component_path( $component ),
				'files'          => $hashes,
			);
			$encoded   = wp_json_encode( $entry );
			// A failed encode (false) must not read as 0 bytes and defeat the
			// cap — treat it as over-cap so the component is isolated.
			$entry_bytes = ( false === $encoded ) ? $this->max_chunk_bytes + 1 : strlen( $encoded );

			// Never start a chunk with nothing; but once it holds a component,
			// stop before a new entry would push the body past the cap.
			if ( ! empty( $slice ) && ( $accum_bytes + $entry_bytes ) > $this->max_chunk_bytes ) {
				break;
			}

			$slice[]          = $component;
			$cti_payload[]    = $entry;
			$component_meta[] = array(
				'component' => $component,
				'hashes'    => $hashes,
			);
			$accum_bytes     += $entry_bytes;
			++$idx;

			// A single component that alone exceeds the cap is sent isolated.
			if ( $accum_bytes > $this->max_chunk_bytes ) {
				break;
			}
		}

		return array( $slice, $cti_payload, $component_meta );
	}

	/**
	 * Handle a failed CTI integrity_check for the in-flight chunk without
	 * stalling the scan. A permanent 4xx (retrying the identical body is
	 * futile) or a transient failure that has exhausted its retry budget marks
	 * the chunk's components unverified and advances the cursor. Transient
	 * failures below the budget hold the cursor for a bounded retry.
	 *
	 * @param WP_Error|mixed $cti_result     The failed result (WP_Error or non-array).
	 * @param array          $slice          Components in the failed chunk.
	 * @param array          $component_meta  Per-component {component, hashes} metadata.
	 * @return array Progress shape.
	 */
	private function handle_chunk_failure( $cti_result, array $slice, array $component_meta ) {
		$status  = 0;
		$message = 'unexpected response';
		if ( is_wp_error( $cti_result ) ) {
			$message = $cti_result->get_error_message();
			$data    = $cti_result->get_error_data();
			if ( is_array( $data ) && isset( $data['status'] ) ) {
				$status = (int) $data['status'];
			}
		}

		if ( ! $this->is_permanent_failure( $status ) ) {
			$cursor = (int) $this->state['cursor'];
			if ( (int) ( $this->state['retry_cursor'] ?? -1 ) === $cursor ) {
				$this->state['retry_count'] = (int) ( $this->state['retry_count'] ?? 0 ) + 1;
			} else {
				$this->state['retry_cursor'] = $cursor;
				$this->state['retry_count']  = 1;
			}

			if ( (int) $this->state['retry_count'] < self::MAX_CHUNK_RETRIES ) {
				Segurium_Debug::log(
					sprintf(
						'[segurium] integrity_check chunk transient failure (status=%d, attempt %d/%d): %s',
						$status,
						(int) $this->state['retry_count'],
						self::MAX_CHUNK_RETRIES,
						$message
					)
				);
				$this->save_state();
				return $this->build_progress( false );
			}

			Segurium_Debug::log(
				sprintf(
					'[segurium] integrity_check chunk failed %d attempts (status=%d): %s — skipping and advancing',
					self::MAX_CHUNK_RETRIES,
					$status,
					$message
				)
			);
		} else {
			Segurium_Debug::log(
				sprintf(
					'[segurium] integrity_check chunk permanent failure (status=%d): %s — skipping and advancing',
					$status,
					$message
				)
			);
		}

		// Record the skipped components as unverified rather than as results.
		// A result row with empty issues would be reconciled as verified-clean
		// on completion — silently resolving any pre-existing open finding for
		// the component. `unverified` keeps the component out of the not-found
		// sweep while leaving its persisted state untouched until a later scan
		// actually checks it.
		foreach ( $component_meta as $meta ) {
			$comp                        = $meta['component'];
			$this->state['unverified'][] = $comp['type'] . ':' . $comp['slug'];
		}

		$this->state['cursor']      += count( $slice );
		$this->state['processed']    = $this->state['cursor'];
		$this->state['retry_cursor'] = -1;
		$this->state['retry_count']  = 0;

		if ( $this->state['cursor'] >= $this->state['total'] ) {
			$this->complete();
			return $this->build_progress( true );
		}

		$this->save_state();
		return $this->build_progress( false );
	}

	/**
	 * Whether a CTI failure with the given HTTP status is permanent (the same
	 * request body will be rejected again). 4xx are permanent except 408
	 * (Request Timeout) and 429 (Too Many Requests), which are transient. A
	 * status of 0 (connection loss, no HTTP response) and any 5xx are transient.
	 *
	 * @param int $status HTTP status code, or 0 when there was no response.
	 * @return bool
	 */
	private function is_permanent_failure( $status ) {
		if ( $status >= 400 && $status < 500 ) {
			return ! in_array( (int) $status, array( 408, 429 ), true );
		}
		return false;
	}

	/**
	 * Load scan state from the active tmp workspace via runtime_kv.
	 *
	 * @return bool True if state was loaded, false otherwise.
	 */
	public function load_state() {
		$active_json = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s AND (expires_at IS NULL OR expires_at > %d)',
			array( 'integrity_scan_active', time() )
		);
		if ( ! $active_json ) {
			return false;
		}
		$active = json_decode( $active_json, true );
		if ( ! is_array( $active ) || empty( $active['workspace'] ) ) {
			return false;
		}
		$this->workspace = $active['workspace'];

		$json = Segurium_Storage::tmp_read( $this->workspace, 'state.json' );
		if ( ! $json ) {
			return false;
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || empty( $data['scan_id'] ) ) {
			return false;
		}
		$this->state = array_merge( $this->state, $data );
		return true;
	}

	/**
	 * Return the current scan state array.
	 *
	 * @return array
	 */
	public function get_state() {
		return $this->state;
	}

	/**
	 * Build a progress response for the frontend.
	 *
	 * @param bool $completed Whether the scan has completed.
	 * @return array Progress data.
	 */
	public function build_progress( $completed = false ) {
		$out = array(
			'running'      => ! empty( $this->state['scan_id'] ) && ! $completed,
			'completed'    => (bool) $completed,
			'scan_id'      => $this->state['scan_id'],
			'total'        => (int) $this->state['total'],
			'processed'    => (int) $this->state['processed'],
			'currently'    => $this->current_label(),
			'elapsed_secs' => $this->state['started_at'] > 0 ? max( 0, time() - (int) $this->state['started_at'] ) : 0,
		);
		if ( $completed ) {
			$out['running']    = false;
			$out['components'] = $this->state['results'];
		}
		return $out;
	}

	/**
	 * Return the label for the currently processing component.
	 *
	 * @return string|null
	 */
	private function current_label() {
		return $this->state['currently'];
	}

	/**
	 * Finalize the scan: persist results to integrity_issues table, clean workspace.
	 */
	private function complete() {
		$this->flush_issues_to_table();

		if ( $this->workspace ) {
			Segurium_Storage::tmp_destroy( $this->workspace );
			$this->workspace = null;
		}
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => 'integrity_scan_active' ) );
	}

	/**
	 * Upsert all file-level findings from the completed scan into integrity_issues table.
	 * Also records the last-scan timestamp in runtime_kv.
	 */
	private function flush_issues_to_table() {
		$now = time();

		foreach ( $this->state['results'] as $comp ) {
			foreach ( $comp['issues'] as $issue ) {
				if ( ! is_string( $issue['verdict'] ?? null ) || '' === $issue['verdict'] ) {
					continue;
				}
				$file_sha256 = (string) ( $issue['sha256'] ?? '' );
				Segurium_Storage::table_upsert(
					'integrity_issues',
					array(
						'comp_type'      => $comp['type'],
						'comp_slug'      => $comp['slug'],
						'comp_version'   => $comp['version'],
						'comp_name'      => $comp['name'] ?? $comp['slug'],
						'file_path'      => $issue['path'],
						'file_path_hash' => hash( 'sha256', $issue['path'] ),
						'verdict'        => $issue['verdict'],
						'status'         => $issue['status'] ?? 'open',
						'sha256'         => $file_sha256,
						'is_malicious'   => Segurium_Integrity_Server_State::lookup_is_malicious( $file_sha256 ),
						'backup_id'      => $issue['backup_id'] ?? null,
						'created_at'     => $now,
						'fixed_at'       => isset( $issue['fixed_at'] ) && $issue['fixed_at'] ? (int) $issue['fixed_at'] : null,
					),
					array( 'comp_type', 'comp_slug', 'file_path_hash' )
				);
			}
		}

		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => 'integrity:last_scan',
				'kv_value'   => (string) $now,
				'expires_at' => null,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
	}

	/**
	 * Persist current scan state to the tmp workspace.
	 */
	private function save_state() {
		if ( ! $this->workspace ) {
			return;
		}
		Segurium_Storage::tmp_write( $this->workspace, 'state.json', wp_json_encode( $this->state ) );
	}

	/**
	 * Resolve the relative path for a component.
	 *
	 * @param array $component Component descriptor with type and slug.
	 * @return string Relative path.
	 */
	private function component_path( array $component ) {
		switch ( $component['type'] ) {
			case 'core':
				return $this->base_path;
			case 'plugin':
				return 'wp-content/plugins/' . $component['slug'];
			case 'theme':
				return 'wp-content/themes/' . $component['slug'];
		}
		return '';
	}

	/**
	 * Whether the cloud flagged any file of this component as belonging to a
	 * release with a known vulnerability.
	 *
	 * The flag rides on pristine files, which never become findings, so it is
	 * read here rather than from the issue list. A build talking to a service
	 * that does not send it sees no flag and behaves as before.
	 *
	 * @param array $cti_row One component row from the integrity response.
	 * @return bool
	 */
	private static function has_vulnerable_file( $cti_row ) {
		foreach ( $cti_row['files'] ?? array() as $file ) {
			if ( ! empty( $file['vulnerable'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Read one file row's verdict, logging a row that carries none.
	 *
	 * @param array  $file          One file row from the integrity response.
	 * @param string $component_key `<type>:<slug>` of the owning component.
	 * @return string|null Null when the verdict is absent, empty or not a string.
	 */
	public static function file_verdict( array $file, $component_key ) {
		$verdict = $file['verdict'] ?? null;
		if ( is_string( $verdict ) && '' !== $verdict ) {
			return $verdict;
		}
		Segurium_Debug::log(
			sprintf(
				'[segurium] integrity_verdict_missing: CTI returned no verdict for %s in %s, file dropped',
				(string) ( $file['path'] ?? '' ),
				(string) $component_key
			)
		);
		return null;
	}

	/**
	 * Loads the previous scan results from the integrity_issues table and indexes
	 * each issue by `<type>:<slug>:<path>` so we can preserve the user's
	 * fix/delete state across re-scans.
	 */
	private function load_saved_status_map() {
		if ( null !== $this->saved_status_map ) {
			return $this->saved_status_map;
		}

		$rows = Segurium_Storage::table_get_results(
			'integrity_issues',
			'SELECT comp_type, comp_slug, file_path, status, backup_id, fixed_at FROM {{table}}',
			array(),
			ARRAY_A
		);

		$map = array();
		foreach ( $rows as $row ) {
			$key         = $row['comp_type'] . ':' . $row['comp_slug'] . ':' . $row['file_path'];
			$map[ $key ] = array(
				'path'      => $row['file_path'],
				'status'    => $row['status'],
				'backup_id' => $row['backup_id'],
				'fixed_at'  => $row['fixed_at'],
			);
		}

		$this->saved_status_map = $map;
		return $map;
	}

	/**
	 * Merge the previously persisted fix-state for a file into the new
	 * issue payload. A file marked fixed/deleted that's still flagged by
	 * CTI gets reset to 'open' so the Fix button reappears.
	 *
	 * @param string $key       Component key (type:slug).
	 * @param array  $issue     New issue data from CTI.
	 * @param array  $saved_map Previously saved status map.
	 * @return array Updated issue with merged status.
	 */
	private function merge_saved_status( $key, array $issue, array $saved_map ) {
		$ikey = $key . ':' . ( $issue['path'] ?? '' );
		if ( ! isset( $saved_map[ $ikey ] ) ) {
			$issue['status']    = 'open';
			$issue['backup_id'] = null;
			$issue['fixed_at']  = null;
			return $issue;
		}
		$prev        = $saved_map[ $ikey ];
		$prev_status = $prev['status'] ?? 'open';
		if ( in_array( $prev_status, array( 'fixed', 'deleted' ), true ) ) {
			$issue['status']    = 'open';
			$issue['backup_id'] = $prev['backup_id'] ?? null;
			$issue['fixed_at']  = null;
		} else {
			$issue['status']    = $prev_status;
			$issue['backup_id'] = $prev['backup_id'] ?? null;
			$issue['fixed_at']  = $prev['fixed_at'] ?? null;
		}
		return $issue;
	}

	/**
	 * Whether the scan has processed all queued components.
	 *
	 * @return bool
	 */
	public function is_completed() {
		return $this->state['cursor'] >= $this->state['total']
			&& $this->state['total'] > 0;
	}

	/**
	 * Return a read-only progress snapshot for the runner's status endpoint.
	 *
	 * @return array
	 */
	public function get_progress_snapshot() {
		$completed = $this->is_completed();
		return $this->build_progress( $completed );
	}

	/**
	 * Mark this scan as cancelled (user-initiated stop). Removes the
	 * workspace so no stale progress lingers. Accepts a reason
	 * code for signature parity with `Segurium_Scan::mark_cancelled()`;
	 * integrity scans don't write a `scan_history` row today, so the code is
	 * accepted but not persisted by this engine.
	 *
	 * @param string $reason_code Reason code from `Segurium_Scan_Runner::REASON_*`.
	 * @param bool   $cleanup     When false, skip
	 *                            `cleanup_workspace()` so a parallel worker
	 *                            mid-tick can run cleanup itself via the
	 *                            cooperative cancel handshake.
	 * @return void
	 */
	public function mark_cancelled( $reason_code = Segurium_Scan_Runner::REASON_USER_CANCEL, $cleanup = true ) {
		Segurium_Storage::cti_send_message(
			'scan_cancelled',
			$this->terminal_message_payload(
				(string) $reason_code,
				array( 'cancelled_by' => Segurium_Scan_Runner::cancelled_by( $reason_code ) )
			)
		);
		if ( $cleanup ) {
			$this->cleanup_workspace();
		}
	}

	/**
	 * Mark this scan as aborted. Same cleanup as cancellation for integrity
	 * scans. Accepts a reason code for signature parity.
	 *
	 * @param string $reason_code Reason code from `Segurium_Scan_Runner::REASON_*`.
	 * @param bool   $cleanup     When false, skip
	 *                            `cleanup_workspace()` so a parallel worker
	 *                            mid-tick can run cleanup itself via the
	 *                            cooperative cancel handshake.
	 * @return void
	 */
	public function mark_aborted( $reason_code = Segurium_Scan_Runner::REASON_RUNTIME_ERROR, $cleanup = true ) {
		Segurium_Storage::cti_send_message(
			'scan_aborted',
			$this->terminal_message_payload( (string) $reason_code )
		);
		if ( $cleanup ) {
			$this->cleanup_workspace();
		}
	}

	/**
	 * Build the integrity-scan terminal message payload.
	 *
	 * @param string $reason_code REASON_* constant for `error_code`.
	 * @param array  $extra       Per-message_type additions.
	 * @return array
	 */
	private function terminal_message_payload( $reason_code, array $extra = array() ) {
		$started  = isset( $this->state['started_at'] ) ? (int) $this->state['started_at'] : 0;
		$duration = $started > 0 ? max( 0, time() - $started ) : 0;
		return array_merge(
			array(
				'scan_id'          => isset( $this->state['scan_id'] ) ? (string) $this->state['scan_id'] : '',
				'scan_type'        => 'integrity',
				'error_code'       => (string) $reason_code,
				'duration_seconds' => $duration,
			),
			$extra
		);
	}

	/**
	 * Idempotent workspace teardown for the cooperative-cancel
	 * handshake. The runner's chunk-loop cancel observer calls this from the
	 * worker-side so cleanup never races a live tick reading the workspace.
	 *
	 * @return void
	 */
	public function cleanup_state() {
		$this->cleanup_workspace();
	}

	/**
	 * Destroy the tmp workspace and clear the runtime_kv active-scan marker.
	 */
	private function cleanup_workspace() {
		// Resolve workspace path from runtime_kv if not already loaded.
		if ( null === $this->workspace ) {
			$active_json = Segurium_Storage::table_get_var(
				'runtime_kv',
				'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
				array( 'integrity_scan_active' )
			);
			if ( $active_json ) {
				$active          = json_decode( $active_json, true );
				$this->workspace = is_array( $active ) ? ( $active['workspace'] ?? null ) : null;
			}
		}

		if ( $this->workspace && is_dir( $this->workspace ) ) {
			Segurium_Storage::tmp_destroy( $this->workspace );
		}
		$this->workspace = null;

		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => 'integrity_scan_active' ) );
	}
}

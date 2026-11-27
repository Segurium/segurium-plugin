<?php
/**
 * Walk of the database fields that can hold a script, for the Database phase.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads six table fields by primary key in pages, one page per step, keeps
 * each distinct script once by hash and every place it was found, then
 * hands the scripts to the item pipeline as its reader.
 */
final class Segurium_Db_Script_Walk {

	const KIND             = 'db_js';
	const KIND_SRC         = 'db_js_src';
	const CAP              = 2000;
	const MAX_SCRIPT_BYTES = 262144;
	const MAX_FIELD_BYTES  = 4194304;
	const MAX_TRACKED      = 10000;
	const MAX_LISTED       = 20;
	const PAGE_ROWS        = 1000;
	const PAGE_MIN         = 100;
	const PAGE_MAX         = 20000;
	const PAGE_TARGET_SEC  = 1.0;
	const PAGE_CUT_SEC     = 2.0;
	const FETCH_ROWS       = 100;
	const OVER_PREFIX      = 16;
	const RETRY_GAPS_SEC   = array( 15, 45 );

	const KV_PREFIX  = 'script_walk:';
	const PLACES     = 'places.jsonl';
	const INFLIGHT   = 'page';
	const FAIL_TABLE = 'ABORTED_CONTENT_TABLE_READ_FAILED';

	const KEYS = array(
		self::KIND     => array(
			'kept'        => 'scripts',
			'over_cap'    => 'over',
			'untracked'   => 'untracked',
			'body_prefix' => '',
		),
		self::KIND_SRC => array(
			'kept'        => 'sources',
			'over_cap'    => 'over_src',
			'untracked'   => 'untracked_src',
			'body_prefix' => 'src-',
		),
	);

	/**
	 * The fields of each table, in walk order. `core` tables always exist;
	 * the others are read when the site holds them with these columns.
	 */
	const TABLES = array(
		'posts'        => array(
			'key'    => 'ID',
			'fields' => array( 'post_content' ),
			'decode' => false,
			'core'   => true,
		),
		'postmeta'     => array(
			'key'    => 'meta_id',
			'fields' => array( 'meta_value' ),
			'decode' => true,
			'core'   => true,
		),
		'options'      => array(
			'key'    => 'option_id',
			'fields' => array( 'option_value' ),
			'decode' => true,
			'core'   => true,
		),
		'comments'     => array(
			'key'    => 'comment_ID',
			'fields' => array( 'comment_content', 'comment_author_email' ),
			'decode' => false,
			'core'   => true,
		),
		'hfcm_scripts' => array(
			'key'    => 'script_id',
			'fields' => array( 'snippet' ),
			'decode' => false,
			'core'   => false,
		),
		'snippets'     => array(
			'key'    => 'id',
			'fields' => array( 'code' ),
			'decode' => false,
			'core'   => false,
		),
	);

	/**
	 * Run ID.
	 *
	 * @var string
	 */
	private $run_id;

	/**
	 * Walk state, null when none is loaded.
	 *
	 * @var array|null
	 */
	private $state = null;

	/**
	 * State as last seen, kept for the counters after {@see drop()}.
	 *
	 * @var array|null
	 */
	private $last = null;

	/**
	 * JSON of the state row as stored.
	 *
	 * @var string
	 */
	private $stored = '';

	/**
	 * Constructor.
	 *
	 * @param string $run_id Run ID.
	 */
	public function __construct( $run_id ) {
		$this->run_id = (string) $run_id;
	}

	/**
	 * Create the state. A repeat keeps the state the run already holds.
	 * Removes the state and the locations of earlier runs.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the state row cannot be written.
	 */
	public function start() {
		if ( $this->load() ) {
			return;
		}
		$this->drop_other_runs();
		$tables = array();
		foreach ( array_keys( self::TABLES ) as $name ) {
			$tables[ $name ] = array(
				'after' => 0,
				'page'  => self::PAGE_ROWS,
				'until' => 0,
				'done'  => false,
				'tries' => 0,
				'code'  => '',
			);
		}
		$this->state = array(
			'began'         => false,
			'done'          => false,
			'tables'        => $tables,
			'retry_at'      => 0,
			'workspace'     => '',
			'base64'        => true,
			'placed_at'     => 0,
			'scripts'       => array(),
			'over'          => array(),
			'untracked'     => 0,
			'sources'       => array(),
			'over_src'      => array(),
			'untracked_src' => 0,
			'rows'          => 0,
			'candidates'    => 0,
			'places'        => 0,
			'over_limit'    => 0,
			'skipped_rows'  => 0,
			'read'          => 0,
			'fault'         => '',
		);
		$this->save();
	}

	/**
	 * Read the state an earlier request saved.
	 *
	 * @return bool
	 */
	public function load() {
		$raw          = (string) Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( self::KV_PREFIX . $this->run_id )
		);
		$state        = json_decode( $raw, true );
		$this->state  = is_array( $state ) && isset( $state['tables'], $state['scripts'] ) && is_array( $state['scripts'] ) ? $state + array(
			'sources'       => array(),
			'over_src'      => array(),
			'untracked_src' => 0,
		) : null;
		$this->stored = null === $this->state ? '' : $raw;
		return null !== $this->state;
	}

	/**
	 * Whether a state is loaded.
	 *
	 * @return bool
	 */
	public function loaded() {
		return null !== $this->state;
	}

	/**
	 * Whether every table was walked.
	 *
	 * @return bool
	 */
	public function finished() {
		return null !== $this->state && ! empty( $this->state['done'] );
	}

	/**
	 * Reason code that fails the part once its pipeline is done, or ''.
	 *
	 * @return string
	 */
	public function fault() {
		if ( null === $this->state && null === $this->last ) {
			$this->load();
		}
		$state = null === $this->state ? $this->last : $this->state;
		return null === $state ? '' : (string) $state['fault'];
	}

	/**
	 * One page of the first table not yet walked.
	 *
	 * @return string {@see Segurium_Content_Items::GO}, or WAIT while a read waits for its next try.
	 */
	public function step() {
		if ( ( null === $this->state && ! $this->load() ) || $this->finished() ) {
			return Segurium_Content_Items::GO;
		}
		if ( time() < (int) $this->state['retry_at'] || ! Segurium_Scan_Runner::renew_liveness( $this->run_id ) ) {
			return Segurium_Content_Items::WAIT;
		}
		if ( ! $this->state['began'] ) {
			$this->state['began']  = true;
			$this->state['base64'] = self::base64_in_sql();
		}
		if ( ! $this->open_workspace() ) {
			$this->fail( Segurium_Content_Items::FAIL_STORAGE );
			$this->state['done'] = true;
			$this->save();
			return Segurium_Content_Items::GO;
		}
		foreach ( $this->state['tables'] as $name => $table ) {
			if ( ! $table['done'] ) {
				return $this->page( $name );
			}
		}
		$this->state['done'] = true;
		$this->save();
		return Segurium_Content_Items::GO;
	}

	/**
	 * The reader of the pipeline: one item per distinct script inside the
	 * cap, then null for each script past the cap.
	 *
	 * @param int    $cap  Most items the pipeline takes.
	 * @param string $kind KIND or KIND_SRC.
	 * @return Generator Yields `{locator, body}`, `{locator, sha256, size}` or null.
	 */
	public function items( $cap, $kind = self::KIND ) {
		if ( ( null === $this->state && ! $this->load() ) || ! isset( self::KEYS[ $kind ] ) ) {
			return;
		}
		$map    = self::KEYS[ $kind ]['kept'];
		$listed = array();
		foreach ( $this->places( $kind ) as $place ) {
			$sha = $place[0];
			if ( isset( $this->state[ $map ][ $sha ] ) && ( ! isset( $listed[ $sha ] ) || count( $listed[ $sha ] ) < self::MAX_LISTED ) ) {
				$listed[ $sha ][] = self::location( $place );
			}
		}
		$taken = 0;
		$lost  = false;
		foreach ( $this->state[ $map ] as $sha => $script ) {
			$sha     = (string) $sha;
			$locator = self::locator( isset( $listed[ $sha ] ) ? $listed[ $sha ] : array(), (int) $script[1] );
			if ( ++$taken > $cap ) {
				yield null;
			} elseif ( (int) $script[0] > self::MAX_SCRIPT_BYTES ) {
				yield array(
					'locator' => $locator,
					'sha256'  => $sha,
					'size'    => (int) $script[0],
				);
			} else {
				$body = $this->workspace_valid() ? Segurium_Storage::tmp_read( $this->state['workspace'], self::KEYS[ $kind ]['body_prefix'] . $sha ) : null;
				if ( null === $body || hash( 'sha256', $body ) !== $sha ) {
					$lost = true;
					continue;
				}
				yield array(
					'locator' => $locator,
					'body'    => $body,
				);
			}
		}
		for ( $left = count( $this->state[ self::KEYS[ $kind ]['over_cap'] ] ) + (int) $this->state[ self::KEYS[ $kind ]['untracked'] ]; $left > 0; $left-- ) {
			yield null;
		}
		if ( $lost ) {
			$this->fail( Segurium_Content_Items::FAIL_STORAGE );
			$this->save();
		}
	}

	/**
	 * Remove the stored scripts of one kind once its pipeline holds its own copies. The places stay.
	 *
	 * @param string $kind KIND or KIND_SRC.
	 * @return void
	 */
	public function drop_bodies( $kind = self::KIND ) {
		if ( ( null === $this->state && ! $this->load() ) || ! $this->workspace_valid() || ! isset( self::KEYS[ $kind ] ) ) {
			return;
		}
		foreach ( array_keys( $this->state[ self::KEYS[ $kind ]['kept'] ] ) as $sha ) {
			$path = $this->state['workspace'] . '/' . self::KEYS[ $kind ]['body_prefix'] . $sha;
			if ( is_file( $path ) ) {
				Segurium_Fs::delete( $path );
			}
		}
	}

	/**
	 * Every place a script of one kind inside the cap was found, in walk order.
	 *
	 * @param string $kind KIND or KIND_SRC.
	 * @return Generator Yields `[sha256, table, key, column, encoding, option name]`.
	 */
	public function places( $kind = self::KIND ) {
		if ( ( null === $this->state && ! $this->load() ) || ! $this->workspace_valid() ) {
			return;
		}
		$handle = Segurium_Fs::open( $this->state['workspace'] . '/' . self::PLACES, 'rb' );
		if ( false === $handle ) {
			return;
		}
		try {
			for ( $line = fgets( $handle ); false !== $line; $line = fgets( $handle ) ) {
				$place = json_decode( $line, true );
				if ( is_array( $place ) && 7 === count( $place ) && $kind === $place[6] ) {
					yield array_slice( $place, 0, 6 );
				}
			}
		} finally {
			Segurium_Fs::close( $handle );
		}
	}

	/**
	 * Counts of the walk, without the prefix of the part. Empty until the walk began.
	 *
	 * @return array<string,int>
	 */
	public function counters() {
		if ( null === $this->state && null === $this->last ) {
			$this->load();
		}
		$state = null === $this->state ? $this->last : $this->state;
		if ( null === $state || empty( $state['began'] ) ) {
			return array();
		}
		$failed = 0;
		foreach ( $state['tables'] as $table ) {
			$failed += '' === $table['code'] ? 0 : 1;
		}
		$counters = array(
			'rows'       => (int) $state['rows'],
			'candidates' => (int) $state['candidates'],
			'places'     => (int) $state['places'],
			'distinct'   => count( $state['scripts'] ) + count( $state['over'] ) + (int) $state['untracked'] + count( $state['sources'] ) + count( $state['over_src'] ) + (int) $state['untracked_src'],
			'tables'     => (int) $state['read'],
		);
		$extra    = array(
			'fields_over_limit' => (int) $state['over_limit'],
			'rows_skipped'      => (int) $state['skipped_rows'],
			'tables_failed'     => $failed,
			'base64_off'        => empty( $state['base64'] ) ? 1 : 0,
		);
		return $counters + array_filter( $extra );
	}

	/**
	 * Remove the state row and the locations. The counters stay readable.
	 *
	 * @return void
	 */
	public function drop() {
		if ( null !== $this->state || $this->load() ) {
			$this->last = $this->state;
			self::destroy_workspace( $this->state );
		}
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::KV_PREFIX . $this->run_id ) );
		$this->state  = null;
		$this->stored = '';
	}

	/**
	 * Walk one page of a table. A read that fails leaves the state as it was.
	 *
	 * @param string $name Table name without the prefix.
	 * @return string
	 */
	private function page( $name ) {
		global $wpdb;
		$spec   = self::TABLES[ $name ];
		$table  = self::table( $name );
		$before = $this->state;
		$walk   = $this->state['tables'][ $name ];
		$quiet  = $wpdb->suppress_errors( true );
		try {
			$dead = json_decode( (string) Segurium_Storage::tmp_read( $this->state['workspace'], self::INFLIGHT ), true );
			if ( is_array( $dead ) && isset( $dead['t'], $dead['a'], $dead['n'], $dead['p'], $dead['l'] ) && $name === $dead['t'] && (int) $walk['after'] === (int) $dead['a'] ) {
				return $this->resume( $name, $dead );
			}
			if ( ! isset( $walk['binary'] ) ) {
				$walk['binary'] = self::binary_fields( $table, $spec );
				if ( null === $walk['binary'] && $spec['core'] ) {
					return $this->read_failed( $name, $before, '' === $wpdb->last_error ? 'the table shows no such columns' : $wpdb->last_error );
				}
				if ( null === $walk['binary'] ) {
					$this->state['tables'][ $name ]['done'] = true;
					$this->save();
					return Segurium_Content_Items::GO;
				}
			}

			$started = microtime( true );
			$keys    = $wpdb->get_col( $wpdb->prepare( 'SELECT %i FROM %i WHERE %i > %d ORDER BY %i LIMIT %d', $spec['key'], $table, $spec['key'], (int) $walk['after'], $spec['key'], (int) $walk['page'] ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a walk of the table, each page read once.
			if ( '' !== $wpdb->last_error ) {
				return $this->read_failed( $name, $before, $wpdb->last_error );
			}
			$marker = array(
				't' => $name,
				'a' => (int) $walk['after'],
				'n' => count( $keys ),
				'p' => (int) $walk['page'],
				'l' => empty( $keys ) ? 0 : (int) end( $keys ),
			);
			if ( ! Segurium_Storage::tmp_write( $this->state['workspace'], self::INFLIGHT, (string) wp_json_encode( $marker ) ) ) {
				return $this->give_up();
			}
			$lines = '';
			if ( ! empty( $keys ) ) {
				$upper  = (int) end( $keys );
				$filter = $this->filter( $spec, $walk['binary'] );
				$args   = array_merge( array( $spec['key'] ), $filter['size_args'], array( $table, $spec['key'], (int) $walk['after'], $spec['key'], $upper ), $filter['args'], array( $spec['key'] ) );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber, PluginCheck.Security.DirectDB.UnescapedDBParameter -- the filter holds placeholders only, one OR term per field, its identifiers come from TABLES.
				$found = $wpdb->get_results( $wpdb->prepare( 'SELECT %i AS k, ' . $filter['size'] . ' AS n FROM %i WHERE %i > %d AND %i <= %d AND (' . $filter['sql'] . ') ORDER BY %i', $args ), ARRAY_A );
				if ( '' !== $wpdb->last_error ) {
					return $this->read_failed( $name, $before, $wpdb->last_error );
				}
				$taken = 0;
				foreach ( self::batches( (array) $found ) as $batch ) {
					$read = $this->fetch( $name, $table, $batch );
					if ( false === $read ) {
						return $this->read_failed( $name, $before, $wpdb->last_error );
					}
					$lines .= $read;
					$taken += count( $batch );
					if ( $taken < count( $found ) && microtime( true ) - $started > self::PAGE_CUT_SEC ) {
						$upper = (int) end( $batch );
						break;
					}
				}
				foreach ( $keys as $row_key ) {
					$this->state['rows'] += (int) $row_key <= $upper ? 1 : 0;
				}
				$this->state['candidates'] += $taken;
				$walk['after']              = $upper;
			}
			if ( '' !== $lines ) {
				$path    = $this->state['workspace'] . '/' . self::PLACES;
				$written = Segurium_Fs::write( $path, $lines, FILE_APPEND | LOCK_EX );
				if ( strlen( $lines ) !== $written ) {
					$this->fail( Segurium_Content_Items::FAIL_STORAGE );
				}
				clearstatcache( true, $path );
				$this->state['placed_at'] = (int) Segurium_Fs::size( $path );
			}
			$walk['tries'] = 0;
			if ( empty( $keys ) || ( count( $keys ) < (int) $walk['page'] && (int) end( $keys ) === (int) $walk['after'] ) ) {
				$walk['done'] = true;
				++$this->state['read'];
			}
			$fit                            = (int) ( $walk['page'] * self::PAGE_TARGET_SEC / max( 0.01, microtime( true ) - $started ) );
			$walk['page']                   = (int) $walk['after'] >= (int) $walk['until']
				? max( self::PAGE_MIN, min( self::PAGE_MAX, 2 * (int) $walk['page'], $fit ) )
				: max( min( 2, (int) $walk['page'] ), min( (int) $walk['page'], $fit ) );
			$this->state['tables'][ $name ] = $walk;
			$this->save();
			return $this->clear_marker() ? Segurium_Content_Items::GO : $this->give_up();
		} finally {
			$wpdb->suppress_errors( $quiet );
		}
	}

	/**
	 * Go on after a page whose worker died, reading no row in this chunk.
	 *
	 * @param string $name Table name without the prefix.
	 * @param array  $dead Marker of the dead page: table, cursor, rows, page size asked for, last key.
	 * @return string
	 */
	private function resume( $name, array $dead ) {
		$walk = $this->state['tables'][ $name ];
		$path = $this->state['workspace'] . '/' . self::PLACES;
		if ( is_file( $path ) && (int) Segurium_Fs::size( $path ) > (int) $this->state['placed_at'] ) {
			Segurium_Fs::truncate( $path, (int) $this->state['placed_at'] );
		}
		if ( 1 === (int) $dead['n'] && 1 === (int) $dead['p'] ) {
			$walk['after'] = (int) $dead['l'];
			$walk['page']  = self::PAGE_MIN;
			++$this->state['rows'];
			++$this->state['skipped_rows'];
			Segurium_Debug::log( sprintf( '[segurium-db-scripts] row skipped table=%s key=%d: a page of this row alone did not end', $name, (int) $dead['l'] ) );
		} else {
			$walk['page']  = max( 1, intdiv( (int) $dead['n'], 2 ) );
			$walk['until'] = (int) $dead['l'];
		}
		Segurium_Debug::log( sprintf( '[segurium-db-scripts] resume table=%s after=%d page=%d', $name, (int) $walk['after'], (int) $walk['page'] ) );
		$this->state['tables'][ $name ] = $walk;
		$this->save();
		return $this->clear_marker() ? Segurium_Content_Items::GO : $this->give_up();
	}

	/**
	 * End the walk for a workspace that takes no marker.
	 *
	 * @return string
	 */
	private function give_up() {
		Segurium_Debug::log( sprintf( '[segurium-db-scripts] %s: the page marker cannot be written or removed', Segurium_Content_Items::FAIL_STORAGE ) );
		$this->fail( Segurium_Content_Items::FAIL_STORAGE );
		$this->state['done'] = true;
		$this->save();
		return Segurium_Content_Items::GO;
	}

	/**
	 * Candidate rows in groups of at most FETCH_ROWS rows and MAX_FIELD_BYTES of values.
	 *
	 * @param array $found Rows `{k, n}`: primary key and the bytes of the fields read.
	 * @return array<int,int[]>
	 */
	private static function batches( array $found ) {
		$batches = array();
		$batch   = array();
		$bytes   = 0;
		foreach ( $found as $row ) {
			$size = (int) $row['n'];
			if ( ! empty( $batch ) && ( count( $batch ) >= self::FETCH_ROWS || $bytes + $size > self::MAX_FIELD_BYTES ) ) {
				$batches[] = $batch;
				$batch     = array();
				$bytes     = 0;
			}
			$batch[] = (int) $row['k'];
			$bytes  += $size;
		}
		if ( ! empty( $batch ) ) {
			$batches[] = $batch;
		}
		return $batches;
	}

	/**
	 * Read a group of candidate rows and note the scripts of their fields.
	 *
	 * @param string $name  Table name without the prefix.
	 * @param string $table Table name.
	 * @param int[]  $keys  Primary keys.
	 * @return string|false The place lines of the rows, false when the read failed.
	 */
	private function fetch( $name, $table, array $keys ) {
		global $wpdb;
		$spec = self::TABLES[ $name ];
		$args = array( $spec['key'] );
		foreach ( $spec['fields'] as $index => $field ) {
			array_push( $args, $field, 'n' . $index, $field, self::MAX_FIELD_BYTES, $field, 'v' . $index );
		}
		$args = array_merge( $args, array( $table, $spec['key'] ), $keys, array( $spec['key'] ) );
		if ( 'options' === $name ) {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT %i AS k, option_name AS name, ' . implode( ', ', array_fill( 0, count( $spec['fields'] ), 'LENGTH(%i) AS %i, IF(LENGTH(%i) > %d, NULL, %i) AS %i' ) ) . ' FROM %i WHERE %i IN (' . implode( ', ', array_fill( 0, count( $keys ), '%d' ) ) . ') ORDER BY %i', $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a group of candidate rows, each read once.
		} else {
			$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT %i AS k, ' . implode( ', ', array_fill( 0, count( $spec['fields'] ), 'LENGTH(%i) AS %i, IF(LENGTH(%i) > %d, NULL, %i) AS %i' ) ) . ' FROM %i WHERE %i IN (' . implode( ', ', array_fill( 0, count( $keys ), '%d' ) ) . ') ORDER BY %i', $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- a group of candidate rows, each read once.
		}
		if ( '' !== $wpdb->last_error ) {
			return false;
		}
		$lines = '';
		foreach ( (array) $rows as $row ) {
			foreach ( $spec['fields'] as $index => $field ) {
				if ( null === $row[ 'v' . $index ] ) {
					$this->state['over_limit'] += (int) $row[ 'n' . $index ] > self::MAX_FIELD_BYTES ? 1 : 0;
					continue;
				}
				$found = Segurium_Script_Extractor::field( $row[ 'v' . $index ], $spec['decode'] );
				foreach ( self::KEYS as $kind => $keys ) {
					foreach ( $found[ $keys['kept'] ] as $sha => $identity ) {
						$place  = array( (string) $sha, $name, (int) $row['k'], $field, $found['encoding'], isset( $row['name'] ) ? (string) $row['name'] : '' );
						$lines .= $this->place( $place, $identity, $kind );
					}
				}
			}
		}
		return $lines;
	}

	/**
	 * Count one place of a script and keep the script the first time.
	 *
	 * @param array  $place    `[sha256, table, key, column, encoding, option name]`.
	 * @param string $identity Script bytes or address.
	 * @param string $kind     KIND or KIND_SRC.
	 * @return string The place line, '' for a script past the cap.
	 */
	private function place( array $place, $identity, $kind ) {
		$keys    = self::KEYS[ $kind ];
		$map     = $keys['kept'];
		$over    = $keys['over_cap'];
		$sha     = $place[0];
		$place[] = $kind;
		++$this->state['places'];
		if ( isset( $this->state[ $map ][ $sha ] ) ) {
			++$this->state[ $map ][ $sha ][1];
			return self::line( $place );
		}
		$short = substr( $sha, 0, self::OVER_PREFIX );
		if ( isset( $this->state[ $over ][ $short ] ) ) {
			return '';
		}
		$kept = count( $this->state['scripts'] ) + count( $this->state['sources'] );
		if ( $kept >= self::CAP ) {
			if ( $kept + count( $this->state['over'] ) + count( $this->state['over_src'] ) < self::MAX_TRACKED ) {
				$this->state[ $over ][ $short ] = 1;
			} else {
				++$this->state[ $keys['untracked'] ];
			}
			return '';
		}
		$size = strlen( $identity );
		if ( $size <= self::MAX_SCRIPT_BYTES && ! Segurium_Storage::tmp_write( $this->state['workspace'], $keys['body_prefix'] . $sha, $identity ) ) {
			$this->fail( Segurium_Content_Items::FAIL_STORAGE );
		}
		$this->state[ $map ][ $sha ] = array( $size, 1 );
		return self::line( $place );
	}

	/**
	 * One line of the places file.
	 *
	 * @param array $place `[sha256, table, key, column, encoding, option name, kind]`.
	 * @return string
	 */
	private static function line( array $place ) {
		return wp_json_encode( $place, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE ) . "\n";
	}

	/**
	 * The SQL filter that lets through the rows with a script, before PHP
	 * reads a value, and the bytes of the fields PHP reads of each row.
	 *
	 * @param array    $spec   Entry of TABLES.
	 * @param string[] $binary Fields whose collation tells case apart.
	 * @return array{sql:string,args:array,size:string,size_args:array}
	 */
	private function filter( array $spec, array $binary ) {
		global $wpdb;
		$like  = '%' . $wpdb->esc_like( '<script' ) . '%';
		$terms = array();
		$args  = array();
		$sizes = array();
		$bytes = array();
		foreach ( $spec['fields'] as $field ) {
			$terms[] = in_array( $field, $binary, true ) ? 'CONVERT(%i USING latin1) LIKE %s' : '%i LIKE %s';
			array_push( $args, $field, $like );
			if ( $spec['decode'] && ! empty( $this->state['base64'] ) ) {
				$terms[] = 'CONVERT(FROM_BASE64(%i) USING latin1) LIKE %s';
				array_push( $args, $field, $like );
			}
			$sizes[] = 'IF(LENGTH(%i) > %d, 0, LENGTH(%i))';
			array_push( $bytes, $field, self::MAX_FIELD_BYTES, $field );
		}
		return array(
			'sql'       => implode( ' OR ', $terms ),
			'args'      => $args,
			'size'      => implode( ' + ', $sizes ),
			'size_args' => $bytes,
		);
	}

	/**
	 * Count a failed read. The page repeats after a gap; past the last gap
	 * the table ends with its reason code and the walk goes on with the next table.
	 *
	 * @param string $name   Table name without the prefix.
	 * @param array  $before State before the page.
	 * @param string $error  Database error.
	 * @return string
	 */
	private function read_failed( $name, array $before, $error ) {
		$this->state = $before;
		$walk        = $this->state['tables'][ $name ];
		++$walk['tries'];
		Segurium_Debug::log( sprintf( '[segurium-db-scripts] %s table=%s try=%d: %s', self::FAIL_TABLE, $name, (int) $walk['tries'], substr( (string) $error, 0, 300 ) ) );
		if ( $walk['tries'] > count( self::RETRY_GAPS_SEC ) ) {
			$walk['done'] = true;
			$walk['code'] = self::FAIL_TABLE;
			$this->fail( self::FAIL_TABLE );
		} else {
			$this->state['retry_at'] = time() + self::RETRY_GAPS_SEC[ $walk['tries'] - 1 ];
		}
		$this->state['tables'][ $name ] = $walk;
		$this->save();
		if ( ! $this->clear_marker() ) {
			return $this->give_up();
		}
		return $walk['done'] ? Segurium_Content_Items::GO : Segurium_Content_Items::WAIT;
	}

	/**
	 * Remove the page marker when one is there.
	 *
	 * @return bool False when a marker stays.
	 */
	private function clear_marker() {
		$path = $this->state['workspace'] . '/' . self::INFLIGHT;
		return ! is_file( $path ) || Segurium_Fs::delete( $path );
	}

	/**
	 * Keep the first reason code that fails the part.
	 *
	 * @param string $reason_code Reason code.
	 * @return void
	 */
	private function fail( $reason_code ) {
		if ( '' === $this->state['fault'] ) {
			$this->state['fault'] = $reason_code;
		}
	}

	/**
	 * Make sure the workspace exists. A workspace lost after the walk stored
	 * a place or a script is a fault.
	 *
	 * @return bool
	 */
	private function open_workspace() {
		if ( $this->workspace_valid() ) {
			return true;
		}
		if ( '' !== $this->state['workspace'] ) {
			return false;
		}
		$workspace                = Segurium_Storage::tmp_make_workspace( 'scripts' );
		$this->state['workspace'] = false === $workspace ? '' : (string) $workspace;
		$this->save();
		return '' !== $this->state['workspace'];
	}

	/**
	 * Whether the workspace the state names exists.
	 *
	 * @return bool
	 */
	private function workspace_valid() {
		return '' !== $this->state['workspace'] && is_dir( $this->state['workspace'] );
	}

	/**
	 * Whether the database decodes base64, so the SQL filter can read encoded values.
	 *
	 * @return bool
	 */
	private static function base64_in_sql() {
		global $wpdb;
		$quiet   = $wpdb->suppress_errors( true );
		$decoded = $wpdb->get_var( "SELECT FROM_BASE64('PHNjcmlwdD4=')" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- asks the server, reads no table.
		$wpdb->suppress_errors( $quiet );
		return '<script>' === $decoded;
	}

	/**
	 * The fields of a table whose collation tells case apart, or null when
	 * the table lacks a column the walk reads.
	 *
	 * @param string $table Table name.
	 * @param array  $spec  Entry of TABLES.
	 * @return string[]|null
	 */
	private static function binary_fields( $table, array $spec ) {
		global $wpdb;
		$columns    = $wpdb->get_results( $wpdb->prepare( 'SHOW FULL COLUMNS FROM %i', $table ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- once per table and walk.
		$collations = array_column( (array) $columns, 'Collation', 'Field' );
		$binary     = array();
		foreach ( array_merge( array( $spec['key'] ), $spec['fields'] ) as $column ) {
			if ( ! array_key_exists( $column, $collations ) ) {
				return null;
			}
		}
		foreach ( $spec['fields'] as $field ) {
			if ( ! preg_match( '/_ci$/', (string) $collations[ $field ] ) ) {
				$binary[] = $field;
			}
		}
		return $binary;
	}

	/**
	 * Name of a table of the current site.
	 *
	 * @param string $name Table name without the prefix.
	 * @return string
	 */
	public static function table( $name ) {
		global $wpdb;
		return self::TABLES[ $name ]['core'] ? (string) $wpdb->$name : $wpdb->prefix . $name;
	}

	/**
	 * Text of one place: `db:<table>:<key>:<column>`, `db:options:<name>` for
	 * an option, and `+<encoding>` for a value that is not plain.
	 *
	 * @param array $place `[sha256, table, key, column, encoding, option name]`.
	 * @return string
	 */
	public static function location( array $place ) {
		$text = 'options' === $place[1] ? 'db:options:' . $place[5] : 'db:' . $place[1] . ':' . $place[2] . ':' . $place[3];
		return Segurium_Script_Extractor::PLAIN === $place[4] ? $text : $text . '+' . $place[4];
	}

	/**
	 * Locator of a script: its first places, as many as fit, then the total.
	 *
	 * @param string[] $listed First places, in walk order.
	 * @param int      $total Places of the script.
	 * @return string
	 */
	private static function locator( array $listed, $total ) {
		$suffix = ' total=' . $total;
		$text   = '';
		foreach ( $listed as $location ) {
			$next = '' === $text ? $location : $text . ' ' . $location;
			if ( '' !== $text && strlen( $next . $suffix ) > Segurium_Content_Items::MAX_LOCATOR_BYTES ) {
				break;
			}
			$text = $next;
		}
		return substr( $text, 0, Segurium_Content_Items::MAX_LOCATOR_BYTES - strlen( $suffix ) ) . $suffix;
	}

	/**
	 * Write the state row when the state changed.
	 *
	 * @return void
	 * @throws Segurium_Storage_Exception When the write fails.
	 */
	private function save() {
		$json = (string) wp_json_encode( $this->state );
		if ( $json === $this->stored ) {
			return;
		}
		$now = time();
		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => self::KV_PREFIX . $this->run_id,
				'kv_value'   => $json,
				'expires_at' => $now + DAY_IN_SECONDS,
				'updated_at' => $now,
			),
			array( 'kv_key' )
		);
		$this->stored = $json;
	}

	/**
	 * Remove the rows and the locations earlier runs left.
	 *
	 * @return void
	 */
	private function drop_other_runs() {
		global $wpdb;
		$rows = Segurium_Storage::table_get_results(
			'runtime_kv',
			'SELECT kv_key, kv_value FROM {{table}} WHERE kv_key LIKE %s AND kv_key <> %s',
			array( $wpdb->esc_like( self::KV_PREFIX ) . '%', self::KV_PREFIX . $this->run_id ),
			ARRAY_A
		);
		foreach ( (array) $rows as $row ) {
			self::destroy_workspace( json_decode( (string) $row['kv_value'], true ) );
			Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => (string) $row['kv_key'] ) );
		}
	}

	/**
	 * Remove the workspace a state names.
	 *
	 * @param mixed $state Walk state.
	 * @return void
	 */
	private static function destroy_workspace( $state ) {
		if ( is_array( $state ) && ! empty( $state['workspace'] ) ) {
			Segurium_Storage::tmp_destroy( (string) $state['workspace'] );
		}
	}
}

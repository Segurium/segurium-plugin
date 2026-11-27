<?php
/**
 * WP-Cron events as content items.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns each WP-Cron event into one document: what the event is and the
 * code registered on its hook, in the request that reads it or in the last
 * WP-Cron request.
 */
final class Segurium_Cron_Reader {

	const KIND                   = 'cron';
	const BODY_VERSION           = 1;
	const MAX_SOURCE_BYTES       = 65536;
	const MAX_EVENT_SOURCE_BYTES = 262144;
	const MAX_FILE_BYTES         = 5242880;
	const MAX_ARGS_DEPTH         = 8;
	const MAX_ARGS_NODES         = 2000;
	const READ_CHUNK_BYTES       = 65536;
	const CALLBACK_CACHE_BYTES   = 4194304;

	const RECORD_OPTION        = 'segurium_cron_callback_record';
	const RECORD_VERSION       = 1;
	const RECORD_MAX_HOOKS     = 200;
	const RECORD_MAX_CALLBACKS = 20;
	const RECORD_REFRESH_SEC   = 86400;
	const RECORD_MAX_AGE_SEC   = 604800;
	const RECORD_SHAPE         = array(
		'type'   => '',
		'name'   => '',
		'origin' => '',
		'file'   => '',
		'start'  => 0,
		'end'    => 0,
		'prio'   => 0,
	);

	const RECORD_WRITTEN       = 'CRON_RECORD_WRITTEN';
	const RECORD_UNCHANGED     = 'CRON_RECORD_UNCHANGED';
	const RECORD_NOT_CRON      = 'CRON_RECORD_NOT_CRON';
	const RECORD_GATE_CLOSED   = 'CRON_RECORD_GATE_CLOSED';
	const RECORD_NO_CONSENT    = 'CRON_RECORD_NO_CONSENT';
	const RECORD_WRITE_FAILED  = 'CRON_RECORD_WRITE_FAILED';
	const RECORD_FAILED        = 'CRON_RECORD_FAILED';
	const RECORD_CUT_HOOKS     = 'CRON_RECORD_CUT_HOOKS';
	const RECORD_CUT_CALLBACKS = 'CRON_RECORD_CUT_CALLBACKS';

	/**
	 * Hook the record step.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'wp_loaded', array( __CLASS__, 'record' ), PHP_INT_MAX );
	}

	/**
	 * Keep the callbacks of each scheduled hook as this WP-Cron request has
	 * them, for a read in another kind of request. Reflection only: no file
	 * is read. Each record replaces the one before. An unchanged record is
	 * written again after RECORD_REFRESH_SEC, so its age shows that WP-Cron
	 * requests still run.
	 *
	 * @return string One of the RECORD_* outcome codes.
	 */
	public static function record() {
		if ( ! wp_doing_cron() ) {
			return self::RECORD_NOT_CRON;
		}
		if ( ! Segurium_Scan_Run::content_phase_enabled( Segurium_Scan_Phase_Cron::ID ) ) {
			return self::RECORD_GATE_CLOSED;
		}
		if ( ! Segurium_Consent::given() ) {
			return self::RECORD_NO_CONSENT;
		}
		global $wp_filter;
		try {
			$names = array();
			$crons = _get_cron_array();
			foreach ( is_array( $crons ) ? $crons : array() as $by_hook ) {
				foreach ( is_array( $by_hook ) ? array_keys( $by_hook ) : array() as $hook ) {
					if ( isset( $wp_filter[ $hook ] ) && $wp_filter[ $hook ] instanceof WP_Hook && $wp_filter[ $hook ]->has_filters() ) {
						$names[ (string) $hook ] = true;
					}
				}
			}
			$names = array_map( 'strval', array_keys( $names ) );
			sort( $names, SORT_STRING );
			$cut = count( $names ) > self::RECORD_MAX_HOOKS ? array( self::RECORD_CUT_HOOKS => true ) : array();

			$hooks = array();
			foreach ( array_slice( $names, 0, self::RECORD_MAX_HOOKS ) as $hook ) {
				$found = self::sorted( self::located( $hook ) );
				if ( count( $found ) > self::RECORD_MAX_CALLBACKS ) {
					$cut[ self::RECORD_CUT_CALLBACKS ] = true;
				}
				foreach ( array_slice( $found, 0, self::RECORD_MAX_CALLBACKS ) as $source ) {
					$hooks[ $hook ][] = array_intersect_key( $source, self::RECORD_SHAPE );
				}
			}

			$stored = Segurium_Storage::setting_get( self::RECORD_OPTION );
			$record = array(
				'v'     => self::RECORD_VERSION,
				'at'    => is_array( $stored ) && isset( $stored['at'] ) ? $stored['at'] : 0,
				'root'  => Segurium_Callback_Source::resolved( Segurium_Path_Helpers::wp_root() ),
				'cut'   => array_keys( $cut ),
				'hooks' => $hooks,
			);
			if ( $stored === $record && time() - (int) $record['at'] < self::RECORD_REFRESH_SEC ) {
				return self::RECORD_UNCHANGED;
			}
			$record['at'] = time();
			if ( Segurium_Storage::setting_set( self::RECORD_OPTION, $record, false ) ) {
				return self::RECORD_WRITTEN;
			}
			if ( maybe_serialize( $record ) === Segurium_Storage::setting_get_raw( self::RECORD_OPTION ) ) {
				return self::RECORD_UNCHANGED;
			}
			Segurium_Debug::log( '[segurium] ' . self::RECORD_WRITE_FAILED . ': the cron callback record was not stored' );
			return self::RECORD_WRITE_FAILED;
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] ' . self::RECORD_FAILED . ': ' . get_class( $e ) . ': ' . $e->getMessage() );
			return self::RECORD_FAILED;
		}
	}

	/**
	 * Every event, one item per distinct hook, schedule, interval and
	 * arguments. The time of the next run is no part of an item, so the
	 * hash of an item stays the same from run to run.
	 *
	 * @param int $limit Items to build. Each further event yields null.
	 * @return Generator Yields `{locator, body}` or null.
	 */
	public static function read( $limit ) {
		$seen   = array();
		$cache  = array();
		$cached = 0;
		$hashes = array();
		$record = self::recorded();
		$crons  = _get_cron_array();
		foreach ( is_array( $crons ) ? $crons : array() as $hooks ) {
			foreach ( is_array( $hooks ) ? $hooks : array() as $hook => $events ) {
				foreach ( is_array( $events ) ? $events : array() as $event ) {
					$identity = self::identity( (string) $hook, is_array( $event ) ? $event : array() );
					$key      = self::ref( $identity );
					if ( isset( $seen[ $key ] ) ) {
						continue;
					}
					$seen[ $key ] = true;
					if ( count( $seen ) > $limit ) {
						yield null;
						continue;
					}
					if ( ! isset( $cache[ $hook ] ) ) {
						$callbacks = self::callbacks( (string) $hook, $hashes, isset( $record[ $hook ] ) ? $record[ $hook ] : array() );
						$bytes     = array_sum( array_map( 'strlen', array_column( $callbacks, 'source' ) ) );
						if ( $cached + $bytes > self::CALLBACK_CACHE_BYTES ) {
							$cache  = array();
							$cached = 0;
						}
						$cache[ $hook ] = $callbacks;
						$cached        += $bytes;
					}
					$identity['callbacks'] = $cache[ $hook ];
					yield array(
						'locator' => self::KIND . ':' . $hook,
						'body'    => self::encode( $identity ),
						'ref'     => $key,
					);
				}
			}
		}
	}

	/**
	 * What makes two events the same event.
	 *
	 * @param string $hook  Hook name.
	 * @param array  $event Event as the cron array holds it.
	 * @return array
	 */
	public static function identity( $hook, array $event ) {
		$nodes = self::MAX_ARGS_NODES;
		return array(
			'v'        => self::BODY_VERSION,
			'hook'     => $hook,
			'schedule' => empty( $event['schedule'] ) ? '' : (string) $event['schedule'],
			'interval' => isset( $event['interval'] ) ? (int) $event['interval'] : 0,
			'args'     => self::canonical( isset( $event['args'] ) ? $event['args'] : array(), 0, $nodes ),
		);
	}

	/**
	 * A value with the keys of every map sorted, so equal arguments encode to
	 * equal bytes. Arguments can hold references to themselves, so the walk
	 * ends at MAX_ARGS_DEPTH levels and at MAX_ARGS_NODES values per event.
	 *
	 * @param mixed $value Argument value.
	 * @param int   $depth Nesting level of the value.
	 * @param int   $nodes Values the walk may still take.
	 * @return mixed
	 */
	private static function canonical( $value, $depth, &$nodes ) {
		if ( --$nodes < 0 ) {
			return null;
		}
		if ( is_object( $value ) ) {
			$value = array( '__class' => get_class( $value ) ) + get_object_vars( $value );
		}
		if ( is_array( $value ) ) {
			if ( $depth >= self::MAX_ARGS_DEPTH ) {
				return null;
			}
			$keys = array_keys( $value );
			if ( array_keys( $keys ) !== $keys ) {
				sort( $keys, SORT_STRING );
			}
			$out = array();
			foreach ( $keys as $key ) {
				$out[ $key ] = self::canonical( $value[ $key ], $depth + 1, $nodes );
			}
			return $out;
		}
		if ( is_float( $value ) && ! is_finite( $value ) ) {
			return null;
		}
		return is_scalar( $value ) ? $value : null;
	}

	/**
	 * The callbacks of the record, by hook. A record older than
	 * RECORD_MAX_AGE_SEC or taken under another WordPress root counts as none.
	 *
	 * @return array<string,mixed>
	 */
	private static function recorded() {
		$record = Segurium_Storage::setting_get( self::RECORD_OPTION );
		if ( ! is_array( $record ) || ! isset( $record['v'], $record['at'], $record['root'], $record['hooks'] )
			|| self::RECORD_VERSION !== $record['v'] || ! is_array( $record['hooks'] )
			|| time() - (int) $record['at'] > self::RECORD_MAX_AGE_SEC
			|| Segurium_Callback_Source::resolved( Segurium_Path_Helpers::wp_root() ) !== $record['root'] ) {
			return array();
		}
		return $record['hooks'];
	}

	/**
	 * The callbacks on a hook in this request.
	 *
	 * @param string $hook Hook name.
	 * @return array[] Shaped as RECORD_SHAPE.
	 */
	private static function located( $hook ) {
		global $wp_filter;
		if ( ! isset( $wp_filter[ $hook ] ) || ! $wp_filter[ $hook ] instanceof WP_Hook ) {
			return array();
		}
		$found = array();
		foreach ( $wp_filter[ $hook ]->callbacks as $priority => $callbacks ) {
			foreach ( $callbacks as $callback ) {
				$source         = Segurium_Callback_Source::locate( isset( $callback['function'] ) ? $callback['function'] : null );
				$source['prio'] = (int) $priority;
				$found[]        = $source;
			}
		}
		return $found;
	}

	/**
	 * Callbacks with their path, sorted by priority, path, first line and name.
	 *
	 * @param array[] $found Callbacks shaped as RECORD_SHAPE.
	 * @return array[]
	 */
	private static function sorted( array $found ) {
		foreach ( array_keys( $found ) as $index ) {
			$found[ $index ]['path'] = Segurium_Callback_Source::relative( $found[ $index ]['file'] );
		}
		usort(
			$found,
			static function ( $a, $b ) {
				return array( $a['prio'], $a['path'], $a['start'], $a['name'] ) <=> array( $b['prio'], $b['path'], $b['start'], $b['name'] );
			}
		);
		return $found;
	}

	/**
	 * The callbacks of a hook, in a fixed order: the ones on the hook in this
	 * request, and the recorded ones this request lacks. A named callback
	 * matches its recorded twin whatever its lines. A recorded callback whose
	 * file is gone is left out.
	 *
	 * @param string $hook     Hook name.
	 * @param array  $hashes   File hashes of this read, by resolved path.
	 * @param mixed  $recorded Recorded callbacks of the hook.
	 * @return array
	 */
	private static function callbacks( $hook, array &$hashes, $recorded ) {
		$found = self::located( $hook );
		$id    = static function ( array $source ) {
			if ( '' !== $source['name'] && false === strpos( $source['name'], '@anonymous' ) ) {
				$source['start'] = 0;
				$source['end']   = 0;
			}
			return implode( "\0", $source );
		};
		$live  = array_count_values( array_map( $id, $found ) );
		$shape = array_map( 'gettype', self::RECORD_SHAPE );
		foreach ( is_array( $recorded ) ? $recorded : array() as $source ) {
			if ( ! is_array( $source ) || array_map( 'gettype', $source ) !== $shape ) {
				continue;
			}
			$key = $id( $source );
			if ( ! empty( $live[ $key ] ) ) {
				--$live[ $key ];
			} elseif ( Segurium_Callback_Source::ORIGIN_FILE !== $source['origin'] || is_file( $source['file'] ) ) {
				$found[] = $source;
			}
		}
		$found = self::sorted( $found );

		$out    = array();
		$budget = self::MAX_EVENT_SOURCE_BYTES;
		foreach ( $found as $source ) {
			$entry = array(
				'priority' => $source['prio'],
				'type'     => $source['type'],
				'name'     => $source['name'],
				'origin'   => $source['origin'],
			);
			if ( Segurium_Callback_Source::ORIGIN_EVAL === $source['origin'] ) {
				$entry['lines'] = array( $source['start'], $source['end'] );
			} elseif ( Segurium_Callback_Source::ORIGIN_FILE === $source['origin'] ) {
				$file            = self::file( $source['file'], $source['start'], $source['end'], min( self::MAX_SOURCE_BYTES, $budget ), $hashes );
				$budget         -= strlen( $file['lines'] );
				$entry['path']   = $source['path'];
				$entry['sha256'] = $file['sha256'];
				$entry['lines']  = array( $source['start'], $source['end'] );
				$entry['source'] = $file['lines'];
			}
			$out[] = $entry;
		}
		return $out;
	}

	/**
	 * Hash of a file and some of its lines. The first read of a file takes
	 * both from one pass, so the hash is the hash of the bytes the lines come
	 * from. A later read of the same file with the same size, inode and
	 * times reuses the hash and stops at the last line asked for. The file
	 * is read in chunks and never sits in memory as a whole.
	 *
	 * @param string $path   Resolved path.
	 * @param int    $first  First line, counted from 1.
	 * @param int    $last   Last line.
	 * @param int    $max    Most bytes of the lines to return.
	 * @param array  $hashes File hashes of this read, by resolved path.
	 * @return array{sha256:string,lines:string} Both '' for an unreadable
	 *         file or a file over the size limit. The lines carry no line
	 *         break after the last one.
	 */
	private static function file( $path, $first, $last, $max, array &$hashes ) {
		clearstatcache( true, $path );
		$stat   = is_file( $path ) ? Segurium_Fs::stat( $path ) : false;
		$size   = is_array( $stat ) ? (int) $stat['size'] : 0;
		$handle = $size > 0 && $size <= self::MAX_FILE_BYTES ? Segurium_Fs::open( $path, 'rb' ) : false;
		if ( false === $handle ) {
			return array(
				'sha256' => '',
				'lines'  => '',
			);
		}
		$version = $size . ':' . (int) $stat['ino'] . ':' . (int) $stat['mtime'] . ':' . (int) $stat['ctime'];
		$hash    = isset( $hashes[ $path ] ) && $hashes[ $path ]['version'] === $version ? null : hash_init( 'sha256' );
		$line    = 1;
		$out     = '';
		$kept    = 0;
		while ( null !== $hash || ( $line <= $last && $kept <= $max ) ) {
			$chunk = Segurium_Fs::get( $handle, self::READ_CHUNK_BYTES );
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			if ( null !== $hash ) {
				hash_update( $hash, $chunk );
			}
			$length = strlen( $chunk );
			$offset = 0;
			while ( $offset < $length && $line <= $last && $kept <= $max ) {
				$break = strpos( $chunk, "\n", $offset );
				$stop  = false === $break ? $length : $break + 1;
				if ( $line >= $first ) {
					$out  .= substr( $chunk, $offset, $stop - $offset );
					$kept += $stop - $offset;
				}
				$offset = $stop;
				$line  += false === $break ? 0 : 1;
			}
		}
		Segurium_Fs::close( $handle );
		if ( null !== $hash ) {
			$hashes[ $path ] = array(
				'version' => $version,
				'sha256'  => hash_final( $hash ),
			);
		}
		if ( $line > $last && "\n" === substr( $out, -1 ) ) {
			$out = substr( $out, 0, -1 );
		}
		return array(
			'sha256' => $hashes[ $path ]['sha256'],
			'lines'  => (string) substr( $out, 0, max( 0, $max ) ),
		);
	}

	/**
	 * Short key of an event identity: equal for two events of one item.
	 *
	 * @param array $identity Identity from {@see identity()}.
	 * @return string 32 hex characters.
	 */
	public static function ref( array $identity ) {
		return md5( self::encode( $identity ) );
	}

	/**
	 * Canonical JSON of a document.
	 *
	 * @param array $document Document.
	 * @return string
	 */
	private static function encode( array $document ) {
		return (string) wp_json_encode( $document, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE );
	}
}

<?php
/**
 * Findings of the scripts part of the Database phase: one per bad script.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Kind handler of scripts stored in table fields. A finding keeps the places
 * the walk of its run found; a cleanup rewrites every place or none.
 */
final class Segurium_Db_Script_Finding implements Segurium_Content_Finding_Kind {

	const KIND             = 'db_js';
	const KIND_SRC         = 'db_js_src';
	const BACKUP_VERSION   = 1;
	const MAX_PLACES       = 1000;
	const MAX_BACKUP_BYTES = 8388608;
	const PHP_FIELDS       = array( 'snippets' => 'code' );
	const OBJECT_COLUMNS   = array(
		'options'  => 'option_name',
		'postmeta' => 'post_id',
	);

	/**
	 * KIND for inline scripts, KIND_SRC for external ones.
	 *
	 * @var string
	 */
	private $kind;

	/**
	 * Constructor.
	 *
	 * @param string $kind KIND or KIND_SRC.
	 */
	public function __construct( $kind = self::KIND ) {
		$this->kind = self::KIND_SRC === $kind ? self::KIND_SRC : self::KIND;
	}

	/**
	 * Content kind.
	 *
	 * @return string
	 */
	public function kind() {
		return $this->kind;
	}

	/**
	 * Restore writes every changed field back.
	 *
	 * @return bool
	 */
	public function restorable() {
		return true;
	}

	/**
	 * The verdicts of the part with the places of each threat from the walk of the run.
	 *
	 * @param array                   $verdicts Items with a verdict.
	 * @param Segurium_Db_Script_Walk $walk     Walk of the run.
	 * @param string                  $kind     KIND or KIND_SRC.
	 * @return array Each threat gains `places`, at most MAX_PLACES, and `places_total`.
	 */
	public static function with_places( array $verdicts, Segurium_Db_Script_Walk $walk, $kind = self::KIND ) {
		$want = array();
		foreach ( $verdicts as $index => $item ) {
			if ( Segurium_Content_Items::ITEM_THREAT === $item['state'] ) {
				$want[ (string) $item['sha256'] ]   = $index;
				$verdicts[ $index ]['places']       = array();
				$verdicts[ $index ]['places_total'] = 0;
			}
		}
		if ( array() === $want ) {
			return $verdicts;
		}
		foreach ( $walk->places( $kind ) as $place ) {
			if ( isset( $want[ $place[0] ] ) ) {
				$index = $want[ $place[0] ];
				if ( ++$verdicts[ $index ]['places_total'] <= self::MAX_PLACES ) {
					$verdicts[ $index ]['places'][] = array_slice( $place, 1 );
				}
			}
		}
		return $verdicts;
	}

	/**
	 * Threats with their places, and the clean keys. The key is the hash of the script.
	 *
	 * @param array $verdicts Items with a verdict, after {@see with_places()}.
	 * @return array{threats:array,clean:array}
	 */
	public function detections( array $verdicts ) {
		$out = array(
			'threats' => array(),
			'clean'   => array(),
		);
		foreach ( $verdicts as $item ) {
			$sha = (string) $item['sha256'];
			if ( Segurium_Content_Items::ITEM_CLEAN === $item['state'] ) {
				$out['clean'][] = $sha;
				continue;
			}
			$places           = isset( $item['places'] ) ? array_values( (array) $item['places'] ) : array();
			$out['threats'][] = array(
				'key'     => $sha,
				'locator' => (string) $item['locator'],
				'sha256'  => $sha,
				'verdict' => (int) $item['verdict'],
				'detail'  => array(
					'places'       => $places,
					'places_total' => isset( $item['places_total'] ) ? (int) $item['places_total'] : count( $places ),
				),
			);
		}
		return $out;
	}

	/**
	 * Whether a place of the finding still holds the script. Past MAX_BACKUP_BYTES
	 * of reads, or when a read fails, the script counts as there.
	 *
	 * @param array $finding Finding.
	 * @return bool
	 */
	public function exists( array $finding ) {
		$read = 0;
		foreach ( self::places( $finding ) as $place ) {
			$field = self::read( $place );
			if ( is_wp_error( $field ) ) {
				return true;
			}
			if ( null === $field ) {
				continue;
			}
			if ( $this->holds( $field['value'], $place, $finding['sha256'] ) ) {
				return true;
			}
			$read += strlen( $field['value'] );
			if ( $read > self::MAX_BACKUP_BYTES ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The value of every field that still holds the script.
	 *
	 * @param array $finding Finding.
	 * @return string|WP_Error
	 */
	public function snapshot( array $finding ) {
		$places = self::places( $finding );
		if ( (int) ( $finding['detail']['places_total'] ?? 0 ) > count( $places ) ) {
			return new WP_Error( 'too_many_places', 'the script has more places than one cleanup takes' );
		}
		$out   = array();
		$bytes = 0;
		foreach ( $places as $place ) {
			$field = self::read( $place );
			if ( is_wp_error( $field ) ) {
				return $field;
			}
			if ( null === $field || ! $this->holds( $field['value'], $place, $finding['sha256'] ) ) {
				continue;
			}
			if ( isset( self::PHP_FIELDS[ $place['table'] ] ) && self::PHP_FIELDS[ $place['table'] ] === $place['column'] ) {
				return new WP_Error( 'php_field', 'a field that holds PHP code holds the script' );
			}
			$bytes += strlen( $field['value'] );
			if ( $bytes > self::MAX_BACKUP_BYTES ) {
				return new WP_Error( 'backup_too_large', 'the fields of the script are over the backup bound' );
			}
			$out[] = array(
				'table'  => $place['table'],
				'key'    => $place['key'],
				'column' => $place['column'],
				'option' => $place['option'],
				'value'  => base64_encode( $field['value'] ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- keeps a field value byte for byte inside JSON.
			);
		}
		if ( array() === $out ) {
			return new WP_Error( 'target_gone', 'no place holds the script any more' );
		}
		return (string) wp_json_encode(
			array(
				'v'      => self::BACKUP_VERSION,
				'kind'   => $this->kind,
				'sha256' => (string) $finding['sha256'],
				'places' => $out,
			)
		);
	}

	/**
	 * Rewrite every backed-up field, or none. Each write names the bytes the
	 * backup holds, so a field that changed since is not written.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Backup bytes.
	 * @param string $cleaned  Cleaned script; '' removes each element.
	 * @return array|WP_Error `places`: each written field with the hash of its new value.
	 */
	public function apply( array $finding, $snapshot, $cleaned ) {
		$cleaned = (string) $cleaned;
		if ( strlen( $cleaned ) > Segurium_Db_Script_Walk::MAX_SCRIPT_BYTES ) {
			return new WP_Error( 'cleaned_too_large', 'the cleaned script is over 256 KiB' );
		}
		if ( 1 !== preg_match( '//u', $cleaned ) ) {
			return new WP_Error( 'cleaned_bad_encoding', 'the cleaned script is no UTF-8 text' );
		}
		$plan = $this->parse( $snapshot );
		if ( is_wp_error( $plan ) ) {
			return $plan;
		}
		foreach ( $plan as $index => $entry ) {
			$new = Segurium_Script_Extractor::rewrite( $entry['value'], $entry['decode'], (string) $finding['sha256'], $cleaned, self::KIND_SRC === $this->kind );
			if ( is_wp_error( $new ) ) {
				return $new;
			}
			$plan[ $index ]['new'] = $new;
		}
		if ( ! Segurium_Content_Findings::stage( $finding, self::applied( $plan ) ) ) {
			return new WP_Error( 'staging_failed', 'the record of the writes did not stick' );
		}
		$written = array();
		foreach ( $plan as $index => $entry ) {
			$now  = null;
			$code = self::swap( $entry, $entry['value'], $entry['new'], $now );
			if ( 'place_write_altered' === $code ) {
				$plan[ $index ]['new'] = (string) $now;
				$written[]             = $plan[ $index ];
				Segurium_Content_Findings::stage( $finding, self::applied( $plan ) );
			}
			if ( '' !== $code ) {
				Segurium_Debug::log( sprintf( '[segurium-db-scripts] cleanup %s table=%s key=%d column=%s', $code, $entry['table'], $entry['key'], $entry['column'] ) );
				return new WP_Error( $code, 'a field did not take the rewrite', self::undo( $written ) ? array() : array( 'staged' => true ) );
			}
			$written[] = $entry;
		}
		$auto = Segurium_Content_Findings::ACTOR_AUTO === ( $finding['actor'] ?? '' );
		Segurium_Cache_Invalidation::cleaned( $auto ? Segurium_Cache_Invalidation::TRIGGER_AUTO_FIX : Segurium_Cache_Invalidation::TRIGGER_MANUAL, $auto );
		return self::applied( $plan );
	}

	/**
	 * Write back every field that still holds what the cleanup wrote. A field
	 * that holds anything else stops the Restore before any write.
	 *
	 * @param array  $finding  Finding, with `detail.applied`.
	 * @param string $snapshot Backup bytes.
	 * @return true|WP_Error
	 */
	public function restore( array $finding, $snapshot ) {
		$backed = $this->parse( $snapshot );
		if ( is_wp_error( $backed ) ) {
			return $backed;
		}
		$wrote = array();
		foreach ( (array) ( $finding['detail']['applied']['places'] ?? array() ) as $place ) {
			if ( is_array( $place ) && 5 === count( $place ) ) {
				$wrote[ $place[0] . '|' . $place[1] . '|' . $place[2] ] = (string) $place[4];
			}
		}
		$todo = array();
		foreach ( $backed as $entry ) {
			$id = $entry['table'] . '|' . $entry['key'] . '|' . $entry['column'];
			if ( ! isset( $wrote[ $id ] ) ) {
				continue;
			}
			$field = self::read( $entry );
			if ( is_wp_error( $field ) ) {
				return $field;
			}
			if ( null === $field || $field['value'] === $entry['value'] ) {
				continue;
			}
			if ( ! hash_equals( $wrote[ $id ], hash( 'sha256', $field['value'] ) ) ) {
				if ( ! empty( $finding['staged_undo'] ) ) {
					Segurium_Debug::log( sprintf( '[segurium-db-scripts] undo keeps a field another write changed table=%s key=%d column=%s', $entry['table'], $entry['key'], $entry['column'] ) );
					continue;
				}
				return new WP_Error( 'place_changed', 'a field changed after the cleanup' );
			}
			$todo[] = array( 'new' => $field['value'] ) + $entry;
		}
		$back = array();
		foreach ( $todo as $entry ) {
			$now  = null;
			$code = self::swap( $entry, $entry['new'], $entry['value'], $now );
			if ( '' !== $code ) {
				if ( 'place_write_altered' === $code ) {
					$back[] = array( 'value' => (string) $now ) + $entry;
				}
				foreach ( $back as $done ) {
					self::swap( $done, $done['value'], $done['new'], $now );
				}
				return new WP_Error( $code, 'a field did not take its value back' );
			}
			$back[] = $entry;
		}
		if ( array() !== $todo ) {
			Segurium_Cache_Invalidation::cleaned( Segurium_Cache_Invalidation::TRIGGER_MANUAL );
		}
		return true;
	}

	/**
	 * Row label: the first place of the script.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function label( array $finding ) {
		$places = isset( $finding['detail']['places'] ) ? (array) $finding['detail']['places'] : array();
		$first  = isset( $places[0] ) && is_array( $places[0] ) && 5 === count( $places[0] ) ? Segurium_Db_Script_Walk::location( array_merge( array( '' ), $places[0] ) ) : strtok( (string) $finding['locator'], ' ' );
		/* translators: %s: where a malicious script is stored, e.g. db:posts:4711:post_content. */
		return sprintf( __( 'Script in the database: %s', 'segurium' ), (string) $first );
	}

	/**
	 * Location text: how many places hold the script.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function location( array $finding ) {
		$total = (int) ( $finding['detail']['places_total'] ?? 0 );
		/* translators: %d: number of database fields that hold one malicious script. */
		return sprintf( _n( 'Found in %d place', 'Found in %d places', $total, 'segurium' ), $total );
	}

	/**
	 * The places of a finding whose table and column the walk reads.
	 *
	 * @param array $finding Finding.
	 * @return array<int,array{table:string,key:int,column:string,option:string,decode:bool,name:string,pk:string}>
	 */
	private static function places( array $finding ) {
		$out = array();
		foreach ( (array) ( $finding['detail']['places'] ?? array() ) as $place ) {
			if ( is_array( $place ) && 5 === count( $place ) ) {
				$known = self::place( $place[0], $place[1], $place[2], $place[4] );
				if ( null !== $known ) {
					$out[] = $known;
				}
			}
		}
		return $out;
	}

	/**
	 * One place, checked against the tables of the walk.
	 *
	 * @param mixed $table  Table without the prefix.
	 * @param mixed $key    Primary key.
	 * @param mixed $column Column.
	 * @param mixed $option Option name, '' elsewhere.
	 * @return array|null
	 */
	private static function place( $table, $key, $column, $option ) {
		$table = (string) $table;
		if ( ! isset( Segurium_Db_Script_Walk::TABLES[ $table ] ) || ! in_array( (string) $column, Segurium_Db_Script_Walk::TABLES[ $table ]['fields'], true ) || (int) $key <= 0 ) {
			return null;
		}
		return array(
			'table'  => $table,
			'key'    => (int) $key,
			'column' => (string) $column,
			'option' => (string) $option,
			'decode' => (bool) Segurium_Db_Script_Walk::TABLES[ $table ]['decode'],
			'name'   => Segurium_Db_Script_Walk::table( $table ),
			'pk'     => Segurium_Db_Script_Walk::TABLES[ $table ]['key'],
		);
	}

	/**
	 * The places of a backup with their stored values.
	 *
	 * @param string $snapshot Backup bytes.
	 * @return array|WP_Error
	 */
	private function parse( $snapshot ) {
		$doc = json_decode( (string) $snapshot, true );
		if ( ! is_array( $doc ) || self::BACKUP_VERSION !== ( $doc['v'] ?? null ) || ! isset( $doc['kind'] ) || $doc['kind'] !== $this->kind || ! is_array( $doc['places'] ?? null ) ) {
			return new WP_Error( 'backup_unreadable', 'the backup holds no fields' );
		}
		$out = array();
		foreach ( $doc['places'] as $entry ) {
			$place = is_array( $entry ) ? self::place( $entry['table'] ?? '', $entry['key'] ?? 0, $entry['column'] ?? '', $entry['option'] ?? '' ) : null;
			$value = null === $place ? false : base64_decode( (string) ( $entry['value'] ?? '' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- reads a field value the backup kept.
			if ( false === $value ) {
				return new WP_Error( 'backup_unreadable', 'a field of the backup has the wrong shape' );
			}
			$out[] = array( 'value' => $value ) + $place;
		}
		return $out;
	}

	/**
	 * What Restore needs: each field and the hash of the value the cleanup writes.
	 *
	 * @param array $plan Places with `new`.
	 * @return array
	 */
	private static function applied( array $plan ) {
		$places = array();
		foreach ( $plan as $entry ) {
			$places[] = array( $entry['table'], $entry['key'], $entry['column'], $entry['option'], hash( 'sha256', $entry['new'] ) );
		}
		return array( 'places' => $places );
	}

	/**
	 * Whether a field value holds the script.
	 *
	 * @param string $value  Field value.
	 * @param array  $place  Place.
	 * @param string $sha256 SHA-256 of the script.
	 * @return bool
	 */
	private function holds( $value, array $place, $sha256 ) {
		return isset( Segurium_Script_Extractor::field( $value, $place['decode'] )[ self::KIND_SRC === $this->kind ? 'sources' : 'scripts' ][ (string) $sha256 ] );
	}

	/**
	 * Read one field as the database holds it now.
	 *
	 * @param array $place Place.
	 * @return array{value:string,object:string}|null|WP_Error Null when the row or the option is gone.
	 */
	private static function read( array $place ) {
		global $wpdb;
		$column = $place['column'];
		if ( isset( self::OBJECT_COLUMNS[ $place['table'] ] ) ) {
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT LENGTH(%i) AS n, IF(LENGTH(%i) > %d, NULL, %i) AS v, %i AS o FROM %i WHERE %i = %d', $column, $column, Segurium_Db_Script_Walk::MAX_FIELD_BYTES, $column, self::OBJECT_COLUMNS[ $place['table'] ], $place['name'], $place['pk'], $place['key'] ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the field as stored, past every cache.
		} else {
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT LENGTH(%i) AS n, IF(LENGTH(%i) > %d, NULL, %i) AS v FROM %i WHERE %i = %d', $column, $column, Segurium_Db_Script_Walk::MAX_FIELD_BYTES, $column, $place['name'], $place['pk'], $place['key'] ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the field as stored, past every cache.
		}
		if ( '' !== $wpdb->last_error ) {
			return new WP_Error( 'place_read_failed', 'a field could not be read' );
		}
		if ( ! is_array( $row ) || null === $row['n'] || ( 'options' === $place['table'] && (string) $row['o'] !== $place['option'] ) ) {
			return null;
		}
		if ( null === $row['v'] ) {
			return new WP_Error( 'field_too_large', 'a field is over 4 MiB' );
		}
		return array(
			'value'  => (string) $row['v'],
			'object' => isset( $row['o'] ) ? (string) $row['o'] : '',
		);
	}

	/**
	 * Write one field while it holds $from, then read it back.
	 *
	 * @param array       $place Place.
	 * @param string      $from  Bytes the field must hold.
	 * @param string      $to    Bytes to write.
	 * @param string|null $now   Set to the bytes the field holds after the write.
	 * @return string '' or `place_write_failed`, `place_changed`, `place_write_altered`.
	 */
	private static function swap( array $place, $from, $to, &$now ) {
		global $wpdb;
		$sha256 = hash( 'sha256', $from );
		if ( in_array( $wpdb->charset, array( 'utf8mb4', 'utf8', 'utf8mb3', 'latin1' ), true ) ) {
			$done = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET %i = %s WHERE %i = %d AND SHA2(CONVERT(%i USING %i), 256) = %s', $place['name'], $place['column'], $to, $place['pk'], $place['key'], $place['column'], $wpdb->charset, $sha256 ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the hash pins the bytes the write replaces.
		} else {
			$done = $wpdb->query( $wpdb->prepare( 'UPDATE %i SET %i = %s WHERE %i = %d AND SHA2(%i, 256) = %s', $place['name'], $place['column'], $to, $place['pk'], $place['key'], $place['column'], $sha256 ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the hash pins the bytes the write replaces.
		}
		if ( false === $done ) {
			return 'place_write_failed';
		}
		if ( 1 !== (int) $done ) {
			return 'place_changed';
		}
		$field = self::read( $place );
		$now   = is_array( $field ) ? $field['value'] : null;
		self::flush( $place, is_array( $field ) ? $field['object'] : '' );
		return $now === $to ? '' : 'place_write_altered';
	}

	/**
	 * Put back the fields a failed cleanup wrote.
	 *
	 * @param array $written Places with `value` and the `new` bytes they hold.
	 * @return bool False when a field still holds bytes of the cleanup.
	 */
	private static function undo( array $written ) {
		$clean = true;
		foreach ( array_reverse( $written ) as $entry ) {
			$now = null;
			if ( '' === self::swap( $entry, $entry['new'], $entry['value'], $now ) ) {
				continue;
			}
			$field = self::read( $entry );
			if ( is_wp_error( $field ) || ( is_array( $field ) && $field['value'] === $entry['new'] ) ) {
				$clean = false;
			}
		}
		return $clean;
	}

	/**
	 * Drop what the object cache holds of a written row.
	 *
	 * @param array  $place Place.
	 * @param string $owner Post ID of a meta row, name of an option.
	 * @return void
	 */
	private static function flush( array $place, $owner ) {
		if ( 'posts' === $place['table'] ) {
			clean_post_cache( $place['key'] );
		} elseif ( 'postmeta' === $place['table'] ) {
			wp_cache_delete( (int) $owner, 'post_meta' );
		} elseif ( 'comments' === $place['table'] ) {
			clean_comment_cache( $place['key'] );
		} elseif ( 'options' === $place['table'] ) {
			foreach ( array( $owner, 'alloptions', 'notoptions' ) as $key ) {
				wp_cache_delete( $key, 'options' );
			}
		}
	}
}

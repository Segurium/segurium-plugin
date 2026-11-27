<?php
/**
 * Findings of the Cron jobs phase: one per bad WP-Cron event.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Kind handler of WP-Cron events.
 */
final class Segurium_Cron_Finding implements Segurium_Content_Finding_Kind {

	const KIND           = 'cron';
	const BACKUP_VERSION = 2;
	const MAX_SHOWN_ARGS = 200;

	/**
	 * Content kind.
	 *
	 * @return string
	 */
	public function kind() {
		return self::KIND;
	}

	/**
	 * Restore puts the events back.
	 *
	 * @return bool
	 */
	public function restorable() {
		return true;
	}

	/**
	 * Threats whose events are still scheduled, and the clean keys.
	 *
	 * @param array $verdicts Items with a verdict.
	 * @return array{threats:array,clean:array}
	 */
	public function detections( array $verdicts ) {
		$live = self::live();
		$out  = array(
			'threats' => array(),
			'clean'   => array(),
		);
		foreach ( $verdicts as $item ) {
			$ref = isset( $item['ref'] ) ? (string) $item['ref'] : '';
			if ( '' === $ref ) {
				continue;
			}
			$key = $item['locator'] . '#' . $ref;
			if ( Segurium_Content_Items::ITEM_CLEAN === $item['state'] ) {
				$out['clean'][] = $key;
				continue;
			}
			if ( empty( $live[ $ref ] ) ) {
				continue;
			}
			$identity = $live[ $ref ][0]['identity'];
			unset( $identity['v'] );
			$out['threats'][] = array(
				'key'     => $key,
				'locator' => (string) $item['locator'],
				'sha256'  => (string) $item['sha256'],
				'verdict' => (int) $item['verdict'],
				'detail'  => array(
					'ref'      => $ref,
					'event'    => $identity,
					'next_run' => min( array_column( $live[ $ref ], 'timestamp' ) ),
				),
			);
		}
		return $out;
	}

	/**
	 * Whether an event of the finding is scheduled.
	 *
	 * @param array $finding Finding.
	 * @return bool
	 */
	public function exists( array $finding ) {
		return array() !== self::events( $finding );
	}

	/**
	 * Every event of the finding as the cron array holds it.
	 *
	 * @param array $finding Finding.
	 * @return string|WP_Error
	 */
	public function snapshot( array $finding ) {
		$events = self::events( $finding );
		if ( array() === $events ) {
			return new WP_Error( 'target_gone', 'no event of the finding is scheduled' );
		}
		$out = array();
		foreach ( $events as $event ) {
			$out[] = array_intersect_key( $event, array_flip( array( 'timestamp', 'hook', 'key', 'event' ) ) );
		}
		try {
			$bytes = serialize( $out ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- the cron option holds these bytes.
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-cron-finding] args_not_restorable: ' . $e->getMessage() );
			return new WP_Error( 'args_not_restorable', 'the arguments cannot be serialized' );
		}
		if ( false === self::read_back( $bytes ) ) {
			return new WP_Error( 'args_not_restorable', 'the arguments lose data when read back without their classes' );
		}
		return (string) wp_json_encode(
			array(
				'v'      => self::BACKUP_VERSION,
				'kind'   => self::KIND,
				'events' => base64_encode( $bytes ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- keeps the serialized events byte for byte inside JSON.
			)
		);
	}

	/**
	 * Remove the events. A cron job takes no cleaned version.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Backup bytes.
	 * @param string $cleaned  Cleaned version from the cloud; only '' applies.
	 * @return array|WP_Error
	 */
	public function apply( array $finding, $snapshot, $cleaned ) {
		if ( '' !== (string) $cleaned ) {
			return new WP_Error( 'cleaned_unsupported', 'a cron job takes no cleaned version' );
		}
		$backed = self::parse( $snapshot );
		$live   = self::events( $finding );
		if ( is_wp_error( $backed ) || array() === $live ) {
			return is_wp_error( $backed ) ? $backed : new WP_Error( 'target_gone', 'no event of the finding is scheduled' );
		}
		$known = array();
		foreach ( $backed as $event ) {
			$known[ $event['hook'] . '|' . $event['key'] ] = true;
		}
		foreach ( $live as $event ) {
			if ( ! isset( $known[ $event['hook'] . '|' . $event['key'] ] ) ) {
				return new WP_Error( 'target_changed', 'an event of the finding is missing from the backup' );
			}
		}
		$before = _get_cron_array();
		if ( ! self::write( $before, self::without( $before, $live ) ) || array() !== self::events( $finding ) ) {
			self::write( _get_cron_array(), $before );
			return new WP_Error( 'cron_write_failed', 'the cron array did not take the change' );
		}
		return array();
	}

	/**
	 * Put the backed-up events back. A copy of the job scheduled at another
	 * time since the cleanup goes, so the job does not run twice.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Backup bytes.
	 * @return true|WP_Error
	 */
	public function restore( array $finding, $snapshot ) {
		$backed = self::parse( $snapshot );
		if ( is_wp_error( $backed ) ) {
			return $backed;
		}
		$places = array();
		foreach ( $backed as $event ) {
			$places[ $event['timestamp'] . '|' . $event['hook'] . '|' . $event['key'] ] = true;
		}
		$copies = array();
		foreach ( self::events( $finding ) as $event ) {
			if ( ! isset( $places[ $event['timestamp'] . '|' . $event['hook'] . '|' . $event['key'] ] ) ) {
				$copies[] = $event;
			}
		}
		$before = _get_cron_array();
		$after  = self::without( $before, $copies );
		foreach ( $backed as $event ) {
			$after[ $event['timestamp'] ][ $event['hook'] ][ $event['key'] ] = $event['event'];
		}
		if ( ! self::write( $before, $after ) ) {
			return new WP_Error( 'cron_write_failed', 'the cron array did not take the restore' );
		}
		foreach ( $backed as $event ) {
			if ( ! self::scheduled( $event ) ) {
				return new WP_Error( 'cron_write_failed', 'a restored event is missing' );
			}
		}
		return true;
	}

	/**
	 * Row label.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function label( array $finding ) {
		/* translators: %s: name of the WP-Cron hook of a malicious scheduled event. */
		return sprintf( __( 'Cron job: %s', 'segurium' ), self::identity( $finding )['hook'] );
	}

	/**
	 * Location text: when the event runs and with which arguments.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function location( array $finding ) {
		$event     = self::identity( $finding );
		$schedules = wp_get_schedules();
		if ( '' === $event['schedule'] ) {
			$when = wp_date( 'Y-m-d H:i', isset( $finding['detail']['next_run'] ) ? (int) $finding['detail']['next_run'] : 0 );
		} else {
			$when = isset( $schedules[ $event['schedule'] ]['display'] ) ? (string) $schedules[ $event['schedule'] ]['display'] : $event['schedule'];
		}
		$args = (string) wp_json_encode( $event['args'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE );
		if ( strlen( $args ) > self::MAX_SHOWN_ARGS ) {
			$args = wp_html_excerpt( $args, self::MAX_SHOWN_ARGS, '…' );
		}
		/* translators: 1: how often a WP-Cron event runs, or the date of its single run; 2: the arguments of the event as JSON. */
		return sprintf( __( 'Schedule: %1$s, arguments: %2$s', 'segurium' ), $when, $args );
	}

	/**
	 * Hook, schedule, interval and arguments of a finding.
	 *
	 * @param array $finding Finding.
	 * @return array{hook:string,schedule:string,interval:int,args:mixed}
	 */
	private static function identity( array $finding ) {
		$event = isset( $finding['detail']['event'] ) ? (array) $finding['detail']['event'] : array();
		return array(
			'hook'     => isset( $event['hook'] ) ? (string) $event['hook'] : substr( (string) $finding['locator'], strlen( self::KIND ) + 1 ),
			'schedule' => isset( $event['schedule'] ) ? (string) $event['schedule'] : '',
			'interval' => isset( $event['interval'] ) ? (int) $event['interval'] : 0,
			'args'     => isset( $event['args'] ) ? $event['args'] : array(),
		);
	}

	/**
	 * Scheduled events by the ref of their identity.
	 *
	 * @return array<string, array<int, array{timestamp:int,hook:string,key:string,event:array,identity:array}>>
	 */
	private static function live() {
		static $memo = null;
		$crons       = _get_cron_array();
		if ( null !== $memo && $memo[0] === $crons ) {
			return $memo[1];
		}
		$out = array();
		foreach ( is_array( $crons ) ? $crons : array() as $timestamp => $hooks ) {
			foreach ( is_array( $hooks ) ? $hooks : array() as $hook => $events ) {
				foreach ( is_array( $events ) ? $events : array() as $key => $event ) {
					$event    = is_array( $event ) ? $event : array();
					$identity = Segurium_Cron_Reader::identity( (string) $hook, $event );
					$out[ Segurium_Cron_Reader::ref( $identity ) ][] = array(
						'timestamp' => (int) $timestamp,
						'hook'      => (string) $hook,
						'key'       => (string) $key,
						'event'     => $event,
						'identity'  => $identity,
					);
				}
			}
		}
		$memo = array( $crons, $out );
		return $out;
	}

	/**
	 * Scheduled events of a finding.
	 *
	 * @param array $finding Finding.
	 * @return array
	 */
	private static function events( array $finding ) {
		$ref  = isset( $finding['detail']['ref'] ) ? (string) $finding['detail']['ref'] : '';
		$live = '' === $ref ? array() : self::live();
		return isset( $live[ $ref ] ) ? $live[ $ref ] : array();
	}

	/**
	 * Events of a backup.
	 *
	 * @param string $snapshot Backup bytes.
	 * @return array|WP_Error
	 */
	private static function parse( $snapshot ) {
		$doc = json_decode( (string) $snapshot, true );
		if ( ! is_array( $doc ) || self::BACKUP_VERSION !== ( $doc['v'] ?? null ) || self::KIND !== ( $doc['kind'] ?? null ) || ! is_string( $doc['events'] ?? null ) ) {
			return new WP_Error( 'backup_unreadable', 'the backup holds no cron events' );
		}
		$bytes = base64_decode( $doc['events'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- reads the serialized events the backup kept.
		if ( false === $bytes ) {
			return new WP_Error( 'backup_unreadable', 'the events of the backup are not base64' );
		}
		$events = self::read_back( $bytes );
		if ( ! is_array( $events ) ) {
			return new WP_Error( 'backup_unreadable', 'the events of the backup do not read back' );
		}
		foreach ( $events as $event ) {
			if ( ! is_array( $event ) || ! is_int( $event['timestamp'] ?? null ) || $event['timestamp'] <= 0
				|| ! is_string( $event['hook'] ?? null ) || ! is_string( $event['key'] ?? null ) || ! is_array( $event['event'] ?? null ) ) {
				return new WP_Error( 'backup_unreadable', 'an event of the backup has the wrong shape' );
			}
		}
		return $events;
	}

	/**
	 * A serialized value read back with every object as __PHP_Incomplete_Class,
	 * which serialize() writes again under its own class name. PHP warns when
	 * the read drops data: a C: object comes back empty.
	 *
	 * @param string $bytes Serialized value.
	 * @return mixed False when the bytes do not parse or lose data.
	 */
	private static function read_back( $bytes ) {
		$lost = null;
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- a warning of unserialize() marks a loss.
		set_error_handler(
			static function ( $errno, $errstr ) use ( &$lost ) {
				$lost = null === $lost ? (string) $errstr : $lost;
				return true;
			}
		);
		try {
			$value = unserialize( $bytes, array( 'allowed_classes' => false ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- no class is built.
		} finally {
			restore_error_handler();
		}
		if ( null !== $lost ) {
			Segurium_Debug::log( '[segurium-cron-finding] read_back_lost: ' . $lost );
			return false;
		}
		return $value;
	}

	/**
	 * A cron array without some events. A timestamp or hook left empty goes.
	 *
	 * @param array $crons  Cron array.
	 * @param array $events Events: `{timestamp, hook, key}`.
	 * @return array
	 */
	private static function without( array $crons, array $events ) {
		foreach ( $events as $event ) {
			unset( $crons[ $event['timestamp'] ][ $event['hook'] ][ $event['key'] ] );
			if ( empty( $crons[ $event['timestamp'] ][ $event['hook'] ] ) ) {
				unset( $crons[ $event['timestamp'] ][ $event['hook'] ] );
			}
			if ( empty( $crons[ $event['timestamp'] ] ) ) {
				unset( $crons[ $event['timestamp'] ] );
			}
		}
		return $crons;
	}

	/**
	 * Store a changed cron array.
	 *
	 * @param array $before Array as read.
	 * @param array $after  Array to store.
	 * @return bool
	 */
	private static function write( array $before, array $after ) {
		try {
			if ( serialize( $after ) === serialize( $before ) ) { // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- two reads of one object are not ===.
				return true;
			}
			uksort( $after, 'strnatcasecmp' );
			return true === _set_cron_array( $after, true );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-cron-finding] cron_write_failed: ' . $e->getMessage() );
			return false;
		}
	}

	/**
	 * Whether the cron array holds an event at its place.
	 *
	 * @param array $event `{timestamp, hook, key}`.
	 * @return bool
	 */
	private static function scheduled( array $event ) {
		$crons = _get_cron_array();
		return isset( $crons[ $event['timestamp'] ][ $event['hook'] ][ $event['key'] ] );
	}
}

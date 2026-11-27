<?php
/**
 * Findings of the session part of the Database phase: one per bad login session.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Kind handler of login sessions. A cleanup ends the one session; no Restore.
 */
final class Segurium_Db_Session_Finding implements Segurium_Content_Finding_Kind {

	const KIND           = 'db_session';
	const BACKUP_VERSION = 1;
	const META_KEY       = 'session_tokens';

	/**
	 * Content kind.
	 *
	 * @return string
	 */
	public function kind() {
		return self::KIND;
	}

	/**
	 * An ended session does not come back.
	 *
	 * @return bool
	 */
	public function restorable() {
		return false;
	}

	/**
	 * Threats whose session is still live, and the clean keys.
	 *
	 * @param array $verdicts Items with a verdict.
	 * @return array{threats:array,clean:array}
	 */
	public function detections( array $verdicts ) {
		$out = array(
			'threats' => array(),
			'clean'   => array(),
		);
		foreach ( $verdicts as $item ) {
			$locator = (string) $item['locator'];
			if ( ! preg_match( '/\Adb:sessions:(([1-9][0-9]{0,18})-[0-9a-f]{' . Segurium_Account_Reader::SESSION_ID_HEX . '})\z/', $locator, $match ) ) {
				continue;
			}
			if ( Segurium_Content_Items::ITEM_CLEAN === $item['state'] ) {
				$out['clean'][] = $locator;
				continue;
			}
			$found = self::find( (int) $match[2], $match[1] );
			if ( null === $found ) {
				continue;
			}
			$out['threats'][] = array(
				'key'     => $locator,
				'locator' => $locator,
				'sha256'  => (string) $item['sha256'],
				'verdict' => (int) $item['verdict'],
				'detail'  => array(
					'sid'        => $match[1],
					'user'       => (int) $match[2],
					'login'      => (int) ( $found['session']['login'] ?? 0 ),
					'expiration' => (int) ( $found['session']['expiration'] ?? 0 ),
				),
			);
		}
		return $out;
	}

	/**
	 * Whether the session is still live.
	 *
	 * @param array $finding Finding.
	 * @return bool
	 */
	public function exists( array $finding ) {
		return null !== self::of( $finding );
	}

	/**
	 * Which session the cleanup ends. Holds no token, address or browser string.
	 *
	 * @param array $finding Finding.
	 * @return string|WP_Error
	 */
	public function snapshot( array $finding ) {
		if ( 2 === (int) $finding['verdict'] ) {
			return new WP_Error( 'verdict_not_applicable', 'a session has no cleaned version' );
		}
		$code = self::guard( $finding, self::of( $finding ) );
		if ( '' !== $code ) {
			return new WP_Error( $code, 'the session cannot be ended' );
		}
		return (string) wp_json_encode(
			array(
				'v'    => self::BACKUP_VERSION,
				'kind' => self::KIND,
				'id'   => (string) $finding['detail']['sid'],
				'user' => (int) $finding['detail']['user'],
			)
		);
	}

	/**
	 * End the one session of the finding; the other sessions of the account stay.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Backup bytes.
	 * @param string $cleaned  Cleaned version; only '' ends the session.
	 * @return array|WP_Error
	 */
	public function apply( array $finding, $snapshot, $cleaned ) {
		unset( $snapshot );
		if ( '' !== (string) $cleaned ) {
			return new WP_Error( 'verdict_not_applicable', 'a session has no cleaned version' );
		}
		$found = self::of( $finding );
		$code  = self::guard( $finding, $found );
		if ( '' !== $code ) {
			return new WP_Error( $code, 'the session cannot be ended' );
		}
		$uid  = (int) $finding['detail']['user'];
		$left = $found['all'];
		unset( $left[ $found['verifier'] ] );
		if ( array() === $left ) {
			delete_user_meta( $uid, self::META_KEY, $found['all'] );
		} else {
			update_user_meta( $uid, self::META_KEY, $left, $found['all'] );
		}
		if ( null !== self::of( $finding ) ) {
			return new WP_Error( 'session_write_failed', 'the session is still stored' );
		}
		return array();
	}

	/**
	 * Never reached: the kind is not restorable.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Backup bytes.
	 * @return WP_Error
	 */
	public function restore( array $finding, $snapshot ) {
		unset( $finding, $snapshot );
		return new WP_Error( 'not_restorable', 'an ended session does not come back' );
	}

	/**
	 * Row label: the login of the account, as the locked-account rows show it.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function label( array $finding ) {
		$user = get_userdata( (int) ( $finding['detail']['user'] ?? 0 ) );
		/* translators: %s: login name of the WordPress account a malicious login session belongs to. */
		return sprintf( __( 'Login session of %s', 'segurium' ), $user instanceof WP_User ? (string) $user->user_login : (string) $finding['locator'] );
	}

	/**
	 * Location text: when the session began and when it expires.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function location( array $finding ) {
		$login = (int) ( $finding['detail']['login'] ?? 0 );
		/* translators: 1: date and time a login session began; 2: date and time the session expires. */
		return sprintf( __( 'Signed in: %1$s, expires: %2$s', 'segurium' ), $login > 0 ? wp_date( 'Y-m-d H:i', $login ) : '-', wp_date( 'Y-m-d H:i', (int) ( $finding['detail']['expiration'] ?? 0 ) ) );
	}

	/**
	 * Why the session must not be ended, or ''.
	 *
	 * @param array      $finding Finding.
	 * @param array|null $found   The session as {@see find()} returns it.
	 * @return string
	 */
	private static function guard( array $finding, $found ) {
		if ( null === $found ) {
			return 'target_gone';
		}
		$token = wp_get_session_token();
		if ( get_current_user_id() === (int) $finding['detail']['user'] && '' !== $token && hash_equals( $found['verifier'], hash( 'sha256', $token ) ) ) {
			return 'current_session';
		}
		return '';
	}

	/**
	 * The live session a finding names.
	 *
	 * @param array $finding Finding.
	 * @return array{verifier:string,session:array,all:array}|null
	 */
	private static function of( array $finding ) {
		return self::find( (int) ( $finding['detail']['user'] ?? 0 ), (string) ( $finding['detail']['sid'] ?? '' ) );
	}

	/**
	 * Find a live session by its ID in the store of the default session manager.
	 *
	 * @param int    $uid User ID.
	 * @param string $sid Session ID.
	 * @return array{verifier:string,session:array,all:array}|null
	 */
	private static function find( $uid, $sid ) {
		if ( $uid <= 0 || '' === $sid ) {
			return null;
		}
		wp_cache_delete( $uid, 'user_meta' );
		$all = get_user_meta( $uid, self::META_KEY, true );
		foreach ( is_array( $all ) ? $all : array() as $verifier => $session ) {
			$session = is_array( $session ) ? $session : array( 'expiration' => $session );
			if ( (int) ( $session['expiration'] ?? 0 ) >= time() && hash_equals( Segurium_Account_Reader::session_id( $uid, (string) $verifier ), $sid ) ) {
				return array(
					'verifier' => (string) $verifier,
					'session'  => $session,
					'all'      => $all,
				);
			}
		}
		return null;
	}
}

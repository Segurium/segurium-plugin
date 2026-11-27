<?php
/**
 * Accounts and their login sessions as content items.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Accounts that can change the site, hidden accounts and their login sessions as documents.
 */
final class Segurium_Account_Reader {

	const KIND_USER      = 'db_user';
	const KIND_SESSION   = 'db_session';
	const BODY_VERSION   = 1;
	const MAX_UA_BYTES   = 1024;
	const SESSION_ID_HEX = 32;

	/**
	 * One item per found account.
	 *
	 * @param int $limit Documents to build. Each further account yields null.
	 * @return Generator Yields `{locator, body}` or null.
	 */
	public static function accounts( $limit ) {
		return self::guarded( self::account_items( (int) $limit ) );
	}

	/**
	 * One item per live login session of the found accounts.
	 *
	 * @param int $limit Documents to build. Each further session yields null.
	 * @return Generator Yields `{locator, body}` or null.
	 */
	public static function sessions( $limit ) {
		return self::guarded( self::session_items( (int) $limit ) );
	}

	/**
	 * ID of one session: the user ID and a keyed hash of the stored verifier.
	 *
	 * @param int    $user_id  User ID.
	 * @param string $verifier Key of the session in the user meta.
	 * @return string
	 */
	public static function session_id( $user_id, $verifier ) {
		$user_id = (int) $user_id;
		$keyed   = hash_hmac( 'sha256', 'segurium-session:' . $user_id . ':' . $verifier, wp_salt( 'auth' ) );
		return $user_id . '-' . substr( $keyed, 0, self::SESSION_ID_HEX );
	}

	/**
	 * Rethrow a fault as its class name: the pipeline logs the message, which can name an account.
	 *
	 * @param Generator $items Items of one read.
	 * @return Generator
	 * @throws RuntimeException When the read fails.
	 */
	private static function guarded( Generator $items ) {
		try {
			yield from $items;
		} catch ( Throwable $e ) {
			throw new RuntimeException( esc_html( get_class( $e ) ) );
		}
	}

	/**
	 * The account documents.
	 *
	 * @param int $limit Documents to build.
	 * @return Generator
	 */
	private static function account_items( $limit ) {
		$built = 0;
		foreach ( self::found() as $user_id => $hidden ) {
			$user = get_userdata( $user_id );
			if ( ! $user instanceof WP_User ) {
				continue;
			}
			if ( ++$built > $limit ) {
				yield null;
				continue;
			}
			yield array(
				'locator' => 'db:users:' . $user_id,
				'body'    => self::encode( self::account( $user, $hidden ) ),
			);
		}
	}

	/**
	 * The session documents.
	 *
	 * @param int $limit Documents to build.
	 * @return Generator
	 */
	private static function session_items( $limit ) {
		$built = 0;
		foreach ( array_keys( self::found() ) as $user_id ) {
			$stored = self::stored_sessions( $user_id );
			for ( $away = count( WP_Session_Tokens::get_instance( $user_id )->get_all() ) - count( $stored ); $away > 0; $away-- ) {
				yield array( 'elsewhere' => true );
			}
			foreach ( $stored as $verifier => $session ) {
				if ( ++$built > $limit ) {
					yield null;
					continue;
				}
				$id = self::session_id( $user_id, $verifier );
				yield array(
					'locator' => 'db:sessions:' . $id,
					'body'    => self::encode(
						array(
							'v'    => self::BODY_VERSION,
							'id'   => $id,
							'user' => $user_id,
						) + $session
					),
				);
			}
		}
	}

	/**
	 * The accounts the census code finds, hidden accounts first.
	 *
	 * @return array<int,bool> Hidden flag by user ID.
	 */
	private static function found() {
		$hidden     = array_map( 'intval', array_column( Segurium_Account_Lock::hidden_accounts(), 'uid' ) );
		$privileged = array_map( 'intval', array_column( Segurium_Activity_Tracker::privileged_rows(), 'uid' ) );
		sort( $hidden );
		sort( $privileged );
		return array_fill_keys( $hidden, true ) + array_fill_keys( $privileged, false );
	}

	/**
	 * Document of one account.
	 *
	 * @param WP_User $user   Account.
	 * @param bool    $hidden Whether a user query leaves the account out.
	 * @return array
	 */
	private static function account( WP_User $user, $hidden ) {
		$caps = array();
		foreach ( (array) $user->allcaps as $cap => $granted ) {
			if ( $granted ) {
				$caps[] = (string) $cap;
			}
		}
		sort( $caps, SORT_STRING );
		$user_id = (int) $user->ID;
		return array(
			'v'             => self::BODY_VERSION,
			'id'            => $user_id,
			'login'         => (string) $user->user_login,
			'email'         => (string) $user->user_email,
			'roles'         => array_values( array_map( 'strval', (array) $user->roles ) ),
			'caps'          => $caps,
			'registered'    => (string) $user->user_registered,
			'hidden'        => (bool) $hidden,
			'app_passwords' => count( WP_Application_Passwords::get_user_application_passwords( $user_id ) ),
			'sessions'      => count( WP_Session_Tokens::get_instance( $user_id )->get_all() ),
		);
	}

	/**
	 * Live sessions by verifier, newest login first. WP_Session_Tokens hides the verifier.
	 *
	 * @param int $user_id User ID.
	 * @return array<string,array{login:int,expiration:int,ip:string,ua:string}>
	 */
	private static function stored_sessions( $user_id ) {
		$stored = get_user_meta( $user_id, 'session_tokens', true );
		$now    = time();
		$live   = array();
		foreach ( is_array( $stored ) ? $stored : array() as $verifier => $session ) {
			$session = is_array( $session ) ? $session : array( 'expiration' => $session );
			$expires = isset( $session['expiration'] ) ? (int) $session['expiration'] : 0;
			if ( $expires < $now ) {
				continue;
			}
			$live[ (string) $verifier ] = array(
				'login'      => isset( $session['login'] ) ? (int) $session['login'] : 0,
				'expiration' => $expires,
				'ip'         => self::text( $session, 'ip' ),
				'ua'         => substr( self::text( $session, 'ua' ), 0, self::MAX_UA_BYTES ),
			);
		}
		uksort(
			$live,
			static function ( $a, $b ) use ( $live ) {
				$newer = $live[ $b ]['login'] <=> $live[ $a ]['login'];
				return 0 !== $newer ? $newer : strcmp( (string) $a, (string) $b );
			}
		);
		return $live;
	}

	/**
	 * A text field of a stored session.
	 *
	 * @param array  $session Session as stored.
	 * @param string $key     Field name.
	 * @return string
	 */
	private static function text( array $session, $key ) {
		return isset( $session[ $key ] ) && is_scalar( $session[ $key ] ) ? (string) $session[ $key ] : '';
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

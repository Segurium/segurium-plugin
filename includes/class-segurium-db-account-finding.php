<?php
/**
 * Findings of the account part of the Database phase: one per bad account.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Kind handler of accounts. A cleanup locks the account; Restore unlocks it.
 */
final class Segurium_Db_Account_Finding implements Segurium_Content_Finding_Kind {

	const KIND           = 'db_user';
	const BACKUP_VERSION = 1;

	/**
	 * Content kind.
	 *
	 * @return string
	 */
	public function kind() {
		return self::KIND;
	}

	/**
	 * Restore unlocks the account.
	 *
	 * @return bool
	 */
	public function restorable() {
		return true;
	}

	/**
	 * Threats whose account still exists, and the clean keys.
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
			if ( ! preg_match( '/\Adb:users:([1-9][0-9]{0,18})\z/', $locator, $match ) ) {
				continue;
			}
			if ( Segurium_Content_Items::ITEM_CLEAN === $item['state'] ) {
				$out['clean'][] = $locator;
				continue;
			}
			$user = get_userdata( (int) $match[1] );
			if ( ! $user instanceof WP_User ) {
				continue;
			}
			$out['threats'][] = array(
				'key'     => $locator,
				'locator' => $locator,
				'sha256'  => (string) $item['sha256'],
				'verdict' => (int) $item['verdict'],
				'detail'  => array(
					'uid'        => (int) $user->ID,
					'uhash'      => hash( 'sha256', (string) $user->user_login ),
					'registered' => (string) $user->user_registered,
					'roles'      => array_values( array_map( 'strval', (array) $user->roles ) ),
				),
			);
		}
		return $out;
	}

	/**
	 * Whether the account of the finding is still on the site.
	 *
	 * @param array $finding Finding.
	 * @return bool
	 */
	public function exists( array $finding ) {
		return null !== self::user( $finding );
	}

	/**
	 * The account the lock would change, after every guard of the lock.
	 *
	 * @param array $finding Finding.
	 * @return string|WP_Error
	 */
	public function snapshot( array $finding ) {
		if ( 2 === (int) $finding['verdict'] ) {
			return new WP_Error( 'verdict_not_applicable', 'an account has no cleaned version' );
		}
		$code = self::guard( $finding );
		if ( '' !== $code ) {
			return new WP_Error( $code, 'the account lock refuses' );
		}
		return (string) wp_json_encode(
			array(
				'v'          => self::BACKUP_VERSION,
				'kind'       => self::KIND,
				'uid'        => (int) $finding['detail']['uid'],
				'registered' => (string) $finding['detail']['registered'],
			)
		);
	}

	/**
	 * Lock the account. The lock keeps its own backup of the credentials.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Backup bytes.
	 * @param string $cleaned  Cleaned version; only '' locks.
	 * @return array|WP_Error
	 */
	public function apply( array $finding, $snapshot, $cleaned ) {
		unset( $snapshot );
		if ( '' !== (string) $cleaned ) {
			return new WP_Error( 'verdict_not_applicable', 'an account has no cleaned version' );
		}
		$code = self::guard( $finding, false );
		if ( '' === $code ) {
			$actor = Segurium_Content_Findings::ACTOR_AUTO === ( $finding['actor'] ?? '' ) ? Segurium_Account_Lock::ACTOR_SYSTEM : Segurium_Account_Lock::ACTOR_MANUAL;
			$code  = Segurium_Account_Lock::lock( (int) $finding['detail']['uid'], (string) $finding['detail']['uhash'], $actor );
			$code  = Segurium_Remote_Actions::OK === $code ? '' : $code;
		}
		return '' === $code ? array() : new WP_Error( $code, 'the account lock refuses' );
	}

	/**
	 * Unlock the account. An account that is no longer locked counts as restored.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Backup bytes.
	 * @return true|WP_Error
	 */
	public function restore( array $finding, $snapshot ) {
		unset( $snapshot );
		$code = Segurium_Account_Lock::restore( (int) ( $finding['detail']['uid'] ?? 0 ), Segurium_Account_Lock::ACTOR_MANUAL );
		if ( Segurium_Remote_Actions::OK === $code || Segurium_Account_Lock::REFUSE_NOT_LOCKED === $code ) {
			return true;
		}
		return new WP_Error( $code, 'the account stays locked' );
	}

	/**
	 * Row label: the login, as the locked-account rows show it.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function label( array $finding ) {
		$user = self::user( $finding );
		/* translators: %s: login name of a WordPress account with a malicious verdict. */
		return sprintf( __( 'Account: %s', 'segurium' ), null === $user ? (string) $finding['locator'] : (string) $user->user_login );
	}

	/**
	 * Location text: the user ID and the roles the account held at the detection.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public function location( array $finding ) {
		$names = wp_roles()->get_names();
		$roles = array();
		foreach ( (array) ( $finding['detail']['roles'] ?? array() ) as $role ) {
			$roles[] = isset( $names[ $role ] ) ? translate_user_role( $names[ $role ] ) : (string) $role;
		}
		/* translators: 1: numeric ID of a WordPress account; 2: comma-separated role names of the account. */
		return sprintf( __( 'User ID %1$d, roles: %2$s', 'segurium' ), (int) ( $finding['detail']['uid'] ?? 0 ), implode( ', ', $roles ) );
	}

	/**
	 * Status of the finding of each account that has one. The account shows
	 * once: as the finding while the finding is cured or the lock row has no action.
	 *
	 * @return array<int,string> Finding status by user ID.
	 */
	public static function covered() {
		if ( ! isset( Segurium_Content_Findings::kinds()[ self::KIND ] ) ) {
			return array();
		}
		$out = array();
		foreach ( (array) Segurium_Storage::table_get_results( Segurium_Content_Findings::TABLE, 'SELECT status, detail FROM {{table}} WHERE kind = %s', array( self::KIND ), ARRAY_A ) as $row ) {
			$detail = json_decode( (string) $row['detail'], true );
			if ( isset( $detail['uid'] ) && ( ! isset( $out[ (int) $detail['uid'] ] ) || Segurium_Content_Findings::STATUS_CURED === $row['status'] ) ) {
				$out[ (int) $detail['uid'] ] = (string) $row['status'];
			}
		}
		return $out;
	}

	/**
	 * Why the account must not be locked, or ''.
	 *
	 * @param array $finding Finding.
	 * @param bool  $of_lock Run the guards of the lock too; the lock runs them itself.
	 * @return string
	 */
	private static function guard( array $finding, $of_lock = true ) {
		$user = self::user( $finding );
		if ( null === $user ) {
			return Segurium_Account_Lock::REFUSE_USER_NOT_FOUND;
		}
		$uid = (int) $user->ID;
		if ( get_current_user_id() === $uid ) {
			return 'own_account';
		}
		if ( Segurium_Content_Findings::ACTOR_AUTO === ( $finding['actor'] ?? '' ) && Segurium_Account_Lock::is_trusted( $uid ) ) {
			return 'account_trusted';
		}
		$code = $of_lock ? Segurium_Account_Lock::guard( $uid, (string) $finding['detail']['uhash'] ) : Segurium_Remote_Actions::OK;
		return Segurium_Remote_Actions::OK === $code ? '' : $code;
	}

	/**
	 * The account of a finding while its user ID still holds the account registered then.
	 *
	 * @param array $finding Finding.
	 * @return WP_User|null
	 */
	private static function user( array $finding ) {
		$uid  = (int) ( $finding['detail']['uid'] ?? 0 );
		$user = $uid > 0 ? get_userdata( $uid ) : false;
		if ( ! $user instanceof WP_User || (string) ( $finding['detail']['registered'] ?? '' ) !== (string) $user->user_registered ) {
			return null;
		}
		return $user;
	}
}

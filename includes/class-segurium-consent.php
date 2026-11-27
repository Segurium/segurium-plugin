<?php
/**
 * External Service Disclosure: the one consent path.
 *
 * The disclosure text and the accept sequence live here so the admin
 * screen, WP-CLI and the wp-config constant cannot drift from each other.
 * Every caller reaches CTI through {@see Segurium_Consent::accept()} and
 * differs only in the `source` it reports.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Consent state, disclosure copy, and the accept sequence.
 */
final class Segurium_Consent {

	const OPTION_CONSENT = 'segurium_cti_consent';
	const OPTION_SOURCE  = 'segurium_consent_source';
	const OPTION_EDITION = 'segurium_consent_edition';

	/**
	 * Per-edition marker for the wp-config path, so a site that defines the
	 * constant and later revokes consent from the admin screen is not
	 * re-consented on the next request.
	 */
	const OPTION_CONSTANT_APPLIED = 'segurium_consent_constant_applied';

	const META_RENEWAL_DISMISSED = 'segurium_consent_renewal_dismissed';

	const EDITION_BASE    = 1;
	const EDITION_CONTENT = 2;

	const CONSTANT_CONSENT = 'SEGURIUM_CTI_CONSENT';
	const CONSTANT_EMAIL   = 'SEGURIUM_ALERTS_EMAIL';

	/**
	 * MySQL named lock serialising the wp-config path. `init` runs on
	 * every visitor request, so two hits on a freshly rolled-out site can
	 * both pass the marker check and both register a fresh IID.
	 */
	const CONSTANT_LOCK_NAME = 'segurium_consent_constant';

	const SOURCE_UI       = 'ui';
	const SOURCE_CLI      = 'cli';
	const SOURCE_CONSTANT = 'constant';

	/**
	 * Accepted values of the `source` field on the `consent` message.
	 *
	 * @return string[]
	 */
	public static function sources() {
		return array( self::SOURCE_UI, self::SOURCE_CLI, self::SOURCE_CONSTANT );
	}

	/**
	 * Whether the External Service Disclosure has been accepted.
	 *
	 * @return bool
	 */
	public static function given() {
		return Segurium_Storage::setting_get_bool( self::OPTION_CONSENT );
	}

	/**
	 * Edition that the screen, the command and the constant offer.
	 *
	 * @return int
	 */
	public static function edition_in_force() {
		return Segurium_Scan_Run::content_phases_enabled() ? self::EDITION_CONTENT : self::EDITION_BASE;
	}

	/**
	 * Edition on record; a consent stored before editions existed counts as the base edition.
	 *
	 * @return int 0 without consent.
	 */
	public static function accepted_edition() {
		if ( ! self::given() ) {
			return 0;
		}
		return max( self::EDITION_BASE, Segurium_Storage::setting_get_int( self::OPTION_EDITION ) );
	}

	/**
	 * Whether consent stands on an edition older than the one in force.
	 *
	 * @return bool
	 */
	public static function renewal_pending() {
		return self::given() && self::accepted_edition() < self::edition_in_force();
	}

	/**
	 * Whether the current user gets the renewal screen in this login session.
	 *
	 * @return bool
	 */
	public static function renewal_due_for_current_user() {
		if ( ! self::renewal_pending() || ! current_user_can( 'manage_options' ) ) {
			return false;
		}
		$token     = wp_get_session_token();
		$dismissed = (string) get_user_option( self::META_RENEWAL_DISMISSED );
		return '' === $token || ! hash_equals( self::session_mark( $token ), $dismissed );
	}

	/**
	 * Hide the renewal screen for the rest of the current login session.
	 *
	 * @return string `dismissed`, `no_session` without a login session, `write_failed`.
	 */
	public static function dismiss_renewal() {
		$token = wp_get_session_token();
		if ( '' === $token ) {
			return 'no_session';
		}
		$mark = self::session_mark( $token );
		if ( false === update_user_option( get_current_user_id(), self::META_RENEWAL_DISMISSED, $mark ) && get_user_option( self::META_RENEWAL_DISMISSED ) !== $mark ) {
			return 'write_failed';
		}
		return 'dismissed';
	}

	/**
	 * Mark of one login session under the edition in force.
	 *
	 * @param string $token Session token.
	 * @return string
	 */
	private static function session_mark( $token ) {
		return wp_hash( self::edition_in_force() . '|' . $token );
	}

	/**
	 * The line above a renewed disclosure.
	 *
	 * @return string
	 */
	public static function renewal_notice() {
		return __( 'This disclosure changed after you accepted it. Segurium sends the new data under your earlier consent. Please read the new version and accept it.', 'segurium' );
	}

	/**
	 * The External Service Disclosure, as data.
	 *
	 * The admin screen renders it as HTML and the CLI prints it as text.
	 * Both read this array, so they differ only where the email field differs.
	 *
	 * @param int|null $edition     Edition to describe. Default: the edition in force.
	 * @param bool     $email_field Whether the alerts email field follows the list.
	 * @return array{edition:int,title:string,intro:string,lists:array,facts:array,legal:array}
	 */
	public static function disclosure( $edition = null, $email_field = false ) {
		$edition = null === $edition ? self::edition_in_force() : (int) $edition;
		$content = $edition >= self::EDITION_CONTENT;

		$sent = array(
			__( 'File metadata: SHA-256 hash, path relative to your WordPress installation, size, modification time.', 'segurium' ),
			__( 'File content — only when classification by hash alone is not conclusive, or when generating a clean replacement during cleanup.', 'segurium' ),
		);
		if ( $content ) {
			$sent[] = __( 'Scheduled tasks (WP-Cron events): hook name, schedule, interval and arguments, and for each callback on the hook its name, file path, line numbers, file SHA-256 hash and source code.', 'segurium' );
			$sent[] = __( 'Accounts with administrator or editor rights, and accounts hidden from the user list: user ID, login name and email address in clear, roles, capabilities, registration date, and the number of application passwords and active login sessions.', 'segurium' );
			$sent[] = __( 'Active login sessions of those accounts: user ID, a one-way session ID, IP address and browser string in clear, sign-in time and expiry time.', 'segurium' );
			$sent[] = __( 'Scripts stored in the database: the code inside each script tag, or the address of an external script, and where Segurium found it (table, row and column, or option name). Segurium reads post content, post meta, options, comment text and comment author email, and the tables of code snippet plugins.', 'segurium' );
		}
		$sent[] = __( 'A randomly-generated installation identifier and basic site info (URL, name, WordPress version) used to associate requests with this install.', 'segurium' );
		$sent[] = __( 'Scan, cleanup, and security-settings events, so the cloud can keep your site protection in sync.', 'segurium' );
		$sent[] = __( 'Firewall events (blocked IPs, attack patterns) used to adapt protection across all Segurium-protected sites.', 'segurium' );
		$sent[] = $email_field
			? __( 'The email address for security alerts: the WordPress admin email, or the one you enter below, together with your email alerts choice.', 'segurium' )
			: __( 'The email address for security alerts: the WordPress admin email, or the one you set in Segurium Settings, together with your email alerts choice.', 'segurium' );

		$not_sent = array( __( 'Visitor analytics or personal data of users who visit your site.', 'segurium' ) );
		if ( $content ) {
			$not_sent[] = __( 'User passwords, password hashes and login session tokens.', 'segurium' );
			$not_sent[] = __( 'Media files, and posts, comments or other database content apart from the scripts listed above.', 'segurium' );
		} else {
			$not_sent[] = __( 'Database content, posts, comments, or media files.', 'segurium' );
		}
		$not_sent[] = __( 'Files whose hash is already known to the cloud — only the hash leaves your server.', 'segurium' );

		return array(
			'edition' => $edition,
			'title'   => __( 'External Service Disclosure', 'segurium' ),
			'intro'   => __( 'Segurium protects your site by working together with the Segurium cloud. When you enable it, Segurium exchanges data with our servers so it can detect malware, verify your files, and adapt protection to active threats.', 'segurium' ),
			'lists'   => array(
				array(
					'heading' => __( 'What is sent:', 'segurium' ),
					'items'   => $sent,
				),
				array(
					'heading' => __( 'What is NOT sent:', 'segurium' ),
					'items'   => $not_sent,
				),
			),
			'facts'   => array(
				array(
					'label' => __( 'Where it is sent:', 'segurium' ),
					'value' => __( 'Segurium servers at cti.segurium.com.', 'segurium' ),
				),
				array(
					'label' => __( 'Retention:', 'segurium' ),
					'value' => $content
						? __( 'File samples uploaded for analysis are kept for up to 365 days and then removed by an automated nightly purge. A sample may be removed sooner once it has been reviewed. Scheduled tasks, accounts, sessions and scripts are kept for up to 60 days after their last upload; the ones found malicious are kept with no time limit.', 'segurium' )
						: __( 'File samples uploaded for analysis are kept for up to 365 days and then removed by an automated nightly purge. A sample may be removed sooner once it has been reviewed.', 'segurium' ),
				),
			),
			'legal'   => array(
				/* translators: 1: opening link tag for Terms of Service, 2: closing link tag, 3: opening link tag for Privacy Policy, 4: closing link tag */
				'format'      => __( 'By enabling scanning, you agree to the %1$sTerms of Service%2$s and %3$sPrivacy Policy%4$s.', 'segurium' ),
				'terms_url'   => 'https://segurium.com/terms',
				'privacy_url' => 'https://segurium.com/privacy',
			),
		);
	}

	/**
	 * Accept the disclosure.
	 *
	 * The whole sequence, identical on every path: consent and cloud
	 * detection on, the alerts contact written before any CTI call so the
	 * register body carries it, IID registration deferred to cron because
	 * {@see Segurium_IID::register()} makes a 15s blocking POST, then the
	 * `plugin_activated` and `consent` messages and a platform snapshot so
	 * the installation-base dashboard populates without waiting for the
	 * daily tick. A renewal of an older edition stores the edition and sends `consent` only.
	 *
	 * @param string $source One of {@see self::sources()}.
	 * @param array  $args   Optional. `alerts` => array{enabled:bool,email:string}
	 *                       writes the alerts contact; omit it to leave the
	 *                       stored settings alone. `edition` lowers the edition accepted.
	 * @return array{accepted:bool,code:string,source:string,state:array}
	 */
	public static function accept( $source, array $args = array() ) {
		$source = (string) $source;
		if ( ! in_array( $source, self::sources(), true ) ) {
			return self::outcome( false, 'invalid_source', $source );
		}

		$edition = self::edition_in_force();
		if ( isset( $args['edition'] ) ) {
			$edition = max( self::EDITION_BASE, min( $edition, (int) $args['edition'] ) );
		}

		if ( self::given() ) {
			if ( self::accepted_edition() >= $edition ) {
				return self::outcome( false, 'already_accepted', $source );
			}
			if ( ! self::store_edition( $edition ) ) {
				return self::outcome( false, 'edition_write_failed', $source );
			}
			Segurium_Storage::setting_set( self::OPTION_SOURCE, $source );
			Segurium_Storage::cti_send_message(
				'consent',
				array(
					'source'  => $source,
					'edition' => $edition,
				)
			);
			return self::outcome( true, 'renewed', $source );
		}

		if ( ! self::store_edition( $edition ) ) {
			return self::outcome( false, 'edition_write_failed', $source );
		}
		Segurium_Storage::setting_set( self::OPTION_CONSENT, 1 );
		$cloud = Segurium_Settings_Writer::save( 'general', array( 'cloud_detection_enabled' => 1 ) );
		if ( ! $cloud['ok'] ) {
			// Consent itself stands — the operator answered. Cloud detection
			// staying off is a separate failure, and `state()` reports it.
			Segurium_Debug::log( '[segurium] consent_cloud_detection_failed: ' . $cloud['errors'][0]['code'] );
		}
		Segurium_Storage::setting_set( self::OPTION_SOURCE, $source );

		if ( isset( $args['alerts'] ) && is_array( $args['alerts'] ) ) {
			Segurium_Alerts_Settings::set(
				! empty( $args['alerts']['enabled'] ),
				isset( $args['alerts']['email'] ) ? (string) $args['alerts']['email'] : ''
			);
		}

		if ( ! wp_next_scheduled( Segurium::IID_REGISTER_CRON_HOOK ) ) {
			wp_schedule_single_event( time(), Segurium::IID_REGISTER_CRON_HOOK );
		}

		Segurium_Storage::cti_send_message( 'plugin_activated' );
		Segurium_Storage::cti_send_message(
			'consent',
			array(
				'source'  => $source,
				'edition' => $edition,
			)
		);

		Segurium_Platform_Snapshot::send_on_consent();

		return self::outcome( true, 'accepted', $source );
	}

	/**
	 * Store the accepted edition.
	 *
	 * @param int $edition Edition.
	 * @return bool Whether the option holds the edition.
	 */
	private static function store_edition( $edition ) {
		return Segurium_Storage::setting_set( self::OPTION_EDITION, $edition )
			|| Segurium_Storage::setting_get_int( self::OPTION_EDITION ) === $edition;
	}

	/**
	 * Result of one accept call.
	 *
	 * @param bool   $accepted Whether the call accepted an edition.
	 * @param string $code     Outcome code.
	 * @param string $source   Source the caller named.
	 * @return array{accepted:bool,code:string,source:string,state:array}
	 */
	private static function outcome( $accepted, $code, $source ) {
		return array(
			'accepted' => $accepted,
			'code'     => $code,
			'source'   => $source,
			'state'    => self::state(),
		);
	}

	/**
	 * Current consent state, for `wp segurium consent status` and for the
	 * report a repeat accept hands back.
	 *
	 * @return array{consent:bool,source:string,edition:int,edition_in_force:int,renewal_pending:bool,cloud_detection:bool,iid_registered:bool,alerts_enabled:bool,alerts_email:string,constant_applied:bool}
	 */
	public static function state() {
		$alerts = Segurium_Alerts_Settings::get();
		return array(
			'consent'          => self::given(),
			'source'           => Segurium_Storage::setting_get_string( self::OPTION_SOURCE ),
			'edition'          => self::accepted_edition(),
			'edition_in_force' => self::edition_in_force(),
			'renewal_pending'  => self::renewal_pending(),
			'cloud_detection'  => (bool) Segurium_Settings::get_field( 'general', 'cloud_detection_enabled' ),
			'iid_registered'   => null !== Segurium_IID::get_iid(),
			'alerts_enabled'   => (bool) $alerts['enabled'],
			'alerts_email'     => (string) $alerts['email'],
			'constant_applied' => Segurium_Storage::setting_get_bool( self::OPTION_CONSTANT_APPLIED ),
		);
	}

	/**
	 * Whether wp-config asks for consent on this install.
	 *
	 * @return bool
	 */
	public static function constant_requested() {
		return defined( self::CONSTANT_CONSENT ) && constant( self::CONSTANT_CONSENT );
	}

	/**
	 * Edition named by a value of the wp-config constant.
	 *
	 * @param mixed $value Value of the constant.
	 * @return int
	 */
	public static function edition_of( $value ) {
		$edition = is_numeric( $value ) ? (int) $value : self::EDITION_BASE;
		return max( self::EDITION_BASE, min( self::EDITION_CONTENT, $edition ) );
	}

	/**
	 * Alerts contact the wp-config path asks for.
	 *
	 * Always present, so the constant lands the same alerts state a click
	 * and a CLI accept land: opted in, following the site admin email
	 * unless `SEGURIUM_ALERTS_EMAIL` names another one. An address that
	 * cannot be an address is logged and dropped rather than silently
	 * pointing the alerts at nothing.
	 *
	 * @return array
	 */
	private static function constant_alerts_args() {
		$email = defined( self::CONSTANT_EMAIL ) ? (string) constant( self::CONSTANT_EMAIL ) : '';
		if ( '' !== $email && ! is_email( $email ) ) {
			Segurium_Debug::log(
				'[segurium] ' . self::CONSTANT_EMAIL . ' is not a valid address; security alerts follow the site admin email'
			);
			$email = '';
		}

		return array(
			'alerts' => array(
				'enabled' => true,
				'email'   => $email,
			),
		);
	}

	/**
	 * Apply the wp-config constant, once per edition.
	 *
	 * Runs on `init` on every tier so an unattended rollout does not wait
	 * for someone to open the admin screen. The marker is stamped whether
	 * or not the accept did any work, so a site that later revokes consent
	 * stays revoked.
	 *
	 * @return array|null The accept result, or null when nothing was due.
	 */
	public static function maybe_apply_constant() {
		return self::constant_requested() ? self::apply_constant( self::edition_of( constant( self::CONSTANT_CONSENT ) ) ) : null;
	}

	/**
	 * Accept the edition the constant names, capped by the edition in force.
	 *
	 * @param int $requested Edition the constant names.
	 * @return array|null The accept result, or null when nothing was due.
	 */
	public static function apply_constant( $requested ) {
		$due = min( (int) $requested, self::edition_in_force() );
		if ( $due < self::EDITION_BASE || ! self::constant_due( $due ) ) {
			return null;
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- session-bound advisory lock has no SQL helper and is intentionally uncacheable.
		$lock = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', self::CONSTANT_LOCK_NAME ) );
		if ( '1' !== (string) $lock ) {
			return null;
		}

		try {
			// Past this request's option cache: the winner of the race
			// stamped the marker after the read above filled it.
			wp_cache_delete( 'alloptions', 'options' );
			if ( ! self::constant_due( $due ) ) {
				return null;
			}

			$result = self::accept( self::SOURCE_CONSTANT, self::constant_alerts_args() + array( 'edition' => $due ) );
			if ( 'edition_write_failed' !== $result['code'] ) {
				Segurium_Storage::setting_set( self::OPTION_CONSTANT_APPLIED, $due );
			}

			return $result;
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- session-bound advisory lock release; matches the GET_LOCK above.
			$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::CONSTANT_LOCK_NAME ) );
		}
	}

	/**
	 * Whether the constant still has an edition to apply.
	 *
	 * @param int $due Edition the constant would apply now.
	 * @return bool
	 */
	private static function constant_due( $due ) {
		$applied = Segurium_Storage::setting_get_int( self::OPTION_CONSTANT_APPLIED );
		return $applied < $due && ( 0 === $applied || self::given() );
	}
}

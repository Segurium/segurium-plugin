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

	/**
	 * One-shot marker for the wp-config path, so a site that defines the
	 * constant and later revokes consent from the admin screen is not
	 * re-consented on the next request.
	 */
	const OPTION_CONSTANT_APPLIED = 'segurium_consent_constant_applied';

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
	 * The External Service Disclosure, as data.
	 *
	 * The admin screen renders it as HTML and the CLI prints it as text.
	 * Both read this array, so neither can show copy the other does not.
	 *
	 * @return array{title:string,intro:string,lists:array,facts:array,legal:array}
	 */
	public static function disclosure() {
		return array(
			'title' => __( 'External Service Disclosure', 'segurium' ),
			'intro' => __( 'Segurium protects your site by working together with the Segurium cloud. When you enable it, Segurium exchanges data with our servers so it can detect malware, verify your files, and adapt protection to active threats.', 'segurium' ),
			'lists' => array(
				array(
					'heading' => __( 'What is sent:', 'segurium' ),
					'items'   => array(
						__( 'File metadata: SHA-256 hash, path relative to your WordPress installation, size, modification time.', 'segurium' ),
						__( 'File content — only when classification by hash alone is not conclusive, or when generating a clean replacement during cleanup.', 'segurium' ),
						__( 'A randomly-generated installation identifier and basic site info (URL, name, WordPress version) used to associate requests with this install.', 'segurium' ),
						__( 'Scan, cleanup, and security-settings events, so the cloud can keep your site protection in sync.', 'segurium' ),
						__( 'Firewall events (blocked IPs, attack patterns) used to adapt protection across all Segurium-protected sites.', 'segurium' ),
						__( 'The email address for security alerts: the WordPress admin email, or the one you enter below, together with your email alerts choice.', 'segurium' ),
					),
				),
				array(
					'heading' => __( 'What is NOT sent:', 'segurium' ),
					'items'   => array(
						__( 'Visitor analytics or personal data of users who visit your site.', 'segurium' ),
						__( 'Database content, posts, comments, or media files.', 'segurium' ),
						__( 'Files whose hash is already known to the cloud — only the hash leaves your server.', 'segurium' ),
					),
				),
			),
			'facts' => array(
				array(
					'label' => __( 'Where it is sent:', 'segurium' ),
					'value' => __( 'Segurium servers at cti.segurium.com.', 'segurium' ),
				),
				array(
					'label' => __( 'Retention:', 'segurium' ),
					'value' => __( 'File samples uploaded for analysis are kept for up to 365 days and then removed by an automated nightly purge. A sample may be removed sooner once it has been reviewed.', 'segurium' ),
				),
			),
			'legal' => array(
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
	 * daily tick.
	 *
	 * @param string $source One of {@see self::sources()}.
	 * @param array  $args   Optional. `alerts` => array{enabled:bool,email:string}
	 *                       writes the alerts contact; omit it to leave the
	 *                       stored settings alone.
	 * @return array{accepted:bool,code:string,source:string,state:array}
	 */
	public static function accept( $source, array $args = array() ) {
		$source = (string) $source;
		if ( ! in_array( $source, self::sources(), true ) ) {
			return array(
				'accepted' => false,
				'code'     => 'invalid_source',
				'source'   => $source,
				'state'    => self::state(),
			);
		}

		if ( self::given() ) {
			return array(
				'accepted' => false,
				'code'     => 'already_accepted',
				'source'   => $source,
				'state'    => self::state(),
			);
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
		Segurium_Storage::cti_send_message( 'consent', array( 'source' => $source ) );

		Segurium_Platform_Snapshot::send_on_consent();

		return array(
			'accepted' => true,
			'code'     => 'accepted',
			'source'   => $source,
			'state'    => self::state(),
		);
	}

	/**
	 * Current consent state, for `wp segurium consent status` and for the
	 * report a repeat accept hands back.
	 *
	 * @return array{consent:bool,source:string,cloud_detection:bool,iid_registered:bool,alerts_enabled:bool,alerts_email:string,constant_applied:bool}
	 */
	public static function state() {
		$alerts = Segurium_Alerts_Settings::get();
		return array(
			'consent'          => self::given(),
			'source'           => Segurium_Storage::setting_get_string( self::OPTION_SOURCE ),
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
	 * Apply the wp-config constant, once.
	 *
	 * Runs on `init` on every tier so an unattended rollout does not wait
	 * for someone to open the admin screen. The marker is stamped whether
	 * or not the accept did any work, so a site that later revokes consent
	 * stays revoked.
	 *
	 * @return array|null The accept result, or null when nothing was due.
	 */
	public static function maybe_apply_constant() {
		if ( ! self::constant_requested() ) {
			return null;
		}
		if ( Segurium_Storage::setting_get_bool( self::OPTION_CONSTANT_APPLIED ) ) {
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
			if ( Segurium_Storage::setting_get_bool( self::OPTION_CONSTANT_APPLIED ) ) {
				return null;
			}

			$result = self::accept( self::SOURCE_CONSTANT, self::constant_alerts_args() );
			Segurium_Storage::setting_set( self::OPTION_CONSTANT_APPLIED, 1 );

			return $result;
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- session-bound advisory lock release; matches the GET_LOCK above.
			$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::CONSTANT_LOCK_NAME ) );
		}
	}
}

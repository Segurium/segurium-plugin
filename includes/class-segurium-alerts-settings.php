<?php
/**
 * Email-alerts opt-in settings.
 *
 * Two fields under the registry's `alerts` row:
 *   - enabled (bool, default false)
 *   - email   (string, default get_option('admin_email'))
 *
 * A separate option, segurium_migrated_alerts_timezone, marks the one-shot
 * snapshot that carries the site timezone to installs which opted in
 * before the field existed.
 *
 * A save that changes a value pushes one `settings_snapshot` with
 * `feature=alerts`, so the server-side mailer picks up the new contact
 * without forcing a re-register cycle. CTI itself decides when to send
 * digests — the plugin never sends mail.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Persisted settings + CTI sync for the email-alerts feature.
 */
final class Segurium_Alerts_Settings {

	const SETTINGS_SLUG = 'alerts';

	/**
	 * One-shot sentinel for the snapshot that backfills the timezone. Not
	 * stamped until the IID exists, so an install that has not registered
	 * yet retries on a later admin request.
	 */
	const MIGRATION_FLAG_TIMEZONE = 'segurium_migrated_alerts_timezone';

	/**
	 * Wire the one-shot timezone backfill. The settings writer owns the
	 * snapshot a save produces.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'admin_init', array( __CLASS__, 'migrate_push_timezone' ) );
	}

	/**
	 * Deliver the timezone of an install that opted in before the field
	 * existed, so it does not wait for the owner to change a setting.
	 *
	 * The capability check is not decoration: `segurium_2fa_*` are `nopriv`
	 * actions, and admin-ajax fires `admin_init`.
	 *
	 * @return void
	 */
	public static function migrate_push_timezone() {
		if ( (bool) Segurium_Storage::setting_get( self::MIGRATION_FLAG_TIMEZONE, false ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( null === Segurium_IID::get_iid() ) {
			return;
		}
		if ( self::get()['enabled'] ) {
			self::push_to_cti();
		}
		Segurium_Storage::setting_set( self::MIGRATION_FLAG_TIMEZONE, 1 );
	}

	/**
	 * Retrieve the current settings, filling in defaults.
	 *
	 * @return array{enabled:bool,email:string}
	 */
	public static function get() {
		$settings = Segurium_Settings::get( self::SETTINGS_SLUG );
		if ( '' === $settings['email'] ) {
			$settings['email'] = (string) Segurium_Storage::setting_get( 'admin_email', '' );
		}
		return $settings;
	}

	/**
	 * Reduce raw input to the two stored fields. An empty or invalid address
	 * is stored as '' so {@see self::get()} keeps following `admin_email`.
	 *
	 * @param array $input Raw settings input.
	 * @return array{enabled:bool,email:string}
	 */
	public static function validate_settings( $input ) {
		$input = is_array( $input ) ? $input : array();
		$email = isset( $input['email'] ) && is_string( $input['email'] ) ? sanitize_email( $input['email'] ) : '';
		return array(
			'enabled' => ! empty( $input['enabled'] ),
			'email'   => (string) $email,
		);
	}

	/**
	 * Persist the settings tuple. Returns true when the stored values moved.
	 *
	 * @param bool   $enabled Whether alerts are opted in.
	 * @param string $email   Contact email. An empty or invalid value is
	 *                        stored as '' so get() keeps following the
	 *                        site's `admin_email`.
	 * @return bool
	 */
	public static function set( $enabled, $email ) {
		$result = Segurium_Settings_Writer::save(
			self::SETTINGS_SLUG,
			array(
				'enabled' => $enabled,
				'email'   => $email,
			)
		);
		return (bool) $result['changed'];
	}

	/**
	 * The `settings` object CTI reads to upsert the alerts contact. The
	 * address is a registry secret, so it is named here rather than left to
	 * the default builder: CTI cannot mail a digest without it.
	 *
	 * The tier is resolved server-side too via the entitlements snapshot —
	 * we send what we know locally so the server has the latest copy
	 * without an extra CAS hop.
	 *
	 * @param array $applied Stored settings after the write.
	 * @return array
	 */
	public static function snapshot_settings( array $applied ) {
		$email = (string) ( $applied['email'] ?? '' );
		if ( '' === $email ) {
			$email = (string) Segurium_Storage::setting_get( 'admin_email', '' );
		}
		return array(
			'email'    => $email,
			'opt_in'   => ! empty( $applied['enabled'] ),
			'tier'     => self::current_tier(),
			'locale'   => self::short_locale(),
			'timezone' => wp_timezone_string(),
		);
	}

	/**
	 * Emit the snapshot for the settings as they stand.
	 *
	 * @return void
	 */
	public static function push_to_cti() {
		if ( ! class_exists( 'Segurium_Storage' ) ) {
			return;
		}
		// Before the IID exists the register body carries the same
		// contact fields, and sending here would register synchronously
		// inside the consent request.
		if ( null === Segurium_IID::get_iid() ) {
			return;
		}
		Segurium_Settings_Writer::push_snapshot( self::SETTINGS_SLUG );
	}

	/**
	 * Resolve the operator's current tier. Free / Pro only for now.
	 *
	 * @return string
	 */
	private static function current_tier() {
		// Tier is owned by CTI's quota envelope, not
		// Freemius. The cached envelope reflects webhook-flipped state
		// within one /v1/quota/state hop; on a fresh install (no cache
		// yet) we report Free, which is the conservative default.
		if ( ! class_exists( 'Segurium_Quota' ) ) {
			return 'free';
		}
		try {
			return Segurium_Quota::plan_tier();
		} catch ( Throwable $e ) {
			return 'free';
		}
	}

	/**
	 * Short ISO-639-1 locale string, e.g. `en` for `en_US`. Falls back to
	 * `en` when WordPress hasn't reported a locale yet.
	 *
	 * @return string
	 */
	private static function short_locale() {
		$loc = (string) get_locale();
		if ( '' === $loc ) {
			return 'en';
		}
		return strtolower( substr( $loc, 0, 2 ) );
	}
}

<?php
/**
 * Email-alerts opt-in settings.
 *
 * Two persisted options:
 *   - segurium_alerts_email_enabled (bool, default false)
 *   - segurium_alerts_email_address (string, default get_option('admin_email'))
 *
 * A third option, segurium_migrated_alerts_timezone, marks the one-shot
 * snapshot that carries the site timezone to installs which opted in
 * before the field existed.
 *
 * On any change to either option we push a `settings_snapshot` CTI message
 * with `feature=alerts` so the server-side mailer picks up the new contact
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

	const OPTION_ENABLED = 'segurium_alerts_email_enabled';
	const OPTION_EMAIL   = 'segurium_alerts_email_address';
	const FEATURE_KEY    = 'alerts';
	const CTI_MSG_TYPE   = 'settings_snapshot';

	/**
	 * One-shot sentinel for the snapshot that backfills the timezone. Not
	 * stamped until the IID exists, so an install that has not registered
	 * yet retries on a later admin request.
	 */
	const MIGRATION_FLAG_TIMEZONE = 'segurium_migrated_alerts_timezone';

	/**
	 * Raised while set() writes its two options so the option hooks do
	 * not push a half-written tuple.
	 *
	 * @var bool
	 */
	private static $suppress_push = false;

	/**
	 * Wire `update_option` hooks so a settings change immediately flows to
	 * CTI. Idempotent — safe to call from the plugin bootstrap on every
	 * request.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'update_option_' . self::OPTION_ENABLED, array( __CLASS__, 'on_change' ), 10, 2 );
		add_action( 'update_option_' . self::OPTION_EMAIL, array( __CLASS__, 'on_change' ), 10, 2 );
		add_action( 'add_option_' . self::OPTION_ENABLED, array( __CLASS__, 'on_added' ), 10, 2 );
		add_action( 'add_option_' . self::OPTION_EMAIL, array( __CLASS__, 'on_added' ), 10, 2 );
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
		$enabled = (bool) Segurium_Storage::setting_get_bool( self::OPTION_ENABLED );
		$email   = (string) Segurium_Storage::setting_get_string( self::OPTION_EMAIL );
		if ( '' === $email ) {
			$email = (string) Segurium_Storage::setting_get( 'admin_email', '' );
		}
		return array(
			'enabled' => $enabled,
			'email'   => $email,
		);
	}

	/**
	 * Persist the settings tuple.
	 *
	 * Pushes one settings_snapshot to CTI when either option changed.
	 * Returns true in that case.
	 *
	 * @param bool   $enabled Whether alerts are opted in.
	 * @param string $email   Contact email. An empty or invalid value is
	 *                        stored as '' so get() keeps following the
	 *                        site's `admin_email`.
	 * @return bool
	 */
	public static function set( $enabled, $email ) {
		$email               = is_string( $email ) ? sanitize_email( $email ) : '';
		self::$suppress_push = true;
		try {
			$changed_a = (bool) Segurium_Storage::setting_set( self::OPTION_ENABLED, $enabled ? 1 : 0 );
			$changed_b = (bool) Segurium_Storage::setting_set( self::OPTION_EMAIL, $email );
		} finally {
			self::$suppress_push = false;
		}
		$changed = $changed_a || $changed_b;
		if ( $changed ) {
			self::push_to_cti();
		}
		return $changed;
	}

	/**
	 * Hook callback for `update_option_*`.
	 *
	 * @param mixed $old Old value (unused).
	 * @param mixed $new_value New value (unused — we re-read both options to
	 *                         send a complete snapshot).
	 * @return void
	 */
	public static function on_change( $old, $new_value ) {
		unset( $old, $new_value );
		self::push_to_cti();
	}

	/**
	 * Hook callback for `add_option_*` (first-time write of an option that
	 * never existed). Same payload shape as on_change.
	 *
	 * @param string $option Option name (unused).
	 * @param mixed  $value  New value (unused).
	 * @return void
	 */
	public static function on_added( $option, $value ) {
		unset( $option, $value );
		self::push_to_cti();
	}

	/**
	 * Build the `settings_snapshot` payload and emit it via the CTI client.
	 * The tier is resolved server-side too via the entitlements snapshot —
	 * we send what we know locally so the server has the latest copy
	 * without an extra CAS hop.
	 *
	 * @return void
	 */
	public static function push_to_cti() {
		if ( self::$suppress_push || ! class_exists( 'Segurium_Storage' ) ) {
			return;
		}
		// Before the IID exists the register body carries the same
		// contact fields, and sending here would register synchronously
		// inside the consent request.
		if ( null === Segurium_IID::get_iid() ) {
			return;
		}
		$settings = self::get();
		$tier     = self::current_tier();
		$locale   = self::short_locale();
		$payload  = array(
			'feature'  => self::FEATURE_KEY,
			'settings' => array(
				'email'    => $settings['email'],
				'opt_in'   => (bool) $settings['enabled'],
				'tier'     => $tier,
				'locale'   => $locale,
				'timezone' => wp_timezone_string(),
			),
		);
		Segurium_Storage::cti_send_message( self::CTI_MSG_TYPE, wp_json_encode( $payload ) );
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

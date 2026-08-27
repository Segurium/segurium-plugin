<?php
/**
 * Persisted settings + CTI sync for the auto-fix feature.
 *
 * Single boolean option:
 *   - segurium_auto_fix_enabled (bool, default false)
 *
 * Auto-fix runs on every install. Plan-tier rate limits
 * are enforced per-cleanup by CTI's quota service: Free sites get the
 * first N findings cleaned in a 30-day window and quota_exceeded for
 * the rest, Pro sites are effectively unbounded.
 *
 * On any change to the option we push a `settings_snapshot` CTI message
 * so the server has the latest user preference for diagnostics / support.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Persisted settings + CTI sync for unattended malware auto-fix.
 */
final class Segurium_Auto_Fix_Settings {

	const OPTION_ENABLED = 'segurium_auto_fix_enabled';
	const FEATURE_KEY    = 'auto_fix';
	const CTI_MSG_TYPE   = 'settings_snapshot';

	/**
	 * Wire `update_option` / `add_option` listeners so a settings change
	 * immediately flows to CTI. Idempotent — safe to call from the plugin
	 * bootstrap on every request.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'update_option_' . self::OPTION_ENABLED, array( __CLASS__, 'on_change' ), 10, 2 );
		add_action( 'add_option_' . self::OPTION_ENABLED, array( __CLASS__, 'on_added' ), 10, 2 );
	}

	/**
	 * Whether the user has opted in to unattended auto-fix.
	 *
	 * Note: this only reflects the persisted preference. CTI's per-cleanup
	 * quota check is what bounds the actual cleanup volume per plan tier.
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return (bool) Segurium_Storage::setting_get_bool( self::OPTION_ENABLED, false );
	}

	/**
	 * Persist the toggle state. Returns true when the underlying option
	 * actually changed (matching the Segurium_Alerts_Settings shape).
	 *
	 * @param bool $enabled Whether auto-fix should run unattended.
	 * @return bool
	 */
	public static function set( $enabled ) {
		return (bool) Segurium_Storage::setting_set( self::OPTION_ENABLED, (bool) $enabled );
	}

	/**
	 * Hook callback for `update_option_*`.
	 *
	 * @param mixed $old       Old value (unused).
	 * @param mixed $new_value New value (unused — we re-read on emit).
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
	 *
	 * @return void
	 */
	public static function push_to_cti() {
		if ( ! class_exists( 'Segurium_Storage' ) ) {
			return;
		}
		$payload = array(
			'feature'  => self::FEATURE_KEY,
			'settings' => array(
				'enabled' => self::is_enabled(),
				'tier'    => self::current_tier(),
			),
		);
		Segurium_Storage::cti_send_message( self::CTI_MSG_TYPE, (string) wp_json_encode( $payload ) );
	}

	/**
	 * Resolve the current tier ("free" / "pro").
	 *
	 * @return string
	 */
	private static function current_tier() {
		// Tier is owned by CTI's quota envelope.
		if ( ! class_exists( 'Segurium_Quota' ) ) {
			return 'free';
		}
		try {
			return Segurium_Quota::plan_tier();
		} catch ( Throwable $e ) {
			return 'free';
		}
	}
}

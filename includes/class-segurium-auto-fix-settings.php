<?php
/**
 * Persisted settings + CTI sync for the auto-fix feature.
 *
 * Single boolean field under the registry's `auto_fix` row:
 *   - enabled (bool, default false)
 *
 * Auto-fix runs on every install. Plan-tier rate limits
 * are enforced per-cleanup by CTI's quota service: Free sites get the
 * first N findings cleaned in a 30-day window and quota_exceeded for
 * the rest, Pro sites are effectively unbounded.
 *
 * On any change to the row we push a `settings_snapshot` CTI message
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

	const SETTINGS_SLUG = 'auto_fix';

	/**
	 * Whether the user has opted in to unattended auto-fix.
	 *
	 * Note: this only reflects the persisted preference. CTI's per-cleanup
	 * quota check is what bounds the actual cleanup volume per plan tier.
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return (bool) Segurium_Settings::get_field( self::SETTINGS_SLUG, 'enabled' );
	}

	/**
	 * Reduce raw input to the single stored field.
	 *
	 * @param array $input Raw settings input.
	 * @return array{enabled:bool}
	 */
	public static function validate_settings( $input ) {
		$input = is_array( $input ) ? $input : array();
		return array( 'enabled' => ! empty( $input['enabled'] ) );
	}

	/**
	 * Persist the toggle state. Returns true when the underlying option
	 * actually changed (matching the Segurium_Alerts_Settings shape).
	 *
	 * @param bool $enabled Whether auto-fix should run unattended.
	 * @return bool
	 */
	public static function set( $enabled ) {
		$result = Segurium_Settings_Writer::save( self::SETTINGS_SLUG, array( 'enabled' => $enabled ) );
		return (bool) $result['changed'];
	}

	/**
	 * The `settings` object CTI reads to pick the mail footer a Pro site
	 * gets. It owns the `enabled` field and nothing else.
	 *
	 * @param array $applied Stored settings after the write.
	 * @return array
	 */
	public static function snapshot_settings( array $applied ) {
		return array(
			'enabled' => ! empty( $applied['enabled'] ),
			'tier'    => self::current_tier(),
		);
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

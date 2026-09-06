<?php
/**
 * Settings model for the scheduled scan feature.
 *
 * The user picks a frequency (off / daily / weekly) and a firing
 * time. On first access we generate sensible randomized defaults so
 * not every Segurium installation hammers WP-Cron at the same minute,
 * and those randomized values persist across mode switches.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Persisted settings + helpers for the scheduled malware scan.
 */
final class Segurium_Scheduled_Scan_Settings {

	const OPTION_KEY    = 'segurium_settings_scheduled_scan';
	const SETTINGS_SLUG = 'scheduled_scan';

	const MODE_OFF    = 'off';
	const MODE_DAILY  = 'daily';
	const MODE_WEEKLY = 'weekly';

	const VALID_MODES = array(
		self::MODE_OFF,
		self::MODE_DAILY,
		self::MODE_WEEKLY,
	);

	/**
	 * Default mode the first time settings are generated for a
	 * consented installation.
	 */
	const DEFAULT_MODE = self::MODE_DAILY;

	/**
	 * Return the current settings, filling in defaults for any keys
	 * that have never been written. Does NOT touch the database.
	 *
	 * @return array
	 */
	public static function get() {
		$settings = Segurium_Settings::get( self::SETTINGS_SLUG );
		if ( ! in_array( $settings['mode'], self::VALID_MODES, true ) ) {
			$settings['mode'] = self::MODE_OFF;
		}
		return $settings;
	}

	/**
	 * Lazily seed the per-site randomized defaults the first time the
	 * scheduled scan feature is observed. Idempotent: subsequent calls
	 * are no-ops once the option has been generated.
	 *
	 * Generation rules (per requirement):
	 *   - hour ∈ [1, 5] inclusive
	 *   - minute ∈ [0, 59] inclusive
	 *   - day_of_week ∈ {Sat=6, Sun=0}
	 *   - mode defaults to MODE_DAILY
	 *
	 * @return void
	 */
	public static function ensure_pregenerated() {
		if ( ! empty( self::get()['generated_at'] ) ) {
			return;
		}

		Segurium_Settings_Writer::save(
			self::SETTINGS_SLUG,
			array(
				'mode'         => self::DEFAULT_MODE,
				'hour'         => self::random_hour(),
				'minute'       => self::random_minute(),
				'day_of_week'  => self::random_weekend_day(),
				'generated_at' => time(),
			)
		);
	}

	/**
	 * Save a (possibly partial) settings update. Unspecified fields
	 * inherit the previous value so the user can switch modes without
	 * losing their pre-generated time / day. Validates every input.
	 *
	 * @param array $input Subset of {mode, hour, minute, day_of_week}.
	 * @return true|WP_Error True on success, WP_Error on validation failure.
	 */
	public static function save( $input ) {
		$result = Segurium_Settings_Writer::save( self::SETTINGS_SLUG, $input );
		if ( ! $result['ok'] ) {
			$error = $result['errors'][0];
			return new WP_Error( $error['code'], Segurium_Settings_Writer::error_message( $error ) );
		}

		return true;
	}

	/**
	 * Validate a (possibly partial) settings update against the persisted
	 * values, without writing anything.
	 *
	 * @param array $input Subset of {mode, hour, minute, day_of_week}.
	 * @return array|WP_Error Storable settings, or the first validation error.
	 */
	public static function validate_settings( $input ) {
		if ( ! is_array( $input ) ) {
			return new WP_Error(
				'invalid_settings',
				__( 'Invalid settings payload.', 'segurium' )
			);
		}

		$current = self::get();
		// If we have never generated, do so now so partial saves still
		// land coherent values.
		if ( empty( $current['generated_at'] ) ) {
			$current['hour']         = self::random_hour();
			$current['minute']       = self::random_minute();
			$current['day_of_week']  = self::random_weekend_day();
			$current['generated_at'] = time();
		}

		if ( array_key_exists( 'mode', $input ) ) {
			$mode = (string) $input['mode'];
			if ( ! in_array( $mode, self::VALID_MODES, true ) ) {
				return new WP_Error(
					'invalid_mode',
					__( 'Frequency must be one of: off, daily, weekly.', 'segurium' )
				);
			}
			$current['mode'] = $mode;
		}

		if ( array_key_exists( 'hour', $input ) ) {
			$hour = (int) $input['hour'];
			if ( $hour < 0 || $hour > 23 ) {
				return new WP_Error(
					'invalid_hour',
					__( 'Hour must be between 0 and 23.', 'segurium' )
				);
			}
			$current['hour'] = $hour;
		}

		if ( array_key_exists( 'minute', $input ) ) {
			$minute = (int) $input['minute'];
			if ( $minute < 0 || $minute > 59 ) {
				return new WP_Error(
					'invalid_minute',
					__( 'Minute must be between 0 and 59.', 'segurium' )
				);
			}
			$current['minute'] = $minute;
		}

		if ( array_key_exists( 'day_of_week', $input ) ) {
			$dow = (int) $input['day_of_week'];
			if ( $dow < 0 || $dow > 6 ) {
				return new WP_Error(
					'invalid_day_of_week',
					__( 'Day of week must be between 0 (Sunday) and 6 (Saturday).', 'segurium' )
				);
			}
			$current['day_of_week'] = $dow;
		}

		return $current;
	}

	/**
	 * Compute the next firing timestamp in UTC for the current
	 * settings, taking the site timezone into account so the user's
	 * "03:15" actually fires at 03:15 site-local time.
	 *
	 * @return int Unix timestamp in UTC, or 0 when scheduling is off.
	 */
	public static function to_next_timestamp_utc() {
		$s = self::get();
		if ( self::MODE_OFF === $s['mode'] ) {
			return 0;
		}

		$tz = wp_timezone();

		try {
			$now = new DateTimeImmutable( 'now', $tz );
		} catch ( Exception $e ) {
			return 0;
		}

		$candidate = $now->setTime( $s['hour'], $s['minute'], 0 );
		if ( $candidate <= $now ) {
			$candidate = $candidate->modify( '+1 day' );
		}

		if ( self::MODE_WEEKLY === $s['mode'] ) {
			$target = $s['day_of_week'];
			while ( (int) $candidate->format( 'w' ) !== $target ) {
				$candidate = $candidate->modify( '+1 day' );
			}
		}

		return $candidate->getTimestamp();
	}

	/**
	 * Random hour in [1, 5] — picks an off-peak slot. Uses PHP's
	 * cryptographically strong random_int instead of wp_rand because
	 * this method is reachable during plugin construction (before
	 * wp-includes/load.php has loaded the wp_rand pluggable).
	 *
	 * @return int
	 */
	private static function random_hour() {
		try {
			return random_int( 1, 5 );
		} catch ( Throwable $e ) {
			return 1 + ( (int) ( microtime( true ) * 1000 ) % 5 );
		}
	}

	/**
	 * Random minute in [0, 59].
	 *
	 * @return int
	 */
	private static function random_minute() {
		try {
			return random_int( 0, 59 );
		} catch ( Throwable $e ) {
			return (int) ( microtime( true ) * 1000 ) % 60;
		}
	}

	/**
	 * Random weekend day under the WordPress convention
	 * (0 = Sunday, 6 = Saturday). Returns one of those two only.
	 *
	 * @return int
	 */
	private static function random_weekend_day() {
		try {
			return random_int( 0, 1 ) ? 6 : 0;
		} catch ( Throwable $e ) {
			return ( (int) ( microtime( true ) * 1000 ) % 2 ) ? 6 : 0;
		}
	}
}

<?php
/**
 * Pricing-page presentation tweaks.
 *
 * Hooks into Freemius's `pricing/css_path` filter to ship a stylesheet
 * that overrides the SDK defaults (uppercase plan title / description /
 * cycle / CTA, uniform 700 weights, hidden featured plan), and into
 * `pricing/show_annual_in_monthly` so the annual-only price ladder is
 * quoted per year rather than broken down per month.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the Freemius pricing-page filters.
 */
final class Segurium_Pricing {

	/**
	 * Plugin-relative path of the override stylesheet.
	 */
	const CSS_RELATIVE_PATH = 'assets/css/pricing-overrides.css';

	/**
	 * Wire the Freemius filters. Invoked once during plugin init.
	 */
	public static function register_hooks() {
		add_filter(
			'fs_pricing/css_path_segurium',
			array( __CLASS__, 'override_css_path' )
		);
		add_filter(
			'fs_pricing/show_annual_in_monthly_segurium',
			array( __CLASS__, 'show_annual_in_monthly' )
		);
	}

	/**
	 * Filter callback. Returns the absolute path of the override CSS
	 * file Freemius should enqueue alongside its bundled stylesheet.
	 *
	 * Returns the original value untouched if the file is missing on
	 * disk so a half-installed plugin can't break the pricing page.
	 *
	 * @param mixed $current Current filter value (Freemius default: null).
	 * @return mixed
	 */
	public static function override_css_path( $current ) {
		if ( ! defined( 'SEGURIUM_PLUGIN_DIR' ) ) {
			return $current;
		}
		$path = SEGURIUM_PLUGIN_DIR . self::CSS_RELATIVE_PATH;
		if ( ! file_exists( $path ) ) {
			return $current;
		}
		return $path;
	}

	/**
	 * Filter callback. Segurium bills annually only, so the SDK default
	 * of dividing the annual price into a monthly figure quotes a price
	 * nobody is ever charged.
	 *
	 * @param mixed $current Current filter value (Freemius default: true).
	 * @return bool
	 */
	public static function show_annual_in_monthly( $current ) {
		unset( $current );
		return false;
	}
}

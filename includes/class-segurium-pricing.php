<?php
/**
 * Pricing-page presentation tweaks.
 *
 * Hooks into Freemius's `pricing/css_path` filter to ship a stylesheet
 * that overrides the SDK defaults (uppercase plan title / description /
 * cycle / CTA, uniform 700 weights).
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the `pricing/css_path` filter that ships our override stylesheet.
 */
final class Segurium_Pricing {

	/**
	 * Plugin-relative path of the override stylesheet.
	 */
	const CSS_RELATIVE_PATH = 'assets/css/pricing-overrides.css';

	/**
	 * Wire the Freemius filter. Invoked once during plugin init.
	 */
	public static function register_hooks() {
		add_filter(
			'fs_pricing/css_path_segurium',
			array( __CLASS__, 'override_css_path' )
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
}

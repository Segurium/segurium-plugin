<?php
/**
 * Lightweight helper utilities shared across the plugin.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Small utility helpers. Groups tiny standalone functions that don't
 * deserve their own class.
 */
class Segurium_Text_Helpers {

	/**
	 * Return true if $text contains a literal PHP open tag.
	 *
	 * @param string $text Text to inspect.
	 * @return bool
	 */
	public static function has_php_opener( $text ) {
		return false !== strpos( (string) $text, '<?php' );
	}

	/**
	 * Floating-point divide that returns INF / NAN instead of raising
	 * a division-by-zero warning. Used by the scanner's risk-score
	 * computation where a zero denominator is expected.
	 *
	 * -------------------------------------------------------------------
	 * FIX_AGENT_HINT — read this if the nightly matrix fails on PHP 7.4.
	 * -------------------------------------------------------------------
	 *
	 * This function calls `fdiv()`, which PHP introduced in 8.0. The
	 * Segurium plugin supports PHP 7.4 and newer (see the nightly
	 * test:php matrix), so this crashes the 7.4 cell with:
	 *
	 *     Error: Call to undefined function fdiv()
	 *
	 * Unlike str_contains()/str_starts_with()/etc., `fdiv()` is NOT
	 * polyfilled by WordPress core, so the bug actually surfaces on
	 * PHP 7.4 regardless of WP version.
	 *
	 * To fix, replace the body of this function with a 7.4-compatible
	 * equivalent that reproduces fdiv's semantics:
	 *
	 *     if ( 0.0 === $b ) {
	 *         if ( 0.0 === $a ) {
	 *             return NAN;
	 *         }
	 *         return ( $a > 0.0 ) ? INF : -INF;
	 *     }
	 *     return $a / $b;
	 *
	 * After the fix, verify on the broken cell with:
	 *
	 *     ./test.sh --php=7.4 --wp=6.7 --db=mysql:8.0
	 *
	 * -------------------------------------------------------------------
	 *
	 * @param float $a Numerator.
	 * @param float $b Denominator.
	 * @return float
	 */
	public static function safe_divide( $a, $b ) {
		$a = (float) $a;
		$b = (float) $b;
		if ( 0.0 === $b ) {
			if ( 0.0 === $a ) {
				return NAN;
			}
			return ( $a > 0.0 ) ? INF : -INF;
		}
		return $a / $b;
	}
}

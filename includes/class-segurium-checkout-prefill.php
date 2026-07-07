<?php
/**
 * Freemius checkout prefill (SEGURIUM-447 Tier 1).
 *
 * Hooks into Freemius's `pricing_url` and `checkout_url` filters and
 * appends `user_email`, `user_firstname`, `user_lastname` from the
 * current WP user. Those land in $_GET when the pricing / checkout
 * pages load and FS_Checkout_Manager::get_query_params() forwards $_GET
 * into the iframe URL it builds for the Freemius checkout server.
 *
 * Tier 1 is UX-only — the buyer can edit any field at checkout, and we
 * never trust these values for license binding. Tier 2 (server-side
 * `user_token` for tamper-proof binding) plugs in here by replacing the
 * URL params with a freshly minted token.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the Freemius URL filters that prefill the buyer's identity.
 */
final class Segurium_Checkout_Prefill {

	/**
	 * Wire the Freemius filters. Called once during plugin init.
	 *
	 * Filter names follow Freemius's `fs_<tag>_<unique_affix>` convention
	 * (see fs_apply_filter() in plugin/vendor/freemius/includes/fs-core-functions.php).
	 */
	public static function register_hooks() {
		add_filter( 'fs_pricing_url_segurium', array( __CLASS__, 'append_user_data' ) );
		add_filter( 'fs_checkout_url_segurium', array( __CLASS__, 'append_user_data' ) );
	}

	/**
	 * Append `user_email`, `user_firstname`, `user_lastname` query
	 * params to a Freemius URL based on the current WP user. Empty
	 * fields are skipped — only what the WP user record actually has.
	 *
	 * @param mixed $url Filter input from Freemius.
	 * @return mixed Filtered URL (or the original input when there's no
	 *               logged-in user / the URL isn't a non-empty string).
	 */
	public static function append_user_data( $url ) {
		if ( ! is_string( $url ) || '' === $url ) {
			return $url;
		}

		$user = wp_get_current_user();
		if ( 0 === (int) $user->ID ) {
			return $url;
		}

		$params = array();
		if ( ! empty( $user->user_email ) ) {
			$params['user_email'] = $user->user_email;
		}
		if ( ! empty( $user->user_firstname ) ) {
			$params['user_firstname'] = $user->user_firstname;
		}
		if ( ! empty( $user->user_lastname ) ) {
			$params['user_lastname'] = $user->user_lastname;
		}

		return add_query_arg( $params, $url );
	}
}

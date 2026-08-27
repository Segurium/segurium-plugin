<?php
/**
 * WP-CLI `wp segurium iid ...` commands.
 *
 * Split out of class-segurium-cli.php so each file holds a single class
 * (Generic.Files.OneObjectStructurePerFile).
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * `wp segurium iid ...` — installation-identity recovery commands.
 */
class Segurium_CLI_Iid {

	/**
	 * Reset the installation identity and arm a deferred re-register.
	 *
	 * Drops the IID token, the cached quota envelope (so any local Pro
	 * tier collapses to Free until a Freemius webhook re-binds against
	 * the new IID, or the user re-activates the license and the
	 * sync runs), and any pending billing-conflict banner.
	 * Sets the re-register pending flag so the next
	 * `admin_init` (subject to the External Service Disclosure consent
	 * gate) re-registers a fresh IID with CTI.
	 *
	 * Use this as the operator escape hatch when an install ends up in
	 * a stuck identity state that the automatic 409 → admin_init flow
	 * has not resolved on its own.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium iid reset
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args (unused).
	 */
	public function reset( $args, $assoc_args ) {
		unset( $args, $assoc_args );

		$summary = Segurium_IID::reset_for_recovery();

		WP_CLI::log( 'iid_cleared:              ' . ( $summary['iid_cleared'] ? 'yes' : 'no (was already empty)' ) );
		WP_CLI::log( 'quota_envelope_cleared:   ' . ( $summary['quota_envelope_cleared'] ? 'yes' : 'no (none cached)' ) );
		WP_CLI::log( 'billing_conflict_cleared: ' . ( $summary['billing_conflict_cleared'] ? 'yes' : 'no (none pending)' ) );
		WP_CLI::log( 'reregister_armed:         ' . ( $summary['reregister_armed'] ? 'yes' : 'no' ) );

		WP_CLI::success(
			'IID reset. The next admin page load will re-register with Segurium Cloud '
			. '(consent permitting). If you have a Pro license, re-activate it '
			. 'on the Segurium account screen so Pro features are restored.'
		);
	}
}

WP_CLI::add_command( 'segurium iid', 'Segurium_CLI_Iid' );

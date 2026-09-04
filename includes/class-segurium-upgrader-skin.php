<?php
/**
 * Upgrader skin that keeps the WP_Error core failed with.
 *
 * `WP_Upgrader::run()` hands the error to the skin and then returns the
 * still-empty `$result` property, so `Plugin_Upgrader::upgrade()` answers a
 * caller with an empty array and no code. Recording the error here is the
 * only way to report what core actually refused on.
 *
 * The parent class lives in wp-admin/includes/class-wp-upgrader.php, so this
 * file is required on demand rather than at plugin load.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Automatic_Upgrader_Skin' ) ) {
	return;
}

/**
 * Silent upgrader skin that remembers the failure.
 */
class Segurium_Upgrader_Skin extends Automatic_Upgrader_Skin {

	/**
	 * The error core reported, if any.
	 *
	 * @var WP_Error|null
	 */
	public $segurium_error = null;

	/**
	 * Record the failure before letting the parent format it.
	 *
	 * @param string|WP_Error $errors Error to report.
	 * @return void
	 */
	public function error( $errors ) {
		if ( is_wp_error( $errors ) && $errors->has_errors() && null === $this->segurium_error ) {
			$this->segurium_error = $errors;
		}
		parent::error( $errors );
	}
}

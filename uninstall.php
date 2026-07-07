<?php
/**
 * Plugin uninstall hook.
 *
 * @package Segurium
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// WP loads uninstall.php as a standalone entry point — segurium.php
// never runs here, so anything segurium needs at uninstall time has
// to be required explicitly.
require_once __DIR__ . '/includes/segurium-uninstall-functions.php';

$segurium_upload_dir = wp_upload_dir();
if ( ! empty( $segurium_upload_dir['basedir'] ) ) {
	segurium_remove_data_dir( $segurium_upload_dir['basedir'] . '/segurium-data' );
}
segurium_delete_options();

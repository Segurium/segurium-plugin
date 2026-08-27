<?php
/**
 * Centralized debug / error logging.
 *
 * Single chokepoint for error_log() so the
 * WordPress.PHP.DevelopmentFunctions.error_log_error_log suppression lives in
 * exactly one place instead of being repeated at every call site. This is a
 * behavior-preserving wrapper: messages are written to the PHP error log
 * exactly as a direct error_log() call would.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin static wrapper around error_log().
 */
class Segurium_Debug {

	/**
	 * Write a message to the PHP error log.
	 *
	 * @param string $message Already-formatted log line.
	 * @return void
	 */
	public static function log( $message ) {
		error_log( (string) $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- centralized log chokepoint; the only sanctioned error_log() in the plugin.
	}
}

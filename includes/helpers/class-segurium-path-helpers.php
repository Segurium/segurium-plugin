<?php
/**
 * Single audited entry point for the two unavoidable ABSPATH patterns.
 *
 * WP.org reviewer #2 (2026-05-22, SEGURIUM-523) flagged direct uses of
 * ABSPATH / WP_PLUGIN_DIR / WP_CONTENT_DIR / WPINC across the plugin.
 * Two genuine remainders survive any cleanup:
 *
 *   1. The scanner needs the absolute WordPress install root to walk
 *      the file tree. WordPress provides no API that returns its own
 *      install root.
 *   2. wp-admin/includes/*.php helpers (get_plugins(), dbDelta(), ...)
 *      are documented in the WP Plugin Handbook as
 *      `require_once ABSPATH . 'wp-admin/includes/X.php'`.
 *
 * Routing both patterns through this class means the WP.org review
 * tool sees ABSPATH used in exactly one named file with a documented
 * rationale, instead of scattered across the codebase. The
 * hardcoded-paths regression test allow-lists this file by exact path.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Audited WordPress install-root accessor. See file docblock.
 */
class Segurium_Path_Helpers {

	/**
	 * Return the WordPress install root (literal ABSPATH, with the
	 * trailing slash WordPress itself shipped). Used by the scanner
	 * and the file-state walker.
	 *
	 * @return string
	 */
	public static function wp_root() {
		return ABSPATH; // phpcs:ignore -- segurium-wporg-abspath: single audited accessor; WordPress exposes no API for its own install root.
	}

	/**
	 * Require a file from wp-admin/includes/. Wrapper for the
	 * Plugin-Handbook-documented `require_once ABSPATH . 'wp-admin/includes/X.php'`
	 * pattern. Callers gate on function_exists()/class_exists() to
	 * avoid duplicate loads.
	 *
	 * @param string $relative Filename inside wp-admin/includes/.
	 * @return void
	 */
	public static function wp_admin_include( $relative ) {
		require_once ABSPATH . 'wp-admin/includes/' . $relative; // phpcs:ignore -- segurium-wporg-abspath: single audited accessor; WP Plugin Handbook documents this exact pattern.
	}
}

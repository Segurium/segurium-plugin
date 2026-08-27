<?php
/**
 * Segurium admin-menu shell.
 *
 * On /wp-admin/* pages that aren't Segurium pages
 * (admin_other tier) we don't load the full plugin. We still need the
 * Segurium menu visible in the WP sidebar and the dashboard widget
 * available on the Dashboard. This file registers those hooks with
 * lazy-load callbacks: when the user actually clicks the menu /
 * renders the widget, we promote the request to the full plugin.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Register the admin-menu and dashboard-widget hooks for the lightweight
 * admin tier. Idempotent (registered hooks are deduped by WP).
 */
function segurium_admin_menu_shell_register() {
	add_action( 'admin_menu', 'segurium_admin_menu_shell_add_menu' );
	add_action( 'wp_dashboard_setup', 'segurium_admin_menu_shell_add_widget' );
	// Same heartbeat throttle that the full plugin sets,
	// applied here so admin pages outside Segurium also get the 60 s
	// ceiling when Segurium is active.
	add_filter( 'heartbeat_settings', 'segurium_admin_menu_shell_throttle_heartbeat' );
}

/**
 * Admin_menu callback: register the top-level Segurium menu. Render
 * handler lazy-loads the full plugin only when the user opens it.
 */
function segurium_admin_menu_shell_add_menu() {
	add_menu_page(
		__( 'Segurium', 'segurium' ),
		__( 'Segurium', 'segurium' ),
		'manage_options',
		'segurium',
		'segurium_admin_menu_shell_render_page',
		segurium_admin_menu_icon(),
		65
	);
}

/**
 * Build the admin-menu icon as a base64 SVG data URI. WP only applies
 * its admin-colour-scheme recolor filter to base64 data URIs (URL-loaded
 * SVGs render as plain `<img>` and keep their original colors at their
 * intrinsic size). Cached statically — `add_menu_page` fires once per
 * request, but the helper is also reused by the full-plugin tier.
 *
 * @return string `data:image/svg+xml;base64,...` URI.
 */
function segurium_admin_menu_icon() {
	static $uri = null;
	if ( null !== $uri ) {
		return $uri;
	}
	$path = SEGURIUM_PLUGIN_DIR . 'assets/img/brand/mark-mono.svg';
	if ( ! function_exists( 'WP_Filesystem' ) ) {
		// phpcs:ignore -- segurium-wporg-abspath: canonical WP bootstrap of the WP_Filesystem API; ABSPATH is the WP install root by definition.
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}
	global $wp_filesystem;
	$svg = '';
	if ( WP_Filesystem() && $wp_filesystem->exists( $path ) ) {
		$svg = (string) $wp_filesystem->get_contents( $path );
	}
	$uri = '' === $svg
		? 'dashicons-shield'
		: 'data:image/svg+xml;base64,' . base64_encode( $svg ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- inlining a static SVG into a data URI for the WP admin menu icon.
	return $uri;
}

/**
 * Lazy-load the full plugin and dispatch to the real renderer. Reached
 * only when the user is actually on /wp-admin/admin.php?page=segurium —
 * the request would already have classified as `admin_segurium` (the
 * classifier checks $_GET['page']), so the heavy bootstrap path runs.
 * This function exists as a safety net in case the lightweight tier
 * still ends up serving a Segurium page (e.g., when sub-page routing
 * passes a different page= value but the menu callback fires).
 */
function segurium_admin_menu_shell_render_page() {
	segurium_load_full_plugin();
	if ( class_exists( 'Segurium' ) && method_exists( 'Segurium', 'get_instance' ) ) {
		Segurium::get_instance()->render_admin_page();
	}
}

/**
 * Dashboard widget shell. Defers to the full Segurium class when the
 * widget actually renders — Dashboard hits are admin_other tier (page=
 * is empty), so without lazy-load this widget would be invisible.
 */
function segurium_admin_menu_shell_add_widget() {
	wp_add_dashboard_widget(
		'segurium_widget',
		__( 'Segurium', 'segurium' ),
		'segurium_admin_menu_shell_render_widget'
	);
}

/**
 * Render the dashboard widget without loading the full plugin. Reads
 * the cached Self-Check result transient directly so /wp-admin/
 * (which is admin_other tier and renders every dashboard widget on
 * every visit) doesn't pay the cost of bootstrapping the 6.5k-LOC
 * Segurium class. Mirrors Segurium::render_dashboard_widget output.
 */
function segurium_admin_menu_shell_render_widget() {
	// Self_Check writes the cached result with key
	// `segurium_self_check_result` (see Segurium_Self_Check::CACHE_KEY).
	// Keep these in sync; if Self_Check changes its cache key the
	// widget will render the empty fallback.
	$result = get_transient( 'segurium_self_check_result' );

	if ( is_array( $result ) && isset( $result['grade'], $result['score'] ) ) {
		printf(
			'<p class="segurium-widget-score" data-grade="%1$s"><strong>%2$s</strong> %3$s <span class="segurium-widget-score-num">(%4$d/100)</span></p>',
			esc_attr( (string) $result['grade'] ),
			esc_html__( 'Security score:', 'segurium' ),
			esc_html( (string) $result['grade'] ),
			(int) $result['score']
		);
		if ( ! empty( $result['scanned_at'] ) ) {
			printf(
				'<p><small>%s</small></p>',
				esc_html(
					sprintf(
						/* translators: %s: human-readable time difference */
						__( 'Last checked %s ago.', 'segurium' ),
						human_time_diff( (int) $result['scanned_at'], time() )
					)
				)
			);
		}
	} else {
		echo '<p>' . esc_html__( 'Run a Self-Check from the Segurium admin page to see your security score.', 'segurium' ) . '</p>';
	}

	printf(
		'<p><a class="button" href="%1$s">%2$s</a></p>',
		esc_url( admin_url( 'admin.php?page=segurium' ) ),
		esc_html__( 'Open Segurium', 'segurium' )
	);
}

/**
 * Throttle WP Heartbeat to 60 s on admin pages. Mirrors the filter
 * registered by the full Segurium class so admin_other tier doesn't
 * regress its idle-load reduction.
 *
 * @param array $settings Heartbeat settings.
 * @return array
 */
function segurium_admin_menu_shell_throttle_heartbeat( $settings ) {
	if ( ! is_array( $settings ) ) {
		return $settings;
	}
	$settings['interval'] = 60;
	return $settings;
}

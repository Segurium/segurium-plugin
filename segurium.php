<?php
/**
 * Plugin Name: Segurium – Free Malware Removal & Auto Cleanup for Hacked Websites, Antivirus Scanner, Vulnerability Alerts
 * Plugin URI:  https://segurium.com
 * Description: Website hacked? Free malware removal and auto cleanup on every site you run, plus vulnerability alerts, firewall and 2FA. Same setup everywhere.
 * Version:     1.4.3
 * Author:      Segurium
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: segurium
 * Domain Path: /languages
 * Requires at least: 6.2
 * Requires PHP: 7.4
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SEGURIUM_VERSION', '1.4.3' );
define( 'SEGURIUM_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'SEGURIUM_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'SEGURIUM_PLUGIN_FILE', __FILE__ );

if ( ! defined( 'SEGURIUM_FS_PRODUCT_ID' ) ) {
	define( 'SEGURIUM_FS_PRODUCT_ID', '26814' );
}
if ( ! defined( 'SEGURIUM_FS_PUBLIC_KEY' ) ) {
	define( 'SEGURIUM_FS_PUBLIC_KEY', 'pk_4d5db65ea2aac519d7e38a8535281' );
}
if ( ! defined( 'SEGURIUM_FS_SLUG' ) ) {
	define( 'SEGURIUM_FS_SLUG', 'segurium' );
}

/*
 * Hard requirements gate. Runs BEFORE any require_once because some included
 * files use PHP 7.4+ syntax (numeric literal separators, etc.) that would
 * trigger a parse error on older PHP — which fires before WordPress can call
 * the activation hook, so the user would see a raw PHP fatal instead of a
 * friendly message. segurium_check_requirements() is hoisted at parse time
 * even though declared further down in this file.
 */
$segurium_bootstrap_error = segurium_check_requirements( PHP_VERSION, get_bloginfo( 'version' ) );
if ( null !== $segurium_bootstrap_error ) {
	wp_die(
		esc_html( $segurium_bootstrap_error ),
		esc_html__( 'Plugin Activation Error', 'segurium' ),
		array( 'back_link' => true )
	);
}
unset( $segurium_bootstrap_error );

/**
 * Classify the current request into a bootstrap tier.
 *
 * Every active plugin pays the cost of its `require_once`
 * graph + every `add_action` registered at file-load time. Most Segurium
 * code paths only matter for a small subset of requests — admin UI on
 * /wp-admin/, AJAX handlers when the action is ours, brute-force on
 * wp-login.php, etc. We classify the request shape once here and only
 * load the slice each tier needs.
 *
 * Constants honoured by the classifier (callers can override for tests
 * or one-off debugging):
 *   - `SEGURIUM_TESTING`       — force `testing` (PHPUnit rig).
 *   - `SEGURIUM_FORCE_FULL`    — force `full` (debug shortcut).
 *
 * @return string One of testing|cli|cron|ajax_segurium|ajax_other|
 *                admin_segurium|admin_other|login|visitor.
 */
function segurium_request_tier() {
	// Routing-only classifier. Runs during plugin bootstrap
	// BEFORE WordPress has loaded the nonce verification context, before
	// any user identity exists, and before request sanitisation. Its
	// only job is to decide which slice of the plugin to load — values
	// are never trusted, never written, never echoed.

	static $tier = null;
	if ( null !== $tier ) {
		return $tier;
	}

	if ( defined( 'SEGURIUM_TESTING' ) && SEGURIUM_TESTING ) {
		$tier = 'testing';
		return $tier;
	}
	if ( defined( 'SEGURIUM_FORCE_FULL' ) && SEGURIUM_FORCE_FULL ) {
		$tier = 'full';
		return $tier;
	}
	// Benchmark / debug knob. Lets the memory-bench
	// harness drive each tier from inside a single WP-CLI process by
	// pinning the classifier to a chosen value. Allowed values match
	// segurium_tier_groups() keys; anything else is ignored.
	if ( defined( 'SEGURIUM_FORCE_TIER' ) ) {
		$forced  = (string) SEGURIUM_FORCE_TIER;
		$allowed = array(
			'visitor',
			'login',
			'admin_other',
			'admin_segurium',
			'ajax_other',
			'ajax_segurium',
			'rest_segurium',
			'cron',
			'cli',
			'full',
			'testing',
		);
		if ( in_array( $forced, $allowed, true ) ) {
			$tier = $forced;
			return $tier;
		}
	}
	if ( defined( 'WP_CLI' ) && WP_CLI ) {
		$tier = 'cli';
		return $tier;
	}
	if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
		$tier = 'cron';
		return $tier;
	}

	// REST requests targeting /wp-json/segurium/v1/* (or
	// the rest_route fallback) need the full plugin loaded so the scan
	// runner is available to the route handler. is_admin() is false and
	// DOING_AJAX is unset on these requests, so without this branch they
	// would classify as `visitor` and load only the firewall slice.
	$rest_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-auth request router selecting the include-group to load; runs before WP auth/nonce context exists, reads no nonce-protected action, mutates nothing, emits nothing.
	if ( '' !== $rest_uri ) {
		if ( false !== strpos( $rest_uri, '/wp-json/segurium/' )
			|| false !== strpos( $rest_uri, 'rest_route=/segurium/' )
			|| false !== strpos( $rest_uri, 'rest_route=%2Fsegurium%2F' ) ) {
			$tier = 'rest_segurium';
			return $tier;
		}
	}

	$is_ajax = ( defined( 'DOING_AJAX' ) && DOING_AJAX );
	if ( $is_ajax ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-auth request router selecting the include-group to load; runs before WP auth/nonce context exists, reads no nonce-protected action, mutates nothing, emits nothing.
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-auth request router selecting the include-group to load; runs before WP auth/nonce context exists, reads no nonce-protected action, mutates nothing, emits nothing.
		$module_id = isset( $_REQUEST['module_id'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['module_id'] ) ) : '';
		$tier      = segurium_classify_ajax_action( $action, $module_id );
		return $tier;
	}

	// is_admin() is reliable here because admin-ajax + cron have already
	// short-circuited above; what's left for is_admin()=true is a real
	// /wp-admin/* page hit.
	if ( is_admin() ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-auth request router selecting the include-group to load; runs before WP auth/nonce context exists, reads no nonce-protected action, mutates nothing, emits nothing.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		$tier = ( 0 === strncmp( $page, 'segurium', 8 ) ) ? 'admin_segurium' : 'admin_other';
		return $tier;
	}

	$script = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';
	if ( '' !== $script && false !== strpos( $script, 'wp-login.php' ) ) {
		$tier = 'login';
		return $tier;
	}

	$tier = 'visitor';
	return $tier;
}

/**
 * Classify an AJAX request to either the heavy `ajax_segurium` tier (which
 * loads the full plugin) or the lightweight `ajax_other` tier (firewall
 * only). Pure helper so the routing rule is unit-testable without having
 * to defeat the request-level memoisation on `segurium_request_tier()`.
 *
 * `segurium_*` actions are obviously ours. Freemius SDK actions are
 * shaped `fs_<tag>_<module_id>` and arrive with a `module_id` request
 * param. They are ours when the embedded `module_id` matches our product
 * ID — without this branch the Freemius pricing/license/opt-in/GDPR
 * handlers never bootstrap on admin-ajax.php and admin-ajax.php returns
 * its `wp_die('0', '', ['response' => 400])` fallthrough, which is what
 * users reported as the hung "Upgrade to Pro" pricing page.
 *
 * @param string $action    `$_REQUEST['action']` from admin-ajax.php.
 * @param string $module_id `$_REQUEST['module_id']`. May be empty.
 * @return string `ajax_segurium` or `ajax_other`.
 */
function segurium_classify_ajax_action( $action, $module_id ) {
	if ( 0 === strncmp( $action, 'segurium_', 9 ) ) {
		return 'ajax_segurium';
	}
	// Freemius's sticky-notice dismiss JS POSTs no
	// module_id, so the gate below misroutes it and the sticky
	// notice re-renders on every page load.
	if ( 0 === strncmp( $action, 'fs_dismiss_notice_action_', 25 ) ) {
		return 'ajax_segurium';
	}
	if (
		0 === strncmp( $action, 'fs_', 3 )
		&& '' !== $module_id
		&& defined( 'SEGURIUM_FS_PRODUCT_ID' )
		&& (string) SEGURIUM_FS_PRODUCT_ID === (string) $module_id
	) {
		return 'ajax_segurium';
	}
	return 'ajax_other';
}

/**
 * Decide whether the admin_other tier must still bootstrap the Freemius SDK
 * on the current request. The SDK registers a `plugin_action_links_<basename>`
 * filter (`_add_license_action_link`) that injects the canonical
 * "Activate License" row action on /wp-admin/plugins.php. Skipping
 * `segurium_fs()` on that page silently drops the only official entry point
 * a free-tier user has to apply a license key.
 *
 * Pure helper so the routing rule is unit-testable without forging
 * $_SERVER state inside PHPUnit.
 *
 * @param string $script_name `$_SERVER['SCRIPT_NAME']` for the request.
 * @return bool True when admin_other must call segurium_fs().
 */
function segurium_admin_other_needs_fs( $script_name ) {
	if ( '' === $script_name ) {
		return false;
	}
	return 'plugins.php' === basename( $script_name );
}

/**
 * Decide whether the admin_other tier must load the exit-reason ask on
 * the current request. It hangs off the Deactivate row action, which
 * only exists on the plugins screen.
 *
 * Network deactivation is excluded: it acts on every site at once, so a
 * single operator's reason would speak for a whole fleet. The network
 * screen shares this basename, hence the directory test.
 *
 * Pure helper so the routing rule is unit-testable without forging
 * $_SERVER state inside PHPUnit.
 *
 * @param string $script_name `$_SERVER['SCRIPT_NAME']` for the request.
 * @return bool True when admin_other must wire the exit ask.
 */
function segurium_admin_other_needs_deactivation_ask( $script_name ) {
	if ( '' === $script_name || 'plugins.php' !== basename( $script_name ) ) {
		return false;
	}

	return 'network' !== basename( dirname( $script_name ) );
}

/**
 * Whether this request is the MainWP dashboard call the child bridge
 * answers.
 *
 * Cheap shape check, run on every light-tier request: the signature must
 * be present, the operation must be the one MainWP call we serve, and the
 * request must name a Segurium action. That last condition keeps every
 * other MainWP extension's `extra_execution` traffic clear of us.
 *
 * Nothing here is authenticated — it cannot be, because MainWP verifies
 * the signature later on `init`. It only decides whether to require one
 * class; see {@see segurium_maybe_register_mainwp_bridge()}. The caller
 * pairs it with {@see segurium_mainwp_child_active()}, kept separate so
 * that option read is short-circuited away on every request failing the
 * shape check here.
 *
 * Pure helper so the rule is unit-testable without forging $_POST inside
 * PHPUnit.
 *
 * @param string $signature  `$_POST['mainwpsignature']` for the request.
 * @param string $operation  `$_POST['function']` for the request.
 * @param bool   $has_action Whether `$_POST['segurium_action']` is present.
 * @return bool True when this has the shape of a bridge call.
 */
function segurium_is_mainwp_bridge_request( $signature, $operation, $has_action ) {
	if ( '' === (string) $signature ) {
		return false;
	}
	if ( 'extra_execution' !== (string) $operation ) {
		return false;
	}
	return (bool) $has_action;
}

/**
 * Register the MainWP child bridge on a light tier.
 *
 * MainWP posts to the child's `admin-ajax.php` with `function=` and no
 * `action=`, so a fleet request classifies as `ajax_other` — the firewall
 * slice, which loads none of the scan runner, quota gate or integrity
 * state the bridge reads. Verified on the DDEV MainWP rig: without this
 * the child answers normally with no `segurium` key, and the dashboard
 * reports `bridge_absent` — indistinguishable from Segurium being too old
 * to answer. PHPUnit cannot catch it, because the harness runs in the
 * `testing` tier, which loads everything.
 *
 * The fix is deliberately not a new heavy tier. The classifier runs
 * before MainWP Child verifies the request signature on `init`, and
 * before the firewall runs on `plugins_loaded`, so promoting on the
 * request's shape alone would let an unauthenticated
 * `curl -d 'mainwpsignature=x&function=extra_execution'` buy the whole
 * include graph on every MainWP-managed site. Instead we require only
 * this one small class and attach the filter. MainWP fires that filter
 * only after it has verified the signature and set an administrator, and
 * `Segurium_MainWP_Bridge::handle()` loads the rest of the plugin at that
 * point. A forged POST is rejected by MainWP before the filter ever runs,
 * so it pays for one `require_once` and nothing else.
 *
 * @return void
 */
function segurium_maybe_register_mainwp_bridge() {
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Bootstrap-time shape check that decides only whether to require one class; MainWP Child verifies this request's own signature before the filter it registers can fire, and the values are never trusted, written or echoed.
	$signature = isset( $_POST['mainwpsignature'] ) ? sanitize_text_field( wp_unslash( $_POST['mainwpsignature'] ) ) : '';
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Bootstrap-time shape check that decides only whether to require one class; MainWP Child verifies this request's own signature before the filter it registers can fire, and the values are never trusted, written or echoed.
	$operation = isset( $_POST['function'] ) ? sanitize_text_field( wp_unslash( $_POST['function'] ) ) : '';
	// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Bootstrap-time shape check that decides only whether to require one class; MainWP Child verifies this request's own signature before the filter it registers can fire, and the values are never trusted, written or echoed.
	$has_action = isset( $_POST['segurium_action'] );

	if ( ! segurium_is_mainwp_bridge_request( $signature, $operation, $has_action ) ) {
		return;
	}
	if ( ! segurium_mainwp_child_active() ) {
		return;
	}

	// The marker is deliberately not required here. `handle()` loads the
	// full include graph before it dispatches, so the marker arrives with
	// it — after MainWP has authenticated the caller, which is the whole
	// point of the lazy path.
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-mainwp-bridge.php';
	Segurium_MainWP_Bridge::register();
}

/**
 * Whether MainWP Child is active on this site.
 *
 * `MAINWP_CHILD_PLUGIN_DIR` is not enough on its own: plugins load in
 * activation order, so on a site where Segurium activated first the
 * constant does not exist yet when the tier classifier runs. Falling
 * back to the active-plugin list settles it either way, and
 * `active_plugins` is autoloaded so the lookup costs nothing. Matching
 * on the file's basename rather than the full path survives a renamed
 * plugin folder.
 *
 * @return bool
 */
function segurium_mainwp_child_active() {
	if ( defined( 'MAINWP_CHILD_PLUGIN_DIR' ) ) {
		return true;
	}

	$active = get_option( 'active_plugins', array() ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found -- WordPress core option read during bootstrap, before the storage facade is available.
	if ( is_array( $active ) ) {
		foreach ( $active as $segurium_plugin_file ) {
			if ( 'mainwp-child.php' === basename( (string) $segurium_plugin_file ) ) {
				return true;
			}
		}
	}

	if ( is_multisite() ) {
		$network = get_site_option( 'active_sitewide_plugins', array() );
		if ( is_array( $network ) ) {
			foreach ( array_keys( $network ) as $segurium_plugin_file ) {
				if ( 'mainwp-child.php' === basename( (string) $segurium_plugin_file ) ) {
					return true;
				}
			}
		}
	}

	return false;
}

/**
 * Tier → include group composition. Each group is an ordered list of
 * include files relative to SEGURIUM_PLUGIN_DIR. Storage is implicit and
 * loaded before any tier-specific group.
 *
 * @param string $tier Tier name from segurium_request_tier().
 * @return array<int,string>|null List of relative include paths to load,
 *                                or null when the tier loads the full plugin.
 */
function segurium_tier_groups( $tier ) {
	$firewall_group        = array(
		'includes/class-segurium-cloudflare-ranges.php',
		'includes/class-segurium-trusted-proxies.php',
		'includes/class-segurium-pending-changes.php',
		'includes/class-segurium-firewall-rules.php',
		'includes/class-segurium-geo-db.php',
		'includes/class-segurium-geo-updater.php',
		'includes/class-segurium-geo-blocker.php',
	);
	$login_group           = array(
		'includes/class-segurium-brute-force.php',
		'includes/class-segurium-2fa-crypto.php',
		'includes/class-segurium-qr-svg.php',
		'includes/class-segurium-2fa.php',
	);
	$visitor_headers_group = array(
		'includes/class-segurium-security-headers.php',
		'includes/class-segurium-info-shield.php',
		'includes/class-segurium-self-check.php',
	);
	$admin_shell_group     = array(
		// Read-only on this tier: the sidebar icon needs the stored
		// open-issue flags, and neither counter class is loaded here.
		'includes/class-segurium-issue-indicator.php',
		'includes/segurium-admin-menu-shell.php',
	);
	// Account registration is a front-end action on any store or
	// membership site, and plugin activation happens on plugins.php,
	// which carries no `page=segurium`. Neither lands on a heavy tier,
	// so the tracker has to be present on all four light ones. Its
	// listeners only write to the local activity_log; the flush runs
	// from cron and from admin_init.
	$activity_group = array(
		'includes/class-segurium-activity-tracker.php',
	);

	switch ( $tier ) {
		case 'visitor':
			return array_merge( $firewall_group, $visitor_headers_group, $activity_group );
		case 'ajax_other':
			// Firewall + geo-block must run on every reachable WP entry
			// point — admin-ajax is reachable, including unauthenticated
			// (wp_ajax_nopriv_* handlers). Storage tier is loaded above;
			// add the firewall slice plus the activity tracker, since a
			// store's registration form posts here. No login/headers/
			// admin-shell classes — heartbeat and third-party AJAX don't
			// render UI.
			return array_merge( $firewall_group, $activity_group );
		case 'login':
			return array_merge( $firewall_group, $login_group, $visitor_headers_group, $activity_group );
		case 'admin_other':
			return array_merge( $firewall_group, $admin_shell_group, $activity_group );
		default:
			// testing / cli / cron / ajax_segurium / admin_segurium /
			// rest_segurium / full.
			return null;
	}
}

/**
 * Load the full plugin include graph (everything under includes/). Used
 * by the heavy tiers (testing/cli/cron/ajax_segurium/admin_segurium) and
 * by activation/deactivation hooks which need every class available.
 */
function segurium_load_full_plugin() {
	static $loaded = false;
	if ( $loaded ) {
		return;
	}
	$loaded = true;

	// IP-list cache class — lives next to the IP_List file. Heavy
	// tiers may need it (admin UIs reading the live cache, settings
	// pages purging it on save). Storage tier already loads its own
	// require, but full-load is idempotent: require_once is a no-op
	// the second time.
	require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-ip-list-cache.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/segurium-ajax-envelope.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-text-helpers.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-entitlements.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-pro-transition.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-license-vendor-error.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-license.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-license-menu.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-settings-profile.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-cli.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scanner.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-iid.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-alerts-settings.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-consent.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-auto-fix-settings.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-cti-signature.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-cti-client.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-quota.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-cloudflare-ranges.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-state-file.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-verdict-queue.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-async-scan-pause.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-async-scan-first-poll-eta.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-async-scan-submitter.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-async-scan-results-loop.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scan.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scan-lock.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scan-runner.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scan-trigger-auth.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-rest-scan-tick.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-rest-scan-spawn.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-component-updates.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-remote-action-paths.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-remote-actions.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-rest-actions-poke.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scheduled-scan-settings.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scheduled-scan.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-backup.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-upload-scan.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-realtime-scan.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-file-state.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-server-state.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-issue-indicator.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-ignore-lists.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-cleanup.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-auto-fix.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-review-prompt.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-paywall-telemetry.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-deactivation-reason.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-integrity.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-integrity-component-discovery.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-integrity-scan-state.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-integrity-server-state.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-integrity-inventory-cron.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-platform-snapshot.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-memory-recorder.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-activity-tracker.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-integrity-chain.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-component-backup.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-pending-changes.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-geo-db.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-geo-updater.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-trusted-proxies.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-firewall-rules.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-geo-blocker.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-brute-force.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-2fa-crypto.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-qr-svg.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-2fa.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-security-headers.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-info-shield.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-self-check.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-migration.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/migrations/class-segurium-migration-wordfence.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/migrations/class-segurium-migration-aios.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/migrations/class-segurium-migration-sucuri.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/migrations/class-segurium-migration-solid-security.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/segurium-admin-menu-shell.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-pricing.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-checkout-prefill.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-mainwp-bridge.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-mainwp-fleet-marker.php';
	require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium.php';

	$segurium_dev_bootstrap = SEGURIUM_PLUGIN_DIR . 'dev/bootstrap.php';
	if ( file_exists( $segurium_dev_bootstrap ) ) {
		require_once $segurium_dev_bootstrap;
	}
}

/**
 * Lazy bootstrap of the Freemius SDK. Returns the SDK instance, or null when
 * the SDK is not vendored / failed to initialize. Callers must NOT use this
 * directly for entitlement checks — go through Segurium_Entitlements::can()
 * so the rest of the plugin stays decoupled from the billing layer.
 *
 * @return Freemius|null
 */
function segurium_fs() {
	global $segurium_fs;
	if ( isset( $segurium_fs ) ) {
		return $segurium_fs;
	}
	$sdk_entry = SEGURIUM_PLUGIN_DIR . 'vendor/freemius/start.php';
	if ( ! file_exists( $sdk_entry ) ) {
		$segurium_fs = null;
		return null;
	}
	try {
		// Unconditional: start.php arbitrates newest-SDK-wins via
		// $fs_active_plugins. A class_exists guard would pin the site to an
		// older bundled copy.
		require_once $sdk_entry;
		$segurium_fs = fs_dynamic_init(
			array(
				'id'                  => SEGURIUM_FS_PRODUCT_ID,
				'slug'                => SEGURIUM_FS_SLUG,
				'type'                => 'plugin',
				'public_key'          => SEGURIUM_FS_PUBLIC_KEY,
				'is_premium'          => false,
				'has_premium_version' => false,
				'has_paid_plans'      => true,
				'is_org_compliant'    => true,
				'menu'                => array(
					'slug' => 'segurium',
				),
			)
		);
	} catch ( Throwable $e ) {
		Segurium_Debug::log(
			'[segurium] Freemius bootstrap failed: ' . $e->getMessage()
		);
		$segurium_fs = null;
	}
	return $segurium_fs;
}

// Single audited accessor for WordPress install-root paths.
// Loaded before the storage tier because storage's install_all() calls
// Segurium_Path_Helpers::wp_admin_include() to pull in dbDelta.
require_once SEGURIUM_PLUGIN_DIR . 'includes/helpers/class-segurium-path-helpers.php';

// Centralized debug/error-log chokepoint. Loaded before everything so any
// tier (storage, cron, activation) can route Segurium_Debug::log() through it.
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-debug.php';

// Centralized raw-filesystem chokepoint. Loaded before the storage tier so
// every layer routes raw file ops through Segurium_Fs.
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-fs.php';

// Storage tier is small and required by every other tier (firewall reads
// settings, scheduling reads ip lists, etc.). Always loaded.
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-exception.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-ip.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-settings.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-schema-registry.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-tables.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-tables-query.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-fs.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-crypto.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-tmp.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-backup.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-ip-list.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-ip-list-cache.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage-gc.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/storage/class-segurium-storage.php';

// The settings registry sits directly on top of storage and is read on every
// tier: the firewall, the geo blocker, the security headers and 2FA all resolve
// settings on a plain visitor request.
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-settings.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-scan-exclusions.php';

// The one save path. Loaded on every tier because an expired geo-blocking or
// firewall fuse reverts from a plain visitor request.
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-settings-writer.php';

// CTI access layer ships with storage: every lightweight tier funnels
// settings + security events through Segurium_Storage::cti_send_message,
// so loading storage without the CTI client fatals on first call.
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-iid.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-cti-signature.php';
require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-cti-client.php';

Segurium_Storage::boot();

// Carry a pre-registry site onto the `segurium_settings_*` layout before any
// feature reads a setting. Runs inline rather than on `plugins_loaded` so the
// order cannot depend on hook registration, and short-circuits on an autoloaded
// flag once the site is current.
Segurium_Settings::upgrade();

// integrity_issues stores a backup_id alongside each fixed file
// and the UI offers Restore for as long as that row exists, so rotation must
// never silently drop those envelopes. The byte cap is the meaningful limit;
// max_count is set high enough to never bind, and the pinned-ids provider
// teaches rotation about the rows that the UI is still referencing.
Segurium_Storage::backup_register_bucket(
	'integrity',
	array(
		'max_count'           => PHP_INT_MAX,
		'max_bytes'           => 200 * 1048576,
		'pinned_ids_provider' => static function () {
			$ids = Segurium_Storage::table_get_col(
				'integrity_issues',
				"SELECT DISTINCT backup_id FROM {{table}} WHERE backup_id IS NOT NULL AND backup_id <> ''",
				array()
			);
			return is_array( $ids ) ? $ids : array();
		},
	)
);
Segurium_Storage::backup_register_bucket(
	'malware',
	array(
		'max_count' => 200,
		'max_bytes' => 200 * 1048576,
	)
);
// Component backups (whole plugin/theme archives) are user-managed: no
// implicit rotation, so caps are set astronomically high. The 100 MB
// per-archive size gate lives in Segurium_Component_Backup, not here.
Segurium_Storage::backup_register_bucket(
	'component',
	array(
		'max_count' => 1000000,
		'max_bytes' => PHP_INT_MAX,
	)
);

/**
 * Self-heal schema drift introduced by in-place plugin updates.
 *
 * The register_activation_hook only fires on admin-triggered activation, so a
 * user who updates Segurium via the WordPress .org updater (the default path)
 * would otherwise never get newly-registered tables. Hooking on
 * plugins_loaded @ 0 gives us a fingerprint-cached check that runs cheaply on
 * every request and triggers dbDelta only when the registered schema set
 * changes.
 *
 * Schema drift can only legitimately occur after a plugin
 * update, which always lands through an admin or CLI request first.
 * Visitor / login / ajax_other / cron requests would just pay a DB
 * roundtrip per hit for nothing. We gate the fingerprint check to the
 * tiers that can actually trigger drift.
 */
$segurium_self_heal_tiers = array( 'testing', 'cli', 'cron', 'admin_segurium', 'admin_other', 'ajax_segurium', 'rest_segurium', 'full' );
if ( in_array( segurium_request_tier(), $segurium_self_heal_tiers, true ) ) {
	add_action(
		'plugins_loaded',
		static function () {
			try {
				Segurium_Storage::ensure_schema();
			} catch ( Throwable $e ) {
				Segurium_Debug::log(
					'[segurium] plugins_loaded ensure_schema failed: ' . $e->getMessage()
				);
			}
			segurium_migrate_scan_tick_cron_rescue();
			segurium_migrate_async_scan_retry_after_kv();
			segurium_migrate_drop_async_submit_deprecated_options();
			segurium_migrate_close_orphaned_scan_history();
		},
		0
	);
}
unset( $segurium_self_heal_tiers );

/**
 * One-shot close of scan_history rows orphaned at
 * status=running by a lock overwrite before this release. Runs
 * `Segurium_Scan_Runner::sweep_orphaned_history()` once per install and
 * stamps `segurium_migrated_871_orphan_sweep`; the hourly watchdog keeps
 * sweeping afterwards. Skipped on light tiers where the runner class is
 * not loaded — the next heavy request performs it.
 */
function segurium_migrate_close_orphaned_scan_history() {
	if ( ! class_exists( 'Segurium_Storage' ) || ! class_exists( 'Segurium_Scan_Runner' ) ) {
		return;
	}
	if ( Segurium_Storage::setting_get( 'segurium_migrated_871_orphan_sweep' ) ) {
		return;
	}
	try {
		if ( false !== Segurium_Scan_Runner::sweep_orphaned_history() ) {
			Segurium_Storage::setting_set( 'segurium_migrated_871_orphan_sweep', 1, false );
		}
	} catch ( Throwable $e ) {
		Segurium_Debug::log(
			'[segurium] orphaned scan_history sweep failed: ' . $e->getMessage()
		);
	}
}

/**
 * Drop any wp-cron events still scheduled under the legacy
 * `segurium_every_5_seconds` schedule. The recurring scan tick now runs at
 * 60 s under `segurium_every_60_seconds`; without this migration any scan
 * that started before the upgrade keeps firing the old 5-second beat
 * (WordPress reschedules using the saved schedule key, not the constant)
 * and races the chain's mutex on every release window. Idempotent: when
 * no legacy entries exist this is a single `_get_cron_array()` call.
 */
function segurium_migrate_scan_tick_cron_rescue() {
	if ( ! class_exists( 'Segurium_Scan_Runner' ) ) {
		return;
	}
	$legacy_schedule = Segurium_Scan_Runner::TICK_RECURRING_SCHEDULE_LEGACY;
	$tick_hook       = Segurium_Scan_Runner::TICK_HOOK;

	$crons = _get_cron_array();
	if ( ! is_array( $crons ) ) {
		return;
	}

	$dirty = false;
	foreach ( $crons as $timestamp => $hooks ) {
		if ( ! isset( $hooks[ $tick_hook ] ) || ! is_array( $hooks[ $tick_hook ] ) ) {
			continue;
		}
		foreach ( $hooks[ $tick_hook ] as $sig => $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry['schedule'] ) ) {
				continue;
			}
			if ( $legacy_schedule !== $entry['schedule'] ) {
				continue;
			}
			$args = isset( $entry['args'] ) && is_array( $entry['args'] ) ? $entry['args'] : array();
			wp_unschedule_event( (int) $timestamp, $tick_hook, $args );
			$dirty = true;
		}
	}

	if ( $dirty && Segurium_Scan_Lock::is_running() ) {
		wp_schedule_event(
			time(),
			Segurium_Scan_Runner::TICK_RECURRING_SCHEDULE,
			$tick_hook
		);
	}
}

/**
 * Drop legacy per-`scan_id` Retry-After rows from the
 * runtime_kv table. The old design stored the cross-tick deadline under
 * `async_scan:retry_after:<scan_id>`; the new design stamps an
 * IID-scoped transient instead (see {@see Segurium_Async_Scan_Pause}),
 * so the legacy rows are dead weight and confusing if left around.
 *
 * A `segurium_migrated_478_retry_after_kv` option short-circuits later
 * calls so we don't issue a DELETE on every plugins_loaded firing.
 */
function segurium_migrate_async_scan_retry_after_kv() {
	if ( ! class_exists( 'Segurium_Storage' ) ) {
		return;
	}
	if ( Segurium_Storage::setting_get( 'segurium_migrated_478_retry_after_kv' ) ) {
		return;
	}
	try {
		global $wpdb;
		$table = Segurium_Storage::table_name( 'runtime_kv' );
		if ( '' === $table ) {
			return;
		}
		$like = $wpdb->esc_like( 'async_scan:retry_after:' ) . '%';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE kv_key LIKE %s', $table, $like ) );
		Segurium_Storage::setting_set( 'segurium_migrated_478_retry_after_kv', 1, false );
	} catch ( Throwable $e ) {
		Segurium_Debug::log(
			'[segurium] async-scan retry-after kv migration failed: ' . $e->getMessage()
		);
	}
}

/**
 * Drop deprecated wp_options that belonged to the
 * abandoned v2 concurrent-submit design (curl_multi, max_in_flight).
 * The v3 pipeline replaces them with native
 * `wp_remote_post` + IID-scoped Retry-After transients, so the options
 * carry no signal — leaving stale values around would confuse anyone
 * reading wp_options.
 *
 * Idempotent via `segurium_migrated_482_deprecated_options`. The body
 * issues three `delete_option` calls — all no-ops on the common case
 * where the options were never set.
 */
function segurium_migrate_drop_async_submit_deprecated_options() {
	if ( Segurium_Storage::setting_get( 'segurium_migrated_482_deprecated_options' ) ) {
		return;
	}
	$deprecated = array(
		'segurium_scan_submit_max_in_flight',
		'segurium_scan_submit_drain_secs',
		'segurium_scan_submit_pause_floor_secs',
	);
	foreach ( $deprecated as $opt ) {
		Segurium_Storage::setting_delete( $opt );
	}
	Segurium_Storage::setting_set( 'segurium_migrated_482_deprecated_options', 1, false );
}

/**
 * Hide Freemius's auto-injected Contact / Affiliation / Add-Ons submenus
 * (none of which apply to Segurium). The Account submenu stays visible
 * so users can activate licenses, sync, and deactivate via the FS UI.
 *
 * The Upgrade submenu follows the cached cloud tier, not the SDK's own
 * license read: a purchase the cloud already bound while the SDK still
 * waits for the buyer's email would otherwise keep an Upgrade link in
 * the sidebar of a site that reads Plan: Pro. The pricing page stays
 * registered, only its menu entry and the plugins-list action link go.
 *
 * @param bool   $visible Default visibility.
 * @param string $id      Submenu identifier.
 * @return bool
 */
function segurium_hide_unused_freemius_submenus( $visible, $id ) {
	if ( in_array( $id, array( 'contact', 'affiliation', 'addons' ), true ) ) {
		return false;
	}
	if ( 'pricing' === $id
		&& class_exists( 'Segurium_Quota' )
		&& Segurium_Quota::PLAN_TIER_PRO === Segurium_Quota::plan_tier()
	) {
		return false;
	}
	return $visible;
}

/*
 * Tier dispatch. The classifier returns one of nine values; we either
 * load the full plugin or the slice the tier needs and register only
 * the hooks relevant to that tier.
 */
$segurium_tier   = segurium_request_tier();
$segurium_groups = segurium_tier_groups( $segurium_tier );

if ( null === $segurium_groups ) {
	// Heavy tier: full plugin (current behaviour). Keeps tests, CLI,
	// cron, and any actual Segurium AJAX/admin work fully wired.
	segurium_load_full_plugin();

	if ( 'testing' !== $segurium_tier ) {
		segurium_fs();
		do_action( 'segurium_fs_loaded' );

		add_action(
			'plugins_loaded',
			static function () {
				$fs = segurium_fs();
				if ( ! $fs ) {
					return;
				}
				if ( get_transient( 'segurium_fs_optin_intent' ) ) {
					return;
				}
				try {
					if ( $fs->is_registered() || $fs->is_anonymous() ) {
						return;
					}
					if ( method_exists( $fs, 'skip_connection' ) ) {
						$fs->skip_connection();
					}
				} catch ( Throwable $e ) {
					Segurium_Debug::log(
						'[segurium] auto-skip Freemius opt-in failed: ' . $e->getMessage()
					);
				}
			},
			20
		);
	}

	segurium_init();

	if (
		( ! defined( 'SEGURIUM_TESTING' ) || ! SEGURIUM_TESTING )
		&& class_exists( 'Segurium_Pro_Transition' )
		&& function_exists( 'segurium_fs' )
	) {
		Segurium_Pro_Transition::instance()->register_hooks();
	}

	if ( 'testing' !== $segurium_tier && is_admin() && class_exists( 'Segurium_License_Menu' ) ) {
		Segurium_License_Menu::instance()->register_hooks();
	}

	add_filter( 'fs_is_submenu_visible_segurium', 'segurium_hide_unused_freemius_submenus', 10, 2 );

	if ( class_exists( 'Segurium_Pricing' ) ) {
		Segurium_Pricing::register_hooks();
	}

	if ( class_exists( 'Segurium_Paywall_Telemetry' ) ) {
		Segurium_Paywall_Telemetry::register_hooks();
	}

	if ( class_exists( 'Segurium_Checkout_Prefill' ) ) {
		Segurium_Checkout_Prefill::register_hooks();
	}

	// Attaching this is inert on its own — the filter only
	// exists inside MainWP Child, so a site without it never fires.
	if ( class_exists( 'Segurium_MainWP_Bridge' ) ) {
		Segurium_MainWP_Bridge::register();
	}

	// The cron listener has to exist on every heavy tier, or
	// the queued fleet report fires into nothing.
	if ( class_exists( 'Segurium_MainWP_Fleet_Marker' ) ) {
		Segurium_MainWP_Fleet_Marker::register();
	}
} else {
	// Lightweight tier: load only the requested groups and register
	// only the hooks that tier needs.
	foreach ( $segurium_groups as $segurium_rel ) {
		require_once SEGURIUM_PLUGIN_DIR . $segurium_rel;
	}
	unset( $segurium_rel );
	segurium_lightweight_bootstrap( $segurium_tier );
	segurium_maybe_register_mainwp_bridge();
}

/**
 * Lightweight per-tier bootstrap. Only fires for visitor / login /
 * ajax_other / admin_other. Heavy tiers go through segurium_init().
 *
 * @param string $tier The classified request tier.
 */
function segurium_lightweight_bootstrap( $tier ) {
	// Firewall + geo-blocker must run on every reachable WP entry point
	// when enabled — visitor, login, admin_other, AND ajax_other (admin-ajax
	// is reachable, incl. wp_ajax_nopriv_*). The cached IP-list match is
	// ~0.02 ms per hit, well inside the TTFB budget for non-Segurium AJAX.
	add_action( 'plugins_loaded', array( Segurium_Geo_Blocker::get_instance(), 'maybe_block_by_firewall' ), 0 );
	add_action( 'plugins_loaded', array( Segurium_Geo_Blocker::get_instance(), 'maybe_block_request' ), 1 );
	// Register the firewall pending-revert handler on every
	// tier the firewall runs on, so check_expired() finds a listener even
	// when the heavy Segurium class is not loaded.
	Segurium_Firewall_Rules::register_hooks();
	Segurium_Activity_Tracker::register_hooks();

	if ( 'visitor' === $tier ) {
		Segurium_Security_Headers::get_instance()->init();
		Segurium_Info_Shield::get_instance()->init();
		return;
	}

	if ( 'login' === $tier ) {
		Segurium_Brute_Force::get_instance()->init();
		Segurium_2FA::get_instance()->init();
		Segurium_Security_Headers::get_instance()->init();
		Segurium_Info_Shield::get_instance()->init();
		// 2FA also has nopriv AJAX handlers (verify code on login). Those
		// won't fire on `login` tier itself but must be registered if the
		// admin-ajax POST happens — handled in ajax_segurium tier.
		return;
	}

	if ( 'admin_other' === $tier ) {
		// Register Segurium menu in the WP admin sidebar and the
		// dashboard widget without instantiating the full Segurium
		// class (which is 6.5k LOC and registers ~95 hooks).
		// Pro_Transition register_hooks pulls in the Freemius SDK as a
		// side-effect — defer it to the admin_segurium tier where the
		// Segurium UI is actually rendered.
		segurium_admin_menu_shell_register();

		// /wp-admin/plugins.php is admin_other but Freemius needs to be
		// alive there so its `plugin_action_links_<basename>` filter
		// injects the "Activate License" row action (the canonical
		// entry point for users with a license key). Bootstrap the SDK
		// only — full Segurium class graph stays unloaded.
		$segurium_script = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing only.
		if ( segurium_admin_other_needs_fs( $segurium_script ) ) {
			segurium_fs();
			require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-quota.php';
			require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-license-menu.php';
			Segurium_License_Menu::instance()->register_hooks();
		}

		// The exit ask hangs off the Deactivate row action on that same
		// screen. One small class, loaded only there — the answer itself
		// travels on admin-ajax, which runs the full graph anyway.
		if ( segurium_admin_other_needs_deactivation_ask( $segurium_script ) ) {
			require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-deactivation-reason.php';
			Segurium_Deactivation_Reason::register_hooks();
		}

		// 2FA hooks `show_user_profile` /
		// `edit_user_profile` (the per-user configurator on
		// /wp-admin/profile.php and user-edit.php) and `admin_notices`
		// (the enforcement banner on every admin screen). Those pages
		// don't carry `?page=segurium*`, so without a tier-local init
		// the configurator never renders and enforced users never see
		// the grace-period notice. Load the slice + run init() only
		// when the feature is on; init() short-circuits otherwise.
		// Stored row, not the merged read: this tier deliberately leaves the
		// 2FA class unloaded, so its default set cannot be resolved yet.
		$segurium_tfa_settings = Segurium_Settings::get_stored( '2fa' );
		if ( ! empty( $segurium_tfa_settings['enabled'] ) ) {
			require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-2fa-crypto.php';
			require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-qr-svg.php';
			require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-2fa.php';
			Segurium_2FA::get_instance()->init();
		}
		return;
	}

	// ajax_other: firewall is registered above. Nothing else loads —
	// heartbeat and third-party AJAX actions don't see any other Segurium
	// hooks, classes, or UI side-effects.
}

/**
 * Check if the server meets the minimum requirements.
 *
 * @param string $php_version Current PHP version.
 * @param string $wp_version  Current WordPress version.
 * @return string|null Error message or null if requirements are met.
 */
function segurium_check_requirements( $php_version, $wp_version ) {
	if ( version_compare( $php_version, '7.4', '<' ) ) {
		return sprintf(
			/* translators: 1: required PHP version, 2: detected PHP version */
			__( 'Segurium requires PHP %1$s or higher. This site is running PHP %2$s. Please ask your host to upgrade PHP, then try activating Segurium again.', 'segurium' ),
			'7.4',
			$php_version
		);
	}
	if ( version_compare( $wp_version, '6.0', '<' ) ) {
		return sprintf(
			/* translators: 1: required WordPress version, 2: detected WordPress version */
			__( 'Segurium requires WordPress %1$s or higher. This site is running WordPress %2$s. Please update WordPress, then try activating Segurium again.', 'segurium' ),
			'6.0',
			'' === $wp_version ? __( 'unknown', 'segurium' ) : $wp_version
		);
	}
	return null;
}

/**
 * Every recurring cron hook the plugin owns, mapped to the scheduler
 * that arms it.
 *
 * One declaration feeds both the re-arm helper and the light-tier
 * missing-hook check, so a newly-owned cron cannot reach the helper
 * without also reaching the check. Building the array resolves no
 * callable and loads no class, which is what lets the check run on a
 * tier where none of these classes exist.
 *
 * @return array<string, callable> Cron hook name => scheduler.
 */
function segurium_cron_schedulers() {
	return array(
		'segurium_storage_gc'                => array( 'Segurium_Storage_GC', 'schedule' ),
		'segurium_bf_prune'                  => array( 'Segurium_Brute_Force', 'schedule_prune' ),
		'segurium_daily_components_snapshot' => array( 'Segurium_Integrity_Inventory_Cron', 'schedule' ),
		'segurium_actions_poll'              => array( 'Segurium_Remote_Actions', 'schedule' ),
		'segurium_daily_platform_snapshot'   => array( 'Segurium_Platform_Snapshot', 'schedule' ),
		'segurium_daily_memory_sample'       => array( 'Segurium_Memory_Recorder', 'schedule' ),
		'segurium_daily_self_check'          => array( 'Segurium_Self_Check', 'schedule' ),
	);
}

/**
 * Names of the recurring cron hooks the plugin owns.
 *
 * @return string[] Cron hook names.
 */
function segurium_owned_cron_hooks() {
	return array_keys( segurium_cron_schedulers() );
}

/**
 * Tiers allowed to run the cron self-heal on `admin_init`.
 *
 * `admin_init` fires on `/wp-admin/*` and on admin-ajax.php alike, so an
 * ungated hook runs the self-heal on every heartbeat and third-party
 * AJAX call — the exact workload the `ajax_other` tier exists to keep
 * cheap. Only the two admin page tiers are listed. WP-CLI and wp-cron
 * never fire `admin_init` and so cannot heal at all: an update applied
 * over CLI heals on the operator's next admin page load.
 *
 * @return string[] Tier names.
 */
function segurium_cron_self_heal_tiers() {
	return array( 'testing', 'full', 'admin_segurium', 'admin_other' );
}

/**
 * Cron hooks the plugin owns that are not currently queued.
 *
 * `wp_next_scheduled()` reads the autoloaded `cron` option, so on the
 * healthy path this is seven in-memory array lookups and no query.
 *
 * @return string[] Missing hook names, empty when every hook is queued.
 */
function segurium_missing_cron_hooks() {
	$missing = array();
	foreach ( segurium_owned_cron_hooks() as $hook ) {
		if ( ! wp_next_scheduled( $hook ) ) {
			$missing[] = $hook;
		}
	}
	return $missing;
}

/**
 * Self-heal missing cron registrations without paying for the include
 * graph on the healthy path.
 *
 * Only a genuinely missing hook loads the full plugin — on `admin_other`
 * that is once per auto-update, not once per admin page load.
 *
 * A re-arm can fail for reasons no retry fixes: a cron manager filtering
 * `pre_schedule_event`, a read-only `cron` option. Each failure doubles
 * the retry window from an hour up to a day, so a site in that state
 * pays one graph load a day rather than one per admin request, and each
 * attempt logs the hooks that stayed unscheduled. A successful heal
 * clears the counter.
 */
function segurium_maybe_ensure_all_crons_scheduled() {
	if ( ! segurium_missing_cron_hooks() ) {
		return;
	}
	if ( get_transient( 'segurium_cron_heal_backoff' ) ) {
		return;
	}

	segurium_ensure_all_crons_scheduled();

	$still_missing = segurium_missing_cron_hooks();
	if ( ! $still_missing ) {
		Segurium_Storage::setting_delete( 'segurium_cron_heal_failures' );
		return;
	}

	$attempt = Segurium_Storage::setting_get_int( 'segurium_cron_heal_failures', 0 ) + 1;
	Segurium_Storage::setting_set( 'segurium_cron_heal_failures', $attempt, false );
	set_transient(
		'segurium_cron_heal_backoff',
		1,
		min( DAY_IN_SECONDS, HOUR_IN_SECONDS * ( 1 << min( $attempt - 1, 5 ) ) )
	);
	Segurium_Debug::log(
		'[segurium] cron self-heal attempt ' . $attempt . ' could not schedule: ' . implode( ', ', $still_missing )
	);
}

/**
 * Re-arm every recurring cron event the plugin owns.
 *
 * The `register_activation_hook` callback only fires on a manual
 * activate/deactivate cycle, never on auto-update. Installs that were
 * activated before a cron-emitting feature shipped, then auto-updated
 * past it, silently lose the cron registration. Reached from
 * `segurium_maybe_ensure_all_crons_scheduled()` on `admin_init` (and
 * directly from activation), which self-heals those installs on the
 * next admin page load.
 *
 * Each schedule() short-circuits via wp_next_scheduled(), so this is
 * effectively a handful of in-memory option reads when every hook is
 * already queued.
 */
function segurium_ensure_all_crons_scheduled() {
	segurium_load_full_plugin();

	foreach ( segurium_cron_schedulers() as $scheduler ) {
		call_user_func( $scheduler );
	}
}

if ( in_array( segurium_request_tier(), segurium_cron_self_heal_tiers(), true ) ) {
	add_action( 'admin_init', 'segurium_maybe_ensure_all_crons_scheduled' );
}

/**
 * Apply the wp-config consent constant on the first request that sees it.
 *
 * Registered on every tier, because an unattended rollout has no admin
 * page load to wait for and a fresh site may not tick cron for hours. The
 * two guards run before anything is loaded: sites that never define
 * `SEGURIUM_CTI_CONSENT` pay one `defined()`, and sites that do read an
 * autoloaded marker already in memory. Only a site that is both asking
 * and unstamped loads the include graph. The marker name is spelled out
 * rather than read off `Segurium_Consent::OPTION_CONSTANT_APPLIED`,
 * because the class this guard decides whether to load is where that
 * constant lives; a test pins the two together.
 */
function segurium_maybe_apply_consent_constant() {
	if ( ! defined( 'SEGURIUM_CTI_CONSENT' ) || ! SEGURIUM_CTI_CONSENT ) {
		return;
	}
	if ( Segurium_Storage::setting_get_bool( 'segurium_consent_constant_applied' ) ) {
		return;
	}

	segurium_load_full_plugin();

	try {
		Segurium_Consent::maybe_apply_constant();
	} catch ( Throwable $e ) {
		Segurium_Debug::log(
			'[segurium] wp-config consent could not be applied: ' . $e->getMessage()
		);
	}
}
add_action( 'init', 'segurium_maybe_apply_consent_constant' );

/**
 * Handle plugin activation.
 *
 * Runs in admin context (user clicks Activate Plugin) or via WP-CLI.
 * Lazy-load the full plugin first so every Segurium_* class is available
 * — activation only fires once, the cost doesn't matter.
 */
function segurium_activate() {
	$error = segurium_check_requirements( PHP_VERSION, get_bloginfo( 'version' ) );
	if ( $error ) {
		deactivate_plugins( plugin_basename( __FILE__ ) );
		wp_die(
			esc_html( $error ),
			esc_html__( 'Plugin Activation Error', 'segurium' ),
			array( 'back_link' => true )
		);
	}

	segurium_load_full_plugin();

	Segurium_Storage_Fs::ensure_layout();
	Segurium_Storage::table_install_all();
	Segurium_Brute_Force::create_tables();

	segurium_ensure_all_crons_scheduled();

	segurium_migrate_scan_tick_cron_rescue();

	// Stamp the install date so the review ask can tell a
	// week-old install from a five-minute-old one. Never overwrites.
	Segurium_Review_Prompt::record_first_activation();

	// No CTI traffic on this path. IID registration, geo DB /
	// trusted-proxies fetch, and the first plugin_activated message all
	// run after consent (see Segurium::ajax_accept_consent and
	// maybe_schedule_missing_data).
	//
	// A re-activation still has to be reported — consent and an IID are
	// already on record, and without this CTI only ever hears the
	// deactivation. It goes through cron rather than an inline
	// send_message: `blocking => false` does not make wp_remote_post
	// asynchronous (Requests calls curl_exec either way and only
	// discards the response), so an inline send would stall activation
	// for the connect timeout on a site that cannot reach CTI.
	if ( Segurium_Storage::setting_get_bool( 'segurium_cti_consent' )
		&& null !== Segurium_IID::get_iid()
		&& ! wp_next_scheduled( Segurium::ACTIVATED_PING_CRON_HOOK ) ) {
		wp_schedule_single_event( time(), Segurium::ACTIVATED_PING_CRON_HOOK );
	}
}
register_activation_hook( __FILE__, 'segurium_activate' );

/**
 * Handle plugin deactivation. Runs in admin context — full include graph
 * is needed for the uninstall side-effects.
 */
function segurium_deactivate() {
	segurium_load_full_plugin();

	// Only ping CTI on deactivation if the install has
	// previously consented and registered. Without an IID, send_message
	// is a no-op anyway (the IID gate in maybe_register short-circuits),
	// but skipping the call here keeps intent explicit and avoids
	// loading the CTI client class for no reason.
	if ( null !== Segurium_IID::get_iid() ) {
		$client = new Segurium_CTI_Client();
		$client->send_message( 'plugin_deactivated' );
	}

	Segurium_Realtime_Scan::unschedule();
	Segurium_Scheduled_Scan::unschedule();
	Segurium_Geo_Updater::unschedule_retry();
	Segurium_Trusted_Proxies::unschedule();
	Segurium_Brute_Force::unschedule_prune();
	Segurium_Storage_GC::unschedule();
	Segurium_Integrity_Inventory_Cron::unschedule();
	Segurium_Remote_Actions::unschedule();
	Segurium_Platform_Snapshot::unschedule();
	Segurium_Memory_Recorder::unschedule();
	Segurium_Self_Check::unschedule();
	Segurium_MainWP_Fleet_Marker::unschedule();
}
register_deactivation_hook( __FILE__, 'segurium_deactivate' );

/**
 * Initialize the plugin (heavy tiers only).
 *
 * @return Segurium
 */
function segurium_init() {
	return Segurium::get_instance();
}

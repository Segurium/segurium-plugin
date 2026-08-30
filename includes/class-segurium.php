<?php
/**
 * Main plugin class.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Segurium class.
 */
class Segurium {

	/**
	 * Cron hook used to register the installation identifier with CTI off
	 * the AJAX consent path. {@see Segurium_IID::register()} performs a
	 * 15-second blocking POST and must not stall the consent UI.
	 */
	const IID_REGISTER_CRON_HOOK = 'segurium_iid_register';

	/**
	 * Transient key + TTL (seconds) for the CTI health probe.
	 *
	 * The status indicator is informational; a stale read for up to 5
	 * minutes saves an outbound HTTP probe on every poll while still
	 * reflecting reachability changes within the same admin session.
	 */
	const CTI_HEALTH_CACHE_KEY = 'segurium_cti_health_cache';
	const CTI_HEALTH_CACHE_TTL = 300;

	/**
	 * Widest cleanup cap the at-limit card still draws as blocks. Past
	 * this the row stops reading as a count, and the counter line beside
	 * it carries the same two numbers anyway.
	 */
	const MAX_QUOTA_METER_SLOTS = 12;

	/**
	 * Singleton instance.
	 *
	 * @var Segurium|null
	 */
	private static $instance = null;

	/**
	 * Get singleton instance.
	 *
	 * @return Segurium
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widget' ) );
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		// Buffer admin notices on our page so they paint inside
		// the wrap on first hit. Without this, WP common.js moves notices to
		// the first <h1>/<h2> in .wrap on document.ready — which for us lives
		// inside a hidden feature panel — and the Freemius sticky notice
		// flashes for ~500 ms before vanishing.
		add_action( 'load-toplevel_page_segurium', array( $this, 'register_admin_notice_buffer' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
		// Throttle WP Heartbeat to its 60s ceiling on Segurium
		// admin pages. Most admins leave the Segurium tab open for hours; the
		// 15s default produces ~5,800 admin-ajax round-trips/day per parked
		// tab, each one bootstrapping WordPress.
		add_filter( 'heartbeat_settings', array( $this, 'throttle_heartbeat_settings' ) );
		// Every privileged Segurium AJAX action is registered
		// to ONE central dispatcher (ajax_dispatch). The dispatcher verifies
		// a CORE nonce (check_ajax_referer) + capability (current_user_can)
		// for the matched route before handing off to the per-action
		// handler. This is the dispatcher model used by Wordfence, Defender
		// and Sucuri, and the form the WP.org reviewer credits. The route
		// table (action => [nonce action, capability, handler]) lives in
		// ajax_routes(); the enforcement tripwire is
		// tests/wporg/test-wporg-ajax-nonce-and-cap.php.
		foreach ( array_keys( $this->ajax_routes() ) as $segurium_ajax_action ) {
			add_action( 'wp_ajax_' . $segurium_ajax_action, array( $this, 'ajax_dispatch' ) );
		}

		// 2FA login flow runs BEFORE a WordPress user identity exists, so it
		// cannot pass the dispatcher's capability gate. These pre-login
		// actions — and their authenticated twins, used when a user has
		// passed the password step but not yet the second factor — are
		// registered directly and own their own verification, exactly as
		// Wordfence's login-security dispatcher exempts its no-permission
		// actions.
		$tfa = Segurium_2FA::get_instance();
		add_action( 'wp_ajax_nopriv_segurium_2fa_authenticate', array( $tfa, 'ajax_authenticate' ) );
		add_action( 'wp_ajax_nopriv_segurium_2fa_verify', array( $tfa, 'ajax_verify' ) );
		add_action( 'wp_ajax_nopriv_segurium_2fa_resend', array( $tfa, 'ajax_resend_email' ) );
		add_action( 'wp_ajax_segurium_2fa_authenticate', array( $tfa, 'ajax_authenticate' ) );
		add_action( 'wp_ajax_segurium_2fa_verify', array( $tfa, 'ajax_verify' ) );
		add_action( 'wp_ajax_segurium_2fa_resend', array( $tfa, 'ajax_resend_email' ) );

		// Handler lives on Segurium_Firewall_Rules (firewall
		// include group) so it is registered on lightweight tiers too.
		Segurium_Firewall_Rules::register_hooks();

		add_action( 'plugins_loaded', array( Segurium_Geo_Blocker::get_instance(), 'maybe_block_by_firewall' ), 0 );
		add_action( 'plugins_loaded', array( Segurium_Geo_Blocker::get_instance(), 'maybe_block_request' ), 1 );
		Segurium_Brute_Force::get_instance()->init();
		Segurium_2FA::get_instance()->init();
		Segurium_Security_Headers::get_instance()->init();
		Segurium_Info_Shield::get_instance()->init();
		add_action( Segurium_Pending_Changes::CRON_HOOK, array( 'Segurium_Pending_Changes', 'expire_pending' ) );
		add_action( Segurium_Geo_Updater::CRON_HOOK, array( $this, 'run_geo_db_update' ) );
		add_action( Segurium_Geo_Updater::RETRY_CRON_HOOK, array( $this, 'run_geo_db_update' ) );
		Segurium_Geo_Updater::schedule();
		add_action( Segurium_Trusted_Proxies::CRON_HOOK, array( 'Segurium_Trusted_Proxies', 'fetch' ) );
		Segurium_Trusted_Proxies::schedule();
		add_action( self::IID_REGISTER_CRON_HOOK, array( 'Segurium_IID', 'maybe_register' ) );
		// Drain the deferred re-register flag set by the CTI
		// 409 `re_register` short-circuit. admin_init runs on every admin
		// page load — the first one after a clone-bounce re-registers and
		// clears the flag.
		add_action( 'admin_init', array( 'Segurium_IID', 'process_pending_reregister' ) );
		add_action( 'admin_notices', array( 'Segurium_IID', 'render_reregister_notice' ) );
		// Surfaces a license-side recovery prompt when a
		// `/v1/billing/sync` call is rejected with HTTP 409
		// `binding_conflict`. The flag is armed by the sync caller and
		// cleared either by a successful sync, by `wp segurium iid reset`,
		// or by `Segurium_IID::clear_billing_conflict_pending()` directly.
		add_action( 'admin_notices', array( 'Segurium_IID', 'render_billing_conflict_notice' ) );
		// SWR refresh of the Free-tier quota readout. The
		// AJAX poll serves the cached envelope and queues this hook;
		// wp-cron runs it in a separate loopback request, so the user's
		// browser never waits on the CTI hop.
		add_action(
			Segurium_Quota::CRON_REFRESH_HOOK,
			static function () {
				Segurium_Quota::instance()->refresh();
			}
		);
		add_action( 'init', array( $this, 'maybe_schedule_missing_data' ) );

		if ( Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			add_filter( 'wp_handle_upload', array( $this, 'filter_upload' ) );
			add_action( Segurium_Realtime_Scan::CRON_HOOK, array( $this, 'run_realtime_scan' ) );
			Segurium_Realtime_Scan::schedule();

			// Phase B (`/v1/scan/results`) now runs in
			// the scan-runner tick, not on WP-Cron. The only hook
			// registered here is the one-shot migration that
			// unschedules the retired cron event.
			Segurium_Async_Scan_Results_Loop::register_hooks();

			// Bind the first-poll ETA stamper to the
			// submitter's first-success hook so Phase B's first-poll
			// gate has a deadline to honour.
			Segurium_Async_Scan_First_Poll_Eta::register_hooks();

			Segurium_Scheduled_Scan::register_hooks();
			Segurium_Scheduled_Scan_Settings::ensure_pregenerated();
			if ( ! wp_next_scheduled( Segurium_Scheduled_Scan::CRON_HOOK ) ) {
				$mode = Segurium_Scheduled_Scan_Settings::get()['mode'];
				if ( Segurium_Scheduled_Scan_Settings::MODE_OFF !== $mode ) {
					Segurium_Scheduled_Scan::reschedule();
				}
			}
		}

		Segurium_Scan_Runner::register_hooks();
		Segurium_Rest_Scan_Tick::register_hooks();
		Segurium_Rest_Scan_Spawn::register_hooks();
		Segurium_Rest_Actions_Poke::register_hooks();
		Segurium_Remote_Actions::register_hooks();
		Segurium_Integrity_Inventory_Cron::register_hooks();
		Segurium_Platform_Snapshot::register_hooks();
		Segurium_Memory_Recorder::register_hooks();
		Segurium_Activity_Tracker::register_hooks();
		Segurium_Self_Check::register_hooks();
		Segurium_Integrity_Chain::register_hooks();
		Segurium_Realtime_Scan::register_hooks();
		// Alerts opt-in syncs to CTI on every settings change.
		Segurium_Alerts_Settings::register_hooks();
		// Unattended auto-fix listens after the default scan-
		// completion handler so canonical scan_findings rows are persisted.
		Segurium_Auto_Fix_Settings::register_hooks();
		Segurium_Auto_Fix::register_hooks();
		// Review ask. Listens after auto-fix so a scan that
		// auto-cleaned is judged on the cleanup, not on the scan that
		// found the threats.
		Segurium_Review_Prompt::register_hooks();
		add_action( 'segurium_scan_completed', array( $this, 'on_scan_completed' ), 10, 1 );
		add_action( 'segurium_integrity_scan_completed', array( $this, 'on_integrity_scan_completed' ), 10, 1 );
	}

	/**
	 * The central AJAX route table.
	 *
	 * Maps each privileged Segurium `wp_ajax_*` action to the nonce action
	 * and capability the central dispatcher must verify before running the
	 * handler. Every entry is `action => array( nonce_action, capability,
	 * callable )`. This is the single source of truth used both to register
	 * the hooks (see the constructor) and to dispatch a request
	 * (see ajax_dispatch()).
	 *
	 * The pre-login 2FA actions (`segurium_2fa_authenticate` / `_verify` /
	 * `_resend`) are intentionally NOT here: they run before a user identity
	 * exists and are registered + verified directly. Scan-spawn / scan-tick
	 * REST endpoints are signature-authenticated and
	 * registered separately via register_rest_route(); they are not AJAX
	 * actions and do not belong in this table.
	 *
	 * @return array<string,array{0:string,1:string,2:callable}>
	 */
	private function ajax_routes() {
		$tfa = Segurium_2FA::get_instance();
		$mo  = 'manage_options';

		$consent   = 'segurium_consent';
		$settings  = 'segurium_settings';
		$cleanup   = 'segurium_cleanup';
		$scan      = 'segurium_scan';
		$integrity = 'segurium_integrity';
		$migration = 'segurium_migration';
		$support   = 'segurium_support';
		$bf        = Segurium_Brute_Force::NONCE_ACTION;
		$selfcheck = Segurium_Self_Check::NONCE_ACTION;
		$twofa     = Segurium_2FA::NONCE_ACTION;
		$review    = Segurium_Review_Prompt::NONCE_ACTION;
		$paywall   = Segurium_Paywall_Telemetry::NONCE_ACTION;
		$deact     = Segurium_Deactivation_Reason::NONCE_ACTION;

		return array(
			// Consent + core settings.
			'segurium_accept_consent'                    => array( $consent, $mo, array( $this, 'ajax_accept_consent' ) ),
			'segurium_save_settings'                     => array( $settings, $mo, array( $this, 'ajax_save_settings' ) ),
			'segurium_get_scheduled_scan_settings'       => array( $settings, $mo, array( $this, 'ajax_get_scheduled_scan_settings' ) ),
			'segurium_save_scheduled_scan_settings'      => array( $settings, $mo, array( $this, 'ajax_save_scheduled_scan_settings' ) ),

			// Malware scan lifecycle + readouts.
			'segurium_start_scan'                        => array( $scan, $mo, array( $this, 'ajax_start_scan' ) ),
			'segurium_stop_scan'                         => array( $scan, $mo, array( $this, 'ajax_stop_scan' ) ),
			'segurium_continue_scan'                     => array( $scan, $mo, array( $this, 'ajax_continue_scan_legacy' ) ),
			'segurium_quota_state'                       => array( $scan, $mo, array( $this, 'ajax_quota_state' ) ),
			'segurium_get_server_state'                  => array( $scan, $mo, array( $this, 'ajax_get_server_state' ) ),
			'segurium_initial_state'                     => array( $scan, $mo, array( $this, 'ajax_get_initial_state' ) ),
			'segurium_scanner_fix_all_preview'           => array( $scan, $mo, array( $this, 'ajax_scanner_fix_all_preview' ) ),
			'segurium_scan_status'                       => array( $scan, $mo, array( $this, 'ajax_scan_status' ) ),
			'segurium_cti_health'                        => array( $scan, $mo, array( $this, 'ajax_cti_health' ) ),
			'segurium_scan_tick'                         => array( $scan, $mo, array( 'Segurium_Scan_Runner', 'ajax_tick' ) ),

			// Cleanup / restore / false-positive flows.
			'segurium_get_threats'                       => array( $cleanup, $mo, array( $this, 'ajax_get_threats' ) ),
			'segurium_cleanup_file'                      => array( $cleanup, $mo, array( $this, 'ajax_cleanup_file' ) ),
			'segurium_restore_file'                      => array( $cleanup, $mo, array( $this, 'ajax_restore_file' ) ),
			'segurium_restore_preflight'                 => array( $cleanup, $mo, array( $this, 'ajax_restore_preflight' ) ),
			'segurium_get_backup_content'                => array( $cleanup, $mo, array( $this, 'ajax_get_backup_content' ) ),
			'segurium_get_disk_content'                  => array( $cleanup, $mo, array( $this, 'ajax_get_disk_content' ) ),
			'segurium_ignore_file'                       => array( $cleanup, $mo, array( $this, 'ajax_ignore_file' ) ),
			'segurium_submit_fp_report'                  => array( $cleanup, $mo, array( $this, 'ajax_submit_fp_report' ) ),
			'segurium_unignore_file'                     => array( $cleanup, $mo, array( $this, 'ajax_unignore_file' ) ),

			// Integrity scan lifecycle (segurium_scan nonce).
			'segurium_integrity_start'                   => array( $scan, $mo, array( $this, 'ajax_integrity_start' ) ),
			'segurium_integrity_stop'                    => array( $scan, $mo, array( $this, 'ajax_integrity_stop' ) ),
			'segurium_integrity_status'                  => array( $scan, $mo, array( $this, 'ajax_integrity_status' ) ),
			'segurium_integrity_continue'                => array( $scan, $mo, array( $this, 'ajax_integrity_continue_legacy' ) ),
			'segurium_get_integrity_state'               => array( $scan, $mo, array( $this, 'ajax_get_integrity_state' ) ),
			'segurium_integrity_ignore_file'             => array( $scan, $mo, array( $this, 'ajax_integrity_ignore_file' ) ),
			'segurium_integrity_unignore_file'           => array( $scan, $mo, array( $this, 'ajax_integrity_unignore_file' ) ),
			'segurium_integrity_restore_and_ignore_file' => array( $scan, $mo, array( $this, 'ajax_integrity_restore_and_ignore_file' ) ),
			'segurium_integrity_ignore_component'        => array( $scan, $mo, array( $this, 'ajax_integrity_ignore_component' ) ),
			'segurium_integrity_unignore_component'      => array( $scan, $mo, array( $this, 'ajax_integrity_unignore_component' ) ),
			'segurium_integrity_delete_component'        => array( $scan, $mo, array( $this, 'ajax_integrity_delete_component' ) ),
			'segurium_integrity_restore_component'       => array( $scan, $mo, array( $this, 'ajax_integrity_restore_component' ) ),
			'segurium_integrity_fix_all_preview'         => array( $scan, $mo, array( $this, 'ajax_integrity_fix_all_preview' ) ),

			// Integrity per-file actions (segurium_integrity nonce).
			'segurium_integrity_fix_file'                => array( $integrity, $mo, array( $this, 'ajax_integrity_fix_file' ) ),
			'segurium_integrity_restore_file'            => array( $integrity, $mo, array( $this, 'ajax_integrity_restore_file' ) ),
			'segurium_integrity_diff_file'               => array( $integrity, $mo, array( $this, 'ajax_integrity_diff_file' ) ),
			'segurium_integrity_view_file'               => array( $integrity, $mo, array( $this, 'ajax_integrity_view_file' ) ),

			// Geo blocker.
			'segurium_get_geo_settings'                  => array( $settings, $mo, array( $this, 'ajax_get_geo_settings' ) ),
			'segurium_save_geo_settings'                 => array( $settings, $mo, array( $this, 'ajax_save_geo_settings' ) ),
			'segurium_trigger_geo_db_update'             => array( $settings, $mo, array( $this, 'ajax_trigger_geo_db_update' ) ),
			'segurium_get_geo_stats'                     => array( $settings, $mo, array( $this, 'ajax_get_geo_stats' ) ),
			'segurium_confirm_pending'                   => array( $settings, $mo, array( $this, 'ajax_confirm_pending' ) ),
			'segurium_revert_pending'                    => array( $settings, $mo, array( $this, 'ajax_revert_pending' ) ),

			// Firewall + trusted proxies.
			'segurium_get_firewall_settings'             => array( $settings, $mo, array( $this, 'ajax_get_firewall_settings' ) ),
			'segurium_save_firewall_settings'            => array( $settings, $mo, array( $this, 'ajax_save_firewall_settings' ) ),
			'segurium_get_trusted_proxies_status'        => array( $settings, $mo, array( $this, 'ajax_get_trusted_proxies_status' ) ),
			'segurium_trigger_trusted_proxies_update'    => array( $settings, $mo, array( $this, 'ajax_trigger_trusted_proxies_update' ) ),

			// Brute-force protection (segurium_bf nonce).
			'segurium_get_bf_settings'                   => array( $bf, $mo, array( $this, 'ajax_get_bf_settings' ) ),
			'segurium_save_bf_settings'                  => array( $bf, $mo, array( $this, 'ajax_save_bf_settings' ) ),
			'segurium_get_bf_lockouts'                   => array( $bf, $mo, array( $this, 'ajax_get_bf_lockouts' ) ),
			'segurium_unlock_bf_ip'                      => array( $bf, $mo, array( $this, 'ajax_unlock_bf_ip' ) ),
			'segurium_get_bf_stats'                      => array( $bf, $mo, array( $this, 'ajax_get_bf_stats' ) ),
			'segurium_get_bf_log'                        => array( $bf, $mo, array( $this, 'ajax_get_bf_log' ) ),

			// Migration.
			'segurium_migration_detect'                  => array( $migration, $mo, array( $this, 'ajax_migration_detect' ) ),
			'segurium_migration_preview'                 => array( $migration, $mo, array( $this, 'ajax_migration_preview' ) ),
			'segurium_migration_apply'                   => array( $migration, $mo, array( $this, 'ajax_migration_apply' ) ),

			// Support.
			'segurium_submit_support_ticket'             => array( $support, $mo, array( $this, 'ajax_submit_support_ticket' ) ),

			// Review ask (leave / later / never).
			Segurium_Review_Prompt::AJAX_ACTION          => array( $review, $mo, array( 'Segurium_Review_Prompt', 'ajax_review_prompt_action' ) ),

			// Quota-wall CTA impressions and clicks.
			Segurium_Paywall_Telemetry::AJAX_ACTION      => array( $paywall, $mo, array( 'Segurium_Paywall_Telemetry', 'ajax_paywall_cta' ) ),

			// Exit reason picked on the Deactivate link.
			Segurium_Deactivation_Reason::AJAX_ACTION    => array( $deact, $mo, array( 'Segurium_Deactivation_Reason', 'ajax_deactivation_reason' ) ),

			// Security headers + info shield.
			'segurium_get_sh_settings'                   => array( $settings, $mo, array( $this, 'ajax_get_sh_settings' ) ),
			'segurium_save_sh_settings'                  => array( $settings, $mo, array( $this, 'ajax_save_sh_settings' ) ),
			'segurium_get_info_shield_settings'          => array( $settings, $mo, array( $this, 'ajax_get_info_shield_settings' ) ),
			'segurium_save_info_shield_settings'         => array( $settings, $mo, array( $this, 'ajax_save_info_shield_settings' ) ),

			// Self check.
			'segurium_run_self_check'                    => array( $selfcheck, $mo, array( $this, 'ajax_run_self_check' ) ),

			// 2FA admin settings (manage_options).
			'segurium_get_2fa_settings'                  => array( $twofa, $mo, array( $this, 'ajax_get_2fa_settings' ) ),
			'segurium_save_2fa_settings'                 => array( $twofa, $mo, array( $this, 'ajax_save_2fa_settings' ) ),
			'segurium_get_2fa_user_stats'                => array( $twofa, $mo, array( $this, 'ajax_get_2fa_user_stats' ) ),
			'segurium_admin_reset_user_2fa'              => array( $twofa, $mo, array( $this, 'ajax_admin_reset_user_2fa' ) ),

			// 2FA per-user profile setup (capability 'read' — any logged-in
			// user manages their own second factor).
			'segurium_2fa_setup_totp'                    => array( $twofa, 'read', array( $tfa, 'ajax_setup_totp' ) ),
			'segurium_2fa_confirm_totp'                  => array( $twofa, 'read', array( $tfa, 'ajax_confirm_totp' ) ),
			'segurium_2fa_setup_email'                   => array( $twofa, 'read', array( $tfa, 'ajax_setup_email' ) ),
			'segurium_2fa_confirm_email'                 => array( $twofa, 'read', array( $tfa, 'ajax_confirm_email' ) ),
			'segurium_2fa_disable'                       => array( $twofa, 'read', array( $tfa, 'ajax_disable_2fa' ) ),
			'segurium_2fa_regenerate_backup'             => array( $twofa, 'read', array( $tfa, 'ajax_regenerate_backup' ) ),
		);
	}

	/**
	 * Central privileged AJAX dispatcher (Pattern A).
	 *
	 * Every privileged Segurium `wp_ajax_*` action is routed here. The
	 * dispatcher looks the action up in ajax_routes(), verifies the route's
	 * nonce with the CORE check_ajax_referer() and the route's capability
	 * with current_user_can(), then hands off to the handler. Handlers keep
	 * their own defence-in-depth guards, but this dispatcher is the single
	 * gate the WP.org review credits.
	 *
	 * @return void
	 */
	public function ajax_dispatch() {
		// The action name selects the route; WordPress already used it to
		// reach this callback. We sanitise it and look up the per-action
		// nonce + capability, which are then verified below with core
		// WordPress functions before any handler runs.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended -- the matched route's nonce is verified immediately below.
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		$routes = $this->ajax_routes();

		if ( '' === $action || ! isset( $routes[ $action ] ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unknown_action',
					'message' => __( 'Unknown or unsupported action.', 'segurium' ),
				),
				400
			);
			return;
		}

		list( $nonce_action, $capability, $handler ) = $routes[ $action ];

		check_ajax_referer( $nonce_action, 'nonce' );

		if ( ! current_user_can( $capability ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
			return;
		}

		if ( ! is_callable( $handler ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'handler_unavailable',
					'message' => __( 'This action is temporarily unavailable.', 'segurium' ),
				),
				500
			);
			return;
		}

		call_user_func( $handler );
	}

	/**
	 * Handle scan completion dispatched by the runner. Updates the server
	 * state from the scan results — this was previously inlined in the
	 * ajax_start_scan / ajax_continue_scan handlers.
	 *
	 * @param Segurium_Scan $scan Completed scan instance.
	 * @return void
	 */
	public function on_scan_completed( $scan ) {
		if ( ! $scan instanceof Segurium_Scan ) {
			return;
		}
		$this->update_server_state_from_scan( $scan );
		// Stamp last-malware-scan freshness and, if an
		// integrity scan was queued behind this run, schedule it to start
		// after the runner releases the lock.
		Segurium_Integrity_Chain::note_malware_completed();
		$scan->cleanup();
	}

	/**
	 * Filter file uploads to scan for malware.
	 *
	 * @param array $upload Upload data array.
	 * @return array Filtered upload data.
	 */
	public function filter_upload( $upload ) {
		$scanner = new Segurium_Upload_Scan( $this->get_data_dir() );
		return $scanner->handle_upload( $upload );
	}

	/**
	 * Run the scheduled realtime scan.
	 *
	 * @return void
	 */
	public function run_realtime_scan() {
		$rt = new Segurium_Realtime_Scan( Segurium_Path_Helpers::wp_root(), $this->get_data_dir() );
		$rt->run();
	}

	/**
	 * Register the dashboard widget.
	 */
	public function add_dashboard_widget() {
		wp_add_dashboard_widget(
			'segurium_widget',
			__( 'Segurium', 'segurium' ),
			array( $this, 'render_dashboard_widget' )
		);
	}

	/**
	 * Render the dashboard widget. Surfaces the latest Self-Check grade
	 * and a shortcut to the admin page.
	 */
	public function render_dashboard_widget() {
		$result = class_exists( 'Segurium_Self_Check' )
			? Segurium_Self_Check::get_instance()->get_last_result()
			: null;

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
	 * Register the admin menu page.
	 *
	 * @return void
	 */
	public function add_admin_menu() {
		add_menu_page(
			__( 'Segurium', 'segurium' ),
			__( 'Segurium', 'segurium' ),
			'manage_options',
			'segurium',
			array( $this, 'render_admin_page' ),
			segurium_admin_menu_icon(),
			65
		);
	}

	/**
	 * Build a cache-busting version string for a plugin asset.
	 *
	 * Using `SEGURIUM_VERSION` alone means the browser keeps serving the
	 * stale admin JS for the entire release cycle, which has been the
	 * source of real support incidents (stale JS calling retired AJAX
	 * actions). Appending the on-disk mtime forces a fresh download the
	 * moment the file changes, while still falling back to the plugin
	 * version when the file is unreadable.
	 *
	 * @param string $relative Relative path under the plugin directory.
	 * @return string Version string suitable for wp_enqueue_script/style.
	 */
	private function asset_version( $relative ) {
		$absolute = SEGURIUM_PLUGIN_DIR . ltrim( $relative, '/' );
		$mtime    = @filemtime( $absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $mtime ) {
			return SEGURIUM_VERSION . '.' . $mtime;
		}
		return SEGURIUM_VERSION;
	}

	/**
	 * Resolve the accent palette derived from the user's WordPress
	 * Administration Color Scheme.
	 *
	 * Returns the colors used by `assets/css/segurium-admin.css` via CSS
	 * custom properties:
	 *   - `accent`         primary accent (links, focus rings, active tab)
	 *   - `accent_hover`   secondary accent (hover/highlight)
	 *   - `accent_strong`  darker shade (text on light accent chips)
	 *   - `accent_chip`    light accent background (chips, active pills)
	 *   - `accent_soft`    very light accent background (hover rows)
	 *   - `chrome_from`    plugin banner gradient start (= scheme `colors[0]`)
	 *   - `chrome_to`      plugin banner gradient end   (= scheme `colors[1]`)
	 *   - `chrome_text`    text color on the banner — flips between white
	 *                      and dark based on the gradient luminance so
	 *                      Light scheme users keep a readable banner
	 *
	 * The chrome stops are exactly what wp-admin uses for its own admin
	 * sidebar gradient, so the plugin banner reads as a continuation of
	 * the WordPress chrome rather than a foreign element.
	 *
	 * Sources the base from `$_wp_admin_css_colors[ <slug> ]->colors`
	 * (registered by `register_admin_color_schemes()`); falls back to
	 * the Fresh palette when the global is not populated or the user
	 * picked a deregistered scheme.
	 *
	 * @param string|null $scheme Optional scheme slug. Defaults to
	 *                            `get_user_option( 'admin_color' )`.
	 * @return array{accent:string,accent_hover:string,accent_strong:string,accent_chip:string,accent_soft:string,chrome_from:string,chrome_to:string,chrome_text:string}
	 */
	public static function get_admin_accent_palette( $scheme = null ) {
		if ( null === $scheme || '' === $scheme ) {
			$scheme = function_exists( 'get_user_option' ) ? get_user_option( 'admin_color' ) : '';
			if ( ! is_string( $scheme ) || '' === $scheme ) {
				$scheme = 'fresh';
			}
		}

		// WP Fresh palette — used when the requested scheme is missing.
		$colors = array( '#1d2327', '#2c3338', '#2271b1', '#72aee6' );

		global $_wp_admin_css_colors;
		if ( ( ! is_array( $_wp_admin_css_colors ) || empty( $_wp_admin_css_colors ) ) && function_exists( 'register_admin_color_schemes' ) ) {
			register_admin_color_schemes();
		}
		if ( is_array( $_wp_admin_css_colors ) && isset( $_wp_admin_css_colors[ $scheme ] ) ) {
			$candidate = isset( $_wp_admin_css_colors[ $scheme ]->colors ) ? $_wp_admin_css_colors[ $scheme ]->colors : null;
			if ( is_array( $candidate ) && count( $candidate ) >= 3 ) {
				$colors = array_values( $candidate );
			}
		}

		$accent       = self::sanitize_hex_color( isset( $colors[2] ) ? $colors[2] : null, '#2271b1' );
		$accent_hover = self::sanitize_hex_color( isset( $colors[3] ) ? $colors[3] : $accent, $accent );
		$chrome_from  = self::sanitize_hex_color( isset( $colors[0] ) ? $colors[0] : null, '#1d2327' );
		$chrome_to    = self::sanitize_hex_color( isset( $colors[1] ) ? $colors[1] : $chrome_from, $chrome_from );

		return array(
			'accent'        => $accent,
			'accent_hover'  => $accent_hover,
			'accent_strong' => self::mix_hex_color( $accent, '#000000', 0.30 ),
			'accent_chip'   => self::mix_hex_color( $accent, '#ffffff', 0.80 ),
			'accent_soft'   => self::mix_hex_color( $accent, '#ffffff', 0.92 ),
			'chrome_from'   => $chrome_from,
			'chrome_to'     => $chrome_to,
			'chrome_text'   => self::contrast_text_for( $chrome_from, $chrome_to ),
		);
	}

	/**
	 * Inline CSS that re-declares Segurium's `--segurium-accent-*` custom
	 * properties from the user's wp-admin color scheme.
	 *
	 * Attached to the `segurium-admin` style handle via
	 * `wp_add_inline_style()` so it loads after the linked stylesheet
	 * and overrides the literal `var()` fallbacks baked into the file.
	 *
	 * @return string Minified CSS, no surrounding `<style>` tag.
	 */
	public static function admin_color_scheme_inline_css() {
		$p = self::get_admin_accent_palette();
		return ':root{'
			. '--segurium-accent:' . $p['accent'] . ';'
			. '--segurium-accent-hover:' . $p['accent_hover'] . ';'
			. '--segurium-accent-strong:' . $p['accent_strong'] . ';'
			. '--segurium-accent-chip-bg:' . $p['accent_chip'] . ';'
			. '--segurium-accent-soft-bg:' . $p['accent_soft'] . ';'
			. '--segurium-chrome-from:' . $p['chrome_from'] . ';'
			. '--segurium-chrome-to:' . $p['chrome_to'] . ';'
			. '--segurium-chrome-text:' . $p['chrome_text'] . ';'
			. '}';
	}

	/**
	 * Pick a readable text color (white or near-black) for a two-stop
	 * gradient. Uses the average sRGB-relative luminance of the two
	 * stops with the standard 0.5 cutoff.
	 *
	 * Why: the wp-admin Light scheme has near-white sidebar stops
	 * (`#e5e5e5` → `#999`); white plugin-banner text on that gradient
	 * is invisible. Flipping to dark text when luminance is high keeps
	 * the banner legible across every shipped scheme.
	 *
	 * @param string $a Sanitized hex.
	 * @param string $b Sanitized hex.
	 * @return string `#ffffff` or `#1d2327`.
	 */
	private static function contrast_text_for( $a, $b ) {
		$la = self::relative_luminance( $a );
		$lb = self::relative_luminance( $b );
		return ( ( $la + $lb ) / 2.0 ) < 0.5 ? '#ffffff' : '#1d2327';
	}

	/**
	 * SRGB-relative luminance per WCAG 2.x — returns a value in [0, 1].
	 *
	 * @param string $hex Sanitized hex color.
	 * @return float
	 */
	private static function relative_luminance( $hex ) {
		$rgb = self::hex_to_rgb( $hex );
		$lin = static function ( $c ) {
			$s = $c / 255.0;
			return ( $s <= 0.03928 ) ? ( $s / 12.92 ) : pow( ( $s + 0.055 ) / 1.055, 2.4 );
		};
		return 0.2126 * $lin( $rgb[0] ) + 0.7152 * $lin( $rgb[1] ) + 0.0722 * $lin( $rgb[2] );
	}

	/**
	 * Validate / normalize a hex color string to `#rrggbb`.
	 *
	 * @param mixed  $value    Candidate color.
	 * @param string $fallback Returned when validation fails.
	 * @return string
	 */
	private static function sanitize_hex_color( $value, $fallback ) {
		if ( ! is_string( $value ) ) {
			return $fallback;
		}
		$value = strtolower( trim( $value ) );
		if ( ! preg_match( '/^#([0-9a-f]{3}|[0-9a-f]{6})$/', $value ) ) {
			return $fallback;
		}
		if ( 4 === strlen( $value ) ) {
			$value = '#' . $value[1] . $value[1] . $value[2] . $value[2] . $value[3] . $value[3];
		}
		return $value;
	}

	/**
	 * Linear-blend two hex colors in sRGB space.
	 *
	 * `$weight_b` = 0 returns `$a`, `1.0` returns `$b`. Used to derive the
	 * `accent_strong` / `accent_chip` / `accent_soft` shades from the base
	 * accent without depending on the (browser-version-gated) CSS
	 * `color-mix()` function.
	 *
	 * @param string $a        Source color (sanitized hex).
	 * @param string $b        Target color (sanitized hex).
	 * @param float  $weight_b Blend weight of `$b`, clamped to [0,1].
	 * @return string
	 */
	private static function mix_hex_color( $a, $b, $weight_b ) {
		$w     = max( 0.0, min( 1.0, (float) $weight_b ) );
		$a_rgb = self::hex_to_rgb( $a );
		$b_rgb = self::hex_to_rgb( $b );
		$r     = (int) round( $a_rgb[0] * ( 1 - $w ) + $b_rgb[0] * $w );
		$g     = (int) round( $a_rgb[1] * ( 1 - $w ) + $b_rgb[1] * $w );
		$bl    = (int) round( $a_rgb[2] * ( 1 - $w ) + $b_rgb[2] * $w );
		return sprintf( '#%02x%02x%02x', $r, $g, $bl );
	}

	/**
	 * Convert a `#rrggbb` (or `#rgb`) string to an [r, g, b] integer tuple.
	 *
	 * @param string $hex Hex color, with or without leading `#`.
	 * @return array{0:int,1:int,2:int}
	 */
	private static function hex_to_rgb( $hex ) {
		$h = ltrim( (string) $hex, '#' );
		if ( 3 === strlen( $h ) ) {
			$h = $h[0] . $h[0] . $h[1] . $h[1] . $h[2] . $h[2];
		}
		return array(
			(int) hexdec( substr( $h, 0, 2 ) ),
			(int) hexdec( substr( $h, 2, 2 ) ),
			(int) hexdec( substr( $h, 4, 2 ) ),
		);
	}

	/**
	 * Read a scalar request/server value after unslashing it.
	 *
	 * @param int    $source  INPUT_POST, INPUT_GET, INPUT_REQUEST, INPUT_COOKIE, or INPUT_SERVER.
	 * @param string $key     Superglobal key.
	 * @param string $fallback Default value.
	 * @return mixed
	 */
	private static function request_scalar( $source, $key, $fallback = '' ) {
		// Centralised superglobal reader. The actual
		// nonce + capability enforcement lives at each call site (the
		// central AJAX dispatcher verifies nonce + capability before any
		// handler runs; admin page renders gate on current_user_can).
		$bag = array();
		// phpcs:disable WordPress.Security.NonceVerification -- centralized request reader; callers sanitize by type after this helper unslashes.
		switch ( $source ) {
			case INPUT_POST:
				$bag = $_POST;
				break;
			case INPUT_GET:
				$bag = $_GET;
				break;
			case INPUT_COOKIE:
				$bag = $_COOKIE;
				break;
			case INPUT_SERVER:
				$bag = $_SERVER;
				break;
			default:
				$bag = $_REQUEST;
				break;
		}
		$value = isset( $bag[ $key ] ) ? wp_unslash( $bag[ $key ] ) : $fallback;
		// phpcs:enable WordPress.Security.NonceVerification

		if ( is_array( $value ) ) {
			return $fallback;
		}
		if ( null === $value ) {
			return null;
		}
		return $value;
	}

	/**
	 * Read an array request value after unslashing it.
	 *
	 * @param int    $source Superglobal source.
	 * @param string $key    Superglobal key.
	 * @return array
	 */
	private static function request_array( $source, $key ) {
		// Centralised superglobal reader. Real enforcement
		// lives at each call site (the central AJAX dispatcher).
		$bag = array();
		// phpcs:disable WordPress.Security.NonceVerification -- centralized request reader; arrays are sanitized by their owning settings classes.
		switch ( $source ) {
			case INPUT_POST:
				$bag = $_POST;
				break;
			case INPUT_GET:
				$bag = $_GET;
				break;
			case INPUT_COOKIE:
				$bag = $_COOKIE;
				break;
			case INPUT_SERVER:
				$bag = $_SERVER;
				break;
			default:
				$bag = $_REQUEST;
				break;
		}
		$value = isset( $bag[ $key ] ) && is_array( $bag[ $key ] ) ? $bag[ $key ] : array();
		// phpcs:enable WordPress.Security.NonceVerification

		return (array) wp_unslash( $value );
	}

	/**
	 * Check whether a request key is present.
	 *
	 * @param int    $source Superglobal source.
	 * @param string $key    Superglobal key.
	 * @return bool
	 */
	private static function request_has( $source, $key ) {
		// Centralised superglobal presence check. Real
		// enforcement lives at each call site (the central AJAX dispatcher).
		$bag = array();
		// phpcs:disable WordPress.Security.NonceVerification -- presence check only; values are read through typed helpers.
		switch ( $source ) {
			case INPUT_POST:
				$bag = $_POST;
				break;
			case INPUT_GET:
				$bag = $_GET;
				break;
			case INPUT_COOKIE:
				$bag = $_COOKIE;
				break;
			case INPUT_SERVER:
				$bag = $_SERVER;
				break;
			default:
				$bag = $_REQUEST;
				break;
		}
		$present = isset( $bag[ $key ] );
		// phpcs:enable WordPress.Security.NonceVerification

		return $present;
	}

	/**
	 * Read an integer request value.
	 *
	 * @param int    $source  Superglobal source.
	 * @param string $key     Superglobal key.
	 * @param int    $fallback Default value.
	 * @return int
	 */
	private static function request_int( $source, $key, $fallback = 0 ) {
		$value = self::request_scalar( $source, $key, null );
		if ( null === $value || '' === $value ) {
			return (int) $fallback;
		}
		return (int) sanitize_text_field( (string) $value );
	}

	/**
	 * Read a boolean request value.
	 *
	 * @param int    $source Superglobal source.
	 * @param string $key    Superglobal key.
	 * @return bool
	 */
	private static function request_bool( $source, $key ) {
		$value = self::request_scalar( $source, $key, null );
		if ( null === $value ) {
			return false;
		}
		$value = strtolower( sanitize_text_field( (string) $value ) );
		return '' !== $value && ! in_array( $value, array( '0', 'false', 'no', 'off' ), true );
	}

	/**
	 * Enqueue admin scripts and styles.
	 *
	 * @param string $hook The current admin page hook suffix.
	 * @return void
	 */
	public function enqueue_admin_assets( $hook ) {
		if ( 'toplevel_page_segurium' !== $hook ) {
			return;
		}
		wp_enqueue_style(
			'segurium-admin',
			SEGURIUM_PLUGIN_URL . 'assets/css/segurium-admin.css',
			array(),
			$this->asset_version( 'assets/css/segurium-admin.css' )
		);
		// Re-declare accent CSS variables from the user's
		// chosen wp-admin color scheme so our admin UI follows it.
		wp_add_inline_style( 'segurium-admin', self::admin_color_scheme_inline_css() );
		wp_enqueue_script(
			'segurium-ajax',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-ajax.js',
			array(),
			$this->asset_version( 'assets/js/segurium-ajax.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-scan',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-scan.js',
			array( 'segurium-ajax' ),
			$this->asset_version( 'assets/js/segurium-scan.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-migration',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-migration.js',
			array( 'segurium-scan' ),
			$this->asset_version( 'assets/js/segurium-migration.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-support',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-support.js',
			array( 'segurium-scan' ),
			$this->asset_version( 'assets/js/segurium-support.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-self-check',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-self-check.js',
			array( 'segurium-scan' ),
			$this->asset_version( 'assets/js/segurium-self-check.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-iid-copy',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-iid-copy.js',
			array(),
			$this->asset_version( 'assets/js/segurium-iid-copy.js' ),
			true
		);
		// Only enqueued when the ask is actually painting
		// this request, so the file costs nothing on every other load.
		if ( Segurium_Review_Prompt::should_render() ) {
			wp_enqueue_script(
				'segurium-review-prompt',
				SEGURIUM_PLUGIN_URL . 'assets/js/segurium-review-prompt.js',
				array( 'segurium-ajax' ),
				$this->asset_version( 'assets/js/segurium-review-prompt.js' ),
				true
			);
		}
		// Feed the JS the most recent *terminal* scan so the
		// summary line can render an honest "Scan stopped — X of Y" after a
		// user cancellation or watchdog abort, not the stale previous
		// completed run. The JS branches on `.status` for copy.
		$last_scan = $this->get_last_terminal_scan();

		// segurium_pending_ctx_* keys are owned by Segurium_Pending_Changes.
		$geo_token   = Segurium_Storage::setting_get( 'segurium_pending_ctx_geo_blocking' );
		$geo_pending = null;
		if ( $geo_token ) {
			$geo_data = Segurium_Pending_Changes::get( $geo_token );
			if ( $geo_data ) {
				$remaining = max( 0, $geo_data['expires'] - time() );
				if ( $remaining > 0 ) {
					$geo_pending = array(
						'token'     => $geo_token,
						'remaining' => $remaining,
					);
				}
			}
		}

		$fw_token   = Segurium_Storage::setting_get( 'segurium_pending_ctx_firewall' );
		$fw_pending = null;
		if ( $fw_token ) {
			$fw_data = Segurium_Pending_Changes::get( $fw_token );
			if ( $fw_data ) {
				$remaining = max( 0, $fw_data['expires'] - time() );
				if ( $remaining > 0 ) {
					$fw_pending = array(
						'token'     => $fw_token,
						'remaining' => $remaining,
					);
				}
			}
		}

		// Tier signal for the JS payload comes from the cached
		// CTI quota envelope's `plan_tier` field, not
		// from a local Freemius read — the plugin code must run identically
		// for every install (WP.org Guideline 5). Plan flips reach the JS
		// within ≤60s of the CTI webhook; mid-session changes still require
		// a reload, same as before.
		$plan_tier = $this->plan_tier_from_envelope();
		wp_add_inline_script(
			'segurium-scan',
			'var seguriumScan = ' . wp_json_encode(
				array(
					'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
					'activeTab'      => self::current_tab(),
					'adminPage'      => self::admin_tab_url( '' ),
					'nonce'          => wp_create_nonce( 'segurium_scan' ),
					'consentNonce'   => wp_create_nonce( 'segurium_consent' ),
					'settingsNonce'  => wp_create_nonce( 'segurium_settings' ),
					'cleanupNonce'   => wp_create_nonce( 'segurium_cleanup' ),
					'integrityNonce' => wp_create_nonce( 'segurium_integrity' ),
					'paywallNonce'   => wp_create_nonce( Segurium_Paywall_Telemetry::NONCE_ACTION ),
					'lastScan'       => $last_scan,
					// Surface host-environment problems that
					// would silently break scanning (short max_execution_time,
					// disabled WP-Cron with no real cron) so the user gets a
					// banner instead of a stuck progress bar.
					'envWarnings'    => Segurium_Scan_Runner::environment_warnings(),
					// Paywall CTA destination. Resolves to the public
					// pricing page whenever the SDK yields nothing, so the
					// modal always has somewhere to send the user.
					'upgradeUrl'     => class_exists( 'Segurium_Entitlements' )
						? Segurium_Entitlements::instance()->upgrade_url()
						: '',
					'upgradeOffsite' => class_exists( 'Segurium_Entitlements' )
						&& Segurium_Entitlements::is_offsite_url( Segurium_Entitlements::instance()->upgrade_url() ),
					// Seeds renderQuotaReadout()'s at-limit card decision so the
					// first JS repaint agrees with the server pre-render instead
					// of collapsing the card until the scanner list lands. Pro
					// hides every readout node before the count is consulted,
					// so the query would be dead work there.
					'threatsOpen'    => 'pro' === $plan_tier ? 0 : $this->outstanding_threat_count(),
					'meterMaxSlots'  => self::MAX_QUOTA_METER_SLOTS,
					'planTier'       => $plan_tier,
					'isPro'          => 'pro' === $plan_tier,
					'migrationNonce' => wp_create_nonce( 'segurium_migration' ),
					'supportNonce'   => wp_create_nonce( 'segurium_support' ),
					'currentUser'    => array(
						'name'  => wp_get_current_user()->display_name,
						'email' => wp_get_current_user()->user_email,
					),
					'bfNonce'        => wp_create_nonce( Segurium_Brute_Force::NONCE_ACTION ),
					'tfaNonce'       => wp_create_nonce( Segurium_2FA::NONCE_ACTION ),
					'selfCheckNonce' => wp_create_nonce( Segurium_Self_Check::NONCE_ACTION ),
					'i18n'           => array(
						'malware'                 => __( 'Malware', 'segurium' ),
						'clean'                   => __( 'Clean', 'segurium' ),
						'cleaned'                 => __( 'Cleaned', 'segurium' ),
						'restored'                => __( 'Restored', 'segurium' ),
						'failed'                  => __( 'Failed', 'segurium' ),
						'processing'              => __( 'Processing...', 'segurium' ),
						'showMalware'             => __( 'Show malware', 'segurium' ),
						'reportFp'                => __( 'Report false positive', 'segurium' ),
						'fpModalTitle'            => __( 'Report False Positive', 'segurium' ),
						'fpFieldPath'             => __( 'File path', 'segurium' ),
						'fpFieldHash'             => __( 'SHA-256', 'segurium' ),
						'fpFieldComponent'        => __( 'Component', 'segurium' ),
						'fpFieldVerdict'          => __( 'Current verdict', 'segurium' ),
						'fpFieldNote'             => __( 'Note (optional, max 2000 chars)', 'segurium' ),
						'fpAlsoIgnore'            => __( 'Also ignore this file on this site', 'segurium' ),
						'fpSubmit'                => __( 'Submit report', 'segurium' ),
						'fpCancel'                => __( 'Cancel', 'segurium' ),
						'fpSubmitting'            => __( 'Submitting…', 'segurium' ),
						'fpThanks'                => __( 'Report submitted. Thank you.', 'segurium' ),
						'fpFailed'                => __( 'Could not submit the report.', 'segurium' ),
						'restore'                 => __( 'Restore', 'segurium' ),
						'confirmRestore'          => __( 'This will restore the original infected file from backup. Continue?', 'segurium' ),
						'restoreTitle'            => __( 'Restore file', 'segurium' ),
						'restoreChecking'         => __( 'Checking…', 'segurium' ),
						'restoreAlreadyRestored'  => __( 'The file on disk is already the backed-up version. Restore anyway to update database records?', 'segurium' ),
						/* translators: %s: relative file path */
						'restoreOverwrite'        => __( 'The file at %s has been modified since the last cleanup. Restoring will overwrite the existing file with the backed-up version. This cannot be undone.', 'segurium' ),
						'restoreOverwriteBtn'     => __( 'Overwrite & Restore', 'segurium' ),
						'noThreats'               => __( 'No threats found.', 'segurium' ),
						'scanComplete'            => __( 'Scan complete.', 'segurium' ),
						'scanSummaryFiles'        => __( 'files', 'segurium' ),
						'scanSummaryFailed'       => __( 'failed', 'segurium' ),
						'scanSummarySkipped'      => __( 'skipped', 'segurium' ),
						'scanSummaryScanned'      => __( 'scanned', 'segurium' ),
						'scanStarting'            => __( 'Starting scan...', 'segurium' ),
						'scanError'               => __( 'Error', 'segurium' ),
						'scanAlreadyRunning'      => __( 'A scan is already in progress.', 'segurium' ),
						'scanRunning'             => __( 'Scan in progress...', 'segurium' ),
						'errGeneric'              => __( 'Request failed', 'segurium' ),
						'errSessionExpired'       => __( 'Your session has expired. Reload the page and try again.', 'segurium' ),
						'errUnauthorized'         => __( 'You do not have permission to manage scans.', 'segurium' ),
						'errConsentRequired'      => __( 'Segurium Cloud consent is required before scanning.', 'segurium' ),
						'errInitializeFailed'     => __( 'The scan could not be initialized. Check the PHP error log.', 'segurium' ),
						'errDispatchFailed'       => __( 'The scan started but the background worker could not be dispatched. Try again.', 'segurium' ),
						'errScanStartException'   => __( 'The scan could not be started due to a server error. Check the PHP error log.', 'segurium' ),
						'errScanStatusException'  => __( 'Could not fetch scan status due to a server error. Check the PHP error log.', 'segurium' ),
						'errScanStopException'    => __( 'Could not stop the running scan due to a server error. Check the PHP error log.', 'segurium' ),
						'errServerError'          => __( 'The server returned an error while processing the request.', 'segurium' ),
						'errNetworkError'         => __( 'Network error — the request could not reach the server.', 'segurium' ),
						'errPollHandler'          => __( 'The progress display hit a script error and stopped updating. Reload the page to see the current state — the scan itself is unaffected. Details are in the browser console.', 'segurium' ),
						'errUnexpectedResponse'   => __( 'The server returned an unexpected response. Reload the page and try again.', 'segurium' ),
						'errEnvelopeEmpty'        => __( 'Segurium got an empty response from the server. The PHP handler likely crashed before producing any output — check the PHP error log for a fatal, OOM, or timeout.', 'segurium' ),
						'errEnvelopeAbsent'       => __( 'Segurium\'s response markers are missing from the body. The Segurium AJAX handler did not run, or another plugin replaced the entire response. Check wp-content/mu-plugins, active plugins, and the PHP error log.', 'segurium' ),
						'errEnvelopeTruncated'    => __( 'Segurium\'s response was cut off mid-stream — the start marker arrived but the end marker did not. The PHP handler crashed mid-response (fatal, OOM, or timeout). Check the PHP error log.', 'segurium' ),
						'errEnvelopeMissing'      => __( 'Segurium could not unwrap the server response. Check the PHP error log for a fatal, OOM, or timeout in the Segurium handler.', 'segurium' ),
						'errEnvelopeMalformed'    => __( 'Segurium received a response wrapped in valid markers but the JSON inside did not parse. This usually indicates a fatal PHP error inside the Segurium handler — check the PHP error log.', 'segurium' ),
						'errLegacyContinueAction' => __( 'This version of the admin page is stale. Reload the page to continue.', 'segurium' ),
						'errSchemaUnavailable'    => __( 'Scan storage is not ready. Please deactivate and reactivate the Segurium plugin, then try again.', 'segurium' ),
						'errUnexpectedError'      => __( 'An unexpected server error occurred. Check the PHP error log and try again.', 'segurium' ),
						'schedFrequency'          => __( 'Frequency', 'segurium' ),
						'schedModeOff'            => __( 'Off', 'segurium' ),
						'schedModeDaily'          => __( 'Daily', 'segurium' ),
						'schedModeWeekly'         => __( 'Weekly', 'segurium' ),
						'schedTime'               => __( 'Time of day', 'segurium' ),
						'schedDay'                => __( 'Day of week', 'segurium' ),
						'schedNextRunPrefix'      => __( 'Next run:', 'segurium' ),
						'schedSaved'              => __( 'Schedule saved.', 'segurium' ),
						'schedSaveError'          => __( 'Could not save schedule.', 'segurium' ),
						'schedTimeHint'           => __( 'Stored in UTC. Displayed in your browser locale.', 'segurium' ),
						'scannedFiles'            => __( 'Scanned files', 'segurium' ),
						'showingFirst'            => __( 'showing first', 'segurium' ),
						'originalFile'            => __( 'Original file content (malware)', 'segurium' ),
						/* translators: %s: relative file path */
						'diskFile'                => __( 'Current on-disk content (malware): %s', 'segurium' ),
						'closeBtn'                => __( 'Close', 'segurium' ),
						/* translators: button label on a notice popup that closes the popup */
						'noticeOk'                => __( 'OK', 'segurium' ),
						'intDeleteFailed'         => __( 'Delete failed', 'segurium' ),
						'intRestoreFailed'        => __( 'Restore failed', 'segurium' ),
						'intFixFailed'            => __( 'Fix failed', 'segurium' ),
						'intDiffFailed'           => __( 'Diff failed', 'segurium' ),
						'intDiffDecodeError'      => __( 'Diff decode error', 'segurium' ),
						'intViewFailed'           => __( 'View failed', 'segurium' ),
						'intRestoreNoBackup'      => __( 'Cannot restore — no backup recorded for this file. The backup may have been rotated out.', 'segurium' ),
						'fixed'                   => __( 'Fixed', 'segurium' ),
						'ignored'                 => __( 'Ignored', 'segurium' ),
						'ignoreUntilSame'         => __( 'Ignore until file is the same', 'segurium' ),
						'alwaysIgnore'            => __( 'Always ignore', 'segurium' ),
						'removeFromIgnore'        => __( 'Remove from ignore', 'segurium' ),
						'ctiConnected'            => __( 'Connected', 'segurium' ),
						'ctiDisconnected'         => __( 'Disconnected', 'segurium' ),
						'serverStateEmpty'        => __( 'No files found.', 'segurium' ),
						/* translators: %d: number of malicious files still needing attention */
						'threatsRemaining'        => __( '%d threats still need your attention', 'segurium' ),
						'noThreatsRemaining'      => __( 'No threats — you are clear.', 'segurium' ),
						'noScansYet'              => __( 'No scans yet — run your first scan.', 'segurium' ),
						'stopScanBtn'             => __( 'Stop scan', 'segurium' ),
						'stopScanConfirm'         => __( 'Stop the running scan? Progress so far will be discarded.', 'segurium' ),
						'stopScanFailed'          => __( 'Could not stop the scan.', 'segurium' ),
						'scanStopped'             => __( 'Scan stopped.', 'segurium' ),
						/* translators: %1$d: files scanned before stop, %2$d: files discovered */
						'scanStoppedSummary'      => __( 'Scan stopped — %1$d of %2$d files scanned.', 'segurium' ),
						/* translators: %1$d: files scanned before abort, %2$d: files discovered */
						'scanAbortedSummary'      => __( 'Scan aborted — %1$d of %2$d files scanned.', 'segurium' ),
						/* translators: %d: number of seconds since the scan worker last reported progress */
						'scanWorkerStalled'       => __( 'no progress for %ds — waiting for worker', 'segurium' ),
						'envWarningsTitle'        => __( 'Hosting environment warnings', 'segurium' ),
						'tabMaliciousEmpty'       => __( 'No malicious files. All known threats have been handled.', 'segurium' ),
						'tabCleanedEmpty'         => __( 'No cleaned files yet.', 'segurium' ),
						'tabFixedEmpty'           => __( 'No files marked fixed.', 'segurium' ),
						'tabIgnoredEmpty'         => __( 'No ignored files.', 'segurium' ),
						'recentlyProcessed'       => __( 'Recently processed in this session', 'segurium' ),
						'page'                    => __( 'Page', 'segurium' ),
						'of'                      => __( 'of', 'segurium' ),
						'items'                   => __( 'items', 'segurium' ),
						'prev'                    => __( 'Previous', 'segurium' ),
						'next'                    => __( 'Next', 'segurium' ),
						'intFix'                  => __( 'Fix', 'segurium' ),
						'intIgnore'               => __( 'Ignore', 'segurium' ),
						'intRestore'              => __( 'Restore', 'segurium' ),
						'intFixed'                => __( 'Fixed', 'segurium' ),
						'intDeleted'              => __( 'Deleted', 'segurium' ),
						'notFound'                => __( 'Not found', 'segurium' ),
						'intConfirmDelete'        => __( 'This file is not part of the original installation and will be deleted. A backup will be created. Continue?', 'segurium' ),
						'intConfirmDeleteAll'     => __( 'Some files will be deleted (unknown files) and some will be replaced with originals (modified files). Backups will be created for all. Continue?', 'segurium' ),
						'intFixAll'               => __( 'Fixing files...', 'segurium' ),
						// Pre-flight backup-eviction warning shown inside the Fix All preview modal.
						'intFixAllEvictHeading'   => __( 'Older backups will be rotated out', 'segurium' ),
						/* translators: 1: number of files to fix, 2: human-readable size (e.g. "12.4 MB") */
						'intFixAllEvictBody1'     => __( 'You are about to fix %1$d files (~%2$s).', 'segurium' ),
						/* translators: 1: number of envelopes to evict, 2: human-readable size of those envelopes */
						'intFixAllEvictBody2'     => __( '%1$d older backups (~%2$s) will be rotated out — these are restore points for previously-fixed files.', 'segurium' ),
						/* translators: %d: number of pinned backups that are protected from rotation */
						'intFixAllEvictPinned'    => __( '%d pinned backups will be kept (still referenced by Restore).', 'segurium' ),
						'intFixAllEvictContinue'  => __( 'Continue', 'segurium' ),
						'progressRestoring'       => __( 'Restoring files…', 'segurium' ),
						'progressIgnoring'        => __( 'Updating files…', 'segurium' ),
						/* translators: 1: number of items completed; 2: total number of items */
						'progressOf'              => __( '%1$d of %2$d', 'segurium' ),
						'progressCancelling'      => __( 'Cancelling…', 'segurium' ),
						'scannerFixAllTitle'      => __( 'Clean all detected malware', 'segurium' ),
						/* translators: %d: number of malicious files queued for cleanup */
						'scannerFixAllCopy'       => __( 'This will attempt to clean %d detected malicious file(s). Each file is backed up before cleanup.', 'segurium' ),
						'scannerFixAllConfirm'    => __( 'Clean all', 'segurium' ),
						'scannerFixAllRunning'    => __( 'Cleaning malware...', 'segurium' ),
						'cancel'                  => __( 'Cancel', 'segurium' ),
						'intChainRunningMalware'  => __( 'Running a quick malware scan first…', 'segurium' ),
						'paywallProTitle'         => __( 'Upgrade to Pro', 'segurium' ),
						'paywallProUpgrade'       => __( 'Upgrade to Pro', 'segurium' ),
						'paywallProMaybeLater'    => __( 'Maybe later', 'segurium' ),
						'paywallProFallback'      => __( 'Cleanup quota reached. Upgrade to Pro for an unbounded cloud cleanup quota.', 'segurium' ),
						'paywallQuotaTitle'       => __( 'Cleanup quota reached', 'segurium' ),
						/* translators: 1: number of cleanups consumed in the rolling window (e.g., 3); 2: rolling window length in days (e.g., 30) */
						'paywallQuotaCopy'        => __( 'You’ve used %1$d cloud cleanups in the last %2$d days. Upgrade to Pro for an unbounded cloud cleanup quota.', 'segurium' ),
						/* translators: %s: localized date when the next cleanup slot becomes available */
						'paywallQuotaResets'      => __( 'Next slot opens %s', 'segurium' ),
						/* translators: 1: cleanups used so far, 2: per-window cap (e.g., 3), 3: rolling window length in days (e.g., 30) */
						'quotaReadout'            => __( '%1$d of %2$d cleanups used in the last %3$d days', 'segurium' ),
						/* translators: 1: cleanups used so far, 2: per-window cap (e.g., 3), 3: rolling window length in days (e.g., 30), 4: localized date when the next slot opens */
						'quotaReadoutAtLimit'     => __( '%1$d of %2$d cleanups used in the last %3$d days — next slot opens %4$s', 'segurium' ),
						'quotaReadoutUpgradeCta'  => __( 'Upgrade to Pro', 'segurium' ),
						'plansTab'                => __( 'Plans', 'segurium' ),
						'moneyBackGuarantee'      => __( '14-day money-back guarantee.', 'segurium' ),
						'proBadge'                => __( 'Pro', 'segurium' ),
						'intDiff'                 => __( 'Diff', 'segurium' ),
						'intDelisted'             => __( 'Delisted from official WordPress.org', 'segurium' ),
						'intAbandoned'            => __( 'Abandoned (no updates >2 years)', 'segurium' ),
						'intNotWpOrg'             => __( 'Not from official WordPress.org', 'segurium' ),
						'ignoredLabel'            => __( 'ignored', 'segurium' ),
						'issuesFound'             => __( 'Issues', 'segurium' ),
						'issue'                   => __( 'issue', 'segurium' ),
						'unrecognizedFile'        => __( 'unrecognized file', 'segurium' ),
						'verdictMalwareSuffix'    => __( '(!) malware', 'segurium' ),
						'view'                    => __( 'View', 'segurium' ),
						'issues'                  => __( 'issues', 'segurium' ),
						'checking'                => __( 'Checking', 'segurium' ),
						'discoveringComponents'   => __( 'Discovering components…', 'segurium' ),
						'geoConfirmed'            => __( 'Saved permanently.', 'segurium' ),
						'geoReverted'             => __( 'Changes reverted.', 'segurium' ),
						'geoBlockedCountries'     => __( 'Blocked Countries', 'segurium' ),
						'geoAllowedCountries'     => __( 'Allowed Countries', 'segurium' ),
						'geoBlockedCountriesDesc' => __( 'Type a country name or ISO code to add it to the block list.', 'segurium' ),
						'geoAllowedCountriesDesc' => __( 'Type a country name or ISO code to add it to the allow list.', 'segurium' ),
						'fwBlockedIps'            => __( 'Blocked IPs / CIDRs', 'segurium' ),
						'fwBlockedIpsDesc'        => __( 'These IPs are always blocked. One entry per line. Accepts IPv4, IPv6, and CIDR ranges.', 'segurium' ),
						'fwAllowedIps'            => __( 'Allowed IPs / CIDRs', 'segurium' ),
						'fwAllowedIpsDesc'        => __( 'Only these IPs can access the site. All others are blocked. One entry per line.', 'segurium' ),
						'migNoPlugins'            => __( 'No supported security plugins detected.', 'segurium' ),
						'migPreview'              => __( 'Preview', 'segurium' ),
						'migApply'                => __( 'Apply Migration', 'segurium' ),
						'migCancel'               => __( 'Cancel', 'segurium' ),
						'migApplied'              => __( 'Migration complete.', 'segurium' ),
						'migImport'               => __( 'Import', 'segurium' ),
						'migSkip'                 => __( 'Skip', 'segurium' ),
						'migPending'              => __( 'Planned feature', 'segurium' ),
						'migFeature'              => __( 'Feature', 'segurium' ),
						'migValue'                => __( 'Value', 'segurium' ),
						'migAction'               => __( 'Action', 'segurium' ),
						'migNote'                 => __( 'Note', 'segurium' ),
						'migItemsImported'        => __( 'items imported', 'segurium' ),
						'migItemsPending'         => __( 'features planned', 'segurium' ),
						'suppSubmitting'          => __( 'Submitting\u2026', 'segurium' ),
						'suppSuccess'             => __( 'Ticket submitted successfully.', 'segurium' ),
						'suppTicketRef'           => __( 'Your ticket reference:', 'segurium' ),
						'suppError'               => __( 'Failed to submit ticket. Please try again.', 'segurium' ),
						'suppFnNoFile'            => __( 'Please attach a file before submitting.', 'segurium' ),
						'suppFnTooLarge'          => __( 'Selected file exceeds the 100 MB limit.', 'segurium' ),
						'suppInvalidEmail'        => __( 'Please enter a valid reply-to email.', 'segurium' ),
						'suppMissingName'         => __( 'Please enter your name.', 'segurium' ),
						'reviewPromptError'       => __( 'Could not save your choice. Please try again.', 'segurium' ),
						'bfTitle'                 => __( 'Brute-Force Protection', 'segurium' ),
						'bfEnable'                => __( 'Enable brute-force protection', 'segurium' ),
						'bfMaxAttempts'           => __( 'Max failed attempts', 'segurium' ),
						'bfMaxAttemptsDesc'       => __( 'Number of failed login attempts allowed before the IP is locked out.', 'segurium' ),
						'bfCountWindow'           => __( 'Attempt window (seconds)', 'segurium' ),
						'bfCountWindowDesc'       => __( 'Time window in which failed attempts are counted toward the threshold.', 'segurium' ),
						'bfTier1Duration'         => __( 'Initial lockout duration (seconds)', 'segurium' ),
						'bfTier2Threshold'        => __( 'Lockouts before extended ban', 'segurium' ),
						'bfTier2Duration'         => __( 'Extended lockout duration (seconds)', 'segurium' ),
						'bfHistoryWindow'         => __( 'History window (seconds)', 'segurium' ),
						'bfProtectXmlrpc'         => __( 'Also protect XML-RPC (xmlrpc.php)', 'segurium' ),
						'bfHoneypot'              => __( 'Add honeypot field to login form', 'segurium' ),
						'bfActiveLockouts'        => __( 'Active Lockouts', 'segurium' ),
						'bfNoActiveLockouts'      => __( 'No IPs are currently locked out.', 'segurium' ),
						'bfUnlock'                => __( 'Unlock', 'segurium' ),
						'bfTier'                  => __( 'Tier', 'segurium' ),
						'bfIp'                    => __( 'IP', 'segurium' ),
						'bfCreated'               => __( 'Locked at', 'segurium' ),
						'bfExpires'               => __( 'Expires', 'segurium' ),
						'bfSettingsSaved'         => __( 'Settings saved.', 'segurium' ),
						'bfUnlockConfirm'         => __( 'Unlock this IP?', 'segurium' ),
						'bfLogRetention'          => __( 'Log retention (days)', 'segurium' ),
						'bfHcaptchaSection'       => __( 'hCaptcha', 'segurium' ),
						'bfHcaptchaEnable'        => __( 'Require hCaptcha after repeated failures', 'segurium' ),
						'bfHcaptchaSiteKey'       => __( 'hCaptcha site key', 'segurium' ),
						'bfHcaptchaSecretKey'     => __( 'hCaptcha secret key', 'segurium' ),
						'bfCaptchaThreshold'      => __( 'Show CAPTCHA after N failed attempts', 'segurium' ),
						'bfPresets'               => __( 'Presets:', 'segurium' ),
						'bfPresetLight'           => __( 'Light', 'segurium' ),
						'bfPresetRecommended'     => __( 'Recommended', 'segurium' ),
						'bfPresetStrict'          => __( 'Strict', 'segurium' ),
						'bfPresetsHint'           => __( 'Click a preset to fill the form, then Save.', 'segurium' ),
						'bfStatsTitle'            => __( 'Statistics', 'segurium' ),
						'bfStatsActiveLockouts'   => __( 'Active lockouts', 'segurium' ),
						'bfStatsAttempts24h'      => __( 'Attempts (24h)', 'segurium' ),
						'bfStatsLockouts24h'      => __( 'Lockouts (24h)', 'segurium' ),
						'bfStatsHoneypot24h'      => __( 'Honeypot hits (24h)', 'segurium' ),
						'bfStatsCaptcha24h'       => __( 'CAPTCHA failures (24h)', 'segurium' ),
						'bfStatsTopIps'           => __( 'Top attacking IPs (24h)', 'segurium' ),
						'bfStatsTopUsernames'     => __( 'Top targeted usernames (24h)', 'segurium' ),
						'bfStatsTopIpsEmpty'      => __( 'No attacking IPs in the last 24 hours.', 'segurium' ),
						'bfStatsTopUsersEmpty'    => __( 'No targeted usernames in the last 24 hours.', 'segurium' ),
						'bfLogTitle'              => __( 'Event log', 'segurium' ),
						'bfLogColumnTime'         => __( 'When', 'segurium' ),
						'bfLogColumnEvent'        => __( 'Event', 'segurium' ),
						'bfLogColumnIp'           => __( 'IP', 'segurium' ),
						'bfLogColumnUsername'     => __( 'Username', 'segurium' ),
						'bfLogColumnSurface'      => __( 'Surface', 'segurium' ),
						'bfLogColumnTier'         => __( 'Tier', 'segurium' ),
						'bfLogFilterAny'          => __( 'All events', 'segurium' ),
						'bfLogEmpty'              => __( 'No events recorded yet.', 'segurium' ),
						'bfLogPrev'               => __( 'Previous', 'segurium' ),
						'bfLogNext'               => __( 'Next', 'segurium' ),
						'bfLogPage'               => __( 'Page', 'segurium' ),
						'bfLogOf'                 => __( 'of', 'segurium' ),
						'bfEventAttempt'          => __( 'Attempt', 'segurium' ),
						'bfEventLockout'          => __( 'Lockout', 'segurium' ),
						'bfEventHoneypot'         => __( 'Honeypot', 'segurium' ),
						'bfEventUnlock'           => __( 'Unlock', 'segurium' ),
						'bfEventCaptchaFail'      => __( 'CAPTCHA failed', 'segurium' ),
						'bfSurfaceWpLogin'        => __( 'wp-login.php', 'segurium' ),
						'bfSurfaceXmlrpc'         => __( 'XML-RPC', 'segurium' ),
						'isLoading'               => __( 'Loading settings...', 'segurium' ),
						'isSaving'                => __( 'Saving...', 'segurium' ),
						'isSaved'                 => __( 'Settings saved.', 'segurium' ),
						'isSaveError'             => __( 'Failed to save settings.', 'segurium' ),
						'isLoadError'             => __( 'Failed to load settings.', 'segurium' ),
						'isEnableAllDone'         => __( 'All recommended settings enabled.', 'segurium' ),
						'scTitle'                 => __( 'Self-Check', 'segurium' ),
						'scRun'                   => __( 'Run Self-Check', 'segurium' ),
						'scRunning'               => __( 'Running...', 'segurium' ),
						'scNeverRun'              => __( 'Click Run Self-Check to grade your site.', 'segurium' ),
						/* translators: %s: human-readable time difference such as "5 mins" */
						'scLastRun'               => __( 'Last checked %s ago.', 'segurium' ),
						'scFix'                   => __( 'Fix', 'segurium' ),
						'scHowToFix'              => __( 'How to fix', 'segurium' ),
						'scHideFix'               => __( 'Hide details', 'segurium' ),
						'scFail'                  => __( 'fail', 'segurium' ),
						'scWarn'                  => __( 'warn', 'segurium' ),
						'scCategoryHeaders'       => __( 'HTTP Security Headers', 'segurium' ),
						'scCategoryDisclosure'    => __( 'Information Disclosure', 'segurium' ),
						'scCategoryHardening'     => __( 'WordPress Hardening', 'segurium' ),
						'scCategoryCookies'       => __( 'Cookie Security', 'segurium' ),
						'scCategoryMalware'       => __( 'Malware Protection', 'segurium' ),
						/* translators: 1: pass count, 2: warn count, 3: fail count */
						'scPassWarnFail'          => __( '%1$d pass, %2$d warn, %3$d fail', 'segurium' ),
						/* translators: %d: numeric score, always out of 100 */
						'scScoreOutOf'            => __( '%1$d/100', 'segurium' ),
						/* translators: 1: previous grade letter, 2: previous score, 3: new grade letter, 4: new score */
						'scChangedFromTo'         => __( 'Changed from %1$s (%2$d) to %3$s (%4$d).', 'segurium' ),
						'scNoChange'              => __( 'No change since last run.', 'segurium' ),
						/* translators: %s: error message returned by the self-ping */
						'scSelfPingError'         => __( 'Self-check could not reach your site: %s. Results are incomplete.', 'segurium' ),
						'scExtSH'                 => __( 'Verify with securityheaders.com', 'segurium' ),
						'scExtMO'                 => __( 'Verify with Mozilla Observatory', 'segurium' ),
					),
					'geoPending'     => $geo_pending,
					'fwPending'      => $fw_pending,
				)
			) . ';',
			'before'
		);

		// Bootstrap self-check payload so the tab can render cached state
		// without an initial round-trip. `historyEmpty` is
		// the authoritative cold-start signal for the JS auto-run — true
		// only when the `self_check_history` table has zero rows. Once
		// any check has been recorded the flag flips false forever and
		// the JS never auto-runs again.
		$sc      = Segurium_Self_Check::get_instance();
		$history = $sc->get_history();
		wp_add_inline_script(
			'segurium-self-check',
			'window.seguriumSelfCheck = ' . wp_json_encode(
				array(
					'last'         => $sc->get_last_result(),
					'history'      => $history,
					'historyEmpty' => empty( $history ),
				)
			) . ';',
			'before'
		);
	}

	/**
	 * Normalize a single scan-exclude line.
	 *
	 * The scanner matches patterns against paths relative to ABSPATH
	 * (after stripping the WordPress install root from each enumerated
	 * file). Any user-entered absolute path that lives under ABSPATH is
	 * therefore a silent no-op — the relative form is what the matcher
	 * actually sees. Rewrite such lines to their relative
	 * equivalent at save time. Lines we cannot map (absolute paths that
	 * are not under ABSPATH, plain wildcard patterns, relative paths) are
	 * returned untouched.
	 *
	 * @param string $line Raw line from the textarea.
	 * @return string Normalized line.
	 */
	public static function normalize_scan_exclude_pattern( $line ) {
		$trimmed = trim( (string) $line );
		if ( '' === $trimmed ) {
			return $line;
		}
		// Only rewrite absolute paths. Linux: leading "/", Windows: "C:\" or "C:/".
		$is_abs = ( '/' === $trimmed[0] )
			|| (bool) preg_match( '#^[A-Za-z]:[\\\\/]#', $trimmed );
		if ( ! $is_abs ) {
			return $line;
		}
		$wp_root   = Segurium_Path_Helpers::wp_root();
		$abspath   = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $wp_root ) : $wp_root;
		$abspath   = rtrim( $abspath, '/' ) . '/';
		$candidate = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $trimmed ) : $trimmed;
		if ( 0 === strpos( $candidate, $abspath ) ) {
			$relative = substr( $candidate, strlen( $abspath ) );
			if ( '' !== $relative ) {
				return $relative;
			}
		}
		return $line;
	}

	/**
	 * Get the list of scan exclusion patterns.
	 *
	 * @return array List of exclusion patterns.
	 */
	public function get_scan_exclusions() {
		// segurium_scan_exclude stays in wp_options per plan (small settings-array, capped/validated).
		$raw = Segurium_Storage::setting_get( 'segurium_scan_exclude', '' );
		if ( empty( $raw ) ) {
			return array();
		}
		$lines = explode( "\n", $raw );
		$clean = array();
		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line || '*' === $line ) {
				continue;
			}
			$clean[] = $line;
		}
		return $clean;
	}

	/**
	 * Check if the user has given CTI consent.
	 *
	 * @return bool True if CTI consent is given.
	 */
	public function has_cti_consent() {
		return Segurium_Storage::setting_get_bool( 'segurium_cti_consent' );
	}

	/**
	 * Check if the plugin is running in on-premise mode.
	 *
	 * @return bool True if on-premise mode is enabled.
	 */
	public function is_on_premise() {
		return Segurium_Storage::on_premise_mode();
	}

	/**
	 * Render the admin page.
	 *
	 * @return void
	 */
	public function render_admin_page() {
		if ( ! $this->has_cti_consent() ) {
			$this->render_consent_page();
		} else {
			$this->render_main_page();
		}
	}

	/**
	 * Canonical list of admin feature tabs whose panel is rendered inside
	 * `?page=segurium`. The `segurium_admin_tabs` filter lets extensions
	 * (e.g. the dev-only Scans tab) join the allow-list so their panel can
	 * be server-rendered on first paint when `?tab=` matches.
	 *
	 * @return string[]
	 */
	public static function admin_tabs() {
		$tabs = array(
			'self-check',
			'scanner',
			'integrity-scanner',
			'geo',
			'firewall',
			'bruteforce',
			'twofactor',
			'headers',
			'info-shield',
			'settings',
			'migration',
			'support',
			'plans',
		);

		$filtered = apply_filters( 'segurium_admin_tabs', $tabs );
		if ( ! is_array( $filtered ) ) {
			return $tabs;
		}

		$clean = array();
		foreach ( $filtered as $tab ) {
			if ( is_string( $tab ) && '' !== $tab && ! in_array( $tab, $clean, true ) ) {
				$clean[] = $tab;
			}
		}
		return $clean;
	}

	/**
	 * Resolve the active feature tab from `$_GET['tab']`, validated against
	 * {@see self::admin_tabs()}. Falls back to `self-check` on missing /
	 * unknown / non-string values.
	 *
	 * No nonce is required: the value is a read-only display selector, not
	 * a state-changing action — mirroring how core WP option pages encode
	 * their own tabs (`?tab=general` on Settings).
	 *
	 * @return string
	 */
	public static function current_tab() {
		// Read-only admin nav helper. Real cap enforcement is
		// upstream — WP routes admin pages through
		// `current_user_can( 'manage_options' )` before rendering this tab
		// strip — and the value is validated against an allow-list below.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only display selector, validated against an allow-list below.
		if ( ! isset( $_GET['tab'] ) || ! is_string( $_GET['tab'] ) ) {
			return 'self-check';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only display selector, validated against an allow-list below.
		$tab = sanitize_key( wp_unslash( $_GET['tab'] ) );
		return in_array( $tab, self::admin_tabs(), true ) ? $tab : 'self-check';
	}

	/**
	 * Build the canonical admin URL for a feature tab. Unknown slugs yield
	 * the bare admin URL (which resolves to the default tab).
	 *
	 * @param string $tab Tab slug from {@see self::admin_tabs()}.
	 * @return string
	 */
	public static function admin_tab_url( $tab ) {
		$base = menu_page_url( 'segurium', false );
		if ( '' === $base ) {
			// `menu_page_url` returns '' before `admin_menu` has fired.
			$base = admin_url( 'admin.php?page=segurium' );
		}
		if ( ! is_string( $tab ) || ! in_array( $tab, self::admin_tabs(), true ) ) {
			return $base;
		}
		return add_query_arg( 'tab', $tab, $base );
	}

	/**
	 * HTML captured from the admin-notice action chain, re-emitted inside
	 * the wrap by {@see self::render_main_page()} so WP core's notice mover
	 * finds notices already positioned.
	 *
	 * @var string
	 */
	private static $captured_notices_html = '';

	/**
	 * Buffer-level snapshot taken at `ob_start()`. The capture callback
	 * only closes the buffer if PHP is still on the same level — defends
	 * against another callback in the same priority window taking over
	 * output buffering on us, or a `wp_die()` short-circuit that leaves
	 * the buffer orphaned.
	 *
	 * @var int|null
	 */
	private static $notice_buffer_level = null;

	/**
	 * Attach the admin-notice capture window. Wired to
	 * `load-toplevel_page_segurium` so it only runs on our admin page.
	 * `user_admin_notices` and `network_admin_notices` are deliberately
	 * not subscribed — the top-level page hook never fires on those
	 * sub-admin contexts.
	 *
	 * @return void
	 */
	public function register_admin_notice_buffer() {
		add_action( 'admin_notices', array( __CLASS__, 'start_admin_notice_buffer' ), PHP_INT_MIN );
		add_action( 'all_admin_notices', array( __CLASS__, 'capture_admin_notice_buffer' ), PHP_INT_MAX );
	}

	/**
	 * Open the capture buffer before any notice callback runs.
	 *
	 * @return void
	 */
	public static function start_admin_notice_buffer() {
		if ( null !== self::$notice_buffer_level ) {
			return;
		}
		ob_start();
		self::$notice_buffer_level = ob_get_level();
	}

	/**
	 * Close the capture buffer after every notice callback has finished
	 * and stash the captured HTML.
	 *
	 * @return void
	 */
	public static function capture_admin_notice_buffer() {
		if ( null === self::$notice_buffer_level || ob_get_level() !== self::$notice_buffer_level ) {
			self::$notice_buffer_level = null;
			return;
		}
		$buf                         = ob_get_clean();
		self::$captured_notices_html = is_string( $buf ) ? $buf : '';
		self::$notice_buffer_level   = null;
	}

	/**
	 * Captured admin-notice HTML for re-emission inside the wrap. Reads
	 * are destructive: subsequent calls return an empty string so the
	 * captured payload cannot be accidentally double-emitted.
	 *
	 * @return string
	 */
	public static function consume_captured_notices_html() {
		$html                        = self::$captured_notices_html;
		self::$captured_notices_html = '';
		return $html;
	}

	/**
	 * Render the consent page.
	 *
	 * @return void
	 */
	private function render_consent_page() {
		?>
		<div class="wrap segurium-wrap">
			<div id="segurium-consent-panel" class="segurium-consent-panel">
				<h2><?php esc_html_e( 'External Service Disclosure', 'segurium' ); ?></h2>
				<p><?php esc_html_e( 'Segurium protects your site by working together with the Segurium cloud. When you enable it, Segurium exchanges data with our servers so it can detect malware, verify your files, and adapt protection to active threats.', 'segurium' ); ?></p>

				<p><strong><?php esc_html_e( 'What is sent:', 'segurium' ); ?></strong></p>
				<ul>
					<li><?php esc_html_e( 'File metadata: SHA-256 hash, path relative to your WordPress installation, size, modification time.', 'segurium' ); ?></li>
					<li><?php esc_html_e( 'File content — only when classification by hash alone is not conclusive, or when generating a clean replacement during cleanup.', 'segurium' ); ?></li>
					<li><?php esc_html_e( 'A randomly-generated installation identifier and basic site info (URL, name, WordPress version) used to associate requests with this install.', 'segurium' ); ?></li>
					<li><?php esc_html_e( 'Scan, cleanup, and security-settings events, so the cloud can keep your site protection in sync.', 'segurium' ); ?></li>
					<li><?php esc_html_e( 'Firewall events (blocked IPs, attack patterns) used to adapt protection across all Segurium-protected sites.', 'segurium' ); ?></li>
					<li><?php esc_html_e( 'The email address for security alerts: the WordPress admin email, or the one you enter below, together with your email alerts choice.', 'segurium' ); ?></li>
				</ul>

				<p><strong><?php esc_html_e( 'What is NOT sent:', 'segurium' ); ?></strong></p>
				<ul>
					<li><?php esc_html_e( 'Visitor analytics or personal data of users who visit your site.', 'segurium' ); ?></li>
					<li><?php esc_html_e( 'Database content, posts, comments, or media files.', 'segurium' ); ?></li>
					<li><?php esc_html_e( 'Files whose hash is already known to the cloud — only the hash leaves your server.', 'segurium' ); ?></li>
				</ul>

				<p><strong><?php esc_html_e( 'Where it is sent:', 'segurium' ); ?></strong> <?php esc_html_e( 'Segurium servers at cti.segurium.com.', 'segurium' ); ?></p>
				<p><strong><?php esc_html_e( 'Retention:', 'segurium' ); ?></strong> <?php esc_html_e( 'File samples uploaded for analysis are kept for up to 365 days and then removed by an automated nightly purge. A sample may be removed sooner once it has been reviewed.', 'segurium' ); ?></p>

				<p>
					<?php
					printf(
						/* translators: 1: opening link tag for Terms of Service, 2: closing link tag, 3: opening link tag for Privacy Policy, 4: closing link tag */
						esc_html__( 'By enabling scanning, you agree to the %1$sTerms of Service%2$s and %3$sPrivacy Policy%4$s.', 'segurium' ),
						'<a href="https://segurium.com/terms" target="_blank" rel="noopener noreferrer">',
						'</a>',
						'<a href="https://segurium.com/privacy" target="_blank" rel="noopener noreferrer">',
						'</a>'
					);
					?>
				</p>
				<?php $segurium_alerts_stored = Segurium_Storage::setting_get( Segurium_Alerts_Settings::OPTION_ENABLED, null ); ?>
				<div class="segurium-setting-row segurium-consent-alerts">
					<label>
						<input type="checkbox" id="segurium_consent_alerts_enabled" <?php checked( null === $segurium_alerts_stored || (bool) $segurium_alerts_stored ); ?>>
						<strong><?php esc_html_e( 'Notify me on malware findings and security threats on this website.', 'segurium' ); ?></strong>
					</label>
					<label for="segurium_consent_alerts_email" class="screen-reader-text"><?php esc_html_e( 'Alert email address', 'segurium' ); ?></label>
					<input
						type="email"
						id="segurium_consent_alerts_email"
						class="regular-text"
						placeholder="<?php echo esc_attr( (string) Segurium_Storage::setting_get( 'admin_email', '' ) ); ?>"
						value="<?php echo esc_attr( (string) Segurium_Storage::setting_get_string( Segurium_Alerts_Settings::OPTION_EMAIL ) ); ?>"
					/>
					<p class="description"><?php esc_html_e( 'One email per day at most, sent from support@segurium.com. You can change this later under Settings.', 'segurium' ); ?></p>
					<p class="description"><?php esc_html_e( 'Leave blank to use the WordPress site admin email.', 'segurium' ); ?></p>
				</div>
				<button id="segurium-accept-consent" class="button button-primary">
					<?php esc_html_e( 'I agree', 'segurium' ); ?>
				</button>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the main plugin page.
	 *
	 * @return void
	 */
	/**
	 * Tier read for the JS payload. Thin wrapper over
	 * `Segurium_Quota::plan_tier()` so the bootstrap reflects the same
	 * envelope-sourced state as every other renderer; defaults to Free
	 * until CTI confirms otherwise.
	 *
	 * @return string `free` | `pro`.
	 */
	private function plan_tier_from_envelope() {
		return Segurium_Quota::plan_tier();
	}

	/**
	 * Pre-rendered inner HTML for `.segurium-quota-readout`, mirroring
	 * what segurium-scan.js's renderQuotaReadout() produces. Reads the
	 * last cached CTI envelope (Segurium_Quota::cached_envelope()) so
	 * the counter is visible at first paint without a synchronous CTI
	 * round-trip; the JS still refreshes on tab activation and after
	 * every cleanup.
	 *
	 * Returns '' when the readout should stay hidden — Pro tier, no
	 * cached envelope yet, or a previously-cached fail-open placeholder.
	 *
	 * Gate strictly on the cached envelope's plan_tier rather
	 * than the `unlimited_cleanup` entitlement. Pro installs must show
	 * nothing about quotas anywhere in the plugin UI; plan_tier is the
	 * single source of truth for that decision (entitlements are derived
	 * from it and are therefore one indirection further from the contract
	 * the ticket states).
	 *
	 * @param bool $with_cta Attach the at-limit upgrade link. The Plans
	 *                       tab passes false — the Pro card beside it
	 *                       already carries the primary CTA, and a second
	 *                       one to the same destination competes with it.
	 * @return string Already-escaped HTML, or ''.
	 */
	private function quota_readout_inner_html( $with_cta = true ) {
		$parts = $this->quota_readout_parts( $with_cta );
		return $parts['html'];
	}

	/**
	 * Malicious files the operator has not dealt with yet, over the same
	 * recent window the scanner list defaults to, so the number on the
	 * card matches the one on the tab badge beside it.
	 *
	 * A storage error yields 0, which downgrades the card to the strip
	 * rather than claiming a threat count nobody measured. One grouped
	 * COUNT; the bootstrap and the server pre-render each pay for their
	 * own, rather than share a memo the page-lifetime singleton would
	 * carry past the request that filled it.
	 *
	 * @return int
	 */
	private function outstanding_threat_count() {
		if ( ! class_exists( 'Segurium_File_State' ) ) {
			return 0;
		}
		try {
			$counts = Segurium_File_State::get_counts( true );
		} catch ( Throwable $e ) {
			return 0;
		}
		return isset( $counts['malicious'] ) ? max( 0, (int) $counts['malicious'] ) : 0;
	}

	/**
	 * Readout body plus the shape it should take.
	 *
	 * Three states. Below the cap and at the cap with nothing
	 * outstanding both render the strip they have always rendered. The
	 * third — cap reached while malicious files are still on disk — is
	 * the one moment the plugin has refused work the operator is asking
	 * for, so it escalates to a card: a heading, the two numbers the
	 * install produced itself, a primary button and a secondary path.
	 *
	 * @param bool $with_cta Attach the at-limit upgrade affordance.
	 * @return array{html:string,card:bool}
	 */
	private function quota_readout_parts( $with_cta = true ) {
		$hidden = array(
			'html' => '',
			'card' => false,
		);
		if ( Segurium_Quota::PLAN_TIER_FREE !== Segurium_Quota::plan_tier() ) {
			return $hidden;
		}
		$env = Segurium_Quota::cached_envelope();
		if ( null === $env || ! empty( $env['fail_open'] ) ) {
			return $hidden;
		}

		$used   = (int) $env['used'];
		$limit  = (int) $env['limit'] > 0 ? (int) $env['limit'] : Segurium_Quota::DEFAULT_LIMIT;
		$window = (int) $env['window_days'] > 0 ? (int) $env['window_days'] : Segurium_Quota::DEFAULT_WINDOW_DAYS;

		if ( $used >= $limit ) {
			$next_slot_at = isset( $env['next_slot_at'] ) ? (int) $env['next_slot_at'] : 0;
			// ISO format is intentional: the JS refresh on tab activation
			// rewrites the readout with the browser's locale-formatted date,
			// so this string is only visible for the few hundred ms before
			// the AJAX response lands. Avoiding get_option('date_format')
			// keeps the storage-façade lint clean.
			$next_slot = $next_slot_at > 0 ? wp_date( 'Y-m-d', $next_slot_at ) : '—';
			/* translators: see seguriumScan.i18n.quotaReadoutAtLimit — kept identical so JS swap is seamless. */
			$copy = sprintf(
				/* translators: 1: cleanups used so far, 2: per-window cap (e.g., 3), 3: rolling window length in days (e.g., 30), 4: localized date when the next slot opens */
				__( '%1$d of %2$d cleanups used in the last %3$d days — next slot opens %4$s', 'segurium' ),
				$used,
				$limit,
				$window,
				$next_slot
			);
		} else {
			$copy = sprintf(
				/* translators: 1: cleanups used so far, 2: per-window cap (e.g., 3), 3: rolling window length in days (e.g., 30) */
				__( '%1$d of %2$d cleanups used in the last %3$d days', 'segurium' ),
				$used,
				$limit,
				$window
			);
		}

		$html = '<span>' . esc_html( $copy ) . '</span>';

		// Only attach the Upgrade-to-Pro CTA on the at-limit
		// branch. Rendering it at 0/3 is constant promotion (WP.org
		// Guideline 11). Mirrors segurium-scan.js renderQuotaReadout() so
		// the JS refresh on tab activation does not flip the CTA in or out.
		if ( $with_cta && $used >= $limit ) {
			$upgrade_url = class_exists( 'Segurium_Entitlements' )
				? Segurium_Entitlements::instance()->upgrade_url()
				: '';
			if ( '' !== $upgrade_url ) {
				$threats = $this->outstanding_threat_count();
				if ( $threats > 0 ) {
					return array(
						'html' => $this->quota_card_html( $used, $limit, $copy, $threats, $upgrade_url ),
						'card' => true,
					);
				}
				$html .= '<a class="segurium-quota-readout-cta" href="' . esc_url( $upgrade_url ) . '"'
					. ( Segurium_Entitlements::is_offsite_url( $upgrade_url ) ? ' target="_blank" rel="noopener noreferrer"' : '' )
					. '>'
					. esc_html__( 'Upgrade to Pro', 'segurium' )
					. '</a>';
			}
		}

		return array(
			'html' => $html,
			'card' => false,
		);
	}

	/**
	 * Card body for the at-limit state. Every string here already
	 * ships — the heading comes from the paywall modal, the threat line
	 * from the scanner's own banner, the guarantee from the Plans tab.
	 * What changes is hierarchy, not vocabulary.
	 *
	 * Kept byte-compatible with the branch of segurium-scan.js's
	 * renderQuotaReadout() that rebuilds this node, so a tab switch does
	 * not repaint the card into something else.
	 *
	 * @param int    $used        Cleanups consumed in the window.
	 * @param int    $limit       Per-window cap.
	 * @param string $usage_copy  Rendered at-limit counter line.
	 * @param int    $threats     Malicious files still outstanding.
	 * @param string $upgrade_url Destination for the primary button.
	 * @return string
	 */
	private function quota_card_html( $used, $limit, $usage_copy, $threats, $upgrade_url ) {
		$threat_copy = sprintf(
			/* translators: %d: number of malicious files still needing attention */
			__( '%d threats still need your attention', 'segurium' ),
			$threats
		);

		$offsite = class_exists( 'Segurium_Entitlements' ) && Segurium_Entitlements::is_offsite_url( $upgrade_url );

		return '<div class="segurium-quota-card__body">'
			. '<h3 class="segurium-quota-card__title">' . esc_html__( 'Cleanup quota reached', 'segurium' ) . '</h3>'
			. '<p class="segurium-quota-card__threats">' . esc_html( $threat_copy ) . '</p>'
			. '<p class="segurium-quota-card__usage">' . esc_html( $usage_copy ) . '</p>'
			. self::quota_card_meter_html( $used, $limit )
			. '</div>'
			. '<div class="segurium-quota-card__actions">'
			. '<p class="segurium-quota-card__buttons">'
				. '<a class="button button-primary button-hero segurium-quota-readout-cta" href="' . esc_url( $upgrade_url ) . '"'
					. ( $offsite ? ' target="_blank" rel="noopener noreferrer"' : '' ) . '>'
					. esc_html__( 'Upgrade to Pro', 'segurium' )
				. '</a>'
				. '<a class="segurium-quota-card__secondary" href="' . esc_url( self::admin_tab_url( 'plans' ) ) . '">'
					. esc_html__( 'Plans', 'segurium' )
				. '</a>'
			. '</p>'
			. '<p class="segurium-quota-card__guarantee">' . esc_html__( '14-day money-back guarantee.', 'segurium' ) . '</p>'
			. '</div>';
	}

	/**
	 * One block per cleanup slot in the window, spent ones filled. The
	 * counter line above it already states the same two numbers, so the
	 * blocks carry no text of their own.
	 *
	 * Skipped entirely past MAX_QUOTA_METER_SLOTS — a row of forty
	 * blocks reads as a texture rather than a count.
	 *
	 * @param int $used  Cleanups consumed in the window.
	 * @param int $limit Per-window cap.
	 * @return string
	 */
	private static function quota_card_meter_html( $used, $limit ) {
		if ( $limit < 1 || $limit > self::MAX_QUOTA_METER_SLOTS ) {
			return '';
		}
		$slots = '';
		for ( $i = 0; $i < $limit; $i++ ) {
			$slots .= '<span class="segurium-quota-card__slot' . ( $i < $used ? ' is-spent' : '' ) . '"></span>';
		}
		return '<span class="segurium-quota-card__meter">' . $slots . '</span>';
	}

	/**
	 * Render a status-card `<dd>` for a daily-refreshed timestamp with a
	 * freshness dashicon. Stale also covers the `0`/never-updated case.
	 *
	 * @param int $ts             Unix timestamp of the last update (0 if never).
	 * @param int $max_fresh_secs Healthy upper bound; older = stale.
	 * @return void
	 */
	private function render_status_freshness_dd( $ts, $max_fresh_secs ) {
		$is_fresh = $ts > 0 && ( time() - $ts ) <= $max_fresh_secs;
		if ( $is_fresh ) {
			$icon  = 'dashicons-yes-alt';
			$class = 'segurium-status-fresh';
			$title = __( 'Up to date', 'segurium' );
		} else {
			$icon  = 'dashicons-warning';
			$class = 'segurium-status-stale';
			$title = $ts > 0
				? __( 'Stale — last refresh exceeded the daily window', 'segurium' )
				: __( 'Never updated on this site yet', 'segurium' );
		}
		?>
		<dd class="<?php echo esc_attr( $class ); ?>">
			<span
				class="dashicons <?php echo esc_attr( $icon ); ?> segurium-status-icon"
				title="<?php echo esc_attr( $title ); ?>"
				aria-label="<?php echo esc_attr( $title ); ?>"
			></span>
			<?php echo $ts > 0 ? esc_html( wp_date( 'Y-m-d H:i', $ts ) ) : '&mdash;'; ?>
		</dd>
		<?php
	}

	/**
	 * Render the main plugin page.
	 *
	 * @return void
	 */
	private function render_main_page() {
		// Tier class drives Pro-affordance visibility (badge,
		// upgrade CTAs) without per-element PHP branching. Default Free —
		// Pro is granted only when Entitlements confirms.
		$is_pro               = ( class_exists( 'Segurium_Entitlements' )
			&& Segurium_Entitlements::instance()->can( 'unlimited_cleanup' ) );
		$tier_class           = $is_pro ? 'segurium--pro' : 'segurium--free';
		$quota_readout_parts  = $this->quota_readout_parts();
		$quota_readout_html   = $quota_readout_parts['html'];
		$quota_readout_class  = 'segurium-quota-readout' . ( $quota_readout_parts['card'] ? ' segurium-quota-readout--card' : '' );
		$quota_readout_plan   = $this->quota_readout_inner_html( false );
		$active_tab           = self::current_tab();
		$segurium_nav_class   = function ( $feature ) use ( $active_tab ) {
			return 'segurium-nav-item' . ( $feature === $active_tab ? ' segurium-nav-item--active' : '' );
		};
		$segurium_panel_style = function ( $feature ) use ( $active_tab ) {
			return $feature === $active_tab ? 'block' : 'none';
		};
		?>
		<div class="wrap segurium-wrap <?php echo esc_attr( $tier_class ); ?>">
			<div class="segurium-banner">
				<img class="segurium-banner-logo" src="<?php echo esc_url( SEGURIUM_PLUGIN_URL . 'assets/img/brand/mark.svg' ); ?>" alt="" aria-hidden="true" width="32" height="32" />
				<span class="segurium-banner-title"><?php esc_html_e( 'Segurium', 'segurium' ); ?></span>
				<span class="segurium-banner-tagline"><?php esc_html_e( 'WordPress Security', 'segurium' ); ?></span>
			</div>
			<hr class="wp-header-end" style="display:none;" />
			<?php echo wp_kses_post( self::consume_captured_notices_html() ); ?>
			<div class="segurium-layout">
				<div class="segurium-main">
					<div class="segurium-nav">
						<a href="<?php echo esc_url( self::admin_tab_url( 'self-check' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'self-check' ) ); ?>" data-feature="self-check">
							<span class="dashicons dashicons-yes-alt segurium-nav-icon-dashicon"></span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Self-Check', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'scanner' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'scanner' ) ); ?>" data-feature="scanner">
							<span class="segurium-nav-icon">&#x1F50D;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Malware Scanner', 'segurium' ); ?></span>
						</a>
						<?php
						/**
						 * Diagnostic-only nav items injected after the Scanner tab.
						 * The Scans tab subscribes from plugin/dev/ and is absent
						 * in the production ZIP (see plugin/.distignore). Receives
						 * the resolved active tab so subscribers can mark themselves
						 * active without re-deriving it.
						 */
						do_action( 'segurium_admin_nav_after_scanner', $active_tab );
						?>
						<a href="<?php echo esc_url( self::admin_tab_url( 'integrity-scanner' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'integrity-scanner' ) ); ?>" data-feature="integrity-scanner">
							<span class="segurium-nav-icon">&#x1F9E9;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Integrity', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'geo' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'geo' ) ); ?>" data-feature="geo">
							<span class="segurium-nav-icon">&#x1F310;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'GEO Blocking', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'firewall' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'firewall' ) ); ?>" data-feature="firewall">
							<span class="segurium-nav-icon">&#x1F525;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Firewall', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'bruteforce' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'bruteforce' ) ); ?>" data-feature="bruteforce">
							<span class="segurium-nav-icon">&#x1F510;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Brute-Force', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'twofactor' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'twofactor' ) ); ?>" data-feature="twofactor">
							<span class="segurium-nav-icon">&#x1F511;</span>
							<span class="segurium-nav-label"><?php esc_html_e( '2FA', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'headers' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'headers' ) ); ?>" data-feature="headers">
							<span class="segurium-nav-icon">&#x1F6E1;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Headers', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'info-shield' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'info-shield' ) ); ?>" data-feature="info-shield">
							<span class="dashicons dashicons-shield segurium-nav-icon-dashicon"></span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Info Shield', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'settings' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'settings' ) ); ?>" data-feature="settings">
							<span class="segurium-nav-icon">&#x2699;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Settings', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'migration' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'migration' ) ); ?>" data-feature="migration">
							<span class="segurium-nav-icon">&#x21C6;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Migration', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'support' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'support' ) ); ?>" data-feature="support">
							<span class="segurium-nav-icon">&#x2753;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Support', 'segurium' ); ?></span>
						</a>
						<a href="<?php echo esc_url( self::admin_tab_url( 'plans' ) ); ?>" class="<?php echo esc_attr( $segurium_nav_class( 'plans' ) ); ?>" data-feature="plans">
							<span class="segurium-nav-icon">&#x1F4B3;</span>
							<span class="segurium-nav-label"><?php esc_html_e( 'Plans', 'segurium' ); ?></span>
						</a>
					</div>
					<?php
					/**
					 * Diagnostic-only feature panels rendered before the Scanner
					 * panel. The Scans tab subscribes from plugin/dev/ and is
					 * absent in the production ZIP. Receives the resolved active
					 * tab so subscribers can render their panel visible on first
					 * paint.
					 */
					do_action( 'segurium_admin_panel_before_scanner', $active_tab );
					?>
					<div class="segurium-feature" id="segurium-feature-scanner" style="display:<?php echo esc_attr( $segurium_panel_style( 'scanner' ) ); ?>;">
						<?php // Free-only quota readout. Pre-rendered from the last cached CTI envelope (Segurium_Quota::cached_envelope) so it shows at first paint; segurium-scan.js refreshes on tab activation. Hidden when no cache, when Pro, or when the cache is fail-open. ?>
						<div id="segurium-quota-readout" class="<?php echo esc_attr( $quota_readout_class ); ?>"<?php echo '' === $quota_readout_html ? ' hidden' : ''; ?>><?php echo wp_kses_post( $quota_readout_html ); ?></div>
						<?php // Host-environment warnings. Populated by JS from seguriumScan.envWarnings on page load — kept hidden when the array is empty. ?>
						<div id="segurium-env-warnings" class="segurium-env-warnings" hidden></div>
						<div class="segurium-ss-scan-area">
							<button id="segurium-ss-scan-btn" class="button button-primary">
								<?php esc_html_e( 'Scan', 'segurium' ); ?>
							</button>
							<?php // Surface a "Stop" affordance during an active scan so the user can clear a stuck/abandoned scan without waiting for the watchdog. JS toggles visibility off the polling state. ?>
							<button id="segurium-ss-stop-btn" class="button" hidden>
								<?php esc_html_e( 'Stop scan', 'segurium' ); ?>
							</button>
							<?php
							// Fix All is available on every install. The button stays
							// disabled until findings exist; clicks consume the
							// per-installation cleanup quota and surface the upsell
							// modal only when the cloud returns paywall_quota_exceeded.
							?>
							<button id="segurium-ss-fix-all-btn" class="button" disabled>
								<?php esc_html_e( 'Fix all', 'segurium' ); ?>
							</button>
							<span id="segurium-ss-scan-status" class="segurium-ss-scan-status"></span>
							<div id="segurium-ss-progress-wrap" class="segurium-progress-bar-wrap" style="display:none;">
								<div id="segurium-ss-progress-bar" class="segurium-progress-bar"></div>
								<span id="segurium-ss-progress-label" class="segurium-progress-bar-label" aria-hidden="true"></span>
							</div>
						</div>
						<div class="segurium-ss-tabs" id="segurium-ss-tabs" role="tablist">
							<button type="button" class="segurium-ss-tab segurium-ss-tab--malicious is-active" data-filter="malicious" role="tab" aria-selected="true">
								<span class="segurium-ss-tab-label"><?php esc_html_e( 'Malicious', 'segurium' ); ?></span>
								<span class="segurium-ss-tab-count" data-count="malicious">0</span>
							</button>
							<button type="button" class="segurium-ss-tab" data-filter="all" role="tab" aria-selected="false">
								<span class="segurium-ss-tab-label"><?php esc_html_e( 'All', 'segurium' ); ?></span>
								<span class="segurium-ss-tab-count" data-count="all">0</span>
							</button>
							<button type="button" class="segurium-ss-tab" data-filter="cleaned" role="tab" aria-selected="false">
								<span class="segurium-ss-tab-label"><?php esc_html_e( 'Cleaned', 'segurium' ); ?></span>
								<span class="segurium-ss-tab-count" data-count="cleaned">0</span>
							</button>
							<button type="button" class="segurium-ss-tab" data-filter="fixed" role="tab" aria-selected="false">
								<span class="segurium-ss-tab-label"><?php esc_html_e( 'Fixed', 'segurium' ); ?></span>
								<span class="segurium-ss-tab-count" data-count="fixed">0</span>
							</button>
							<button type="button" class="segurium-ss-tab" data-filter="ignored" role="tab" aria-selected="false">
								<span class="segurium-ss-tab-label"><?php esc_html_e( 'Ignored', 'segurium' ); ?></span>
								<span class="segurium-ss-tab-count" data-count="ignored">0</span>
							</button>
							<span class="segurium-ss-threat-banner" id="segurium-ss-threat-banner" aria-live="polite"></span>
						</div>
						<table class="widefat segurium-threat-table segurium-server-state-table">
							<thead>
								<tr>
									<th><?php esc_html_e( 'File', 'segurium' ); ?></th>
									<th><?php esc_html_e( 'State', 'segurium' ); ?></th>
									<th><?php esc_html_e( 'Date', 'segurium' ); ?></th>
									<th><?php esc_html_e( 'Actions', 'segurium' ); ?></th>
								</tr>
							</thead>
							<tbody id="segurium-server-state-tbody">
								<?php // Skeleton placeholder rows (replaced by renderServerState() on first AJAX render). ?>
								<?php for ( $segurium_skel_i = 0; $segurium_skel_i < 6; $segurium_skel_i++ ) : ?>
									<tr class="segurium-skeleton-row" aria-hidden="true">
										<td><span class="segurium-skeleton segurium-skeleton--wide"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--short"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--short"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--mid"></span></td>
									</tr>
								<?php endfor; ?>
							</tbody>
						</table>
						<div class="segurium-server-state-toolbar">
							<label class="segurium-ss-recent-label">
								<input type="checkbox" id="segurium-ss-recent-only" checked>
								<?php esc_html_e( 'Show recent only (14 days)', 'segurium' ); ?>
							</label>
							<div id="segurium-server-state-pagination" class="segurium-pagination"></div>
							<span class="segurium-ss-per-page-wrap">
								<select id="segurium-ss-per-page">
									<option value="20" selected>20</option>
									<option value="50">50</option>
									<option value="100">100</option>
									<option value="1000">1000</option>
								</select>
								<?php esc_html_e( 'per page', 'segurium' ); ?>
							</span>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-integrity-scanner" style="display:<?php echo esc_attr( $segurium_panel_style( 'integrity-scanner' ) ); ?>;">
						<?php // Same Free-tier quota readout as the malware scanner panel — pre-rendered from cache so it shows at first paint. ?>
						<div class="<?php echo esc_attr( $quota_readout_class ); ?>"<?php echo '' === $quota_readout_html ? ' hidden' : ''; ?>><?php echo wp_kses_post( $quota_readout_html ); ?></div>
						<?php // Same env-warnings banner as the malware scanner panel; populated by JS from seguriumScan.envWarnings. ?>
						<div class="segurium-env-warnings" hidden></div>
						<div class="segurium-is-scan-area">
							<button id="segurium-is-scan-btn" class="button button-primary">
								<?php esc_html_e( 'Scan', 'segurium' ); ?>
							</button>
							<?php // Stop button mirrors the malware scanner — lets users clear a stuck integrity scan. ?>
							<button id="segurium-is-stop-btn" class="button" hidden>
								<?php esc_html_e( 'Stop scan', 'segurium' ); ?>
							</button>
							<?php // Fix All on the integrity panel is available on every install; clicks hit the cloud cleanup quota and surface the upsell modal only when the cloud returns paywall_quota_exceeded. ?>
							<button id="segurium-is-fix-all-btn" class="button" disabled>
								<?php esc_html_e( 'Fix all', 'segurium' ); ?>
							</button>
							<span id="segurium-is-scan-status" class="segurium-ss-scan-status"></span>
							<div id="segurium-is-progress-wrap" class="segurium-progress-bar-wrap" style="display:none;">
								<div id="segurium-is-progress-bar" class="segurium-progress-bar"></div>
								<span id="segurium-is-progress-label" class="segurium-progress-bar-label" aria-hidden="true"></span>
							</div>
						</div>
						<table class="widefat segurium-threat-table segurium-integrity-state-table">
							<thead>
								<tr>
									<th style="width:30px;"></th>
									<th><?php esc_html_e( 'Component', 'segurium' ); ?></th>
									<th><?php esc_html_e( 'Status', 'segurium' ); ?></th>
									<th><?php esc_html_e( 'Files', 'segurium' ); ?></th>
									<th><?php esc_html_e( 'Last Scanned', 'segurium' ); ?></th>
									<th><?php esc_html_e( 'Actions', 'segurium' ); ?></th>
								</tr>
							</thead>
							<tbody id="segurium-integrity-state-tbody">
								<?php // Skeleton placeholder rows (replaced by renderIntegrityState() on first AJAX render). ?>
								<?php for ( $segurium_skel_i = 0; $segurium_skel_i < 6; $segurium_skel_i++ ) : ?>
									<tr class="segurium-skeleton-row" aria-hidden="true">
										<td><span class="segurium-skeleton segurium-skeleton--short"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--wide"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--short"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--short"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--short"></span></td>
										<td><span class="segurium-skeleton segurium-skeleton--mid"></span></td>
									</tr>
								<?php endfor; ?>
							</tbody>
						</table>
						<div class="segurium-server-state-toolbar">
							<div id="segurium-integrity-state-pagination" class="segurium-pagination"></div>
							<span class="segurium-ss-per-page-wrap">
								<select id="segurium-is-per-page">
									<option value="20" selected>20</option>
									<option value="50">50</option>
									<option value="100">100</option>
									<option value="1000">1000</option>
								</select>
								<?php esc_html_e( 'per page', 'segurium' ); ?>
							</span>
						</div>
					</div>
					<div id="segurium-confirm-modal" style="display:none;" role="dialog" aria-modal="true">
						<div class="segurium-diff-overlay"></div>
						<div class="segurium-diff-box">
							<div class="segurium-diff-header">
								<span id="segurium-confirm-title" class="segurium-diff-title"></span>
								<button id="segurium-confirm-close" class="segurium-diff-close" aria-label="<?php esc_attr_e( 'Close', 'segurium' ); ?>">&times;</button>
							</div>
							<div id="segurium-confirm-content" class="segurium-diff-content" style="max-height:60vh; overflow-y:auto;"></div>
							<div style="padding:12px; text-align:right; border-top:1px solid #dcdcde;">
								<button id="segurium-confirm-cancel" class="button"><?php esc_html_e( 'Cancel', 'segurium' ); ?></button>
								<button id="segurium-confirm-ok" class="button button-primary" style="margin-left:8px;"></button>
							</div>
						</div>
					</div>
					<div id="segurium-diff-modal" style="display:none;" role="dialog" aria-modal="true">
						<div class="segurium-diff-overlay"></div>
						<div class="segurium-diff-box">
							<div class="segurium-diff-header">
								<code id="segurium-diff-title" class="segurium-diff-title"></code>
								<button id="segurium-diff-close" class="segurium-diff-close" aria-label="<?php esc_attr_e( 'Close', 'segurium' ); ?>">&times;</button>
							</div>
							<div id="segurium-diff-content" class="segurium-diff-content"></div>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-geo" style="display:<?php echo esc_attr( $segurium_panel_style( 'geo' ) ); ?>;">
						<div id="segurium-geo-pending-banner" class="segurium-geo-pending-banner" style="display:none;">
							<div class="segurium-geo-pending-inner">
								<span class="segurium-geo-pending-msg">
									&#x23F1; <?php esc_html_e( 'Settings applied. Confirm to keep, or changes revert in', 'segurium' ); ?>
									<strong id="segurium-geo-countdown">60</strong><?php esc_html_e( 's.', 'segurium' ); ?>
								</span>
								<div class="segurium-geo-pending-btns">
									<button id="segurium-geo-confirm-btn" class="button button-primary button-small"><?php esc_html_e( 'Confirm', 'segurium' ); ?></button>
									<button id="segurium-geo-revert-btn" class="button button-small"><?php esc_html_e( 'Revert', 'segurium' ); ?></button>
								</div>
							</div>
						</div>
						<div class="segurium-geo-body">
							<div class="segurium-geo-config">
								<div class="segurium-setting-row">
									<label>
										<input type="checkbox" id="segurium-geo-enabled">
										<strong><?php esc_html_e( 'Enable Geo-Blocking', 'segurium' ); ?></strong>
									</label>
								</div>
								<div id="segurium-geo-settings-body">
								<div class="segurium-setting-row">
									<label><strong><?php esc_html_e( 'Blocking Mode', 'segurium' ); ?></strong></label>
									<div class="segurium-geo-mode-toggle">
										<label class="segurium-geo-mode-option">
											<input type="radio" name="segurium-geo-mode" id="segurium-geo-mode-block" value="block" checked>
											<?php esc_html_e( 'Block specific countries', 'segurium' ); ?>
										</label>
										<label class="segurium-geo-mode-option">
											<input type="radio" name="segurium-geo-mode" id="segurium-geo-mode-allow" value="allow">
											<?php esc_html_e( 'Allow only specific countries', 'segurium' ); ?>
										</label>
									</div>
								</div>
								<div class="segurium-setting-row">
									<label id="segurium-geo-countries-label"><strong><?php esc_html_e( 'Blocked Countries', 'segurium' ); ?></strong></label>
									<div class="segurium-geo-regions">
										<button type="button" class="segurium-geo-region-btn" data-region="eu"><?php esc_html_e( 'EU', 'segurium' ); ?></button>
										<button type="button" class="segurium-geo-region-btn" data-region="americas"><?php esc_html_e( 'Americas', 'segurium' ); ?></button>
										<button type="button" class="segurium-geo-region-btn" data-region="asia_pacific"><?php esc_html_e( 'Asia-Pacific', 'segurium' ); ?></button>
										<button type="button" class="segurium-geo-region-btn" data-region="africa"><?php esc_html_e( 'Africa', 'segurium' ); ?></button>
										<button type="button" class="segurium-geo-region-btn" data-region="middle_east"><?php esc_html_e( 'Middle East', 'segurium' ); ?></button>
										<button type="button" class="segurium-geo-region-btn segurium-geo-region-btn--risk" data-region="high_risk"><?php esc_html_e( 'High-Risk', 'segurium' ); ?></button>
									</div>
									<p class="description" id="segurium-geo-countries-desc"><?php esc_html_e( 'Type a country name or ISO code to add it to the block list.', 'segurium' ); ?></p>
									<div class="segurium-geo-picker">
										<div id="segurium-geo-tags" class="segurium-geo-tags"></div>
										<div class="segurium-geo-input-wrap">
											<input type="text" id="segurium-geo-country-input" class="regular-text"
												placeholder="<?php esc_attr_e( 'Search countries…', 'segurium' ); ?>" autocomplete="off">
											<div id="segurium-geo-country-dropdown" class="segurium-geo-dropdown" style="display:none;"></div>
										</div>
									</div>
								</div>
								<div class="segurium-setting-row">
									<label for="segurium-geo-block-action"><strong><?php esc_html_e( 'Block Action', 'segurium' ); ?></strong></label>
									<select id="segurium-geo-block-action">
										<option value="deny_403"><?php esc_html_e( 'Return 403 Forbidden', 'segurium' ); ?></option>
										<option value="redirect"><?php esc_html_e( 'Redirect to URL', 'segurium' ); ?></option>
										<option value="silent_drop"><?php esc_html_e( 'Silent drop (no response)', 'segurium' ); ?></option>
									</select>
									<div id="segurium-geo-redirect-row" style="display:none; margin-top:8px;">
										<input type="url" id="segurium-geo-redirect-url" class="regular-text" placeholder="https://example.com">
									</div>
								</div>
								</div><!-- #segurium-geo-settings-body -->
								<p class="segurium-geo-save-row">
									<button id="segurium-geo-save-btn" class="button button-primary"><?php esc_html_e( 'Save', 'segurium' ); ?></button>
									<span id="segurium-geo-save-status" class="segurium-geo-save-status"></span>
								</p>
							</div>
							<div class="segurium-geo-aside">
								<div id="segurium-geo-stats-section" class="segurium-geo-stats-card" style="display:none;">
									<h3><?php esc_html_e( 'Blocked Requests', 'segurium' ); ?></h3>
									<table class="widefat striped">
										<thead>
											<tr>
												<th><?php esc_html_e( 'Country', 'segurium' ); ?></th>
												<th><?php esc_html_e( 'Requests', 'segurium' ); ?></th>
											</tr>
										</thead>
										<tbody id="segurium-geo-stats-tbody"></tbody>
									</table>
								</div>
							</div>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-firewall" style="display:<?php echo esc_attr( $segurium_panel_style( 'firewall' ) ); ?>;">
						<div id="segurium-fw-pending-banner" class="segurium-geo-pending-banner" style="display:none;">
							<div class="segurium-geo-pending-inner">
								<span class="segurium-geo-pending-msg">
									&#x23F1; <?php esc_html_e( 'Settings applied. Confirm to keep, or changes revert in', 'segurium' ); ?>
									<strong id="segurium-fw-countdown">60</strong><?php esc_html_e( 's.', 'segurium' ); ?>
								</span>
								<div class="segurium-geo-pending-btns">
									<button id="segurium-fw-confirm-btn" class="button button-primary button-small"><?php esc_html_e( 'Confirm', 'segurium' ); ?></button>
									<button id="segurium-fw-revert-btn" class="button button-small"><?php esc_html_e( 'Revert', 'segurium' ); ?></button>
								</div>
							</div>
						</div>
						<div class="segurium-geo-body">
							<div class="segurium-geo-config">
								<div class="segurium-setting-row">
									<label>
										<input type="checkbox" id="segurium-fw-enabled">
										<strong><?php esc_html_e( 'Enable Firewall', 'segurium' ); ?></strong>
									</label>
								</div>
								<div id="segurium-fw-settings-body">
									<div class="segurium-setting-row">
										<label><strong><?php esc_html_e( 'Mode', 'segurium' ); ?></strong></label>
										<div class="segurium-geo-mode-toggle">
											<label class="segurium-geo-mode-option">
												<input type="radio" name="segurium-fw-mode" value="deny_list" checked>
												<?php esc_html_e( 'Allow everything except…', 'segurium' ); ?>
											</label>
											<label class="segurium-geo-mode-option">
												<input type="radio" name="segurium-fw-mode" value="allow_list">
												<?php esc_html_e( 'Deny everything except…', 'segurium' ); ?>
											</label>
										</div>
									</div>
									<div class="segurium-setting-row">
										<label id="segurium-fw-ip-list-label" for="segurium-fw-ip-list"><strong><?php esc_html_e( 'Blocked IPs / CIDRs', 'segurium' ); ?></strong></label>
										<p class="description" id="segurium-fw-ip-list-desc"><?php esc_html_e( 'These IPs are always blocked. One entry per line. Accepts IPv4, IPv6, and CIDR ranges.', 'segurium' ); ?></p>
										<textarea id="segurium-fw-ip-list" class="segurium-textarea-code" rows="5" placeholder="1.2.3.4&#10;10.0.0.0/8&#10;2001:db8::/32"></textarea>
									</div>
									<div class="segurium-setting-row">
										<label for="segurium-fw-proxies"><strong><?php esc_html_e( 'Custom Trusted Proxy IPs / CIDRs', 'segurium' ); ?></strong></label>
										<div id="segurium-tp-status" class="segurium-tp-status" style="margin:6px 0;padding:6px 10px;background:#f0f0f1;border-left:3px solid #2271b1;font-size:13px;">
											<span id="segurium-tp-status-text"><?php esc_html_e( 'Loading auto-detected proxy status...', 'segurium' ); ?></span>
										</div>
										<p class="description"><?php esc_html_e( 'Additional proxy IPs beyond the auto-detected list, one per line. Leave empty if all your proxies are covered above.', 'segurium' ); ?></p>
										<textarea id="segurium-fw-proxies" class="segurium-textarea-code" rows="3" placeholder="103.21.244.0/22&#10;103.22.200.0/22"></textarea>
									</div>
								</div><!-- #segurium-fw-settings-body -->
								<p>
									<button id="segurium-fw-save-btn" class="button button-primary"><?php esc_html_e( 'Save', 'segurium' ); ?></button>
									<span id="segurium-fw-save-status" class="segurium-geo-save-status"></span>
								</p>
							</div>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-bruteforce" style="display:<?php echo esc_attr( $segurium_panel_style( 'bruteforce' ) ); ?>;">
						<div class="segurium-bf-body">
							<div class="segurium-bf-config">
								<div class="segurium-setting-row">
									<label>
										<input type="checkbox" id="segurium-bf-enabled">
										<strong><?php esc_html_e( 'Enable brute-force protection', 'segurium' ); ?></strong>
									</label>
									<p class="description"><?php esc_html_e( 'Tracks failed login attempts and locks out IPs after a configurable threshold. Reuses the firewall allow-list for trusted IPs.', 'segurium' ); ?></p>
								</div>
								<div id="segurium-bf-settings-body">
									<fieldset class="segurium-bf-mode">
										<legend class="segurium-bf-mode-legend"><?php esc_html_e( 'Settings:', 'segurium' ); ?></legend>
										<label class="segurium-bf-mode-option">
											<input type="radio" name="segurium-bf-mode" value="recommended" id="segurium-bf-mode-recommended">
											<span><strong><?php esc_html_e( 'Recommended', 'segurium' ); ?></strong> &mdash; <?php esc_html_e( 'safe defaults; settings are locked.', 'segurium' ); ?></span>
										</label>
										<label class="segurium-bf-mode-option">
											<input type="radio" name="segurium-bf-mode" value="custom" id="segurium-bf-mode-custom">
											<span><strong><?php esc_html_e( 'Custom', 'segurium' ); ?></strong> &mdash; <?php esc_html_e( 'edit every setting yourself.', 'segurium' ); ?></span>
										</label>
									</fieldset>
									<div id="segurium-bf-locked-section">
									<div class="segurium-setting-row">
										<label for="segurium-bf-max-attempts"><strong><?php esc_html_e( 'Max failed attempts', 'segurium' ); ?></strong></label>
										<input type="number" id="segurium-bf-max-attempts" min="2" class="small-text">
										<p class="description"><?php esc_html_e( 'Number of failed login attempts allowed before the IP is locked out.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row">
										<label for="segurium-bf-count-window"><strong><?php esc_html_e( 'Attempt window (seconds)', 'segurium' ); ?></strong></label>
										<input type="number" id="segurium-bf-count-window" min="60" class="small-text">
										<p class="description"><?php esc_html_e( 'Time window in which failed attempts are counted toward the threshold.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row">
										<label for="segurium-bf-tier1-duration"><strong><?php esc_html_e( 'Initial lockout duration (seconds)', 'segurium' ); ?></strong></label>
										<input type="number" id="segurium-bf-tier1-duration" min="60" class="small-text">
									</div>
									<div class="segurium-setting-row">
										<label for="segurium-bf-tier2-threshold"><strong><?php esc_html_e( 'Lockouts before extended ban', 'segurium' ); ?></strong></label>
										<input type="number" id="segurium-bf-tier2-threshold" min="1" class="small-text">
										<p class="description"><?php esc_html_e( 'After this many lockouts within the history window, the next lockout will use the extended duration.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row">
										<label for="segurium-bf-tier2-duration"><strong><?php esc_html_e( 'Extended lockout duration (seconds)', 'segurium' ); ?></strong></label>
										<input type="number" id="segurium-bf-tier2-duration" min="60" class="small-text">
									</div>
									<div class="segurium-setting-row">
										<label for="segurium-bf-history-window"><strong><?php esc_html_e( 'History window (seconds)', 'segurium' ); ?></strong></label>
										<input type="number" id="segurium-bf-history-window" min="3600" class="small-text">
									</div>
									<div class="segurium-setting-row">
										<label>
											<input type="checkbox" id="segurium-bf-protect-xmlrpc">
											<strong><?php esc_html_e( 'Also protect XML-RPC (xmlrpc.php)', 'segurium' ); ?></strong>
										</label>
									</div>
									<div class="segurium-setting-row">
										<label>
											<input type="checkbox" id="segurium-bf-honeypot">
											<strong><?php esc_html_e( 'Add honeypot field to login form', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Adds an off-screen input that legitimate users never see. Filling it triggers an immediate lockout.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row">
										<label for="segurium-bf-log-retention"><strong><?php esc_html_e( 'Log retention (days)', 'segurium' ); ?></strong></label>
										<input type="number" id="segurium-bf-log-retention" min="1" class="small-text">
									</div>
									</div><?php // /#segurium-bf-locked-section ?>
									<hr class="segurium-bf-section-divider">
									<h3 class="segurium-bf-section-title"><?php esc_html_e( 'hCaptcha', 'segurium' ); ?></h3>
									<p class="description"><?php esc_html_e( 'Optionally show an hCaptcha challenge on the login form after a configurable number of failed attempts. Get free keys at hcaptcha.com.', 'segurium' ); ?></p>
									<div class="segurium-setting-row">
										<label>
											<input type="checkbox" id="segurium-bf-hcaptcha-enabled">
											<strong><?php esc_html_e( 'Require hCaptcha after repeated failures', 'segurium' ); ?></strong>
										</label>
									</div>
									<?php // Decoy fields absorb Chrome/Safari's text+password credential autofill. ?>
									<input type="text" name="username" autocomplete="username" tabindex="-1" aria-hidden="true" style="display:none !important;">
									<input type="password" name="password" autocomplete="current-password" tabindex="-1" aria-hidden="true" style="display:none !important;">
									<div id="segurium-bf-hcaptcha-body">
										<div class="segurium-setting-row">
											<label for="segurium-bf-hcaptcha-site-key"><strong><?php esc_html_e( 'hCaptcha site key', 'segurium' ); ?></strong></label>
											<input type="text" id="segurium-bf-hcaptcha-site-key" class="regular-text"
												autocomplete="off" data-lpignore="true" data-1p-ignore data-form-type="other"
												spellcheck="false">
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-bf-hcaptcha-secret-key"><strong><?php esc_html_e( 'hCaptcha secret key', 'segurium' ); ?></strong></label>
											<input type="password" id="segurium-bf-hcaptcha-secret-key" class="regular-text"
												autocomplete="new-password" data-lpignore="true" data-1p-ignore data-form-type="other"
												spellcheck="false">
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-bf-captcha-threshold"><strong><?php esc_html_e( 'Show CAPTCHA after N failed attempts', 'segurium' ); ?></strong></label>
											<input type="number" id="segurium-bf-captcha-threshold" min="1" class="small-text">
											<p class="description"><?php esc_html_e( 'Must be less than the maximum failed attempts so the challenge fires before the lockout.', 'segurium' ); ?></p>
										</div>
									</div>
								</div>
								<p>
									<button id="segurium-bf-save-btn" class="button button-primary"><?php esc_html_e( 'Save', 'segurium' ); ?></button>
									<span id="segurium-bf-save-status" class="segurium-geo-save-status"></span>
								</p>
							</div>
							<div class="segurium-bf-aside">
								<div class="segurium-bf-lockouts-card">
									<h3><?php esc_html_e( 'Active Lockouts', 'segurium' ); ?></h3>
									<table class="widefat striped" id="segurium-bf-lockouts-table">
										<thead>
											<tr>
												<th><?php esc_html_e( 'IP', 'segurium' ); ?></th>
												<th><?php esc_html_e( 'Tier', 'segurium' ); ?></th>
												<th><?php esc_html_e( 'Locked at', 'segurium' ); ?></th>
												<th><?php esc_html_e( 'Expires', 'segurium' ); ?></th>
												<th></th>
											</tr>
										</thead>
										<tbody id="segurium-bf-lockouts-tbody"></tbody>
									</table>
									<p id="segurium-bf-lockouts-empty" class="description" style="display:none;"><?php esc_html_e( 'No IPs are currently locked out.', 'segurium' ); ?></p>
								</div>
							</div>
						</div>
						<div class="segurium-bf-stats-section">
							<h3><?php esc_html_e( 'Statistics', 'segurium' ); ?></h3>
							<div class="segurium-bf-stat-cards">
								<div class="segurium-bf-stat-card">
									<div class="segurium-bf-stat-label"><?php esc_html_e( 'Active lockouts', 'segurium' ); ?></div>
									<div class="segurium-bf-stat-value" id="segurium-bf-stat-active">&mdash;</div>
								</div>
								<div class="segurium-bf-stat-card">
									<div class="segurium-bf-stat-label"><?php esc_html_e( 'Attempts (24h)', 'segurium' ); ?></div>
									<div class="segurium-bf-stat-value" id="segurium-bf-stat-attempts">&mdash;</div>
								</div>
								<div class="segurium-bf-stat-card">
									<div class="segurium-bf-stat-label"><?php esc_html_e( 'Lockouts (24h)', 'segurium' ); ?></div>
									<div class="segurium-bf-stat-value" id="segurium-bf-stat-lockouts">&mdash;</div>
								</div>
								<div class="segurium-bf-stat-card">
									<div class="segurium-bf-stat-label"><?php esc_html_e( 'Honeypot hits (24h)', 'segurium' ); ?></div>
									<div class="segurium-bf-stat-value" id="segurium-bf-stat-honeypot">&mdash;</div>
								</div>
								<div class="segurium-bf-stat-card">
									<div class="segurium-bf-stat-label"><?php esc_html_e( 'CAPTCHA failures (24h)', 'segurium' ); ?></div>
									<div class="segurium-bf-stat-value" id="segurium-bf-stat-captcha">&mdash;</div>
								</div>
							</div>
							<div class="segurium-bf-top-grid">
								<div class="segurium-bf-top-card">
									<h4><?php esc_html_e( 'Top attacking IPs (24h)', 'segurium' ); ?></h4>
									<table class="widefat striped" id="segurium-bf-top-ips-table">
										<thead>
											<tr>
												<th><?php esc_html_e( 'IP', 'segurium' ); ?></th>
												<th><?php esc_html_e( 'Attempts', 'segurium' ); ?></th>
											</tr>
										</thead>
										<tbody id="segurium-bf-top-ips-tbody"></tbody>
									</table>
									<p id="segurium-bf-top-ips-empty" class="description" style="display:none;"><?php esc_html_e( 'No attacking IPs in the last 24 hours.', 'segurium' ); ?></p>
								</div>
								<div class="segurium-bf-top-card">
									<h4><?php esc_html_e( 'Top targeted usernames (24h)', 'segurium' ); ?></h4>
									<table class="widefat striped" id="segurium-bf-top-users-table">
										<thead>
											<tr>
												<th><?php esc_html_e( 'Username', 'segurium' ); ?></th>
												<th><?php esc_html_e( 'Attempts', 'segurium' ); ?></th>
											</tr>
										</thead>
										<tbody id="segurium-bf-top-users-tbody"></tbody>
									</table>
									<p id="segurium-bf-top-users-empty" class="description" style="display:none;"><?php esc_html_e( 'No targeted usernames in the last 24 hours.', 'segurium' ); ?></p>
								</div>
							</div>
						</div>
						<div class="segurium-bf-log-section">
							<div class="segurium-bf-log-header">
								<h3><?php esc_html_e( 'Event log', 'segurium' ); ?></h3>
								<select id="segurium-bf-log-filter">
									<option value=""><?php esc_html_e( 'All events', 'segurium' ); ?></option>
									<?php
									$bf_event_labels = array(
										Segurium_Brute_Force::EVENT_ATTEMPT      => __( 'Attempt', 'segurium' ),
										Segurium_Brute_Force::EVENT_LOCKOUT      => __( 'Lockout', 'segurium' ),
										Segurium_Brute_Force::EVENT_HONEYPOT     => __( 'Honeypot', 'segurium' ),
										Segurium_Brute_Force::EVENT_UNLOCK       => __( 'Unlock', 'segurium' ),
										Segurium_Brute_Force::EVENT_CAPTCHA_FAIL => __( 'CAPTCHA failed', 'segurium' ),
									);
									foreach ( Segurium_Brute_Force::event_types() as $bf_event ) {
										if ( ! isset( $bf_event_labels[ $bf_event ] ) ) {
											continue;
										}
										printf(
											'<option value="%s">%s</option>',
											esc_attr( $bf_event ),
											esc_html( $bf_event_labels[ $bf_event ] )
										);
									}
									?>
								</select>
							</div>
							<table class="widefat striped" id="segurium-bf-log-table">
								<thead>
									<tr>
										<th><?php esc_html_e( 'When', 'segurium' ); ?></th>
										<th><?php esc_html_e( 'Event', 'segurium' ); ?></th>
										<th><?php esc_html_e( 'IP', 'segurium' ); ?></th>
										<th><?php esc_html_e( 'Country', 'segurium' ); ?></th>
										<th><?php esc_html_e( 'Username', 'segurium' ); ?></th>
										<th><?php esc_html_e( 'Surface', 'segurium' ); ?></th>
										<th><?php esc_html_e( 'Tier', 'segurium' ); ?></th>
									</tr>
								</thead>
								<tbody id="segurium-bf-log-tbody"></tbody>
							</table>
							<p id="segurium-bf-log-empty" class="description" style="display:none;"><?php esc_html_e( 'No events recorded yet.', 'segurium' ); ?></p>
							<div class="segurium-bf-log-pagination">
								<button id="segurium-bf-log-prev" class="button button-small" disabled><?php esc_html_e( 'Previous', 'segurium' ); ?></button>
								<span id="segurium-bf-log-pageinfo" class="segurium-bf-log-pageinfo"></span>
								<button id="segurium-bf-log-next" class="button button-small" disabled><?php esc_html_e( 'Next', 'segurium' ); ?></button>
							</div>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-twofactor" style="display:<?php echo esc_attr( $segurium_panel_style( 'twofactor' ) ); ?>;">
						<div class="segurium-2fa-body">
							<div class="segurium-2fa-config">
								<div class="segurium-setting-row">
									<label>
										<input type="checkbox" id="sgm-2fa-enabled">
										<strong><?php esc_html_e( 'Enable Two-Factor Authentication', 'segurium' ); ?></strong>
									</label>
									<p class="description"><?php esc_html_e( 'Require users to verify their identity with a second factor during login.', 'segurium' ); ?></p>
								</div>
								<div id="sgm-2fa-options" style="display:none;">
									<div class="segurium-setting-row">
										<strong><?php esc_html_e( 'Available Methods', 'segurium' ); ?></strong>
										<p class="description"><?php esc_html_e( 'Select which 2FA methods users can choose from.', 'segurium' ); ?></p>
										<label style="display:block;margin-top:6px;"><input type="checkbox" id="sgm-2fa-method-totp" value="totp"> <?php esc_html_e( 'Authenticator App (TOTP)', 'segurium' ); ?></label>
										<label style="display:block;margin-top:4px;"><input type="checkbox" id="sgm-2fa-method-email" value="email"> <?php esc_html_e( 'Email Verification', 'segurium' ); ?></label>
									</div>
									<div class="segurium-setting-row">
										<strong><?php esc_html_e( 'Enforced Roles', 'segurium' ); ?></strong>
										<p class="description"><?php esc_html_e( 'Users in these roles will be required to set up 2FA.', 'segurium' ); ?></p>
										<div id="sgm-2fa-roles"><!-- populated by JS from AJAX response --></div>
									</div>
									<div class="segurium-setting-row">
										<label for="sgm-2fa-grace"><strong><?php esc_html_e( 'Grace Period (days)', 'segurium' ); ?></strong></label>
										<p class="description"><?php esc_html_e( 'Days before enforcement blocks login for users who have not set up 2FA. Set to 0 to enforce immediately.', 'segurium' ); ?></p>
										<input type="number" id="sgm-2fa-grace" min="0" max="30" value="3" style="width:80px;">
									</div>
									<div class="segurium-setting-row">
										<label for="sgm-2fa-trusted-days"><strong><?php esc_html_e( 'Trusted Device Duration (days)', 'segurium' ); ?></strong></label>
										<p class="description"><?php esc_html_e( 'How many days a device stays trusted after the user checks the trust option.', 'segurium' ); ?></p>
										<input type="number" id="sgm-2fa-trusted-days" min="0" max="365" value="30" style="width:80px;">
									</div>
								</div>
								<p>
									<button id="sgm-2fa-save" class="button button-primary"><?php esc_html_e( 'Save Settings', 'segurium' ); ?></button>
									<span id="sgm-2fa-save-status" style="display:none;margin-left:10px;color:#00a32a;"></span>
								</p>
							</div>
							<div class="segurium-2fa-aside">
								<h3><?php esc_html_e( 'User Statistics', 'segurium' ); ?></h3>
								<table class="widefat striped" id="sgm-2fa-user-stats">
									<thead>
										<tr>
											<th><?php esc_html_e( 'Method', 'segurium' ); ?></th>
											<th><?php esc_html_e( 'Users', 'segurium' ); ?></th>
										</tr>
									</thead>
									<tbody></tbody>
								</table>
								<h3 style="margin-top:20px;"><?php esc_html_e( 'Reset User 2FA', 'segurium' ); ?></h3>
								<p class="description"><?php esc_html_e( 'Enter a username or user ID to reset their 2FA configuration.', 'segurium' ); ?></p>
								<input type="text" id="sgm-2fa-reset-user" placeholder="<?php esc_attr_e( 'Username or ID', 'segurium' ); ?>" style="width:100%;margin-bottom:8px;">
								<button id="sgm-2fa-reset-btn" class="button"><?php esc_html_e( 'Reset 2FA', 'segurium' ); ?></button>
								<span id="sgm-2fa-reset-status" style="display:none;margin-left:10px;"></span>
							</div>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-support" style="display:<?php echo esc_attr( $segurium_panel_style( 'support' ) ); ?>;">
						<h2><?php esc_html_e( 'Support', 'segurium' ); ?></h2>
						<p class="description"><?php esc_html_e( 'Submit a support ticket below. Our team will respond via email.', 'segurium' ); ?></p>
						<form id="segurium-support-form" class="segurium-support-form">
							<div class="segurium-setting-row">
								<label for="segurium-sup-name"><strong><?php esc_html_e( 'Your name', 'segurium' ); ?></strong></label>
								<input type="text" id="segurium-sup-name" name="name" class="regular-text" maxlength="100" value="<?php echo esc_attr( $this->get_support_default_name() ); ?>" required />
							</div>
							<div class="segurium-setting-row">
								<label for="segurium-sup-email"><strong><?php esc_html_e( 'Reply-to email', 'segurium' ); ?></strong></label>
								<input type="email" id="segurium-sup-email" name="email" class="regular-text" maxlength="254" value="<?php echo esc_attr( $this->get_support_default_email() ); ?>" required />
								<p class="description"><?php esc_html_e( 'We will reply to this address. Change it if you want the response to go elsewhere.', 'segurium' ); ?></p>
							</div>
							<div class="segurium-setting-row">
								<label for="segurium-sup-site"><strong><?php esc_html_e( 'Website', 'segurium' ); ?></strong></label>
								<input type="text" id="segurium-sup-site" class="regular-text" value="<?php echo esc_attr( $this->get_support_site_name() ); ?>" readonly disabled />
								<p class="description"><?php esc_html_e( 'Included automatically so support can identify your site. Change this under Settings → General.', 'segurium' ); ?></p>
							</div>
							<div class="segurium-setting-row">
								<label for="segurium-sup-type"><strong><?php esc_html_e( 'Type', 'segurium' ); ?></strong></label>
								<select id="segurium-sup-type" name="type">
									<option value="bug"><?php esc_html_e( 'Bug report', 'segurium' ); ?></option>
									<option value="feature"><?php esc_html_e( 'Feature request', 'segurium' ); ?></option>
									<option value="question"><?php esc_html_e( 'General question', 'segurium' ); ?></option>
									<option value="fn_report"><?php esc_html_e( 'Report missed malware', 'segurium' ); ?></option>
									<option value="other"><?php esc_html_e( 'Other', 'segurium' ); ?></option>
								</select>
							</div>
							<div class="segurium-setting-row segurium-sup-attachment-row" id="segurium-sup-attachment-row" style="display:none;">
								<label for="segurium-sup-attachment"><strong><?php esc_html_e( 'Suspicious file', 'segurium' ); ?></strong></label>
								<input type="file" id="segurium-sup-attachment" name="attachment" />
								<p class="description"><?php esc_html_e( 'Attach the file you believe is malware. Max 100 MB.', 'segurium' ); ?></p>
							</div>
							<div class="segurium-setting-row">
								<label for="segurium-sup-message"><strong><?php esc_html_e( 'Message', 'segurium' ); ?></strong></label>
								<textarea id="segurium-sup-message" name="message" class="segurium-textarea-code" rows="8" maxlength="5000" required></textarea>
							</div>
							<div class="segurium-setting-row">
								<label>
									<input type="checkbox" id="segurium-sup-diag" name="include_diag" checked />
									<?php esc_html_e( 'Attach system information (WP version, PHP version, plugin version, active plugins, last scan date)', 'segurium' ); ?>
								</label>
							</div>
							<div class="segurium-setting-row">
								<button type="submit" class="button button-primary"><?php esc_html_e( 'Submit Ticket', 'segurium' ); ?></button>
							</div>
							<div id="segurium-sup-result" class="segurium-sup-result" style="display:none;"></div>
						</form>
					</div>
					<div class="segurium-feature" id="segurium-feature-headers" style="display:<?php echo esc_attr( $segurium_panel_style( 'headers' ) ); ?>;">
						<div class="segurium-sh-body">
							<div class="segurium-sh-config">
								<div class="segurium-setting-row">
									<label>
										<input type="checkbox" id="segurium-sh-enabled">
										<strong><?php esc_html_e( 'Enable Security Headers', 'segurium' ); ?></strong>
									</label>
									<p class="description"><?php esc_html_e( 'Adds HTTP security response headers to all responses. Protects against clickjacking, MIME sniffing, XSS, and protocol downgrade attacks.', 'segurium' ); ?></p>
								</div>
								<div id="segurium-sh-settings-body">
									<fieldset class="segurium-sh-mode">
										<legend class="segurium-sh-mode-legend"><?php esc_html_e( 'Mode:', 'segurium' ); ?></legend>
										<?php
										$sh_modes = array(
											'off'         => __( 'Off', 'segurium' ),
											'basic'       => __( 'Basic', 'segurium' ) . ' &mdash; ' . __( 'X-Content-Type, X-Frame-Options, X-XSS-Protection', 'segurium' ),
											'recommended' => __( 'Recommended', 'segurium' ) . ' &mdash; ' . __( 'Basic + Referrer-Policy, Permissions-Policy, HSTS', 'segurium' ),
											'strict'      => __( 'Strict', 'segurium' ) . ' &mdash; ' . __( 'Recommended + Cross-Origin policies, DNS prefetch, Cache-Control', 'segurium' ),
											'custom'      => __( 'Custom', 'segurium' ) . ' &mdash; ' . __( 'configure each header individually', 'segurium' ),
										);
										foreach ( $sh_modes as $val => $label ) :
											?>
											<label class="segurium-sh-mode-option">
												<input type="radio" name="segurium-sh-mode" value="<?php echo esc_attr( $val ); ?>">
												<span><?php echo wp_kses( $label, array( 'strong' => array() ) ); ?></span>
											</label>
										<?php endforeach; ?>
									</fieldset>
									<p id="segurium-sh-preset-hint" class="description segurium-sh-preset-hint" style="display:none;">
										<?php esc_html_e( 'This mode emits fixed preset values. Switch to Custom to override individual headers.', 'segurium' ); ?>
									</p>
									<div id="segurium-sh-custom-fields" style="display:none;">
										<h3><?php esc_html_e( 'Header Values', 'segurium' ); ?></h3>
										<div class="segurium-setting-row">
											<label for="segurium-sh-x-frame"><strong><?php esc_html_e( 'X-Frame-Options', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-x-frame">
												<option value="SAMEORIGIN"><?php esc_html_e( 'Same origin', 'segurium' ); ?></option>
												<option value="DENY"><?php esc_html_e( 'Deny all', 'segurium' ); ?></option>
											</select>
											<p class="description"><?php esc_html_e( 'Prevents your site from being embedded in iframes on other domains.', 'segurium' ); ?></p>
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-sh-referrer"><strong><?php esc_html_e( 'Referrer-Policy', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-referrer">
												<?php
												$rp_labels = array(
													'no-referrer'                     => __( 'No referrer', 'segurium' ),
													'no-referrer-when-downgrade'      => __( 'No referrer when downgrade', 'segurium' ),
													'origin'                          => __( 'Origin only', 'segurium' ),
													'origin-when-cross-origin'        => __( 'Origin when cross-origin', 'segurium' ),
													'same-origin'                     => __( 'Same origin', 'segurium' ),
													'strict-origin'                   => __( 'Strict origin', 'segurium' ),
													'strict-origin-when-cross-origin' => __( 'Strict origin when cross-origin', 'segurium' ),
													'unsafe-url'                      => __( 'Unsafe URL', 'segurium' ),
												);
												foreach ( $rp_labels as $val => $label ) :
													?>
													<option value="<?php echo esc_attr( $val ); ?>"><?php echo esc_html( $label ); ?></option>
												<?php endforeach; ?>
											</select>
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-sh-xss"><strong><?php esc_html_e( 'X-XSS-Protection', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-xss">
												<option value="0"><?php esc_html_e( 'Disabled (recommended)', 'segurium' ); ?></option>
												<option value="1"><?php esc_html_e( 'Enabled', 'segurium' ); ?></option>
												<option value="1; mode=block"><?php esc_html_e( 'Enabled with block mode', 'segurium' ); ?></option>
											</select>
											<p class="description"><strong><?php esc_html_e( 'Disabled (recommended)', 'segurium' ); ?></strong> — <?php esc_html_e( 'Explicitly turns off the legacy IE/old-Edge XSS filter, which had universal-XSS bugs that could be weaponised. Modern browsers ignore this header; CSP is the actual XSS defence.', 'segurium' ); ?></p>
											<p class="description"><strong><?php esc_html_e( 'Enabled', 'segurium' ); ?></strong> — <?php esc_html_e( 'Tells legacy browsers to sanitise reflections. The filter has false positives that silently break valid pages and known UXSS bypasses. Not recommended.', 'segurium' ); ?></p>
											<p class="description"><strong><?php esc_html_e( 'Enabled with block mode', 'segurium' ); ?></strong> — <?php esc_html_e( 'Same filter as above, but blocks the page entirely on suspected reflection. Same bugs, plus a timing side-channel that can leak cross-origin data. Not recommended.', 'segurium' ); ?></p>
										</div>
										<h3><?php esc_html_e( 'HSTS (Strict-Transport-Security)', 'segurium' ); ?></h3>
										<div class="segurium-setting-row">
											<label>
												<input type="checkbox" id="segurium-sh-hsts-enabled">
												<strong><?php esc_html_e( 'Enable HSTS', 'segurium' ); ?></strong>
											</label>
											<p class="description"><?php esc_html_e( 'Forces browsers to use HTTPS. Only sent when SSL is active.', 'segurium' ); ?></p>
										</div>
										<div id="segurium-sh-hsts-fields">
											<div class="segurium-setting-row">
												<label for="segurium-sh-hsts-max-age"><strong><?php esc_html_e( 'Max-Age (seconds)', 'segurium' ); ?></strong></label>
												<input type="number" id="segurium-sh-hsts-max-age" min="0" class="small-text" value="31536000">
											</div>
											<div class="segurium-setting-row">
												<label>
													<input type="checkbox" id="segurium-sh-hsts-subdomains">
													<?php esc_html_e( 'Include subdomains', 'segurium' ); ?>
												</label>
											</div>
											<div class="segurium-setting-row">
												<label>
													<input type="checkbox" id="segurium-sh-hsts-preload">
													<?php esc_html_e( 'Preload', 'segurium' ); ?>
												</label>
												<p class="description"><?php esc_html_e( 'Warning: preload is difficult to undo. Requires max-age at least 1 year and subdomains included.', 'segurium' ); ?></p>
											</div>
										</div>
										<div id="segurium-sh-hsts-subdomain-warning" class="segurium-sh-warning" style="display:none;">
											<?php esc_html_e( 'Your site appears to be on a subdomain. Enabling includeSubDomains in HSTS will affect all subdomains of the parent domain, including ones you may not control.', 'segurium' ); ?>
										</div>
										<h3><?php esc_html_e( 'Cross-Origin Policies', 'segurium' ); ?></h3>
										<div class="segurium-setting-row">
											<label for="segurium-sh-coop"><strong><?php esc_html_e( 'Cross-Origin-Opener-Policy', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-coop">
												<option value=""><?php esc_html_e( 'Not set', 'segurium' ); ?></option>
												<option value="same-origin"><?php esc_html_e( 'Same origin', 'segurium' ); ?></option>
												<option value="same-origin-allow-popups"><?php esc_html_e( 'Same origin, allow popups', 'segurium' ); ?></option>
												<option value="unsafe-none"><?php esc_html_e( 'Unsafe none', 'segurium' ); ?></option>
											</select>
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-sh-corp"><strong><?php esc_html_e( 'Cross-Origin-Resource-Policy', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-corp">
												<option value=""><?php esc_html_e( 'Not set', 'segurium' ); ?></option>
												<option value="same-origin"><?php esc_html_e( 'Same origin', 'segurium' ); ?></option>
												<option value="same-site"><?php esc_html_e( 'Same site', 'segurium' ); ?></option>
												<option value="cross-origin"><?php esc_html_e( 'Cross origin', 'segurium' ); ?></option>
											</select>
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-sh-coep"><strong><?php esc_html_e( 'Cross-Origin-Embedder-Policy', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-coep">
												<option value=""><?php esc_html_e( 'Not set (recommended)', 'segurium' ); ?></option>
												<option value="require-corp"><?php esc_html_e( 'Require CORP', 'segurium' ); ?></option>
												<option value="same-origin"><?php esc_html_e( 'Same origin', 'segurium' ); ?></option>
												<option value="unsafe-none"><?php esc_html_e( 'Unsafe none', 'segurium' ); ?></option>
											</select>
										</div>
										<h3><?php esc_html_e( 'Permissions-Policy', 'segurium' ); ?></h3>
										<p class="description"><?php esc_html_e( 'Control which browser features your site may use.', 'segurium' ); ?></p>
										<div class="segurium-sh-pp-grid">
											<?php
											$pp_labels = array(
												'accelerometer' => __( 'Accelerometer', 'segurium' ),
												'autoplay' => __( 'Autoplay', 'segurium' ),
												'camera'   => __( 'Camera', 'segurium' ),
												'encrypted-media' => __( 'Encrypted media', 'segurium' ),
												'fullscreen' => __( 'Fullscreen', 'segurium' ),
												'geolocation' => __( 'Geolocation', 'segurium' ),
												'gyroscope' => __( 'Gyroscope', 'segurium' ),
												'magnetometer' => __( 'Magnetometer', 'segurium' ),
												'microphone' => __( 'Microphone', 'segurium' ),
												'midi'     => __( 'MIDI', 'segurium' ),
												'payment'  => __( 'Payment', 'segurium' ),
												'usb'      => __( 'USB', 'segurium' ),
											);
											foreach ( Segurium_Security_Headers::PP_FEATURES as $feature ) :
												$pp_label = $pp_labels[ $feature ] ?? $feature;
												?>
												<div class="segurium-sh-pp-item">
													<label for="segurium-sh-pp-<?php echo esc_attr( $feature ); ?>">
														<strong><?php echo esc_html( $pp_label ); ?></strong>
													</label>
													<select id="segurium-sh-pp-<?php echo esc_attr( $feature ); ?>" data-pp-feature="<?php echo esc_attr( $feature ); ?>">
														<option value="none"><?php esc_html_e( 'Deny', 'segurium' ); ?></option>
														<option value="self"><?php esc_html_e( 'Self only', 'segurium' ); ?></option>
														<option value="*"><?php esc_html_e( 'Allow all', 'segurium' ); ?></option>
													</select>
												</div>
											<?php endforeach; ?>
										</div>
									</div>
									<hr>
									<h3><?php esc_html_e( 'Content-Security-Policy', 'segurium' ); ?></h3>
									<div class="segurium-setting-row">
										<label>
											<input type="checkbox" id="segurium-sh-csp-enabled">
											<strong><?php esc_html_e( 'Send Content-Security-Policy header', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'CSP restricts where scripts, styles, and other resources may load from, mitigating XSS and injection. CSP is site-specific and can break themes or page builders — start in report-only mode to surface violations before enforcing.', 'segurium' ); ?></p>
									</div>
									<div id="segurium-sh-csp-fields">
										<div class="segurium-setting-row">
											<label for="segurium-sh-csp-mode"><strong><?php esc_html_e( 'Mode', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-csp-mode">
												<option value="report-only"><?php esc_html_e( 'Report-only (recommended for first deploy)', 'segurium' ); ?></option>
												<option value="enforce"><?php esc_html_e( 'Enforce', 'segurium' ); ?></option>
											</select>
											<p class="description"><?php esc_html_e( 'Report-only sends Content-Security-Policy-Report-Only — the browser logs violations but still loads blocked resources. Enforce sends Content-Security-Policy and blocks them.', 'segurium' ); ?></p>
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-sh-csp-directives"><strong><?php esc_html_e( 'Policy directives', 'segurium' ); ?></strong></label>
											<textarea id="segurium-sh-csp-directives" rows="4" class="large-text code" spellcheck="false"></textarea>
											<p class="description">
												<?php esc_html_e( 'Single line of directives separated by semicolons. The default starter policy permits Gutenberg and most themes; tighten once your reports are clean.', 'segurium' ); ?>
												<a href="https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'CSP reference (MDN)', 'segurium' ); ?></a>
											</p>
										</div>
										<div class="segurium-setting-row">
											<label for="segurium-sh-csp-report-uri"><strong><?php esc_html_e( 'Report URI (optional)', 'segurium' ); ?></strong></label>
											<input type="url" id="segurium-sh-csp-report-uri" class="regular-text" placeholder="https://example.report-uri.com/r/d/csp/reportOnly">
											<p class="description"><?php esc_html_e( 'When set, browsers will POST violation reports to this URL. Appended automatically as report-uri unless your directives already contain one.', 'segurium' ); ?></p>
										</div>
									</div>
									<hr>
									<h3><?php esc_html_e( 'Cookie Hardening', 'segurium' ); ?></h3>
									<div class="segurium-setting-row">
										<label>
											<input type="checkbox" id="segurium-sh-cookie-hardening">
											<strong><?php esc_html_e( 'Add SameSite attribute to auth cookies', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Adds SameSite flag to WordPress session cookies. Protects against CSRF attacks. Mozilla Observatory penalizes missing SameSite.', 'segurium' ); ?></p>
									</div>
									<div id="segurium-sh-cookie-fields">
										<div class="segurium-setting-row">
											<label for="segurium-sh-cookie-samesite"><strong><?php esc_html_e( 'SameSite value', 'segurium' ); ?></strong></label>
											<select id="segurium-sh-cookie-samesite">
										<option value="Lax"><?php esc_html_e( 'Lax (recommended)', 'segurium' ); ?></option>
										<option value="Strict"><?php esc_html_e( 'Strict', 'segurium' ); ?></option>
											</select>
											<p class="description"><?php esc_html_e( 'Strict may break OAuth/SSO login flows that redirect back to your site.', 'segurium' ); ?></p>
										</div>
									</div>
								</div>
								<p>
									<button id="segurium-sh-save-btn" class="button button-primary"><?php esc_html_e( 'Save', 'segurium' ); ?></button>
									<span id="segurium-sh-save-status" class="segurium-geo-save-status"></span>
								</p>
							</div>
							<div class="segurium-sh-aside">
								<div id="segurium-sh-preview" class="segurium-sh-preview" style="display:none;">
									<h3><?php esc_html_e( 'Headers Preview', 'segurium' ); ?></h3>
									<pre id="segurium-sh-preview-content"></pre>
								</div>
							</div>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-info-shield" style="display:<?php echo esc_attr( $segurium_panel_style( 'info-shield' ) ); ?>;">
						<div class="segurium-is-body">
							<div class="segurium-is-config">
								<div class="segurium-setting-row">
									<label>
										<input type="checkbox" id="segurium-is-enabled">
										<strong><?php esc_html_e( 'Enable Information Shield', 'segurium' ); ?></strong>
									</label>
									<p class="description"><?php esc_html_e( 'Reduces WordPress information disclosure by removing version fingerprints, discovery endpoints, and unnecessary metadata from HTTP headers and HTML output.', 'segurium' ); ?></p>
								</div>
								<p class="segurium-is-enable-all-wrap">
									<button type="button" id="segurium-is-enable-all" class="button"><?php esc_html_e( 'Enable All Recommended', 'segurium' ); ?></button>
									<span id="segurium-is-enable-all-status"></span>
								</p>
								<div id="segurium-is-settings-body">
									<h3><?php esc_html_e( 'HTTP Header Disclosure', 'segurium' ); ?></h3>
									<div class="segurium-setting-row" data-key="remove_x_powered_by">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove X-Powered-By header', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the header that reveals your PHP version.', 'segurium' ); ?></p>
										<p class="segurium-is-warning" data-warning="x_powered_by" style="display:none;"></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_server_header">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove Server header', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the header that identifies your web server software. Best-effort.', 'segurium' ); ?></p>
										<p class="segurium-is-warning" data-warning="server_header" style="display:none;"></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_x_pingback">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove X-Pingback header', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Hides the pingback/XML-RPC endpoint URL from response headers.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_rest_api_header">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove REST API Link: header', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the HTTP Link header that advertises the REST API endpoint.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_shortlink_header">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove Shortlink Link: header', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the rel=shortlink HTTP header.', 'segurium' ); ?></p>
									</div>

									<h3><?php esc_html_e( 'HTML Meta and Links', 'segurium' ); ?></h3>
									<div class="segurium-setting-row" data-key="remove_wp_generator">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove WordPress generator tag', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the meta generator tag and RSS generator that reveal your WordPress version.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_rsd_link">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove RSD link', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the Really Simple Discovery endpoint link from HTML head.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_wlw_manifest">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove WLW manifest link', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the Windows Live Writer manifest link. Only needed if you use WLW to write posts.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_rest_api_link">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove REST API discovery link', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the discovery link tag from HTML head. The REST API itself remains functional at /wp-json/.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_oembed_links">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove oEmbed discovery links', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Prevents other sites from showing rich embed previews when linking to your content.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_shortlink_link">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove shortlink meta tag', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the shortlink link tag from HTML head.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_emoji">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove emoji scripts and styles', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes the WordPress emoji polyfill JavaScript and CSS. Modern browsers have native emoji support.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_feed_links">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove RSS/Atom feed links', 'segurium' ); ?></strong>
										</label>
										<p class="description segurium-is-note"><?php esc_html_e( 'May break RSS readers and WordPress.com Reader. Only enable if your site does not use RSS feeds.', 'segurium' ); ?></p>
									</div>
									<div class="segurium-setting-row" data-key="remove_adjacent_post_links">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove adjacent post links', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Removes prev/next post rel links from HTML head.', 'segurium' ); ?></p>
									</div>

									<h3><?php esc_html_e( 'Asset Fingerprinting', 'segurium' ); ?></h3>
									<div class="segurium-setting-row" data-key="remove_version_query">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Remove version query strings', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Strips ?ver= from CSS and JavaScript URLs. Browser-cached assets may become stale after plugin or theme updates.', 'segurium' ); ?></p>
									</div>

									<h3><?php esc_html_e( 'XML-RPC', 'segurium' ); ?></h3>
									<div class="segurium-setting-row" data-key="disable_xmlrpc">
										<label>
											<input type="checkbox" class="segurium-is-toggle">
											<strong><?php esc_html_e( 'Disable XML-RPC entirely', 'segurium' ); ?></strong>
										</label>
										<p class="description"><?php esc_html_e( 'Some plugins (Jetpack, WordPress mobile app) require XML-RPC. Disable only if you do not use them.', 'segurium' ); ?></p>
										<p class="segurium-is-warning" data-warning="jetpack_xmlrpc" style="display:none;"></p>
									</div>
								</div>
								<p>
									<button id="segurium-is-save-btn" class="button button-primary"><?php esc_html_e( 'Save', 'segurium' ); ?></button>
									<span id="segurium-is-save-status" class="segurium-geo-save-status"></span>
								</p>
							</div>
						</div>
					</div>
					<div class="segurium-feature" id="segurium-feature-self-check" style="display:<?php echo esc_attr( $segurium_panel_style( 'self-check' ) ); ?>;">
						<h2><?php esc_html_e( 'Security Self-Check', 'segurium' ); ?></h2>
						<p class="description">
							<?php esc_html_e( 'Segurium runs the same checks as leading external security scanners, plus WordPress-specific hardening checks, and grades your site A+ to F. Results are saved until the next run.', 'segurium' ); ?>
						</p>
						<div class="segurium-sc-grade-wrap">
							<div class="segurium-sc-grade" id="segurium-sc-grade" data-grade="">
								<span class="segurium-sc-grade-letter">&mdash;</span>
								<span class="segurium-sc-grade-score">--/100</span>
							</div>
							<div class="segurium-sc-meta">
								<p id="segurium-sc-scanned-at" class="segurium-sc-scanned-at"></p>
								<p id="segurium-sc-delta" class="segurium-sc-delta"></p>
								<p id="segurium-sc-ping-error" class="segurium-sc-ping-error" style="display:none;"></p>
								<p>
									<button type="button" class="button button-primary" id="segurium-sc-run">
										<?php esc_html_e( 'Run Self-Check', 'segurium' ); ?>
									</button>
								</p>
							</div>
						</div>
						<div class="segurium-sc-categories" id="segurium-sc-categories"></div>
						<h3><?php esc_html_e( 'Check results', 'segurium' ); ?></h3>
						<div class="segurium-sc-checks" id="segurium-sc-checks" role="list"></div>
						<h3><?php esc_html_e( 'Independent verification', 'segurium' ); ?></h3>
						<p class="description">
							<?php esc_html_e( 'Cross-check results with these public scanners:', 'segurium' ); ?>
						</p>
						<ul class="segurium-sc-external">
							<li><a id="segurium-sc-sh-link" href="#" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'securityheaders.com', 'segurium' ); ?></a></li>
							<li><a id="segurium-sc-mo-link" href="#" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Mozilla Observatory', 'segurium' ); ?></a></li>
						</ul>
					</div>
					<div class="segurium-feature" id="segurium-feature-plans" style="display:<?php echo esc_attr( $segurium_panel_style( 'plans' ) ); ?>;">
						<?php
						// Plan-picker cards mirroring segurium.com/pricing
						// in a default WP-admin palette. data-current-tier marks the
						// active card so JS / CSS can highlight it.
						$tier_attr   = ( 'segurium--pro' === $tier_class ) ? 'pro' : 'free';
						$upgrade_url = class_exists( 'Segurium_Entitlements' )
							? Segurium_Entitlements::instance()->upgrade_url()
							: '';

						$free_bullets = array(
							__( 'Cleanup: 3 files / 30 days', 'segurium' ),
							__( 'Full malware detection — same findings as Pro', 'segurium' ),
							__( 'Auto-fix and Bulk Fix All', 'segurium' ),
							__( 'Hardening: 2FA, brute-force, geo-blocking, firewall, security headers', 'segurium' ),
							__( 'File-integrity monitoring (core / plugins / themes)', 'segurium' ),
							__( 'Migration importer (Wordfence, AIOS, Solid Security)', 'segurium' ),
							__( 'Community support', 'segurium' ),
						);
						$pro_bullets  = array(
							__( 'Unlimited cleanup', 'segurium' ),
							__( 'Everything in Free', 'segurium' ),
							__( 'Email support, priority queue', 'segurium' ),
						);
						?>
						<section class="segurium-tier-section segurium-plans" data-current-tier="<?php echo esc_attr( $tier_attr ); ?>">
							<div class="segurium-tier-wrap">
								<header class="segurium-plans__head">
									<h2><?php esc_html_e( 'Plans', 'segurium' ); ?></h2>
									<p class="description">
										<?php esc_html_e( 'Every feature ships on every install. Pro lifts the monthly cleanup cap.', 'segurium' ); ?>
									</p>
								</header>

								<div class="segurium-plans__grid">
									<article class="segurium-plan segurium-plan--free<?php echo 'free' === $tier_attr ? ' segurium-plan--current' : ''; ?>">
										<?php if ( 'free' === $tier_attr ) : ?>
											<span class="segurium-plan__badge segurium-plan__badge--current"><?php esc_html_e( 'Current plan', 'segurium' ); ?></span>
										<?php endif; ?>
										<header class="segurium-plan__header">
											<h3><?php esc_html_e( 'Free', 'segurium' ); ?></h3>
											<p class="segurium-plan__tagline">
												<?php esc_html_e( 'Every feature, on every site. Cleanups capped at 3 per 30 days.', 'segurium' ); ?>
											</p>
										</header>
										<p class="segurium-plan__price">
											<span class="segurium-plan__amount">$0</span>
											<span class="segurium-plan__unit"><?php esc_html_e( 'forever', 'segurium' ); ?></span>
										</p>
										<ul class="segurium-plan__bullets" role="list">
											<?php foreach ( $free_bullets as $bullet ) : ?>
												<li><?php echo esc_html( $bullet ); ?></li>
											<?php endforeach; ?>
										</ul>
										<?php // Same Free-tier readout as the scanner panels, pinned to the card foot so it sits level with the Pro card's CTA. The bullet above states the policy; this states the install's position in it. data-cta="off" keeps the readout's own upgrade link out of a card that already sits beside the primary one; segurium-scan.js honours it on refresh. ?>
										<div class="segurium-quota-readout segurium-plan__quota" data-cta="off"<?php echo '' === $quota_readout_plan ? ' hidden' : ''; ?>><?php echo wp_kses_post( $quota_readout_plan ); ?></div>
									</article>

									<article class="segurium-plan segurium-plan--pro segurium-plan--featured<?php echo 'pro' === $tier_attr ? ' segurium-plan--current' : ''; ?>">
										<span class="segurium-plan__badge<?php echo 'pro' === $tier_attr ? ' segurium-plan__badge--current' : ' segurium-plan__badge--recommended'; ?>">
											<?php
											if ( 'pro' === $tier_attr ) {
												esc_html_e( 'Current plan', 'segurium' );
											} else {
												esc_html_e( 'Recommended', 'segurium' );
											}
											?>
										</span>
										<header class="segurium-plan__header">
											<h3><?php esc_html_e( 'Pro', 'segurium' ); ?></h3>
											<p class="segurium-plan__tagline">
												<?php esc_html_e( 'Unlimited cleanup. Same features as Free, with no monthly cap.', 'segurium' ); ?>
											</p>
										</header>
										<p class="segurium-plan__price">
											<span class="segurium-plan__amount">$79</span>
											<span class="segurium-plan__unit"><?php esc_html_e( '/year per site', 'segurium' ); ?></span>
										</p>
										<ul class="segurium-plan__bullets" role="list">
											<?php foreach ( $pro_bullets as $bullet ) : ?>
												<li><?php echo esc_html( $bullet ); ?></li>
											<?php endforeach; ?>
										</ul>
										<?php if ( 'free' === $tier_attr && '' !== $upgrade_url ) : ?>
											<?php // The fallback destination lives on segurium.com. Leaving wp-admin in the same tab discards whatever the operator had open, and the note below this grid already opens the same page in a new one. ?>
											<a class="button button-primary button-hero segurium-plan__cta" href="<?php echo esc_url( $upgrade_url ); ?>"<?php echo class_exists( 'Segurium_Entitlements' ) && Segurium_Entitlements::is_offsite_url( $upgrade_url ) ? ' target="_blank" rel="noopener noreferrer"' : ''; ?>>
												<?php esc_html_e( 'Upgrade to Pro', 'segurium' ); ?>
											</a>
											<p class="segurium-plan__guarantee">
												<?php esc_html_e( '14-day money-back guarantee.', 'segurium' ); ?>
											</p>
										<?php endif; ?>
									</article>
								</div>

								<p class="segurium-plans__note">
									<?php
									echo wp_kses(
										sprintf(
											/* translators: 1: opening anchor tag, 2: closing anchor tag */
											__( 'Bundles for 5 and 25 sites, plus 100+ quotes, on %1$ssegurium.com/pricing/%2$s.', 'segurium' ),
											'<a href="https://segurium.com/pricing/" target="_blank" rel="noopener noreferrer">',
											'</a>'
										),
										array(
											'a' => array(
												'href'   => true,
												'target' => true,
												'rel'    => true,
											),
										)
									);
									?>
								</p>
							</div>
						</section>
					</div>
					<div class="segurium-feature" id="segurium-feature-settings" style="display:<?php echo esc_attr( $segurium_panel_style( 'settings' ) ); ?>;">
						<h2><?php esc_html_e( 'Scan Settings', 'segurium' ); ?></h2>
						<div class="segurium-setting-row">
							<label for="segurium_scan_exclude">
								<strong><?php esc_html_e( 'Exclude files from scan that match these wildcard patterns (one per line)', 'segurium' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'Use * as a wildcard. For example, *.log will exclude all log files. vendor/* will exclude the vendor directory and everything inside it.', 'segurium' ); ?></p>
							<textarea id="segurium_scan_exclude" class="segurium-textarea-code" rows="8"><?php echo esc_textarea( Segurium_Storage::setting_get( 'segurium_scan_exclude', '' ) ); ?></textarea>
						</div>
						<div class="segurium-setting-row">
							<label>
								<input type="checkbox" id="segurium_cloud_detection" <?php checked( Segurium_Storage::setting_get_bool( 'segurium_cloud_detection_enabled', false ) ); ?>>
								<strong><?php esc_html_e( 'Cloud-assisted malware detection', 'segurium' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'When enabled, file contents may be shared with Segurium Cloud for advanced malware detection and cloud-powered cleanup. Only suspicious files are transmitted. Turn it off for On-premise mode: scans then send SHA-256 hashes, file paths, and metadata only, and a file the cloud cannot identify by hash stays unresolved. Reporting a false positive or attaching a file to a support ticket still sends that file, because you pick it yourself.', 'segurium' ); ?></p>
						</div>
						<?php // Opt-in for the server-side daily security digest. ?>
						<div class="segurium-setting-row">
							<label>
								<input type="checkbox" id="segurium_alerts_email_enabled" <?php checked( Segurium_Storage::setting_get_bool( Segurium_Alerts_Settings::OPTION_ENABLED, false ) ); ?>>
								<strong><?php esc_html_e( 'Email me about findings', 'segurium' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'Send a daily digest of malware verdicts and successful cleanups, delivered from support@segurium.com. At most one email per site per 24 hours.', 'segurium' ); ?></p>
							<label for="segurium_alerts_email_address" class="screen-reader-text"><?php esc_html_e( 'Alert email address', 'segurium' ); ?></label>
							<input
								type="email"
								id="segurium_alerts_email_address"
								class="regular-text"
								placeholder="<?php echo esc_attr( (string) Segurium_Storage::setting_get( 'admin_email', '' ) ); ?>"
								value="<?php echo esc_attr( (string) Segurium_Storage::setting_get_string( Segurium_Alerts_Settings::OPTION_EMAIL ) ); ?>"
							/>
							<p class="description"><?php esc_html_e( 'Leave blank to use the WordPress site admin email.', 'segurium' ); ?></p>
						</div>
						<div class="segurium-setting-row segurium-danger-zone">
							<label>
								<input type="checkbox" id="segurium_uninstall_wipe_data" <?php checked( Segurium_Storage::setting_get_bool( 'segurium_uninstall_wipe_data', false ) ); ?>>
								<strong><?php esc_html_e( 'Wipe encrypted backups when the plugin is uninstalled', 'segurium' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'Off (default): encrypted backups of deleted components and cured files are kept in the uploads/segurium-data directory after uninstall, so a reinstall can still restore them. Turn on only if you want a hard deletion on uninstall.', 'segurium' ); ?></p>
						</div>
						<?php
						// Unattended auto-fix toggle.
						// Available on every install; per-cleanup CTI quota
						// applies the right plan-tier cap.
						?>
						<div class="segurium-setting-row">
							<label>
								<input type="checkbox" id="segurium_auto_fix_enabled" <?php checked( Segurium_Auto_Fix_Settings::is_enabled() ); ?>>
								<strong><?php esc_html_e( 'Automatically clean detected malware', 'segurium' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'After every scheduled or real-time scan, files with a known malware or injection verdict are cleaned without requiring a click. Files you have ignored (by path or by hash) are skipped.', 'segurium' ); ?></p>
						</div>
						<?php // Consent for CTI-addressed component updates. ?>
						<div class="segurium-setting-row">
							<label>
								<input type="checkbox" id="segurium_remote_actions_enabled" <?php checked( Segurium_Remote_Actions::enabled() ); ?><?php disabled( Segurium_Remote_Actions::killed() ); ?>>
								<strong><?php esc_html_e( 'Let Segurium Cloud request component updates', 'segurium' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'Segurium Cloud can ask this site to update a plugin, theme, or WordPress itself. It can only name a component you already have installed, and only when WordPress.org already offers that update; the update is downloaded by WordPress from WordPress.org, never from Segurium. WordPress core is limited to security and maintenance releases. Segurium never updates itself this way. Turn this off and the site stops asking for and accepting these requests.', 'segurium' ); ?></p>
							<?php if ( Segurium_Remote_Actions::killed() ) : ?>
								<p class="segurium-is-warning"><?php esc_html_e( 'Switched off in wp-config.php by SEGURIUM_DISABLE_REMOTE_ACTIONS.', 'segurium' ); ?></p>
							<?php endif; ?>
							<?php $segurium_action_log = array_slice( array_reverse( Segurium_Remote_Actions::log_entries() ), 0, 10 ); ?>
							<?php if ( ! empty( $segurium_action_log ) ) : ?>
								<p><strong><?php esc_html_e( 'Recent cloud requests', 'segurium' ); ?></strong></p>
								<table class="widefat striped segurium-remote-actions-log">
									<thead>
										<tr>
											<th scope="col"><?php esc_html_e( 'When', 'segurium' ); ?></th>
											<th scope="col"><?php esc_html_e( 'Component', 'segurium' ); ?></th>
											<th scope="col"><?php esc_html_e( 'Outcome', 'segurium' ); ?></th>
										</tr>
									</thead>
									<tbody>
									<?php foreach ( $segurium_action_log as $segurium_action_entry ) : ?>
										<tr>
											<td><?php echo esc_html( wp_date( 'Y-m-d H:i', (int) ( $segurium_action_entry['at'] ?? 0 ) ) ); ?></td>
											<td>
												<?php
												$segurium_action_slug = (string) ( $segurium_action_entry['slug'] ?? '' );
												echo esc_html(
													'' === $segurium_action_slug
														? (string) ( $segurium_action_entry['ctype'] ?? '' )
														: ( $segurium_action_entry['ctype'] ?? '' ) . ': ' . $segurium_action_slug
												);
												?>
											</td>
											<td><code><?php echo esc_html( (string) ( $segurium_action_entry['code'] ?? '' ) ); ?></code></td>
										</tr>
									<?php endforeach; ?>
									</tbody>
								</table>
							<?php endif; ?>
						</div>
						<p>
							<button id="segurium-save-settings" class="button button-primary">
								<?php esc_html_e( 'Save Settings', 'segurium' ); ?>
							</button>
							<span id="segurium-settings-status"></span>
						</p>

						<hr />
						<h2><?php esc_html_e( 'Scheduled Scan', 'segurium' ); ?></h2>
						<p class="description">
							<?php esc_html_e( 'Run a full malware scan automatically on a recurring schedule. A scheduled scan does the same work as a manual scan, but does not require you to keep your browser open. A scheduled tick that fires while a manual scan is already in progress is skipped, not queued.', 'segurium' ); ?>
						</p>
						<div class="segurium-setting-row">
							<label for="segurium-scheduled-mode">
								<strong><?php esc_html_e( 'Frequency', 'segurium' ); ?></strong>
							</label>
							<select id="segurium-scheduled-mode">
								<option value="off"><?php esc_html_e( 'Off', 'segurium' ); ?></option>
								<option value="daily"><?php esc_html_e( 'Daily', 'segurium' ); ?></option>
								<option value="weekly"><?php esc_html_e( 'Weekly', 'segurium' ); ?></option>
							</select>
						</div>
						<div class="segurium-setting-row" id="segurium-scheduled-time-row" style="display:none;">
							<label for="segurium-scheduled-time">
								<strong><?php esc_html_e( 'Time of day', 'segurium' ); ?></strong>
							</label>
							<input type="time" id="segurium-scheduled-time" />
							<p class="description" id="segurium-scheduled-time-hint"></p>
						</div>
						<div class="segurium-setting-row" id="segurium-scheduled-day-row" style="display:none;">
							<label for="segurium-scheduled-day">
								<strong><?php esc_html_e( 'Day of week', 'segurium' ); ?></strong>
							</label>
							<select id="segurium-scheduled-day"></select>
						</div>
						<p>
							<button id="segurium-scheduled-save" class="button button-primary">
								<?php esc_html_e( 'Save Schedule', 'segurium' ); ?>
							</button>
							<span id="segurium-scheduled-status"></span>
						</p>
						<p class="segurium-scheduled-next-run" id="segurium-scheduled-next-run"></p>
					</div>
					<div class="segurium-feature" id="segurium-feature-migration" style="display:<?php echo esc_attr( $segurium_panel_style( 'migration' ) ); ?>;">
						<div id="segurium-migration-panel">
							<p class="segurium-migration-intro"><?php esc_html_e( 'Import settings from other security plugins into Segurium. Existing Segurium settings are preserved; imported data is merged.', 'segurium' ); ?></p>
							<div id="segurium-migration-list"></div>
						</div>
					</div>
					<div id="segurium-malware-modal" class="segurium-modal" style="display:none;">
						<div class="segurium-modal-overlay"></div>
						<div class="segurium-modal-content">
							<div class="segurium-modal-header">
								<h3 id="segurium-modal-title"></h3>
								<button class="segurium-modal-close" type="button">&times;</button>
							</div>
							<textarea id="segurium-modal-body" class="segurium-modal-body" readonly></textarea>
						</div>
					</div>
					<div id="segurium-fp-modal" class="segurium-modal" style="display:none;" role="dialog" aria-modal="true" aria-labelledby="segurium-fp-modal-title">
						<div class="segurium-modal-overlay"></div>
						<div class="segurium-modal-content">
							<div class="segurium-modal-header">
								<h3 id="segurium-fp-modal-title"><?php esc_html_e( 'Report False Positive', 'segurium' ); ?></h3>
								<button class="segurium-modal-close segurium-fp-cancel" type="button">&times;</button>
							</div>
							<form id="segurium-fp-form" class="segurium-fp-form">
								<dl class="segurium-fp-fields">
									<dt><?php esc_html_e( 'File path', 'segurium' ); ?></dt>
									<dd id="segurium-fp-path"></dd>
									<dt><?php esc_html_e( 'SHA-256', 'segurium' ); ?></dt>
									<dd id="segurium-fp-hash"></dd>
									<dt><?php esc_html_e( 'Component', 'segurium' ); ?></dt>
									<dd id="segurium-fp-component"></dd>
									<dt><?php esc_html_e( 'Current verdict', 'segurium' ); ?></dt>
									<dd id="segurium-fp-verdict"></dd>
								</dl>
								<label for="segurium-fp-note"><?php esc_html_e( 'Note (optional, max 2000 chars)', 'segurium' ); ?></label>
								<textarea id="segurium-fp-note" maxlength="2000" rows="4"></textarea>
								<label class="segurium-fp-checkbox-row">
									<input type="checkbox" id="segurium-fp-also-ignore" checked />
									<?php esc_html_e( 'Also ignore this file on this site', 'segurium' ); ?>
								</label>
								<div class="segurium-fp-actions">
									<button type="button" class="button segurium-fp-cancel"><?php esc_html_e( 'Cancel', 'segurium' ); ?></button>
									<button type="submit" class="button button-primary segurium-fp-submit"><?php esc_html_e( 'Submit report', 'segurium' ); ?></button>
								</div>
								<p id="segurium-fp-status" class="segurium-fp-status" aria-live="polite"></p>
							</form>
						</div>
					</div>
				</div>
				<div class="segurium-sidebar">
					<div class="segurium-status-card">
						<h3><?php esc_html_e( 'Status', 'segurium' ); ?></h3>
						<dl class="segurium-status-list">
							<dt><?php esc_html_e( 'Version', 'segurium' ); ?></dt>
							<dd><?php echo esc_html( SEGURIUM_VERSION ); ?></dd>
							<dt><?php esc_html_e( 'Plan', 'segurium' ); ?></dt>
							<dd><?php $is_pro ? esc_html_e( 'Pro', 'segurium' ) : esc_html_e( 'Free', 'segurium' ); ?></dd>
							<?php /* translators: brand name of the service, do not translate */ ?>
							<dt><?php esc_html_e( 'Segurium Cloud', 'segurium' ); ?></dt>
							<dd id="segurium-cti-status"></dd>
							<dt><?php esc_html_e( 'Geo DB updated', 'segurium' ); ?></dt>
							<?php
								$geo_ts = Segurium_Storage::setting_get_int( 'segurium_geo_updated_at' );
								// Both CTI and the plugin refresh on a daily timer, so worst-case
								// healthy lag is one CTI cycle plus one plugin cycle = 2 days.
								$this->render_status_freshness_dd( $geo_ts, 2 * DAY_IN_SECONDS );
							?>
							<dt><?php esc_html_e( 'Proxies DB updated', 'segurium' ); ?></dt>
							<?php
								$tp_ts = (int) Segurium_Storage::setting_get( Segurium_Trusted_Proxies::OPTION_UPDATED_AT, 0 );
								$this->render_status_freshness_dd( $tp_ts, 2 * DAY_IN_SECONDS );
							?>
							<?php
								$iid = Segurium_IID::get_iid();
							if ( null !== $iid && '' !== $iid ) :
								$iid_short = substr( $iid, 0, 8 );
								?>
								<dt><?php esc_html_e( 'IID', 'segurium' ); ?></dt>
								<dd class="segurium-iid-row" data-segurium-iid="<?php echo esc_attr( $iid ); ?>">
									<code class="segurium-iid-display"><?php echo esc_html( $iid_short ); ?>&hellip;</code>
									<button
										type="button"
										class="button-link segurium-iid-copy"
										aria-label="<?php esc_attr_e( 'Copy IID to clipboard', 'segurium' ); ?>"
									><span class="dashicons dashicons-clipboard" aria-hidden="true"></span></button>
								</dd>
							<?php endif; ?>
							<dt><?php esc_html_e( 'Your IP', 'segurium' ); ?></dt>
							<dd>
							<?php
								$your_ip      = Segurium_Geo_Blocker::get_instance()->get_real_ip();
								$your_country = $your_ip ? Segurium_Geo_DB::get_country( $your_ip ) : null;
								echo esc_html( $your_ip );
							if ( $your_country ) {
								echo ' <span class="segurium-country-flag" title="' . esc_attr( $your_country ) . '">' . esc_html( $your_country ) . '</span>';
							}
							?>
							</dd>
						</dl>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Store the alerts opt-in fields when the request carries them.
	 * Absent fields (older cached JS) leave the stored options untouched.
	 * The caller verifies the nonce.
	 *
	 * @return void
	 */
	private static function save_alerts_from_request() {
		if ( ! self::request_has( INPUT_POST, 'alerts_email_address' ) && ! self::request_has( INPUT_POST, 'alerts_email_enabled' ) ) {
			return;
		}
		Segurium_Alerts_Settings::set(
			self::request_bool( INPUT_POST, 'alerts_email_enabled' ),
			self::request_scalar( INPUT_POST, 'alerts_email_address' )
		);
	}

	/**
	 * AJAX handler for accepting CTI consent.
	 *
	 * @return void
	 */
	public function ajax_accept_consent() {
		check_ajax_referer( 'segurium_consent', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		Segurium_Storage::setting_set( 'segurium_cti_consent', 1 );
		Segurium_Storage::setting_set( 'segurium_cloud_detection_enabled', 1 );

		// Written before any CTI call so the register body carries the
		// contact the user just chose.
		self::save_alerts_from_request();

		// Defer IID registration off the AJAX path —
		// {@see Segurium_IID::register()} makes a 15s blocking POST.
		// {@see self::maybe_schedule_missing_data()} retries on init
		// if the cron event misses for any reason.
		if ( ! wp_next_scheduled( self::IID_REGISTER_CRON_HOOK ) ) {
			wp_schedule_single_event( time(), self::IID_REGISTER_CRON_HOOK );
		}

		Segurium_Storage::cti_send_message( 'plugin_activated' );
		Segurium_Storage::cti_send_message( 'consent' );

		// Piggyback a fresh platform snapshot so the
		// installation-base dashboard populates without waiting for
		// the daily cron tick.
		Segurium_Platform_Snapshot::send_on_consent();

		segurium_send_json_success();
	}

	/**
	 * AJAX handler for saving plugin settings.
	 *
	 * @return void
	 */
	public function ajax_save_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$scan_exclude = isset( $_POST['scan_exclude'] ) ? sanitize_textarea_field( wp_unslash( $_POST['scan_exclude'] ) ) : '';

		$warnings   = array();
		$lines      = explode( "\n", $scan_exclude );
		$clean      = array();
		$rejected   = 0;
		$normalized = 0;
		foreach ( $lines as $line ) {
			$trimmed = trim( $line );
			if ( '*' === $trimmed ) {
				$warnings[] = __( 'A bare * pattern was removed because it would exclude all files.', 'segurium' );
				continue;
			}
			if ( strlen( $trimmed ) > 191 ) {
				++$rejected;
				continue;
			}
			$rewritten = self::normalize_scan_exclude_pattern( $line );
			if ( $rewritten !== $line ) {
				++$normalized;
				$line = $rewritten;
			}
			$clean[] = $line;
		}
		if ( $normalized > 0 ) {
			$warnings[] = sprintf(
				/* translators: %d: number of rewritten lines */
				_n(
					'%d absolute path was rewritten to a path relative to the WordPress install root.',
					'%d absolute paths were rewritten to paths relative to the WordPress install root.',
					$normalized,
					'segurium'
				),
				$normalized
			);
		}
		if ( count( $clean ) > 500 ) {
			segurium_send_json_error(
				array(
					'code'    => 'scan_exclude_too_large',
					'message' => __( 'Scan exclusion list is limited to 500 entries.', 'segurium' ),
				)
			);
		}
		if ( $rejected > 0 ) {
			$warnings[] = sprintf(
				/* translators: %d: number of rejected lines */
				_n( '%d entry longer than 191 characters was removed.', '%d entries longer than 191 characters were removed.', $rejected, 'segurium' ),
				$rejected
			);
		}
		$scan_exclude = implode( "\n", $clean );

		// segurium_scan_exclude stays in wp_options per plan.
		Segurium_Storage::setting_set( 'segurium_scan_exclude', $scan_exclude, true );

		$cloud_detection = self::request_bool( INPUT_POST, 'cloud_detection' );
		Segurium_Storage::setting_set( 'segurium_cloud_detection_enabled', $cloud_detection ? 1 : 0 );

		$wipe_on_uninstall = self::request_bool( INPUT_POST, 'uninstall_wipe_data' );
		Segurium_Storage::setting_set( 'segurium_uninstall_wipe_data', $wipe_on_uninstall ? 1 : 0 );

		self::save_alerts_from_request();

		// Unattended auto-fix opt-in. Available
		// on every install; CTI applies plan-tier limits per cleanup.
		if ( self::request_has( INPUT_POST, 'auto_fix_enabled' ) ) {
			Segurium_Auto_Fix_Settings::set( self::request_bool( INPUT_POST, 'auto_fix_enabled' ) );
		}

		// Consent for CTI-addressed component updates. The
		// wp-config kill switch outranks the checkbox, so a site pinned off
		// there cannot be re-opened from the admin screen.
		if ( self::request_has( INPUT_POST, 'remote_actions_enabled' ) && ! Segurium_Remote_Actions::killed() ) {
			Segurium_Remote_Actions::set_consent( self::request_bool( INPUT_POST, 'remote_actions_enabled' ) );
		}

		segurium_send_json_success( array( 'warnings' => $warnings ) );
	}

	/**
	 * AJAX handler for the scheduled-scan settings GET endpoint.
	 *
	 * Returns the current persisted settings (lazy-generating defaults
	 * the first time we're called) plus the next firing time in UTC
	 * and the site timezone string so the JS can render in the user's
	 * browser locale without losing the wall-clock alignment.
	 *
	 * @return void
	 */
	public function ajax_get_scheduled_scan_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'You do not have permission to manage scan settings.', 'segurium' ),
				),
				403
			);
		}

		Segurium_Scheduled_Scan_Settings::ensure_pregenerated();
		$settings = Segurium_Scheduled_Scan_Settings::get();

		segurium_send_json_success(
			array(
				'settings'      => $settings,
				'next_run_utc'  => Segurium_Scheduled_Scan_Settings::to_next_timestamp_utc(),
				'site_timezone' => wp_timezone_string(),
			)
		);
	}

	/**
	 * AJAX handler for the scheduled-scan settings save endpoint.
	 *
	 * Validates and persists the user-supplied frequency / hour /
	 * minute / day-of-week, then immediately re-arms the cron firing
	 * for the new schedule.
	 *
	 * @return void
	 */
	public function ajax_save_scheduled_scan_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'You do not have permission to manage scan settings.', 'segurium' ),
				),
				403
			);
		}

		$input = array();
		$mode  = sanitize_text_field( self::request_scalar( INPUT_POST, 'mode' ) );
		if ( '' !== $mode ) {
			$input['mode'] = $mode;
		}
		$hour = self::request_scalar( INPUT_POST, 'hour', null );
		if ( null !== $hour ) {
			$input['hour'] = self::request_int( INPUT_POST, 'hour' );
		}
		$minute = self::request_scalar( INPUT_POST, 'minute', null );
		if ( null !== $minute ) {
			$input['minute'] = self::request_int( INPUT_POST, 'minute' );
		}
		$day_of_week = self::request_scalar( INPUT_POST, 'day_of_week', null );
		if ( null !== $day_of_week ) {
			$input['day_of_week'] = self::request_int( INPUT_POST, 'day_of_week' );
		}

		$result = Segurium_Scheduled_Scan_Settings::save( $input );
		if ( is_wp_error( $result ) ) {
			segurium_send_json_error(
				array(
					'code'    => $result->get_error_code(),
					'message' => $result->get_error_message(),
				)
			);
		}

		Segurium_Scheduled_Scan::reschedule();

		segurium_send_json_success(
			array(
				'settings'     => Segurium_Scheduled_Scan_Settings::get(),
				'next_run_utc' => Segurium_Scheduled_Scan_Settings::to_next_timestamp_utc(),
			)
		);
	}

	/**
	 * AJAX handler for starting a malware scan.
	 *
	 * @return void
	 */
	public function ajax_start_scan() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'You do not have permission to manage scans.', 'segurium' ),
				),
				403
			);
		}

		if ( ! $this->has_cti_consent() ) {
			segurium_send_json_error(
				array(
					'code'    => 'consent_required',
					'message' => __( 'Segurium Cloud consent is required before scanning.', 'segurium' ),
				)
			);
		}

		try {
			$result = Segurium_Scan_Runner::start( 'manual' );
		} catch ( Throwable $e ) {
			$this->log_runner_exception( 'ajax_start_scan', $e );
			segurium_send_json_error(
				array(
					'code'    => 'scan_start_exception',
					'message' => $this->format_exception_message(
						__( 'The scan could not be started due to a server error.', 'segurium' ),
						$e
					),
				)
			);
		}

		if ( is_wp_error( $result ) ) {
			segurium_send_json_error(
				array(
					'code'    => $result->get_error_code(),
					'message' => $result->get_error_message(),
				)
			);
		}

		segurium_send_json_success(
			array(
				'scan_id' => $result,
				'running' => true,
				'status'  => 'dispatched',
			)
		);
	}

	/**
	 * Legacy compatibility shim for the retired segurium_continue_scan
	 * action. The endpoint was removed when manual scans were moved onto
	 * the browser-independent runner; browsers with a cached pre-runner
	 * segurium-scan.js will keep calling this action until the
	 * cache-busting version string forces a reload. Return a structured
	 * JSON error the JS error pipeline can actually surface.
	 *
	 * @return void
	 */
	public function ajax_continue_scan_legacy() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'You do not have permission to manage scans.', 'segurium' ),
				),
				403
			);
		}

		segurium_send_json_error(
			array(
				'code'    => 'legacy_continue_action',
				'message' => __( 'This version of the admin page is stale. Reload the page to continue.', 'segurium' ),
			),
			410
		);
	}

	/**
	 * AJAX handler for stopping an in-flight malware scan.
	 *
	 * @return void
	 */
	public function ajax_stop_scan() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'You do not have permission to manage scans.', 'segurium' ),
				),
				403
			);
		}

		// If the user cancels the chained malware scan, the
		// integrity scan that was queued behind it must also be cancelled
		// — otherwise the deferred-start cron would silently start it.
		// Capture the active scan_type before we tear the lock down.
		$lock_before = Segurium_Scan_Lock::get();

		try {
			$stopped = Segurium_Scan_Runner::stop();
		} catch ( Throwable $e ) {
			$this->log_runner_exception( 'ajax_stop_scan', $e );
			segurium_send_json_error(
				array(
					'code'    => 'scan_stop_exception',
					'message' => $this->format_exception_message(
						__( 'Could not stop the running scan due to a server error.', 'segurium' ),
						$e
					),
				)
			);
		}

		if ( $stopped
			&& null !== $lock_before
			&& 'integrity' !== ( $lock_before['scan_type'] ?? '' ) ) {
			Segurium_Integrity_Chain::note_malware_cancelled();
		}

		segurium_send_json_success( array( 'stopped' => (bool) $stopped ) );
	}

	/**
	 * Log an unexpected Throwable from the scan runner to the PHP error log.
	 *
	 * @param string    $where Identifier for the originating call site.
	 * @param Throwable $e     Captured throwable.
	 * @return void
	 */
	private function log_runner_exception( $where, $e ) {
		Segurium_Debug::log(
			sprintf(
				'[segurium] %s: %s: %s at %s:%d',
				$where,
				get_class( $e ),
				$e->getMessage(),
				$e->getFile(),
				$e->getLine()
			)
		);
	}

	/**
	 * Build a user-facing error message that includes the underlying
	 * exception message when WP_DEBUG is on, and a generic hint otherwise.
	 *
	 * @param string    $prefix Localized human-readable lead-in.
	 * @param Throwable $e      Captured throwable.
	 * @return string
	 */
	private function format_exception_message( $prefix, $e ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			return sprintf( '%s (%s)', $prefix, $e->getMessage() );
		}
		return $prefix . ' ' . __( 'Check the PHP error log for details.', 'segurium' );
	}

	/**
	 * Get the plugin data directory path.
	 *
	 * @return string Path to the data directory.
	 */
	public function get_data_dir() {
		return Segurium_Storage_Fs::data_dir();
	}

	/**
	 * Get the last completed scan data.
	 *
	 * @return array|null Scan data or null if no completed scan found.
	 */
	public function get_last_completed_scan() {
		$row = Segurium_Storage::table_get_row(
			'scan_history',
			"SELECT scan_uuid, scan_type, started_at, finished_at, files_found, files_scanned, files_failed, files_skipped, threats_found, threats_cleaned
			 FROM {{table}} WHERE status = %s AND scan_type IN ('manual','scheduled')
			 ORDER BY started_at DESC LIMIT 1",
			array( 'completed' ),
			ARRAY_A
		);
		if ( ! is_array( $row ) ) {
			return null;
		}
		// Read frozen counters from the row; manual cleanups
		// performed AFTER scan completion must not retroactively change the
		// summary line.
		$threats   = (int) $row['threats_found'];
		$cleaned   = (int) $row['threats_cleaned'];
		$started   = (int) $row['started_at'];
		$completed = null !== $row['finished_at'] ? (int) $row['finished_at'] : $started;
		$found     = (int) $row['files_found'];
		$verdicted = (int) $row['files_scanned'];
		return array(
			'scan_id'         => (string) $row['scan_uuid'],
			'files_found'     => $found,
			'files_verdicted' => $verdicted,
			'files_skipped'   => (int) $row['files_skipped'],
			'files_failed'    => (int) $row['files_failed'],
			'threats_found'   => $threats,
			'files_cleaned'   => $cleaned,
			'completed_at'    => $completed,
			'started_at'      => $started,
			'duration'        => max( 0, $completed - $started ),
			'scan_type'       => (string) $row['scan_type'],
			'completed'       => true,
			'phase'           => 'completed',
			'status'          => 'completed',
		);
	}

	/**
	 * Last terminal scan (completed | cancelled | aborted) for the manual /
	 * scheduled malware scanner. Used by `segurium_scan_tick` to surface a
	 * truthful summary after the runner finished between polls — without
	 * this, a cancelled run was masked by the previous completed scan.
	 *
	 * @return array|null
	 */
	public function get_last_terminal_scan() {
		$row = Segurium_Scan_Runner::last_terminal_scan();
		if ( ! is_array( $row ) ) {
			return null;
		}
		// Read frozen counters from the row.
		$threats   = (int) $row['threats_found'];
		$cleaned   = (int) $row['threats_cleaned'];
		$started   = (int) $row['started_at'];
		$completed = null !== $row['finished_at'] ? (int) $row['finished_at'] : $started;
		return array(
			'scan_id'         => (string) $row['scan_uuid'],
			'status'          => (string) $row['status'],
			'files_found'     => (int) $row['files_found'],
			'files_verdicted' => (int) $row['files_scanned'],
			'files_skipped'   => (int) $row['files_skipped'],
			'files_failed'    => (int) $row['files_failed'],
			'threats_found'   => $threats,
			'files_cleaned'   => $cleaned,
			'completed_at'    => $completed,
			'started_at'      => $started,
			'duration'        => max( 0, $completed - $started ),
			'scan_type'       => (string) $row['scan_type'],
			'completed'       => 'completed' === (string) $row['status'],
			'phase'           => 'completed',
		);
	}

	/**
	 * Get the time limit for scan processing chunks.
	 *
	 * @return int Time limit in seconds.
	 */
	public function get_scan_time_limit() {
		$max = (int) ini_get( 'max_execution_time' );
		if ( $max <= 0 ) {
			$max = 30;
		}
		// Use 40% of max_execution_time, clamped between 5 and 25 seconds.
		$limit = (int) floor( $max * 0.4 );
		return max( 5, min( 25, $limit ) );
	}

	/**
	 * AJAX handler for getting threat data.
	 *
	 * @return void
	 */
	public function ajax_get_threats() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$scan_id = isset( $_POST['scan_id'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_id'] ) ) : '';

		$latest_id = (string) Segurium_Storage::table_get_var(
			'scan_history',
			"SELECT scan_uuid FROM {{table}} WHERE scan_type IN ('manual','scheduled','realtime','upload') ORDER BY started_at DESC LIMIT 1"
		);
		$is_latest = ( '' !== $scan_id && $latest_id === $scan_id );

		if ( '' === $scan_id ) {
			$scan_id   = $latest_id;
			$is_latest = true;
		}
		if ( '' === $scan_id ) {
			segurium_send_json_error( array( 'message' => __( 'No scan results available', 'segurium' ) ) );
		}

		$scan          = $this->create_scan();
		$threats       = $scan->get_threats( null, null, $scan_id );
		$scanned_files = array(
			'paths'     => array(),
			'total'     => 0,
			'truncated' => false,
		);

		// scan_findings rows are append-only — their `status` reflects the
		// state at the moment of detection, not the current state of the
		// file. Overlay current_status from file_state so action buttons
		// (Clean / Restore / ...) reflect what the admin last did.
		$path_hashes = array();
		foreach ( $threats as $t ) {
			if ( ! empty( $t['path'] ) ) {
				$path_hashes[] = hash( 'sha256', (string) $t['path'] );
			}
		}
		$status_map = Segurium_File_State::get_status_map( $path_hashes );

		foreach ( $threats as &$t ) {
			$path           = isset( $t['path'] ) ? (string) $t['path'] : '';
			$current_status = '' !== $path && isset( $status_map[ hash( 'sha256', $path ) ] )
				? $status_map[ hash( 'sha256', $path ) ]
				: ( isset( $t['status'] ) ? (string) $t['status'] : 'open' );
			$t['status']    = $current_status;
			switch ( $current_status ) {
				case 'cured':
					$t['state'] = 'cleaned';
					break;
				case 'fixed':
					$t['state'] = 'fixed';
					break;
				case 'ignored':
					$t['state'] = 'ignored';
					break;
				default:
					$t['state'] = 'malware';
			}
		}
		unset( $t );

		segurium_send_json_success(
			array(
				'threats'        => $threats,
				'scanned_files'  => $scanned_files,
				'is_latest_scan' => $is_latest,
			)
		);
	}

	/**
	 * AJAX handler for cleaning up an infected file.
	 *
	 * @return void
	 */
	public function ajax_cleanup_file() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$path    = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
		$sha256  = isset( $_POST['sha256'] ) ? sanitize_text_field( wp_unslash( $_POST['sha256'] ) ) : '';
		$verdict = self::request_int( INPUT_POST, 'verdict' );
		$scan_id = isset( $_POST['scan_id'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_id'] ) ) : '';

		if ( empty( $path ) || empty( $sha256 ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters', 'segurium' ) ) );
		}

		// Resolve in 'write' mode so an in-root path that no
		// longer exists on disk falls through to the explicit File-not-found
		// branch below. 'read' mode collapses "outside ABSPATH" and "in-root
		// but file gone" into a single null and would mislabel a deleted
		// file as 403 Invalid path.
		$abs_path = $this->resolve_abs_within_wp_root( $path, 'write' );
		if ( null === $abs_path ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ), 403 );
		}

		if ( ! is_file( $abs_path ) ) {
			segurium_send_json_error( array( 'message' => __( 'File not found', 'segurium' ) ) );
		}

		// The rolling-window cap is enforced inside
		// `/v1/cleanup` on CTI now — the plugin no longer asks twice.
		// Paywall denial surfaces as `error_code = paywall_quota_exceeded`
		// on the cleanup primitive's result, with the envelope on
		// `paywall`; non-paywall failures still surface as plain errors.
		$result = Segurium_Cleanup::cleanup_file(
			$abs_path,
			$path,
			$sha256,
			$verdict,
			$scan_id,
			Segurium_Cleanup::ACTOR_MANUAL
		);
		if ( ! $result['ok'] ) {
			if ( 'paywall_quota_exceeded' === (string) $result['error_code'] ) {
				$envelope = is_array( $result['paywall'] ) && isset( $result['paywall']['quota'] )
					? (array) $result['paywall']['quota']
					: array();
				Segurium_Paywall_Telemetry::stamp_wall( $envelope );
				segurium_send_json_error(
					array_merge(
						array(
							'message' => __( 'Cleanup quota reached. Upgrade to Pro for an unbounded cloud cleanup quota.', 'segurium' ),
						),
						Segurium_Quota::paywall_payload(
							$envelope,
							Segurium_Paywall_Telemetry::ACTION_CLEANUP
						)
					),
					402
				);
			}
			segurium_send_json_error( array( 'message' => (string) $result['error'] ) );
		}

		// Prefer the post-charge quota envelope CTI echoes
		// in the `/v1/cleanup` 200 body — it carries the authoritative
		// `next_slot_at`, so the at-limit readout shows a real date
		// instead of "next slot opens —". Fall back to the
		// local bump for older CTI builds that omit the echo: that path
		// keeps the readout deterministic when a `/v1/quota/state`
		// re-fetch would silently no-op on a transient transport blip.
		$quota_echo = ( isset( $result['quota'] ) && is_array( $result['quota'] ) ) ? $result['quota'] : null;
		if ( null !== $quota_echo ) {
			Segurium_Quota::instance()->apply_cleanup_envelope( $quota_echo );
		} else {
			Segurium_Quota::instance()->record_consumed_slot();
		}

		segurium_send_json_success(
			array(
				'message'   => __( 'File cleaned', 'segurium' ),
				'backup_id' => $result['backup_id'],
				'quota'     => Segurium_Quota::instance()->state(),
			)
		);
	}

	/**
	 * AJAX handler for the read-only Free-tier quota readout.
	 * Returns the same envelope shape as Segurium_Quota::consume() but
	 * without consuming a slot. Pro short-circuits client-side via
	 * Segurium_Entitlements; the readout is only rendered for Free, and
	 * `fail_open=true` (CTI down) tells the front-end to hide rather than
	 * display a stale counter.
	 *
	 * @return void
	 */
	public function ajax_quota_state() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		// Wall-clock log line so future regressions are
		// visible without a fresh profile run. The pre-302 baseline was
		// ~1,070ms (synchronous CTI hop). With the SWR cache active a
		// readout at >100ms means the hot path regressed back to a
		// blocking CTI call.
		$started_us = microtime( true );

		$state = Segurium_Quota::instance()->state();

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			$elapsed_ms = ( microtime( true ) - $started_us ) * 1000.0;
			Segurium_Debug::log(
				sprintf(
					'[segurium] ajax_quota_state %.1fms cached_at=%d is_pro=%d fail_open=%d',
					$elapsed_ms,
					isset( $state['cached_at'] ) ? (int) $state['cached_at'] : 0,
					! empty( $state['is_pro'] ) ? 1 : 0,
					! empty( $state['fail_open'] ) ? 1 : 0
				)
			);
		}

		segurium_send_json_success( $state );
	}

	/**
	 * AJAX handler for restoring a file from backup.
	 *
	 * @return void
	 */
	public function ajax_restore_file() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_id'] ) ) : '';
		if ( empty( $backup_id ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing backup ID', 'segurium' ) ) );
		}

		$backup_entry = null;
		foreach ( Segurium_Storage::backup_list( 'malware' ) as $meta ) {
			if ( ( $meta['backup_id'] ?? '' ) === $backup_id ) {
				$backup_entry = $meta;
				break;
			}
		}
		if ( null === $backup_entry ) {
			segurium_send_json_error( array( 'message' => __( 'Backup not found', 'segurium' ) ) );
		}

		$restore = Segurium_Storage::backup_restore_detailed( 'malware', $backup_id );
		if ( null === $restore['content'] ) {
			segurium_send_json_error(
				array(
					'message' => $this->backup_restore_failure_message( $restore['reason'] ),
					'reason'  => $restore['reason'],
				)
			);
		}
		$content = $restore['content'];

		$target = isset( $backup_entry['original_path'] ) ? (string) $backup_entry['original_path'] : (string) ( $backup_entry['ref'] ?? '' );
		if ( '' === $target ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to restore file', 'segurium' ) ) );
		}
		$safe_target = $this->resolve_abs_within_wp_root( $this->strip_abspath( $target ), 'write' );
		if ( null === $safe_target ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid restore path', 'segurium' ) ), 403 );
		}
		$dir = dirname( $safe_target );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		if ( ! $this->write_in_place( $safe_target, $content ) ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to restore file', 'segurium' ) ) );
		}

		$rel_path = $this->strip_abspath( $safe_target );
		Segurium_File_State::mark_restored( (string) $rel_path, time() );

		Segurium_Storage::cti_send_message(
			'file_restored',
			wp_json_encode(
				array(
					'backup_id' => $backup_id,
				)
			)
		);

		segurium_send_json_success( array( 'message' => __( 'File restored from backup', 'segurium' ) ) );
	}

	/**
	 * AJAX handler: pre-flight check before restoring a file.
	 *
	 * Compares the current on-disk hash against the backed-up (malware) hash
	 * and the clean-replacement hash to decide which confirmation the UI
	 * should show.
	 *
	 * @return void
	 */
	public function ajax_restore_preflight() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_id'] ) ) : '';
		if ( empty( $backup_id ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing backup ID', 'segurium' ) ) );
		}

		$backup_entry = null;
		foreach ( Segurium_Storage::backup_list( 'malware' ) as $meta ) {
			if ( ( $meta['backup_id'] ?? '' ) === $backup_id ) {
				$backup_entry = $meta;
				break;
			}
		}
		if ( null === $backup_entry ) {
			segurium_send_json_error( array( 'message' => __( 'Backup not found', 'segurium' ) ) );
		}

		$target = isset( $backup_entry['original_path'] ) ? (string) $backup_entry['original_path'] : (string) ( $backup_entry['ref'] ?? '' );
		if ( '' === $target ) {
			segurium_send_json_error( array( 'message' => __( 'Backup has no target path', 'segurium' ) ) );
		}

		$safe_target = $this->resolve_abs_within_wp_root( $this->strip_abspath( $target ), 'write' );
		if ( null === $safe_target ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid restore path', 'segurium' ) ), 403 );
		}

		$rel_path = $this->strip_abspath( $safe_target );

		if ( ! file_exists( $safe_target ) ) {
			segurium_send_json_success(
				array(
					'exists' => false,
					'state'  => 'not_exists',
					'path'   => $rel_path,
				)
			);
		}

		$current_hash = Segurium_Fs::hash_file( 'sha256', $safe_target );
		if ( false === $current_hash ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to read target file', 'segurium' ) ) );
		}

		$malware_hash = $backup_entry['sha256_plain'] ?? '';
		$clean_hash   = $backup_entry['sha256_clean'] ?? '';

		if ( '' === $clean_hash ) {
			$db_clean = Segurium_Storage::table_get_var(
				'scan_findings',
				'SELECT sha256_clean FROM {{table}} WHERE file_path_hash = %s LIMIT 1',
				array( hash( 'sha256', $rel_path ) )
			);
			if ( ! empty( $db_clean ) ) {
				$clean_hash = (string) $db_clean;
			}
		}

		if ( '' !== $malware_hash && hash_equals( $malware_hash, $current_hash ) ) {
			$state = 'already_restored';
		} elseif ( '' !== $clean_hash && hash_equals( $clean_hash, $current_hash ) ) {
			$state = 'unchanged';
		} else {
			$state = 'modified';
		}

		segurium_send_json_success(
			array(
				'exists' => true,
				'state'  => $state,
				'path'   => $rel_path,
			)
		);
	}

	/**
	 * AJAX handler for getting backup file content.
	 *
	 * @return void
	 */
	public function ajax_get_backup_content() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_id'] ) ) : '';
		if ( empty( $backup_id ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing backup ID', 'segurium' ) ) );
		}

		$content = Segurium_Storage::backup_restore( 'malware', $backup_id );
		if ( null === $content ) {
			segurium_send_json_error( array( 'message' => __( 'Backup not found', 'segurium' ) ) );
		}

		// Base64-encode so non-UTF-8 / NUL-containing payloads survive
		// json_encode() and reach the admin "Show malware" modal intact.
		segurium_send_json_success(
			array(
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'content'  => base64_encode( $content ),
				'encoding' => 'base64',
			)
		);
	}

	/**
	 * Return the current on-disk bytes of an active-malware file so the
	 * admin can inspect the live payload. Only paths whose file_state
	 * row is currently in the malicious bucket ('open' or 'restored')
	 * are allowed — the endpoint is not a general file reader.
	 *
	 * @return void
	 */
	public function ajax_get_disk_content() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
		if ( '' === $path || false !== strpos( $path, "\0" ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ) );
		}

		$status = Segurium_File_State::get_status( $path );
		if ( 'open' !== $status && 'restored' !== $status ) {
			// Either the file is unknown to the scanner, or it's already
			// been handled (cured / fixed / ignored) — in both cases the
			// admin should use the backup viewer, not a raw disk read.
			segurium_send_json_error( array( 'message' => __( 'File is not an active malware entry.', 'segurium' ) ), 403 );
		}

		$abs_path = Segurium_Path_Helpers::wp_root() . ltrim( $path, '/' );
		$real     = Segurium_Fs::realpath( $abs_path );
		$base     = Segurium_Fs::realpath( Segurium_Path_Helpers::wp_root() );
		if ( false === $real || false === $base || 0 !== strpos( $real, rtrim( $base, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR ) ) {
			segurium_send_json_error( array( 'message' => __( 'File is outside the WordPress root.', 'segurium' ) ), 403 );
		}
		if ( ! is_file( $real ) || ! is_readable( $real ) ) {
			segurium_send_json_error( array( 'message' => __( 'File not found or not readable.', 'segurium' ) ) );
		}

		$max_bytes = 1024 * 1024;
		$size      = (int) Segurium_Fs::size( $real );
		if ( $size > $max_bytes ) {
			segurium_send_json_error(
				array(
					'message'   => __( 'File is too large to preview.', 'segurium' ),
					'size'      => $size,
					'max_bytes' => $max_bytes,
				)
			);
		}

		$content = Segurium_Fs::read( $real );
		if ( false === $content ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to read file.', 'segurium' ) ) );
		}

		$disk_sha256     = hash( 'sha256', $content );
		$recorded_sha256 = (string) Segurium_Storage::table_get_var(
			'file_state',
			'SELECT current_sha256 FROM {{table}} WHERE file_path_hash = %s LIMIT 1',
			array( hash( 'sha256', $path ) )
		);

		segurium_send_json_success(
			array(
				'content'         => $content,
				'sha256'          => $disk_sha256,
				'recorded_sha256' => $recorded_sha256,
				'size'            => $size,
				'sha256_mismatch' => ( '' !== $recorded_sha256 && $disk_sha256 !== $recorded_sha256 ),
			)
		);
	}

	/**
	 * AJAX handler for getting the server state.
	 *
	 * @return void
	 */
	public function ajax_get_server_state() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$page        = max( 1, self::request_int( INPUT_POST, 'page', 1 ) );
		$per_page    = self::request_int( INPUT_POST, 'per_page', 20 );
		$recent_only = self::request_bool( INPUT_POST, 'recent_only' );

		$allowed_per_page = array( 20, 50, 100, 1000 );
		if ( ! in_array( $per_page, $allowed_per_page, true ) ) {
			$per_page = 20;
		}

		$allowed_filters = array(
			Segurium_File_State::FILTER_ALL,
			Segurium_File_State::FILTER_MALICIOUS,
			Segurium_File_State::FILTER_CLEANED,
			Segurium_File_State::FILTER_FIXED,
			Segurium_File_State::FILTER_IGNORED,
		);
		$filter          = isset( $_POST['filter'] )
			? sanitize_key( wp_unslash( $_POST['filter'] ) )
			: Segurium_File_State::FILTER_MALICIOUS;
		if ( ! in_array( $filter, $allowed_filters, true ) ) {
			$filter = Segurium_File_State::FILTER_MALICIOUS;
		}

		$state = new Segurium_Server_State( $this->get_data_dir() );
		$state->load();

		$items  = $state->get_items( $page, $per_page, $recent_only, $filter );
		$total  = $state->get_total( $recent_only, $filter );
		$counts = $state->get_counts( $recent_only );

		segurium_send_json_success(
			array(
				'items'       => $items,
				'total'       => $total,
				'page'        => $page,
				'per_page'    => $per_page,
				'total_pages' => max( 1, (int) ceil( $total / $per_page ) ),
				'filter'      => $filter,
				'counts'      => $counts,
			)
		);
	}

	/**
	 * AJAX handler: batched initial-state read for the admin SPA.
	 *
	 * Collapses the three first-paint reads (server state, quota, CTI health)
	 * into a single admin-ajax round-trip so first paint pays one WP bootstrap
	 * tax instead of three. The legacy single-purpose handlers stay alive for
	 * subsequent reads (pagination, periodic CTI poll, post-action quota
	 * refresh, other callers).
	 *
	 * Accepts the same `page` / `per_page` / `recent_only` / `filter` params
	 * as ajax_get_server_state so the JS can request its initial server-state
	 * page in the same call.
	 *
	 * @return void
	 */
	public function ajax_get_initial_state() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$page        = max( 1, self::request_int( INPUT_POST, 'page', 1 ) );
		$per_page    = self::request_int( INPUT_POST, 'per_page', 20 );
		$recent_only = self::request_bool( INPUT_POST, 'recent_only' );

		$allowed_per_page = array( 20, 50, 100, 1000 );
		if ( ! in_array( $per_page, $allowed_per_page, true ) ) {
			$per_page = 20;
		}

		$allowed_filters = array(
			Segurium_File_State::FILTER_ALL,
			Segurium_File_State::FILTER_MALICIOUS,
			Segurium_File_State::FILTER_CLEANED,
			Segurium_File_State::FILTER_FIXED,
			Segurium_File_State::FILTER_IGNORED,
		);
		$filter          = isset( $_POST['filter'] )
			? sanitize_key( wp_unslash( $_POST['filter'] ) )
			: Segurium_File_State::FILTER_MALICIOUS;
		if ( ! in_array( $filter, $allowed_filters, true ) ) {
			$filter = Segurium_File_State::FILTER_MALICIOUS;
		}

		$state = new Segurium_Server_State( $this->get_data_dir() );
		$state->load();

		$items  = $state->get_items( $page, $per_page, $recent_only, $filter );
		$total  = $state->get_total( $recent_only, $filter );
		$counts = $state->get_counts( $recent_only );

		$server_state = array(
			'items'       => $items,
			'total'       => $total,
			'page'        => $page,
			'per_page'    => $per_page,
			'total_pages' => max( 1, (int) ceil( $total / $per_page ) ),
			'filter'      => $filter,
			'counts'      => $counts,
		);

		$quota = Segurium_Quota::instance()->state();

		// Reuse the same 5-minute transient cache as ajax_cti_health so the
		// batch read does not bypass the caching policy.
		$cached = get_transient( self::CTI_HEALTH_CACHE_KEY );
		if ( false === $cached ) {
			$healthy = Segurium_Storage::cti_health();
			set_transient( self::CTI_HEALTH_CACHE_KEY, $healthy ? '1' : '0', self::CTI_HEALTH_CACHE_TTL );
		} else {
			$healthy = ( '1' === $cached );
		}

		segurium_send_json_success(
			array(
				'server_state' => $server_state,
				'quota'        => $quota,
				'cti_health'   => array( 'healthy' => $healthy ),
			)
		);
	}

	/**
	 * AJAX handler for the malware-scanner "Fix all" button.
	 *
	 * Returns the list of currently-open malicious findings so the JS can
	 * iterate per-file cleanup. Per-file cleanups are quota-gated server-
	 * side by CTI; there is no local entitlement
	 * paywall, so the preview is available on every install.
	 *
	 * @return void
	 */
	public function ajax_scanner_fix_all_preview() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$state = new Segurium_Server_State( $this->get_data_dir() );
		$state->load();
		$items = $state->get_items( 1, 10000, false, Segurium_File_State::FILTER_MALICIOUS );

		$files = array();
		foreach ( (array) $items as $it ) {
			$path = isset( $it['path'] ) ? (string) $it['path'] : '';
			if ( '' === $path ) {
				continue;
			}
			$files[] = array(
				'path'    => $path,
				'sha256'  => isset( $it['sha256'] ) ? (string) $it['sha256'] : '',
				'verdict' => isset( $it['verdict'] ) ? (int) $it['verdict'] : 0,
			);
		}

		segurium_send_json_success(
			array(
				'count' => count( $files ),
				'files' => $files,
			)
		);
	}

	/**
	 * AJAX handler for getting scan status.
	 *
	 * @return void
	 */
	public function ajax_scan_status() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'You do not have permission to manage scans.', 'segurium' ),
				),
				403
			);
		}

		try {
			// Only return status for non-integrity scans so the malware
			// tab never shows integrity scan progress. The runner's
			// `shutdown` trigger drives life_support_system() on this
			// same request, so each poll both reads progress AND keeps
			// the worker alive.
			//
			// The chain-driven-malware suppression is gone. The malware tab is the canonical driver for
			// any non-integrity scan, regardless of whether a chain
			// marker is queued behind it. Stranded markers therefore
			// can no longer make a user-initiated malware scan look
			// like it isn't running.
			$status = Segurium_Scan_Runner::get_status();
			if ( null !== $status && 'integrity' === ( $status['scan_type'] ?? '' ) ) {
				$status = null;
			}
		} catch ( Throwable $e ) {
			$this->log_runner_exception( 'ajax_scan_status', $e );
			segurium_send_json_error(
				array(
					'code'    => 'scan_status_exception',
					'message' => $this->format_exception_message(
						__( 'Could not fetch scan status due to a server error.', 'segurium' ),
						$e
					),
				)
			);
		}

		if ( null === $status ) {
			$payload  = array( 'running' => false );
			$terminal = $this->get_last_terminal_scan();
			if ( null !== $terminal ) {
				// See Segurium_Scan_Runner::ajax_tick() — paired
				// payload shape so both status entry points behave the same.
				$payload['last_terminal'] = $terminal;
				if ( 'completed' === ( $terminal['status'] ?? '' ) ) {
					$payload['last_completed'] = $terminal;
				}
			}
			segurium_send_json_success( $payload );
			return;
		}

		segurium_send_json_success( $status );
	}

	/**
	 * AJAX handler for checking CTI service health.
	 *
	 * @return void
	 */
	public function ajax_cti_health() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		// 5-Minute server-side cache. The status indicator is
		// purely informational ("CTI Connected / Disconnected") and does not
		// gate any feature — a stale read for a few minutes is acceptable
		// and saves an outbound HTTP probe on every poll.
		$cached = get_transient( self::CTI_HEALTH_CACHE_KEY );
		if ( false === $cached ) {
			$healthy = Segurium_Storage::cti_health();
			set_transient( self::CTI_HEALTH_CACHE_KEY, $healthy ? '1' : '0', self::CTI_HEALTH_CACHE_TTL );
		} else {
			$healthy = ( '1' === $cached );
		}

		segurium_send_json_success( array( 'healthy' => $healthy ) );
	}

	/**
	 * Throttle WP Heartbeat on Segurium admin pages.
	 *
	 * The heartbeat default of 15s produces ~5,800 admin-ajax round-trips
	 * per day for a parked tab; bumping it to the 60s ceiling cuts that to
	 * ~1,440. Other admin pages are unaffected.
	 *
	 * @param array $settings Heartbeat settings array.
	 * @return array Filtered settings.
	 */
	public function throttle_heartbeat_settings( $settings ) {
		if ( ! $this->is_on_segurium_admin_page() ) {
			return $settings;
		}
		$settings['interval'] = 60;
		return $settings;
	}

	/**
	 * Detect whether the current request is rendering a Segurium admin page.
	 *
	 * Used to scope load-reduction filters (heartbeat
	 * throttle, server-side polling caches) to our own admin surface
	 * without affecting unrelated admin pages.
	 *
	 * @return bool
	 */
	private function is_on_segurium_admin_page() {
		// Read-only page-slug probe; no state is mutated.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only check of the admin page slug; no state is mutated.
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
		return '' !== $page && 0 === strpos( $page, 'segurium' );
	}

	/**
	 * Schedule immediate cron events for data sources that have never been fetched.
	 *
	 * Runs on every `init`. The check is cheap (two get_option calls).
	 * Once the data is fetched, the condition is false and nothing happens.
	 *
	 * @return void
	 */
	public function maybe_schedule_missing_data() {
		// Every CTI-touching catch-up below is gated on
		// consent. The plugin must not contact CTI before the user
		// accepts the External Service Disclosure.
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}

		if ( null === Segurium_IID::get_iid() ) {
			if ( ! wp_next_scheduled( self::IID_REGISTER_CRON_HOOK ) ) {
				wp_schedule_single_event( time(), self::IID_REGISTER_CRON_HOOK );
			}
		}

		if ( 0 === Segurium_Storage::setting_get_int( 'segurium_geo_updated_at' ) ) {
			if ( ! wp_next_scheduled( Segurium_Geo_Updater::RETRY_CRON_HOOK ) ) {
				wp_schedule_single_event( time(), Segurium_Geo_Updater::RETRY_CRON_HOOK );
			}
		}

		// Trusted-proxy timestamp lives in a deferred blob — Stage 6.
		if ( ! Segurium_Storage::setting_get( Segurium_Trusted_Proxies::OPTION_UPDATED_AT ) ) {
			if ( ! wp_next_scheduled( 'segurium_trusted_proxies_retry' ) ) {
				wp_schedule_single_event( time(), Segurium_Trusted_Proxies::CRON_HOOK );
			}
		}
	}

	/**
	 * Create and return an integrity scan state instance.
	 *
	 * @return Segurium_Integrity_Scan_State The scan state instance.
	 */
	private function create_integrity_scan_state() {
		$discovery = new Segurium_Integrity_Component_Discovery(
			Segurium_Path_Helpers::wp_root(),
			$this->get_scan_exclusions()
		);
		return new Segurium_Integrity_Scan_State(
			Segurium_Path_Helpers::wp_root(),
			$this->get_data_dir(),
			null,
			$discovery
		);
	}

	/**
	 * AJAX handler for starting an integrity scan via the runner.
	 *
	 * @return void
	 */
	public function ajax_integrity_start() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'Unauthorized', 'segurium' ),
				),
				403
			);
		}

		$this->handle_integrity_ajax(
			function () {
				// Gate on a fresh malware scan (<24h). When
				// stale, the chain helper kicks off a malware scan first
				// and queues the integrity scan to start on completion.
				$result = Segurium_Integrity_Chain::start_or_chain();

				if ( is_wp_error( $result ) ) {
					return array(
						'ok'      => false,
						'code'    => $result->get_error_code(),
						'message' => $result->get_error_message(),
					);
				}

				// Report only the integrity scan's own
				// state. When start_or_chain() returns kind=chain, the
				// chained malware scan runs under the malware tab; the
				// integrity tab waits in not-running state until its
				// turn arrives. `chain_message` is preserved as a
				// one-shot informational banner (e.g. "Running a quick
				// malware scan first…") with no implied "running" UX.
				return array(
					'ok'   => true,
					'data' => array(
						'scan_id'       => $result['scan_id'],
						'running'       => 'integrity' === $result['kind'],
						'queued'        => 'chain' === $result['kind'],
						'chain_message' => isset( $result['message'] ) ? $result['message'] : '',
					),
				);
			}
		);
	}

	/**
	 * AJAX handler for stopping an in-flight integrity scan.
	 *
	 * Mirrors `ajax_stop_scan` for the integrity engine so the user can
	 * clear a stuck or abandoned integrity scan without waiting for the
	 * watchdog. Only releases the lock if the active scan is integrity —
	 * a malware scan running under the chain helper is not affected.
	 *
	 * @return void
	 */
	public function ajax_integrity_stop() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'Unauthorized', 'segurium' ),
				),
				403
			);
		}

		$this->handle_integrity_ajax(
			function () {
				$lock = Segurium_Scan_Lock::get();
				if ( null === $lock ) {
					return array(
						'ok'   => true,
						'data' => array( 'stopped' => false ),
					);
				}
				if ( 'integrity' !== ( $lock['scan_type'] ?? '' ) ) {
					return array(
						'ok'      => false,
						'code'    => 'not_integrity_scan',
						'message' => __( 'No integrity scan is currently running.', 'segurium' ),
					);
				}
				$stopped = Segurium_Scan_Runner::stop();
				return array(
					'ok'   => true,
					'data' => array( 'stopped' => (bool) $stopped ),
				);
			}
		);
	}

	/**
	 * AJAX handler for polling integrity scan status.
	 *
	 * The integrity tab strictly mirrors the integrity
	 * scan entity's state. It no longer reads
	 * `Segurium_Integrity_Chain::is_chain_pending()` to derive a
	 * running indicator — that marker is a queue note, not live
	 * state, and a stranded marker from an aborted/cancelled chained
	 * malware scan would otherwise keep the tab "running" forever.
	 *
	 * @return void
	 */
	public function ajax_integrity_status() {
		check_ajax_referer( 'segurium_scan', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'unauthorized',
					'message' => __( 'Unauthorized', 'segurium' ),
				),
				403
			);
		}

		$this->handle_integrity_ajax(
			function () {
				$status = Segurium_Scan_Runner::get_status( 'integrity' );
				$msg    = Segurium_Integrity_Chain::pop_status_message();

				if ( null !== $status ) {
					$status['chain_message'] = $msg;
					return array(
						'ok'   => true,
						'data' => $status,
					);
				}

				$last_ts = (int) Segurium_Storage::table_get_var(
					'runtime_kv',
					'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
					array( 'integrity:last_scan' )
				);
				return array(
					'ok'   => true,
					'data' => array(
						'running'       => false,
						'completed'     => $last_ts > 0,
						'chain_message' => $msg,
					),
				);
			}
		);
	}

	/**
	 * AJAX envelope shared by the integrity start/status handlers.
	 *
	 * - Verifies nonce + capability.
	 * - Auto-heals schema drift (in case plugins_loaded ran before the tables
	 *   existed on a freshly-updated install).
	 * - Buffers output so stray echo/notices from other plugins or
	 *   dbDelta/WPDB error HTML cannot corrupt the JSON envelope.
	 * - Catches every Throwable so the browser always receives a structured
	 *   `{success:false, data:{code, message}}` instead of a blank or HTML
	 *   response (which JS surfaces as "Error: Unknown").
	 *
	 * @param callable $callback Closure returning ['ok'=>true,'data'=>…] or
	 *                           ['ok'=>false,'code'=>…,'message'=>…].
	 * @return void
	 */
	private function handle_integrity_ajax( callable $callback ) {
		// Nonce + capability are verified inline by each calling handler
		// (ajax_integrity_start / stop / status) before delegating here, so
		// this helper is a pure try/catch envelope around the callback.

		// Auto-heal in case this is the first request after a code update and
		// plugins_loaded @ 0 hasn't run yet (it has, but we're defense-in-depth).
		try {
			Segurium_Storage::ensure_schema();
		} catch ( Throwable $e ) {
			Segurium_Debug::log(
				'[segurium] ajax ensure_schema failed: ' . $e->getMessage()
			);
			segurium_send_json_error(
				array(
					'code'    => 'schema_unavailable',
					'message' => __( 'Scan storage is not ready. Please deactivate and reactivate the Segurium plugin, then try again.', 'segurium' ),
				)
			);
			return;
		}

		ob_start();
		try {
			$result = $callback();
		} catch ( Throwable $e ) {
			ob_end_clean();
			Segurium_Debug::log(
				sprintf( '[segurium] integrity ajax threw: %s at %s:%d', $e->getMessage(), $e->getFile(), $e->getLine() )
			);
			segurium_send_json_error(
				array(
					'code'    => 'unexpected_error',
					'message' => sprintf(
						/* translators: %s: underlying exception message */
						__( 'Unexpected error: %s', 'segurium' ),
						$e->getMessage()
					),
				)
			);
			return;
		}
		// Swallow any stray output captured during the handler — it would
		// otherwise appear before the JSON response and break JSON.parse on
		// the client.
		ob_end_clean();

		if ( is_array( $result ) && ! empty( $result['ok'] ) ) {
			segurium_send_json_success( $result['data'] ?? array() );
			return;
		}

		$code    = ( is_array( $result ) && isset( $result['code'] ) ) ? (string) $result['code'] : 'unexpected_error';
		$message = ( is_array( $result ) && isset( $result['message'] ) && '' !== $result['message'] )
			? (string) $result['message']
			: __( 'Unexpected error.', 'segurium' );
		segurium_send_json_error(
			array(
				'code'    => $code,
				'message' => $message,
			)
		);
	}

	/**
	 * Legacy shim: older admin JS may still POST to segurium_integrity_continue.
	 *
	 * @return void
	 */
	public function ajax_integrity_continue_legacy() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
		}
		segurium_send_json_error(
			array(
				'code'    => 'endpoint_removed',
				'message' => __( 'This endpoint has been removed. Please reload the page.', 'segurium' ),
			)
		);
	}

	/**
	 * Handle integrity scan completion dispatched by the runner.
	 *
	 * @param Segurium_Integrity_Scan_State $engine Completed engine.
	 * @return void
	 */
	public function on_integrity_scan_completed( $engine ) {
		if ( ! $engine instanceof Segurium_Integrity_Scan_State ) {
			return;
		}
		$state      = $engine->get_state();
		$results    = $state['results'] ?? array();
		$unverified = $state['unverified'] ?? array();
		if ( ! empty( $results ) || ! empty( $unverified ) ) {
			$this->update_integrity_server_state( $results, $unverified );
		}
	}

	/**
	 * Update the integrity server state from scan components.
	 *
	 * @param array $components      List of scanned components.
	 * @param array $unverified_keys "type:slug" keys CTI could not verify this
	 *                               scan. They are kept out of
	 *                               the not-found sweep but not reconciled, so
	 *                               a pre-existing open finding is never
	 *                               silently resolved by a chunk we never
	 *                               actually checked.
	 * @return void
	 */
	private function update_integrity_server_state( $components, $unverified_keys = array() ) {
		$acc = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$acc->load();

		$scanned_keys = array();
		foreach ( $components as $comp ) {
			$ok_count    = 0;
			$issue_files = array();

			foreach ( $comp['issues'] ?? array() as $issue ) {
				$issue_files[] = array(
					'path'         => $issue['path'] ?? '',
					'verdict'      => $issue['verdict'] ?? 'unknown',
					'state'        => $issue['status'] ?? 'open',
					'sha256'       => $issue['sha256'] ?? '',
					'correct_hash' => $issue['correct_hash'] ?? null,
					'backup_id'    => $issue['backup_id'] ?? null,
					'timestamp'    => time(),
				);
			}

			$ok_count = ( $comp['files'] ?? 0 ) - count( $issue_files );
			if ( $ok_count < 0 ) {
				$ok_count = 0;
			}

			$slug           = $comp['slug'] ?? '';
			$type           = $comp['type'] ?? '';
			$scanned_keys[] = $type . ':' . $slug;

			$acc->update_component(
				array(
					'slug'             => $slug,
					'type'             => $type,
					'name'             => $comp['name'] ?? $slug,
					'version'          => $comp['version'] ?? '',
					'path'             => $comp['path'] ?? '',
					'component_status' => $comp['component_status'] ?? 'listed',
					'last_updated'     => $comp['last_updated'] ?? null,
					'latest_version'   => $comp['latest_version'] ?? null,
					'ok_count'         => $ok_count,
					'files'            => $issue_files,
				)
			);
		}

		// Unverified components stay "present" (excluded from the not-found
		// sweep) but are not passed through update_component, so their existing
		// findings and metadata are left exactly as the last real scan saw them.
		foreach ( $unverified_keys as $uk ) {
			$scanned_keys[] = $uk;
		}

		$acc->mark_not_found( $scanned_keys );
		$acc->save();
	}

	/**
	 * AJAX handler for getting the integrity server state.
	 *
	 * @return void
	 */
	public function ajax_get_integrity_state() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$page     = max( 1, self::request_int( INPUT_POST, 'page', 1 ) );
		$per_page = self::request_int( INPUT_POST, 'per_page', 20 );
		if ( ! in_array( $per_page, array( 20, 50, 100, 1000 ), true ) ) {
			$per_page = 20;
		}

		$snapshot_id = isset( $_POST['snapshot_id'] ) ? sanitize_text_field( wp_unslash( $_POST['snapshot_id'] ) ) : '';
		// Hex-only id, capped: protect runtime_kv key length and reject probes.
		if ( '' !== $snapshot_id && ! preg_match( '/^[a-f0-9]{8,64}$/', $snapshot_id ) ) {
			$snapshot_id = '';
		}

		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();

		$items = $state->get_components( $page, $per_page, $snapshot_id );
		$total = $state->get_total();

		segurium_send_json_success(
			array(
				'items'       => $items,
				'total'       => $total,
				'page'        => $page,
				'per_page'    => $per_page,
				'total_pages' => max( 1, (int) ceil( $total / $per_page ) ),
			)
		);
	}

	/**
	 * Mark a file as ignored in the integrity accumulated state.
	 *
	 * @return void
	 */
	public function ajax_integrity_ignore_file() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$slug      = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '';
		$type      = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';
		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';

		if ( empty( $slug ) || empty( $type ) || empty( $file_path ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing parameters.', 'segurium' ) ) );
		}

		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();
		$state->update_file_state( $slug, $type, $file_path, 'ignored' );
		$state->save();

		segurium_send_json_success();
	}

	/**
	 * Mark a file as open (un-ignore) in the integrity accumulated state.
	 *
	 * @return void
	 */
	public function ajax_integrity_unignore_file() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$slug      = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '';
		$type      = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';
		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';

		if ( empty( $slug ) || empty( $type ) || empty( $file_path ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing parameters.', 'segurium' ) ) );
		}

		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();
		$state->update_file_state( $slug, $type, $file_path, 'open' );
		$state->save();

		segurium_send_json_success();
	}

	/**
	 * Two-step: restore a fixed file from backup, then mark as ignored.
	 * Used by the component-level Ignore action on abandoned components.
	 *
	 * @return void
	 */
	public function ajax_integrity_restore_and_ignore_file() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$slug      = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '';
		$type      = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';
		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
		$backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_id'] ) ) : '';

		if ( empty( $slug ) || empty( $type ) || empty( $file_path ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing parameters.', 'segurium' ) ) );
		}

		$file_path = ltrim( $file_path, '/' );
		$abs_path  = $this->resolve_abs_within_wp_root( $file_path, 'write' );
		if ( null === $abs_path ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ), 403 );
		}

		// Step 1: restore the pre-fix content from the integrity bucket.
		if ( ! empty( $backup_id ) ) {
			$restore = Segurium_Storage::backup_restore_detailed( 'integrity', $backup_id );
			if ( null === $restore['content'] ) {
				segurium_send_json_error(
					array(
						'message' => $this->backup_restore_failure_message( $restore['reason'] ),
						'reason'  => $restore['reason'],
					)
				);
			}
			$content = $restore['content'];
			$dir     = dirname( $abs_path );
			if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
				segurium_send_json_error( array( 'message' => __( 'Restore target directory is not writable.', 'segurium' ) ) );
			}
			if ( ! $this->write_in_place( $abs_path, $content ) ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to write restored file', 'segurium' ) ) );
			}
		}

		// Step 2: mark as ignored in both stores.
		$this->update_integrity_issue_status( $type, $slug, $file_path, 'ignored', null );

		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();
		$state->update_file_state( $slug, $type, $file_path, 'ignored' );
		$state->save();

		segurium_send_json_success();
	}

	/**
	 * View a file's content (base64-encoded).
	 *
	 * @return void
	 */
	public function ajax_integrity_view_file() {
		check_ajax_referer( 'segurium_integrity', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
		if ( empty( $file_path ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ) );
		}

		$abs_path = $this->resolve_abs_within_wp_root( $file_path, 'read' );
		if ( null === $abs_path ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ), 403 );
		}

		if ( ! is_file( $abs_path ) ) {
			segurium_send_json_error( array( 'message' => __( 'File not found', 'segurium' ) ) );
		}

		$size = Segurium_Fs::size( $abs_path );
		if ( $size > 2 * 1024 * 1024 ) {
			segurium_send_json_error( array( 'message' => __( 'File too large to view (>2 MB)', 'segurium' ) ) );
		}

		$content = Segurium_Fs::read( $abs_path );
		segurium_send_json_success(
			array(
				'path'    => $file_path,
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'content' => base64_encode( $content ),
			)
		);
	}

	/**
	 * Ignore an entire component (set component state to "ignored").
	 *
	 * @return void
	 */
	public function ajax_integrity_ignore_component() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$slug = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '';
		$type = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';

		if ( empty( $slug ) || empty( $type ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing parameters.', 'segurium' ) ) );
		}

		$t0    = microtime( true );
		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();
		$state->update_component_state( $slug, $type, 'ignored' );
		$state->save();

		Segurium_Storage::cti_log_component_action(
			array(
				'component_type' => $type,
				'slug'           => $slug,
				'version'        => '',
				'action'         => 'ignore',
				'files_count'    => 0,
				'bytes'          => 0,
				'backup_id'      => '',
				'success'        => 1,
				'error'          => '',
				'duration_ms'    => (int) round( ( microtime( true ) - $t0 ) * 1000 ),
			)
		);

		segurium_send_json_success();
	}

	/**
	 * Un-ignore an entire component (set component state back to "active").
	 *
	 * @return void
	 */
	public function ajax_integrity_unignore_component() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$slug = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '';
		$type = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';

		if ( empty( $slug ) || empty( $type ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing parameters.', 'segurium' ) ) );
		}

		$t0    = microtime( true );
		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();
		$state->update_component_state( $slug, $type, 'active' );
		$state->save();

		Segurium_Storage::cti_log_component_action(
			array(
				'component_type' => $type,
				'slug'           => $slug,
				'version'        => '',
				'action'         => 'unignore',
				'files_count'    => 0,
				'bytes'          => 0,
				'backup_id'      => '',
				'success'        => 1,
				'error'          => '',
				'duration_ms'    => (int) round( ( microtime( true ) - $t0 ) * 1000 ),
			)
		);

		segurium_send_json_success();
	}

	/**
	 * Delete an entire plugin/theme component with backup.
	 *
	 * @return void
	 */
	public function ajax_integrity_delete_component() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$type = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';
		$slug = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '';

		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) || empty( $slug ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters.', 'segurium' ) ) );
		}

		if ( ! $this->is_safe_component_slug( $slug ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters.', 'segurium' ) ) );
		}

		$t0      = microtime( true );
		$version = $this->lookup_component_version( $type, $slug );

		if ( 'plugin' === $type ) {
			$root_dir    = dirname( plugin_dir_path( SEGURIUM_PLUGIN_FILE ) );
			$abs_path    = $root_dir . '/' . $slug;
			$plugin_file = $this->find_plugin_main_file( $slug );
			if ( $plugin_file && is_plugin_active( $plugin_file ) ) {
				deactivate_plugins( $plugin_file );
			}
		} else {
			$root_dir     = get_theme_root();
			$abs_path     = $root_dir . '/' . $slug;
			$active_theme = wp_get_theme();
			if ( $active_theme->get_stylesheet() === $slug ) {
				segurium_send_json_error(
					array(
						'message' => __( 'Cannot delete the currently active theme. Switch to a different theme first.', 'segurium' ),
					)
				);
			}
		}

		if ( ! $this->is_path_within_root( $abs_path, $root_dir ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters.', 'segurium' ) ) );
		}

		if ( ! is_dir( $abs_path ) ) {
			Segurium_Storage::cti_log_component_action(
				array(
					'component_type' => $type,
					'slug'           => $slug,
					'version'        => $version,
					'action'         => 'delete',
					'files_count'    => 0,
					'bytes'          => 0,
					'backup_id'      => '',
					'success'        => 0,
					'error'          => 'component_dir_missing',
					'duration_ms'    => (int) round( ( microtime( true ) - $t0 ) * 1000 ),
				)
			);
			segurium_send_json_error( array( 'message' => __( 'Component directory not found.', 'segurium' ) ) );
		}

		$measurements = $this->measure_directory( $abs_path );

		$backup = new Segurium_Component_Backup();
		$result = $backup->create( $type, $slug, $abs_path );

		if ( is_wp_error( $result ) ) {
			Segurium_Storage::cti_log_component_action(
				array(
					'component_type' => $type,
					'slug'           => $slug,
					'version'        => $version,
					'action'         => 'delete',
					'files_count'    => $measurements['files'],
					'bytes'          => $measurements['bytes'],
					'backup_id'      => '',
					'success'        => 0,
					'error'          => (string) $result->get_error_code(),
					'duration_ms'    => (int) round( ( microtime( true ) - $t0 ) * 1000 ),
				)
			);
			segurium_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		$this->recursive_rmdir( $abs_path );

		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();
		$state->update_component_state( $slug, $type, 'deleted', $result['backup_id'] );
		$state->save();

		Segurium_Storage::cti_log_component_action(
			array(
				'component_type' => $type,
				'slug'           => $slug,
				'version'        => $version,
				'action'         => 'delete',
				'files_count'    => $measurements['files'],
				'bytes'          => $measurements['bytes'],
				'backup_id'      => (string) $result['backup_id'],
				'success'        => 1,
				'error'          => '',
				'duration_ms'    => (int) round( ( microtime( true ) - $t0 ) * 1000 ),
			)
		);

		segurium_send_json_success(
			array(
				'message'   => sprintf(
				/* translators: 1: component type, 2: component slug. */
					__( '%1$s "%2$s" has been deleted. A backup was created.', 'segurium' ),
					ucfirst( $type ),
					$slug
				),
				'backup_id' => $result['backup_id'],
			)
		);
	}

	/**
	 * Restore a previously deleted component from backup.
	 *
	 * @return void
	 */
	public function ajax_integrity_restore_component() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$type      = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';
		$slug      = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : '';
		$backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_id'] ) ) : '';

		if ( empty( $backup_id ) || empty( $slug ) || empty( $type ) ) {
			segurium_send_json_error( array( 'message' => __( 'Missing parameters.', 'segurium' ) ) );
		}

		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters.', 'segurium' ) ) );
		}

		if ( ! $this->is_safe_component_slug( $slug ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters.', 'segurium' ) ) );
		}

		$t0 = microtime( true );
		if ( 'plugin' === $type ) {
			$root_dir   = dirname( plugin_dir_path( SEGURIUM_PLUGIN_FILE ) );
			$restore_to = $root_dir . '/' . $slug;
		} else {
			$root_dir   = get_theme_root();
			$restore_to = $root_dir . '/' . $slug;
		}

		if ( ! $this->is_path_within_root( $restore_to, $root_dir ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters.', 'segurium' ) ) );
		}

		$backup = new Segurium_Component_Backup();
		$result = $backup->restore( $backup_id, $restore_to );

		if ( is_wp_error( $result ) ) {
			Segurium_Storage::cti_log_component_action(
				array(
					'component_type' => $type,
					'slug'           => $slug,
					'version'        => '',
					'action'         => 'restore',
					'files_count'    => 0,
					'bytes'          => 0,
					'backup_id'      => $backup_id,
					'success'        => 0,
					'error'          => (string) $result->get_error_code(),
					'duration_ms'    => (int) round( ( microtime( true ) - $t0 ) * 1000 ),
				)
			);
			segurium_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();
		$state->update_component_state( $slug, $type, 'active' );
		$state->save();

		// Re-activate plugin if it was deactivated during deletion.
		if ( 'plugin' === $type ) {
			$plugin_file = $this->find_plugin_main_file( $slug );
			if ( $plugin_file && ! is_plugin_active( $plugin_file ) ) {
				activate_plugin( $plugin_file );
			}
		}

		$measurements = $this->measure_directory( $restore_to );
		$version      = $this->lookup_component_version( $type, $slug );

		Segurium_Storage::cti_log_component_action(
			array(
				'component_type' => $type,
				'slug'           => $slug,
				'version'        => $version,
				'action'         => 'restore',
				'files_count'    => $measurements['files'],
				'bytes'          => $measurements['bytes'],
				'backup_id'      => $backup_id,
				'success'        => 1,
				'error'          => '',
				'duration_ms'    => (int) round( ( microtime( true ) - $t0 ) * 1000 ),
			)
		);

		segurium_send_json_success(
			array(
				'message' => sprintf(
				/* translators: 1: component type, 2: component slug. */
					__( '%1$s "%2$s" has been restored from backup.', 'segurium' ),
					ucfirst( $type ),
					$slug
				),
			)
		);
	}

	/**
	 * Build a detailed preview of what Fix All will do.
	 *
	 * @return void
	 */
	public function ajax_integrity_fix_all_preview() {
		check_ajax_referer( 'segurium_scan', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		// Fix All preview is available on every
		// install. Per-file fixes against malicious findings are quota-gated
		// inside CTI, so a Free site hitting "Fix All" cleans
		// the next-N-allowed and surfaces quota_exceeded for the rest from
		// the per-file path.
		$state = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$state->load();

		$preview = array(
			'files_replace'         => array(),
			'files_delete'          => array(),
			'components_delete'     => array(),
			'components_deactivate' => array(),
			'skipped'               => array(),
			'warnings'              => array(),
		);

		$active_theme = wp_get_theme();

		foreach ( $state->get_all_active_components() as $comp ) {
			$is_known  = 'not_in_repository' !== ( $comp['component_status'] ?? 'listed' );
			$is_plugin = 'plugin' === $comp['type'];
			$is_theme  = 'theme' === $comp['type'];
			$is_core   = 'core' === $comp['type'];
			$cs        = $comp['component_status'] ?? 'listed';

			// Delisted → delete component.
			if ( 'delisted' === $cs && ! $is_core ) {
				if ( $is_plugin ) {
					$pf = $this->find_plugin_main_file( $comp['slug'] );
					if ( $pf && is_plugin_active( $pf ) ) {
						$preview['components_deactivate'][] = array(
							'slug' => $comp['slug'],
							'type' => $comp['type'],
						);
					}
				} elseif ( $is_theme && $active_theme->get_stylesheet() === $comp['slug'] ) {
					$preview['skipped'][] = array(
						'slug'   => $comp['slug'],
						'type'   => $comp['type'],
						'reason' => __( 'Cannot delete active theme. Switch first.', 'segurium' ),
					);
					continue;
				}
				$preview['components_delete'][] = array(
					'slug'   => $comp['slug'],
					'type'   => $comp['type'],
					'reason' => __( 'Delisted from WordPress.org', 'segurium' ),
				);
				continue;
			}

			// Abandoned.
			if ( 'abandoned' === $cs && ! $is_core ) {
				if ( $is_theme && $active_theme->get_stylesheet() === $comp['slug'] ) {
					$preview['warnings'][] = sprintf(
						/* translators: %s: theme slug. */
						__( 'Theme "%s" is abandoned but currently active. It will be skipped.', 'segurium' ),
						$comp['slug']
					);
					$preview['skipped'][] = array(
						'slug'   => $comp['slug'],
						'type'   => $comp['type'],
						'reason' => __( 'Active abandoned theme — switch manually.', 'segurium' ),
					);
					continue;
				}
				if ( $is_plugin ) {
					$pf = $this->find_plugin_main_file( $comp['slug'] );
					if ( $pf && is_plugin_active( $pf ) ) {
						$preview['components_deactivate'][] = array(
							'slug' => $comp['slug'],
							'type' => $comp['type'],
						);
					}
				}
				$preview['components_delete'][] = array(
					'slug'   => $comp['slug'],
					'type'   => $comp['type'],
					'reason' => __( 'Abandoned (no updates >2 years)', 'segurium' ),
				);
				continue;
			}

			// Unknown → skip.
			if ( ! $is_known ) {
				$preview['skipped'][] = array(
					'slug'   => $comp['slug'],
					'type'   => $comp['type'],
					'reason' => __( 'Not from WordPress.org — integrity cannot be verified.', 'segurium' ),
				);
				continue;
			}

			// File-level actions for known components.
			$comp_version = $comp['version'] ?? '';
			$vnf_count    = 0;
			foreach ( $comp['files'] ?? array() as $f ) {
				if ( 'open' !== ( $f['state'] ?? '' ) ) {
					continue;
				}
				// Defense-in-depth. The walker never submits
				// excluded paths and CTI only echoes verdicts for submitted
				// files, so an open row on a protected path can only be stale
				// state or a future verdict source. Never queue one.
				if ( Segurium_Integrity::is_excluded( $f['path'] ) ) {
					$preview['skipped'][] = array(
						'slug'   => $comp['slug'],
						'type'   => $comp['type'],
						'path'   => $f['path'],
						'reason' => __( 'Protected file (exclusion list).', 'segurium' ),
					);
					continue;
				}
				$verdict = $f['verdict'] ?? '';
				if ( 'modified' === $verdict || 'missing' === $verdict ) {
					$preview['files_replace'][] = array(
						'component' => $comp['slug'],
						'type'      => $comp['type'],
						'version'   => $comp_version,
						'path'      => $f['path'],
						'sha256'    => $f['sha256'] ?? '',
						'verdict'   => $verdict,
						'size'      => $this->safe_filesize_within_wp_root( $f['path'] ),
					);
				} elseif ( 'unknown' === $verdict ) {
					$preview['files_delete'][] = array(
						'component' => $comp['slug'],
						'type'      => $comp['type'],
						'version'   => $comp_version,
						'path'      => $f['path'],
						'sha256'    => $f['sha256'] ?? '',
						'size'      => $this->safe_filesize_within_wp_root( $f['path'] ),
					);
				} elseif ( 'version_not_found' === $verdict ) {
					// CTI stamps this verdict on every file of a
					// component whose version it cannot resolve; there is
					// nothing to restore from and bulk-deleting would wipe the
					// component. Collapse to one skipped row after the loop.
					++$vnf_count;
				} else {
					// Fail closed on any verdict without a fix
					// recipe (`unavailable`, future additions) instead of
					// silently dropping the row from the preview.
					$preview['skipped'][] = array(
						'slug'   => $comp['slug'],
						'type'   => $comp['type'],
						'path'   => $f['path'],
						'reason' => sprintf(
							/* translators: %s: file verdict reported by the integrity check. */
							__( 'No automatic fix for verdict "%s".', 'segurium' ),
							$verdict
						),
					);
				}
			}
			if ( $vnf_count > 0 ) {
				$preview['skipped'][] = array(
					'slug'   => $comp['slug'],
					'type'   => $comp['type'],
					'reason' => sprintf(
						/* translators: %d: number of files. */
						_n(
							'Component version not recognized. %d file cannot be verified.',
							'Component version not recognized. %d files cannot be verified.',
							$vnf_count,
							'segurium'
						),
						$vnf_count
					),
				);
			}
		}

		// Simulate the integrity bucket rotation that would
		// happen once we start writing pre-fix backups. Only modified-file
		// replacements and unknown-file deletions create envelopes — missing
		// files are re-downloaded with no backup. Use plaintext sizes; the
		// envelope is gzipped+encrypted so this is an upper bound, which is
		// the right side to err on for a pre-flight warning.
		$pending_sizes = array();
		$bytes_total   = 0;
		foreach ( $preview['files_replace'] as $row ) {
			$sz           = (int) ( $row['size'] ?? 0 );
			$bytes_total += $sz;
			if ( 'modified' === ( $row['verdict'] ?? '' ) && $sz > 0 ) {
				$pending_sizes[] = $sz;
			}
		}
		foreach ( $preview['files_delete'] as $row ) {
			$sz           = (int) ( $row['size'] ?? 0 );
			$bytes_total += $sz;
			if ( $sz > 0 ) {
				$pending_sizes[] = $sz;
			}
		}

		$sim                        = Segurium_Storage::backup_simulate_rotation( 'integrity', $pending_sizes );
		$preview['bucket_eviction'] = array(
			'files_count'              => count( $preview['files_replace'] ) + count( $preview['files_delete'] ),
			'bytes_total'              => $bytes_total,
			'bucket_used_count'        => $sim['bucket_used_count'],
			'bucket_used_bytes'        => $sim['bucket_used_bytes'],
			'bucket_max_count'         => $sim['bucket_max_count'],
			'bucket_max_bytes'         => $sim['bucket_max_bytes'],
			'would_evict_count'        => $sim['would_evict_count'],
			'would_evict_bytes'        => $sim['would_evict_bytes'],
			'would_evict_pinned_count' => $sim['would_evict_pinned_count'],
		);

		$preview['summary'] = array(
			'files_replace'         => count( $preview['files_replace'] ),
			'files_delete'          => count( $preview['files_delete'] ),
			'components_delete'     => count( $preview['components_delete'] ),
			'components_deactivate' => count( $preview['components_deactivate'] ),
			'skipped'               => count( $preview['skipped'] ),
			'warnings'              => count( $preview['warnings'] ),
		);

		segurium_send_json_success( $preview );
	}

	/**
	 * Safe `filesize()` for a WP-root-relative path. Returns 0 on any failure
	 * (path traversal, missing file, unreadable). Used by the Integrity Fix-all
	 * preview to size the envelopes that the batch is about to create.
	 *
	 * @param string $rel_path Path relative to ABSPATH (no leading slash).
	 */
	private function safe_filesize_within_wp_root( $rel_path ): int {
		$abs = $this->resolve_abs_within_wp_root( (string) $rel_path, 'read' );
		if ( null === $abs ) {
			return 0;
		}
		$sz = Segurium_Fs::size( $abs );
		return ( false === $sz ) ? 0 : (int) $sz;
	}

	/**
	 * Find the main plugin file for a given slug.
	 *
	 * @param string $slug Plugin slug (directory name).
	 * @return string|null Plugin file relative to plugins directory, or null.
	 */
	private function find_plugin_main_file( $slug ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			Segurium_Path_Helpers::wp_admin_include( 'plugin.php' );
		}
		$plugins = get_plugins();
		foreach ( $plugins as $file => $data ) {
			if ( dirname( $file ) === $slug || $file === $slug . '.php' ) {
				return $file;
			}
		}
		return null;
	}

	/**
	 * Resolve a component's installed version string for CTI reporting.
	 *
	 * @param string $type plugin|theme|core.
	 * @param string $slug Component slug.
	 * @return string Version string, or '' if unknown.
	 */
	private function lookup_component_version( $type, $slug ) {
		if ( 'core' === $type ) {
			return function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'version' ) : '';
		}
		if ( 'plugin' === $type ) {
			$file = $this->find_plugin_main_file( $slug );
			if ( ! $file ) {
				return '';
			}
			if ( ! function_exists( 'get_plugins' ) ) {
				Segurium_Path_Helpers::wp_admin_include( 'plugin.php' );
			}
			$plugins = get_plugins();
			return isset( $plugins[ $file ]['Version'] ) ? (string) $plugins[ $file ]['Version'] : '';
		}
		if ( 'theme' === $type ) {
			$theme = wp_get_theme( $slug );
			return $theme->exists() ? (string) $theme->get( 'Version' ) : '';
		}
		return '';
	}

	/**
	 * Count files and total bytes under a directory. Used to size
	 * component-level integrity actions for the CTI report. Returns zeros on
	 * missing / unreadable paths — a report with zeros is still useful.
	 *
	 * @param string $dir Directory path.
	 * @return array { files: int, bytes: int }
	 */
	private function measure_directory( $dir ) {
		$out = array(
			'files' => 0,
			'bytes' => 0,
		);
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		try {
			$iter = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::SELF_FIRST
			);
			foreach ( $iter as $item ) {
				if ( $item->isFile() ) {
					++$out['files'];
					$out['bytes'] += (int) $item->getSize();
				}
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] measure_directory: ' . $e->getMessage() );
		}
		return $out;
	}

	/**
	 * Recursively delete a directory.
	 *
	 * Uses getPathname() + isLink() so symlinks inside the tree are unlinked
	 * without following them — deleting the target of a symlink (e.g. a
	 * planted link to wp-config.php) must never happen.
	 *
	 * @param string $dir Directory path.
	 * @return bool
	 */
	private function recursive_rmdir( $dir ) {
		if ( ! is_dir( $dir ) || is_link( $dir ) ) {
			return false;
		}
		$items = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $items as $item ) {
			$path = $item->getPathname();
			if ( $item->isDir() && ! $item->isLink() ) {
				Segurium_Fs::rmdir( $path );
			} else {
				Segurium_Fs::delete( $path );
			}
		}
		return Segurium_Fs::rmdir( $dir );
	}

	/**
	 * AJAX handler for ignoring a file.
	 *
	 * @return void
	 */
	public function ajax_ignore_file() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$path        = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
		$sha256      = isset( $_POST['sha256'] ) ? sanitize_text_field( wp_unslash( $_POST['sha256'] ) ) : '';
		$ignore_type = isset( $_POST['ignore_type'] ) ? sanitize_text_field( wp_unslash( $_POST['ignore_type'] ) ) : '';

		if ( empty( $path ) || ! in_array( $ignore_type, array( 'path', 'hash' ), true ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters', 'segurium' ) ) );
		}

		if ( 'hash' === $ignore_type && empty( $sha256 ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters', 'segurium' ) ) );
		}

		$ignore = new Segurium_Ignore_Lists( $this->get_data_dir() );
		$ignore->load();

		if ( 'path' === $ignore_type ) {
			$ignore->add_path( $path );
		} else {
			$ignore->add_hash( $path, $sha256 );
		}
		$ignore->save();

		$server_state = new Segurium_Server_State( $this->get_data_dir() );
		$server_state->load();
		$server_state->ignore_file( $path, $ignore_type );
		$server_state->save();

		Segurium_Storage::cti_send_message(
			'file_ignored',
			wp_json_encode(
				array(
					'path'        => $path,
					'sha256'      => $sha256,
					'ignore_type' => $ignore_type,
				)
			)
		);

		segurium_send_json_success();
	}

	/**
	 * AJAX handler for submitting a False-Positive report.
	 *
	 * Reads the malware row's file from disk, gzips it, posts to the CTI
	 * /v1/submissions endpoint, and (when the "ignore on this site" box
	 * was checked) adds a hash entry to the local ignore list so the file
	 * stops surfacing as malware on subsequent scans.
	 *
	 * @return void
	 */
	public function ajax_submit_fp_report() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$path        = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
		$sha256      = isset( $_POST['sha256'] ) ? sanitize_text_field( wp_unslash( $_POST['sha256'] ) ) : '';
		$component   = isset( $_POST['component'] ) ? sanitize_text_field( wp_unslash( $_POST['component'] ) ) : '';
		$verdict     = isset( $_POST['verdict'] ) ? sanitize_text_field( wp_unslash( $_POST['verdict'] ) ) : '';
		$note        = isset( $_POST['note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['note'] ) ) : '';
		$also_ignore = isset( $_POST['also_ignore'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['also_ignore'] ) );

		if ( '' === $path || ! preg_match( '/^[0-9a-f]{64}$/', $sha256 ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters', 'segurium' ) ) );
		}
		if ( strlen( $note ) > 2000 ) {
			$note = substr( $note, 0, 2000 );
		}

		$abs = $this->resolve_abs_within_wp_root( $path, 'read' );
		if ( null === $abs || ! is_file( $abs ) || ! is_readable( $abs ) ) {
			segurium_send_json_error( array( 'message' => __( 'File not found on disk.', 'segurium' ) ) );
		}
		$size = Segurium_Fs::size( $abs );
		if ( false === $size || $size > Segurium_Scanner::MAX_FILE_SIZE ) {
			segurium_send_json_error( array( 'message' => __( 'File is too large to submit.', 'segurium' ) ) );
		}
		$body = Segurium_Fs::read( $abs );
		if ( false === $body ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to read file.', 'segurium' ) ) );
		}
		if ( strtolower( hash( 'sha256', $body ) ) !== $sha256 ) {
			segurium_send_json_error( array( 'message' => __( 'File contents changed since the scan.', 'segurium' ) ) );
		}
		$gz = gzencode( $body, 6 );
		if ( false === $gz ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to compress file.', 'segurium' ) ) );
		}

		$user   = wp_get_current_user();
		$domain = wp_parse_url( home_url(), PHP_URL_HOST );

		$client = new Segurium_CTI_Client();
		$result = $client->submit_fp(
			array(
				'report_type' => 'fp',
				'sha256'      => $sha256,
				'size_raw'    => (int) $size,
				'path'        => $path,
				'note'        => $note,
				'admin_name'  => $user ? (string) $user->display_name : '',
				'admin_email' => $user ? (string) $user->user_email : '',
				'site_domain' => is_string( $domain ) ? $domain : '',
				'component'   => $component,
				'verdict'     => $verdict,
			),
			$gz
		);
		if ( is_wp_error( $result ) ) {
			segurium_send_json_error(
				array(
					'message' => $result->get_error_message(),
					'code'    => $result->get_error_code(),
				)
			);
		}

		$ignored = false;
		if ( $also_ignore ) {
			$ignore = new Segurium_Ignore_Lists( $this->get_data_dir() );
			$ignore->load();
			$ignore->add_hash( $path, $sha256 );
			$ignore->save();

			$server_state = new Segurium_Server_State( $this->get_data_dir() );
			$server_state->load();
			$server_state->ignore_file( $path, 'hash' );
			$server_state->save();
			$ignored = true;
		}

		segurium_send_json_success(
			array(
				'submission_id' => isset( $result['submission_id'] ) ? (string) $result['submission_id'] : '',
				'ignored'       => $ignored,
			)
		);
	}

	/**
	 * AJAX handler for removing a file from the ignore list.
	 *
	 * @return void
	 */
	public function ajax_unignore_file() {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
		if ( empty( $path ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters', 'segurium' ) ) );
		}

		$ignore = new Segurium_Ignore_Lists( $this->get_data_dir() );
		$ignore->load();
		$ignore->remove_path( $path );
		$ignore->remove_hash( $path );
		$ignore->save();

		$server_state = new Segurium_Server_State( $this->get_data_dir() );
		$server_state->load();
		$server_state->update_file_state( $path, 'malicious' );
		$server_state->save();

		segurium_send_json_success();
	}

	/**
	 * Update the server state from scan results.
	 *
	 * @param Segurium_Scan $scan The completed scan instance.
	 * @return void
	 */
	private function update_server_state_from_scan( $scan ) {
		$threats       = $scan->get_threats();
		$scanned_paths = $scan->get_verdicted_paths();
		$threat_paths  = array();
		foreach ( $threats as $t ) {
			if ( ! empty( $t['path'] ) ) {
				$threat_paths[] = (string) $t['path'];
			}
		}
		$state = new Segurium_Server_State();
		$state->mark_fixed_after_scan( $threat_paths, $scanned_paths, time() );
	}

	/**
	 * Strip the ABSPATH prefix from a file path.
	 *
	 * @param string $path Full file path.
	 * @return string Relative path.
	 */
	private function strip_abspath( $path ) {
		$base = rtrim( Segurium_Path_Helpers::wp_root(), '/' ) . '/';
		if ( 0 === strpos( $path, $base ) ) {
			return substr( $path, strlen( $base ) );
		}
		return $path;
	}

	/**
	 * Write restored/cleaned bytes back to a path already confined to the
	 * WordPress root by {@see resolve_abs_within_wp_root()}. This is the single
	 * raw-write site shared by every integrity-repair / restore branch, so the
	 * one annotated call documents the intent once instead of at each caller.
	 *
	 * @param string $abs_path Confined absolute destination under the WP root.
	 * @param string $content  Bytes to write.
	 * @return bool True on success.
	 */
	private function write_in_place( $abs_path, $content ) {
		// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- in-place repair to the verified WP-root path from resolve_abs_within_wp_root(); the original infected file IS the destination, so wp_upload_dir() is wrong by design and this never targets the plugin folder.
		return false !== Segurium_Fs::write( $abs_path, $content );
	}

	/**
	 * Resolve a client-supplied relative path to a canonical absolute path
	 * guaranteed to live under the WordPress root (ABSPATH).
	 *
	 * Returns null if the input would escape ABSPATH — via `..` segments,
	 * an absolute path, a null byte, or a symlink ancestor that points
	 * outside the tree. Any AJAX handler that turns $_POST into a
	 * filesystem target MUST call this and respond with 403 on null.
	 *
	 * Resolution walks up the candidate's ancestor chain until the deepest
	 * existing component is found via realpath(), verifies that component
	 * lies under ABSPATH, and reconstructs the canonical target by joining
	 * the ancestor's realpath with the remaining path suffix. This covers:
	 *   - read an existing file,
	 *   - write to a file whose parent dir already exists,
	 *   - restore a file after its parent dir has been deleted.
	 *
	 * @param string $rel_path Path relative to ABSPATH (leading slashes tolerated).
	 * @param string $mode     'read' = target must exist; 'write' = target may
	 *                         be created, parent chain must resolve under ABSPATH.
	 * @return string|null Canonical absolute path, or null when unsafe.
	 */
	private function resolve_abs_within_wp_root( $rel_path, $mode = 'read' ) {
		if ( ! is_string( $rel_path ) || '' === $rel_path ) {
			return null;
		}
		if ( false !== strpos( $rel_path, "\0" ) ) {
			return null;
		}
		$rel_path = ltrim( $rel_path, '/\\' );
		if ( '' === $rel_path ) {
			return null;
		}

		$wp_root = Segurium_Path_Helpers::wp_root();
		$base    = Segurium_Fs::realpath( $wp_root );
		if ( false === $base ) {
			return null;
		}
		$base_prefix = rtrim( $base, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR;

		$candidate = $wp_root . $rel_path;
		$suffix    = '';
		$probe     = $candidate;

		for ( $i = 0; $i < 64; $i++ ) {
			$real = Segurium_Fs::realpath( $probe );
			if ( false !== $real ) {
				$real_with_ds = rtrim( $real, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR;
				if ( $real_with_ds !== $base_prefix && 0 !== strpos( $real_with_ds, $base_prefix ) ) {
					return null;
				}
				$resolved = $real . $suffix;
				if ( 'read' === $mode && ! file_exists( $resolved ) ) {
					return null;
				}
				return $resolved;
			}
			$parent = dirname( $probe );
			if ( $parent === $probe ) {
				return null;
			}
			$suffix = DIRECTORY_SEPARATOR . basename( $probe ) . $suffix;
			$probe  = $parent;
		}
		return null;
	}

	/**
	 * Reject component slugs that can escape their plugin/theme root.
	 *
	 * A legitimate plugin/theme slug is a single path segment (no separators)
	 * with no parent-directory traversal and no NUL byte. Empty slug is
	 * rejected by callers before this is invoked.
	 *
	 * @param string $slug Candidate slug.
	 * @return bool True when safe to concatenate onto a root directory.
	 */
	private function is_safe_component_slug( $slug ) {
		if ( ! is_string( $slug ) || '' === $slug ) {
			return false;
		}
		if ( false !== strpos( $slug, '..' ) ) {
			return false;
		}
		if ( false !== strpos( $slug, '/' ) || false !== strpos( $slug, '\\' ) ) {
			return false;
		}
		if ( false !== strpos( $slug, "\0" ) ) {
			return false;
		}
		return true;
	}

	/**
	 * Verify that $abs_path resolves inside $root_dir.
	 *
	 * The component root (WP_PLUGIN_DIR / get_theme_root()) must exist, and
	 * the parent of $abs_path must realpath-resolve to that root — this
	 * catches symlinks in the slug component and traversal sequences that
	 * survived the slug validation.
	 *
	 * @param string $abs_path Candidate component directory.
	 * @param string $root_dir Expected parent root directory.
	 * @return bool
	 */
	private function is_path_within_root( $abs_path, $root_dir ) {
		$real_root = Segurium_Fs::realpath( $root_dir );
		if ( false === $real_root ) {
			return false;
		}
		$parent      = dirname( $abs_path );
		$real_parent = Segurium_Fs::realpath( $parent );
		if ( false === $real_parent ) {
			return false;
		}
		$root_with_ds   = rtrim( $real_root, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR;
		$parent_with_ds = rtrim( $real_parent, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR;
		return $root_with_ds === $parent_with_ds;
	}

	/**
	 * Create and return a verdict queue instance.
	 *
	 * @return Segurium_Verdict_Queue The verdict queue instance.
	 */
	private function create_verdict_queue() {
		return new Segurium_Verdict_Queue(
			$this->get_data_dir(),
			$this->get_scan_time_limit()
		);
	}

	/**
	 * Create and return a scan instance.
	 *
	 * @return Segurium_Scan The scan instance.
	 */
	private function create_scan() {
		$ignore = new Segurium_Ignore_Lists( $this->get_data_dir() );
		$ignore->load();

		$exclusions = array_merge(
			$this->get_scan_exclusions(),
			$ignore->get_path_list()
		);

		return new Segurium_Scan(
			Segurium_Path_Helpers::wp_root(),
			$this->get_data_dir(),
			$this->get_scan_time_limit(),
			$this->create_verdict_queue(),
			$exclusions
		);
	}

	/**
	 * Public accessor for the runner — returns a fresh scan instance
	 * wired with production defaults. Uses a tighter per-chunk time
	 * limit than the legacy AJAX path so the admin status poller sees
	 * frequent heartbeats; the overall per-invocation cap comes from
	 * `Segurium_Scan_Runner::tick_budget()`, which cooperates with
	 * `max_execution_time` (no `set_time_limit()` calls — forbidden by
	 * wp.org plugin-check).
	 *
	 * @return Segurium_Scan
	 */
	public function build_scan_for_runner() {
		$ignore = new Segurium_Ignore_Lists( $this->get_data_dir() );
		$ignore->load();

		$exclusions = array_merge(
			$this->get_scan_exclusions(),
			$ignore->get_path_list()
		);

		$time_limit = (int) apply_filters(
			'segurium_runner_chunk_time_limit',
			5
		);
		$time_limit = max( 1, $time_limit );

		$queue = new Segurium_Verdict_Queue( $this->get_data_dir(), $time_limit );

		return new Segurium_Scan(
			Segurium_Path_Helpers::wp_root(),
			$this->get_data_dir(),
			$time_limit,
			$queue,
			$exclusions
		);
	}

	/**
	 * Public accessor for the runner — returns a fresh integrity scan state
	 * wired with production defaults.
	 *
	 * @return Segurium_Integrity_Scan_State
	 */
	public function build_integrity_scan_for_runner() {
		return $this->create_integrity_scan_state();
	}

	/**
	 * Public accessor for the runner to update server state after a scan
	 * completes.
	 *
	 * @param Segurium_Scan $scan Completed scan instance.
	 * @return void
	 */
	public function update_server_state_from_scan_public( $scan ) {
		$this->update_server_state_from_scan( $scan );
	}

	/**
	 * Run the geo database update.
	 *
	 * @return void
	 */
	public function run_geo_db_update() {
		$updater = new Segurium_Geo_Updater( $this->get_data_dir() );
		$updater->trigger_update();
		$status = $updater->get_db_status();
		if ( ! $status['exists'] ) {
			Segurium_Geo_Updater::schedule_retry();
		}
	}

	/**
	 * AJAX handler for getting geo-blocking settings.
	 *
	 * @return void
	 */
	public function ajax_get_geo_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$blocker = Segurium_Geo_Blocker::get_instance();
		$updater = new Segurium_Geo_Updater( $this->get_data_dir() );
		segurium_send_json_success( array_merge( $blocker->get_settings(), $updater->get_db_status() ) );
	}

	/**
	 * AJAX handler for saving geo-blocking settings.
	 *
	 * @return void
	 */
	public function ajax_save_geo_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$data   = self::request_array( INPUT_POST, 'settings' );
		$result = Segurium_Geo_Blocker::get_instance()->save_settings( $data );

		if ( is_wp_error( $result ) ) {
			segurium_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		if ( null === $result ) {
			segurium_send_json_success(
				array(
					'token'      => null,
					'expires_in' => 0,
				)
			);
		}

		segurium_send_json_success(
			array(
				'token'      => $result,
				'expires_in' => Segurium_Pending_Changes::DEFAULT_TTL,
			)
		);
	}

	/**
	 * AJAX handler for triggering a geo database update.
	 *
	 * @return void
	 */
	public function ajax_trigger_geo_db_update() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$updater = new Segurium_Geo_Updater( $this->get_data_dir() );
		$result  = $updater->trigger_update();

		if ( is_wp_error( $result ) ) {
			segurium_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		segurium_send_json_success( $updater->get_db_status() );
	}

	/**
	 * AJAX handler for getting geo-blocking statistics.
	 *
	 * @return void
	 */
	public function ajax_get_geo_stats() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		segurium_send_json_success( Segurium_Geo_Blocker::get_instance()->get_stats() );
	}

	/**
	 * AJAX handler for confirming a pending change.
	 *
	 * @return void
	 */
	public function ajax_confirm_pending() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		$data  = Segurium_Pending_Changes::confirm( $token );

		if ( false === $data ) {
			segurium_send_json_error( array( 'message' => __( 'Pending change not found or already expired.', 'segurium' ) ) );
		}

		do_action( 'segurium_pending_confirmed', $data['context'], $data['old'], $data['new'] );
		segurium_send_json_success();
	}

	/**
	 * AJAX handler for reverting a pending change.
	 *
	 * @return void
	 */
	public function ajax_revert_pending() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		$data  = Segurium_Pending_Changes::revert( $token );

		if ( false === $data ) {
			segurium_send_json_error( array( 'message' => __( 'Pending change not found or already expired.', 'segurium' ) ) );
		}

		do_action( 'segurium_pending_reverted', $data['context'], $data['old'], $token );
		do_action( 'segurium_pending_revert', $data['context'], $data['old'], $token );
		segurium_send_json_success();
	}

	/**
	 * AJAX handler for getting firewall settings.
	 *
	 * @return void
	 */
	public function ajax_get_firewall_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		segurium_send_json_success(
			array(
				'enabled'         => Segurium_Storage::setting_get_bool( 'segurium_firewall_enabled' ),
				'mode'            => Segurium_Storage::setting_get_string( 'segurium_firewall_mode', 'deny_list' ),
				'ip_list'         => self::firewall_rules_read(),
				'trusted_proxies' => self::trusted_proxies_manual_read(),
			)
		);
	}

	/**
	 * Read user-managed firewall CIDR entries from the ip_list table.
	 *
	 * Implementation moved to Segurium_Firewall_Rules (firewall
	 * include group). Kept here as a thin BC delegator for existing callers.
	 *
	 * @return string[] Array of `<ip>/<bits>` strings.
	 */
	public static function firewall_rules_read() {
		return Segurium_Firewall_Rules::read();
	}

	/**
	 * Replace the user-managed firewall CIDR entries in ip_list.
	 *
	 * Implementation moved to Segurium_Firewall_Rules. BC delegator.
	 *
	 * @param string   $mode  `deny_list` or `allow_list`.
	 * @param string[] $cidrs Array of `<ip>/<bits>` strings.
	 */
	public static function firewall_rules_save( $mode, array $cidrs ) {
		Segurium_Firewall_Rules::save( $mode, $cidrs );
	}

	/**
	 * Read user-managed trusted-proxy CIDR entries from ip_list.
	 *
	 * @return string[]
	 */
	public static function trusted_proxies_manual_read() {
		// Storage helpers moved to Segurium_Trusted_Proxies
		// (firewall include group) so the geo-blocker pending-revert path
		// works without the heavy Segurium class loaded. Kept here as a
		// thin BC delegator for existing callers.
		return Segurium_Trusted_Proxies::manual_read();
	}

	/**
	 * Replace user-managed trusted proxy entries in ip_list.
	 *
	 * @param string[] $cidrs Array of CIDR strings.
	 */
	public static function trusted_proxies_manual_save( array $cidrs ) {
		Segurium_Trusted_Proxies::manual_save( $cidrs );
	}

	/**
	 * AJAX handler for saving firewall settings.
	 *
	 * @return void
	 */
	public function ajax_save_firewall_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$data    = self::request_array( INPUT_POST, 'settings' );
		$enabled = ! empty( $data['enabled'] );
		$mode    = ( 'allow_list' === ( $data['mode'] ?? '' ) ) ? 'allow_list' : 'deny_list';

		$ip_list         = $this->sanitize_ip_list( (array) ( $data['ip_list'] ?? array() ) );
		$trusted_proxies = $this->sanitize_ip_list( (array) ( $data['trusted_proxies'] ?? array() ) );

		$old = array(
			'enabled'         => Segurium_Storage::setting_get_bool( 'segurium_firewall_enabled' ),
			'mode'            => Segurium_Storage::setting_get_string( 'segurium_firewall_mode', 'deny_list' ),
			'ip_list'         => self::firewall_rules_read(),
			'trusted_proxies' => self::trusted_proxies_manual_read(),
		);

		Segurium_Storage::setting_set( 'segurium_firewall_enabled', $enabled );
		Segurium_Storage::setting_set( 'segurium_firewall_mode', $mode );
		self::firewall_rules_save( $mode, $ip_list );
		self::trusted_proxies_manual_save( $trusted_proxies );

		if ( ! $enabled ) {
			$existing = Segurium_Storage::setting_get( 'segurium_pending_ctx_firewall' );
			if ( $existing ) {
				Segurium_Pending_Changes::cancel( $existing );
			}
			segurium_send_json_success(
				array(
					'token'      => null,
					'expires_in' => 0,
				)
			);
			return;
		}

		$new   = array(
			'enabled'         => true,
			'mode'            => $mode,
			'ip_list'         => $ip_list,
			'trusted_proxies' => $trusted_proxies,
		);
		$token = Segurium_Pending_Changes::stage( 'firewall', $old, $new );

		segurium_send_json_success(
			array(
				'token'      => $token,
				'expires_in' => Segurium_Pending_Changes::DEFAULT_TTL,
			)
		);
	}

	/**
	 * AJAX: return the auto-fetched trusted proxies status.
	 *
	 * @return void
	 */
	public function ajax_get_trusted_proxies_status() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		segurium_send_json_success( Segurium_Trusted_Proxies::get_status() );
	}

	/**
	 * AJAX: trigger an immediate trusted proxies refresh.
	 *
	 * @return void
	 */
	public function ajax_trigger_trusted_proxies_update() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$result = Segurium_Trusted_Proxies::fetch();
		if ( is_wp_error( $result ) ) {
			segurium_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		segurium_send_json_success( Segurium_Trusted_Proxies::get_status() );
	}

	/**
	 * AJAX handler for fixing an integrity issue file.
	 *
	 * @return void
	 */
	public function ajax_integrity_fix_file() {
		check_ajax_referer( 'segurium_integrity', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$comp_type    = isset( $_POST['comp_type'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_type'] ) ) : '';
		$comp_slug    = isset( $_POST['comp_slug'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_slug'] ) ) : '';
		$comp_version = isset( $_POST['comp_version'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_version'] ) ) : '';
		$file_path    = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';
		$sha256       = isset( $_POST['sha256'] ) ? sanitize_text_field( wp_unslash( $_POST['sha256'] ) ) : '';
		$verdict      = isset( $_POST['verdict'] ) ? sanitize_text_field( wp_unslash( $_POST['verdict'] ) ) : '';

		if ( ! in_array( $comp_type, array( 'core', 'plugin', 'theme' ), true )
			|| empty( $file_path )
			|| ! in_array( $verdict, array( 'modified', 'missing', 'new' ), true )
			|| false !== strpos( $comp_slug, '..' )
		) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters', 'segurium' ) ) );
		}

		$file_path = ltrim( $file_path, '/' );

		// file_path is always relative to ABSPATH (e.g. "wp-content/plugins/akismet/readme.txt").
		// 'missing' restores a file that's absent on disk by definition — the
		// 'read' mode would refuse before we get a chance to recreate it, so
		// allow 'write' mode for that branch.
		$resolve_mode = 'missing' === $verdict ? 'write' : 'read';
		$abs_path     = $this->resolve_abs_within_wp_root( $file_path, $resolve_mode );
		if ( null === $abs_path ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ), 403 );
		}

		// Derive the canonical relative form of the target for
		// the guard only — a spelling like "./aios-bootstrap.php" resolves
		// to the loader while matching none of the root-anchored patterns.
		// $file_path itself must stay the logical (walker-issued) path:
		// integrity_issues rows, status updates, and CTI paths are keyed on
		// it, and on symlinked component layouts the two legitimately differ.
		$guard_path   = $file_path;
		$wp_root_real = Segurium_Fs::realpath( Segurium_Path_Helpers::wp_root() );
		if ( false !== $wp_root_real ) {
			$abs_norm  = wp_normalize_path( $abs_path );
			$root_norm = rtrim( wp_normalize_path( $wp_root_real ), '/' ) . '/';
			if ( 0 === strpos( $abs_norm, $root_norm ) ) {
				$guard_path = substr( $abs_norm, strlen( $root_norm ) );
			}
		}

		// Refuse one-click deletion of protected paths, checked
		// against both the logical and the canonical spelling. Also covers
		// integrity_issues rows written before the walker
		// exclusion and every verdict the UI maps to 'new'
		// (unknown, version_not_found). See docs/features/integrity-scan.md.
		if ( 'new' === $verdict
			&& ( Segurium_Integrity::is_excluded( $file_path ) || Segurium_Integrity::is_excluded( $guard_path ) )
		) {
			segurium_send_json_error(
				array(
					'message' => sprintf(
						/* translators: %s: file path relative to the WordPress root. */
						__( 'Deletion refused: "%s" is a protected file. The web server or another plugin may load it, and removing it can take the whole site down. Delete it manually if you are certain it is safe.', 'segurium' ),
						$file_path
					),
					'code'    => 'integrity_protected_file',
				),
				403
			);
		}

		// Strip the component prefix so CTI can build the correct SVN/Git URL.
		switch ( $comp_type ) {
			case 'plugin':
				$cti_path = ltrim( substr( $file_path, strlen( 'wp-content/plugins/' . $comp_slug ) ), '/' );
				break;
			case 'theme':
				$cti_path = ltrim( substr( $file_path, strlen( 'wp-content/themes/' . $comp_slug ) ), '/' );
				break;
			default: // Core.
				$cti_path = $file_path;
		}

		// Corrected axis: the cleanup quota is consumed when
		// remediation touches an *infected* file, not based on whether the
		// file is modified vs added. The authoritative classification lives
		// in integrity_issues.is_malicious — populated at scan time by
		// joining scan_findings on sha256 (Segurium_Integrity_Server_State::
		// lookup_is_malicious). The POST never carries it; trusting the
		// client would let attackers bypass the gate.
		$row          = Segurium_Storage::table_get_row(
			'integrity_issues',
			'SELECT sha256, is_malicious FROM {{table}} '
				. 'WHERE comp_type = %s AND comp_slug = %s AND file_path_hash = %s LIMIT 1',
			array( $comp_type, $comp_slug, hash( 'sha256', $file_path ) ),
			ARRAY_A
		);
		$row_sha256   = is_array( $row ) ? (string) ( $row['sha256'] ?? '' ) : '';
		$is_malicious = is_array( $row ) ? 1 === (int) ( $row['is_malicious'] ?? 0 ) : false;

		$bkp_id       = null;
		$sha256_after = '';

		if ( 'missing' === $verdict ) {
			// Restoring a manifest-known file that's absent from disk cannot
			// host malware — re-downloading the canonical content is always
			// free regardless of plan.
			$content = Segurium_Storage::cti_fetch_original_content_bytes( $comp_type, $cti_path, $comp_slug, $comp_version );
			if ( is_wp_error( $content ) ) {
				segurium_send_json_error( array( 'message' => $content->get_error_message() ) );
			}

			$dir = dirname( $abs_path );
			if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to create directory', 'segurium' ) ) );
			}
			if ( ! $this->write_in_place( $abs_path, $content ) ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to write file', 'segurium' ) ) );
			}

			$action       = 'replace';
			$status       = 'fixed';
			$sha256_after = hash( 'sha256', $content );

		} else {
			// 'modified' or 'new': there should be a file on disk to act on.
			if ( ! file_exists( $abs_path ) ) {
				segurium_send_json_error( array( 'message' => __( 'File not found', 'segurium' ) ) );
			}

			$current_sha256 = Segurium_Fs::hash_file( 'sha256', $abs_path );
			if ( false === $current_sha256 || '' === $current_sha256 ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to read file for backup', 'segurium' ) ) );
			}

			// Hash-drift refusal: integrity_issues.sha256 captures what the
			// scanner saw. If the on-disk content has changed since then, the
			// is_malicious annotation may be stale — bounce the user to a
			// rescan rather than letting them slip past the quota gate.
			if ( '' !== $row_sha256 && $current_sha256 !== $row_sha256 ) {
				segurium_send_json_error( array( 'message' => __( 'File has been modified since scan. Re-scan first.', 'segurium' ) ) );
			}

			if ( $is_malicious ) {
				// Any malicious integrity finding (modified
				// or new) is a real malware cleanup — route it through
				// the shared cleanup primitive so the slot is paid via
				// `/v1/cleanup` and the file is wiped (or cured)
				// according to CTI's verdict cache. We hand
				// VERDICT_MALICIOUS as a record-keeping value; CTI
				// decides cured-vs-empty server-side. For 'new'
				// findings (extraneous-but-malicious files) we also
				// unlink the now-empty shell so the integrity report
				// reflects the file as deleted rather than zero-byte.
				$cleanup = Segurium_Cleanup::cleanup_file(
					$abs_path,
					$file_path,
					(string) $current_sha256,
					Segurium_Cleanup::VERDICT_MALICIOUS,
					'',
					Segurium_Cleanup::ACTOR_MANUAL
				);
				if ( ! $cleanup['ok'] ) {
					if ( 'paywall_quota_exceeded' === (string) $cleanup['error_code'] ) {
						$envelope = is_array( $cleanup['paywall'] ) && isset( $cleanup['paywall']['quota'] )
							? (array) $cleanup['paywall']['quota']
							: array();
						Segurium_Paywall_Telemetry::stamp_wall( $envelope );
						segurium_send_json_error(
							array_merge(
								array(
									'message' => __( 'Cleanup quota reached. Upgrade to Pro for an unbounded cloud cleanup quota.', 'segurium' ),
								),
								Segurium_Quota::paywall_payload(
									$envelope,
									Segurium_Paywall_Telemetry::ACTION_MALWARE_FIX
								)
							),
							402
						);
					}
					segurium_send_json_error( array( 'message' => (string) $cleanup['error'] ) );
				}

				// Same rationale as ajax_cleanup_file —
				// prefer CTI's echoed post-charge envelope (authoritative
				// `next_slot_at`), falling back to the local bump for
				// older CTI builds that omit it.
				$ifix_quota_echo = ( isset( $cleanup['quota'] ) && is_array( $cleanup['quota'] ) ) ? $cleanup['quota'] : null;
				if ( null !== $ifix_quota_echo ) {
					Segurium_Quota::instance()->apply_cleanup_envelope( $ifix_quota_echo );
				} else {
					Segurium_Quota::instance()->record_consumed_slot();
				}

				$bkp_id = $cleanup['backup_id'];
				$status = 'fixed';

				if ( 'new' === $verdict ) {
					Segurium_Fs::delete( $abs_path );
					$action       = 'delete';
					$sha256_after = '';
				} else {
					$action       = 'replace';
					$sha256_after = (string) $cleanup['clean_hash'];
				}

				$this->update_integrity_issue_status( $comp_type, $comp_slug, $file_path, $status, $bkp_id );
				$acc = new Segurium_Integrity_Server_State( $this->get_data_dir() );
				$acc->load();
				$acc->update_file_state( $comp_slug, $comp_type, $file_path, $status, $bkp_id );
				$acc->save();

				Segurium_Storage::cti_log_integrity_action(
					array(
						'component_type' => $comp_type,
						'name'           => $comp_slug,
						'version'        => $comp_version,
						'file_path'      => $file_path,
						'action'         => $action,
						'sha256_before'  => $sha256,
						'sha256_after'   => $sha256_after,
						'backup_id'      => $bkp_id,
						'success'        => 1,
						'error'          => '',
					)
				);

				segurium_send_json_success(
					array(
						'message'      => __( 'File cleaned', 'segurium' ),
						'backup_id'    => $bkp_id,
						'sha256_after' => $sha256_after,
						'quota'        => Segurium_Quota::instance()->state(),
					)
				);
			}

			$file_content = Segurium_Fs::read( $abs_path );
			if ( false === $file_content ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to read file for backup', 'segurium' ) ) );
			}

			try {
				$bkp_id = Segurium_Storage::backup_store(
					'integrity',
					$file_path,
					$file_content,
					array(
						'sha256'   => $current_sha256,
						'action'   => 'modified' === $verdict ? 'integrity_fixed' : 'integrity_deleted',
						'abs_path' => $abs_path,
					)
				);
			} catch ( Segurium_Storage_Exception $e ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to create backup', 'segurium' ) ) );
			}

			if ( 'modified' === $verdict ) {
				// Signature- and hash-verified fetch. Refuses
				// to hand us content whose decoded SHA-256 does not match
				// the signed envelope's advertised hash, so we never write
				// a MITM-tampered body as a legitimate integrity fix.
				$content = Segurium_Storage::cti_fetch_original_content_bytes( $comp_type, $cti_path, $comp_slug, $comp_version );
				if ( is_wp_error( $content ) ) {
					segurium_send_json_error( array( 'message' => $content->get_error_message() ) );
				}

				if ( ! $this->write_in_place( $abs_path, $content ) ) {
					segurium_send_json_error( array( 'message' => __( 'Failed to write file', 'segurium' ) ) );
				}

				$action       = 'replace';
				$status       = 'fixed';
				$sha256_after = hash( 'sha256', $content );
			} else {
				// verdict === 'new': delete the extraneous file.
				if ( ! Segurium_Fs::delete( $abs_path ) ) {
					segurium_send_json_error( array( 'message' => __( 'Failed to delete file', 'segurium' ) ) );
				}

				$action       = 'delete';
				$status       = 'fixed';
				$sha256_after = '';
			}
		}

		$this->update_integrity_issue_status( $comp_type, $comp_slug, $file_path, $status, $bkp_id );

		// Also update accumulated state so the Integrity tab reflects the change.
		$acc = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$acc->load();
		$acc->update_file_state( $comp_slug, $comp_type, $file_path, $status, $bkp_id );
		$acc->save();

		Segurium_Storage::cti_log_integrity_action(
			array(
				'component_type' => $comp_type,
				'name'           => $comp_slug,
				'version'        => $comp_version,
				'file_path'      => $file_path,
				'action'         => $action,
				'sha256_before'  => $sha256,
				'sha256_after'   => $sha256_after,
				'backup_id'      => $bkp_id,
				'success'        => 1,
				'error'          => '',
			)
		);

		segurium_send_json_success(
			array(
				'backup_id' => $bkp_id,
				'status'    => $status,
			)
		);
	}

	/**
	 * AJAX handler for restoring an integrity file from backup.
	 *
	 * @return void
	 */
	public function ajax_integrity_restore_file() {
		check_ajax_referer( 'segurium_integrity', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$backup_id = isset( $_POST['backup_id'] ) ? sanitize_text_field( wp_unslash( $_POST['backup_id'] ) ) : '';
		$comp_type = isset( $_POST['comp_type'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_type'] ) ) : '';
		$comp_slug = isset( $_POST['comp_slug'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_slug'] ) ) : '';
		$file_path = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';

		if ( empty( $backup_id ) ) {
			segurium_send_missing_param( 'backup_id' );
		}
		if ( empty( $file_path ) ) {
			segurium_send_missing_param( 'file_path' );
		}

		// Surface the precise reason instead of the legacy
		// "Failed to restore file" so the operator can tell a rotation
		// eviction apart from corruption / permissions. The
		// load_files_for_component reconcile drops dangling backup_ids on
		// the next state read, so the Restore button disappears organically.
		$restore = Segurium_Storage::backup_restore_detailed( 'integrity', $backup_id );
		if ( null === $restore['content'] ) {
			segurium_send_json_error(
				array(
					'message' => $this->backup_restore_failure_message( $restore['reason'] ),
					'reason'  => $restore['reason'],
				)
			);
		}
		$restored_content = $restore['content'];

		$file_path = ltrim( $file_path, '/' );
		$abs_path  = $this->resolve_abs_within_wp_root( $file_path, 'write' );
		if ( null === $abs_path ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ), 403 );
		}
		$restore_dir = dirname( $abs_path );
		if ( ! is_dir( $restore_dir ) ) {
			wp_mkdir_p( $restore_dir );
		}
		if ( ! $this->write_in_place( $abs_path, $restored_content ) ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to write restored file', 'segurium' ) ) );
		}

		$this->update_integrity_issue_status( $comp_type, $comp_slug, $file_path, 'open', null );

		$acc = new Segurium_Integrity_Server_State( $this->get_data_dir() );
		$acc->load();
		$acc->update_file_state( $comp_slug, $comp_type, $file_path, 'open' );
		$acc->save();

		Segurium_Storage::cti_log_integrity_action(
			array(
				'component_type' => $comp_type,
				'name'           => $comp_slug,
				'version'        => '',
				'file_path'      => $file_path,
				'action'         => 'restore',
				'sha256_before'  => '',
				'sha256_after'   => '',
				'backup_id'      => $backup_id,
				'success'        => 1,
				'error'          => '',
			)
		);

		segurium_send_json_success( array( 'message' => __( 'File restored from backup', 'segurium' ) ) );
	}

	/**
	 * AJAX handler for getting the diff of an integrity file.
	 *
	 * @return void
	 */
	public function ajax_integrity_diff_file() {
		check_ajax_referer( 'segurium_integrity', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$comp_type    = isset( $_POST['comp_type'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_type'] ) ) : '';
		$comp_slug    = isset( $_POST['comp_slug'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_slug'] ) ) : '';
		$comp_version = isset( $_POST['comp_version'] ) ? sanitize_text_field( wp_unslash( $_POST['comp_version'] ) ) : '';
		$file_path    = isset( $_POST['file_path'] ) ? sanitize_text_field( wp_unslash( $_POST['file_path'] ) ) : '';

		if ( ! in_array( $comp_type, array( 'core', 'plugin', 'theme' ), true )
			|| empty( $file_path )
			|| false !== strpos( $comp_slug, '..' )
		) {
			segurium_send_json_error( array( 'message' => __( 'Invalid parameters', 'segurium' ) ) );
		}

		$file_path = ltrim( $file_path, '/' );

		$abs_path = $this->resolve_abs_within_wp_root( $file_path, 'read' );
		if ( null === $abs_path ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid path', 'segurium' ) ), 403 );
		}

		switch ( $comp_type ) {
			case 'plugin':
				$cti_path = ltrim( substr( $file_path, strlen( 'wp-content/plugins/' . $comp_slug ) ), '/' );
				break;
			case 'theme':
				$cti_path = ltrim( substr( $file_path, strlen( 'wp-content/themes/' . $comp_slug ) ), '/' );
				break;
			default: // Core.
				$cti_path = $file_path;
		}

		if ( ! is_file( $abs_path ) ) {
			segurium_send_json_error( array( 'message' => __( 'File not found', 'segurium' ) ) );
		}

		$current = Segurium_Fs::read( $abs_path );
		if ( false === $current ) {
			segurium_send_json_error( array( 'message' => __( 'Failed to read file', 'segurium' ) ) );
		}

		// Signature- and hash-verified fetch.
		$original = Segurium_Storage::cti_fetch_original_content_bytes( $comp_type, $cti_path, $comp_slug, $comp_version );
		if ( is_wp_error( $original ) ) {
			segurium_send_json_error( array( 'message' => $original->get_error_message() ) );
		}

		segurium_send_json_success(
			array(
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'current'  => base64_encode( $current ),
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'original' => base64_encode( $original ),
				'path'     => $file_path,
			)
		);
	}

	/**
	 * Map a {@see Segurium_Storage_Backup::restore_detailed()} reason tag
	 * to a localized, operator-facing message. Falls back to a generic
	 * "Failed to restore file" if the tag is absent or unrecognised so we
	 * never silently emit an empty error.
	 *
	 * @param string|null $reason Reason tag from `restore_detailed()`.
	 * @return string Localized message safe for a JSON `message` field.
	 */
	private function backup_restore_failure_message( $reason ) {
		switch ( (string) $reason ) {
			case 'envelope_missing':
				return __( 'Backup is no longer available — it was rotated out by newer backups.', 'segurium' );
			case 'meta_missing':
				return __( 'Backup metadata is missing or unreadable.', 'segurium' );
			case 'read_failed':
				return __( 'Backup file is unreadable. Check filesystem permissions on uploads/segurium-data.', 'segurium' );
			case 'decrypt_failed':
				return __( 'Backup file is corrupt — decryption failed.', 'segurium' );
			case 'gzdecode_failed':
				return __( 'Backup file is corrupt — decompression failed.', 'segurium' );
			case 'sha256_mismatch':
				return __( 'Backup integrity check failed — content hash does not match metadata.', 'segurium' );
			case 'invalid_args':
				return __( 'Invalid backup reference.', 'segurium' );
			default:
				return __( 'Failed to restore file', 'segurium' );
		}
	}

	/**
	 * Update the status of an integrity issue in stored results.
	 *
	 * @param string      $comp_type Component type (core, plugin, theme).
	 * @param string      $comp_slug Component slug.
	 * @param string      $file_path File path relative to ABSPATH.
	 * @param string      $status    New status.
	 * @param string|null $backup_id Backup ID or null.
	 * @return void
	 */
	private function update_integrity_issue_status( $comp_type, $comp_slug, $file_path, $status, $backup_id ) {
		$file_path = ltrim( $file_path, '/' );
		$data      = array(
			'status'   => $status,
			'fixed_at' => 'open' !== $status ? time() : null,
		);
		if ( null !== $backup_id ) {
			$data['backup_id'] = $backup_id;
		}
		Segurium_Storage::table_update(
			'integrity_issues',
			$data,
			array(
				'comp_type'      => $comp_type,
				'comp_slug'      => $comp_slug,
				'file_path_hash' => hash( 'sha256', $file_path ),
			)
		);
	}

	/**
	 * Sanitize a list of IP addresses and CIDR ranges.
	 *
	 * @param array $raw Raw IP list.
	 * @return array Sanitized IP list in CIDR notation.
	 */
	private function sanitize_ip_list( array $raw ) {
		$clean = array();
		foreach ( $raw as $entry ) {
			$entry = trim( sanitize_text_field( $entry ) );
			if ( '' === $entry ) {
				continue;
			}
			if ( false !== strpos( $entry, '/' ) ) {
				$parts = explode( '/', $entry, 2 );
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( false !== @inet_pton( $parts[0] ) && ctype_digit( $parts[1] ) ) {
					$clean[] = $entry;
				}
				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			} elseif ( false !== @inet_pton( $entry ) ) {
				$clean[] = $entry . ( strpos( $entry, ':' ) !== false ? '/128' : '/32' );
			}
		}
		return $clean;
	}

	/**
	 * AJAX handler for getting brute-force settings.
	 *
	 * @return void
	 */
	public function ajax_get_bf_settings() {
		check_ajax_referer( Segurium_Brute_Force::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$settings = Segurium_Brute_Force::get_instance()->get_settings();
		// Never ship the hCaptcha secret back to the browser. Replace with a marker so
		// the JS knows the secret is set without giving DOM/JS access to the plaintext value.
		$settings['hcaptcha_secret_key'] = ! empty( $settings['hcaptcha_secret_key'] ) ? '__set__' : '';
		segurium_send_json_success(
			array(
				'settings' => $settings,
				'defaults' => Segurium_Brute_Force::default_settings(),
			)
		);
	}

	/**
	 * AJAX handler for saving brute-force settings.
	 *
	 * @return void
	 */
	public function ajax_save_bf_settings() {
		check_ajax_referer( Segurium_Brute_Force::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$raw   = self::request_array( INPUT_POST, 'settings' );
		$saved = Segurium_Brute_Force::get_instance()->save_settings( $raw );
		segurium_send_json_success( array( 'settings' => $saved ) );
	}

	/**
	 * AJAX handler for getting security headers settings.
	 *
	 * @return void
	 */
	public function ajax_get_sh_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$sh = Segurium_Security_Headers::get_instance();
		segurium_send_json_success(
			array(
				'settings'     => $sh->get_settings(),
				'defaults'     => Segurium_Security_Headers::default_settings(),
				'is_subdomain' => $sh->is_subdomain(),
				'is_ssl'       => is_ssl(),
			)
		);
	}

	/**
	 * AJAX handler for saving security headers settings.
	 *
	 * @return void
	 */
	public function ajax_save_sh_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$raw   = self::request_array( INPUT_POST, 'settings' );
		$saved = Segurium_Security_Headers::get_instance()->save_settings( $raw );
		segurium_send_json_success( array( 'settings' => $saved ) );
	}

	/**
	 * AJAX handler for getting Information Shield settings.
	 *
	 * @return void
	 */
	public function ajax_get_info_shield_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$shield = Segurium_Info_Shield::get_instance();
		segurium_send_json_success(
			array(
				'settings'    => $shield->get_settings(),
				'defaults'    => Segurium_Info_Shield::default_settings(),
				'environment' => Segurium_Info_Shield::detect_server_environment(),
				'conflicts'   => Segurium_Info_Shield::detect_conflicts(),
			)
		);
	}

	/**
	 * AJAX handler for saving Information Shield settings.
	 *
	 * @return void
	 */
	public function ajax_save_info_shield_settings() {
		check_ajax_referer( 'segurium_settings', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$raw   = self::request_array( INPUT_POST, 'settings' );
		$saved = Segurium_Info_Shield::get_instance()->save_settings( $raw );
		segurium_send_json_success( array( 'settings' => $saved ) );
	}

	/**
	 * AJAX handler for running the security Self-Check. The scan is cached
	 * for 1 hour; the `force` POST field bypasses the cache.
	 *
	 * @return void
	 */
	public function ajax_run_self_check() {
		check_ajax_referer( Segurium_Self_Check::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$force  = self::request_bool( INPUT_POST, 'force' );
		$result = Segurium_Self_Check::get_instance()->run_checks( $force );
		segurium_send_json_success( $result );
	}

	/**
	 * AJAX handler for getting brute-force lockout list.
	 *
	 * @return void
	 */
	public function ajax_get_bf_lockouts() {
		check_ajax_referer( Segurium_Brute_Force::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$page     = max( 1, self::request_int( INPUT_POST, 'page', 1 ) );
		$per_page = self::request_int( INPUT_POST, 'per_page', 20 );
		segurium_send_json_success( Segurium_Brute_Force::get_instance()->get_active_lockouts( $page, $per_page ) );
	}

	/**
	 * AJAX handler for unlocking a brute-force locked IP.
	 *
	 * @return void
	 */
	public function ajax_unlock_bf_ip() {
		check_ajax_referer( Segurium_Brute_Force::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid IP address.', 'segurium' ) ) );
		}
		$ok = Segurium_Brute_Force::get_instance()->unlock_ip( $ip );
		segurium_send_json_success( array( 'unlocked' => (bool) $ok ) );
	}

	/**
	 * AJAX handler for getting brute-force statistics.
	 *
	 * @return void
	 */
	public function ajax_get_bf_stats() {
		check_ajax_referer( Segurium_Brute_Force::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		segurium_send_json_success( Segurium_Brute_Force::get_instance()->get_stats() );
	}

	/**
	 * AJAX handler for getting brute-force event log.
	 *
	 * @return void
	 */
	public function ajax_get_bf_log() {
		check_ajax_referer( Segurium_Brute_Force::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$args = array(
			'page'     => max( 1, self::request_int( INPUT_POST, 'page', 1 ) ),
			'per_page' => self::request_int( INPUT_POST, 'per_page', 25 ),
			'event'    => isset( $_POST['event'] ) ? sanitize_text_field( wp_unslash( $_POST['event'] ) ) : '',
			'ip'       => isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '',
		);
		segurium_send_json_success( Segurium_Brute_Force::get_instance()->get_log( $args ) );
	}

	/**
	 * AJAX handler for detecting available migrations.
	 *
	 * @return void
	 */
	public function ajax_migration_detect() {
		check_ajax_referer( 'segurium_migration', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		segurium_send_json_success( Segurium_Migration::get_available() );
	}

	/**
	 * AJAX handler for previewing a migration.
	 *
	 * @return void
	 */
	public function ajax_migration_preview() {
		check_ajax_referer( 'segurium_migration', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$slug    = isset( $_POST['slug'] ) ? sanitize_key( wp_unslash( $_POST['slug'] ) ) : '';
		$adapter = Segurium_Migration::get_adapter( $slug );
		if ( ! $adapter ) {
			segurium_send_json_error( array( 'message' => __( 'Plugin not found or no data to migrate.', 'segurium' ) ) );
		}
		segurium_send_json_success(
			array(
				'slug'  => $slug,
				'name'  => $adapter::get_plugin_name(),
				'items' => $adapter->preview(),
			)
		);
	}

	/**
	 * AJAX handler for applying a migration.
	 *
	 * @return void
	 */
	public function ajax_migration_apply() {
		check_ajax_referer( 'segurium_migration', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$slug    = isset( $_POST['slug'] ) ? sanitize_key( wp_unslash( $_POST['slug'] ) ) : '';
		$adapter = Segurium_Migration::get_adapter( $slug );
		if ( ! $adapter ) {
			segurium_send_json_error( array( 'message' => __( 'Plugin not found or no data to migrate.', 'segurium' ) ) );
		}
		segurium_send_json_success( $adapter->apply() );
	}

	/**
	 * Get the current support ticket rate limit data.
	 *
	 * @return array Rate limit data with count and reset_at.
	 */
	private function get_support_rate() {
		$data = Segurium_Storage::setting_get_array(
			'segurium_support_rate',
			array(
				'count'    => 0,
				'reset_at' => 0,
			)
		);
		if ( empty( $data['reset_at'] ) ) {
			return array(
				'count'    => 0,
				'reset_at' => 0,
			);
		}
		if ( $data['reset_at'] < time() ) {
			return array(
				'count'    => 0,
				'reset_at' => 0,
			);
		}
		return $data;
	}

	/**
	 * Increment the support ticket rate counter.
	 *
	 * @return void
	 */
	private function increment_support_rate() {
		$data = $this->get_support_rate();
		$now  = time();
		if ( $data['reset_at'] < $now ) {
			$data = array(
				'count'    => 1,
				'reset_at' => $now + DAY_IN_SECONDS,
			);
		} else {
			++$data['count'];
		}
		Segurium_Storage::setting_set( 'segurium_support_rate', $data );
	}

	/**
	 * Default reply-to email for the support form: current user's email
	 * if it validates, otherwise the site's admin_email. Empty string if
	 * neither is a valid address.
	 *
	 * @return string
	 */
	public function get_support_default_email() {
		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		if ( $user && ! empty( $user->user_email ) && is_email( $user->user_email ) ) {
			return (string) $user->user_email;
		}
		$admin = (string) Segurium_Storage::setting_get( 'admin_email', '' );
		if ( '' !== $admin && is_email( $admin ) ) {
			return $admin;
		}
		return '';
	}

	/**
	 * Default human name for the support form: display_name, falling
	 * back to user_login, then to the site name. Empty string if none.
	 *
	 * @return string
	 */
	public function get_support_default_name() {
		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		if ( $user ) {
			$candidates = array( (string) $user->display_name, (string) $user->user_login );
			foreach ( $candidates as $cand ) {
				$cand = trim( $cand );
				if ( '' !== $cand ) {
					return $cand;
				}
			}
		}
		$site = $this->get_support_site_name();
		return '' !== $site ? $site : '';
	}

	/**
	 * The site name shown in the support form and included in the
	 * outbound ticket so support staff can identify the site. Server-
	 * derived — the form surfaces it read-only.
	 *
	 * @return string
	 */
	public function get_support_site_name() {
		$name = trim( (string) get_bloginfo( 'name' ) );
		if ( '' !== $name ) {
			return $name;
		}
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return is_string( $host ) ? $host : '';
	}

	/**
	 * Human subject line derived from the ticket type. The old form
	 * had a free-text subject; with that gone, the type is the subject.
	 *
	 * @param string $type Sanitized type key.
	 * @return string
	 */
	private function support_subject_for_type( $type ) {
		switch ( $type ) {
			case 'bug':
				return __( 'Bug report', 'segurium' );
			case 'feature':
				return __( 'Feature request', 'segurium' );
			case 'question':
				return __( 'General question', 'segurium' );
			case 'fn_report':
				return __( 'Missed malware report', 'segurium' );
			default:
				return __( 'Other request', 'segurium' );
		}
	}

	/**
	 * Get diagnostic data for support tickets.
	 *
	 * @return array Diagnostic data.
	 */
	private function get_support_diagnostics() {
		return array(
			'wp_version'     => get_bloginfo( 'version' ),
			'php_version'    => PHP_VERSION,
			'plugin_version' => SEGURIUM_VERSION,
			// active_plugins is a WordPress core key, read through the settings facade.
			'active_plugins' => Segurium_Storage::setting_get( 'active_plugins', array() ),
			'last_scan'      => Segurium_Storage::setting_get_int( 'segurium_last_scan_time' ) > 0 ? Segurium_Storage::setting_get_int( 'segurium_last_scan_time' ) : null,
			'site_url'       => home_url(),
		);
	}

	/**
	 * AJAX handler for submitting a support ticket.
	 *
	 * @return void
	 */
	public function ajax_submit_support_ticket() {
		check_ajax_referer( 'segurium_support', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Permission denied.', 'segurium' ) ), 403 );
		}

		$type         = sanitize_key( wp_unslash( isset( $_POST['type'] ) ? $_POST['type'] : '' ) );
		$message      = sanitize_textarea_field( wp_unslash( isset( $_POST['message'] ) ? $_POST['message'] : '' ) );
		$email_raw    = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
		$name_raw     = sanitize_text_field( wp_unslash( isset( $_POST['name'] ) ? $_POST['name'] : '' ) );
		$include_diag = self::request_bool( INPUT_POST, 'include_diag' );

		if ( empty( $message ) ) {
			segurium_send_json_error( array( 'message' => __( 'Message is required.', 'segurium' ) ) );
		}

		if ( '' === $email_raw || ! is_email( $email_raw ) ) {
			$email_raw = $this->get_support_default_email();
		}
		if ( '' === $email_raw || ! is_email( $email_raw ) ) {
			segurium_send_json_error( array( 'message' => __( 'A valid reply-to email is required.', 'segurium' ) ) );
		}

		if ( '' === $name_raw ) {
			$name_raw = $this->get_support_default_name();
		}
		$name_raw = trim( $name_raw );
		if ( strlen( $name_raw ) > 100 ) {
			$name_raw = substr( $name_raw, 0, 100 );
		}

		$allowed_types = array( 'bug', 'feature', 'question', 'fn_report', 'other' );
		if ( ! in_array( $type, $allowed_types, true ) ) {
			$type = 'other';
		}

		$rate = $this->get_support_rate();
		if ( $rate['count'] >= 5 ) {
			segurium_send_json_error( array( 'message' => __( 'You have submitted too many tickets today. Please try again tomorrow.', 'segurium' ) ) );
		}

		$attachments = array();
		if ( 'fn_report' === $type && isset( $_FILES['attachment']['error'], $_FILES['attachment']['tmp_name'] ) ) {
			if ( UPLOAD_ERR_OK !== (int) $_FILES['attachment']['error'] ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to upload the file. Try again.', 'segurium' ) ) );
			}
			$file_size = isset( $_FILES['attachment']['size'] ) ? (int) $_FILES['attachment']['size'] : 0;
			if ( $file_size <= 0 || $file_size > Segurium_Scanner::MAX_FILE_SIZE ) {
				segurium_send_json_error( array( 'message' => __( 'File is empty or too large (max 100 MB).', 'segurium' ) ) );
			}
			$tmp_name = sanitize_text_field( wp_unslash( $_FILES['attachment']['tmp_name'] ) );
			if ( '' === $tmp_name || ! is_uploaded_file( $tmp_name ) ) {
				segurium_send_json_error( array( 'message' => __( 'Invalid upload.', 'segurium' ) ) );
			}
			$body = Segurium_Fs::read( $tmp_name );
			if ( false === $body ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to read uploaded file.', 'segurium' ) ) );
			}
			$gz = gzencode( $body, 6 );
			if ( false === $gz ) {
				segurium_send_json_error( array( 'message' => __( 'Failed to compress file.', 'segurium' ) ) );
			}
			$orig_name     = isset( $_FILES['attachment']['name'] ) ? sanitize_file_name( wp_unslash( $_FILES['attachment']['name'] ) ) : 'sample.bin';
			$attachments[] = array(
				'filename' => $orig_name . '.gz',
				'data'     => $gz,
			);
		}

		$site_name   = $this->get_support_site_name();
		$ticket_data = array(
			'subject'   => $this->support_subject_for_type( $type ),
			'type'      => $type,
			'message'   => $message,
			'name'      => '' !== $name_raw ? $name_raw : ( '' !== $site_name ? $site_name : 'Site admin' ),
			'email'     => $email_raw,
			'site_name' => $site_name,
		);

		if ( $include_diag ) {
			$ticket_data['diagnostics'] = $this->get_support_diagnostics();
		}

		$result = Segurium_Storage::cti_submit_support_ticket( $ticket_data, $attachments );

		if ( is_wp_error( $result ) ) {
			segurium_send_json_error( array( 'message' => $result->get_error_message() ) );
		}

		$this->increment_support_rate();

		segurium_send_json_success(
			array(
				'ticket_id' => isset( $result['ticket_id'] ) ? $result['ticket_id'] : '',
			)
		);
	}

	/*
	─────────────────────────────────────────────────────────────────────
	 * 2FA admin AJAX handlers.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * AJAX: Get 2FA settings.
	 *
	 * @return void
	 */
	public function ajax_get_2fa_settings() {
		check_ajax_referer( Segurium_2FA::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		segurium_send_json_success(
			array(
				'settings' => Segurium_2FA::get_instance()->get_settings(),
				'defaults' => Segurium_2FA::default_settings(),
				'roles'    => wp_roles()->get_names(),
			)
		);
	}

	/**
	 * AJAX: Save 2FA settings.
	 *
	 * @return void
	 */
	public function ajax_save_2fa_settings() {
		check_ajax_referer( Segurium_2FA::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}
		$raw   = self::request_array( INPUT_POST, 'settings' );
		$saved = Segurium_2FA::get_instance()->save_settings( $raw );
		segurium_send_json_success( array( 'settings' => $saved ) );
	}

	/**
	 * AJAX: Get user 2FA statistics.
	 *
	 * @return void
	 */
	public function ajax_get_2fa_user_stats() {
		check_ajax_referer( Segurium_2FA::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$stats = array(
			'totp'  => 0,
			'email' => 0,
		);

		$users = get_users(
			array(
				'meta_key'     => Segurium_2FA::USER_META_METHOD, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_compare' => 'EXISTS',
				'fields'       => 'ids',
			)
		);

		foreach ( $users as $uid ) {
			$method = get_user_meta( $uid, Segurium_2FA::USER_META_METHOD, true );
			if ( isset( $stats[ $method ] ) ) {
				++$stats[ $method ];
			}
		}

		segurium_send_json_success( array( 'stats' => $stats ) );
	}

	/**
	 * AJAX: Reset a user's 2FA configuration.
	 *
	 * @return void
	 */
	public function ajax_admin_reset_user_2fa() {
		check_ajax_referer( Segurium_2FA::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized.', 'segurium' ) ), 403 );
		}

		$input = isset( $_POST['user'] ) ? sanitize_text_field( wp_unslash( $_POST['user'] ) ) : '';
		if ( '' === $input ) {
			segurium_send_json_error( array( 'message' => __( 'Please enter a username or user ID.', 'segurium' ) ) );
		}

		$user = is_numeric( $input ) ? get_user_by( 'id', (int) $input ) : get_user_by( 'login', $input );
		if ( ! $user ) {
			segurium_send_json_error( array( 'message' => __( 'User not found.', 'segurium' ) ) );
		}

		Segurium_2FA::get_instance()->reset_user_2fa( $user->ID );

		segurium_send_json_success(
			array(
				/* translators: %s: username */
				'message' => sprintf( __( '2FA reset for user %s.', 'segurium' ), $user->user_login ),
			)
		);
	}
}

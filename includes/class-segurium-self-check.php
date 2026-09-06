<?php
/**
 * Self-Check — computes a security posture score from HTTP response
 * headers, HTML body disclosure checks, WordPress-specific hardening
 * state, and cookie flag verification.
 *
 * Read-only by design — never mutates settings. Does not ship results
 * to the CTI.
 *
 * The self-ping observes the cached production homepage (no
 * cache-buster) so that internal scoring matches the external scan
 * exposed at segurium.com/scan/. Both code paths apply identical
 * methodology to the same surface.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Singleton that runs the 24-check security self-check.
 */
class Segurium_Self_Check {

	const NONCE_ACTION = 'segurium_self_check';
	const CACHE_KEY    = 'segurium_self_check_result';
	const CACHE_TTL    = 0; // No expiry — results persist until next run.
	// OPTION_HISTORY was retired in Stage 5; history now lives in the
	// self_check_history custom table.
	const HISTORY_MAX     = 10;
	const SCAN_FRESH_DAYS = 7;

	/**
	 * WP-Cron hook for the daily auto-run. Fired once per day
	 * irrespective of whether anyone visits the admin tab — keeps the CTI
	 * inventory fresh for the Site Profile + System Health dashboards.
	 */
	const CRON_HOOK = 'segurium_daily_self_check';

	/**
	 * CTI message_type. Server-side allow-list lives in
	 * segurium-cti's handler.rs::VALID_MESSAGE_TYPES. The materialised view
	 * `segurium.self_check_mv` filters on this exact value.
	 */
	const CTI_MESSAGE_TYPE = 'self_check';

	/**
	 * Per-category maximum point totals. Must sum to 100.
	 */
	const PTS_HEADERS    = 8;
	const PTS_DISCLOSURE = 24;
	const PTS_HARDENING  = 40;
	const PTS_COOKIES    = 8;
	const PTS_MALWARE    = 20;

	/**
	 * 24-hour freshness window for the malware-protection scan checks.
	 */
	const SCAN_24H_FRESH_SECS = DAY_IN_SECONDS;

	/**
	 * Category identifiers.
	 */
	const CAT_HEADERS    = 'headers';
	const CAT_DISCLOSURE = 'disclosure';
	const CAT_HARDENING  = 'hardening';
	const CAT_COOKIES    = 'cookies';
	const CAT_MALWARE    = 'malware';

	/**
	 * Per-check status identifiers.
	 */
	const STATUS_PASS    = 'pass';
	const STATUS_PARTIAL = 'partial';
	const STATUS_WARN    = 'warn';
	const STATUS_FAIL    = 'fail';

	/**
	 * Admin tab slugs used for Fix-button deep links. Must match the
	 * `data-feature=` values declared in `render_main_page()`.
	 */
	const TAB_HEADERS     = 'headers';
	const TAB_INFO_SHIELD = 'info-shield';
	const TAB_BRUTEFORCE  = 'bruteforce';
	const TAB_TWOFACTOR   = 'twofactor';
	const TAB_SCANNER     = 'scanner';
	const TAB_INTEGRITY   = 'integrity-scanner';
	const TAB_FIREWALL    = 'firewall';
	const TAB_SETTINGS    = 'settings';
	const TAB_NONE        = '';

	/**
	 * Features a failing row can switch on without leaving this tab.
	 */
	const FIX_INFO_SHIELD     = 'info_shield';
	const FIX_HEADERS         = 'security_headers';
	const FIX_BRUTE_FORCE     = 'brute_force';
	const FIX_AUTO_CLEANUP    = 'auto_cleanup';
	const FIX_SCHEDULED_SCANS = 'scheduled_scans';

	/**
	 * Check ids whose failure is one settings write away, mapped to the
	 * feature that owns the write.
	 *
	 * Membership is deliberately narrow. A row belongs here only when the
	 * write is reversible from the feature's own tab, cannot take the site
	 * offline, and carries no consequence the user would want to hear
	 * about first. That rules out 2FA enforcement (every administrator
	 * must then enrol), XML-RPC (Jetpack, the mobile app and several
	 * backup plugins stop working), the firewall (staged behind a
	 * confirm-or-auto-revert of its own), HSTS (a browser pins it for a
	 * year), CSP (enforcing it breaks third-party assets on most sites)
	 * and on-premise mode (switching it off sends file contents to the
	 * cloud, which is the administrator's call). Those keep the
	 * tab-switch button.
	 *
	 * This map is also the renderer's source of truth — `make_check()`
	 * projects it onto every row as `fix_action`, so the JS never carries
	 * a second copy of the list.
	 */
	const FIXABLE = array(
		'x_powered_by'       => self::FIX_INFO_SHIELD,
		'wp_generator'       => self::FIX_INFO_SHIELD,
		'version_query'      => self::FIX_INFO_SHIELD,
		'rest_api_link'      => self::FIX_INFO_SHIELD,
		'xcto'               => self::FIX_HEADERS,
		'xfo'                => self::FIX_HEADERS,
		'xss_protection'     => self::FIX_HEADERS,
		'referrer_policy'    => self::FIX_HEADERS,
		'permissions_policy' => self::FIX_HEADERS,
		'bruteforce'         => self::FIX_BRUTE_FORCE,
		'auto_cleanup'       => self::FIX_AUTO_CLEANUP,
		'scheduled_scans'    => self::FIX_SCHEDULED_SCANS,
	);

	/**
	 * Header modes that do not emit every value the five auto-fixable
	 * header rows test, so switching the feature on is not enough.
	 */
	const HEADER_MODES_TO_UPGRADE = array( 'off', 'basic' );

	/**
	 * Info Shield removal key each disclosure row is scored from.
	 *
	 * Switching the feature on is not enough: a user who once saved the
	 * Info Shield form with one of these unchecked would press Fix, see
	 * nothing move, and be told the page cache was to blame. The write
	 * forces the one key the clicked row needs and leaves the rest of
	 * their form alone.
	 */
	const FIX_SHIELD_KEYS = array(
		'x_powered_by'  => 'remove_x_powered_by',
		'wp_generator'  => 'remove_wp_generator',
		'version_query' => 'remove_version_query',
		'rest_api_link' => 'remove_rest_api_link',
	);

	/**
	 * Singleton instance.
	 *
	 * @var Segurium_Self_Check|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return Segurium_Self_Check
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Reset the singleton — used in tests.
	 */
	public static function reset_instance() {
		self::$instance = null;
	}

	/**
	 * Private constructor (singleton).
	 */
	private function __construct() {}

	/**
	 * Run the full check battery and return a structured result array.
	 *
	 * @param bool $force          When true, bypass the 1-hour transient.
	 * @param bool $record_history When false, skip the history row. Used by
	 *                             `apply_fix()`, whose rescores would
	 *                             otherwise push every real run out of the
	 *                             ten-entry trend within a minute.
	 * @return array { score, grade, categories, checks, scanned_at, self_ping_error }
	 */
	public function run_checks( $force = false, $record_history = true ) {
		if ( ! $force ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( is_array( $cached ) ) {
				return $cached;
			}
		}

		$ping = $this->self_ping();

		$checks = array();
		$checks = array_merge( $checks, $this->check_security_headers( $ping['headers'] ) );
		$checks = array_merge( $checks, $this->check_info_disclosure( $ping['headers'], $ping['body'] ) );
		$checks = array_merge( $checks, $this->check_wp_hardening() );
		$checks = array_merge( $checks, $this->check_cookie_security( $ping['headers'] ) );
		$checks = array_merge( $checks, $this->check_malware_protection() );

		$result                    = $this->calculate_score( $checks );
		$result['self_ping_error'] = $ping['error'];

		set_transient( self::CACHE_KEY, $result, self::CACHE_TTL );
		if ( $record_history ) {
			$this->save_to_history( $result );
		}
		$this->send_to_cti( $result );
		return $result;
	}

	/**
	 * Register the daily-cron hook handler. Scheduling itself
	 * is driven by activation (see `schedule()`), mirroring
	 * `Segurium_Platform_Snapshot`.
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( self::CRON_HOOK, array( __CLASS__, 'run_cron' ) );
	}

	/**
	 * Schedule the daily self-check event. Idempotent — safe on every
	 * activation / auto-update bootstrap. Same `time() + HOUR_IN_SECONDS`
	 * convention as the other plugin daily crons so install-time spreads
	 * the load across the day.
	 *
	 * @return void
	 */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Clear the daily event. Called on plugin deactivation.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/**
	 * Cron handler — force a fresh run so the CTI report always carries
	 * today's posture (the no-expiry cache transient would otherwise let
	 * us re-send a week-old grade). `run_checks(true)` writes the result
	 * to history + transient and triggers `send_to_cti()` itself.
	 *
	 * @return void
	 */
	public static function run_cron(): void {
		try {
			self::get_instance()->run_checks( true );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-self-check] daily cron failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Build the compact CTI payload. Shape stays small on purpose: the
	 * plugin already keeps full check details locally; CTI only needs the
	 * grade, score, per-category roll-up, ordered list of failed check
	 * IDs, and the per-check status map for fleet-wide drill-down.
	 *
	 * Mirrors the schema declared by `segurium.self_check_mv` (see
	 * `infra/clickhouse/migrations/2026-05-09-self-check.sql` in
	 * segurium-cti).
	 *
	 * @param array $result Result returned by `run_checks()` /
	 *                      `calculate_score()`.
	 * @return array
	 */
	private function build_cti_payload( array $result ): array {
		$statuses         = array();
		$failed_check_ids = array();
		if ( isset( $result['checks'] ) && is_array( $result['checks'] ) ) {
			foreach ( $result['checks'] as $check ) {
				$id     = isset( $check['id'] ) ? (string) $check['id'] : '';
				$status = isset( $check['status'] ) ? (string) $check['status'] : '';
				if ( '' === $id ) {
					continue;
				}
				$statuses[ $id ] = $status;
				if ( self::STATUS_FAIL === $status ) {
					$failed_check_ids[] = $id;
				}
			}
		}

		return array(
			'score'            => isset( $result['score'] ) ? (int) $result['score'] : 0,
			'grade'            => isset( $result['grade'] ) ? (string) $result['grade'] : '',
			'categories'       => isset( $result['categories'] ) && is_array( $result['categories'] ) ? $result['categories'] : array(),
			'failed_check_ids' => $failed_check_ids,
			'statuses'         => (object) $statuses,
		);
	}

	/**
	 * Send the latest result to CTI as a `self_check` message. Best-effort
	 * fire-and-forget: `Segurium_CTI_Client::send_message` is non-blocking
	 * and already gates on consent + IID inside the client. We additionally
	 * skip when the consent setting is off so this method short-circuits
	 * without instantiating the client (saves the autoloader cost on
	 * pre-consent admin loads).
	 *
	 * @param array $result Result returned by `run_checks()`.
	 * @return bool Whether the dispatch attempt succeeded.
	 */
	private function send_to_cti( array $result ): bool {
		if ( ! class_exists( 'Segurium_Storage' ) || ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return false;
		}
		if ( ! class_exists( 'Segurium_CTI_Client' ) ) {
			return false;
		}

		$payload = wp_json_encode( $this->build_cti_payload( $result ) );
		if ( ! is_string( $payload ) ) {
			return false;
		}

		$client = new Segurium_CTI_Client();
		return (bool) $client->send_message( self::CTI_MESSAGE_TYPE, $payload );
	}

	/**
	 * Return the last cached result without running a new check.
	 *
	 * @return array|null
	 */
	public function get_last_result() {
		$cached = get_transient( self::CACHE_KEY );
		return is_array( $cached ) ? $cached : null;
	}

	/**
	 * Return the stored score history (up to HISTORY_MAX entries).
	 *
	 * @return array
	 */
	public function get_history() {
		$rows    = Segurium_Storage::table_get_results(
			'self_check_history',
			'SELECT result_json FROM {{table}} WHERE check_type = %s ORDER BY id ASC LIMIT %d',
			array( 'self_check', self::HISTORY_MAX ),
			ARRAY_A
		);
		$history = array();
		foreach ( $rows as $row ) {
			$decoded = isset( $row['result_json'] ) ? json_decode( (string) $row['result_json'], true ) : null;
			if ( is_array( $decoded ) ) {
				$history[] = $decoded;
			}
		}
		return $history;
	}

	/**
	 * Self-ping the cached production homepage to capture response
	 * headers and body. No cache-buster: scoring must reflect the
	 * surface real visitors see, which is what the external scan at
	 * segurium.com/scan/ also observes.
	 *
	 * Returns a normalized lowercase-key header array regardless of
	 * whether the WP HTTP layer handed us a dictionary or a plain array.
	 *
	 * @return array { headers: array, body: string, error: string }
	 */
	private function self_ping() {
		$url = home_url( '/' );

		$args = array(
			'timeout'     => 10,
			'redirection' => 0,
			// We're calling ourselves; internal TLS (self-signed, or terminated upstream) must not fail the check.
			'sslverify'   => false,
			'user-agent'  => 'Segurium-SelfCheck/' . ( defined( 'SEGURIUM_VERSION' ) ? SEGURIUM_VERSION : '1.0' ),
		);

		// Self-ping to home_url(): wp_safe_remote_get() rejects loopback / RFC1918 hosts, so the unsafe variant is required here.
		$response = wp_remote_get( $url, $args );
		if ( is_wp_error( $response ) ) {
			return array(
				'headers' => array(),
				'body'    => '',
				'error'   => $response->get_error_message(),
			);
		}

		$raw = wp_remote_retrieve_headers( $response );
		if ( is_object( $raw ) && method_exists( $raw, 'getAll' ) ) {
			$headers = $raw->getAll();
		} elseif ( is_array( $raw ) ) {
			$headers = $raw;
		} else {
			$headers = array();
		}
		$headers = array_change_key_case( $headers, CASE_LOWER );

		return array(
			'headers' => $headers,
			'body'    => (string) wp_remote_retrieve_body( $response ),
			'error'   => '',
		);
	}

	/**
	 * Build a single check row from an associative payload. Unknown
	 * keys are ignored; missing keys fall back to safe defaults.
	 *
	 * `help_html` carries per-check guidance for failures that cannot be
	 * fixed from a plugin tab (e.g. server-level configuration). It is
	 * only emitted on failing/warning checks by the helpers that build
	 * them — absent otherwise.
	 *
	 * @param array $spec Row fields — `id`, `category`, `label`, `status`, `detail`, `fix_tab`, `help_html`, `points`.
	 * @return array
	 */
	private function make_check( array $spec ) {
		$id = (string) ( $spec['id'] ?? '' );

		return array(
			'id'         => $id,
			'category'   => (string) ( $spec['category'] ?? '' ),
			'label'      => (string) ( $spec['label'] ?? '' ),
			'status'     => (string) ( $spec['status'] ?? self::STATUS_FAIL ),
			'detail'     => (string) ( $spec['detail'] ?? '' ),
			'fix_tab'    => (string) ( $spec['fix_tab'] ?? self::TAB_NONE ),
			'fix_action' => self::is_fixable( $id ) && self::server_supports_fix( $id ),
			'help_html'  => (string) ( $spec['help_html'] ?? '' ),
			'points'     => (float) ( $spec['points'] ?? 0 ),
		);
	}

	/**
	 * Whether a check id can be resolved by a settings write from the
	 * Self-Check tab itself.
	 *
	 * @param string $check_id Check identifier as emitted by `make_check()`.
	 * @return bool
	 */
	public static function is_fixable( $check_id ) {
		return is_string( $check_id ) && '' !== $check_id && isset( self::FIXABLE[ $check_id ] );
	}

	/**
	 * Whether this server can actually deliver the fix.
	 *
	 * `X-Powered-By` is the one row where the write can land and the
	 * header still come back: under FastCGI the web server re-adds it
	 * after PHP has run. Offering an in-place button there would leave
	 * the row failing forever while the tab blamed a page cache, and
	 * would hide the Info Shield tab link that carries the real
	 * server-level guidance.
	 *
	 * @param string $check_id Check identifier.
	 * @return bool
	 */
	public static function server_supports_fix( $check_id ) {
		if ( 'x_powered_by' !== $check_id ) {
			return true;
		}
		if ( ! class_exists( 'Segurium_Info_Shield' ) ) {
			return false;
		}
		$env = Segurium_Info_Shield::detect_server_environment();
		return ! empty( $env['can_remove_x_powered'] );
	}

	/**
	 * Switch on the feature that resolves one failing row, then rescore.
	 *
	 * The rescore is forced so the caller always gets the posture the
	 * write produced rather than the transient it replaced. It reads the
	 * homepage the same way every other run does, so a check derived from
	 * the response (the header rows, and the two disclosure rows read out
	 * of the HTML) can still report `fail` when a page cache is serving
	 * the pre-fix response. That is what `flipped` is for: the setting
	 * landed, the observation has not caught up, and the caller has to say
	 * so rather than leave the user staring at an unchanged row.
	 *
	 * @param string $check_id Check identifier from the FIXABLE map.
	 * @return array|WP_Error { check_id, feature, flipped, score_before, result }
	 */
	public function apply_fix( $check_id ) {
		if ( ! self::is_fixable( $check_id ) ) {
			return new WP_Error(
				'segurium_self_check_unknown_fix',
				'',
				array( 'status' => 400 )
			);
		}

		if ( ! self::server_supports_fix( $check_id ) ) {
			return new WP_Error(
				'segurium_self_check_fix_blocked_by_server',
				__( 'This server re-adds the header after the plugin removes it. Open the feature tab for the server-level fix.', 'segurium' ),
				array( 'status' => 409 )
			);
		}

		$feature = self::FIXABLE[ $check_id ];
		$applied = $this->run_fix( $feature, $check_id );
		if ( is_wp_error( $applied ) ) {
			return $applied;
		}

		$previous     = $this->get_last_result();
		$score_before = ( is_array( $previous ) && isset( $previous['score'] ) ) ? (int) $previous['score'] : null;

		// No history row: twelve presses would otherwise flush the whole
		// ten-entry trend the delta messaging exists to show.
		$result = $this->run_checks( true, false );

		$status = '';
		foreach ( $result['checks'] as $check ) {
			if ( $check['id'] === $check_id ) {
				$status = $check['status'];
				break;
			}
		}

		return array(
			'check_id'     => $check_id,
			'feature'      => $feature,
			'flipped'      => ( self::STATUS_PASS === $status ),
			'score_before' => $score_before,
			'result'       => $result,
		);
	}

	/**
	 * Perform the settings write for one feature, preserving every
	 * choice the user has already made inside it.
	 *
	 * @param string $feature  One of the FIX_* constants.
	 * @param string $check_id Check the user pressed, for the per-row key.
	 * @return true|WP_Error
	 */
	private function run_fix( $feature, $check_id ) {
		switch ( $feature ) {
			case self::FIX_INFO_SHIELD:
				if ( ! class_exists( 'Segurium_Info_Shield' ) ) {
					return $this->fix_unavailable( $feature );
				}
				$shield              = Segurium_Info_Shield::get_instance();
				$settings            = $shield->get_settings();
				$settings['enabled'] = true;
				if ( isset( self::FIX_SHIELD_KEYS[ $check_id ] ) ) {
					$settings[ self::FIX_SHIELD_KEYS[ $check_id ] ] = true;
				}
				$saved = $shield->save_settings( $settings );
				return empty( $saved['enabled'] ) ? $this->fix_not_persisted( $feature ) : true;

			case self::FIX_HEADERS:
				if ( ! class_exists( 'Segurium_Security_Headers' ) ) {
					return $this->fix_unavailable( $feature );
				}
				$headers             = Segurium_Security_Headers::get_instance();
				$settings            = $headers->get_settings();
				$settings['enabled'] = true;
				if ( in_array( $settings['mode'], self::HEADER_MODES_TO_UPGRADE, true ) ) {
					$settings['mode']   = 'custom';
					$settings['custom'] = self::header_values_without_hsts();
				}
				$saved = $headers->save_settings( $settings );
				return empty( $saved['enabled'] ) ? $this->fix_not_persisted( $feature ) : true;

			case self::FIX_BRUTE_FORCE:
				if ( ! class_exists( 'Segurium_Brute_Force' ) ) {
					return $this->fix_unavailable( $feature );
				}
				$brute               = Segurium_Brute_Force::get_instance();
				$settings            = $brute->get_settings();
				$settings['enabled'] = true;
				$saved               = $brute->save_settings( $settings );
				return empty( $saved['enabled'] ) ? $this->fix_not_persisted( $feature ) : true;

			case self::FIX_AUTO_CLEANUP:
				if ( ! class_exists( 'Segurium_Auto_Fix_Settings' ) ) {
					return $this->fix_unavailable( $feature );
				}
				Segurium_Auto_Fix_Settings::set( true );
				return Segurium_Auto_Fix_Settings::is_enabled() ? true : $this->fix_not_persisted( $feature );

			case self::FIX_SCHEDULED_SCANS:
				if ( ! class_exists( 'Segurium_Scheduled_Scan_Settings' ) || ! class_exists( 'Segurium_Scheduled_Scan' ) ) {
					return $this->fix_unavailable( $feature );
				}
				$previous_mode = Segurium_Scheduled_Scan_Settings::get()['mode'];
				$saved         = Segurium_Scheduled_Scan_Settings::save(
					array( 'mode' => Segurium_Scheduled_Scan_Settings::DEFAULT_MODE )
				);
				if ( is_wp_error( $saved ) ) {
					return $saved;
				}
				Segurium_Scheduled_Scan::reschedule();
				// A host that refuses to queue cron events would otherwise leave the
				// row green with no run scheduled, so the mode goes back.
				if ( ! wp_next_scheduled( Segurium_Scheduled_Scan::CRON_HOOK ) ) {
					Segurium_Scheduled_Scan_Settings::save( array( 'mode' => $previous_mode ) );
					return $this->fix_not_persisted( $feature );
				}
				return true;
		}

		return $this->fix_unavailable( $feature );
	}

	/**
	 * The Recommended header set with HSTS left switched off.
	 *
	 * The five auto-fixable header rows all pass under Recommended, but
	 * that preset also turns on `Strict-Transport-Security` with a
	 * one-year max-age and `includeSubDomains`. A browser pins that for
	 * the full year, so any subdomain still served over plain HTTP goes
	 * dark and switching the setting back off does not bring it back.
	 * `hsts` is excluded from FIXABLE for exactly that reason, and it
	 * must not ride in through the preset either — so the write lands as
	 * a custom set instead. Reached only when the mode was `off` or
	 * `basic`, neither of which has a custom set worth preserving.
	 *
	 * @return array
	 */
	private static function header_values_without_hsts() {
		$values = Segurium_Security_Headers::MODE_PRESETS['recommended'];

		$values['hsts_enabled']            = false;
		$values['hsts_max_age']            = 0;
		$values['hsts_include_subdomains'] = false;
		$values['hsts_preload']            = false;

		return $values;
	}

	/**
	 * The feature that owns this fix is not loaded on this install.
	 *
	 * @param string $feature Feature key that could not be reached.
	 * @return WP_Error
	 */
	private function fix_unavailable( $feature ) {
		return new WP_Error(
			'segurium_self_check_fix_unavailable',
			'',
			array(
				'status'  => 500,
				'feature' => $feature,
			)
		);
	}

	/**
	 * The write was issued but did not survive a read-back.
	 *
	 * @param string $feature Feature key whose write did not survive.
	 * @return WP_Error
	 */
	private function fix_not_persisted( $feature ) {
		return new WP_Error(
			'segurium_self_check_fix_not_persisted',
			'',
			array(
				'status'  => 500,
				'feature' => $feature,
			)
		);
	}

	/**
	 * Category 1 — 7 HTTP security header checks, total 10 points.
	 *
	 * @param array $headers Lower-cased header map.
	 * @return array
	 */
	private function check_security_headers( $headers ) {
		$pts    = self::PTS_HEADERS / 7;
		$checks = array();

		$has_csp    = ! empty( $headers['content-security-policy'] );
		$has_csp_ro = ! empty( $headers['content-security-policy-report-only'] );
		$checks[]   = $this->make_check(
			array(
				'id'       => 'csp',
				'category' => self::CAT_HEADERS,
				'label'    => __( 'Content-Security-Policy', 'segurium' ),
				'status'   => $has_csp ? self::STATUS_PASS : ( $has_csp_ro ? self::STATUS_WARN : self::STATUS_FAIL ),
				'detail'   => $has_csp
					? __( 'CSP is enforced.', 'segurium' )
					: ( $has_csp_ro
						? __( 'CSP is report-only. Switch to enforce for full protection.', 'segurium' )
						: __( 'No Content-Security-Policy header. Protects against XSS and injection.', 'segurium' ) ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => $has_csp ? $pts : ( $has_csp_ro ? $pts * 0.5 : 0 ),
			)
		);

		$hsts    = isset( $headers['strict-transport-security'] ) ? (string) $headers['strict-transport-security'] : '';
		$hsts_ok = false;
		if ( $hsts && preg_match( '/max-age=(\d+)/i', $hsts, $m ) && (int) $m[1] >= 31536000 ) {
			$hsts_ok = true;
		}
		$checks[] = $this->make_check(
			array(
				'id'       => 'hsts',
				'category' => self::CAT_HEADERS,
				'label'    => __( 'Strict-Transport-Security', 'segurium' ),
				'status'   => $hsts_ok ? self::STATUS_PASS : ( $hsts ? self::STATUS_WARN : self::STATUS_FAIL ),
				'detail'   => $hsts_ok
					? __( 'HSTS active with at least a one-year max-age.', 'segurium' )
					: ( $hsts
						? __( 'HSTS present but max-age is below one year.', 'segurium' )
						: __( 'No HSTS header. Browsers may connect over plain HTTP.', 'segurium' ) ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => $hsts_ok ? $pts : ( $hsts ? $pts * 0.5 : 0 ),
			)
		);

		$xcto     = isset( $headers['x-content-type-options'] ) ? strtolower( trim( (string) $headers['x-content-type-options'] ) ) : '';
		$xcto_ok  = ( 'nosniff' === $xcto );
		$checks[] = $this->make_check(
			array(
				'id'       => 'xcto',
				'category' => self::CAT_HEADERS,
				'label'    => __( 'X-Content-Type-Options', 'segurium' ),
				'status'   => $xcto_ok ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $xcto_ok
					? __( 'MIME sniffing prevented.', 'segurium' )
					: __( 'Missing. Browsers may misinterpret file types.', 'segurium' ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => $xcto_ok ? $pts : 0,
			)
		);

		$xfo      = isset( $headers['x-frame-options'] ) ? strtoupper( trim( (string) $headers['x-frame-options'] ) ) : '';
		$xfo_ok   = ( 'DENY' === $xfo || 'SAMEORIGIN' === $xfo );
		$checks[] = $this->make_check(
			array(
				'id'       => 'xfo',
				'category' => self::CAT_HEADERS,
				'label'    => __( 'X-Frame-Options', 'segurium' ),
				'status'   => $xfo_ok ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $xfo_ok
					? __( 'Clickjacking protection via X-Frame-Options.', 'segurium' )
					: __( 'Missing X-Frame-Options. Site may be framed by attackers.', 'segurium' ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => $xfo_ok ? $pts : 0,
			)
		);

		$rp       = isset( $headers['referrer-policy'] ) ? strtolower( trim( (string) $headers['referrer-policy'] ) ) : '';
		$rp_ok    = ( '' !== $rp && 'unsafe-url' !== $rp );
		$checks[] = $this->make_check(
			array(
				'id'       => 'referrer_policy',
				'category' => self::CAT_HEADERS,
				'label'    => __( 'Referrer-Policy', 'segurium' ),
				'status'   => $rp_ok ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $rp_ok
					? __( 'Referrer-Policy restricts information leakage on navigation.', 'segurium' )
					: __( 'Missing or unsafe Referrer-Policy. Full URLs may be leaked.', 'segurium' ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => $rp_ok ? $pts : 0,
			)
		);

		$pp_ok    = ! empty( $headers['permissions-policy'] );
		$checks[] = $this->make_check(
			array(
				'id'       => 'permissions_policy',
				'category' => self::CAT_HEADERS,
				'label'    => __( 'Permissions-Policy', 'segurium' ),
				'status'   => $pp_ok ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $pp_ok
					? __( 'Permissions-Policy restricts access to browser features.', 'segurium' )
					: __( 'Missing Permissions-Policy. Browser features are not restricted.', 'segurium' ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => $pp_ok ? $pts : 0,
			)
		);

		$xss      = isset( $headers['x-xss-protection'] ) ? (string) $headers['x-xss-protection'] : '';
		$xss_ok   = ( '' !== $xss );
		$checks[] = $this->make_check(
			array(
				'id'       => 'xss_protection',
				'category' => self::CAT_HEADERS,
				'label'    => __( 'X-XSS-Protection', 'segurium' ),
				'status'   => $xss_ok ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $xss_ok
					? __( 'Legacy XSS filter directive present.', 'segurium' )
					: __( 'Missing X-XSS-Protection. Set to 0 to disable legacy browser XSS filters safely.', 'segurium' ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => $xss_ok ? $pts : 0,
			)
		);

		return $checks;
	}

	/**
	 * Category 2 — 3 information-disclosure checks, total 30 points.
	 *
	 * @param array  $headers Lower-cased header map.
	 * @param string $body    Response HTML body.
	 * @return array
	 */
	private function check_info_disclosure( $headers, $body ) {
		$pts    = self::PTS_DISCLOSURE / 3;
		$checks = array();

		$xpb_present = isset( $headers['x-powered-by'] ) && '' !== trim( (string) $headers['x-powered-by'] );
		$checks[]    = $this->make_check(
			array(
				'id'       => 'x_powered_by',
				'category' => self::CAT_DISCLOSURE,
				'label'    => __( 'X-Powered-By hidden', 'segurium' ),
				'status'   => $xpb_present ? self::STATUS_FAIL : self::STATUS_PASS,
				'detail'   => $xpb_present
					? sprintf(
						/* translators: %s: header value */
						__( 'X-Powered-By reveals: %s', 'segurium' ),
						(string) $headers['x-powered-by']
					)
					: __( 'X-Powered-By header is not exposed.', 'segurium' ),
				'fix_tab'  => self::TAB_INFO_SHIELD,
				'points'   => $xpb_present ? 0 : $pts,
			)
		);

		$has_generator = (bool) preg_match( '/<meta\s+name=["\']generator["\']\s+content=["\']WordPress/i', $body );
		$checks[]      = $this->make_check(
			array(
				'id'       => 'wp_generator',
				'category' => self::CAT_DISCLOSURE,
				'label'    => __( 'WordPress version hidden', 'segurium' ),
				'status'   => $has_generator ? self::STATUS_FAIL : self::STATUS_PASS,
				'detail'   => $has_generator
					? __( 'WordPress version exposed in HTML source.', 'segurium' )
					: __( 'WordPress version not visible in HTML.', 'segurium' ),
				'fix_tab'  => self::TAB_INFO_SHIELD,
				'points'   => $has_generator ? 0 : $pts,
			)
		);

		$has_vq   = (bool) preg_match( '/\.(?:css|js)(?:\?[^"\'\s>]*\bver=[\d.]+)/i', $body );
		$checks[] = $this->make_check(
			array(
				'id'       => 'version_query',
				'category' => self::CAT_DISCLOSURE,
				'label'    => __( 'Asset version query hidden', 'segurium' ),
				'status'   => $has_vq ? self::STATUS_FAIL : self::STATUS_PASS,
				'detail'   => $has_vq
					? __( 'Core/theme/plugin version exposed in ?ver= on asset URLs.', 'segurium' )
					: __( 'Asset URLs do not expose version numbers.', 'segurium' ),
				'fix_tab'  => self::TAB_INFO_SHIELD,
				'points'   => $has_vq ? 0 : $pts,
			)
		);

		return $checks;
	}

	/**
	 * Category 3 — 6 WordPress hardening checks, total 40 points. Scan
	 * freshness/result rows live in `check_malware_protection()`.
	 *
	 * @return array
	 */
	private function check_wp_hardening() {
		$pts    = self::PTS_HARDENING / 6;
		$checks = array();

		$info_shield = Segurium_Info_Shield::get_instance()->get_settings();
		$is_on       = ! empty( $info_shield['enabled'] );

		$xmlrpc_off = $is_on && ! empty( $info_shield['disable_xmlrpc'] );
		$checks[]   = $this->make_check(
			array(
				'id'       => 'xmlrpc',
				'category' => self::CAT_HARDENING,
				'label'    => __( 'XML-RPC disabled', 'segurium' ),
				'status'   => $xmlrpc_off ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $xmlrpc_off
					? __( 'XML-RPC endpoint is disabled.', 'segurium' )
					: __( 'XML-RPC is reachable. A frequent brute-force and pingback-amplification target.', 'segurium' ),
				'fix_tab'  => self::TAB_INFO_SHIELD,
				'points'   => $xmlrpc_off ? $pts : 0,
			)
		);

		$rest_off = $is_on && ! empty( $info_shield['remove_rest_api_link'] );
		$checks[] = $this->make_check(
			array(
				'id'       => 'rest_api_link',
				'category' => self::CAT_HARDENING,
				'label'    => __( 'REST API discovery disabled', 'segurium' ),
				'status'   => $rest_off ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $rest_off
					? __( 'REST API discovery link removed from <head>.', 'segurium' )
					: __( 'REST API discovery link exposed — simplifies reconnaissance.', 'segurium' ),
				'fix_tab'  => self::TAB_INFO_SHIELD,
				'points'   => $rest_off ? $pts : 0,
			)
		);

		$bf_on    = ! empty( Segurium_Brute_Force::get_instance()->get_settings()['enabled'] );
		$checks[] = $this->make_check(
			array(
				'id'       => 'bruteforce',
				'category' => self::CAT_HARDENING,
				'label'    => __( 'Brute-force protection', 'segurium' ),
				'status'   => $bf_on ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $bf_on
					? __( 'Login brute-force protection is active.', 'segurium' )
					: __( 'Brute-force protection is disabled.', 'segurium' ),
				'fix_tab'  => self::TAB_BRUTEFORCE,
				'points'   => $bf_on ? $pts : 0,
			)
		);

		$tfa       = Segurium_2FA::get_instance()->get_settings();
		$tfa_admin = ! empty( $tfa['enabled'] )
			&& ! empty( $tfa['enforced_roles'] )
			&& is_array( $tfa['enforced_roles'] )
			&& in_array( 'administrator', $tfa['enforced_roles'], true );
		$checks[]  = $this->make_check(
			array(
				'id'       => 'twofactor_admin',
				'category' => self::CAT_HARDENING,
				'label'    => __( 'Two-factor enforced for administrators', 'segurium' ),
				'status'   => $tfa_admin ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $tfa_admin
					? __( 'Two-factor authentication is enforced for the administrator role.', 'segurium' )
					: __( 'Administrators can log in with a password alone.', 'segurium' ),
				'fix_tab'  => self::TAB_TWOFACTOR,
				'points'   => $tfa_admin ? $pts : 0,
			)
		);

		// A follow-up splits WAF from firewall; self-check will move to that option when it lands.
		$waf_on   = (bool) Segurium_Settings::get_field( 'firewall', 'enabled' );
		$checks[] = $this->make_check(
			array(
				'id'       => 'waf',
				'category' => self::CAT_HARDENING,
				'label'    => __( 'Firewall', 'segurium' ),
				'status'   => $waf_on ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $waf_on
					? __( 'Firewall rules are active.', 'segurium' )
					: __( 'No firewall rules are active.', 'segurium' ),
				'fix_tab'  => self::TAB_FIREWALL,
				'points'   => $waf_on ? $pts : 0,
			)
		);

		// A follow-up will supply a fix target for the SSL row.
		$ssl_on   = 'https' === strtolower( (string) wp_parse_url( home_url( '/' ), PHP_URL_SCHEME ) );
		$checks[] = $this->make_check(
			array(
				'id'       => 'ssl',
				'category' => self::CAT_HARDENING,
				'label'    => __( 'HTTPS / SSL active', 'segurium' ),
				'status'   => $ssl_on ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $ssl_on
					? __( 'Site is served over HTTPS.', 'segurium' )
					: __( 'Site is not served over HTTPS. Traffic is unencrypted.', 'segurium' ),
				'fix_tab'  => self::TAB_NONE,
				'points'   => $ssl_on ? $pts : 0,
			)
		);

		return $checks;
	}

	/**
	 * Category 4 — 2 cookie security checks, total 8 points.
	 *
	 * Observation-style scoring: every Set-Cookie on the homepage is
	 * inspected for Secure / SameSite. PASS only when every cookie has
	 * the flag; PARTIAL when some do; FAIL when none do. Mirrors CTI
	 * `eval_cookies()` so the plugin and the external scan agree on the
	 * same observable surface.
	 *
	 * @param array $headers Lower-cased header map (Set-Cookie may be string or array).
	 * @return array
	 */
	private function check_cookie_security( $headers ) {
		$pts     = self::PTS_COOKIES / 2;
		$cookies = $headers['set-cookie'] ?? array();
		if ( is_string( $cookies ) ) {
			$cookies = array( $cookies );
		}
		if ( ! is_array( $cookies ) ) {
			$cookies = array();
		}
		$cookies = array_values(
			array_filter(
				array_map( 'strval', $cookies ),
				static function ( $line ) {
					return '' !== trim( $line );
				}
			)
		);

		if ( empty( $cookies ) ) {
			$detail = __( 'No Set-Cookie headers on the homepage; cannot assess cookie flags from outside.', 'segurium' );
			return array(
				$this->make_check(
					array(
						'id'       => 'cookie_secure',
						'category' => self::CAT_COOKIES,
						'label'    => __( 'Cookies — Secure', 'segurium' ),
						'status'   => self::STATUS_WARN,
						'detail'   => $detail,
						'fix_tab'  => self::TAB_HEADERS,
						'points'   => $pts,
					)
				),
				$this->make_check(
					array(
						'id'       => 'cookie_samesite',
						'category' => self::CAT_COOKIES,
						'label'    => __( 'Cookies — SameSite', 'segurium' ),
						'status'   => self::STATUS_WARN,
						'detail'   => $detail,
						'fix_tab'  => self::TAB_HEADERS,
						'points'   => $pts,
					)
				),
			);
		}

		return array(
			$this->cookie_flag_check( $cookies, 'cookie_secure', __( 'Cookies — Secure', 'segurium' ), 'Secure', $pts ),
			$this->cookie_samesite_check( $cookies, $pts ),
		);
	}

	/**
	 * Score a boolean cookie attribute across all Set-Cookie lines from
	 * the homepage response.
	 *
	 * @param string[] $cookies Raw Set-Cookie header values.
	 * @param string   $id      Check id (`cookie_secure`).
	 * @param string   $label   Localised label.
	 * @param string   $flag    Attribute name as it appears in Set-Cookie.
	 * @param float    $pts     Per-check max points.
	 * @return array
	 */
	private function cookie_flag_check( array $cookies, $id, $label, $flag, $pts ) {
		$total    = count( $cookies );
		$matching = 0;
		foreach ( $cookies as $cookie ) {
			if ( $this->cookie_has_attr( $cookie, $flag ) ) {
				++$matching;
			}
		}
		if ( $matching === $total ) {
			return $this->make_check(
				array(
					'id'       => $id,
					'category' => self::CAT_COOKIES,
					'label'    => $label,
					'status'   => self::STATUS_PASS,
					/* translators: 1: total cookie count, 2: cookie attribute name */
					'detail'   => sprintf( __( 'All %1$d cookies set the %2$s attribute.', 'segurium' ), $total, $flag ),
					'fix_tab'  => self::TAB_HEADERS,
					'points'   => $pts,
				)
			);
		}
		if ( $matching > 0 ) {
			return $this->make_check(
				array(
					'id'       => $id,
					'category' => self::CAT_COOKIES,
					'label'    => $label,
					'status'   => self::STATUS_PARTIAL,
					/* translators: 1: matching cookie count, 2: total cookie count, 3: cookie attribute name */
					'detail'   => sprintf( __( '%1$d of %2$d cookies set %3$s.', 'segurium' ), $matching, $total, $flag ),
					'fix_tab'  => self::TAB_HEADERS,
					'points'   => $pts * 0.5,
				)
			);
		}
		return $this->make_check(
			array(
				'id'       => $id,
				'category' => self::CAT_COOKIES,
				'label'    => $label,
				'status'   => self::STATUS_FAIL,
				/* translators: 1: total cookie count, 2: cookie attribute name */
				'detail'   => sprintf( __( 'None of the %1$d cookies set the %2$s attribute.', 'segurium' ), $total, $flag ),
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => 0,
			)
		);
	}

	/**
	 * Score the SameSite attribute. PASS only when every cookie sets
	 * SameSite=Lax or Strict. PARTIAL when some do and none use
	 * SameSite=None. Otherwise FAIL.
	 *
	 * @param string[] $cookies Raw Set-Cookie header values.
	 * @param float    $pts     Per-check max points.
	 * @return array
	 */
	private function cookie_samesite_check( array $cookies, $pts ) {
		$total      = count( $cookies );
		$good       = 0;
		$none_value = 0;
		foreach ( $cookies as $cookie ) {
			$value = $this->cookie_attr_value( $cookie, 'SameSite' );
			if ( null === $value ) {
				continue;
			}
			$lower = strtolower( $value );
			if ( 'lax' === $lower || 'strict' === $lower ) {
				++$good;
			} elseif ( 'none' === $lower ) {
				++$none_value;
			}
		}
		if ( $good === $total ) {
			return $this->make_check(
				array(
					'id'       => 'cookie_samesite',
					'category' => self::CAT_COOKIES,
					'label'    => __( 'Cookies — SameSite', 'segurium' ),
					'status'   => self::STATUS_PASS,
					/* translators: %d: total cookie count */
					'detail'   => sprintf( __( 'All %d cookies set SameSite=Lax/Strict.', 'segurium' ), $total ),
					'fix_tab'  => self::TAB_HEADERS,
					'points'   => $pts,
				)
			);
		}
		if ( $good > 0 && 0 === $none_value ) {
			return $this->make_check(
				array(
					'id'       => 'cookie_samesite',
					'category' => self::CAT_COOKIES,
					'label'    => __( 'Cookies — SameSite', 'segurium' ),
					'status'   => self::STATUS_PARTIAL,
					/* translators: 1: good cookie count, 2: total cookie count */
					'detail'   => sprintf( __( '%1$d of %2$d cookies set SameSite=Lax/Strict.', 'segurium' ), $good, $total ),
					'fix_tab'  => self::TAB_HEADERS,
					'points'   => $pts * 0.5,
				)
			);
		}
		$detail = $none_value > 0
			/* translators: 1: count of cookies using SameSite=None, 2: total cookie count */
			? sprintf( __( '%1$d of %2$d cookies use SameSite=None.', 'segurium' ), $none_value, $total )
			/* translators: %d: total cookie count */
			: sprintf( __( 'No cookies set SameSite=Lax or Strict (out of %d).', 'segurium' ), $total );
		return $this->make_check(
			array(
				'id'       => 'cookie_samesite',
				'category' => self::CAT_COOKIES,
				'label'    => __( 'Cookies — SameSite', 'segurium' ),
				'status'   => self::STATUS_FAIL,
				'detail'   => $detail,
				'fix_tab'  => self::TAB_HEADERS,
				'points'   => 0,
			)
		);
	}

	/**
	 * Whether a Set-Cookie line carries a flag attribute (case-insensitive).
	 *
	 * @param string $cookie Raw Set-Cookie value.
	 * @param string $attr   Attribute name (e.g. `Secure`).
	 * @return bool
	 */
	private function cookie_has_attr( $cookie, $attr ) {
		foreach ( explode( ';', $cookie ) as $piece ) {
			if ( 0 === strcasecmp( trim( $piece ), $attr ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Read the value of a `name=value` attribute from a Set-Cookie line.
	 *
	 * @param string $cookie Raw Set-Cookie value.
	 * @param string $attr   Attribute name (e.g. `SameSite`).
	 * @return string|null
	 */
	private function cookie_attr_value( $cookie, $attr ) {
		$prefix = strtolower( $attr ) . '=';
		foreach ( explode( ';', $cookie ) as $piece ) {
			$p = trim( $piece );
			if ( 0 === strncasecmp( $p, $prefix, strlen( $prefix ) ) ) {
				return substr( $p, strlen( $prefix ) );
			}
		}
		return null;
	}

	/**
	 * Category 5 — 6 malware-protection checks, total 20 points.
	 *
	 * Verifies the configuration, freshness, and verdict of the malware
	 * and integrity scanners — the signals that most directly affect
	 * whether infections get caught.
	 *
	 * @return array
	 */
	private function check_malware_protection() {
		$pts    = self::PTS_MALWARE / 6;
		$checks = array();
		$now    = time();

		$on_premise = Segurium::get_instance()->is_on_premise();
		$checks[]   = $this->make_check(
			array(
				'id'       => 'on_premise_mode',
				'category' => self::CAT_MALWARE,
				'label'    => __( 'Cloud-assisted malware detection', 'segurium' ),
				'status'   => $on_premise ? self::STATUS_FAIL : self::STATUS_PASS,
				'detail'   => $on_premise
					? __( 'On-premise mode is enabled: file contents stay on this server, and any file the cloud cannot identify by hash goes unresolved. Turn on cloud-assisted detection for full accuracy.', 'segurium' )
					: __( 'Cloud-assisted malware detection is active.', 'segurium' ),
				'fix_tab'  => self::TAB_SETTINGS,
				'points'   => $on_premise ? 0 : $pts,
			)
		);

		$sched_mode    = (string) Segurium_Scheduled_Scan_Settings::get()['mode'];
		$sched_enabled = ( Segurium_Scheduled_Scan_Settings::MODE_OFF !== $sched_mode );
		$checks[]      = $this->make_check(
			array(
				'id'       => 'scheduled_scans',
				'category' => self::CAT_MALWARE,
				'label'    => __( 'Scheduled malware scans', 'segurium' ),
				'status'   => $sched_enabled ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $sched_enabled
					? __( 'A recurring malware scan is scheduled.', 'segurium' )
					: __( 'No recurring malware scan is scheduled.', 'segurium' ),
				'fix_tab'  => self::TAB_SETTINGS,
				'points'   => $sched_enabled ? $pts : 0,
			)
		);

		// Auto-fix is available on every install; pass = enabled.
		$auto_enabled = Segurium_Auto_Fix_Settings::is_enabled();
		$checks[]     = $this->make_check(
			array(
				'id'       => 'auto_cleanup',
				'category' => self::CAT_MALWARE,
				'label'    => __( 'Automatic malware cleanup', 'segurium' ),
				'status'   => $auto_enabled ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $auto_enabled
					? __( 'Detected malware is cleaned automatically after every scan.', 'segurium' )
					: __( 'Automatic cleanup is disabled. Detected malware requires a manual click to clean.', 'segurium' ),
				'fix_tab'  => self::TAB_SETTINGS,
				'points'   => $auto_enabled ? $pts : 0,
			)
		);

		$last_scan     = Segurium::get_instance()->get_last_completed_scan();
		$malware_t     = is_array( $last_scan ) ? (int) ( $last_scan['completed_at'] ?? 0 ) : 0;
		$malware_n     = is_array( $last_scan ) ? (int) ( $last_scan['threats_found'] ?? 0 ) : 0;
		$malware_fresh = ( $malware_t > 0 && ( $now - $malware_t ) <= ( self::SCAN_FRESH_DAYS * DAY_IN_SECONDS ) );
		$checks[]      = $this->make_check(
			array(
				'id'       => 'malware_fresh',
				'category' => self::CAT_MALWARE,
				'label'    => __( 'Malware scan up to date', 'segurium' ),
				'status'   => $malware_fresh ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $malware_fresh
					? sprintf(
						/* translators: %s: human time difference */
						__( 'Last malware scan completed %s ago.', 'segurium' ),
						human_time_diff( $malware_t, $now )
					)
					: ( $malware_t > 0
						? __( 'Malware scan is older than 7 days.', 'segurium' )
						: __( 'No malware scan has been completed yet.', 'segurium' ) ),
				'fix_tab'  => self::TAB_SCANNER,
				'points'   => $malware_fresh ? $pts : 0,
			)
		);

		$malware_24h_fresh = ( $malware_t > 0 && ( $now - $malware_t ) <= self::SCAN_24H_FRESH_SECS );
		$malware_24h_pass  = ( $malware_24h_fresh && 0 === $malware_n );
		$checks[]          = $this->make_check(
			array(
				'id'       => 'no_malware_24h',
				'category' => self::CAT_MALWARE,
				'label'    => __( 'No malware in the last 24 hours', 'segurium' ),
				'status'   => $malware_24h_pass ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $malware_24h_pass
					? __( 'The most recent malware scan ran in the last 24 hours and found nothing.', 'segurium' )
					: ( ! $malware_24h_fresh
						? __( 'No malware scan has run in the last 24 hours. Scans are quick — run one to refresh this verdict.', 'segurium' )
						: sprintf(
							/* translators: %d: number of threats */
							_n( 'Last malware scan flagged %d threat. Review it on the Malware scanner tab.', 'Last malware scan flagged %d threats. Review them on the Malware scanner tab.', $malware_n, 'segurium' ),
							$malware_n
						) ),
				'fix_tab'  => self::TAB_SCANNER,
				'points'   => $malware_24h_pass ? $pts : 0,
			)
		);

		$integrity_t = (int) Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( 'integrity:last_scan' )
		);

		$integrity_24h_fresh = ( $integrity_t > 0 && ( $now - $integrity_t ) <= self::SCAN_24H_FRESH_SECS );

		$integrity_open_issues = $integrity_t > 0 ? $this->count_open_integrity_issues( $integrity_t ) : 0;

		$integrity_pass = ( $integrity_24h_fresh && 0 === $integrity_open_issues );

		$checks[] = $this->make_check(
			array(
				'id'       => 'no_integrity_issues_24h',
				'category' => self::CAT_MALWARE,
				'label'    => __( 'No integrity issues in the last 24 hours', 'segurium' ),
				'status'   => $integrity_pass ? self::STATUS_PASS : self::STATUS_FAIL,
				'detail'   => $integrity_pass
					? __( 'The most recent integrity scan ran in the last 24 hours and reported no issues.', 'segurium' )
					: ( ! $integrity_24h_fresh
						? __( 'No integrity scan has run in the last 24 hours. Scans are quick — run one to refresh this verdict.', 'segurium' )
						: sprintf(
							/* translators: %d: number of open integrity issues */
							_n( '%d open integrity issue is unresolved. Review it on the Integrity scanner tab.', '%d open integrity issues are unresolved. Review them on the Integrity scanner tab.', $integrity_open_issues, 'segurium' ),
							$integrity_open_issues
						) ),
				'fix_tab'  => self::TAB_INTEGRITY,
				'points'   => $integrity_pass ? $pts : 0,
			)
		);

		return $checks;
	}

	/**
	 * Everything the integrity scanner UI still counts as an issue: open
	 * file findings, plus the components whose release the cloud flags as
	 * vulnerable.
	 *
	 * Both halves come from Segurium_Integrity_Server_State, which mirrors
	 * the tab. File findings are restricted to rows touched by the latest
	 * scan, so a stale `open` row from an earlier scan cannot keep a clean
	 * site red. Components the user has already acted on drop out of both.
	 * A component carrying both counts once.
	 *
	 * The flagged releases have to be added separately because their files
	 * match the vendor's own hashes and so never become findings — the
	 * whole reason a site with two flagged plugins used to score a clean
	 * 100 while the tab showed them in red.
	 *
	 * @param int $scan_ts Timestamp of the most recent integrity scan.
	 * @return int
	 */
	private function count_open_integrity_issues( $scan_ts ) {
		return Segurium_Integrity_Server_State::count_open_tab_issues( $scan_ts );
	}

	/**
	 * Aggregate point totals and per-category pass/warn/fail counts.
	 *
	 * @param array $checks Raw check rows from the category methods.
	 * @return array
	 */
	private function calculate_score( $checks ) {
		$total = 0.0;
		foreach ( $checks as $c ) {
			$total += (float) $c['points'];
		}
		$score = (int) round( min( 100.0, max( 0.0, $total ) ) );
		$grade = $this->score_to_grade( $score );

		$cats = array();
		foreach ( $checks as $c ) {
			$cat = $c['category'];
			if ( ! isset( $cats[ $cat ] ) ) {
				$cats[ $cat ] = array(
					'total'   => 0,
					'pass'    => 0,
					'partial' => 0,
					'warn'    => 0,
					'fail'    => 0,
				);
			}
			++$cats[ $cat ]['total'];
			if ( isset( $cats[ $cat ][ $c['status'] ] ) ) {
				++$cats[ $cat ][ $c['status'] ];
			}
		}

		return array(
			'score'      => $score,
			'grade'      => $grade,
			'categories' => $cats,
			'checks'     => $checks,
			'scanned_at' => time(),
		);
	}

	/**
	 * Map a 0-100 score to a letter grade.
	 *
	 * @param int $score Integer score in the range 0-100.
	 * @return string
	 */
	private function score_to_grade( $score ) {
		if ( $score >= 95 ) {
			return 'A+';
		}
		if ( $score >= 85 ) {
			return 'A';
		}
		if ( $score >= 70 ) {
			return 'B';
		}
		if ( $score >= 55 ) {
			return 'C';
		}
		if ( $score >= 40 ) {
			return 'D';
		}
		return 'F';
	}

	/**
	 * Append the latest result summary to the score history and cap at
	 * HISTORY_MAX entries. Called on every cache miss (force-refresh or
	 * natural hourly expiry), bounded to HISTORY_MAX so the option stays
	 * tiny.
	 *
	 * @param array $result Result array from `calculate_score()`.
	 */
	private function save_to_history( $result ) {
		$entry = array(
			'score'      => (int) $result['score'],
			'grade'      => (string) $result['grade'],
			'scanned_at' => (int) $result['scanned_at'],
		);
		try {
			Segurium_Storage::table_insert(
				'self_check_history',
				array(
					'check_type'  => 'self_check',
					'status'      => (string) $result['grade'],
					'result_json' => (string) wp_json_encode( $entry ),
					'created_at'  => (int) $result['scanned_at'],
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-self-check] history insert failed: ' . $e->getMessage() );
			return;
		}

		// Cap rows on insert so the table stays bounded without relying on GC.
		global $wpdb;
		$table = Segurium_Storage::table_name( 'self_check_history' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE check_type = %s AND id NOT IN (SELECT id FROM (SELECT id FROM %i WHERE check_type = %s ORDER BY id DESC LIMIT %d) AS keep)', $table, 'self_check', $table, 'self_check', self::HISTORY_MAX ) );

		// Mirror as a short activity_log entry.
		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => 'self_check',
					'severity'   => 0,
					'subject'    => (string) $result['grade'],
					'data_json'  => (string) wp_json_encode( $entry ),
					'created_at' => (int) $result['scanned_at'],
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-self-check] activity_log insert failed: ' . $e->getMessage() );
		}
	}
}

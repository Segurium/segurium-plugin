<?php
/**
 * MainWP child bridge — action router (SEGURIUM-877, SEGURIUM-882).
 *
 * An agency running a MainWP dashboard manages ~35 client sites from one
 * screen. The dashboard extension (`segurium-for-mainwp`, a separate wp.org
 * plugin) asks each child site for its security state by calling MainWP's
 * `extra_execution`; MainWP Child applies `mainwp_child_extra_execution` and
 * this class answers under the `segurium` key.
 *
 * There is no new HTTP surface here and no new business logic. Every value
 * comes from state the plugin already keeps.
 *
 * The action set is split. Three read-only actions answer questions and
 * write nothing. One write action starts a scan (SEGURIUM-882), because a
 * fleet-wide scan is the one thing an agency cannot already do from
 * anywhere else. Cleanup stays out: it is quota-metered and it modifies
 * files, so it remains a deliberate per-site action taken in the site's own
 * admin — a fleet-wide cleanup button would burn an agency's free quota
 * across thirty sites in one click.
 *
 * Trust model. Before this filter fires, MainWP Child has verified the
 * request signature, confirmed the named user exists and is an
 * administrator, and called `wp_set_current_user()` on them. That is not a
 * reason to skip our own checks: a security plugin does not delegate its
 * trust boundary to another plugin. If MainWP Child is misconfigured or
 * compromised, this router is reachable, so the capability is re-verified
 * here for every action and nothing beyond the two contract fields is ever
 * read from the request.
 *
 * It is, however, the reason the rest of the plugin loads here rather than
 * from the request classifier. On a light tier this class is the only file
 * required; `handle()` pulls in the include graph after MainWP has
 * authenticated the caller. Promoting on the request's shape alone would
 * have let an unauthenticated POST buy the whole bootstrap on any
 * MainWP-managed site.
 *
 * No action in the read-only set makes an outbound request. The dashboard
 * is blocked on this response while it walks a whole fleet, so a
 * synchronous hop to Cloud Threat Inspection there would multiply one
 * dashboard refresh into 35 round trips. `scan_start` is the exception and
 * has to be: starting a scan announces itself, and the scan it starts
 * verdicts every file. That call is non-blocking, so the cost here is a
 * TCP connect rather than a round trip.
 *
 * "Read-only" means the site's security state is not changed. Two things
 * are still written on a read: the SEGURIUM-880 fleet marker records that
 * a dashboard called, and WordPress may schedule this plugin's own cron
 * events the first time the include graph loads on a light tier.
 *
 * The wire contract is `docs/child-bridge-contract.md` in segurium-mainwp.
 * The dashboard half is `Segurium_MainWP_Bridge_Envelope`.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Child-side dispatcher for MainWP dashboard requests.
 */
final class Segurium_MainWP_Bridge {

	/**
	 * Envelope version this build speaks. A dashboard asking for a
	 * different one is refused rather than served a guessed shape.
	 */
	const VERSION = 1;

	/**
	 * Key we answer under inside MainWP's `$information` array.
	 */
	const KEY = 'segurium';

	/**
	 * Longest per-section finding list returned by `findings`. The full
	 * count travels alongside as `open_total`, so a truncated list still
	 * reports the true size.
	 */
	const MAX_ITEMS = 25;

	/**
	 * Capability required for every action.
	 */
	const CAPABILITY = 'manage_options';

	/**
	 * Shortest gap between two scans started from a dashboard.
	 */
	const MIN_SCAN_INTERVAL = HOUR_IN_SECONDS;

	/**
	 * When this site last started a scan for a dashboard.
	 */
	const OPT_LAST_SCAN_START = 'segurium_mainwp_last_scan_start';

	/**
	 * Read-only actions. Nothing in this set writes, and
	 * `test_no_read_only_action_leaves_a_trace_on_the_site` asserts that
	 * against state rather than against this list.
	 *
	 * @return string[]
	 */
	public static function read_actions() {
		return array( 'status', 'findings', 'quota' );
	}

	/**
	 * Actions that change something (SEGURIUM-882).
	 *
	 * Deliberately one entry. Cleanup is quota-metered and modifies files,
	 * so it stays a per-site action taken in the site's own admin — a
	 * fleet-wide cleanup button would burn an agency's free quota across
	 * thirty sites in one click. A scan is neither metered nor
	 * destructive, and it is the one thing an agency cannot already do to
	 * a whole fleet from anywhere else.
	 *
	 * @return string[]
	 */
	public static function write_actions() {
		return array( 'scan_start' );
	}

	/**
	 * Everything the router will route.
	 *
	 * @return string[]
	 */
	public static function actions() {
		return array_merge( self::read_actions(), self::write_actions() );
	}

	/**
	 * Attach the router. Registering is inert on its own: the filter only
	 * exists inside MainWP Child, so on a site without it nothing fires.
	 *
	 * @return void
	 */
	public static function register() {
		add_filter( 'mainwp_child_extra_execution', array( __CLASS__, 'handle' ), 10, 2 ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- MainWP Child hook.
	}

	/**
	 * Whether MainWP Child is loaded on this site.
	 *
	 * @return bool
	 */
	public static function is_child_present() {
		return defined( 'MAINWP_CHILD_PLUGIN_DIR' );
	}

	/**
	 * Whether MainWP Child has been connected to a dashboard. MainWP Child
	 * stores the dashboard's public key on connect and clears it on
	 * disconnect, so an installed-but-unconnected child reports false.
	 *
	 * @return bool
	 */
	public static function is_child_connected() {
		// MainWP's own option, so it does not live behind the Segurium
		// storage facade.
		return '' !== (string) get_option( 'mainwp_child_pubkey', '' ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found -- third-party option owned by MainWP Child.
	}

	/**
	 * Route one dashboard request.
	 *
	 * @param mixed $information Answers written by other extensions.
	 * @param mixed $post        MainWP Child's copy of the request body.
	 * @return array
	 */
	public static function handle( $information, $post ) {
		if ( ! is_array( $information ) ) {
			$information = array();
		}
		if ( ! is_array( $post ) ) {
			return $information;
		}

		$has_action  = array_key_exists( 'segurium_action', $post );
		$has_version = array_key_exists( 'segurium_v', $post );
		if ( ! $has_action && ! $has_version ) {
			// Another extension's call. Leave it alone.
			return $information;
		}

		// Capability first, before anything about the request is parsed
		// or reflected back. A caller without it learns only that
		// something answered — not which actions exist, nor which
		// envelope version this build speaks.
		if ( ! current_user_can( self::CAPABILITY ) ) {
			$information[ self::KEY ] = self::fail( '', 'capability_denied' );
			return $information;
		}

		$action = '';
		if ( $has_action && is_string( $post['segurium_action'] ) ) {
			$action = sanitize_key( wp_unslash( $post['segurium_action'] ) );
		}

		if ( '' === $action ) {
			$information[ self::KEY ] = self::fail( '', 'missing_action' );
			return $information;
		}

		if ( ! self::version_matches( $has_version ? $post['segurium_v'] : null ) ) {
			$information[ self::KEY ] = self::fail( $action, 'version_unsupported' );
			return $information;
		}

		if ( ! in_array( $action, self::actions(), true ) ) {
			$information[ self::KEY ] = self::fail( $action, 'unknown_action' );
			return $information;
		}

		// On a light tier only this class was loaded. Everything the
		// actions read arrives now, once MainWP has verified the request
		// signature and set an administrator — a forged POST never gets
		// this far, so it never pays for the include graph.
		if ( ! class_exists( 'Segurium_Scan_Runner' ) && function_exists( 'segurium_load_full_plugin' ) ) {
			segurium_load_full_plugin();
		}

		$reply = self::dispatch( $action );

		// SEGURIUM-880: an answered call is the definition of "this install
		// is managed from a MainWP dashboard", and that count is the only
		// measurement of the epic's KPI. Refusals do not count — something
		// that cannot speak the contract is not a managed dashboard. The
		// marker writes options and queues a one-off event; it never sends
		// anything on this request.
		if ( ! empty( $reply['ok'] ) && class_exists( 'Segurium_MainWP_Fleet_Marker' ) ) {
			Segurium_MainWP_Fleet_Marker::observe();
		}

		$information[ self::KEY ] = $reply;
		return $information;
	}

	/**
	 * Whether the dashboard asked for the envelope version this build
	 * speaks.
	 *
	 * Strict on type as well as value: `$_POST` values are strings, so a
	 * bare `(int)` cast would accept `true`, `1.9`, `'1beta'` and even an
	 * array (which casts to 1) and serve them a v1 payload instead of the
	 * refusal the contract promises.
	 *
	 * @param mixed $raw Raw `segurium_v` value, null when absent.
	 * @return bool
	 */
	private static function version_matches( $raw ) {
		if ( null === $raw || is_bool( $raw ) || ! is_scalar( $raw ) ) {
			return false;
		}

		return (string) self::VERSION === (string) $raw;
	}

	/**
	 * Run one validated action.
	 *
	 * @param string $action Action name, already in the read-only set.
	 * @return array
	 */
	private static function dispatch( $action ) {
		try {
			switch ( $action ) {
				case 'status':
					return self::ok( $action, self::status_payload() );
				case 'findings':
					return self::ok( $action, self::findings_payload() );
				case 'quota':
					return self::quota_reply( $action );
				case 'scan_start':
					return self::scan_start_reply( $action );
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-mainwp] ' . $action . ' failed: ' . $e->getMessage() );
			return self::fail( $action, $action . '_failed' );
		}

		return self::fail( $action, 'unknown_action' );
	}

	// ---------------------------------------------------------------
	// status
	// ---------------------------------------------------------------

	/**
	 * Whole-site posture in one flat payload.
	 *
	 * Malware and integrity stay separate fields throughout. A site with a
	 * modified plugin file and no malware is a different problem from a
	 * site with a backdoor, and merging them into one "issues" number
	 * hides which one the operator is looking at.
	 *
	 * @return array
	 */
	private static function status_payload() {
		$terminal = self::last_terminal_malware_scan();
		$counts   = Segurium_File_State::get_counts( false );
		$live     = Segurium_Scan_Runner::get_status();
		$malware  = ( null !== $live && 'integrity' !== ( $live['scan_type'] ?? '' ) ) ? $live : null;

		$integrity_since = self::integrity_last_scan_at();

		return array_merge(
			array(
				'plugin_version'    => SEGURIUM_VERSION,
				'last_scan_at'      => null === $terminal ? 0 : (int) $terminal['completed_at'],
				'scan_state'        => self::malware_scan_state( $terminal, $malware ),
				// A held lock reports `running` for up to LOCK_MAX_AGE
				// (6 h) after the worker dies — deliberately, so the
				// site's own UI can show a stall rather than a false
				// idle. The dashboard needs the same distinction, or it
				// shows a clean "scanning" all afternoon.
				'scan_stalled'      => ( null !== $malware && empty( $malware['worker_alive'] ) ) ? 1 : 0,
				'scan_started_at'   => self::scan_started_at( $terminal, $malware ),
				'threats_found'     => null === $terminal ? 0 : (int) $terminal['threats_found'],
				'threats_open'      => (int) ( $counts['malicious'] ?? 0 ),
				'integrity_state'   => self::integrity_scan_state(),
				'integrity_stalled' => self::integrity_stalled(),
				'integrity_open'    => $integrity_since > 0
					? Segurium_Integrity_Server_State::count_open_issues( $integrity_since )
					: 0,
			),
			self::quota_fields()
		);
	}

	/**
	 * Free-cleanup fields, shared by `status` and `quota`.
	 *
	 * `quota_known` says whether the counter beside it means anything. It
	 * is 0 in two cases, and both would otherwise render as "no cleanups
	 * left": no CTI envelope has ever been cached here, or the site is on
	 * Pro, where the free counter is vestigial — the plugin's own readout
	 * hides it outright for Pro installs.
	 *
	 * @return array
	 */
	private static function quota_fields() {
		$tier  = Segurium_Quota::plan_tier();
		$quota = Segurium_Quota::cached_envelope();

		if ( ! is_array( $quota ) || Segurium_Quota::PLAN_TIER_PRO === $tier ) {
			return array(
				'plan_tier'          => $tier,
				'quota_known'        => 0,
				'quota_remaining'    => 0,
				'quota_window_reset' => 0,
			);
		}

		return array(
			'plan_tier'          => $tier,
			'quota_known'        => 1,
			'quota_remaining'    => max( 0, (int) $quota['limit'] - (int) $quota['used'] ),
			'quota_window_reset' => (int) $quota['next_slot_at'],
		);
	}

	/**
	 * Terminal state of the malware scanner.
	 *
	 * @param array|null $terminal Last terminal scan row.
	 * @param array|null $live     Live non-integrity scan status, or null.
	 * @return string
	 */
	private static function malware_scan_state( $terminal, $live ) {
		if ( null !== $live && ! empty( $live['running'] ) ) {
			return 'running';
		}

		if ( null === $terminal ) {
			return 'never_run';
		}

		return (string) $terminal['status'];
	}

	/**
	 * When the scan the state refers to began.
	 *
	 * @param array|null $terminal Last terminal scan row.
	 * @param array|null $live     Live non-integrity scan status, or null.
	 * @return int
	 */
	private static function scan_started_at( $terminal, $live ) {
		if ( null !== $live && ! empty( $live['running'] ) ) {
			return (int) ( $live['started_at'] ?? 0 );
		}

		return null === $terminal ? 0 : (int) $terminal['started_at'];
	}

	/**
	 * Last completed / cancelled / aborted malware scan.
	 *
	 * Reads through the shared static on the runner, which the admin UI
	 * also uses, so the SEGURIUM-548 frozen-counter semantics have one
	 * implementation. Deliberately not `Segurium::get_instance()`: that
	 * constructor registers hooks and schedules cron events, so a
	 * `status` read would have written to the child.
	 *
	 * @return array|null
	 */
	private static function last_terminal_malware_scan() {
		$row = Segurium_Scan_Runner::last_terminal_scan();
		if ( null === $row ) {
			return null;
		}

		$started = (int) $row['started_at'];

		return array(
			'status'        => (string) $row['status'],
			'started_at'    => $started,
			'completed_at'  => null !== $row['finished_at'] ? (int) $row['finished_at'] : $started,
			'threats_found' => (int) $row['threats_found'],
		);
	}

	/**
	 * Terminal state of the integrity scanner.
	 *
	 * @return string
	 */
	private static function integrity_scan_state() {
		$live = Segurium_Scan_Runner::get_status( 'integrity' );
		if ( null !== $live && ! empty( $live['running'] ) ) {
			return 'running';
		}

		$row = Segurium_Storage::table_get_row(
			'scan_history',
			"SELECT status FROM {{table}}
			 WHERE status IN ('completed','cancelled','aborted') AND scan_type = 'integrity'
			 ORDER BY started_at DESC LIMIT 1",
			array(),
			ARRAY_A
		);
		if ( is_array( $row ) ) {
			return (string) $row['status'];
		}

		return self::integrity_last_scan_at() > 0 ? 'completed' : 'never_run';
	}

	/**
	 * Whether a running integrity scan has lost its worker.
	 *
	 * @return int
	 */
	private static function integrity_stalled() {
		$live = Segurium_Scan_Runner::get_status( 'integrity' );

		return ( null !== $live && ! empty( $live['running'] ) && empty( $live['worker_alive'] ) ) ? 1 : 0;
	}

	/**
	 * Timestamp of the most recent integrity scan.
	 *
	 * @return int
	 */
	private static function integrity_last_scan_at() {
		return (int) Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s',
			array( 'integrity:last_scan' )
		);
	}

	// ---------------------------------------------------------------
	// findings
	// ---------------------------------------------------------------

	/**
	 * Open findings, split into two sections that never merge.
	 *
	 * @return array
	 */
	private static function findings_payload() {
		return array(
			'malware'   => self::malware_findings(),
			'integrity' => self::integrity_findings(),
		);
	}

	/**
	 * Open malware findings, capped.
	 *
	 * @return array
	 */
	private static function malware_findings() {
		$total = Segurium_File_State::get_total( false, Segurium_File_State::FILTER_MALICIOUS );
		$items = array();

		if ( $total > 0 ) {
			$rows = Segurium_File_State::get_page( 1, self::MAX_ITEMS, false, Segurium_File_State::FILTER_MALICIOUS );
			foreach ( $rows as $row ) {
				$items[] = array(
					'path'        => self::relative_path( $row['path'] ),
					'sha256'      => (string) $row['sha256'],
					'verdict'     => (int) $row['verdict'],
					'detected_at' => (int) $row['timestamp'],
				);
			}
		}

		return array(
			'open_total' => (int) $total,
			'truncated'  => count( $items ) < (int) $total,
			'items'      => $items,
		);
	}

	/**
	 * Open integrity findings, capped.
	 *
	 * @return array
	 */
	private static function integrity_findings() {
		$since = self::integrity_last_scan_at();
		if ( $since <= 0 ) {
			return array(
				'open_total' => 0,
				'truncated'  => false,
				'items'      => array(),
			);
		}

		// One decode of `integrity:comp_meta` for both queries.
		$inactive = Segurium_Integrity_Server_State::inactive_key_set();
		$total    = Segurium_Integrity_Server_State::count_open_issues( $since, $inactive );
		$items    = array();

		if ( $total > 0 ) {
			$rows = Segurium_Integrity_Server_State::list_open_issues( $since, self::MAX_ITEMS, $inactive );
			foreach ( $rows as $row ) {
				$items[] = array(
					'component'   => (string) $row['comp_slug'],
					'type'        => (string) $row['comp_type'],
					'path'        => self::relative_path( $row['file_path'] ),
					'detected_at' => (int) $row['created_at'],
				);
			}
		}

		return array(
			'open_total' => (int) $total,
			'truncated'  => count( $items ) < (int) $total,
			'items'      => $items,
		);
	}

	/**
	 * Strip the install root so the server's directory layout never
	 * travels to the dashboard.
	 *
	 * @param mixed $path Stored path.
	 * @return string
	 */
	private static function relative_path( $path ) {
		$path = (string) $path;
		$root = Segurium_Path_Helpers::wp_root();

		if ( '' !== $root && 0 === strncmp( $path, $root, strlen( $root ) ) ) {
			$path = substr( $path, strlen( $root ) );
		}

		return ltrim( $path, '/' );
	}

	// ---------------------------------------------------------------
	// quota
	// ---------------------------------------------------------------

	/**
	 * Free cleanup slots left in the current window.
	 *
	 * Reads the cached envelope rather than `Segurium_Quota::state()`:
	 * that method falls back to a blocking CTI round trip on a cold
	 * cache, which is the wrong thing to do while a dashboard waits.
	 * A site with no envelope yet says so instead of reporting zero left,
	 * and a Pro site reports `quota_known: 0` because the free counter
	 * does not apply to it.
	 *
	 * @param string $action Action name for the envelope.
	 * @return array
	 */
	private static function quota_reply( $action ) {
		if ( null === Segurium_Quota::cached_envelope() ) {
			return self::fail( $action, 'quota_unavailable' );
		}

		return self::ok( $action, self::quota_fields() );
	}

	// ---------------------------------------------------------------
	// scan_start (write)
	// ---------------------------------------------------------------

	/**
	 * Start a malware scan on this site.
	 *
	 * Nothing about the scan comes from the request: the engine is fixed
	 * and no path, type or option is read. A scan that could be pointed at
	 * a path would be a different feature with a different threat model.
	 *
	 * `Segurium_Scan_Runner::start()` already owns the lock, the
	 * installation-ID gate and the schema check, and it names each refusal
	 * with a code in the shape the dashboard renders. This is a thin
	 * adapter over it, not a second start path.
	 *
	 * @param string $action Action name for the envelope.
	 * @return array
	 */
	private static function scan_start_reply( $action ) {
		// The scanner talks to Cloud Threat Inspection for every file
		// verdict, so a site that has not accepted the disclosure cannot
		// scan. Refusing here rather than inside the runner keeps the
		// reason specific.
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return self::fail( $action, 'consent_required' );
		}

		// A held lock whose worker is dead still answers `is_running()` for
		// six hours by design. Saying `scan_already_running` there tells an
		// agency to wait for something that is never going to finish, so
		// the stalled case gets its own code and the fleet screen can say
		// to open the site.
		$live = Segurium_Scan_Runner::get_status();
		if ( null !== $live && ! empty( $live['running'] ) && empty( $live['worker_alive'] ) ) {
			return self::fail( $action, 'scan_stalled' );
		}

		if ( ! self::scan_interval_elapsed() ) {
			return self::fail( $action, 'scan_too_soon' );
		}

		$result = Segurium_Scan_Runner::start( 'manual' );

		if ( is_wp_error( $result ) ) {
			return self::fail( $action, self::error_code( $result ) );
		}

		Segurium_Storage::setting_set( self::OPT_LAST_SCAN_START, time() );

		return self::ok(
			$action,
			array(
				'scan_id' => (string) $result,
				'started' => 1,
			)
		);
	}

	/**
	 * Whether enough time has passed since the last fleet-started scan.
	 *
	 * The lock bounds concurrency, not rate: it refuses only while a scan
	 * runs. Without this a caller could re-issue `scan_start` the moment
	 * each scan reached a terminal state and keep a child site scanning —
	 * and paying for one cloud verdict lookup per file — around the clock.
	 * MainWP authenticates the caller, so this is not an attacker control;
	 * it is a brake on a dashboard, a retry loop or a cron that means well.
	 *
	 * Scans a site starts for itself are unaffected. Only this path is
	 * throttled, and only against its own last start.
	 *
	 * @return bool
	 */
	private static function scan_interval_elapsed() {
		$last = Segurium_Storage::setting_get_int( self::OPT_LAST_SCAN_START, 0 );

		return $last <= 0 || ( time() - $last ) >= self::MIN_SCAN_INTERVAL;
	}

	/**
	 * A WP_Error code the dashboard can render, or a named fallback.
	 *
	 * The runner's codes reach an admin screen on another site, so they
	 * pass the same shape check the dashboard applies rather than being
	 * forwarded on trust.
	 *
	 * @param WP_Error $error Error from the runner.
	 * @return string
	 */
	private static function error_code( WP_Error $error ) {
		$code = strtolower( (string) $error->get_error_code() );

		// An allow-list, not a shape check. These codes come from a
		// subsystem this class does not own and travel to an agency's
		// admin screen on another site, so a future runner code naming an
		// engine or a vendor would otherwise pass a charset test
		// untouched and break the rule about internal names on external
		// surfaces. Anything unrecognised is reported as a refusal
		// without borrowing its wording.
		$known = array(
			'scan_already_running',
			'no_iid',
			'schema_unavailable',
			'invalid_scan_type',
			'lock_write_failed',
			'scan_initialize_failed',
		);

		return in_array( $code, $known, true ) ? $code : 'scan_start_refused';
	}

	// ---------------------------------------------------------------
	// Envelopes
	// ---------------------------------------------------------------

	/**
	 * Successful reply.
	 *
	 * @param string $action Action name.
	 * @param array  $data   Payload.
	 * @return array
	 */
	private static function ok( $action, array $data ) {
		return array(
			'v'      => self::VERSION,
			'action' => $action,
			'ok'     => true,
			'data'   => $data,
		);
	}

	/**
	 * Refusal. Every caller passes a specific code — there is no branch
	 * that returns a generic failure, because the dashboard renders this
	 * code and "unknown error" tells an operator nothing.
	 *
	 * @param string $action Action name, empty when none was given.
	 * @param string $code   Reason code, `^[a-z0-9_]{1,64}$`.
	 * @return array
	 */
	private static function fail( $action, $code ) {
		return array(
			'v'      => self::VERSION,
			'action' => $action,
			'ok'     => false,
			'code'   => $code,
		);
	}
}

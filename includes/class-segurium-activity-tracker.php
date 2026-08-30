<?php
/**
 * User and component lifecycle telemetry.
 *
 * The daily component-inventory ping already tells CTI what is
 * installed here. What it cannot tell anyone is when a change
 * happened, who made it, or that anything happened at all between two
 * ticks: a plugin installed, activated, deactivated and deleted inside
 * one day reads as no change. User accounts were not reported at all.
 *
 * Hooks write rows into the local activity_log and never touch the
 * network. A store that registers five thousand customers in a day
 * costs five thousand row inserts and one HTTP request, not five
 * thousand requests fired from inside the signup path. The flush rides
 * the component-inventory cron rather than adding a scheduled event of
 * its own; privileged-user events also get an opportunistic admin-side
 * flush so a new administrator does not wait a day.
 *
 * An attacker holding a working administrator account trips none of
 * the account-lifecycle hooks. The login that used it, an email
 * address swapped onto it, a rewritten `siteurl` and a payload pasted
 * through the built-in file editor are recorded for that reason.
 * Logins are recorded for privileged accounts only: a store with five
 * thousand daily customer logins would otherwise bury the one that
 * matters.
 *
 * Privacy contract: a role, a numeric user id and a SHA-256 of the
 * login. The login itself, the display name and the email address
 * never leave the site, which is the rule the brute-force payloads
 * already follow. An email change therefore travels as two hashes.
 * Site identity is added at the envelope layer by
 * Segurium_CTI_Client::send_message.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Collector + batching reporter for site activity.
 */
final class Segurium_Activity_Tracker {

	const MSG_ACTIVITY = 'site_activity';
	const MSG_CENSUS   = 'user_census';

	/**
	 * The component-inventory cron's hook, shared on purpose: this
	 * feature adds no scheduled event of its own. Spelled out rather
	 * than read off Segurium_Integrity_Inventory_Cron because the
	 * tracker also registers on the light tiers, where that class is
	 * not loaded. The two are pinned together by a test.
	 */
	const FLUSH_HOOK = 'segurium_daily_components_snapshot';

	/**
	 * Events carried by one flush. Beyond this the batch reports the
	 * shortfall as `dropped` rather than growing without bound or
	 * building a backlog a daily flush can never clear.
	 */
	const MAX_EVENTS_PER_BATCH = 200;

	/** Detail rows in one census; beyond this only counts travel. */
	const MAX_PRIVILEGED_ROWS = 100;

	/**
	 * An account that can change the site appearing, vanishing or being
	 * promoted. Sorted to the front of a batch and eligible for the
	 * admin-side flush, so a signup storm cannot bury it and it does not
	 * wait for the daily tick.
	 */
	const SEVERITY_ESCALATION = 2;

	/** Worth keeping, not worth interrupting the daily cadence for. */
	const SEVERITY_NOTABLE = 1;

	/**
	 * Options that change what the site is rather than how it looks,
	 * mapped to the severity a change earns. A rewritten `siteurl`
	 * sends every visitor somewhere else while every file on disk
	 * still matches its checksum; open registration with an
	 * administrator default role is a backdoor with no file behind it.
	 */
	const WATCHED_OPTIONS = array(
		'siteurl'            => self::SEVERITY_ESCALATION,
		'home'               => self::SEVERITY_ESCALATION,
		'users_can_register' => self::SEVERITY_NOTABLE,
		'default_role'       => self::SEVERITY_NOTABLE,
	);

	const OPT_LAST_FLUSHED_ID = 'segurium_activity_last_id';
	const OPT_CENSUS_HASH     = 'segurium_activity_census_hash';
	const OPT_CENSUS_SENT_AT  = 'segurium_activity_census_at';

	const TRANSIENT_FLUSH_LOCK = 'segurium_activity_flush_lock';

	/**
	 * Set when a severity-2 row lands, read on every admin request.
	 * Without it the admin_init hook would run a COUNT over activity_log
	 * on every wp-admin pageload of every install, since the throttle
	 * lock is only set once a flush has actually happened. Expiry is a
	 * backstop; the daily flush covers anything this drops.
	 */
	const TRANSIENT_ESCALATION_ARMED = 'segurium_activity_esc_armed';

	const FLUSH_LOCK_SECONDS = 5 * MINUTE_IN_SECONDS;

	/** Back-off after a send that did not leave, so a blip costs 30s not 5min. */
	const FLUSH_RETRY_SECONDS  = 30;
	const CENSUS_STALE_SECONDS = 7 * DAY_IN_SECONDS;

	/**
	 * Capabilities that make an account worth a detail row. Roles are
	 * site-defined, so the census asks what an account can do rather
	 * than what it is called.
	 */
	const PRIVILEGED_CAPS = array( 'manage_options', 'edit_plugins', 'edit_others_posts' );

	/**
	 * Wire the listeners. Called from Segurium::register_hooks() on the
	 * heavy tiers and from segurium_lightweight_bootstrap() elsewhere,
	 * because user registration runs on the front end and component
	 * changes run on admin screens that carry no `page=segurium`.
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( 'user_register', array( __CLASS__, 'on_user_registered' ), 10, 1 );
		add_action( 'deleted_user', array( __CLASS__, 'on_user_deleted' ), 10, 3 );
		add_action( 'set_user_role', array( __CLASS__, 'on_user_role_set' ), 10, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'on_user_role_added' ), 10, 2 );
		add_action( 'profile_update', array( __CLASS__, 'on_profile_updated' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'on_user_login' ), 10, 2 );

		foreach ( array_keys( self::WATCHED_OPTIONS ) as $watched_option ) {
			add_action( 'update_option_' . $watched_option, array( __CLASS__, 'on_watched_option_changed' ), 10, 3 );
			add_action( 'add_option_' . $watched_option, array( __CLASS__, 'on_watched_option_added' ), 10, 2 );
		}

		// Core writes the file and returns, firing no action of its own,
		// so the request that carries the edit is the only place the write
		// can be seen from. admin_init covers all three entry points that
		// reach wp_edit_theme_plugin_file() — the ajax action the editor
		// uses and the two editor screens' no-JavaScript fallback — and on
		// every one of them it runs before the write.
		add_action( 'admin_init', array( __CLASS__, 'on_file_editor_save' ) );

		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin_activated' ), 10, 1 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_deactivated' ), 10, 1 );
		add_action( 'deleted_plugin', array( __CLASS__, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrader_complete' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'on_theme_switched' ), 10, 2 );

		add_action( self::FLUSH_HOOK, array( __CLASS__, 'run_scheduled_flush' ), 20 );
		add_action( 'admin_init', array( __CLASS__, 'maybe_flush_escalation' ) );
	}

	/**
	 * Drop per-request state and the reporter's stored progress.
	 *
	 * @return void
	 */
	public static function reset_for_tests(): void {
		Segurium_Storage::setting_delete( self::OPT_LAST_FLUSHED_ID );
		Segurium_Storage::setting_delete( self::OPT_CENSUS_HASH );
		Segurium_Storage::setting_delete( self::OPT_CENSUS_SENT_AT );
		delete_transient( self::TRANSIENT_FLUSH_LOCK );
		delete_transient( self::TRANSIENT_ESCALATION_ARMED );
	}

	// ---------------------------------------------------------------
	// Collection. Nothing below this line makes a network call.
	// ---------------------------------------------------------------

	/**
	 * Record a new account.
	 *
	 * @param int $user_id Newly created user.
	 * @return void
	 */
	public static function on_user_registered( $user_id ): void {
		$user = get_userdata( (int) $user_id );
		if ( ! $user instanceof WP_User ) {
			return;
		}
		$role = self::primary_role( $user );
		self::record(
			'user_created',
			self::is_privileged_role( $role ) ? self::SEVERITY_ESCALATION : 0,
			self::login_hash( $user->user_login ),
			array(
				'uhash' => self::login_hash( $user->user_login ),
				'role'  => $role,
			)
		);
	}

	/**
	 * Record a removed account.
	 *
	 * @param int      $user_id  Deleted user id.
	 * @param int|null $reassign Reassignment target, unused.
	 * @param WP_User  $user     The user as it was before deletion.
	 * @return void
	 */
	public static function on_user_deleted( $user_id, $reassign, $user = null ): void {
		if ( ! $user instanceof WP_User ) {
			return;
		}
		$role = self::primary_role( $user );
		self::record(
			'user_deleted',
			self::is_privileged_role( $role ) ? self::SEVERITY_ESCALATION : 0,
			self::login_hash( $user->user_login ),
			array(
				'uhash' => self::login_hash( $user->user_login ),
				'role'  => $role,
			)
		);
	}

	/**
	 * Record a role change on an existing account.
	 *
	 * @param int                $user_id   Affected user.
	 * @param string             $role      Role now held.
	 * @param array<int, string> $old_roles Roles held before.
	 * @return void
	 */
	public static function on_user_role_set( $user_id, $role, $old_roles = array() ): void {
		// `wp_insert_user` sets the role before it fires `user_register`,
		// so every registration passes through here first. A brand-new
		// account arrives with no previous role, and a privilege
		// escalation always has one, which is the difference this reads.
		if ( ! is_array( $old_roles ) || empty( $old_roles ) ) {
			return;
		}

		$user = get_userdata( (int) $user_id );
		if ( ! $user instanceof WP_User ) {
			return;
		}

		$was = (string) reset( $old_roles );
		if ( $was === (string) $role ) {
			return;
		}

		self::record(
			'user_role_changed',
			self::is_privileged_role( (string) $role ) ? self::SEVERITY_ESCALATION : 0,
			self::login_hash( $user->user_login ),
			array(
				'uhash'     => self::login_hash( $user->user_login ),
				'role'      => (string) $role,
				'from_role' => $was,
			)
		);
	}

	/**
	 * Record a role granted alongside the ones an account already has.
	 * `set_user_role` replaces the role set and `add_user_role` appends
	 * to it, so an account handed administrator on top of subscriber
	 * passes only through here.
	 *
	 * @param int    $user_id Affected user.
	 * @param string $role    Role granted.
	 * @return void
	 */
	public static function on_user_role_added( $user_id, $role ): void {
		$user = get_userdata( (int) $user_id );
		if ( ! $user instanceof WP_User ) {
			return;
		}

		// set_role() fires this hook too, immediately before set_user_role
		// and having already emptied the previous role set. That case
		// belongs to on_user_role_set, and recording it here would double
		// every role change, registrations included. An appended role is
		// the one that leaves the account holding more than one.
		if ( count( (array) $user->roles ) < 2 ) {
			return;
		}

		self::record(
			'user_role_added',
			self::is_privileged_role( (string) $role ) ? self::SEVERITY_ESCALATION : 0,
			self::login_hash( $user->user_login ),
			array(
				'uhash' => self::login_hash( $user->user_login ),
				'role'  => (string) $role,
			)
		);
	}

	/**
	 * Record an email address moving on an existing account, which is
	 * how a stolen account survives the password reset that follows.
	 * Every profile save fires this hook, so a display-name edit must
	 * cost nothing.
	 *
	 * @param int     $user_id       Affected user.
	 * @param WP_User $old_user_data The account before the save.
	 * @return void
	 */
	public static function on_profile_updated( $user_id, $old_user_data = null ): void {
		if ( ! $old_user_data instanceof WP_User ) {
			return;
		}

		$user = get_userdata( (int) $user_id );
		if ( ! $user instanceof WP_User ) {
			return;
		}

		$was = (string) $old_user_data->user_email;
		$now = (string) $user->user_email;
		if ( '' === $now || $was === $now ) {
			return;
		}

		$role = self::primary_role( $user );
		self::record(
			'user_email_changed',
			self::is_privileged_user( $user ) ? self::SEVERITY_ESCALATION : 0,
			self::login_hash( $user->user_login ),
			array(
				'uhash'    => self::login_hash( $user->user_login ),
				'role'     => $role,
				'emh'      => self::opaque( $now ),
				'from_emh' => self::opaque( $was ),
			)
		);
	}

	/**
	 * Record a successful login by an account that can change the
	 * site. Subscribers are skipped: the row would carry no security
	 * signal and a busy store would push everything else out of the
	 * batch and past the prune cutoff.
	 *
	 * The actor is passed explicitly because `wp_login` fires before
	 * the current user is established for the request.
	 *
	 * @param string  $login Username that authenticated.
	 * @param WP_User $user  The authenticated account.
	 * @return void
	 */
	public static function on_user_login( $login, $user = null ): void {
		if ( ! $user instanceof WP_User ) {
			$user = get_user_by( 'login', (string) $login );
		}
		if ( ! $user instanceof WP_User ) {
			return;
		}

		if ( ! self::is_privileged_user( $user ) ) {
			return;
		}

		$role = self::primary_role( $user );
		self::record(
			'user_login',
			self::SEVERITY_NOTABLE,
			self::login_hash( $user->user_login ),
			array(
				'uhash' => self::login_hash( $user->user_login ),
				'role'  => $role,
			),
			(int) $user->ID
		);
	}

	/**
	 * Record a change to one of the options on the watch list.
	 *
	 * @param mixed  $old_value Value before the write.
	 * @param mixed  $value     Value after it.
	 * @param string $option    Option name.
	 * @return void
	 */
	public static function on_watched_option_changed( $old_value, $value, $option = '' ): void {
		$option = (string) $option;
		if ( ! isset( self::WATCHED_OPTIONS[ $option ] ) ) {
			return;
		}

		self::record(
			'site_option_changed',
			self::WATCHED_OPTIONS[ $option ],
			$option,
			array(
				'opt'  => $option,
				'from' => self::option_scalar( $old_value ),
				'to'   => self::option_scalar( $value ),
			)
		);
	}

	/**
	 * Record a watched option being created rather than updated.
	 * `delete_option()` then `add_option()` reaches the same end state
	 * as an update and fires a different hook, so watching only the
	 * update leaves a way round the list.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Value written.
	 * @return void
	 */
	public static function on_watched_option_added( $option, $value ): void {
		self::on_watched_option_changed( null, $value, $option );
	}

	/**
	 * Record an edit submitted through the built-in plugin or theme
	 * editor, which writes PHP straight into the tree.
	 *
	 * Runs on every admin request, so the field test comes first and
	 * costs two isset() calls on everything else. The nonce and
	 * capability are checked here rather than trusted from upstream:
	 * this runs ahead of core, which validates the same pair and then
	 * writes without firing anything. Checking both keeps a rejected
	 * request out of the log and stops an unprivileged POST from
	 * forging entries.
	 *
	 * @return void
	 */
	public static function on_file_editor_save(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- the nonce these reads carry is verified below, against the same action core uses.
		if ( ! isset( $_POST['newcontent'], $_POST['file'], $_POST['nonce'] ) ) {
			return;
		}

		$nonce = sanitize_text_field( wp_unslash( $_POST['nonce'] ) );
		$file  = sanitize_text_field( wp_unslash( $_POST['file'] ) );
		if ( '' === $nonce || '' === $file || 0 !== validate_file( $file ) ) {
			return;
		}

		$plugin = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : '';
		$theme  = isset( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( $_POST['theme'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' !== $plugin ) {
			if ( ! current_user_can( 'edit_plugins' ) || ! wp_verify_nonce( $nonce, 'edit-plugin_' . $file ) ) {
				return;
			}
			self::record_file_edit( 'plugin', $plugin, $file );

			return;
		}

		if ( '' !== $theme ) {
			if ( ! current_user_can( 'edit_themes' ) || ! wp_verify_nonce( $nonce, 'edit-theme_' . $theme . '_' . $file ) ) {
				return;
			}
			self::record_file_edit( 'theme', $theme, $file );
		}
	}

	/**
	 * Record a plugin activation.
	 *
	 * @param string $plugin Plugin file relative to the plugins dir.
	 * @return void
	 */
	public static function on_plugin_activated( $plugin ): void {
		self::record_component( 'component_activated', 'plugin', (string) $plugin );
	}

	/**
	 * Record a plugin deactivation.
	 *
	 * @param string $plugin Plugin file relative to the plugins dir.
	 * @return void
	 */
	public static function on_plugin_deactivated( $plugin ): void {
		self::record_component( 'component_deactivated', 'plugin', (string) $plugin );
	}

	/**
	 * Record a plugin deletion.
	 *
	 * @param string $plugin_file Plugin file relative to the plugins dir.
	 * @param bool   $deleted     Whether the delete succeeded.
	 * @return void
	 */
	public static function on_plugin_deleted( $plugin_file, $deleted = true ): void {
		if ( ! $deleted ) {
			return;
		}
		self::record_component( 'component_deleted', 'plugin', (string) $plugin_file );
	}

	/**
	 * Install and update both arrive here; core's updater has no
	 * dedicated per-component hook for either.
	 *
	 * @param mixed                $upgrader Upgrader instance, unused.
	 * @param array<string, mixed> $options  Upgrade context.
	 * @return void
	 */
	public static function on_upgrader_complete( $upgrader, $options = array() ): void {
		$action = (string) ( $options['action'] ?? '' );
		$type   = (string) ( $options['type'] ?? '' );
		if ( 'install' !== $action && 'update' !== $action ) {
			return;
		}

		$event = 'install' === $action ? 'component_installed' : 'component_updated';

		if ( 'plugin' === $type ) {
			$targets = array();
			if ( isset( $options['plugins'] ) && is_array( $options['plugins'] ) ) {
				$targets = $options['plugins'];
			} elseif ( isset( $options['plugin'] ) ) {
				$targets = array( $options['plugin'] );
			} elseif ( is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) ) {
				// An install passes only type and action in hook_extra —
				// core names the component nowhere in it. The upgrader
				// resolves it from what actually landed on disk.
				$info    = $upgrader->plugin_info();
				$targets = $info ? array( $info ) : array();
			}
			foreach ( $targets as $plugin ) {
				self::record_component( $event, 'plugin', (string) $plugin );
			}
			return;
		}

		if ( 'theme' === $type ) {
			$targets = array();
			if ( isset( $options['themes'] ) && is_array( $options['themes'] ) ) {
				$targets = $options['themes'];
			} elseif ( isset( $options['theme'] ) ) {
				$targets = array( $options['theme'] );
			} elseif ( is_object( $upgrader ) && method_exists( $upgrader, 'theme_info' ) ) {
				$info    = $upgrader->theme_info();
				$targets = $info instanceof WP_Theme ? array( $info->get_stylesheet() ) : array();
			}
			foreach ( $targets as $theme ) {
				self::record_component( $event, 'theme', (string) $theme );
			}
			return;
		}

		if ( 'core' === $type ) {
			self::record_component( $event, 'core', 'WordPress' );
		}
	}

	/**
	 * Record a theme switch.
	 *
	 * @param string        $new_name  New theme name, unused.
	 * @param WP_Theme|null $new_theme New theme.
	 * @return void
	 */
	public static function on_theme_switched( $new_name, $new_theme = null ): void {
		$slug = $new_theme instanceof WP_Theme ? (string) $new_theme->get_stylesheet() : '';
		if ( '' === $slug ) {
			return;
		}
		self::record_component( 'component_activated', 'theme', $slug );
	}

	// ---------------------------------------------------------------
	// Reporting.
	// ---------------------------------------------------------------

	/**
	 * Cron handler on the component-inventory job.
	 *
	 * @return void
	 */
	public static function run_scheduled_flush(): void {
		try {
			// Same lock the admin path takes. Without it a cron tick
			// overlapping an admin flush reads the same high-water mark
			// and ships the same rows twice.
			if ( self::acquire_flush_lock() ) {
				self::flush_locked();
			}
			self::send_census();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-activity] scheduled flush failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Take the flush mutex.
	 *
	 * @return bool False when another flush holds it.
	 */
	private static function acquire_flush_lock(): bool {
		if ( get_transient( self::TRANSIENT_FLUSH_LOCK ) ) {
			return false;
		}
		set_transient( self::TRANSIENT_FLUSH_LOCK, 1, self::FLUSH_LOCK_SECONDS );

		return true;
	}

	/**
	 * Flush, then shorten the lock if nothing left the site.
	 *
	 * A failed send must not hold the full window: the next admin request
	 * should get another go rather than waiting on the daily tick.
	 *
	 * @return bool
	 */
	private static function flush_locked(): bool {
		$sent = self::flush();
		if ( ! $sent ) {
			set_transient( self::TRANSIENT_FLUSH_LOCK, 1, self::FLUSH_RETRY_SECONDS );
		}

		return $sent;
	}

	/**
	 * Admin-side catch-up for events that should not wait for the
	 * daily tick. Creating an administrator is itself an admin-context
	 * action, so the next admin request is usually the very next thing
	 * that happens; this also covers hosts running with WP-Cron off.
	 *
	 * @return void
	 */
	public static function maybe_flush_escalation(): void {
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}
		// Two cheap reads before anything touches a table: the marker is
		// absent on an install where no privileged event ever fired,
		// which is the overwhelming majority of admin requests.
		if ( ! get_transient( self::TRANSIENT_ESCALATION_ARMED ) ) {
			return;
		}
		if ( ! self::acquire_flush_lock() ) {
			return;
		}

		if ( ! self::has_pending_escalation() ) {
			delete_transient( self::TRANSIENT_ESCALATION_ARMED );

			return;
		}

		try {
			if ( self::flush_locked() ) {
				delete_transient( self::TRANSIENT_ESCALATION_ARMED );
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-activity] escalation flush failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Ship every buffered event since the last flush.
	 *
	 * Higher severity travels first, so a signup storm cannot push the
	 * one new administrator or the one plugin install out of the batch.
	 *
	 * @return bool True when a batch left the site.
	 */
	public static function flush(): bool {
		if ( ! self::can_send() ) {
			return false;
		}

		$since = Segurium_Storage::setting_get_int( self::OPT_LAST_FLUSHED_ID );

		// One upper bound for all three reads. Measuring the count and the
		// high-water mark at different instants let a row inserted between
		// them be swept past without being counted as dropped.
		$newest = self::newest_pending_id( $since );
		if ( $newest <= $since ) {
			return false;
		}

		$pending = self::pending_count( $since, $newest );
		if ( 0 === $pending ) {
			return false;
		}

		$rows = Segurium_Storage::table_get_results(
			'activity_log',
			'SELECT id, event_type, severity, actor_user, data_json, created_at
			   FROM {{table}}
			  WHERE id > %d AND id <= %d AND ' . self::event_like_sql() . '
			  ORDER BY severity DESC, id ASC
			  LIMIT %d',
			array_merge( array( $since, $newest ), self::event_like_patterns(), array( self::MAX_EVENTS_PER_BATCH ) ),
			ARRAY_A
		);
		if ( empty( $rows ) ) {
			return false;
		}

		$events = array();
		foreach ( $rows as $row ) {
			$events[] = self::event_from_row( $row );
		}

		$sent = Segurium_Storage::cti_send_message(
			self::MSG_ACTIVITY,
			array(
				'events'  => $events,
				'dropped' => max( 0, $pending - count( $events ) ),
			)
		);

		// The mark advances past the whole window, discarded tail
		// included, so a busy site never builds a backlog the daily flush
		// could not clear. Note what $sent means: the transport is
		// non-blocking, so this is "the request was dispatched", not "CTI
		// received it". There is no acknowledgement to wait for and no
		// redelivery; a batch lost in flight is lost.
		if ( $sent ) {
			Segurium_Storage::setting_set( self::OPT_LAST_FLUSHED_ID, $newest );
		}

		return (bool) $sent;
	}

	/**
	 * Ship the account baseline. Change-detected, so an install whose
	 * user list is stable sends one census a week rather than seven.
	 *
	 * @return bool True when a census left the site.
	 */
	public static function send_census(): bool {
		if ( ! self::can_send() ) {
			return false;
		}

		$payload = self::census_payload();
		$hash    = substr( md5( (string) wp_json_encode( $payload ) ), 0, 32 );
		$last    = Segurium_Storage::setting_get_int( self::OPT_CENSUS_SENT_AT );
		$stale   = ( time() - $last ) > self::CENSUS_STALE_SECONDS;

		if ( Segurium_Storage::setting_get_string( self::OPT_CENSUS_HASH ) === $hash && ! $stale ) {
			return false;
		}

		$sent = Segurium_Storage::cti_send_message( self::MSG_CENSUS, $payload );
		if ( $sent ) {
			Segurium_Storage::setting_set( self::OPT_CENSUS_HASH, $hash );
			Segurium_Storage::setting_set( self::OPT_CENSUS_SENT_AT, time() );
		}

		return (bool) $sent;
	}

	// ---------------------------------------------------------------
	// Internals.
	// ---------------------------------------------------------------

	/**
	 * Write one row to the local buffer.
	 *
	 * @param string               $event_type Event vocabulary entry.
	 * @param int                  $severity   2 = escalation-worthy.
	 * @param string               $subject    Slug or login hash.
	 * @param array<string, mixed> $data       Event detail.
	 * @param int|null             $actor      Override for hooks that fire
	 *                                         before the current user is set.
	 * @return void
	 */
	private static function record( string $event_type, int $severity, string $subject, array $data, ?int $actor = null ): void {
		if ( null === $actor ) {
			$actor = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		}

		$data['actor_role'] = self::actor_role( $actor );

		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => $event_type,
					'severity'   => $severity,
					'actor_ip'   => self::actor_ip(),
					'actor_user' => $actor > 0 ? $actor : null,
					'subject'    => substr( $subject, 0, 191 ),
					'data_json'  => (string) wp_json_encode( $data ),
					'created_at' => time(),
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-activity] activity_log insert failed: ' . $e->getMessage() );

			return;
		}

		if ( self::SEVERITY_ESCALATION === $severity ) {
			set_transient( self::TRANSIENT_ESCALATION_ARMED, 1, DAY_IN_SECONDS );
		}
	}

	/**
	 * Buffer one component event.
	 *
	 * @param string $event_type Event vocabulary entry.
	 * @param string $type       plugin|theme|core.
	 * @param string $file       Plugin file, theme stylesheet or 'WordPress'.
	 * @return void
	 */
	private static function record_component( string $event_type, string $type, string $file ): void {
		$slug = self::component_slug( $type, $file );
		if ( '' === $slug ) {
			return;
		}

		self::record(
			$event_type,
			self::SEVERITY_NOTABLE,
			$slug,
			array(
				'ct'   => $type,
				'slug' => $slug,
				'ver'  => self::component_version( $type, $file ),
			)
		);
	}

	/**
	 * LIKE patterns matching the event families this feature owns.
	 *
	 * @return array<int, string>
	 */
	private static function event_like_patterns(): array {
		global $wpdb;

		return array(
			$wpdb->esc_like( 'user_' ) . '%',
			$wpdb->esc_like( 'component_' ) . '%',
			$wpdb->esc_like( 'site_' ) . '%',
		);
	}

	/**
	 * The matching WHERE fragment, built from the pattern list so a new
	 * family cannot be added to one and forgotten in the other. A
	 * mismatch leaves the family's rows unreported and, once the prune
	 * cutoff passes, gone.
	 *
	 * @return string
	 */
	private static function event_like_sql(): string {
		return '( ' . implode(
			' OR ',
			array_fill( 0, count( self::event_like_patterns() ), 'event_type LIKE %s' )
		) . ' )';
	}

	/**
	 * Turn a buffered row into a wire event.
	 *
	 * @param array<string, mixed> $row activity_log row.
	 * @return array<string, mixed>
	 */
	private static function event_from_row( array $row ): array {
		$data = json_decode( (string) $row['data_json'], true );
		$data = is_array( $data ) ? $data : array();

		$event = array(
			't'          => (int) $row['created_at'],
			'type'       => (string) $row['event_type'],
			'actor'      => (int) $row['actor_user'],
			'actor_role' => (string) ( $data['actor_role'] ?? '' ),
		);

		foreach ( array( 'ct', 'slug', 'ver', 'file', 'uhash', 'role', 'from_role', 'emh', 'from_emh', 'opt', 'from', 'to' ) as $key ) {
			if ( isset( $data[ $key ] ) && '' !== $data[ $key ] ) {
				$event[ $key ] = (string) $data[ $key ];
			}
		}

		return $event;
	}

	/**
	 * Count events waiting to be reported.
	 *
	 * @param int $since Highest already-flushed row id.
	 * @param int $upto  Inclusive upper bound for this batch.
	 * @return int
	 */
	private static function pending_count( int $since, int $upto ): int {
		return (int) Segurium_Storage::table_get_var(
			'activity_log',
			'SELECT COUNT(*) FROM {{table}}
			  WHERE id > %d AND id <= %d AND ' . self::event_like_sql(),
			array_merge( array( $since, $upto ), self::event_like_patterns() )
		);
	}

	/**
	 * Highest row id among the waiting events.
	 *
	 * @param int $since Highest already-flushed row id.
	 * @return int
	 */
	private static function newest_pending_id( int $since ): int {
		// No placeholder may precede {{table}}: the query runner prepends
		// the table name to the argument list, so it binds to whichever
		// placeholder comes first. A COALESCE default in front of the FROM
		// clause fed the table name to %d and the row id to %i, and
		// with_suppressed_errors() turned the failure into a silent 0.
		// MAX() over no rows is NULL, which casts to the same 0 anyway.
		return (int) Segurium_Storage::table_get_var(
			'activity_log',
			'SELECT MAX(id) FROM {{table}}
			  WHERE id > %d AND ' . self::event_like_sql(),
			array_merge( array( $since ), self::event_like_patterns() )
		);
	}

	/**
	 * Whether a privileged-account event is waiting.
	 *
	 * @return bool
	 */
	private static function has_pending_escalation(): bool {
		$since = Segurium_Storage::setting_get_int( self::OPT_LAST_FLUSHED_ID );

		return (int) Segurium_Storage::table_get_var(
			'activity_log',
			'SELECT COUNT(*) FROM {{table}}
			  WHERE id > %d AND severity >= %d AND ' . self::event_like_sql(),
			array_merge( array( $since, self::SEVERITY_ESCALATION ), self::event_like_patterns() )
		) > 0;
	}

	/**
	 * Build the census body.
	 *
	 * @return array<string, mixed>
	 */
	private static function census_payload(): array {
		$counts  = function_exists( 'count_users' ) ? count_users() : array();
		$by_role = array();
		foreach ( (array) ( $counts['avail_roles'] ?? array() ) as $role => $n ) {
			if ( (int) $n > 0 ) {
				$by_role[ (string) $role ] = (int) $n;
			}
		}

		// count_users() groups without an ORDER BY, and privileged_rows()
		// walks capabilities in whatever order get_users() answers. Both
		// feed the change-detection hash, so an unsorted payload would
		// re-send a census that had not changed.
		ksort( $by_role );

		$privileged = self::privileged_rows();
		usort(
			$privileged,
			static function ( $a, $b ) {
				return $a['uid'] <=> $b['uid'];
			}
		);

		return array(
			'total'      => (int) ( $counts['total_users'] ?? 0 ),
			'by_role'    => $by_role,
			'privileged' => $privileged,
		);
	}

	/**
	 * Detail rows for accounts that can change the site. Everyone else
	 * is a count, which is what keeps a 50k-customer store's census
	 * small.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	private static function privileged_rows(): array {
		$rows = array();
		$seen = array();

		foreach ( self::PRIVILEGED_CAPS as $cap ) {
			$users = get_users(
				array(
					'capability' => $cap,
					'fields'     => array( 'ID', 'user_login', 'user_registered' ),
					'number'     => self::MAX_PRIVILEGED_ROWS,
				)
			);

			foreach ( $users as $user ) {
				$uid = (int) $user->ID;
				if ( isset( $seen[ $uid ] ) ) {
					continue;
				}
				$seen[ $uid ] = true;

				$full   = get_userdata( $uid );
				$rows[] = array(
					'uid'        => $uid,
					'uhash'      => self::login_hash( (string) $user->user_login ),
					'role'       => $full instanceof WP_User ? self::primary_role( $full ) : '',
					'registered' => strtotime( (string) $user->user_registered ),
				);

				if ( count( $rows ) >= self::MAX_PRIVILEGED_ROWS ) {
					return $rows;
				}
			}
		}

		return $rows;
	}

	/**
	 * Whether telemetry may leave this install.
	 *
	 * @return bool
	 */
	private static function can_send(): bool {
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return false;
		}

		return null !== Segurium_IID::get_iid();
	}

	/**
	 * Hash a login for the wire.
	 *
	 * @param string $login WordPress login.
	 * @return string
	 */
	private static function login_hash( string $login ): string {
		return self::opaque( $login );
	}

	/**
	 * Hash a value that must not leave the site in the clear.
	 *
	 * @param string $value Login or email address.
	 * @return string
	 */
	private static function opaque( string $value ): string {
		return '' === $value ? '' : hash( 'sha256', $value );
	}

	/**
	 * Flatten an option value for the log. Anything that is not a
	 * scalar is recorded as the fact that it changed and nothing more;
	 * the watch list holds no arrays today.
	 *
	 * @param mixed $value Option value.
	 * @return string
	 */
	private static function option_scalar( $value ): string {
		if ( is_bool( $value ) ) {
			return $value ? '1' : '0';
		}

		return is_scalar( $value ) ? substr( (string) $value, 0, 191 ) : '';
	}

	/**
	 * The address the current request came from, packed for storage.
	 * Prefers the geo blocker's resolver, which unwraps the proxy
	 * headers this install trusts, and falls back to REMOTE_ADDR on
	 * the light bootstrap tiers where that class is not loaded.
	 *
	 * @return string|null
	 */
	private static function actor_ip(): ?string {
		$ip = '';

		if ( class_exists( 'Segurium_Geo_Blocker' ) ) {
			$resolved = Segurium_Geo_Blocker::get_instance()->get_real_ip();
			$ip       = is_string( $resolved ) ? $resolved : '';
		}

		if ( '' === $ip && isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		return '' === $ip ? null : Segurium_IP::pack( $ip );
	}

	/**
	 * Record an edit through the built-in file editor.
	 *
	 * @param string $type      plugin|theme.
	 * @param string $component Plugin file or theme stylesheet.
	 * @param string $file      Path edited, relative to the component.
	 * @return void
	 */
	private static function record_file_edit( string $type, string $component, string $file ): void {
		$slug = self::component_slug( $type, $component );
		if ( '' === $slug ) {
			return;
		}

		self::record(
			'component_file_edited',
			self::SEVERITY_ESCALATION,
			$slug,
			array(
				'ct'   => $type,
				'slug' => $slug,
				'file' => substr( $file, 0, 191 ),
			)
		);
	}

	/**
	 * The account's first role.
	 *
	 * @param WP_User $user User.
	 * @return string
	 */
	private static function primary_role( WP_User $user ): string {
		$roles = (array) $user->roles;

		return empty( $roles ) ? '' : (string) reset( $roles );
	}

	/**
	 * The acting account's first role.
	 *
	 * @param int $user_id Actor.
	 * @return string
	 */
	private static function actor_role( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}
		$user = get_userdata( $user_id );

		return $user instanceof WP_User ? self::primary_role( $user ) : '';
	}

	/**
	 * Whether an account can change the site. Asks what it can do
	 * rather than what its first role happens to be called: an
	 * administrator role appended to a subscriber leaves `subscriber`
	 * in front, and that is the exact shape on_user_role_added exists
	 * to catch. Matches how the census picks its detail rows.
	 *
	 * @param WP_User $user Account.
	 * @return bool
	 */
	private static function is_privileged_user( WP_User $user ): bool {
		foreach ( self::PRIVILEGED_CAPS as $cap ) {
			if ( user_can( $user, $cap ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a role can change the site.
	 *
	 * @param string $role Role name.
	 * @return bool
	 */
	private static function is_privileged_role( string $role ): bool {
		if ( '' === $role ) {
			return false;
		}
		$role_object = function_exists( 'get_role' ) ? get_role( $role ) : null;
		if ( ! $role_object ) {
			return false;
		}
		foreach ( self::PRIVILEGED_CAPS as $cap ) {
			if ( ! empty( $role_object->capabilities[ $cap ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Slug for a component event.
	 *
	 * @param string $type plugin|theme|core.
	 * @param string $file Plugin file, theme stylesheet or 'WordPress'.
	 * @return string
	 */
	private static function component_slug( string $type, string $file ): string {
		if ( 'core' === $type ) {
			return 'WordPress';
		}
		if ( 'theme' === $type ) {
			return $file;
		}

		$dir = dirname( $file );

		return ( '.' === $dir || '' === $dir ) ? basename( $file, '.php' ) : $dir;
	}

	/**
	 * Version lookup is best-effort: component events fire on admin
	 * screens where core's plugin API is loaded, but the tracker also
	 * runs on tiers where it is not.
	 *
	 * @param string $type plugin|theme|core.
	 * @param string $file Plugin file, theme stylesheet or 'WordPress'.
	 * @return string
	 */
	private static function component_version( string $type, string $file ): string {
		if ( 'core' === $type ) {
			global $wp_version;

			return (string) $wp_version;
		}

		if ( 'theme' === $type ) {
			if ( ! function_exists( 'wp_get_theme' ) ) {
				return '';
			}
			$theme = wp_get_theme( $file );

			return $theme->exists() ? (string) $theme->get( 'Version' ) : '';
		}

		// get_plugins() keyed by the same plugin file the hook hands us,
		// so the version comes back without this code composing a path
		// out of WP_PLUGIN_DIR. A deleted plugin is simply absent.
		if ( ! function_exists( 'get_plugins' ) ) {
			return '';
		}
		$installed = get_plugins();

		return (string) ( $installed[ $file ]['Version'] ?? '' );
	}
}

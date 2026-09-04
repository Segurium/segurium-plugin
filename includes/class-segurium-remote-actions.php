<?php
/**
 * CTI → plugin action channel.
 *
 * CTI addresses a site by IID and hands it a short, closed-grammar
 * instruction. The only instruction in this release is "update this
 * component", named by type + slug.
 *
 * The design assumes CTI is fully compromised. An attacker who owns CTI
 * holds the Ed25519 signing seed and can write any row into the message
 * table, so signature verification protects only against a network
 * attacker. The control that carries the weight is the message grammar:
 *
 *   - A message names a component. It never carries a URL, a version, a
 *     package, a path, a callback, or code. {@see evaluate()} reads four
 *     fields and ignores everything else in the array.
 *   - The plugin resolves the package itself, through core's own updater
 *     against api.wordpress.org. Nothing is fetched from CTI or from a
 *     host CTI names.
 *   - An action is refused unless the slug is already installed here AND
 *     core already reports a pending update for it.
 *
 * The worst well-formed message a compromised CTI can emit therefore
 * makes sites install updates that wp.org already offers them.
 *
 * Decision and execution are deliberately separate. {@see evaluate()}
 * writes nothing and runs no upgrader, so every refusal path is cheap to
 * assert. {@see execute()} calls it first and stops on anything but OK.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validator, executor and audit log for CTI-addressed actions.
 */
class Segurium_Remote_Actions {

	const HOOK = 'segurium_actions_poll';

	const SETTING_CONSENT        = 'segurium_remote_actions_enabled';
	const SETTING_LAST_SEQ       = 'segurium_remote_actions_last_seq';
	const SETTING_LOG            = 'segurium_remote_actions_log';
	const SETTING_EXECUTED_AT    = 'segurium_remote_actions_executed_at';
	const SETTING_COMPONENT_SEEN = 'segurium_remote_actions_component_seen';
	const SETTING_PENDING_ACKS   = 'segurium_remote_actions_pending_acks';

	const TYPE_UPDATE_COMPONENT = 'update_component';

	const OK = 'ok';

	const REFUSE_BAD_TYPE           = 'bad_type';
	const REFUSE_BAD_COMPONENT_TYPE = 'bad_component_type';
	const REFUSE_BAD_SLUG           = 'bad_slug';
	const REFUSE_NOT_INSTALLED      = 'not_installed';
	const REFUSE_NO_UPDATE_PENDING  = 'no_update_pending';
	const REFUSE_NOT_WPORG_HOSTED   = 'not_wporg_hosted';
	const REFUSE_DENYLISTED         = 'denylisted';
	const REFUSE_CORE_MAJOR         = 'core_major_refused';
	const REFUSE_STALE_SEQ          = 'stale_seq';
	const REFUSE_EXPIRED            = 'expired';
	const REFUSE_RATE_CAPPED        = 'rate_capped';
	const REFUSE_COMPONENT_COOLDOWN = 'component_cooldown';
	const REFUSE_CONSENT_OFF        = 'consent_off';
	const REFUSE_KILL_SWITCH        = 'kill_switch';
	const REFUSE_BACKUP_FAILED      = 'backup_failed';
	const REFUSE_FS_UNAVAILABLE     = 'fs_unavailable';
	const REFUSE_UPGRADER_FAILED    = 'upgrader_failed';
	const REFUSE_WRONG_IID          = 'wrong_iid';
	const REFUSE_NO_CTI_CONSENT     = 'no_cti_consent';
	const REFUSE_TOO_MANY_ACTIONS   = 'too_many_actions';

	/**
	 * Executed actions allowed per site per rolling hour. A compromised
	 * CTI cannot use update churn as a fleet-wide resource attack.
	 */
	const MAX_PER_HOUR = 5;

	/** One action per component per 24h. */
	const COMPONENT_COOLDOWN_SECS = DAY_IN_SECONDS;

	/** Audit-log ring size. */
	const LOG_MAX = 50;

	/**
	 * Actions honoured from one envelope. CTI caps its own page at 20;
	 * this is the same number enforced on the receiving side, because a
	 * compromised CTI does not honour its own limits and each action past
	 * `evaluate()` costs a component snapshot.
	 */
	const MAX_ACTIONS_PER_ENVELOPE = 20;

	/** Guards against two pulls running the queue at once. */
	const LOCK_KEY = 'segurium_actions_run_lock';
	const LOCK_TTL = 900;

	/** Component statuses that are never updatable over this channel. */
	const DENIED_STATUSES = array( 'must_use', 'dropin' );

	/**
	 * Our own slug. Self-update over this channel is the direct path from
	 * a CTI breach to arbitrary code on every install, so it is refused
	 * regardless of what wp.org offers.
	 */
	const SELF_SLUG = 'segurium';

	/**
	 * Directory this plugin actually lives in. The constant above is only
	 * right while nobody renamed the folder; a manual install or a host
	 * that unzips elsewhere would otherwise drop the guard entirely.
	 *
	 * @return string
	 */
	private static function self_slug(): string {
		if ( defined( 'SEGURIUM_PLUGIN_FILE' ) && function_exists( 'plugin_basename' ) ) {
			$dir = dirname( plugin_basename( SEGURIUM_PLUGIN_FILE ) );
			if ( '' !== $dir && '.' !== $dir ) {
				return $dir;
			}
		}
		return self::SELF_SLUG;
	}

	/**
	 * Wire the cron handler. Scheduling is driven by activation
	 * ({@see schedule()}) and deactivation ({@see unschedule()}).
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_action( self::HOOK, array( __CLASS__, 'run' ) );
		add_action( 'update_option_' . self::SETTING_CONSENT, array( __CLASS__, 'on_consent_change' ), 10, 2 );
		add_action( 'add_option_' . self::SETTING_CONSENT, array( __CLASS__, 'on_consent_change' ), 10, 2 );
	}

	/**
	 * Consent changes ship a settings snapshot so CTI stops addressing a
	 * site that opted out instead of queueing for a site that will never
	 * pull again.
	 *
	 * @param mixed $a Unused hook argument.
	 * @param mixed $b Unused hook argument.
	 * @return void
	 */
	public static function on_consent_change( $a = null, $b = null ): void {
		unset( $a, $b );
		self::push_settings_snapshot();
	}

	/**
	 * Emit the `settings_snapshot` message for this feature.
	 *
	 * @return void
	 */
	public static function push_settings_snapshot(): void {
		if ( ! class_exists( 'Segurium_Storage' ) ) {
			return;
		}
		$payload = array(
			'feature'  => 'remote_actions',
			'settings' => array(
				'opt_in'      => Segurium_Storage::setting_get_bool( self::SETTING_CONSENT, true ),
				'kill_switch' => self::killed(),
			),
		);
		Segurium_Storage::cti_send_message( 'settings_snapshot', wp_json_encode( $payload ) );
	}

	/**
	 * Schedule the hourly pull. Idempotent.
	 *
	 * @return void
	 */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::HOOK );
		}
	}

	/**
	 * Clear the hourly pull.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		$ts = wp_next_scheduled( self::HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::HOOK );
		}
		wp_clear_scheduled_hook( self::HOOK );
	}

	/**
	 * Hard kill switch, checked before the user setting so an operator can
	 * sever the channel from wp-config.php without database access.
	 *
	 * @return bool
	 */
	public static function killed(): bool {
		return defined( 'SEGURIUM_DISABLE_REMOTE_ACTIONS' ) && SEGURIUM_DISABLE_REMOTE_ACTIONS;
	}

	/**
	 * Whether the site consents to the channel. Default on; the user can
	 * switch it off, and then the plugin makes no request at all and the
	 * poke route stops answering.
	 *
	 * @return bool
	 */
	public static function enabled(): bool {
		return '' === self::closed_reason();
	}

	/**
	 * Persist the consent flag.
	 *
	 * Stored as int, never as a PHP bool: `update_option()` compares the
	 * new value against `get_option()`, which answers `false` for an
	 * option that was never written, so writing bool `false` to an absent
	 * key is silently discarded and the site would stay opted in after
	 * switching the channel off.
	 *
	 * @param bool $on Whether the site consents.
	 * @return bool True when the stored value changed.
	 */
	public static function set_consent( bool $on ): bool {
		return Segurium_Storage::setting_set( self::SETTING_CONSENT, $on ? 1 : 0 );
	}

	/**
	 * Reason the channel is closed, or '' when it is open. Lets callers
	 * report a specific code instead of a bare false.
	 *
	 * @return string
	 */
	public static function closed_reason(): string {
		if ( self::killed() ) {
			return self::REFUSE_KILL_SWITCH;
		}
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			// A site that never accepted the service disclosure has no
			// cloud relationship at all, so it cannot have a queue.
			return self::REFUSE_NO_CTI_CONSENT;
		}
		if ( ! Segurium_Storage::setting_get_bool( self::SETTING_CONSENT, true ) ) {
			return self::REFUSE_CONSENT_OFF;
		}
		return '';
	}

	/**
	 * Cron / poke handler. Pulls the queue, runs each action, records the
	 * outcome. Never throws — including out of the executor — because a
	 * failure here runs inside a wp-cron request and would surface as a
	 * fatal.
	 *
	 * @param string $trigger Free-form label recorded in the audit log.
	 * @return array<int, array<string, mixed>> Outcomes, one per action.
	 */
	public static function run( string $trigger = 'cron' ): array {
		$closed = self::closed_reason();
		if ( '' !== $closed ) {
			return array();
		}

		// A plugin update routinely outlives WP_CRON_LOCK_TIMEOUT, so a
		// second cron pass can start while the first is still inside the
		// upgrader. Without this, both would pull the same envelope and
		// re-enter the upgrader on the directory the other is unpacking.
		if ( get_transient( self::LOCK_KEY ) ) {
			return array();
		}
		set_transient( self::LOCK_KEY, time(), self::LOCK_TTL );

		try {
			$client   = new Segurium_CTI_Client();
			$envelope = $client->get_actions( self::last_seq(), self::pending_acks() );

			if ( is_wp_error( $envelope ) ) {
				Segurium_Debug::log( '[segurium] remote actions pull error: ' . $envelope->get_error_code() );
				return array();
			}

			return self::consume_envelope( $envelope, $trigger );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] remote actions run failed: ' . $e->getMessage() );
			return array();
		} finally {
			delete_transient( self::LOCK_KEY );
		}
	}

	/**
	 * Validate an already-signature-verified envelope and run its actions.
	 *
	 * @param array<string, mixed> $envelope Decoded response body.
	 * @param string               $trigger  Audit-log label.
	 * @return array<int, array<string, mixed>>
	 */
	public static function consume_envelope( array $envelope, string $trigger = 'cron' ): array {
		$gate = self::validate_envelope( $envelope );
		if ( '' !== $gate ) {
			self::record( array(), $gate, $trigger );
			return array();
		}

		// Only now, once the envelope is proven to be ours, may we forget
		// the outcomes it says it stored. Clearing on an envelope meant for
		// another install would drop this site's audit trail for good — the
		// buffer rides the pull body precisely so a bad exchange retries.
		if ( isset( $envelope['acked'] ) && is_array( $envelope['acked'] ) ) {
			self::clear_acks( $envelope['acked'] );
		}

		$seq     = isset( $envelope['seq'] ) && is_numeric( $envelope['seq'] ) ? (int) $envelope['seq'] : 0;
		$actions = isset( $envelope['actions'] ) && is_array( $envelope['actions'] ) ? $envelope['actions'] : array();
		if ( empty( $actions ) ) {
			return array();
		}

		if ( count( $actions ) > self::MAX_ACTIONS_PER_ENVELOPE ) {
			self::record( array(), self::REFUSE_TOO_MANY_ACTIONS, $trigger );
			$actions = array_slice( $actions, 0, self::MAX_ACTIONS_PER_ENVELOPE );
		}

		// Advance before executing, not after. An upgrader run can outlive
		// the cron lock, and a concurrent pass that still saw the old value
		// would replay this same batch.
		self::set_last_seq( $seq );

		$outcomes = array();
		foreach ( $actions as $action ) {
			if ( ! is_array( $action ) ) {
				continue;
			}
			$code       = self::execute( $action );
			$outcomes[] = array(
				'id'   => isset( $action['id'] ) ? (string) $action['id'] : '',
				'code' => $code,
			);
			self::record( $action, $code, $trigger );
			self::queue_ack( isset( $action['id'] ) ? (string) $action['id'] : '', $code );
		}

		return $outcomes;
	}

	/**
	 * Envelope-level gate: the response must be addressed to this install,
	 * must move the sequence forward, and must not have expired.
	 *
	 * @param array<string, mixed> $envelope Decoded response body.
	 * @return string '' when the envelope is acceptable, else a refusal code.
	 */
	public static function validate_envelope( array $envelope ): string {
		$our_iid   = (string) Segurium_IID::get_iid();
		$their_iid = isset( $envelope['iid'] ) ? (string) $envelope['iid'] : '';
		if ( '' === $our_iid || ! hash_equals( $our_iid, $their_iid ) ) {
			return self::REFUSE_WRONG_IID;
		}

		// Expiry and sequence both exist to stop a captured envelope
		// replaying its actions. An empty queue carries none, so it is
		// simply nothing to do — holding it to either check would write a
		// refusal into the audit ring every hour on every quiet site.
		$actions = isset( $envelope['actions'] ) && is_array( $envelope['actions'] ) ? $envelope['actions'] : array();
		if ( empty( $actions ) ) {
			return '';
		}

		$expires = isset( $envelope['expires_at'] ) ? (int) $envelope['expires_at'] : 0;
		if ( $expires <= 0 || $expires < time() ) {
			return self::REFUSE_EXPIRED;
		}

		if ( ! isset( $envelope['seq'] ) || ! is_numeric( $envelope['seq'] ) ) {
			return self::REFUSE_STALE_SEQ;
		}
		if ( (int) $envelope['seq'] <= self::last_seq() ) {
			return self::REFUSE_STALE_SEQ;
		}

		return '';
	}

	/**
	 * Decide whether an action may run. Reads exactly four fields off
	 * `$action` and ignores anything else the envelope carried. Writes
	 * nothing, downloads nothing and runs no upgrader, so a refusal costs
	 * a couple of option reads.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	public static function evaluate( array $action ): string {
		$closed = self::closed_reason();
		if ( '' !== $closed ) {
			return $closed;
		}

		$type = isset( $action['type'] ) ? (string) $action['type'] : '';
		if ( self::TYPE_UPDATE_COMPONENT !== $type ) {
			return self::REFUSE_BAD_TYPE;
		}

		$component_type = isset( $action['component_type'] ) ? (string) $action['component_type'] : '';
		if ( ! in_array( $component_type, array( 'core', 'plugin', 'theme' ), true ) ) {
			return self::REFUSE_BAD_COMPONENT_TYPE;
		}

		$slug = isset( $action['slug'] ) ? (string) $action['slug'] : '';
		if ( ! self::slug_acceptable( $component_type, $slug ) ) {
			return self::REFUSE_BAD_SLUG;
		}

		// Both the compiled-in name and wherever the plugin actually sits.
		// Deriving alone would move the guard off `segurium` on an install
		// that resolves oddly; the literal alone would lose it on a renamed
		// directory. Refusing both closes each hole without opening the other.
		if ( 'plugin' === $component_type && in_array( $slug, array( self::SELF_SLUG, self::self_slug() ), true ) ) {
			return self::REFUSE_DENYLISTED;
		}

		if ( 'core' !== $component_type ) {
			$status = self::installed_status( $component_type, $slug );
			if ( null === $status ) {
				return self::REFUSE_NOT_INSTALLED;
			}
			if ( in_array( $status, self::DENIED_STATUSES, true ) ) {
				return self::REFUSE_DENYLISTED;
			}
		}

		if ( self::executed_in_last_hour() >= self::MAX_PER_HOUR ) {
			return self::REFUSE_RATE_CAPPED;
		}

		if ( self::component_in_cooldown( $component_type, $slug ) ) {
			return self::REFUSE_COMPONENT_COOLDOWN;
		}

		return 'core' === $component_type
			? self::evaluate_core()
			: self::evaluate_component( $component_type, $slug );
	}

	/**
	 * Run an action. Evaluates first and stops on any refusal, so nothing
	 * below this line executes for a message that failed the grammar.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	public static function execute( array $action ): string {
		$verdict = self::evaluate( $action );
		if ( self::OK !== $verdict ) {
			return $verdict;
		}

		if ( ! self::filesystem_ready() ) {
			return self::REFUSE_FS_UNAVAILABLE;
		}

		$component_type = (string) $action['component_type'];
		$slug           = isset( $action['slug'] ) ? (string) $action['slug'] : '';

		// Charge both rate windows here, where the expensive work starts,
		// not on success. Charging only successes would let a queue of
		// duplicates re-enter the snapshot-and-upgrade path unbounded,
		// because neither window would ever close.
		self::note_attempt( $component_type, $slug );

		if ( 'core' !== $component_type && ! self::backup_component( $component_type, $slug ) ) {
			return self::REFUSE_BACKUP_FAILED;
		}

		if ( ! self::apply_update( $component_type, $slug ) ) {
			return self::REFUSE_UPGRADER_FAILED;
		}

		return self::OK;
	}

	/**
	 * Whether core can write to the plugin directory without asking a
	 * human for credentials. On a host where WordPress falls back to FTP
	 * or SSH the upgrader stops at `fs_connect()` and reports nothing
	 * useful, so this is checked up front and refused by name.
	 *
	 * @return bool
	 */
	private static function filesystem_ready(): bool {
		Segurium_Path_Helpers::wp_admin_include( 'file.php' );
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			return false;
		}
		if ( 'direct' === get_filesystem_method( array(), Segurium_Path_Helpers::plugins_root(), true ) ) {
			return true;
		}
		return defined( 'FTP_USER' ) && defined( 'FTP_PASS' ) && defined( 'FTP_HOST' );
	}

	/**
	 * Slug grammar. Core carries no slug. Plugin and theme slugs are a
	 * directory name and nothing else — no separators, so no traversal
	 * and no path can be smuggled through this field.
	 *
	 * @param string $component_type core|plugin|theme.
	 * @param string $slug           Candidate slug.
	 * @return bool
	 */
	private static function slug_acceptable( string $component_type, string $slug ): bool {
		if ( 'core' === $component_type ) {
			return '' === $slug;
		}
		return 1 === preg_match( '/^[a-z0-9][a-z0-9-]{0,63}$/', $slug );
	}

	/**
	 * Look the slug up in the site's own inventory.
	 *
	 * @param string $component_type plugin|theme.
	 * @param string $slug           Component slug.
	 * @return string|null Inventory status, or null when not installed.
	 */
	private static function installed_status( string $component_type, string $slug ) {
		$data_dir = class_exists( 'Segurium_Storage_Fs' ) ? (string) Segurium_Storage_Fs::data_dir() : '';
		try {
			$inventory = Segurium_Integrity_Component_Discovery::enumerate_inventory( $data_dir );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] remote actions inventory failed: ' . $e->getMessage() );
			return null;
		}

		foreach ( $inventory as $row ) {
			if ( ( $row['component_type'] ?? '' ) === $component_type && ( $row['slug'] ?? '' ) === $slug ) {
				return (string) ( $row['status'] ?? '' );
			}
		}
		return null;
	}

	/**
	 * Core gate: an update must already be offered, and it must stay on
	 * the current branch. A forced major core bump at fleet scale is real
	 * damage and needs a human.
	 *
	 * @return string
	 */
	private static function evaluate_core(): string {
		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			Segurium_Path_Helpers::wp_admin_include( 'update.php' );
		}
		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			return self::REFUSE_NO_UPDATE_PENDING;
		}

		$offer = get_preferred_from_update_core();
		if ( ! is_object( $offer ) || ! isset( $offer->response ) || 'upgrade' !== $offer->response ) {
			return self::REFUSE_NO_UPDATE_PENDING;
		}

		global $wp_version;
		if ( ! self::same_branch( (string) $wp_version, (string) ( $offer->current ?? '' ) ) ) {
			return self::REFUSE_CORE_MAJOR;
		}

		return self::OK;
	}

	/**
	 * Two versions share a branch when major and minor match, so 6.4.2 to
	 * 6.4.3 passes and 6.4.2 to 6.5 does not.
	 *
	 * @param string $installed Installed version.
	 * @param string $offered   Offered version.
	 * @return bool
	 */
	private static function same_branch( string $installed, string $offered ): bool {
		$a = self::branch_of( $installed );
		$b = self::branch_of( $offered );
		return array() !== $a && $a === $b;
	}

	/**
	 * Major and minor of a version, with any pre-release or build suffix
	 * dropped: a site running 6.9-alpha-60123 or 6.9-RC1 is on branch 6.9
	 * and the 6.9 offer it is served is not a major bump.
	 *
	 * @param string $version Version string.
	 * @return array Empty when no leading numeric component is present.
	 */
	private static function branch_of( string $version ): array {
		$numeric = (string) preg_replace( '/[^0-9.].*$/', '', trim( $version ) );
		if ( '' === $numeric || '.' === $numeric[0] ) {
			return array();
		}
		$parts = explode( '.', $numeric );
		return array( (int) $parts[0], (int) ( $parts[1] ?? 0 ) );
	}

	/**
	 * Plugin / theme gate: core must already report a pending update, and
	 * the package it would fetch must come from wp.org. A component served
	 * by a third-party update server is refused — we cannot validate that
	 * source, and a hijacked one is exactly the escalation this channel
	 * must not open.
	 *
	 * @param string $component_type plugin|theme.
	 * @param string $slug           Component slug.
	 * @return string
	 */
	private static function evaluate_component( string $component_type, string $slug ): string {
		$package = 'plugin' === $component_type
			? self::pending_plugin_package( $slug )
			: self::pending_theme_package( $slug );

		if ( '' === $package ) {
			return self::REFUSE_NO_UPDATE_PENDING;
		}
		if ( ! self::is_wporg_package( $package ) ) {
			return self::REFUSE_NOT_WPORG_HOSTED;
		}
		return self::OK;
	}

	/**
	 * Package URL core would fetch for a pending plugin update, or ''.
	 *
	 * @param string $slug Plugin slug (directory name).
	 * @return string
	 */
	private static function pending_plugin_package( string $slug ): string {
		$file = Segurium_Component_Updates::plugin_file_for_slug( $slug );
		if ( '' === $file ) {
			return '';
		}
		Segurium_Path_Helpers::wp_admin_include( 'update.php' );
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			return '';
		}
		$updates = get_plugin_updates();
		if ( empty( $updates[ $file ]->update ) ) {
			return '';
		}
		$entry = $updates[ $file ]->update;
		return (string) ( is_object( $entry ) ? ( $entry->package ?? '' ) : ( $entry['package'] ?? '' ) );
	}

	/**
	 * Package URL core would fetch for a pending theme update, or ''.
	 *
	 * @param string $slug Theme stylesheet directory.
	 * @return string
	 */
	private static function pending_theme_package( string $slug ): string {
		Segurium_Path_Helpers::wp_admin_include( 'update.php' );
		if ( ! function_exists( 'get_theme_updates' ) ) {
			return '';
		}
		$updates = get_theme_updates();
		if ( empty( $updates[ $slug ]->update ) ) {
			return '';
		}
		$entry = $updates[ $slug ]->update;
		return (string) ( is_array( $entry ) ? ( $entry['package'] ?? '' ) : ( $entry->package ?? '' ) );
	}

	/**
	 * The package must be an https URL on wp.org's download host. Checked
	 * on the host component after parsing, so a lookalike hostname or a
	 * userinfo prefix cannot pass.
	 *
	 * @param string $package Package URL from core's update transient.
	 * @return bool
	 */
	private static function is_wporg_package( string $package ): bool {
		$parts = wp_parse_url( $package );
		if ( ! is_array( $parts ) ) {
			return false;
		}
		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
		$host   = strtolower( (string) ( $parts['host'] ?? '' ) );
		return 'https' === $scheme && 'downloads.wordpress.org' === $host;
	}

	/**
	 * Snapshot a component so a bad update can be rolled back.
	 *
	 * @param string $component_type plugin|theme.
	 * @param string $slug           Component slug.
	 * @return bool
	 */
	private static function backup_component( string $component_type, string $slug ): bool {
		if ( ! class_exists( 'Segurium_Component_Backup' ) ) {
			return false;
		}
		$path = 'plugin' === $component_type
			? Segurium_Path_Helpers::plugins_root() . '/' . $slug
			: get_theme_root( $slug ) . '/' . $slug;

		try {
			$backup = new Segurium_Component_Backup();
			$id     = $backup->create( $component_type, $slug, $path );
			return ! empty( $id ) && ! is_wp_error( $id );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] remote action backup failed: ' . $e->getMessage() );
			return false;
		}
	}

	/**
	 * Hand the update to core's own upgrader. The package URL comes from
	 * core's update transient, never from the message.
	 *
	 * @param string $component_type core|plugin|theme.
	 * @param string $slug           Component slug.
	 * @return bool
	 */
	private static function apply_update( string $component_type, string $slug ): bool {
		$result = Segurium_Component_Updates::apply( $component_type, $slug, Segurium_Component_Updates::TRIGGER_REMOTE_ACTION );
		if ( is_wp_error( $result ) ) {
			Segurium_Debug::log( '[segurium] remote action upgrader failed: ' . $result->get_error_code() );
			return false;
		}
		return true;
	}

	/**
	 * Count of actions attempted in the trailing hour.
	 *
	 * @return int
	 */
	private static function executed_in_last_hour(): int {
		$stamps = Segurium_Storage::setting_get_array( self::SETTING_EXECUTED_AT, array() );
		$cutoff = time() - HOUR_IN_SECONDS;
		$recent = array_filter(
			$stamps,
			static function ( $ts ) use ( $cutoff ) {
				return (int) $ts >= $cutoff;
			}
		);
		return count( $recent );
	}

	/**
	 * Whether this component was already actioned inside the cooldown.
	 *
	 * @param string $component_type core|plugin|theme.
	 * @param string $slug           Component slug.
	 * @return bool
	 */
	private static function component_in_cooldown( string $component_type, string $slug ): bool {
		$seen = Segurium_Storage::setting_get_array( self::SETTING_COMPONENT_SEEN, array() );
		$key  = $component_type . ':' . $slug;
		$last = isset( $seen[ $key ] ) ? (int) $seen[ $key ] : 0;
		return $last > 0 && ( time() - $last ) < self::COMPONENT_COOLDOWN_SECS;
	}

	/**
	 * Charge both rate windows for one attempt.
	 *
	 * @param string $component_type core|plugin|theme.
	 * @param string $slug           Component slug.
	 * @return void
	 */
	private static function note_attempt( string $component_type, string $slug ): void {
		$now    = time();
		$cutoff = $now - HOUR_IN_SECONDS;

		$stamps   = Segurium_Storage::setting_get_array( self::SETTING_EXECUTED_AT, array() );
		$stamps   = array_values(
			array_filter(
				$stamps,
				static function ( $ts ) use ( $cutoff ) {
					return (int) $ts >= $cutoff;
				}
			)
		);
		$stamps[] = $now;
		Segurium_Storage::setting_set( self::SETTING_EXECUTED_AT, $stamps );

		$seen                                  = Segurium_Storage::setting_get_array( self::SETTING_COMPONENT_SEEN, array() );
		$seen[ $component_type . ':' . $slug ] = $now;
		Segurium_Storage::setting_set( self::SETTING_COMPONENT_SEEN, $seen );
	}

	/**
	 * Highest envelope sequence this install has accepted.
	 *
	 * @return int
	 */
	public static function last_seq(): int {
		return Segurium_Storage::setting_get_int( self::SETTING_LAST_SEQ, 0 );
	}

	/**
	 * Persist the accepted sequence.
	 *
	 * @param int $seq Envelope sequence.
	 * @return void
	 */
	private static function set_last_seq( int $seq ): void {
		if ( $seq > self::last_seq() ) {
			Segurium_Storage::setting_set( self::SETTING_LAST_SEQ, $seq );
		}
	}

	/**
	 * Buffer an outcome for delivery on the next pull. Acks ride the pull
	 * body rather than the fire-and-forget message queue so a dropped
	 * request retries instead of silently losing the audit trail.
	 *
	 * @param string $id   Action id from the envelope.
	 * @param string $code Outcome code.
	 * @return void
	 */
	private static function queue_ack( string $id, string $code ): void {
		if ( '' === $id ) {
			return;
		}
		$acks        = Segurium_Storage::setting_get_array( self::SETTING_PENDING_ACKS, array() );
		$acks[ $id ] = $code;
		if ( count( $acks ) > self::LOG_MAX ) {
			$acks = array_slice( $acks, -self::LOG_MAX, null, true );
		}
		Segurium_Storage::setting_set( self::SETTING_PENDING_ACKS, $acks );
	}

	/**
	 * Outcomes waiting to be reported to CTI.
	 *
	 * @return array<string, string> Action id => outcome code.
	 */
	public static function pending_acks(): array {
		return Segurium_Storage::setting_get_array( self::SETTING_PENDING_ACKS, array() );
	}

	/**
	 * Drop acks CTI confirmed it stored.
	 *
	 * @param array<int, string> $ids Confirmed action ids.
	 * @return void
	 */
	public static function clear_acks( array $ids ): void {
		if ( empty( $ids ) ) {
			return;
		}
		$acks = Segurium_Storage::setting_get_array( self::SETTING_PENDING_ACKS, array() );
		foreach ( $ids as $id ) {
			unset( $acks[ (string) $id ] );
		}
		Segurium_Storage::setting_set( self::SETTING_PENDING_ACKS, $acks );
	}

	/**
	 * Append to the local audit ring. A user must be able to see what the
	 * cloud asked their site to do, and what came of it.
	 *
	 * @param array<string, mixed> $action  The action, or [] for an envelope-level refusal.
	 * @param string               $code    Outcome code.
	 * @param string               $trigger Audit label.
	 * @return void
	 */
	private static function record( array $action, string $code, string $trigger ): void {
		$log   = Segurium_Storage::setting_get_array( self::SETTING_LOG, array() );
		$log[] = array(
			'at'      => time(),
			'trigger' => $trigger,
			'type'    => isset( $action['type'] ) ? (string) $action['type'] : '',
			'ctype'   => isset( $action['component_type'] ) ? (string) $action['component_type'] : '',
			'slug'    => isset( $action['slug'] ) ? (string) $action['slug'] : '',
			'code'    => $code,
		);
		if ( count( $log ) > self::LOG_MAX ) {
			$log = array_slice( $log, -self::LOG_MAX );
		}
		Segurium_Storage::setting_set( self::SETTING_LOG, $log );
	}

	/**
	 * Audit ring, newest last.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function log_entries(): array {
		return Segurium_Storage::setting_get_array( self::SETTING_LOG, array() );
	}
}

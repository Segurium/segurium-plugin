<?php
/**
 * CTI → plugin action channel.
 *
 * CTI addresses a site by IID and hands it a short, closed-grammar
 * instruction. Four exist: "update this component", named by type +
 * slug; "scan again", which names nothing at all; "upload this file",
 * naming one site-relative path; and "stop this scan", naming one
 * running scan by id.
 *
 * The design assumes CTI is fully compromised. An attacker who owns CTI
 * holds the Ed25519 signing seed and can write any row into the message
 * table, so signature verification protects only against a network
 * attacker. The control that carries the weight is the message grammar:
 *
 *   - An update names a component, and a rescan names nothing. Neither
 *     carries a URL, a version, a package, a path, a callback, or code.
 *     {@see evaluate()} reads the type plus at most two more fields and
 *     ignores everything else in the array.
 *   - The plugin resolves the package itself, through core's own updater
 *     against api.wordpress.org. Nothing is fetched from CTI or from a
 *     host CTI names.
 *   - An update is refused unless the slug is already installed here AND
 *     core already reports a pending update for it.
 *
 * The worst well-formed update or rescan a compromised CTI can emit
 * therefore makes sites install updates that wp.org already offers them,
 * or run the scan they would have run tonight anyway.
 *
 * An upload does not hold that property and the owner accepted it
 * knowingly: a path field turns the channel into file read across the
 * fleet. What is left bounding it is a path grammar that admits no
 * traversal and no absolute path, a `realpath()` containment check
 * against ABSPATH, the denied-path list in
 * {@see Segurium_Remote_Action_Paths}, an outright refusal in
 * on-premise mode, and the existing five-actions-per-hour cap. The file
 * goes to the same scan pipeline an ordinary scan uses; CTI's only
 * addition is that it keeps the sample whatever the verdict says.
 *
 * There is deliberately no per-path cooldown. The 24h component cooldown
 * keys on a component and does not fit a path, and an analyst asking for
 * the same file twice — before and after a cleanup — is a workflow we
 * have. The hourly cap already bounds the volume, which is what the
 * cooldown was there for.
 *
 * A stop does not hold that property either, for a different reason: the
 * owner exempted it from the hourly cap, so a compromised CTI can
 * suppress scanning without the volume bound the other three carry. The
 * trade was deliberate — every other command starts work and this one
 * ends work, so an emergency stop has to land on a site that already
 * spent its window. A stop names one scan, the runner refuses an id that
 * is not the one its lock holds, and the site's scheduled scan runs as
 * usual afterwards.
 *
 * The first three commands each name their target in a field of their
 * own. A stop reads its `scan_id` out of the generic `args` map instead,
 * which is where every command added after it should read from: a flat
 * map of strings, so a fourth command costs no fourth field.
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

	const SETTINGS_SLUG          = 'remote_actions';
	const SETTING_LAST_SEQ       = 'segurium_remote_actions_last_seq';
	const SETTING_LOG            = 'segurium_remote_actions_log';
	const SETTING_EXECUTED_AT    = 'segurium_remote_actions_executed_at';
	const SETTING_COMPONENT_SEEN = 'segurium_remote_actions_component_seen';
	const SETTING_PENDING_ACKS   = 'segurium_remote_actions_pending_acks';

	const TYPE_UPDATE_COMPONENT = 'update_component';
	const TYPE_START_SCAN       = 'start_scan';
	const TYPE_UPLOAD_FILE      = 'upload_file';
	const TYPE_STOP_SCAN        = 'stop_scan';

	/**
	 * `scan_history.scan_type` written by a start_scan action. The scan
	 * itself is a scheduled scan in every other respect; the label exists
	 * so analytics can tell an operator-triggered run from the nightly one.
	 */
	const SCAN_TYPE = 'rescan';

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
	const REFUSE_SCAN_IN_PROGRESS   = 'scan_in_progress';
	const REFUSE_SCAN_START_FAILED  = 'scan_start_failed';
	const REFUSE_BAD_PATH           = 'bad_path';
	const REFUSE_PATH_DENIED        = 'path_denied';
	const REFUSE_NOT_A_FILE         = 'not_a_file';
	const REFUSE_UNREADABLE         = 'unreadable';
	const REFUSE_TOO_LARGE          = 'too_large';
	const REFUSE_ON_PREMISE         = 'on_premise';
	const REFUSE_UPLOAD_FAILED      = 'upload_failed';
	const REFUSE_BAD_SCAN_ID        = 'bad_scan_id';
	const REFUSE_SCAN_NOT_RUNNING   = 'scan_not_running';

	/**
	 * Longest site-relative path the channel will carry. Mirrors CTI's
	 * own cap and its CHECK constraint; WordPress itself has no such
	 * limit.
	 */
	const MAX_PATH_LEN = 1024;

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
	}

	/**
	 * The `settings` object CTI reads to see which sites accept component
	 * updates.
	 *
	 * `opt_in` is the component-update setting, not the channel. A site
	 * reporting false still pulls, and still runs start_scan and
	 * upload_file. Suppressing a queue on this field would switch off two
	 * instructions the site never opted out of.
	 *
	 * @param array $applied Stored settings after the write.
	 * @return array
	 */
	public static function snapshot_settings( array $applied ): array {
		return array(
			'opt_in'       => ! empty( $applied['enabled'] ),
			'opt_in_scope' => self::TYPE_UPDATE_COMPONENT,
			'kill_switch'  => self::killed(),
		);
	}

	/**
	 * Refusal code when wp-config.php has severed the channel, else ''.
	 * An operator who pinned the site off there cannot be overruled from
	 * the admin screen or from a script.
	 *
	 * @return string
	 */
	public static function kill_reason(): string {
		return self::killed() ? Segurium_Settings_Writer::CODE_KILL_SWITCH : '';
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
	 * Whether the site lets CTI request component updates. Backs the
	 * Settings checkbox, so it answers false whenever that box should
	 * read unchecked — including when the channel above it is closed.
	 *
	 * Switching it off stops component updates only. The queue is still
	 * pulled, because the other instructions on it are not this setting's
	 * to refuse.
	 *
	 * @return bool
	 */
	public static function component_updates_enabled(): bool {
		return '' === self::closed_reason()
			&& self::consent_enabled();
	}

	/**
	 * Whether the site has consented, ignoring the gates above it.
	 * Defaults to true: a site that never touched the box is opted in.
	 *
	 * @return bool
	 */
	public static function consent_enabled(): bool {
		return (bool) Segurium_Settings::get_field( self::SETTINGS_SLUG, 'enabled' );
	}

	/**
	 * Reduce raw input to the single stored field.
	 *
	 * @param array $input Raw settings input.
	 * @return array{enabled:bool}
	 */
	public static function validate_settings( $input ) {
		$input = is_array( $input ) ? $input : array();
		return array( 'enabled' => ! empty( $input['enabled'] ) );
	}

	/**
	 * Persist the consent flag.
	 *
	 * @param bool $on Whether the site consents.
	 * @return bool True when the stored value changed.
	 */
	public static function set_consent( bool $on ): bool {
		$result = Segurium_Settings_Writer::save( self::SETTINGS_SLUG, array( 'enabled' => $on ) );
		return (bool) $result['changed'];
	}

	/**
	 * Reason the whole channel is closed, or '' when it is open. Lets
	 * callers report a specific code instead of a bare false.
	 *
	 * Two gates, and neither is per-feature: the wp-config kill switch,
	 * and the service disclosure. Closed here means no traffic at all —
	 * the plugin does not pull and the poke route refuses.
	 *
	 * The component-updates consent is deliberately not one of them. It is
	 * presented to the user as permission to update components, so it
	 * gates that and nothing else; scanning and shipping a suspicious
	 * file are covered by the disclosure the site already accepted.
	 * {@see evaluate_update_component()} applies it.
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
			self::send_remote_action_message( $action, $code );
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
	 * Decide whether an action may run. Reads the type and dispatches on
	 * it; each branch reads only the fields its own type owns and ignores
	 * anything else the envelope carried. Writes nothing, downloads
	 * nothing and runs no upgrader, so a refusal costs a couple of option
	 * reads.
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
		switch ( $type ) {
			case self::TYPE_UPDATE_COMPONENT:
				return self::evaluate_update_component( $action );
			case self::TYPE_START_SCAN:
				return self::evaluate_start_scan();
			case self::TYPE_UPLOAD_FILE:
				return self::evaluate_upload_file( $action );
			case self::TYPE_STOP_SCAN:
				return self::evaluate_stop_scan( $action );
			default:
				return self::REFUSE_BAD_TYPE;
		}
	}

	/**
	 * Decide whether a start_scan action may run. The message names
	 * nothing, so there is no grammar to check beyond the shared rate cap
	 * and the scan lock.
	 *
	 * @return string self::OK, or the refusal code.
	 */
	private static function evaluate_start_scan(): string {
		if ( self::executed_in_last_hour() >= self::MAX_PER_HOUR ) {
			return self::REFUSE_RATE_CAPPED;
		}

		// Queueing behind a running scan would fire hours later against a
		// signature set that has moved on, so a busy site refuses and the
		// analyst re-queues. The lock decides, not a flag.
		if ( Segurium_Scan_Runner::is_running() ) {
			return self::REFUSE_SCAN_IN_PROGRESS;
		}

		return self::OK;
	}

	/**
	 * Decide whether a stop_scan action may run.
	 *
	 * The scan is named rather than implied, and that is the whole
	 * safety property: between an analyst queueing a stop and this site
	 * pulling it, the scan they meant can finish and another can start.
	 * A stop that named nothing would kill the wrong one.
	 *
	 * The hourly cap deliberately does not apply. Every other command
	 * starts work; this one ends work, and an emergency stop has to land
	 * on a site that already spent its window on uploads. The owner took
	 * that trade knowing it leaves scan suppression uncapped.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	private static function evaluate_stop_scan( array $action ): string {
		$scan_id = self::stop_scan_target( $action );
		if ( '' === $scan_id ) {
			return self::REFUSE_BAD_SCAN_ID;
		}

		if ( ! Segurium_Scan_Runner::is_scan_lock_held( $scan_id ) ) {
			return self::REFUSE_SCAN_NOT_RUNNING;
		}

		return self::OK;
	}

	/**
	 * The scan a stop_scan action names, or an empty string when it
	 * names nothing this grammar recognises.
	 *
	 * `stop_scan` takes exactly one argument. An action carrying a second
	 * one is refused rather than read past: an argument the reader skips
	 * is an argument a later reader might not. Counted before the filter
	 * rather than after, or a second argument whose value is not a string
	 * would be dropped by the filter and leave a count of one.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string
	 */
	private static function stop_scan_target( array $action ): string {
		$raw = isset( $action['args'] ) && is_array( $action['args'] ) ? $action['args'] : array();
		if ( 1 !== count( $raw ) ) {
			return '';
		}

		$args = self::action_args( $action );
		if ( ! isset( $args['scan_id'] ) ) {
			return '';
		}
		return self::scan_id_acceptable( $args['scan_id'] ) ? $args['scan_id'] : '';
	}

	/**
	 * A scan id is what `wp_generate_uuid4()` produced: 36 characters,
	 * hyphenated, lowercase hex. Matched exactly rather than normalised,
	 * because the runner compares it against the lock byte for byte and a
	 * re-cased id would silently match nothing.
	 *
	 * Anchored with `\z` rather than `$`, which in PCRE also matches
	 * before a trailing newline — so `$` would accept an id one byte
	 * longer than the one it names.
	 *
	 * @param string $scan_id Candidate.
	 * @return bool
	 */
	private static function scan_id_acceptable( string $scan_id ): bool {
		return 1 === preg_match(
			'/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/',
			$scan_id
		);
	}

	/**
	 * Decide whether an update_component action may run. Reads exactly
	 * two fields off `$action` and ignores anything else the envelope
	 * carried.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	private static function evaluate_update_component( array $action ): string {
		if ( ! self::consent_enabled() ) {
			return self::REFUSE_CONSENT_OFF;
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
	 * Decide whether an upload may run. Writes nothing and sends nothing;
	 * it reads one field, resolves it, and stats the result.
	 *
	 * The path is checked three times over, because each check catches
	 * something the others cannot. The grammar refuses a string that was
	 * never site-relative. `realpath()` refuses a string that resolves
	 * out of ABSPATH anyway, which is the only thing that catches a
	 * symlink pointing at /etc. The denied list refuses a path that is
	 * legitimately inside the site but whose contents are credentials.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	private static function evaluate_upload_file( array $action ): string {
		$resolved = '';
		$verdict  = self::check_upload_target( $action, $resolved );
		if ( self::OK !== $verdict ) {
			return $verdict;
		}

		if ( self::executed_in_last_hour() >= self::MAX_PER_HOUR ) {
			return self::REFUSE_RATE_CAPPED;
		}

		return self::OK;
	}

	/**
	 * Every check an upload target has to pass, and the resolved path if
	 * it passes them.
	 *
	 * Run twice: once by `evaluate()`, and again by `execute()` on the
	 * line before the read. Re-running is the point. This command exists
	 * for sites we already believe are compromised, so between the two
	 * calls the malware on that site can replace the named file with a
	 * symlink to `wp-config.php` — and a second containment check alone
	 * would not catch that, because the link lands inside `ABSPATH`.
	 *
	 * The rate cap is deliberately *not* here. `execute()` charges the
	 * hourly window before it reads, so re-checking the cap after
	 * charging it would refuse the action that just paid for itself.
	 *
	 * @param array<string, mixed> $action   One entry from `actions[]`.
	 * @param string               $resolved Set to the absolute resolved path on success.
	 * @return string self::OK, or the refusal code.
	 */
	private static function check_upload_target( array $action, string &$resolved ): string {
		$resolved = '';

		// Cloud detection off means file bytes never leave this server,
		// so the refusal is named rather than left to surface as a
		// transport error from a call we should not be making.
		if ( Segurium_Storage::on_premise_mode() ) {
			return self::REFUSE_ON_PREMISE;
		}

		$path = isset( $action['path'] ) && is_string( $action['path'] ) ? $action['path'] : '';
		if ( ! self::path_acceptable( $path ) ) {
			return self::REFUSE_BAD_PATH;
		}

		// Checked twice, on the way in and again after resolution. The
		// first pass answers without touching the disk, so a denied path
		// reads as denied rather than leaking whether it exists. The
		// second catches a path that only lands on a denied file after
		// the filesystem resolved it.
		if ( Segurium_Remote_Action_Paths::is_denied( $path ) ) {
			return self::REFUSE_PATH_DENIED;
		}

		// phpcs:ignore -- segurium-wporg-abspath: an analyst names a path relative to the WordPress root, and containment is the check.
		$absolute = ABSPATH . $path;
		$found    = realpath( $absolute );
		if ( false === $found ) {
			return self::REFUSE_NOT_A_FILE;
		}
		if ( ! self::inside_abspath( $found ) ) {
			return self::REFUSE_BAD_PATH;
		}

		if ( Segurium_Remote_Action_Paths::is_denied( self::relative_to_abspath( $found ) ) ) {
			return self::REFUSE_PATH_DENIED;
		}

		// is_link() is checked on the path as given, not on the resolved
		// one: realpath() has already followed the link, so by then a
		// symlink and a regular file look identical. A link inside
		// ABSPATH pointing at another file inside ABSPATH would pass
		// containment, and we still do not want to ship whatever it
		// currently aims at.
		if ( is_link( $absolute ) || ! is_file( $found ) ) {
			return self::REFUSE_NOT_A_FILE;
		}

		if ( ! is_readable( $found ) ) {
			return self::REFUSE_UNREADABLE;
		}

		$size = filesize( $found );
		if ( false === $size || $size <= 0 || $size > Segurium_Scanner::MAX_FILE_SIZE ) {
			return self::REFUSE_TOO_LARGE;
		}

		$resolved = $found;
		return self::OK;
	}

	/**
	 * Path grammar. Site-relative and staying that way: no leading
	 * separator, no backslash, no `.` or `..` segment, no empty segment
	 * and no control character. Mirrors CTI's `path_is_wellformed()` and
	 * the `plugin_actions_path_ck` constraint; all three have to agree.
	 *
	 * @param string $path Candidate site-relative path.
	 * @return bool
	 */
	private static function path_acceptable( string $path ): bool {
		if ( '' === $path || strlen( $path ) > self::MAX_PATH_LEN ) {
			return false;
		}
		if ( '/' === $path[0] ) {
			return false;
		}
		if ( preg_match( '/[\\\\\x00-\x1f\x7f]/', $path ) ) {
			return false;
		}
		foreach ( explode( '/', $path ) as $segment ) {
			if ( '' === $segment || '.' === $segment || '..' === $segment ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Whether an already-resolved absolute path sits under ABSPATH.
	 *
	 * Both sides are resolved before comparing, so a site whose ABSPATH
	 * itself runs through a symlink is not refused wholesale, and the
	 * separator is appended to the root so `/var/www/htdocs-old` cannot
	 * pass as a child of `/var/www/htdocs`.
	 *
	 * @param string $resolved Absolute path from realpath().
	 * @return bool
	 */
	private static function inside_abspath( string $resolved ): bool {
		// phpcs:ignore -- segurium-wporg-abspath: an analyst names a path relative to the WordPress root, and containment is the check.
		$root = realpath( ABSPATH );
		if ( false === $root ) {
			return false;
		}
		$root = rtrim( $root, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR;
		return 0 === strpos( $resolved, $root );
	}

	/**
	 * Site-relative form of an already-resolved absolute path, forward
	 * slashes, no leading separator. This is what the denied list and the
	 * upload's meta entry are keyed on, so both see where the path
	 * actually landed rather than what the action asked for.
	 *
	 * @param string $resolved Absolute path under ABSPATH.
	 * @return string
	 */
	private static function relative_to_abspath( string $resolved ): string {
		// phpcs:ignore -- segurium-wporg-abspath: an analyst names a path relative to the WordPress root, and containment is the check.
		$root = realpath( ABSPATH );
		if ( false === $root ) {
			return '';
		}
		$root     = rtrim( $root, DIRECTORY_SEPARATOR ) . DIRECTORY_SEPARATOR;
		$relative = 0 === strpos( $resolved, $root ) ? substr( $resolved, strlen( $root ) ) : '';
		return str_replace( DIRECTORY_SEPARATOR, '/', $relative );
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

		$type = isset( $action['type'] ) ? (string) $action['type'] : '';
		if ( self::TYPE_START_SCAN === $type ) {
			return self::execute_start_scan();
		}
		if ( self::TYPE_UPLOAD_FILE === $type ) {
			return self::execute_upload_file( $action );
		}
		if ( self::TYPE_STOP_SCAN === $type ) {
			return self::execute_stop_scan( $action );
		}

		return self::execute_update_component( $action );
	}

	/**
	 * Start the scan. Hands off to the same runner a scheduled scan uses,
	 * so the engine, the tick chain and the lifecycle messages are the
	 * ones already in production; only the recorded type differs.
	 *
	 * The hourly window is charged only once the runner accepted the scan.
	 * A pre-flight refusal creates nothing, and there is no
	 * duplicate-stuffing hole to close here: the second entry in an
	 * envelope of twenty finds the lock held and refuses inside
	 * {@see evaluate()}.
	 *
	 * @return string self::OK, or the refusal code.
	 */
	private static function execute_start_scan(): string {
		$result = Segurium_Scan_Runner::start( self::SCAN_TYPE );
		if ( ! is_wp_error( $result ) ) {
			self::note_execution();
			return self::OK;
		}

		$code = (string) $result->get_error_code();
		Segurium_Debug::log( '[segurium] remote action scan start failed: ' . $code );

		// A scan can start between evaluate() and here — an admin clicking
		// Start Scan, or a cron tick landing mid-pull.
		return 'scan_already_running' === $code
			? self::REFUSE_SCAN_IN_PROGRESS
			: self::REFUSE_SCAN_START_FAILED;
	}

	/**
	 * End the named scan.
	 *
	 * The id is passed through to the runner rather than dropped after
	 * the check above, so a scan that started in the gap between
	 * evaluate() and here is left alone: `terminate()` refuses when the
	 * lock has moved on, and that refusal is the answer the analyst gets.
	 *
	 * The hourly window is neither checked nor charged. See
	 * {@see evaluate_stop_scan()}.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	private static function execute_stop_scan( array $action ): string {
		$scan_id = self::stop_scan_target( $action );
		if ( '' === $scan_id ) {
			return self::REFUSE_BAD_SCAN_ID;
		}

		$stopped = Segurium_Scan_Runner::terminate(
			Segurium_Scan_Runner::REASON_REMOTE_CANCEL,
			$scan_id
		);

		return $stopped ? self::OK : self::REFUSE_SCAN_NOT_RUNNING;
	}

	/**
	 * Snapshot the component, then hand the update to core's upgrader.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	private static function execute_update_component( array $action ): string {
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
	 * Read the named file and hand it to the scan pipeline, tagged with
	 * the action id so the cloud keeps the sample whatever the verdict
	 * says. The verdict itself is not waited for: the outcome this
	 * action reports is whether the file was shipped.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string self::OK, or the refusal code.
	 */
	private static function execute_upload_file( array $action ): string {
		$resolved = '';
		$verdict  = self::check_upload_target( $action, $resolved );
		if ( self::OK !== $verdict ) {
			return $verdict;
		}

		// Charged where the expensive work starts, as on the update path,
		// not on success. The read and the POST both happen before the
		// outcome is known, so charging only successes would let a queue
		// of failing uploads re-enter that work unbounded — the window
		// would never close. Cheap refusals cost nothing: they return
		// from check_upload_target() above this line.
		//
		// Only the hourly window applies. The 24h cooldown is keyed on a
		// component and there is none here, so note_execution() is called
		// directly rather than note_attempt() with an empty key.
		self::note_execution();

		$body = @file_get_contents( $resolved ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged -- local file read; a race with a delete must refuse, not warn.
		if ( ! is_string( $body ) || '' === $body ) {
			return self::REFUSE_UNREADABLE;
		}
		if ( strlen( $body ) > Segurium_Scanner::MAX_FILE_SIZE ) {
			return self::REFUSE_TOO_LARGE;
		}

		$relative = self::relative_to_abspath( $resolved );
		$sent     = self::submit_sample( $body, $relative, self::action_string( $action, 'id' ) );
		if ( is_wp_error( $sent ) ) {
			Segurium_Debug::log( '[segurium] remote action upload failed: ' . $sent->get_error_code() );
			return self::REFUSE_UPLOAD_FAILED;
		}

		return self::OK;
	}

	/**
	 * Ship one file body through the async scan pipeline.
	 *
	 * @param string $body      Raw file bytes.
	 * @param string $relative  Site-relative path the bytes came from.
	 * @param string $action_id Action id, so the cloud can match the upload to the request.
	 * @return true|WP_Error
	 */
	private static function submit_sample( string $body, string $relative, string $action_id ) {
		$sha256 = hash( 'sha256', $body );
		try {
			$client = new Segurium_CTI_Client();
			$result = $client->scan_submit(
				wp_generate_uuid4(),
				wp_generate_uuid4(),
				array(
					array(
						'sha256'    => $sha256,
						'path'      => $relative,
						'body'      => $body,
						'action_id' => $action_id,
					),
				)
			);
		} catch ( Throwable $e ) {
			return new WP_Error( 'upload_exception', $e->getMessage() );
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		// Keyed off the rejection list rather than off `accepted`, the
		// same way neo_ray_scan() reads this response. The cloud is free
		// to answer a hash it already holds without echoing it back, and
		// an empty `accepted` would then report upload_failed forever for
		// a file that arrived.
		$rejected = isset( $result['rejected'] ) && is_array( $result['rejected'] ) ? $result['rejected'] : array();
		foreach ( $rejected as $row ) {
			$hash = isset( $row['hash'] ) ? strtolower( str_replace( 'sha256:', '', (string) $row['hash'] ) ) : '';
			if ( $hash === $sha256 ) {
				$reason = isset( $row['reason'] ) ? (string) $row['reason'] : 'rejected';
				return new WP_Error( 'upload_rejected', 'scan_submit rejected file: ' . $reason );
			}
		}

		return true;
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
	 * Charge both rate windows for one attempt on a named component.
	 * Actions that name no component call {@see note_execution()}
	 * directly, so nothing writes a key the cooldown can never match.
	 *
	 * @param string $component_type core|plugin|theme.
	 * @param string $slug           Component slug.
	 * @return void
	 */
	private static function note_attempt( string $component_type, string $slug ): void {
		self::note_execution();

		$seen                                  = Segurium_Storage::setting_get_array( self::SETTING_COMPONENT_SEEN, array() );
		$seen[ $component_type . ':' . $slug ] = time();
		Segurium_Storage::setting_set( self::SETTING_COMPONENT_SEEN, $seen );
	}

	/**
	 * Charge the per-site hourly window for one attempt.
	 *
	 * @return void
	 */
	private static function note_execution(): void {
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
	 * One field off an action, as a string.
	 *
	 * The envelope is attacker-controlled, so a field can be an array or
	 * an object. Casting one of those emits a PHP 8 warning inside a
	 * wp-cron request and lands the word "Array" in the audit ring and
	 * the analytics row. Anything that is not already a string is simply
	 * not a value this grammar has.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @param string               $key    Field name.
	 * @return string
	 */
	private static function action_string( array $action, string $key ): string {
		return isset( $action[ $key ] ) && is_string( $action[ $key ] ) ? $action[ $key ] : '';
	}

	/**
	 * The named arguments an action carries.
	 *
	 * The first three commands each named their target in a field of
	 * their own; commands added after them read it from here instead, so
	 * a fourth command costs no fourth field.
	 *
	 * The map is flat and string-valued, matching what CTI will store.
	 * Anything else — a nested array, a number, a boolean, a numeric key
	 * — is dropped rather than cast, so a caller cannot reach a reader
	 * expecting a string with something that only prints like one.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return array<string, string>
	 */
	private static function action_args( array $action ): array {
		if ( ! isset( $action['args'] ) || ! is_array( $action['args'] ) ) {
			return array();
		}

		$args = array();
		foreach ( $action['args'] as $key => $value ) {
			if ( is_string( $key ) && is_string( $value ) ) {
				$args[ $key ] = $value;
			}
		}
		return $args;
	}

	/**
	 * Report one performed action to the cloud as an analytics row.
	 *
	 * Additional to the ack, not a replacement for it. The ack rides the
	 * next pull body so it retries, which is the property an audit trail
	 * needs — but it produces no row in the message table, so nothing
	 * could count refusals across the fleet or notice a rollout being
	 * refused everywhere for one reason.
	 *
	 * `target` is one field whatever the action named: a slug for an
	 * update, a site-relative path for an upload, a scan id for a stop.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @param string               $code   Outcome code.
	 * @return void
	 */
	private static function send_remote_action_message( array $action, string $code ): void {
		if ( ! class_exists( 'Segurium_Storage' ) ) {
			return;
		}

		$type = self::action_string( $action, 'type' );
		switch ( $type ) {
			case self::TYPE_UPLOAD_FILE:
				$target = self::action_string( $action, 'path' );
				break;
			case self::TYPE_STOP_SCAN:
				$args   = self::action_args( $action );
				$target = isset( $args['scan_id'] ) ? $args['scan_id'] : '';
				break;
			default:
				$target = self::action_string( $action, 'slug' );
		}

		Segurium_Storage::cti_send_message(
			'remote_action',
			wp_json_encode(
				array(
					'action_id'   => self::action_string( $action, 'id' ),
					'action_type' => $type,
					'target'      => $target,
					'outcome'     => $code,
					'at'          => time(),
				)
			)
		);
	}

	/**
	 * Append to the local audit ring. Nothing renders it; it is the
	 * on-site record of what the cloud asked for and what came of it,
	 * read through log_entries().
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
			'type'    => self::action_string( $action, 'type' ),
			'ctype'   => self::action_string( $action, 'component_type' ),
			'slug'    => self::action_string( $action, 'slug' ),
			'path'    => self::action_string( $action, 'path' ),
			'args'    => self::action_args( $action ),
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

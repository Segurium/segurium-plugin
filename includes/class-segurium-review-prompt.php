<?php
/**
 * SEGURIUM-709: in-plugin review ask, shown only after a positive event.
 *
 * WordPress.org guideline 9 bans compensating, pressuring or sockpuppeting
 * for reviews; a plain unconditioned ask is allowed. Everything here is
 * built around that line: no reward, no star pre-fill, no urgency, at most
 * two impressions over the life of an install, and a "Don't ask again"
 * that is permanent.
 *
 * Two triggers arm the ask:
 *   - a malware scan that finished `completed` with zero threats and zero
 *     read failures, once the install is at least 3 days old;
 *   - a successful malware cleanup, with no age gate — a cleanup is a
 *     strong enough signal to ask on day one.
 *
 * Nothing else arms it. Activation, an aborted or cancelled run, a scan
 * that found threats, and a scan that could not read every file all leave
 * it disarmed.
 *
 * @package Segurium
 * @since   SEGURIUM-709
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Review-ask state machine and admin surface.
 */
final class Segurium_Review_Prompt {

	const OPTION_STATE               = 'segurium_review_prompt';
	const OPTION_FIRST_ACTIVATION_AT = 'segurium_first_activation_at';

	const NONCE_ACTION     = 'segurium_review_prompt';
	const AJAX_ACTION      = 'segurium_review_prompt_action';
	const CTI_MESSAGE_TYPE = 'review_prompt';

	const SCREEN_ID = 'toplevel_page_segurium';

	const STATE_UNSEEN    = 'unseen';
	const STATE_SHOWN     = 'shown';
	const STATE_SNOOZED   = 'snoozed';
	const STATE_DISMISSED = 'dismissed';
	const STATE_REVIEWED  = 'reviewed';

	const TRIGGER_SCAN    = 'scan';
	const TRIGGER_CLEANUP = 'cleanup';

	const ACTION_REVIEW = 'review';
	const ACTION_LATER  = 'later';
	const ACTION_NEVER  = 'never';

	/**
	 * Minimum install age before a clean scan may arm the ask. A review
	 * written minutes after install is a review from someone who has not
	 * used the product yet.
	 */
	const SCAN_MIN_INSTALL_AGE = 3 * DAY_IN_SECONDS;

	/**
	 * Cooling-off window after every impression, answered or ignored.
	 */
	const SNOOZE_SECONDS = 30 * DAY_IN_SECONDS;

	/**
	 * Hard ceiling on impressions over the life of an install.
	 */
	const MAX_IMPRESSIONS = 2;

	const REVIEW_URL = 'https://wordpress.org/support/plugin/segurium/reviews/#new-post';

	/**
	 * Scan history statuses that count as "the scan finished normally".
	 */
	const TERMINAL_OK_STATUS = 'completed';

	/**
	 * Wire the listeners. Idempotent — safe to call from the bootstrap.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'segurium_scan_completed', array( __CLASS__, 'on_scan_completed' ), 20, 1 );
		add_action( 'segurium_cleanup_succeeded', array( __CLASS__, 'on_cleanup_succeeded' ), 10, 0 );
		add_action( 'admin_notices', array( __CLASS__, 'render_notice' ) );
	}

	/**
	 * Stamp the install date on activation. Never overwrites an existing
	 * value, so re-activating the plugin does not reset the age gate.
	 *
	 * @return void
	 */
	public static function record_first_activation() {
		if ( self::stored_first_activation() > 0 ) {
			return;
		}
		Segurium_Storage::setting_set( self::OPTION_FIRST_ACTIVATION_AT, time() );
	}

	/**
	 * Install age reference point.
	 *
	 * Installs that predate this feature have no stamp. Backfilling from
	 * the oldest scan_history row keeps them honest — they get credit for
	 * the time they have actually been running rather than restarting the
	 * clock at upgrade. With no scans on record the current time is
	 * stored, which costs a fresh install nothing.
	 *
	 * @return int Unix timestamp.
	 */
	public static function first_activation_at() {
		$stored = self::stored_first_activation();
		if ( $stored > 0 ) {
			return $stored;
		}

		try {
			$oldest = (int) Segurium_Storage::table_get_var(
				'scan_history',
				'SELECT MIN(started_at) FROM {{table}}'
			);
		} catch ( Segurium_Storage_Exception $e ) {
			// Never persist on this path. A transient DB failure that
			// stamped time() would brand a two-year-old install as new,
			// and the stamp is write-once — the 3-day gate would come
			// back for good. Answer this request, retry the backfill on
			// the next one.
			Segurium_Debug::log( '[segurium-review-prompt] scan_history backfill failed: ' . $e->getMessage() );
			return time();
		}

		$resolved = $oldest > 0 ? $oldest : time();
		Segurium_Storage::setting_set( self::OPTION_FIRST_ACTIVATION_AT, $resolved );

		return $resolved;
	}

	/**
	 * `segurium_scan_completed` listener.
	 *
	 * The engine object only supplies the scan id; the scan_history row
	 * written by the finalizer immediately before this hook is the
	 * authority on how the run actually ended.
	 *
	 * @param mixed $scan Completed scan engine.
	 * @return bool Whether the ask was armed.
	 */
	public static function on_scan_completed( $scan ) {
		if ( ! is_object( $scan ) || ! method_exists( $scan, 'get_state' ) ) {
			return false;
		}
		$state = $scan->get_state();

		return self::evaluate_scan(
			isset( $state['scan_id'] ) ? (string) $state['scan_id'] : ''
		);
	}

	/**
	 * Decide whether a finished scan earned the ask.
	 *
	 * @param string $scan_id Scan UUID.
	 * @return bool Whether the ask was armed.
	 */
	public static function evaluate_scan( $scan_id ) {
		$scan_id = (string) $scan_id;
		if ( '' === $scan_id ) {
			return false;
		}
		// Cheapest gate first. On a dismissed install this skips both the
		// scan_history read and the install-age backfill, which are pure
		// waste once the answer can only be "no".
		if ( ! self::is_askable() ) {
			return false;
		}

		$row = null;
		try {
			$row = Segurium_Storage::table_get_row(
				'scan_history',
				'SELECT status, threats_found, files_failed FROM {{table}} WHERE scan_uuid = %s LIMIT 1',
				array( $scan_id ),
				ARRAY_A
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( '[segurium-review-prompt] scan_history read failed: ' . $e->getMessage() );
			return false;
		}

		if ( ! is_array( $row ) || empty( $row ) ) {
			return false;
		}
		if ( self::TERMINAL_OK_STATUS !== (string) $row['status'] ) {
			return false;
		}
		if ( (int) $row['threats_found'] > 0 || (int) $row['files_failed'] > 0 ) {
			return false;
		}
		if ( ( time() - self::first_activation_at() ) < self::SCAN_MIN_INSTALL_AGE ) {
			return false;
		}

		return self::arm( self::TRIGGER_SCAN );
	}

	/**
	 * `segurium_cleanup_succeeded` listener. Fires for manual, fix-all and
	 * auto-fix cleanups alike.
	 *
	 * @return bool Whether the ask was armed.
	 */
	public static function on_cleanup_succeeded() {
		return self::arm( self::TRIGGER_CLEANUP );
	}

	/**
	 * Arm the ask for the next Segurium admin page load.
	 *
	 * @param string $trigger One of the TRIGGER_* constants.
	 * @return bool Whether the ask was armed.
	 */
	private static function arm( $trigger ) {
		$state = self::get_state();

		if ( ! self::is_askable( $state ) ) {
			return false;
		}
		if ( $state['snooze_until'] > time() ) {
			return false;
		}
		if ( '' !== $state['trigger'] ) {
			return false;
		}

		$state['trigger'] = $trigger;

		if ( ! self::save_state( $state ) ) {
			Segurium_Debug::log( '[segurium-review-prompt] review_prompt_arm_write_failed trigger=' . $trigger );
			return false;
		}

		return true;
	}

	/**
	 * Whether this install may ever be asked again.
	 *
	 * @param array|null $state Optional pre-read state.
	 * @return bool
	 */
	private static function is_askable( $state = null ) {
		$state = is_array( $state ) ? $state : self::get_state();

		if ( in_array( $state['state'], array( self::STATE_DISMISSED, self::STATE_REVIEWED ), true ) ) {
			return false;
		}

		return $state['impressions'] < self::MAX_IMPRESSIONS;
	}

	/**
	 * Whether the notice would paint on this request.
	 *
	 * @return bool
	 */
	public static function should_render() {
		// Without consent the page renders the disclosure screen, which
		// never consumes the captured-notice buffer. Painting there would
		// burn an impression on markup the browser never receives.
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return false;
		}

		$state = self::get_state();

		if ( '' === $state['trigger'] ) {
			return false;
		}
		if ( ! self::is_askable( $state ) ) {
			return false;
		}

		return $state['snooze_until'] <= time();
	}

	/**
	 * `admin_notices` callback. Renders on the Segurium screen only — the
	 * plugin's own notice buffer then repositions it inside the wrap.
	 *
	 * @return void
	 */
	public static function render_notice() {
		if ( ! self::on_our_screen() ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! self::should_render() ) {
			return;
		}

		$state   = self::get_state();
		$trigger = $state['trigger'];
		$copy    = self::copy_for( $trigger );

		// Claim the trigger before printing, not after. Two overlapping
		// page loads (menu double-click, link prefetch, two tabs refreshed
		// together) can both clear should_render() before either writes;
		// claiming first shortens that window to the read-write span and
		// keeps the later arrival's should_render() false. wp_options has
		// no compare-and-swap, so a true simultaneous pair still paints
		// twice — the cost is one duplicate `shown` row, and the
		// impression counter still lands on one.
		$state['state']        = self::STATE_SHOWN;
		$state['trigger']      = '';
		$state['last_trigger'] = $trigger;
		$state['impressions']  = $state['impressions'] + 1;
		$state['shown_at']     = time();
		$state['snooze_until'] = time() + self::SNOOZE_SECONDS;

		if ( ! self::save_state( $state ) ) {
			// The trigger is still armed. Staying silent keeps the ask for
			// the next page load instead of repainting it — and emitting a
			// `shown` row — on every single one.
			Segurium_Debug::log( '[segurium-review-prompt] review_prompt_state_write_failed; suppressing the ask this request' );
			return;
		}

		printf(
			'<div class="notice notice-success is-dismissible segurium-review-prompt" data-segurium-review-nonce="%1$s"><p><strong>%2$s</strong></p><p>%3$s</p><p>' .
			'<a class="button button-primary" href="%4$s" target="_blank" rel="noopener noreferrer" data-segurium-review-action="%5$s">%6$s</a> ' .
			'<button type="button" class="button" data-segurium-review-action="%7$s">%8$s</button> ' .
			'<button type="button" class="button-link segurium-review-prompt__never" data-segurium-review-action="%9$s">%10$s</button>' .
			'</p></div>',
			esc_attr( wp_create_nonce( self::NONCE_ACTION ) ),
			esc_html( $copy['title'] ),
			esc_html( $copy['body'] ),
			esc_url( self::REVIEW_URL ),
			esc_attr( self::ACTION_REVIEW ),
			esc_html__( 'Leave a review', 'segurium' ),
			esc_attr( self::ACTION_LATER ),
			esc_html__( 'Maybe later', 'segurium' ),
			esc_attr( self::ACTION_NEVER ),
			esc_html__( 'Don\'t ask again', 'segurium' )
		);

		self::report( 'shown', $trigger, $state['impressions'] );
	}

	/**
	 * Copy for a trigger. Plain wording: no reward, no star pre-fill, no
	 * urgency, nothing conditioned on what the user writes.
	 *
	 * @param string $trigger One of the TRIGGER_* constants.
	 * @return array{title:string,body:string}
	 */
	private static function copy_for( $trigger ) {
		if ( self::TRIGGER_CLEANUP === $trigger ) {
			return array(
				'title' => __( 'Segurium just cleaned your site.', 'segurium' ),
				'body'  => __( 'Glad we could help. If Segurium saved you time or money today, an honest review on WordPress.org helps other site owners find it, and helps us keep the cleanup tier free.', 'segurium' ),
			);
		}

		return array(
			'title' => __( 'Scan complete. Your site is clean.', 'segurium' ),
			'body'  => __( 'If Segurium is doing its job, would you leave an honest review on WordPress.org? It takes a minute.', 'segurium' ),
		);
	}

	/**
	 * Apply a button press to the state machine.
	 *
	 * @param string $action One of the ACTION_* constants.
	 * @return bool Whether the action was understood.
	 */
	public static function apply_user_action( $action ) {
		$action = (string) $action;
		$state  = self::get_state();

		// "Don't ask again" and "Leave a review" are one-way doors. A
		// replayed press — Back/Forward restoring the pre-dismiss DOM
		// against a still-valid nonce, a second tab that painted the
		// notice concurrently, a hand-rolled POST — must not walk a
		// dismissed install back to `snoozed`, which is not terminal and
		// would let the ask return 30 days later.
		if ( in_array( $state['state'], array( self::STATE_DISMISSED, self::STATE_REVIEWED ), true ) ) {
			return in_array( $action, array( self::ACTION_REVIEW, self::ACTION_LATER, self::ACTION_NEVER ), true );
		}

		switch ( $action ) {
			case self::ACTION_REVIEW:
				$state['state'] = self::STATE_REVIEWED;
				break;
			case self::ACTION_NEVER:
				$state['state'] = self::STATE_DISMISSED;
				break;
			case self::ACTION_LATER:
				$state['state']        = self::STATE_SNOOZED;
				$state['snooze_until'] = max( $state['snooze_until'], time() + self::SNOOZE_SECONDS );
				break;
			default:
				return false;
		}

		$state['trigger'] = '';

		if ( ! self::save_state( $state ) ) {
			Segurium_Debug::log( '[segurium-review-prompt] review_prompt_action_write_failed action=' . $action );
			return false;
		}

		// `last_trigger` is what makes the telemetry answerable: without
		// it every press reports an empty trigger and the cleanup ask
		// cannot be compared against the clean-scan ask.
		self::report( $action, $state['last_trigger'], $state['impressions'] );

		return true;
	}

	/**
	 * AJAX handler for the three buttons.
	 *
	 * @return void
	 */
	public static function ajax_review_prompt_action() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$action = isset( $_POST['review_action'] ) ? sanitize_key( wp_unslash( $_POST['review_action'] ) ) : '';

		if ( ! self::apply_user_action( $action ) ) {
			segurium_send_json_error(
				array(
					'message'    => __( 'Unknown review prompt action.', 'segurium' ),
					'error_code' => 'review_prompt_unknown_action',
				),
				400
			);
		}

		segurium_send_json_success( array( 'state' => self::get_state()['state'] ) );
	}

	/**
	 * Whether the current request is painting our own admin screen.
	 *
	 * @return bool
	 */
	private static function on_our_screen() {
		if ( ! function_exists( 'get_current_screen' ) ) {
			return false;
		}
		$screen = get_current_screen();

		return ( $screen instanceof WP_Screen ) && self::SCREEN_ID === $screen->id;
	}

	/**
	 * Mirror the prompt lifecycle to CTI so the ask can be measured. Uses
	 * the existing message queue — no new transport, no new table.
	 *
	 * @param string $event       shown | review | later | never.
	 * @param string $trigger     Trigger that produced the impression.
	 * @param int    $impressions Impressions so far.
	 * @return void
	 */
	private static function report( $event, $trigger, $impressions ) {
		Segurium_Storage::cti_send_message(
			self::CTI_MESSAGE_TYPE,
			array(
				'event'       => $event,
				'trigger'     => $trigger,
				'impressions' => (int) $impressions,
			)
		);
	}

	/**
	 * Raw install stamp, 0 when absent.
	 *
	 * @return int
	 */
	private static function stored_first_activation() {
		return max( 0, Segurium_Storage::setting_get_int( self::OPTION_FIRST_ACTIVATION_AT, 0 ) );
	}

	/**
	 * Current state, normalised so callers never branch on shape.
	 *
	 * @return array{state:string,trigger:string,impressions:int,shown_at:int,snooze_until:int}
	 */
	public static function get_state() {
		$stored = Segurium_Storage::setting_get_array( self::OPTION_STATE, array() );

		$state = isset( $stored['state'] ) ? (string) $stored['state'] : self::STATE_UNSEEN;
		if ( ! in_array( $state, self::known_states(), true ) ) {
			$state = self::STATE_UNSEEN;
		}

		$trigger      = self::normalise_trigger( isset( $stored['trigger'] ) ? $stored['trigger'] : '' );
		$last_trigger = self::normalise_trigger( isset( $stored['last_trigger'] ) ? $stored['last_trigger'] : '' );

		return array(
			'state'        => $state,
			'trigger'      => $trigger,
			'last_trigger' => $last_trigger,
			'impressions'  => isset( $stored['impressions'] ) ? max( 0, (int) $stored['impressions'] ) : 0,
			'shown_at'     => isset( $stored['shown_at'] ) ? max( 0, (int) $stored['shown_at'] ) : 0,
			'snooze_until' => isset( $stored['snooze_until'] ) ? max( 0, (int) $stored['snooze_until'] ) : 0,
		);
	}

	/**
	 * Coerce a stored trigger to a known value.
	 *
	 * @param mixed $value Stored value.
	 * @return string
	 */
	private static function normalise_trigger( $value ) {
		$value = is_string( $value ) ? $value : '';

		return in_array( $value, array( self::TRIGGER_SCAN, self::TRIGGER_CLEANUP ), true ) ? $value : '';
	}

	/**
	 * Every state the machine may hold.
	 *
	 * @return string[]
	 */
	private static function known_states() {
		return array(
			self::STATE_UNSEEN,
			self::STATE_SHOWN,
			self::STATE_SNOOZED,
			self::STATE_DISMISSED,
			self::STATE_REVIEWED,
		);
	}

	/**
	 * Persist state.
	 *
	 * @param array $state State array.
	 * @return bool Whether the write landed.
	 */
	private static function save_state( array $state ) {
		return Segurium_Storage::setting_set( self::OPTION_STATE, $state );
	}

	/**
	 * Test helper: drop every option this class owns.
	 *
	 * @return void
	 */
	public static function reset_for_testing() {
		Segurium_Storage::setting_delete( self::OPTION_STATE );
		Segurium_Storage::setting_delete( self::OPTION_FIRST_ACTIVATION_AT );
	}
}

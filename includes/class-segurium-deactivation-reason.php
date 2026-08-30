<?php
/**
 * Exit-reason ask on the plugins screen.
 *
 * When an install disappears, the only trace left behind is a
 * `plugin_deactivated` row and a timestamp. Every explanation for the
 * loss is currently an inference drawn from what the site did in the
 * days before it left, and most of those inferences are unfalsifiable.
 *
 * So the Deactivate link asks. One dialog, six reasons, an optional
 * note, and a Skip that costs the user nothing. At most one answer is
 * ever recorded per install, and only from an operator who granted cloud
 * consent: without it there is nowhere to send the answer, and asking a
 * question we cannot record is a toll booth with no road behind it.
 * Skip records nothing and leaves the ask armed, so an install that is
 * reactivated and deactivated again is asked again.
 *
 * Nothing here may block a deactivation. A user who has decided to
 * leave gets to leave: the browser follows the original Deactivate URL
 * whether the report lands, fails, or times out.
 *
 * The billing SDK ships an equivalent dialog, and it is not dead code
 * for us: its guard needs a site object that a skipped install never
 * has, so it paints for the whole free base. See
 * {@see suppress_vendor_dialog()}.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Closed-set validation, reporting and admin surface for the exit ask.
 */
final class Segurium_Deactivation_Reason {

	const NONCE_ACTION     = 'segurium_deactivation_reason';
	const AJAX_ACTION      = 'segurium_deactivation_reason';
	const CTI_MESSAGE_TYPE = 'deactivation_reason';

	const OPTION_ASKED = 'segurium_deactivation_reason_asked';

	const REASON_MISSING_FEATURE   = 'missing_feature';
	const REASON_CAUSING_ISSUES    = 'causing_issues';
	const REASON_NO_LONGER_NEEDED  = 'no_longer_needed';
	const REASON_FOUND_ALTERNATIVE = 'found_alternative';
	const REASON_TEMPORARY         = 'temporary';
	const REASON_OTHER             = 'other';

	/**
	 * Ceiling on the free note, matching the false-positive report field
	 * whose label this dialog reuses.
	 */
	const DETAIL_MAX = 2000;

	const ERR_UNKNOWN_REASON = 'deactivation_reason_unknown_reason';
	const ERR_ALREADY_ASKED  = 'deactivation_reason_already_asked';
	const ERR_NO_CONSENT     = 'deactivation_reason_no_consent';
	const ERR_NO_IID         = 'deactivation_reason_no_iid';
	const ERR_QUEUE_FAILED   = 'deactivation_reason_queue_failed';

	/**
	 * The reasons the dialog offers, in the order it paints them.
	 *
	 * @return array<int, string>
	 */
	public static function reasons() {
		return array(
			self::REASON_MISSING_FEATURE,
			self::REASON_CAUSING_ISSUES,
			self::REASON_NO_LONGER_NEEDED,
			self::REASON_FOUND_ALTERNATIVE,
			self::REASON_TEMPORARY,
			self::REASON_OTHER,
		);
	}

	/**
	 * Wire the plugins-screen surface. The caller decides the screen —
	 * see `segurium_admin_other_needs_deactivation_ask()`.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_action( 'admin_footer', array( __CLASS__, 'render_dialog' ) );
		if ( defined( 'SEGURIUM_FS_SLUG' ) ) {
			add_filter( 'fs_show_deactivation_feedback_form_' . SEGURIUM_FS_SLUG, array( __CLASS__, 'suppress_vendor_dialog' ) );
		}
	}

	/**
	 * Silence the billing SDK's own exit dialog while this one paints.
	 *
	 * Its guard reads `is_object( $site ) && ! is_registered()`, and an
	 * install that skipped the vendor connection carries no site object
	 * at all, so the guard never fires and the SDK form renders for the
	 * whole free base, stacked behind ours. The SDK documents this filter
	 * for exactly that.
	 *
	 * The passed value is deliberately ignored on the other branch. The
	 * SDK seeds it from its own snooze transient and then throws that
	 * away the moment any callback is attached here, handing every filter
	 * a bare `true`. Returning `$show` would therefore un-snooze a form
	 * the user has already dismissed for the snooze window, so the
	 * transient is re-read instead.
	 *
	 * @param bool $show Whether the SDK would paint its form. Always true.
	 * @return bool
	 */
	public static function suppress_vendor_dialog( $show ) {
		if ( self::should_ask() ) {
			return false;
		}
		if ( class_exists( 'Freemius', false ) ) {
			return ! Freemius::is_deactivation_snoozed();
		}

		return (bool) $show;
	}

	/**
	 * Whether the ask may paint at all.
	 *
	 * @return bool
	 */
	public static function should_ask() {
		if ( Segurium_Storage::setting_get_bool( self::OPTION_ASKED ) ) {
			return false;
		}
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return false;
		}
		// Consent is written before the registration round-trip finishes,
		// so an install can be consented and still have no IID. Asking
		// there costs the user a click and then answers no_iid.
		if ( ! class_exists( 'Segurium_IID' ) || null === Segurium_IID::get_iid() ) {
			return false;
		}
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return false;
		}
		if ( self::vendor_owns_the_exit() ) {
			return false;
		}

		return true;
	}

	/**
	 * Whether the billing SDK's dialog is the one that should paint.
	 *
	 * Silencing the SDK's feedback form is not always enough to stop it
	 * printing. It also prints for an install holding a non-lifetime
	 * licence with a live subscription, so it can offer to cancel that
	 * subscription, and the template it prints binds its own delegated
	 * handler to the same Deactivate link: one click, two dialogs.
	 *
	 * Filtering that panel away instead would take a subscription
	 * decision away from someone paying for one, so the ask steps aside
	 * for those installs. The vendor already collects a reason from them.
	 * This ask exists for the base that skipped the vendor connection,
	 * whose answers reach nobody otherwise.
	 *
	 * The SDK's own accessor decides, rather than a plan or licence test
	 * standing in for it. Every cheaper proxy is wrong in one direction:
	 * a paying install with no subscription, or a lifetime licence, still
	 * prints nothing, and stepping aside for it would cost an answer for
	 * a collision that never happens.
	 *
	 * @return bool
	 */
	private static function vendor_owns_the_exit() {
		if ( ! function_exists( 'segurium_fs' ) || ! class_exists( 'Freemius', false ) ) {
			return false;
		}
		$fs     = segurium_fs();
		$method = '_get_subscription_cancellation_dialog_box_template_params';
		if ( ! is_object( $fs ) || ! method_exists( $fs, $method ) ) {
			return false;
		}

		return ! empty( $fs->$method() );
	}

	/**
	 * Enqueue the dialog's assets on the plugins screen.
	 *
	 * @param string $hook Current admin page hook suffix.
	 * @return void
	 */
	public static function enqueue( $hook ) {
		if ( 'plugins.php' !== $hook || ! self::should_ask() ) {
			return;
		}

		wp_enqueue_style(
			'segurium-deactivate',
			SEGURIUM_PLUGIN_URL . 'assets/css/segurium-deactivate.css',
			array(),
			self::asset_version( 'assets/css/segurium-deactivate.css' )
		);
		wp_enqueue_script(
			'segurium-ajax',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-ajax.js',
			array(),
			self::asset_version( 'assets/js/segurium-ajax.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-deactivate',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-deactivate.js',
			array( 'segurium-ajax' ),
			self::asset_version( 'assets/js/segurium-deactivate.js' ),
			true
		);
		wp_add_inline_script(
			'segurium-deactivate',
			'var seguriumDeactivate = ' . wp_json_encode(
				array(
					'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
					'action'   => self::AJAX_ACTION,
					'nonce'    => wp_create_nonce( self::NONCE_ACTION ),
					'basename' => plugin_basename( SEGURIUM_PLUGIN_FILE ),
				)
			) . ';',
			'before'
		);
	}

	/**
	 * Print the dialog, hidden, at the foot of the plugins screen.
	 *
	 * @return void
	 */
	public static function render_dialog() {
		if ( 'plugins.php' !== self::current_hook() || ! self::should_ask() ) {
			return;
		}
		?>
		<div id="segurium-deact-modal" class="segurium-deact-modal" style="display:none;" role="dialog" aria-modal="true" aria-labelledby="segurium-deact-title">
			<div class="segurium-deact-overlay"></div>
			<div class="segurium-deact-box">
				<div class="segurium-deact-head">
					<h2 id="segurium-deact-title"><?php esc_html_e( 'Why are you deactivating Segurium?', 'segurium' ); ?></h2>
					<button type="button" class="segurium-deact-close" aria-label="<?php esc_attr_e( 'Close', 'segurium' ); ?>">&times;</button>
				</div>
				<div class="segurium-deact-body">
					<ul class="segurium-deact-reasons">
						<?php foreach ( self::reasons() as $reason ) : ?>
							<li>
								<label>
									<input type="radio" name="segurium_deact_reason" value="<?php echo esc_attr( $reason ); ?>">
									<?php echo esc_html( self::reason_label( $reason ) ); ?>
								</label>
							</li>
						<?php endforeach; ?>
					</ul>
					<p class="segurium-deact-detail">
						<label for="segurium-deact-detail"><?php esc_html_e( 'Note (optional, max 2000 chars)', 'segurium' ); ?></label>
						<textarea id="segurium-deact-detail" rows="3" maxlength="<?php echo esc_attr( (string) self::DETAIL_MAX ); ?>"></textarea>
					</p>
				</div>
				<div class="segurium-deact-foot">
					<button type="button" class="button button-primary" id="segurium-deact-submit" disabled><?php esc_html_e( 'Continue', 'segurium' ); ?></button>
					<button type="button" class="button" id="segurium-deact-skip"><?php esc_html_e( 'Skip', 'segurium' ); ?></button>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Validate one answer and mirror it to the cloud.
	 *
	 * Every rejection carries its own code so a failure in the field is
	 * identifiable from the response alone.
	 *
	 * @param string $reason One of {@see reasons()}.
	 * @param string $detail Free note. Sanitised and capped here.
	 * @return true|WP_Error
	 */
	public static function record( $reason, $detail = '' ) {
		$reason = (string) $reason;

		if ( ! in_array( $reason, self::reasons(), true ) ) {
			return new WP_Error( self::ERR_UNKNOWN_REASON );
		}
		if ( Segurium_Storage::setting_get_bool( self::OPTION_ASKED ) ) {
			return new WP_Error( self::ERR_ALREADY_ASKED );
		}
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return new WP_Error( self::ERR_NO_CONSENT );
		}
		if ( null === Segurium_IID::get_iid() ) {
			return new WP_Error( self::ERR_NO_IID );
		}

		$sent = Segurium_Storage::cti_send_message(
			self::CTI_MESSAGE_TYPE,
			array_merge(
				array(
					'reason' => $reason,
					'detail' => self::clean_detail( $detail ),
				),
				self::install_context()
			)
		);

		// The message queue posts non-blocking, so this catches a request
		// the client could not build, not an unreachable CTI.
		if ( ! $sent ) {
			return new WP_Error( self::ERR_QUEUE_FAILED );
		}

		// Claimed only on a message that left. A queue failure leaves the
		// ask armed for the next attempt rather than burning the one
		// chance this install gets.
		Segurium_Storage::setting_set( self::OPTION_ASKED, 1 );

		return true;
	}

	/**
	 * AJAX handler. The central dispatcher verifies the nonce and the
	 * capability before this runs; both are repeated here because the
	 * handler must stand on its own when read in isolation.
	 *
	 * @return void
	 */
	public static function ajax_deactivation_reason() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$reason = isset( $_POST['reason'] ) ? sanitize_key( wp_unslash( $_POST['reason'] ) ) : '';
		$detail = isset( $_POST['detail'] ) ? sanitize_textarea_field( wp_unslash( $_POST['detail'] ) ) : '';

		$result = self::record( $reason, $detail );

		if ( is_wp_error( $result ) ) {
			segurium_send_json_error(
				array( 'error_code' => $result->get_error_code() ),
				self::status_for( $result->get_error_code() )
			);
		}

		segurium_send_json_success( array( 'recorded' => true ) );
	}

	/**
	 * HTTP status for one refusal.
	 *
	 * Only a queue failure is a 503. The other three describe permanent
	 * states of this install, and answering them with a service-unavailable
	 * code puts a false outage in every log scan and uptime probe that
	 * reads admin-ajax status codes.
	 *
	 * @param string $code One of the ERR_* constants.
	 * @return int
	 */
	private static function status_for( $code ) {
		switch ( $code ) {
			case self::ERR_UNKNOWN_REASON:
				return 400;
			case self::ERR_ALREADY_ASKED:
				return 409;
			case self::ERR_NO_CONSENT:
			case self::ERR_NO_IID:
				return 412;
			default:
				return 503;
		}
	}

	/**
	 * Translated label for one reason.
	 *
	 * `Other` reuses the catalogue's existing string; the other five are
	 * this feature's own.
	 *
	 * @param string $reason One of {@see reasons()}.
	 * @return string
	 */
	private static function reason_label( $reason ) {
		switch ( $reason ) {
			case self::REASON_MISSING_FEATURE:
				return __( 'Missing feature', 'segurium' );
			case self::REASON_CAUSING_ISSUES:
				return __( 'It is causing issues', 'segurium' );
			case self::REASON_NO_LONGER_NEEDED:
				return __( 'No longer needed', 'segurium' );
			case self::REASON_FOUND_ALTERNATIVE:
				return __( 'Found better alternative', 'segurium' );
			case self::REASON_TEMPORARY:
				return __( 'Temporary deactivation', 'segurium' );
			default:
				return __( 'Other', 'segurium' );
		}
	}

	/**
	 * Sanitise and cap the free note.
	 *
	 * @param string $detail Raw note.
	 * @return string
	 */
	private static function clean_detail( $detail ) {
		$detail = sanitize_textarea_field( (string) $detail );

		// Characters, not bytes. A byte-wise cut can land inside a UTF-8
		// sequence, and wp_json_encode() then returns false for the whole
		// payload rather than a truncated note.
		return mb_substr( $detail, 0, self::DETAIL_MAX );
	}

	/**
	 * What this install did before it decided to leave.
	 *
	 * All three come from local tables, so they measure what the site
	 * still holds rather than the whole life of the install: the
	 * activity log is pruned at 90 days by default.
	 *
	 * @return array<string, int>
	 */
	private static function install_context() {
		return array(
			'days_installed' => self::days_installed(),
			'scans'          => self::scan_count(),
			'cleanups'       => self::cleanup_count(),
		);
	}

	/**
	 * Whole days since the first activation, 0 when unstamped.
	 *
	 * @return int
	 */
	private static function days_installed() {
		if ( ! class_exists( 'Segurium_Review_Prompt' ) ) {
			return 0;
		}
		$since = Segurium_Storage::setting_get_int( Segurium_Review_Prompt::OPTION_FIRST_ACTIVATION_AT, 0 );
		if ( $since <= 0 ) {
			return 0;
		}

		return max( 0, (int) floor( ( time() - $since ) / DAY_IN_SECONDS ) );
	}

	/**
	 * Scans this install still has history for.
	 *
	 * @return int
	 */
	private static function scan_count() {
		return (int) Segurium_Storage::table_get_var(
			'scan_history',
			'SELECT COUNT(*) FROM {{table}}'
		);
	}

	/**
	 * Malware cures this install still has log lines for.
	 *
	 * @return int
	 */
	private static function cleanup_count() {
		return (int) Segurium_Storage::table_get_var(
			'activity_log',
			'SELECT COUNT(*) FROM {{table}} WHERE event_type = %s',
			array( 'malware_cured' )
		);
	}

	/**
	 * Current admin page hook suffix, empty outside the admin.
	 *
	 * @return string
	 */
	private static function current_hook() {
		global $hook_suffix;

		return isset( $hook_suffix ) ? (string) $hook_suffix : '';
	}

	/**
	 * Cache-busting asset version, mirroring the main admin surface.
	 *
	 * @param string $relative Path relative to the plugin root.
	 * @return string
	 */
	private static function asset_version( $relative ) {
		$path  = SEGURIUM_PLUGIN_DIR . $relative;
		$mtime = file_exists( $path ) ? (int) filemtime( $path ) : 0;

		return $mtime > 0 ? SEGURIUM_VERSION . '.' . $mtime : SEGURIUM_VERSION;
	}
}

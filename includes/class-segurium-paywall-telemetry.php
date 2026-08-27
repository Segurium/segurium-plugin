<?php
/**
 * Quota-wall CTA telemetry.
 *
 * The cleanup quota wall is the only place a Free install meets the paid
 * offer. Whether the operator looked at that offer is not derivable from
 * anything else we record: the upgrade link lands on a local admin page,
 * and the billing vendor only reports visits for installs that completed
 * an opt-in, which this plugin skips for everyone.
 *
 * So the wall reports its own impressions. Three events over two
 * surfaces, on the existing message queue. No new transport, no new
 * table, no personal data — the payload is the closed enum pair plus the
 * quota envelope that produced the impression.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Closed-set validation and reporting for quota-wall CTA events.
 */
final class Segurium_Paywall_Telemetry {

	const NONCE_ACTION     = 'segurium_paywall_cta';
	const AJAX_ACTION      = 'segurium_paywall_cta';
	const CTI_MESSAGE_TYPE = 'paywall_cta';

	const EVENT_SHOWN     = 'shown';
	const EVENT_CLICKED   = 'clicked';
	const EVENT_DISMISSED = 'dismissed';

	const SURFACE_MODAL   = 'modal';
	const SURFACE_READOUT = 'readout';
	const SURFACE_PRICING = 'pricing';

	/**
	 * Submenu slug of the embedded pricing page, as the tail of a WP
	 * screen id. WordPress builds a submenu screen id from the sanitised
	 * parent menu *title*, which is translated, so only this suffix is
	 * stable across locales.
	 */
	const PRICING_SCREEN_SUFFIX = '_page_segurium-pricing';

	const ACTION_CLEANUP     = 'cleanup';
	const ACTION_MALWARE_FIX = 'malware_fix';

	const OPTION_LAST_WALL = 'segurium_paywall_last_wall';

	/**
	 * How long a stamped wall stays the authority for the quota fields.
	 * The impression follows the refusal within seconds; anything older
	 * belongs to a wall the operator has already walked away from.
	 */
	const WALL_STAMP_TTL = 15 * MINUTE_IN_SECONDS;

	const ERR_UNKNOWN_EVENT   = 'paywall_cta_unknown_event';
	const ERR_UNKNOWN_SURFACE = 'paywall_cta_unknown_surface';
	const ERR_UNKNOWN_ACTION  = 'paywall_cta_unknown_action';
	const ERR_NO_CONSENT      = 'paywall_cta_no_consent';
	const ERR_NO_IID          = 'paywall_cta_no_iid';
	const ERR_QUEUE_FAILED    = 'paywall_cta_queue_failed';

	/**
	 * Events the wall may report.
	 *
	 * @return array<int, string>
	 */
	public static function events() {
		return array( self::EVENT_SHOWN, self::EVENT_CLICKED, self::EVENT_DISMISSED );
	}

	/**
	 * Surfaces that carry a CTA.
	 *
	 * @return array<int, string>
	 */
	public static function surfaces() {
		return array( self::SURFACE_MODAL, self::SURFACE_READOUT, self::SURFACE_PRICING );
	}

	/**
	 * Wire the pricing-page impression. Idempotent.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'current_screen', array( __CLASS__, 'on_current_screen' ), 10, 1 );
	}

	/**
	 * Report an impression when the embedded pricing page renders.
	 *
	 * The vendor cannot tell us this. Its own event tracking returns
	 * early for an install that is not registered, and the plugin skips
	 * that registration for everyone, so a pricing visit reaches nobody
	 * unless we record it here.
	 *
	 * @param object|null $screen Current screen, as passed by WordPress.
	 * @return void
	 */
	public static function on_current_screen( $screen ) {
		if ( ! is_object( $screen ) || ! isset( $screen->id ) ) {
			return;
		}
		if ( ! self::is_pricing_screen( (string) $screen->id ) ) {
			return;
		}
		self::record( self::EVENT_SHOWN, self::SURFACE_PRICING, '' );
	}

	/**
	 * Whether a screen id belongs to the embedded pricing page.
	 *
	 * Pure so the match is testable without forging screen state.
	 *
	 * @param string $screen_id WP screen id.
	 * @return bool
	 */
	public static function is_pricing_screen( $screen_id ) {
		$screen_id = (string) $screen_id;
		$suffix    = self::PRICING_SCREEN_SUFFIX;
		$offset    = strlen( $screen_id ) - strlen( $suffix );

		return $offset > 0 && strpos( $screen_id, $suffix, $offset ) === $offset;
	}

	/**
	 * Remediation actions that can raise the modal. The empty string is
	 * also valid: the quota readout and the pricing page have no
	 * originating action, and a dismissal is not tied to one either.
	 *
	 * @return array<int, string>
	 */
	public static function action_types() {
		return array( '', self::ACTION_CLEANUP, self::ACTION_MALWARE_FIX );
	}

	/**
	 * Validate one CTA event and mirror it to the cloud.
	 *
	 * Every rejection carries its own code so a failure in the field is
	 * identifiable from the response alone. None carries a message: the
	 * only caller is a beacon whose response the browser discards, so a
	 * translatable string here would cost every locale a round of work on
	 * text nobody can read.
	 *
	 * @param string $event       One of events().
	 * @param string $surface     One of surfaces().
	 * @param string $action_type One of action_types().
	 * @return true|WP_Error
	 */
	public static function record( $event, $surface, $action_type ) {
		$event       = (string) $event;
		$surface     = (string) $surface;
		$action_type = (string) $action_type;

		if ( ! in_array( $event, self::events(), true ) ) {
			return new WP_Error( self::ERR_UNKNOWN_EVENT );
		}
		if ( ! in_array( $surface, self::surfaces(), true ) ) {
			return new WP_Error( self::ERR_UNKNOWN_SURFACE );
		}
		if ( ! in_array( $action_type, self::action_types(), true ) ) {
			return new WP_Error( self::ERR_UNKNOWN_ACTION );
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
					'event'         => $event,
					'surface'       => $surface,
					'action_type'   => $action_type,
					'cta_available' => self::cta_available(),
				),
				self::quota_snapshot()
			)
		);

		// The message queue posts non-blocking, so this catches a request
		// the client could not build, not an unreachable CTI. A cloud
		// outage is invisible here by design — the queue owns delivery.
		if ( ! $sent ) {
			return new WP_Error( self::ERR_QUEUE_FAILED );
		}

		return true;
	}

	/**
	 * Record the envelope a refusal carried, for the impression that is
	 * about to follow it.
	 *
	 * Deliberately not written into the quota cache. That cache is served
	 * ahead of a CTI read for its whole soft TTL, so seeding it from a
	 * refusal would hide a plan flip from the readout and from the next
	 * cleanup response — an operator who upgrades at the wall would keep
	 * seeing Free. This stamp is read by telemetry and by nothing else.
	 *
	 * @param array $envelope Quota envelope from the refusal.
	 * @return void
	 */
	public static function stamp_wall( $envelope ) {
		if ( ! is_array( $envelope ) ) {
			return;
		}
		Segurium_Storage::setting_set(
			self::OPTION_LAST_WALL,
			array(
				'used'        => isset( $envelope['used'] ) ? (int) $envelope['used'] : 0,
				'limit'       => isset( $envelope['limit'] ) ? (int) $envelope['limit'] : 0,
				'window_days' => isset( $envelope['window_days'] ) ? (int) $envelope['window_days'] : 0,
				'at'          => time(),
			)
		);
	}

	/**
	 * Whether an upgrade destination existed at the moment of the event.
	 *
	 * The modal paints whether or not the billing SDK resolved a pricing
	 * URL, and with none it offers a Close button instead of Upgrade. Those
	 * impressions carry no offer, so leaving them unmarked would put them
	 * in the click-through denominator and understate it.
	 *
	 * @return int 1 when the CTA had a destination, 0 otherwise.
	 */
	private static function cta_available() {
		if ( ! class_exists( 'Segurium_Entitlements' ) ) {
			return 0;
		}
		return '' === Segurium_Entitlements::instance()->upgrade_url() ? 0 : 1;
	}

	/**
	 * Quota fields for the payload, read from the cached envelope only.
	 *
	 * Prefers the envelope the refusal itself carried, since the shared
	 * quota cache is not updated on a refusal and still reads one slot
	 * short of the wall the operator just hit. Never refreshes either
	 * source: a telemetry write must not put a network hop in front of
	 * the user's click. `quota_known` separates a genuine 0/0 from an
	 * install with neither a stamp nor an envelope.
	 *
	 * @return array<string, int|string>
	 */
	private static function quota_snapshot() {
		$source = self::fresh_wall_stamp();
		if ( null === $source ) {
			$source = Segurium_Quota::cached_envelope();
		}

		if ( ! is_array( $source ) ) {
			return array(
				'quota_known' => 0,
				'used'        => 0,
				'limit'       => 0,
				'window_days' => 0,
				'plan_tier'   => 'unknown',
			);
		}

		return array(
			'quota_known' => 1,
			'used'        => isset( $source['used'] ) ? (int) $source['used'] : 0,
			'limit'       => isset( $source['limit'] ) ? (int) $source['limit'] : 0,
			'window_days' => isset( $source['window_days'] ) ? (int) $source['window_days'] : 0,
			'plan_tier'   => Segurium_Quota::plan_tier(),
		);
	}

	/**
	 * The stamped wall, or null when there is none inside the TTL.
	 *
	 * @return array<string, int>|null
	 */
	private static function fresh_wall_stamp() {
		$stamp = Segurium_Storage::setting_get_array( self::OPTION_LAST_WALL, array() );
		if ( empty( $stamp['at'] ) ) {
			return null;
		}
		$age = time() - (int) $stamp['at'];
		if ( $age < 0 || $age > self::WALL_STAMP_TTL ) {
			return null;
		}
		return $stamp;
	}

	/**
	 * AJAX shim. The central dispatcher verifies the nonce and the
	 * capability before this runs; both are repeated here because the
	 * handler must stand on its own when read in isolation.
	 *
	 * @return void
	 */
	public static function ajax_paywall_cta() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}

		$event       = isset( $_POST['cta_event'] ) ? sanitize_key( wp_unslash( $_POST['cta_event'] ) ) : '';
		$surface     = isset( $_POST['cta_surface'] ) ? sanitize_key( wp_unslash( $_POST['cta_surface'] ) ) : '';
		$action_type = isset( $_POST['cta_action_type'] ) ? sanitize_key( wp_unslash( $_POST['cta_action_type'] ) ) : '';

		$result = self::record( $event, $surface, $action_type );

		if ( is_wp_error( $result ) ) {
			$client_error = in_array(
				$result->get_error_code(),
				array( self::ERR_UNKNOWN_EVENT, self::ERR_UNKNOWN_SURFACE, self::ERR_UNKNOWN_ACTION ),
				true
			);
			segurium_send_json_error(
				array(
					'error_code' => $result->get_error_code(),
				),
				$client_error ? 400 : 503
			);
		}

		segurium_send_json_success( array( 'recorded' => true ) );
	}
}

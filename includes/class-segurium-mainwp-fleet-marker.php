<?php
/**
 * MainWP fleet marker (SEGURIUM-880).
 *
 * The MainWP epic (SEGURIUM-876) is judged on one number: Segurium
 * child-site installs attributable to MainWP, as opposed to installs of the
 * dashboard extension itself. A few hundred extension installs is the
 * realistic ceiling; a few hundred agency dashboards times ~35 client sites
 * each is the prize. Only the second number decides whether the epic was
 * worth building, and nothing measured it before this.
 *
 * So: the first time the MainWP bridge answers a dashboard call, this
 * install records that it is fleet-managed and reports it to Cloud Threat
 * Inspection as a `mainwp_fleet` message. A site that never sees a MainWP
 * dashboard never records anything.
 *
 * The report is counts only. It carries no dashboard URL and no key
 * material: MainWP generates a keypair per child site, so the child's copy
 * of the dashboard key would identify the child rather than the agency, and
 * the dashboard's URL identifies a business. The agency dimension is already
 * available server-side by grouping on `client_ip`, which is how the first
 * fleet event on record was spotted.
 *
 * Sending never happens on the request the dashboard is waiting on. The
 * bridge answers a synchronous MainWP call while the dashboard walks a whole
 * fleet, so an outbound hop there would multiply one screen refresh by the
 * size of the fleet. Marking writes options and queues a one-off event; the
 * send happens on that event.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Records and reports that this install is managed from a MainWP dashboard.
 */
final class Segurium_MainWP_Fleet_Marker {

	/**
	 * Message type. Cloud Threat Inspection rejects an unlisted type with a
	 * 400, so this string is a contract, not a label.
	 */
	const CTI_MESSAGE_TYPE = 'mainwp_fleet';

	/**
	 * One-off event that carries the report.
	 */
	const CRON_HOOK = 'segurium_mainwp_fleet_report';

	const OPT_FIRST_SEEN  = 'segurium_mainwp_first_seen';
	const OPT_LAST_SEEN   = 'segurium_mainwp_last_seen';
	const OPT_CALLS       = 'segurium_mainwp_calls';
	const OPT_REPORTED_AT = 'segurium_mainwp_reported_at';

	/**
	 * How often a still-managed site repeats its report. The repeat is what
	 * turns a one-off event into a "still fleet-managed" signal, so a site
	 * that leaves a dashboard stops counting instead of counting forever.
	 */
	const REPORT_INTERVAL = WEEK_IN_SECONDS;

	/**
	 * Delay before the queued report fires. Long enough that a burst of
	 * dashboard calls settles into one send.
	 */
	const REPORT_DELAY = MINUTE_IN_SECONDS;

	/**
	 * Attach the cron listener. Without it the scheduled event fires into
	 * nothing and the KPI never arrives.
	 *
	 * @return void
	 */
	public static function register() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'report' ) );
	}

	/**
	 * Record one answered dashboard call.
	 *
	 * @return void
	 */
	public static function observe() {
		$now = time();

		if ( 0 === self::first_seen() ) {
			Segurium_Storage::setting_set( self::OPT_FIRST_SEEN, $now );
		}

		Segurium_Storage::setting_set( self::OPT_LAST_SEEN, $now );
		Segurium_Storage::setting_set( self::OPT_CALLS, self::calls() + 1 );

		self::maybe_schedule();
	}

	/**
	 * Whether this install has ever answered a MainWP dashboard.
	 *
	 * @return bool
	 */
	public static function is_marked() {
		return self::first_seen() > 0;
	}

	/**
	 * Current marker state. Reading helper for tests and support.
	 *
	 * @return array<string, int>
	 */
	public static function state() {
		return array(
			'first_seen'  => self::first_seen(),
			'last_seen'   => Segurium_Storage::setting_get_int( self::OPT_LAST_SEEN, 0 ),
			'calls'       => self::calls(),
			'reported_at' => Segurium_Storage::setting_get_int( self::OPT_REPORTED_AT, 0 ),
		);
	}

	/**
	 * Cron callback: send the report.
	 *
	 * Stamps the send only when the transport accepted it, so a failed hop
	 * is retried on the next call rather than looking like a success.
	 *
	 * @return void
	 */
	public static function report() {
		if ( ! self::is_marked() ) {
			return;
		}
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}
		if ( ! self::report_due() ) {
			return;
		}

		$sent = Segurium_Storage::cti_send_message( self::CTI_MESSAGE_TYPE, self::payload() );

		if ( $sent ) {
			Segurium_Storage::setting_set( self::OPT_REPORTED_AT, time() );
		}
	}

	/**
	 * Drop any queued report. Called on deactivation.
	 *
	 * @return void
	 */
	public static function unschedule() {
		$next = wp_next_scheduled( self::CRON_HOOK );
		while ( false !== $next ) {
			wp_unschedule_event( $next, self::CRON_HOOK );
			$next = wp_next_scheduled( self::CRON_HOOK );
		}
	}

	/**
	 * Forget everything this marker recorded.
	 *
	 * @return void
	 */
	public static function purge() {
		foreach (
			array(
				self::OPT_FIRST_SEEN,
				self::OPT_LAST_SEEN,
				self::OPT_CALLS,
				self::OPT_REPORTED_AT,
			) as $option
		) {
			Segurium_Storage::setting_delete( $option );
		}
	}

	/**
	 * Counts only. Every value is an integer, by design — this is the one
	 * place where adding a field would need re-reading against the
	 * "no new personal data" constraint on SEGURIUM-880.
	 *
	 * @return array<string, int>
	 */
	private static function payload() {
		return array(
			'first_seen'      => self::first_seen(),
			'last_seen'       => Segurium_Storage::setting_get_int( self::OPT_LAST_SEEN, 0 ),
			'calls'           => self::calls(),
			'child_connected' => Segurium_MainWP_Bridge::is_child_connected() ? 1 : 0,
		);
	}

	/**
	 * Queue the report when one is owed and none is already waiting.
	 *
	 * @return void
	 */
	private static function maybe_schedule() {
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}
		if ( ! self::report_due() ) {
			return;
		}
		if ( false !== wp_next_scheduled( self::CRON_HOOK ) ) {
			return;
		}

		wp_schedule_single_event( time() + self::REPORT_DELAY, self::CRON_HOOK );
	}

	/**
	 * Whether a report is owed.
	 *
	 * @return bool
	 */
	private static function report_due() {
		$last = Segurium_Storage::setting_get_int( self::OPT_REPORTED_AT, 0 );

		return $last <= 0 || ( time() - $last ) >= self::REPORT_INTERVAL;
	}

	/**
	 * When this install first answered a dashboard.
	 *
	 * @return int
	 */
	private static function first_seen() {
		return Segurium_Storage::setting_get_int( self::OPT_FIRST_SEEN, 0 );
	}

	/**
	 * How many dashboard calls have been answered.
	 *
	 * @return int
	 */
	private static function calls() {
		return Segurium_Storage::setting_get_int( self::OPT_CALLS, 0 );
	}
}

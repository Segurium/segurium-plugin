<?php
/**
 * Installation ID registration and retrieval.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates and registers a unique installation identifier with CTI.
 */
class Segurium_IID {

	const OPTION_SEED   = 'segurium_iid_seed';
	const OPTION_TOKEN  = 'segurium_iid_token';
	const REGISTER_PATH = '/v1/iid/register';

	/**
	 * Set when CTI returns HTTP 409 `re_register` so the next
	 * `admin_init` can re-register asynchronously instead of paying the
	 * 15s register POST inside whatever request the 409 short-circuited.
	 */
	const OPTION_REREGISTER_PENDING = 'segurium_iid_reregister_pending';

	/**
	 * Set when `POST /v1/billing/sync` returns
	 * HTTP 409 `binding_conflict` — the license is currently bound to a
	 * different installation. Surfaces an admin banner that tells the user
	 * to deactivate the license on the original install via the Freemius
	 * account portal; the unbind webhook then frees the license and the
	 * next sync resolves cleanly.
	 */
	const OPTION_BILLING_CONFLICT_PENDING = 'segurium_billing_conflict_pending';

	/**
	 * Register with CTI if not already registered.
	 *
	 * Enforced consent gate. wp.org submission rules forbid
	 * any unsolicited contact with an external service. Self::register()
	 * POSTs site URL, site name and WP version to CTI; gating it here
	 * makes every transitive caller (Segurium_CTI_Client::ensure_iid(),
	 * the IID_REGISTER_CRON_HOOK, deactivation messages) safe by default,
	 * not just the explicit consent path.
	 */
	public static function maybe_register() {
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}
		if ( Segurium_Storage::setting_get_string( self::OPTION_TOKEN ) ) {
			return;
		}
		self::register();
	}

	/**
	 * Register a new installation ID with CTI.
	 *
	 * @return bool True on success, false on failure.
	 */
	public static function register() {
		$commitment = self::get_commitment();
		$url        = Segurium_Storage::cti_endpoint( 'base' ) . self::REGISTER_PATH;

		// Alerts contact fields. Sent on every register so a
		// fresh install with the checkbox already on (e.g. via WP-CLI seed
		// or import) lands its contact on CTI without a separate round-trip.
		$alerts_payload = self::alerts_payload();
		$body           = array(
			'commitment'  => $commitment,
			'site_name'   => get_bloginfo( 'name' ),
			'site_url'    => home_url(),
			// wp-admin lives under site_url(), not home_url(), on
			// "WordPress in its own directory" installs; the digest
			// links to the scanner page through this.
			'admin_url'   => admin_url(),
			'wp_version'  => get_bloginfo( 'version' ),
			// Tag non-production environments so analytics
			// dashboards exclude this install from production metrics.
			// `wp_get_environment_type()` returns one of `local`,
			// `development`, `staging`, `production` (default
			// `production` if unset). CTI propagates the flag onto every
			// event row — see CTI feature 65.
			'is_test'     => 'production' !== wp_get_environment_type(),
			// Server-side anchor written once on register, then
			// validated on every authenticated request via X-Fingerprint
			// (see Segurium_CTI_Client::request). The four fields together
			// distinguish a clone of `wp_options` from the original install.
			'fingerprint' => self::fingerprint(),
		);
		if ( null !== $alerts_payload ) {
			$body = array_merge( $body, $alerts_payload );
		}

		// CTI listens on TCP/8901 — see Segurium_CTI_Client class docblock for why wp_safe_remote_* cannot be used here.
		$response = wp_remote_post(
			$url,
			array(
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $body ),
				'timeout' => 15,
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 201 !== $code ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! isset( $body['iid'] ) || ! is_string( $body['iid'] ) || '' === $body['iid'] ) {
			return false;
		}

		Segurium_Storage::setting_set( self::OPTION_TOKEN, sanitize_text_field( $body['iid'] ) );
		Segurium_Storage::setting_delete( self::OPTION_REREGISTER_PENDING );
		return true;
	}

	/**
	 * Fingerprint sent at register time and on every
	 * authenticated CTI request. CTI anchors the four fields on the first
	 * register and bounces any subsequent request whose fingerprint
	 * differs.
	 *
	 * `server_name` falls back to the home_url host when `$_SERVER` is
	 * unpopulated (CLI / wp-cli without `--url`) so the fingerprint stays
	 * stable across request contexts on the same install.
	 *
	 * @return array{home_url:string,home_url_hash:string,server_name:string,db_host:string}
	 */
	public static function fingerprint() {
		$server_name = isset( $_SERVER['SERVER_NAME'] )
			? sanitize_text_field( wp_unslash( (string) $_SERVER['SERVER_NAME'] ) )
			: '';
		if ( '' === $server_name ) {
			$host        = wp_parse_url( home_url(), PHP_URL_HOST );
			$server_name = is_string( $host ) ? $host : '';
		}
		return array(
			'home_url'      => home_url(),
			'home_url_hash' => hash( 'sha256', home_url() ),
			'server_name'   => $server_name,
			'db_host'       => defined( 'DB_HOST' ) ? (string) DB_HOST : '',
		);
	}

	/**
	 * Base64-STANDARD of the fingerprint JSON, ready for the
	 * `X-Fingerprint` header. Matches the wire format the CTI knock
	 * middleware decodes.
	 */
	public static function fingerprint_header() {
		return base64_encode( wp_json_encode( self::fingerprint() ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- intentional wire format.
	}

	/**
	 * Handle a CTI 409 `re_register` response. Drops the
	 * stored IID and the cached quota envelope (so Pro tier collapses to
	 * Free locally until Freemius webhook re-binds against the new IID,
	 * or the user re-activates the license and sync runs)
	 * and arms the pending flag the admin_init hook drains.
	 *
	 * Re-register is intentionally NOT performed here — the request that
	 * just got 409'd is some random hot path; we don't want a 15s blocking
	 * register POST inside it.
	 */
	public static function mark_reregister_pending() {
		self::clear();
		if ( class_exists( 'Segurium_Quota' ) ) {
			Segurium_Storage::setting_delete( Segurium_Quota::OPTION_LAST_ENVELOPE );
		}
		Segurium_Storage::setting_set( self::OPTION_REREGISTER_PENDING, 1 );
	}

	/** MySQL named-lock key serialising concurrent
	 * `process_pending_reregister` calls on the same install. */
	const REREGISTER_LOCK_NAME = 'segurium_reregister';

	/**
	 * Entry point for the admin_init hook. Re-registers when the
	 * pending flag is set; consent gate matches `maybe_register()` so a
	 * site that has not yet accepted the External Service Disclosure
	 * stays silent and the flag persists for a future admin load that
	 * happens after consent is given.
	 *
	 * Concurrent admin pageloads can each race past the
	 * pending-flag check and fire their own `register()` POST in
	 * parallel — we saw 7 distinct registrations in 356 ms
	 * from a single site. A non-blocking MySQL `GET_LOCK` collapses
	 * those races to a single winner; losers return immediately and
	 * the pending flag stays armed for the next admin_init tick (which
	 * finds the IID already present and exits via `register()`'s
	 * post-success flag clear).
	 */
	public static function process_pending_reregister() {
		if ( ! Segurium_Storage::setting_get_bool( self::OPTION_REREGISTER_PENDING ) ) {
			return;
		}
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			return;
		}

		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- session-bound advisory lock has no SQL helper and is intentionally uncacheable.
		$lock_acquired = $wpdb->get_var(
			$wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', self::REREGISTER_LOCK_NAME )
		);
		// `GET_LOCK` returns 1 on success, 0 on timeout, NULL on error.
		// Anything other than the string "1" means another connection
		// holds the lock or the server doesn't support named locks; in
		// both cases we no-op and let the lock holder do the register.
		if ( '1' !== (string) $lock_acquired ) {
			return;
		}

		try {
			// Re-check the pending flag under the lock — the holder
			// from a moments-earlier admin_init may have already
			// cleared it via a successful register().
			if ( ! Segurium_Storage::setting_get_bool( self::OPTION_REREGISTER_PENDING ) ) {
				return;
			}
			self::register();
		} finally {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- session-bound advisory lock release; matches the GET_LOCK above.
			$wpdb->get_var(
				$wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::REREGISTER_LOCK_NAME )
			);
		}
	}

	/**
	 * Handler for the admin_notices hook. Tells the admin the
	 * install just re-registered with the cloud service after a site
	 * move/clone, and (for Pro installs) prompts re-activation of the
	 * license — the new IID is not yet tied to the previous Freemius
	 * binding, so Pro features stay collapsed locally until either the
	 * vendor webhook re-binds the license or the operator re-activates
	 * it from the plugin's account screen.
	 *
	 * Stays neutral — no internal mechanism naming per repo policy.
	 */
	public static function render_reregister_notice() {
		if ( ! Segurium_Storage::setting_get_bool( self::OPTION_REREGISTER_PENDING ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html__(
				'Segurium detected this site was moved or cloned and is re-establishing its secure connection in the background. If you have a Pro license, please re-activate it on the Segurium account screen so Pro features are restored on the new identity.',
				'segurium'
			)
		);
	}

	/**
	 * Arm the binding-conflict banner. Called by the
	 * `/v1/billing/sync` caller when CTI returns HTTP 409
	 * `binding_conflict` — the license is bound to a different IID and
	 * the local install cannot transition into Pro until the user
	 * deactivates on the original install.
	 */
	public static function mark_billing_conflict_pending() {
		Segurium_Storage::setting_set( self::OPTION_BILLING_CONFLICT_PENDING, time() );
	}

	/** Seconds the admin-load reconciler waits after a refused bind
	 * before it retries `/v1/billing/sync`. */
	const BILLING_CONFLICT_RETRY_AFTER = 3600;

	/**
	 * True while the last binding conflict is younger than
	 * `BILLING_CONFLICT_RETRY_AFTER`. The admin-load reconciler skips
	 * the sync inside that window so a held license does not turn
	 * every Segurium page load into a refused round trip.
	 *
	 * @return bool
	 */
	public static function billing_conflict_retry_held() {
		$marked_at = Segurium_Storage::setting_get_int( self::OPTION_BILLING_CONFLICT_PENDING );
		return $marked_at > 0 && ( time() - $marked_at ) < self::BILLING_CONFLICT_RETRY_AFTER;
	}

	/**
	 * Drop the binding-conflict banner. Called by the
	 * `/v1/billing/sync` caller on a 2xx response so a
	 * stale banner cannot outlive the conflict that produced it.
	 */
	public static function clear_billing_conflict_pending() {
		Segurium_Storage::setting_delete( self::OPTION_BILLING_CONFLICT_PENDING );
	}

	/**
	 * Handler for the admin_notices binding-conflict surface.
	 * Tells the user the license is currently held by another install
	 * and that deactivating it from the Freemius account portal will
	 * release the binding (the vendor webhook then frees CTI's record
	 * and the next local sync resolves the conflict).
	 *
	 * Stays neutral — no internal mechanism naming per repo policy.
	 */
	public static function render_billing_conflict_notice() {
		if ( ! Segurium_Storage::setting_get_bool( self::OPTION_BILLING_CONFLICT_PENDING ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%s</p></div>',
			esc_html__(
				'Segurium could not activate the Pro license on this site because it is currently bound to another installation. Please open the Segurium account portal on the original installation and deactivate the license there; the binding will be released and Pro features will re-activate here on the next license check.',
				'segurium'
			)
		);
	}

	/**
	 * Operator escape hatch behind `wp segurium iid reset`.
	 * Drops the IID, the cached quota envelope, and any stuck
	 * binding-conflict banner, then arms the re-register
	 * pending flag so the next `admin_init` re-registers (subject to the
	 * same consent gate as `maybe_register()`).
	 *
	 * Returns a per-step summary the CLI surfaces back to the operator
	 * so support can confirm what was actually cleared.
	 *
	 * @return array{
	 *     iid_cleared:bool,
	 *     quota_envelope_cleared:bool,
	 *     billing_conflict_cleared:bool,
	 *     reregister_armed:bool,
	 * }
	 */
	public static function reset_for_recovery() {
		$had_iid              = null !== self::get_iid();
		$had_envelope         = false;
		$had_billing_conflict = Segurium_Storage::setting_get_bool( self::OPTION_BILLING_CONFLICT_PENDING );

		if ( class_exists( 'Segurium_Quota' ) ) {
			$had_envelope = null !== Segurium_Quota::cached_envelope();
		}

		self::mark_reregister_pending();
		if ( $had_billing_conflict ) {
			self::clear_billing_conflict_pending();
		}

		return array(
			'iid_cleared'              => $had_iid,
			'quota_envelope_cleared'   => $had_envelope,
			'billing_conflict_cleared' => $had_billing_conflict,
			'reregister_armed'         => true,
		);
	}

	/**
	 * Retrieve the stored installation ID.
	 *
	 * @return string|null Installation ID or null if not registered.
	 */
	public static function get_iid() {
		$token = Segurium_Storage::setting_get_string( self::OPTION_TOKEN );
		return '' === $token ? null : $token;
	}

	/**
	 * Delete the stored installation ID.
	 */
	public static function clear() {
		Segurium_Storage::setting_delete( self::OPTION_TOKEN );
	}

	/**
	 * Generate or retrieve the commitment hash for registration.
	 *
	 * @return string SHA-256 commitment hash.
	 */
	public static function get_commitment() {
		$seed = Segurium_Storage::setting_get_string( self::OPTION_SEED );
		if ( '' === $seed ) {
			$seed = bin2hex( random_bytes( 32 ) );
			Segurium_Storage::setting_set( self::OPTION_SEED, $seed );
		}
		return hash( 'sha256', hex2bin( $seed ) );
	}

	/**
	 * Helper. Build the alerts contact fields for either the
	 * `/v1/iid/register` body or a `settings_snapshot` push.
	 *
	 * Returns `null` when the operator has not configured a usable email —
	 * caller skips the alerts block entirely so CTI keeps `alerts_opt_in`
	 * as it was, rather than churning the contact record.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function alerts_payload() {
		$alerts = Segurium_Alerts_Settings::get();
		$opt_in = (bool) $alerts['enabled'];
		$email  = (string) $alerts['email'];
		if ( '' === $email || false === strpos( $email, '@' ) ) {
			return null;
		}
		$tier = self::current_tier();
		$loc  = (string) get_locale();
		// Strip the variant suffix (e.g. `en_US` → `en`); CTI is English-only
		// for MVP and the field is captured for forward compat.
		if ( '' !== $loc ) {
			$loc = strtolower( substr( $loc, 0, 2 ) );
		} else {
			$loc = 'en';
		}
		return array(
			'admin_email'   => sanitize_email( $email ),
			'alerts_opt_in' => $opt_in,
			'tier'          => $tier,
			'locale'        => $loc,
		);
	}

	/**
	 * Current Pro/Free tier sourced from the
	 * cached CTI quota envelope. Returns `'pro'` or `'free'`; any
	 * unexpected condition resolves to Free so we never send Pro upsell
	 * copy to an install we can't classify.
	 */
	private static function current_tier() {
		if ( ! class_exists( 'Segurium_Quota' ) ) {
			return 'free';
		}
		try {
			return Segurium_Quota::plan_tier();
		} catch ( Throwable $e ) {
			return 'free';
		}
	}
}

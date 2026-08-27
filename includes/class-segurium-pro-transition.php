<?php
/**
 * Plugin-side reaction to Freemius license transitions.
 *
 * The Freemius SDK polls the vendor API in the background (and on certain
 * admin requests) and fires `after_license_change` whenever the local
 * install transitions between plans. This class subscribes to that hook,
 * recomputes the Pro entitlement, and:
 *
 *   - on a flip into Pro:    resets the cleanup quota ledger (so the
 *                            customer gets a clean slate), appends a
 *                            `pro_activated` row to activity_log, and
 *                            tells CTI via send_message().
 *   - on a flip out of Pro:  appends `pro_deactivated` and tells CTI.
 *                            Past Pro actions are NOT undone — re-locking
 *                            happens naturally on the next entitlement
 *                            check.
 *
 * Idempotency is keyed off the post-transition entitlement state stored
 * in `segurium_pro_state`: if the recomputed `is_pro` matches what we
 * already persisted, the handler is a no-op. This collapses duplicate
 * SDK firings (and the safety-net hourly polling) to a single effect.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Listens to Freemius license transitions and applies plugin-side effects.
 */
final class Segurium_Pro_Transition {

	const OPTION_STATE          = 'segurium_pro_state';
	const EVENT_PRO_ACTIVATED   = 'pro_activated';
	const EVENT_PRO_DEACTIVATED = 'pro_deactivated';

	/**
	 * Process-wide singleton.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Accessor that returns a Segurium_Entitlements (or compatible) instance.
	 *
	 * @var callable
	 */
	private $entitlements_accessor;

	/**
	 * Accessor that returns a Segurium_Quota (or compatible) instance.
	 *
	 * @var callable
	 */
	private $quota_accessor;

	/**
	 * Accessor that returns a Segurium_CTI_Client (or compatible) instance.
	 *
	 * @var callable
	 */
	private $cti_client_accessor;

	/**
	 * Accessor that returns the Freemius SDK instance, or null.
	 *
	 * @var callable
	 */
	private $sdk_accessor;

	/**
	 * Construct a transition listener.
	 *
	 * All accessors are pluggable so unit tests can drive the listener
	 * without a live Freemius SDK or storage backend. In production each
	 * accessor defaults to the matching singleton / global.
	 *
	 * @param callable|null $entitlements_accessor Returns Segurium_Entitlements (or compatible).
	 * @param callable|null $quota_accessor        Returns Segurium_Quota (or compatible).
	 * @param callable|null $cti_client_accessor   Returns Segurium_CTI_Client (or compatible).
	 * @param callable|null $sdk_accessor          Returns the Freemius SDK instance (or null).
	 */
	public function __construct(
		$entitlements_accessor = null,
		$quota_accessor = null,
		$cti_client_accessor = null,
		$sdk_accessor = null
	) {
		$this->entitlements_accessor = is_callable( $entitlements_accessor )
			? $entitlements_accessor
			: static function () {
				return class_exists( 'Segurium_Entitlements' )
					? Segurium_Entitlements::instance()
					: null;
			};

		$this->quota_accessor = is_callable( $quota_accessor )
			? $quota_accessor
			: static function () {
				return class_exists( 'Segurium_Quota' )
					? Segurium_Quota::instance()
					: null;
			};

		$this->cti_client_accessor = is_callable( $cti_client_accessor )
			? $cti_client_accessor
			: static function () {
				return class_exists( 'Segurium_CTI_Client' )
					? new Segurium_CTI_Client()
					: null;
			};

		$this->sdk_accessor = is_callable( $sdk_accessor )
			? $sdk_accessor
			: static function () {
				return function_exists( 'segurium_fs' ) ? segurium_fs() : null;
			};
	}

	/**
	 * Process-wide singleton.
	 *
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Test-only: drop the singleton.
	 */
	public static function reset_for_testing() {
		self::$instance = null;
	}

	/**
	 * Test-only: install a pre-built listener as the singleton.
	 *
	 * @param self $instance Pre-built listener.
	 */
	public static function set_instance_for_testing( self $instance ) {
		self::$instance = $instance;
	}

	/**
	 * Subscribe `on_license_change` to the SDK's `after_license_change`
	 * action. Returns true on success, false when the SDK is unavailable
	 * (e.g., during tests, or when the bootstrap failed).
	 *
	 * @return bool
	 */
	public function register_hooks() {
		$fs = $this->load_sdk();
		if ( ! is_object( $fs ) || ! method_exists( $fs, 'add_action' ) ) {
			return false;
		}
		try {
			$fs->add_action( 'after_license_change', array( $this, 'on_license_change' ) );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-pro-transition] add_action failed: ' . $e->getMessage() );
			return false;
		}
		add_action( 'load-toplevel_page_segurium', array( $this, 'reconcile_on_admin_load' ) );
		return true;
	}

	/**
	 * Deterministic post-checkout reconciliation.
	 *
	 * The Freemius `after_license_change` hook fires when the SDK
	 * detects a license change in-flight, but on the checkout-iframe →
	 * return-URL bounce the SDK has already persisted the license by
	 * the time the hook would run, so it can be skipped. Without a
	 * backstop the cached envelope stays at Free until a scan
	 * completes, the 5-minute SWR TTL expires, or a webhook drains.
	 *
	 * Cached-tier read goes first because it's the cheapest predicate
	 * and the steady-state Pro path can short-circuit before touching
	 * the SDK; the SDK call only runs when the envelope is still Free
	 * and is the discriminator for "did the user actually pay?".
	 */
	public function reconcile_on_admin_load() {
		if ( class_exists( 'Segurium_Quota' )
			&& Segurium_Quota::PLAN_TIER_PRO === Segurium_Quota::plan_tier()
		) {
			return;
		}

		try {
			if ( ! $this->is_pro_from_sdk() ) {
				return;
			}
		} catch ( Throwable $e ) {
			return;
		}

		$this->safe_billing_sync();
	}

	/**
	 * Freemius SDK callback. The SDK passes `($plan_change, $plan)`. The
	 * decision (Pro yes/no) is taken from the entitlement read after the
	 * SDK has already updated its own state; `$plan_change` and the
	 * `$plan` slug are recorded for audit context only.
	 *
	 * @param string $plan_change One of activated|upgraded|changed|downgraded|cancelled|expired|extended|trial_*.
	 * @param mixed  $plan        FS_Plugin_Plan|null. We extract its slug if we can.
	 */
	public function on_license_change( $plan_change = '', $plan = null ) {
		$plan_slug = '';
		if ( is_object( $plan ) && isset( $plan->name ) ) {
			$plan_slug = (string) $plan->name;
		}
		// Read Pro state directly from the Freemius SDK on
		// the license-change hook. The cached CTI quota envelope is the
		// production source of truth for the rest of the plugin, but it
		// has not flipped yet — this handler is what *causes* the flip
		// (via safe_billing_sync / safe_refresh_quota_envelope below).
		// Asking Entitlements::can() here would always return the
		// pre-transition tier and the binding work would never run.
		try {
			$is_pro_now = $this->is_pro_from_sdk();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-pro-transition] entitlement read failed: ' . $e->getMessage() );
			return;
		}

		$previous = $this->load_state();
		$was_pro  = ! empty( $previous['is_pro'] );

		if ( $is_pro_now === $was_pro ) {
			return;
		}

		if ( $is_pro_now ) {
			// Race-resolver sync. On success the response
			// body carries the fresh quota envelope so we skip the
			// follow-up `/v1/quota/state` round-trip; on any other
			// outcome (missing tuple, transport failure, server reject)
			// we still ask CTI for current state so the dashboard
			// counter reflects whatever it last witnessed.
			if ( ! $this->safe_billing_sync() ) {
				$this->safe_refresh_quota_envelope();
			}
			$this->append_activity_log( self::EVENT_PRO_ACTIVATED, (string) $plan_change, $plan_slug );
			$this->safe_send_cti( self::EVENT_PRO_ACTIVATED, (string) $plan_change, $plan_slug );
		} else {
			// Pro→Free transitions originate at Freemius and reach CTI via
			// the vendor webhook (its pending-events drain
			// re-applies them on the next sync). The plugin no longer
			// has a license tuple to send, so we just refresh the local
			// cache against whatever CTI currently reports.
			$this->safe_refresh_quota_envelope();
			$this->append_activity_log( self::EVENT_PRO_DEACTIVATED, (string) $plan_change, $plan_slug );
			$this->safe_send_cti( self::EVENT_PRO_DEACTIVATED, (string) $plan_change, $plan_slug );
		}

		$this->save_state(
			array(
				'is_pro'      => $is_pro_now,
				'updated_at'  => time(),
				'last_change' => (string) $plan_change,
				'plan_slug'   => $plan_slug,
			)
		);
	}

	/**
	 * Diagnostic: snapshot of the persisted transition state, plus the
	 * current entitlement read. Used by the WP-CLI command in support
	 * triage ("did Pro actually flip on this site?").
	 *
	 * @return array{persisted:array,is_pro_now:bool,sdk_loaded:bool}
	 */
	public function dump() {
		$persisted = $this->load_state();
		$fs        = $this->load_sdk();
		$loaded    = is_object( $fs );
		$is_pro    = false;
		if ( $loaded ) {
			try {
				$is_pro = $this->is_pro_from_sdk();
			} catch ( Throwable $e ) {
				$loaded = false;
			}
		}
		return array(
			'persisted'  => $persisted,
			'is_pro_now' => $is_pro,
			'sdk_loaded' => $loaded,
		);
	}

	/**
	 * Read Pro state from the Freemius SDK. Used only by
	 * `on_license_change` (the SDK literally just fired with new state)
	 * and `dump()` (operator triage). The rest of the plugin reads the
	 * envelope via Segurium_Entitlements / Segurium_Quota.
	 *
	 * @return bool
	 */
	private function is_pro_from_sdk() {
		$fs = $this->load_sdk();
		if ( ! is_object( $fs ) || ! method_exists( $fs, 'is_paying' ) ) {
			return false;
		}
		return (bool) $fs->is_paying();
	}

	/**
	 * Race-resolver sync. Forwards the Freemius
	 * `(install_id, install_secret_key, license_id, license_key)` tuple
	 * to `/v1/billing/sync`; CTI cross-checks every field against the
	 * Freemius developer API before binding. On success we cache the
	 * envelope from the response so the caller can skip a follow-up
	 * `/v1/quota/state` round-trip.
	 *
	 * Returns true only on a cached envelope. Tuple-missing, transport
	 * failure, malformed response, or any HTTP non-2xx all return false
	 * so the caller can fall back to a plain refresh — the next webhook
	 * arrival drains pending events at the next sync (ADR §2.3 step 5),
	 * so a missed bind is recoverable.
	 *
	 * @return bool
	 */
	private function safe_billing_sync() {
		try {
			$tuple = $this->extract_license_tuple();
			if ( null === $tuple ) {
				Segurium_Debug::log( '[segurium-pro-transition] billing_sync skipped: code=tuple_missing — FS did not yield install_id/install_secret_key/license_id/license_key' );
				return false;
			}
			$client = $this->load_cti();
			if ( null === $client || ! method_exists( $client, 'billing_sync' ) ) {
				Segurium_Debug::log( '[segurium-pro-transition] billing_sync skipped: code=cti_client_unavailable — Segurium_CTI_Client missing billing_sync method' );
				return false;
			}
			$resp = $client->billing_sync(
				$tuple['install_id'],
				$tuple['install_secret_key'],
				$tuple['license_id'],
				$tuple['license_key']
			);
			if ( ! is_array( $resp ) ) {
				Segurium_Debug::log( sprintf( '[segurium-pro-transition] billing_sync failed: code=cti_response_invalid type=%s — CTI /v1/billing/sync returned non-array (HTTP non-2xx, transport error, or malformed JSON)', gettype( $resp ) ) );
				return false;
			}
			$quota = $this->load_quota();
			if ( null === $quota || ! method_exists( $quota, 'apply_billing_sync_envelope' ) ) {
				Segurium_Debug::log( '[segurium-pro-transition] billing_sync failed: code=quota_unavailable — Segurium_Quota missing apply_billing_sync_envelope method' );
				return false;
			}
			$applied = (bool) $quota->apply_billing_sync_envelope( $resp );
			if ( ! $applied ) {
				Segurium_Debug::log( '[segurium-pro-transition] billing_sync failed: code=envelope_rejected — CTI returned 200 but apply_billing_sync_envelope refused the payload' );
			}
			return $applied;
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-pro-transition] billing_sync failed: code=exception — ' . $e->getMessage() );
			return false;
		}
	}

	/**
	 * Refresh the cached quota envelope so the plugin UI
	 * reflects the new plan tier within one round-trip rather than
	 * waiting for the next dashboard load. Soft failure — `Quota::refresh()`
	 * already swallows its own errors, this just bridges through the
	 * accessor and tolerates a missing dependency.
	 */
	private function safe_refresh_quota_envelope() {
		try {
			$quota = $this->load_quota();
			if ( null !== $quota && method_exists( $quota, 'refresh' ) ) {
				$quota->refresh();
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-pro-transition] quota refresh failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Pull the Freemius identity tuple needed for
	 * `/v1/billing/sync` out of the SDK. The install secret_key
	 * (`$site->secret_key`) is the proof-of-ownership field that
	 * replaced the old plugin-supplied `fs_user_id` claim — it lives in
	 * the WP site's wp_options and only that site can produce it.
	 *
	 * Returns `null` when the SDK is unavailable or any field isn't
	 * populated (e.g. anonymous install) — the caller skips the sync
	 * in that case.
	 *
	 * @return array{install_id:string,install_secret_key:string,license_id:string,license_key:string}|null
	 */
	private function extract_license_tuple() {
		$fs = $this->load_sdk();
		if ( null === $fs ) {
			return null;
		}
		$site    = method_exists( $fs, 'get_site' ) ? $fs->get_site() : null;
		$license = method_exists( $fs, '_get_license' ) ? $fs->_get_license() : null;
		if ( ! is_object( $site ) || ! is_object( $license ) ) {
			return null;
		}
		$install_id         = isset( $site->id ) ? (string) $site->id : '';
		$install_secret_key = isset( $site->secret_key ) ? (string) $site->secret_key : '';
		$license_id         = isset( $license->id ) ? (string) $license->id : '';
		$license_key        = isset( $license->secret_key ) ? (string) $license->secret_key : '';
		if ( '' === $install_id || '' === $install_secret_key || '' === $license_id || '' === $license_key ) {
			return null;
		}
		return array(
			'install_id'         => $install_id,
			'install_secret_key' => $install_secret_key,
			'license_id'         => $license_id,
			'license_key'        => $license_key,
		);
	}

	/**
	 * Notify CTI of the transition; swallow any failure.
	 *
	 * @param string $message_type One of pro_activated|pro_deactivated.
	 * @param string $plan_change  Raw Freemius plan_change tag for audit.
	 * @param string $plan_slug    Resolved plan slug (e.g. "pro"), if any.
	 */
	private function safe_send_cti( $message_type, $plan_change, $plan_slug ) {
		try {
			$client = $this->load_cti();
			if ( null !== $client && method_exists( $client, 'send_message' ) ) {
				$client->send_message(
					$message_type,
					wp_json_encode(
						array(
							'plan_change' => (string) $plan_change,
							'plan_slug'   => (string) $plan_slug,
						)
					)
				);
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-pro-transition] cti send_message failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Append a row to activity_log; swallow any failure.
	 *
	 * @param string $event_type   pro_activated|pro_deactivated.
	 * @param string $plan_change  Raw Freemius plan_change tag for audit.
	 * @param string $plan_slug    Resolved plan slug (e.g. "pro"), if any.
	 */
	private function append_activity_log( $event_type, $plan_change, $plan_slug ) {
		if ( ! class_exists( 'Segurium_Storage' ) ) {
			return;
		}
		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => (string) $event_type,
					'severity'   => 0,
					'subject'    => null,
					'data_json'  => (string) wp_json_encode(
						array(
							'plan_change' => (string) $plan_change,
							'plan_slug'   => (string) $plan_slug,
						)
					),
					'created_at' => time(),
				)
			);
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-pro-transition] activity_log insert failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Read the persisted transition state via the storage façade.
	 *
	 * @return array
	 */
	private function load_state() {
		$raw = Segurium_Storage::setting_get_array( self::OPTION_STATE, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * Persist the new transition state via the storage façade.
	 *
	 * @param array $state The state record.
	 */
	private function save_state( array $state ) {
		Segurium_Storage::setting_set( self::OPTION_STATE, $state, false );
	}

	/**
	 * Resolve the entitlements service via the injected accessor.
	 *
	 * @return Segurium_Entitlements|object|null
	 */
	private function load_entitlements() {
		try {
			$accessor = $this->entitlements_accessor;
			$obj      = $accessor();
		} catch ( Throwable $e ) {
			return null;
		}
		return is_object( $obj ) ? $obj : null;
	}

	/**
	 * Resolve the quota service via the injected accessor.
	 *
	 * @return Segurium_Quota|object|null
	 */
	private function load_quota() {
		try {
			$accessor = $this->quota_accessor;
			$obj      = $accessor();
		} catch ( Throwable $e ) {
			return null;
		}
		return is_object( $obj ) ? $obj : null;
	}

	/**
	 * Resolve the CTI client via the injected accessor.
	 *
	 * @return Segurium_CTI_Client|object|null
	 */
	private function load_cti() {
		try {
			$accessor = $this->cti_client_accessor;
			$obj      = $accessor();
		} catch ( Throwable $e ) {
			return null;
		}
		return is_object( $obj ) ? $obj : null;
	}

	/**
	 * Resolve the Freemius SDK instance via the injected accessor.
	 *
	 * @return object|null
	 */
	private function load_sdk() {
		try {
			$accessor = $this->sdk_accessor;
			$fs       = $accessor();
		} catch ( Throwable $e ) {
			return null;
		}
		return is_object( $fs ) ? $fs : null;
	}
}

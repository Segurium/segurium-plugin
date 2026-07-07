<?php
/**
 * Remediation quota gate (SEGURIUM-65).
 *
 * Every remediation request hits CTI; CTI is the sole rate-limiter and
 * applies the right per-plan cap (Free: 3 actions / 30-day rolling
 * window; Pro: effectively unbounded). Removing the local Pro short-
 * circuit (SEGURIUM-341) is what brings the plugin in line with WP.org
 * Guideline 5 — the artifact runs identical code for every install.
 *
 * Fail-open policy: if CTI is unreachable the request is allowed. The
 * intent is "quota is a soft paywall, not a security boundary"; blocking
 * customers when our backend is down would be hostile.
 *
 * @package Segurium
 * @since   SEGURIUM-65
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Single front door for "may this remediation proceed?" checks.
 */
final class Segurium_Quota {

	/**
	 * Action types accepted by the CTI quota endpoint. The values are
	 * the wire-level strings; do not rename without coordinating with
	 * the CTI side (`service/src/quota.rs::parse_action`).
	 */
	const ACTION_CLEANUP     = 'cleanup';
	const ACTION_MALWARE_FIX = 'malware_fix';

	/**
	 * Default Free-tier values. These are advisory — the canonical
	 * source is the CTI response, which carries `limit` and
	 * `window_days` on every reply.
	 */
	const DEFAULT_LIMIT       = 3;
	const DEFAULT_WINDOW_DAYS = 30;

	/**
	 * Plan-tier strings carried in the envelope (SEGURIUM-348). Match
	 * the CTI wire format exactly — see `service/src/quota.rs::PlanTier`.
	 */
	const PLAN_TIER_FREE = 'free';
	const PLAN_TIER_PRO  = 'pro';

	/**
	 * Entitlement-flag bag (SEGURIUM-348). Key set must stay in lock-step
	 * with `service/src/quota.rs::Entitlements`; every envelope-emitting
	 * code path must include every key (quota-state-key-parity.md).
	 */
	const ENTITLEMENT_KEYS = array(
		'unlimited_cleanup',
		'auto_fix',
		'fix_all',
	);

	/**
	 * Default Free-tier entitlement bag, used when CTI has not spoken
	 * yet (first install, fail-open, malformed response). Mirrors
	 * `Entitlements::for_tier(Free)` on the CTI side — under Serviceware
	 * (SEGURIUM-340), every plugin install runs every feature; only
	 * `unlimited_cleanup` is gated and is used purely for UI labelling.
	 */
	const DEFAULT_FREE_ENTITLEMENTS = array(
		'unlimited_cleanup' => false,
		'auto_fix'          => true,
		'fix_all'           => true,
	);

	/**
	 * Persistent cache of the most recent CTI-sourced envelope so the
	 * admin page can render the readout server-side at load time without
	 * a synchronous CTI hop. Refreshed on every consume() / state() that
	 * actually reaches CTI; never written for Pro or fail-open envelopes.
	 */
	const OPTION_LAST_ENVELOPE = 'segurium_quota_last_envelope';

	/**
	 * SEGURIUM-302: how long a cached envelope is considered fresh enough
	 * to serve from `state()` without scheduling a refresh. The dashboard
	 * counter is a soft paywall readout — a few minutes of staleness is
	 * acceptable, and the synchronous CTI hop was responsible for ~500ms
	 * of admin-ajax tail latency on every poll.
	 */
	const STATE_SOFT_TTL_SECS = 300;

	/**
	 * SEGURIUM-302: cron hook fired by `state()` when it serves a stale
	 * envelope. Runs `refresh()` out of band so the next poll lands on a
	 * fresh cache without the calling request paying the CTI cost.
	 */
	const CRON_REFRESH_HOOK = 'segurium_quota_state_refresh';

	/**
	 * Process-wide singleton.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Callable that returns a Segurium_CTI_Client. Pluggable for tests.
	 *
	 * @var callable
	 */
	private $client_accessor;

	/**
	 * Per-request cache of the most recent CTI state response. Keyed
	 * by the bare action — `consume('cleanup')` and `consume('malware_fix')`
	 * share the same on-server counter, so the latest response is
	 * always authoritative.
	 *
	 * @var array|null
	 */
	private $last_state = null;

	/**
	 * Construct a quota gate. Tests inject a fake CTI client.
	 *
	 * @param callable|null $client_accessor Returns Segurium_CTI_Client or null.
	 *                                       Defaults to a fresh client.
	 */
	public function __construct( $client_accessor = null ) {
		$this->client_accessor = is_callable( $client_accessor )
			? $client_accessor
			: static function () {
				return class_exists( 'Segurium_CTI_Client' )
					? new Segurium_CTI_Client()
					: null;
			};
	}

	/**
	 * Process-wide singleton.
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Test-only.
	 */
	public static function reset_for_testing() {
		self::$instance = null;
		Segurium_Storage::setting_delete( self::OPTION_LAST_ENVELOPE );
	}

	/**
	 * Last CTI-sourced envelope, or null when nothing has been cached
	 * yet (fresh install, or every prior call fail-opened). Returned in
	 * the same shape `state()` produces. Callers must treat the value
	 * as advisory — it is up to N minutes stale until the next AJAX
	 * refresh lands.
	 *
	 * @return array|null
	 */
	public static function cached_envelope() {
		$cached = Segurium_Storage::setting_get( self::OPTION_LAST_ENVELOPE, null );
		if ( ! is_array( $cached ) || ! isset( $cached['used'], $cached['limit'], $cached['window_days'] ) ) {
			return null;
		}
		return $cached;
	}

	/**
	 * Plan tier reported by the most recent CTI envelope. Falls back to
	 * Free when no envelope is cached yet — the conservative default
	 * (matches what every install ships with before CTI flips the IID).
	 *
	 * Renderers should prefer this over poking Freemius directly: it
	 * keeps the plugin code identical for Free and Pro installs (WP.org
	 * Guideline 5 — Serviceware) and reflects webhook-driven plan
	 * transitions within one envelope refresh.
	 *
	 * @return string Either self::PLAN_TIER_FREE or self::PLAN_TIER_PRO.
	 */
	public static function plan_tier() {
		$env = self::cached_envelope();
		if ( is_array( $env ) && isset( $env['plan_tier'] ) ) {
			$tier = strtolower( (string) $env['plan_tier'] );
			if ( self::PLAN_TIER_PRO === $tier || self::PLAN_TIER_FREE === $tier ) {
				return $tier;
			}
		}
		return self::PLAN_TIER_FREE;
	}

	/**
	 * Whether the cached envelope grants the named entitlement. Unknown
	 * keys return false. The entitlement bag is the only source the
	 * plugin should consult for "render Pro chrome here?" decisions.
	 *
	 * @param string $feature One of self::ENTITLEMENT_KEYS.
	 * @return bool
	 */
	public static function entitlement( $feature ) {
		if ( ! is_string( $feature ) || ! in_array( $feature, self::ENTITLEMENT_KEYS, true ) ) {
			return false;
		}
		$env = self::cached_envelope();
		if ( is_array( $env ) && isset( $env['entitlements'][ $feature ] ) ) {
			return (bool) $env['entitlements'][ $feature ];
		}
		return ! empty( self::DEFAULT_FREE_ENTITLEMENTS[ $feature ] );
	}

	/**
	 * Test-only: install a pre-built gate as the singleton so handlers
	 * that call `instance()` receive the stubbed entitlements/client
	 * without needing their own injection points.
	 *
	 * @param self $instance Pre-built quota gate.
	 */
	public static function set_instance_for_testing( self $instance ) {
		self::$instance = $instance;
	}

	/**
	 * SEGURIUM-353: `consume()` is gone. Slot accounting moved into
	 * `/v1/cleanup` on the CTI side. The only legitimate callers were
	 * the cleanup AJAX handler and the integrity-fix AJAX handler; both
	 * now go through {@see Segurium_Cleanup::cleanup_file()}, which
	 * surfaces the paywall envelope as a `WP_Error` on the cleanup
	 * primitive's return value. Keeping the symbol as a no-op would
	 * mask future regressions where someone re-introduces a pre-flight
	 * quota check, so it stays gone.
	 */

	/**
	 * Read-only state for the dashboard counter (SEGURIUM-207).
	 *
	 * SEGURIUM-302: stale-while-revalidate. A cached envelope (written
	 * by the previous CTI hit) is served immediately when within
	 * STATE_SOFT_TTL_SECS, eliminating the ~500ms tail-latency on the
	 * admin counter poll. When the cache is stale the cached value is
	 * still served — the caller never blocks — and a single-event
	 * wp-cron job is scheduled to refresh out of band. The synchronous
	 * CTI call only happens on first install (no cache yet); after that
	 * `consume()` keeps the cache rolling forward on every cleanup.
	 *
	 * @return array Same shape as consume().
	 */
	public function state() {
		$cached    = self::cached_envelope();
		$cached_at = is_array( $cached ) && isset( $cached['cached_at'] ) ? (int) $cached['cached_at'] : 0;
		$age       = time() - $cached_at;

		if ( null !== $cached ) {
			$this->last_state = $cached;
			if ( $cached_at > 0 && $age < self::STATE_SOFT_TTL_SECS ) {
				return $cached;
			}
			// Stale (or legacy envelope without cached_at): serve cached,
			// trigger a non-blocking refresh.
			$this->schedule_refresh();
			return $cached;
		}

		// First-time path: no cache to serve. Fall back to a synchronous
		// hop so the dashboard renders correct data on first paint.
		$client = $this->load_client();
		if ( null === $client ) {
			return $this->fail_open_envelope();
		}
		try {
			$resp = $client->quota_state();
		} catch ( Throwable $e ) {
			return $this->fail_open_envelope();
		}
		if ( is_wp_error( $resp ) ) {
			return $this->fail_open_envelope();
		}
		return $this->wrap_state( $resp );
	}

	/**
	 * SEGURIUM-378 / SEGURIUM-522: cache the envelope returned by
	 * `POST /v1/billing/sync` directly, so a Pro flip-in doesn't need a
	 * second `/v1/quota/state` round-trip to refresh the dashboard counter.
	 *
	 * SEGURIUM-522: CTI now embeds the canonical `/v1/quota/state` envelope
	 * under `resp['quota']`. Pass it through `wrap_state()` unchanged so
	 * `window_days` and `next_slot_at` reflect the server's real
	 * rolling-window state instead of being synthesised from the
	 * `period` + `used`/`remaining` triple (which forced `next_slot_at = 0`
	 * and rendered the dashboard banner as "next slot opens —").
	 *
	 * Back-compat: older CTI builds (pre-SEGURIUM-522) don't carry
	 * `resp['quota']`. Those falls back to the legacy synthesis so the
	 * cache still writes something the renderer can use, only without an
	 * accurate next-slot date.
	 *
	 * Returns true on cache write, false on a malformed response — the
	 * caller can fall back to a `refresh()` round-trip rather than leave
	 * the local cache stale.
	 *
	 * @param array $resp Decoded body of `/v1/billing/sync`.
	 * @return bool
	 */
	public function apply_billing_sync_envelope( $resp ) {
		if ( ! is_array( $resp ) ) {
			return false;
		}
		if ( isset( $resp['quota'] ) && is_array( $resp['quota'] ) ) {
			$this->wrap_state( $resp['quota'] );
			return true;
		}
		if ( ! isset( $resp['tier'], $resp['used'], $resp['remaining'] ) ) {
			return false;
		}
		$tier      = self::sanitize_plan_tier( $resp['tier'] );
		$used      = max( 0, (int) $resp['used'] );
		$remaining = max( 0, (int) $resp['remaining'] );
		$limit     = $used + $remaining;

		$period_start = 0;
		$period_end   = 0;
		if ( isset( $resp['period'] ) && is_array( $resp['period'] ) ) {
			$period_start = isset( $resp['period']['start'] ) ? (int) $resp['period']['start'] : 0;
			$period_end   = isset( $resp['period']['end'] ) ? (int) $resp['period']['end'] : 0;
		}

		// Free: period is the rolling-window. Pro: period is the license
		// validity span; window_days falls back to the default for the
		// (unused) Free counter copy.
		$window_days = self::DEFAULT_WINDOW_DAYS;
		$reset_at    = 0;
		if ( self::PLAN_TIER_FREE === $tier && $period_end > $period_start ) {
			$span        = $period_end - $period_start;
			$window_days = max( 1, (int) round( $span / 86400 ) );
			$reset_at    = $period_end;
		}

		$state = array(
			'allowed'      => 'pro' === $tier ? true : ( $used < $limit ),
			'used'         => $used,
			'limit'        => $limit,
			'window_days'  => $window_days,
			'next_slot_at' => 0,
			'reset_at'     => $reset_at,
			'plan_tier'    => $tier,
			// `wrap_state` derives `is_pro`, `entitlements`, `cached_at`,
			// `fail_open` for us — keep this method as the single mapper
			// from sync-shape to envelope-shape.
			'entitlements' => self::DEFAULT_FREE_ENTITLEMENTS,
		);
		$this->wrap_state( $state );
		return true;
	}

	/**
	 * SEGURIUM-409: record a successfully-paid cleanup slot in the cached
	 * envelope. CTI's `/v1/cleanup` is the slot-charging authority and
	 * the caller must only invoke this after a successful cleanup; the
	 * method then bumps the local cache so the post-clean readout is
	 * deterministic even when a follow-up `/v1/quota/state` round-trip
	 * would silently fail (transient transport blip, brief CTI outage)
	 * and leave the cached envelope frozen on its pre-clean value — the
	 * regression pinned by SEGURIUM-360.
	 *
	 * Falls back to a synchronous `refresh()` when the cache shape is
	 * not safe to bump (no envelope yet, fail-open placeholder, Pro
	 * tier whose `used` counter the readout never displays anyway).
	 *
	 * @return void
	 */
	public function record_consumed_slot() {
		$cached = self::cached_envelope();
		if ( null === $cached
			|| ! empty( $cached['fail_open'] )
			|| ! empty( $cached['is_pro'] )
		) {
			$this->refresh();
			return;
		}
		$cached['used']      = (int) $cached['used'] + 1;
		$cached['allowed']   = (int) $cached['used'] < (int) $cached['limit'];
		$cached['cached_at'] = time();
		$this->last_state    = $cached;
		Segurium_Storage::setting_set( self::OPTION_LAST_ENVELOPE, $cached );
	}

	/**
	 * SEGURIUM-549: apply the post-charge quota envelope CTI echoes in
	 * its `/v1/cleanup` 200 body directly to the cache. This is the
	 * authoritative replacement for {@see record_consumed_slot()} — the
	 * local bump only touches `used`/`allowed` and leaves `next_slot_at`
	 * frozen, so a cache warmed before the bucket filled (`next_slot_at = 0`)
	 * rendered the at-limit readout as "next slot opens —". The echoed
	 * envelope carries the server's real `next_slot_at`, so applying it
	 * gives the readout an accurate date in a single round-trip.
	 *
	 * The caller invokes this only when the cleanup response actually
	 * carried a `quota` echo (CTI ≥ SEGURIUM-549); older builds omit it
	 * and the caller falls back to {@see record_consumed_slot()}.
	 *
	 * @param array $envelope Echoed envelope (same shape as `/v1/quota/state`).
	 * @return bool True when applied, false when the envelope was malformed.
	 */
	public function apply_cleanup_envelope( $envelope ) {
		if ( ! is_array( $envelope ) ) {
			return false;
		}
		$this->wrap_state( $envelope );
		return true;
	}

	/**
	 * SEGURIUM-302: out-of-band cache refresh. Hooked to CRON_REFRESH_HOOK
	 * so wp-cron runs it in a separate request — the AJAX poll never
	 * blocks on this. Transport / HTTP failures are silent: we keep the
	 * prior cached envelope intact rather than overwriting it with a
	 * fail-open placeholder.
	 *
	 * @return void
	 */
	public function refresh() {
		$client = $this->load_client();
		if ( null === $client ) {
			return;
		}
		try {
			$resp = $client->quota_state();
		} catch ( Throwable $e ) {
			return;
		}
		if ( is_wp_error( $resp ) || ! is_array( $resp ) ) {
			return;
		}
		$this->wrap_state( $resp );
	}

	/**
	 * Queue a single-event wp-cron run of the refresh hook so the next
	 * loopback request rolls the cache forward. Idempotent — if a refresh
	 * is already scheduled we do not double-book.
	 *
	 * @return void
	 */
	private function schedule_refresh() {
		if ( ! wp_next_scheduled( self::CRON_REFRESH_HOOK ) ) {
			wp_schedule_single_event( time(), self::CRON_REFRESH_HOOK );
		}
	}

	/**
	 * Build the structured paywall payload for ajax error responses
	 * (SEGURIUM-207 modal). Use when consume() returned `allowed=false`.
	 *
	 * @param array $envelope Output of consume().
	 * @return array
	 */
	public static function paywall_payload( $envelope ) {
		return array(
			'code'  => 'paywall_quota_exceeded',
			'quota' => array(
				'limit'        => isset( $envelope['limit'] ) ? (int) $envelope['limit'] : self::DEFAULT_LIMIT,
				'window_days'  => isset( $envelope['window_days'] ) ? (int) $envelope['window_days'] : self::DEFAULT_WINDOW_DAYS,
				'used'         => isset( $envelope['used'] ) ? (int) $envelope['used'] : self::DEFAULT_LIMIT,
				'next_slot_at' => isset( $envelope['next_slot_at'] ) ? (int) $envelope['next_slot_at'] : 0,
			),
		);
	}

	/**
	 * Envelope returned when CTI is unreachable. Allows the action so
	 * we don't block customers when our backend is down.
	 *
	 * @return array
	 */
	private function fail_open_envelope() {
		$env              = array(
			'allowed'      => true,
			'used'         => 0,
			'limit'        => self::DEFAULT_LIMIT,
			'window_days'  => self::DEFAULT_WINDOW_DAYS,
			'next_slot_at' => 0,
			'reset_at'     => 0,
			'is_pro'       => false,
			'fail_open'    => true,
			// SEGURIUM-305: keep envelope shape uniform across all state()
			// return paths so consumers (test harness, batch endpoint)
			// compare keys regardless of which branch produced the value.
			'cached_at'    => 0,
			// SEGURIUM-343 / 348: the JS demux + PHP renderers read these on
			// every envelope. Free defaults are conservative — fail-open
			// shouldn't grant Pro chrome.
			'plan_tier'    => self::PLAN_TIER_FREE,
			'entitlements' => self::DEFAULT_FREE_ENTITLEMENTS,
		);
		$this->last_state = $env;
		return $env;
	}

	/**
	 * Coerce the raw CTI JSON into the canonical envelope shape.
	 *
	 * @param array $resp Raw decoded CTI response.
	 * @return array
	 */
	private function wrap_state( $resp ) {
		$plan_tier        = self::sanitize_plan_tier( isset( $resp['plan_tier'] ) ? $resp['plan_tier'] : null );
		$entitlements     = self::sanitize_entitlements(
			isset( $resp['entitlements'] ) ? $resp['entitlements'] : null,
			$plan_tier
		);
		$env              = array(
			'allowed'      => isset( $resp['allowed'] ) ? (bool) $resp['allowed'] : false,
			'used'         => isset( $resp['used'] ) ? (int) $resp['used'] : 0,
			'limit'        => isset( $resp['limit'] ) ? (int) $resp['limit'] : self::DEFAULT_LIMIT,
			'window_days'  => isset( $resp['window_days'] ) ? (int) $resp['window_days'] : self::DEFAULT_WINDOW_DAYS,
			'next_slot_at' => isset( $resp['next_slot_at'] ) ? (int) $resp['next_slot_at'] : 0,
			'reset_at'     => isset( $resp['reset_at'] ) ? (int) $resp['reset_at'] : 0,
			// SEGURIUM-343: legacy boolean kept for back-compat with the JS
			// demux's `envelope.is_pro` branch in renderQuotaReadout(); we now
			// derive it from the authoritative plan_tier so a single source
			// of truth wins even if a future CTI build forgets the legacy
			// flag.
			'is_pro'       => self::PLAN_TIER_PRO === $plan_tier,
			'fail_open'    => false,
			// SEGURIUM-302: freshness marker for the SWR path in state().
			'cached_at'    => time(),
			// SEGURIUM-343 / 348: authoritative plan + capability bag.
			'plan_tier'    => $plan_tier,
			'entitlements' => $entitlements,
		);
		$this->last_state = $env;
		Segurium_Storage::setting_set( self::OPTION_LAST_ENVELOPE, $env );
		return $env;
	}

	/**
	 * Coerce a raw plan_tier value into one of the accepted strings.
	 * Unknown values fall back to Free — see SEGURIUM-340 reasoning:
	 * Free is the conservative default that never grants Pro chrome.
	 *
	 * @param mixed $raw Raw value from the CTI response.
	 * @return string self::PLAN_TIER_FREE or self::PLAN_TIER_PRO.
	 */
	private static function sanitize_plan_tier( $raw ) {
		if ( is_string( $raw ) ) {
			$lower = strtolower( $raw );
			if ( self::PLAN_TIER_PRO === $lower ) {
				return self::PLAN_TIER_PRO;
			}
		}
		return self::PLAN_TIER_FREE;
	}

	/**
	 * Coerce the raw entitlements payload into the canonical key set.
	 * Missing keys fall back to the Free default, then are overridden by
	 * "always-on under Serviceware" features when the plan_tier is Pro
	 * — this keeps the bag stable even if CTI omits a key in a future
	 * build (quota-state-key-parity.md).
	 *
	 * @param mixed  $raw       Raw value from the CTI response (expected array).
	 * @param string $plan_tier Sanitized plan_tier (drives Pro overrides).
	 * @return array
	 */
	private static function sanitize_entitlements( $raw, $plan_tier ) {
		$bag = self::DEFAULT_FREE_ENTITLEMENTS;
		if ( is_array( $raw ) ) {
			foreach ( self::ENTITLEMENT_KEYS as $key ) {
				if ( array_key_exists( $key, $raw ) ) {
					$bag[ $key ] = (bool) $raw[ $key ];
				}
			}
		}
		if ( self::PLAN_TIER_PRO === $plan_tier ) {
			$bag['unlimited_cleanup'] = true;
		}
		return $bag;
	}

	/**
	 * Resolve the CTI client via the injected accessor.
	 *
	 * @return mixed Object or null on any failure.
	 */
	private function load_client() {
		try {
			$accessor = $this->client_accessor;
			$client   = $accessor();
		} catch ( Throwable $e ) {
			return null;
		}
		return is_object( $client ) ? $client : null;
	}
}

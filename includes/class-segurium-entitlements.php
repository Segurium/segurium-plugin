<?php
/**
 * Single source of truth for "is this user entitled to feature X?".
 *
 * SEGURIUM-343: thin facade over the CTI quota envelope's entitlement
 * flag bag. The plugin no longer reads Freemius locally to decide
 * feature availability — that's the WP.org Guideline 5 (Serviceware)
 * contract. Renderers call `can()`; we hand back whatever the envelope
 * says, defaulting to Free entitlements when no envelope is cached
 * yet.
 *
 * `upgrade_url()` keeps a Freemius dependency on purpose — it routes
 * the CTA to the embedded pricing page, which is a billing concern,
 * not a feature gate.
 *
 * @package Segurium
 * @since SEGURIUM-203
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Single source of truth for paid-feature checks.
 */
final class Segurium_Entitlements {

	/**
	 * Pro-only capabilities exposed to the rest of the plugin.
	 *
	 * The first two map onto entitlement-bag keys carried in the CTI
	 * quota envelope (`Segurium_Quota::ENTITLEMENT_KEYS`). `email_support`
	 * is plugin-local: it has no quota of its own, so we tie it to the
	 * envelope's `plan_tier` instead.
	 *
	 * @var string[]
	 */
	const FEATURES = array(
		'unlimited_cleanup',
		'auto_fix',
		'email_support',
	);

	/**
	 * Freemius plan slug for the Pro plan. Only used by `upgrade_url()`
	 * routing — renderers should read `plan_tier` from the envelope, not
	 * this constant.
	 */
	const PRO_PLAN_SLUG = 'pro';

	/**
	 * Process-wide singleton.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Callable that returns the Freemius instance, or null when the SDK
	 * is unavailable / unreachable. Used only by `upgrade_url()` —
	 * `can()` is envelope-driven and never touches Freemius.
	 *
	 * @var callable
	 */
	private $fs_accessor;

	/**
	 * Callable that returns the cached CTI quota envelope (or null when
	 * none is cached yet). Pluggable so tests can pin tier without
	 * priming the WP options table.
	 *
	 * @var callable
	 */
	private $envelope_accessor;

	/**
	 * Construct an entitlement resolver.
	 *
	 * @param callable|null $fs_accessor       Returns the Freemius instance or
	 *                                         null. Defaults to the global
	 *                                         segurium_fs() function. Used
	 *                                         only by upgrade_url().
	 * @param callable|null $envelope_accessor Returns the cached quota envelope
	 *                                         or null. Defaults to
	 *                                         Segurium_Quota::cached_envelope().
	 */
	public function __construct( $fs_accessor = null, $envelope_accessor = null ) {
		$this->fs_accessor       = is_callable( $fs_accessor )
			? $fs_accessor
			: static function () {
				return function_exists( 'segurium_fs' ) ? segurium_fs() : null;
			};
		$this->envelope_accessor = is_callable( $envelope_accessor )
			? $envelope_accessor
			: static function () {
				return class_exists( 'Segurium_Quota' )
					? Segurium_Quota::cached_envelope()
					: null;
			};
	}

	/**
	 * Process-wide singleton. Most callers should use this — the constructor
	 * is public only so tests can inject fakes.
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
	 * Test-only: drop the singleton and any cached state.
	 */
	public static function reset_for_testing() {
		self::$instance = null;
	}

	/**
	 * Test-only: install a pre-built entitlements resolver as the
	 * singleton so production handlers that call `instance()` pick up
	 * the stubbed accessors.
	 *
	 * @param self $instance Pre-built resolver.
	 */
	public static function set_instance_for_testing( self $instance ) {
		self::$instance = $instance;
	}

	/**
	 * Whether the current install is entitled to a specific feature.
	 *
	 * Reads the entitlement bag carried in the cached CTI quota envelope
	 * (SEGURIUM-348). When no envelope is cached yet (fresh install
	 * before the first /v1/quota/state hit) the conservative Free
	 * default applies — no Pro chrome rendered until CTI confirms.
	 *
	 * `email_support` has no dedicated bag key; it tracks the envelope's
	 * `plan_tier` so the support-link affordance only renders for Pro.
	 *
	 * @param string $feature One of self::FEATURES.
	 * @return bool
	 */
	public function can( $feature ) {
		if ( ! is_string( $feature ) || ! in_array( $feature, self::FEATURES, true ) ) {
			return false;
		}
		try {
			$accessor = $this->envelope_accessor;
			$env      = $accessor();
		} catch ( Throwable $e ) {
			return false;
		}
		if ( 'email_support' === $feature ) {
			return Segurium_Quota::PLAN_TIER_PRO === $this->plan_tier_from_envelope( $env );
		}
		if ( ! is_array( $env ) || ! isset( $env['entitlements'][ $feature ] ) ) {
			return ! empty( Segurium_Quota::DEFAULT_FREE_ENTITLEMENTS[ $feature ] );
		}
		return (bool) $env['entitlements'][ $feature ];
	}

	/**
	 * URL the "Upgrade to Pro" CTA should target, or '' when no working
	 * target is reachable.
	 *
	 * Routes through Freemius's embedded pricing page (admin.php?page=
	 * segurium-pricing). The page renders the Freemius pricing React app,
	 * which opens the in-WP checkout iframe on plan selection. Checkout
	 * has native gift-code / promo-code support. Anonymous installs are
	 * handled there too — Freemius collects the email at checkout time.
	 *
	 *   - SDK unloaded / throws          → ''
	 *   - pricing submenu not registered → '' (no synced paid plans;
	 *                                          there's nothing to show)
	 *   - otherwise                      → get_upgrade_url()
	 *
	 * @return string
	 */
	public function upgrade_url() {
		$fs = $this->load_sdk();
		if ( null === $fs ) {
			return '';
		}
		try {
			if ( method_exists( $fs, 'is_pricing_page_visible' ) && ! $fs->is_pricing_page_visible() ) {
				return '';
			}
			if ( ! method_exists( $fs, 'get_upgrade_url' ) ) {
				return '';
			}
			$url = (string) $fs->get_upgrade_url();
		} catch ( Throwable $e ) {
			return '';
		}
		return $url;
	}

	/**
	 * Diagnostic snapshot for the WP-CLI command and support tooling.
	 * Envelope-sourced post-SEGURIUM-343 so support sees the same
	 * `plan_tier` and entitlement bag the renderers do.
	 *
	 * @return array{envelope_cached:bool,plan_tier:string,features:array<string,bool>}
	 */
	public function dump() {
		try {
			$accessor = $this->envelope_accessor;
			$env      = $accessor();
		} catch ( Throwable $e ) {
			$env = null;
		}

		$features = array();
		foreach ( self::FEATURES as $feature ) {
			$features[ $feature ] = $this->can( $feature );
		}

		return array(
			'envelope_cached' => is_array( $env ),
			'plan_tier'       => $this->plan_tier_from_envelope( $env ),
			'features'        => $features,
		);
	}

	/**
	 * Read the plan_tier off the envelope, defaulting to Free. Mirrors
	 * `Segurium_Quota::plan_tier()` but works on a local snapshot so
	 * dump() doesn't double-read the option table.
	 *
	 * @param array|null $env Envelope array or null.
	 * @return string
	 */
	private function plan_tier_from_envelope( $env ) {
		if ( is_array( $env ) && isset( $env['plan_tier'] ) ) {
			$tier = strtolower( (string) $env['plan_tier'] );
			if ( Segurium_Quota::PLAN_TIER_PRO === $tier
				|| Segurium_Quota::PLAN_TIER_FREE === $tier ) {
				return $tier;
			}
		}
		return Segurium_Quota::PLAN_TIER_FREE;
	}

	/**
	 * Invoke the SDK accessor, swallowing any error so callers can rely on
	 * a strict null/object return.
	 *
	 * @return mixed Freemius instance or null.
	 */
	private function load_sdk() {
		try {
			$accessor = $this->fs_accessor;
			$fs       = $accessor();
		} catch ( Throwable $e ) {
			return null;
		}
		return is_object( $fs ) ? $fs : null;
	}
}

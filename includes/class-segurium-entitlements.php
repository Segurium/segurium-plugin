<?php
/**
 * Single source of truth for "is this user entitled to feature X?".
 *
 * Thin facade over the CTI quota envelope's entitlement
 * flag bag. The plugin no longer reads Freemius locally to decide
 * feature availability — that's the WP.org Guideline 5 (Serviceware)
 * contract. Renderers call `can()`; we hand back whatever the envelope
 * says, defaulting to Free entitlements when no envelope is cached
 * yet.
 *
 * `upgrade_url()` keeps a Freemius dependency on purpose — it routes
 * the CTA to the embedded pricing page, which is a billing concern,
 * not a feature gate. It never returns an empty string: when the SDK
 * yields nothing the CTA falls back to the public pricing page.
 *
 * @package Segurium
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
	 * Destination `upgrade_url()` returns when the billing SDK yields
	 * nothing. Points at the public pricing page the Plans tab already
	 * links in its footer note, so no new destination is introduced.
	 *
	 * The UTM tail keeps this source separable from the SDK-resolved
	 * checkout in the segurium.com funnel — the two reach the same page
	 * but describe very different installs.
	 */
	const FALLBACK_UPGRADE_URL = 'https://segurium.com/pricing/?utm_source=segurium-plugin&utm_medium=wp-admin&utm_campaign=upgrade-fallback';

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
	 * Reads the entitlement bag carried in the cached CTI quota envelope.
	 * When no envelope is cached yet (fresh install
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
	 * URL the "Upgrade to Pro" CTA should target. Never empty.
	 *
	 * Prefers Freemius's embedded pricing page (admin.php?page=
	 * segurium-pricing). The page renders the Freemius pricing React app,
	 * which opens the in-WP checkout iframe on plan selection. Checkout
	 * has native gift-code / promo-code support. Anonymous installs are
	 * handled there too — Freemius collects the email at checkout time.
	 *
	 * Every other outcome lands on self::FALLBACK_UPGRADE_URL. An install
	 * whose SDK is unloaded, throwing, or hiding its pricing submenu is
	 * still an install that can buy Pro on the website, and every caller
	 * of this method treats an empty return as "render no CTA at all" —
	 * a priced Pro card with no way to buy it.
	 *
	 *   - SDK unloaded / throws          → fallback
	 *   - pricing submenu not registered → fallback (no synced paid plans)
	 *   - get_upgrade_url() absent/empty → fallback
	 *   - otherwise                      → get_upgrade_url()
	 *
	 * @return string
	 */
	public function upgrade_url() {
		$fs = $this->load_sdk();
		if ( null === $fs ) {
			return self::FALLBACK_UPGRADE_URL;
		}
		try {
			if ( method_exists( $fs, 'is_pricing_page_visible' ) && ! $fs->is_pricing_page_visible() ) {
				return self::FALLBACK_UPGRADE_URL;
			}
			if ( ! method_exists( $fs, 'get_upgrade_url' ) ) {
				return self::FALLBACK_UPGRADE_URL;
			}
			$url = trim( (string) $fs->get_upgrade_url() );
		} catch ( Throwable $e ) {
			return self::FALLBACK_UPGRADE_URL;
		}
		return '' === $url ? self::FALLBACK_UPGRADE_URL : $url;
	}

	/**
	 * Submenu slug Freemius registers the embedded pricing page under.
	 * The same slug is the tail of that page's WP screen id.
	 */
	const PRICING_PAGE_SLUG = 'segurium-pricing';

	/**
	 * Whether an upgrade destination leaves wp-admin.
	 *
	 * The SDK's embedded pricing page does not; the fallback does. A
	 * click on an offsite destination must open a new tab, or it throws
	 * the operator out of the admin screen they were working on — mid
	 * scan, in the case of the paywall modal.
	 *
	 * Network admin counts as leaving. On a network-activated install the
	 * SDK builds its pricing URL through `network_admin_url()` even while
	 * the operator is inside a subsite, and on subdomain multisite that
	 * is a different host; following it in place discards the subsite
	 * screen exactly the way segurium.com would.
	 *
	 * @param string $url Destination from upgrade_url().
	 * @return bool
	 */
	public static function is_offsite_url( $url ) {
		$url = (string) $url;
		return '' !== $url && 0 !== strpos( $url, admin_url() );
	}

	/**
	 * Whether a destination is this plugin's own embedded pricing page.
	 *
	 * That page's render is what fires the `pricing` / `shown`
	 * impression, so this is the exact predicate for "the funnel can see
	 * what happens after this click". Everything else ends the funnel at
	 * the click: the public pricing page, the add-on URL the SDK returns
	 * for an add-on, and whatever a third party puts on the SDK's
	 * pricing-url filter.
	 *
	 * Independent of is_offsite_url(), and the two disagree on purpose.
	 * A URL can sit inside wp-admin without being the page we watch, and
	 * the network-admin copy of that page is both offsite (it leaves the
	 * subsite the operator was on) and observable — WordPress suffixes
	 * its screen id with `-network`, which
	 * `Segurium_Paywall_Telemetry::is_pricing_screen()` accepts.
	 *
	 * @param string $url Destination from upgrade_url().
	 * @return bool
	 */
	public static function is_embedded_pricing_url( $url ) {
		$url = (string) $url;
		if ( '' === $url ) {
			return false;
		}

		$under_admin = false;
		foreach ( array( admin_url(), network_admin_url() ) as $base ) {
			if ( 0 === strpos( $url, $base ) ) {
				$under_admin = true;
				break;
			}
		}
		if ( ! $under_admin ) {
			return false;
		}

		$query = (string) wp_parse_url( $url, PHP_URL_QUERY );
		$args  = array();
		parse_str( $query, $args );

		return isset( $args['page'] ) && self::PRICING_PAGE_SLUG === $args['page'];
	}

	/**
	 * Diagnostic snapshot for the WP-CLI command and support tooling.
	 * Envelope-sourced so support sees the same
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

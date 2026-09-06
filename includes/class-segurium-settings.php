<?php
/**
 * The settings registry: one row per feature, one option per feature.
 *
 * Every user-facing preference the plugin persists lives under a
 * `segurium_settings_<slug>` option holding an array. This class names each
 * feature once — option key, defaults, sanitiser, secret fields, pending
 * context, autoload policy and the legacy keys it replaced — and is the only
 * supported way to enumerate settings.
 *
 * A feature without a row here is invisible to `get_all()`, to the uninstall
 * manifest and to every fleet tool built on top of them, so the row is part of
 * shipping a settings feature.
 *
 * Runtime state (identity, scan progress, quota envelopes, telemetry stamps,
 * migration sentinels) is NOT a setting and stays out of the registry. Those
 * keys are listed in {@see Segurium_Settings::RUNTIME_KEYS} so uninstall still
 * removes them.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registry of every Segurium setting plus the reader over the option rows.
 */
final class Segurium_Settings {

	/**
	 * Prefix shared by every settings option row.
	 */
	const OPTION_PREFIX = 'segurium_settings_';

	/**
	 * Option holding the storage-layout version the site has been upgraded to.
	 * Autoloaded so the common "already upgraded" path costs no query.
	 */
	const LAYOUT_OPTION = 'segurium_settings_layout';

	/**
	 * Current storage layout. Bump when a new upgrade step is added.
	 */
	const LAYOUT_VERSION = 1;

	/**
	 * Sentinel telling "option row absent" apart from "option row empty".
	 */
	const ABSENT = "\0segurium_absent\0";

	/**
	 * Plugin-owned option keys that are not settings. Uninstall removes them
	 * alongside the registry's own rows; nothing else reads this list.
	 */
	const RUNTIME_KEYS = array(
		// Install identity and consent.
		'segurium_iid_seed',
		'segurium_iid_token',
		'segurium_iid_reregister_pending',
		'segurium_cti_consent',
		'segurium_consent_source',
		'segurium_consent_constant_applied',

		// Billing and entitlement state.
		'segurium_pro_state',
		'segurium_purchase_pointer',
		'segurium_billing_conflict_pending',
		'segurium_quota_last_envelope',
		'segurium_paywall_last_wall',

		// Scan progress and locks.
		'segurium_scan_lock',
		'segurium_scan_trigger_secret',
		'segurium_async_scan_cursor',
		'segurium_last_scan_time',

		// Schema and storage bookkeeping.
		'segurium_schema_versions',
		'segurium_schema_fingerprint',

		// Feed freshness stamps.
		'segurium_geo_updated_at',
		'segurium_geo_etag',
		'segurium_trusted_proxies_etag',
		'segurium_trusted_proxies_updated_at',
		'segurium_trusted_proxies_dropped',
		'segurium_bf_db_version',

		// Remote-action queue state (the consent flag itself is a setting).
		'segurium_remote_actions_last_seq',
		'segurium_remote_actions_log',
		'segurium_remote_actions_executed_at',
		'segurium_remote_actions_component_seen',
		'segurium_remote_actions_pending_acks',

		// Telemetry stamps.
		'segurium_platform_hash',
		'segurium_platform_last_sent_at',
		'segurium_activity_last_id',
		'segurium_activity_census_hash',
		'segurium_activity_census_at',
		'segurium_mainwp_first_seen',
		'segurium_mainwp_last_seen',
		'segurium_mainwp_calls',
		'segurium_mainwp_reported_at',
		'segurium_mainwp_last_scan_start',

		// Admin prompts and attention markers.
		'segurium_issue_flags',
		'segurium_review_prompt',
		'segurium_review_paywall_at',
		'segurium_first_activation_at',
		'segurium_deactivation_reason_asked',

		// Support-form rate limiter. A counter, not a preference — a settings
		// export or a profile pushed across a fleet must not carry it.
		'segurium_support_rate',

		// Operator overrides read but never written by the plugin.
		'segurium_use_content_encoding_gzip',
		'segurium_scan_neoray_avg_ms_per_file',
		'segurium_scan_poll_max_iters_per_tick',

		// One-shot upgrade sentinels.
		'segurium_settings_layout',
		'segurium_migrated_478_retry_after_kv',
		'segurium_migrated_481_remove_poller_cron',
		'segurium_migrated_482_deprecated_options',
		'segurium_migrated_510_drop_legacy_cursor',
		'segurium_migrated_576_purge_pending_blobs',
		'segurium_migrated_577_purge_snapshot_blob',
		'segurium_migrated_871_orphan_sweep',
		'segurium_migrated_alerts_timezone',
		'segurium_cron_heal_failures',

		// Dead keys earlier layouts wrote. Kept so an upgrade from any
		// shipped version still leaves zero rows behind.
		'segurium_scheduled_scan_settings',
		'segurium_geo_whitelist_ips',
	);

	/**
	 * Built registry, memoised per request.
	 *
	 * @var array<string,array>|null
	 */
	private static $rows = null;

	/**
	 * Every feature row, keyed by slug.
	 *
	 * Row shape:
	 *   option    string   Option key holding the feature's array.
	 *   defaults  array|Closure   Field defaults, or a closure returning them
	 *                             for features that own their own default set.
	 *   sanitize  callable|null   Validator turning raw input into a storable
	 *                             array. Consumed by the save path.
	 *   normalize callable|null   Post-merge fixup for nested field trees.
	 *   warnings  callable|null   Notes about values the sanitiser rewrote,
	 *                             returned to the caller by the save path.
	 *   secret    string[] Fields that must never leave the site in an export,
	 *                      a support dump or a fleet profile.
	 *   local     string[] Fields that belong to this site alone. They stay out
	 *                      of a profile in both directions: carrying the
	 *                      scheduled scan's randomised slot across a fleet
	 *                      would fire every site's scan in the same minute.
	 *   pending   string|null  Pending-change context when the save path
	 *                          stages the change for confirmation.
	 *   stage_when callable|null Whether a given save arms the fuse. A feature
	 *                           switching itself off cannot lock anyone out.
	 *   kill      callable|null  Returns a refusal code when a wp-config
	 *                            switch forbids writing this feature, else ''.
	 *   after     callable|null  Post-write side effects the feature owns.
	 *   snapshot  callable|null  Builds the `settings` object sent to CTI.
	 *                            Without one the stored row goes, minus
	 *                            every `secret` field.
	 *   autoload  bool     Whether the row is read on every page load.
	 *   legacy    array    Replaced option key => field name, or '*' when the
	 *                      legacy key held the whole array. A field entry may
	 *                      be an array with 'field' and 'transform'.
	 *   lists     array    Field name => ['read' => callable, 'write' =>
	 *                      callable] for a list that lives in the ip_list
	 *                      table rather than in the option row.
	 *
	 * @return array<string,array>
	 */
	public static function registry() {
		if ( null !== self::$rows ) {
			return self::$rows;
		}

		self::$rows = array(
			'2fa'              => array(
				'option'   => self::OPTION_PREFIX . '2fa',
				'defaults' => static function () {
					return Segurium_2FA::default_settings();
				},
				'sanitize' => static function ( $input ) {
					return Segurium_2FA::get_instance()->validate_settings( $input );
				},
				'after'    => static function ( $applied, $old ) {
					Segurium_2FA::get_instance()->on_settings_saved( $applied, $old );
				},
				'legacy'   => array( 'segurium_2fa_settings' => '*' ),
			),
			'brute_force'      => array(
				'option'   => self::OPTION_PREFIX . 'brute_force',
				'defaults' => static function () {
					return Segurium_Brute_Force::default_settings();
				},
				'sanitize' => static function ( $input ) {
					return Segurium_Brute_Force::get_instance()->validate_settings( $input );
				},
				'after'    => static function () {
					Segurium_Brute_Force::get_instance()->refresh_settings();
				},
				'secret'   => array( 'hcaptcha_secret_key' ),
				'legacy'   => array( 'segurium_bf_settings' => '*' ),
			),
			'security_headers' => array(
				'option'    => self::OPTION_PREFIX . 'security_headers',
				'defaults'  => static function () {
					return Segurium_Security_Headers::default_settings();
				},
				'sanitize'  => static function ( $input ) {
					return Segurium_Security_Headers::get_instance()->validate_settings( $input );
				},
				'normalize' => array( __CLASS__, 'normalize_security_headers' ),
				'after'     => static function () {
					Segurium_Security_Headers::get_instance()->refresh_settings();
				},
				'legacy'    => array( 'segurium_sh_settings' => '*' ),
			),
			'info_shield'      => array(
				'option'   => self::OPTION_PREFIX . 'info_shield',
				'defaults' => static function () {
					return Segurium_Info_Shield::default_settings();
				},
				'sanitize' => static function ( $input ) {
					return Segurium_Info_Shield::get_instance()->validate_settings( $input );
				},
				'after'    => static function () {
					Segurium_Info_Shield::get_instance()->refresh_settings();
				},
				'legacy'   => array( 'segurium_info_shield_settings' => '*' ),
			),
			'scheduled_scan'   => array(
				'option'   => self::OPTION_PREFIX . 'scheduled_scan',
				'defaults' => array(
					'mode'         => 'off',
					'hour'         => 0,
					'minute'       => 0,
					'day_of_week'  => 0,
					'generated_at' => 0,
				),
				'sanitize' => array( 'Segurium_Scheduled_Scan_Settings', 'validate_settings' ),
				'local'    => array( 'hour', 'minute', 'day_of_week', 'generated_at' ),
				'after'    => static function () {
					if ( class_exists( 'Segurium_Scheduled_Scan' ) ) {
						Segurium_Scheduled_Scan::reschedule();
					}
				},
				'legacy'   => array( 'segurium_scheduled_scan' => '*' ),
			),
			'geo'              => array(
				'option'     => self::OPTION_PREFIX . 'geo',
				'defaults'   => array(
					'enabled'            => false,
					'block_mode'         => 'block',
					'blocked_countries'  => array(),
					'block_action'       => 'deny_403',
					'block_redirect_url' => '',
				),
				'sanitize'   => static function ( $input ) {
					return Segurium_Geo_Blocker::get_instance()->validate_settings( $input );
				},
				'pending'    => 'geo_blocking',
				'stage_when' => static function ( $applied ) {
					return ! empty( $applied['enabled'] );
				},
				'lists'      => array(
					'trusted_proxies' => array(
						'read'  => array( 'Segurium_Trusted_Proxies', 'manual_read' ),
						'write' => array( 'Segurium_Trusted_Proxies', 'manual_save' ),
					),
				),
				'legacy'     => array(
					'segurium_geo_blocking_enabled'   => 'enabled',
					'segurium_geo_block_mode'         => 'block_mode',
					'segurium_geo_blocked_countries'  => 'blocked_countries',
					'segurium_geo_block_action'       => 'block_action',
					'segurium_geo_block_redirect_url' => 'block_redirect_url',
				),
			),
			'firewall'         => array(
				'option'     => self::OPTION_PREFIX . 'firewall',
				'defaults'   => array(
					'enabled' => false,
					'mode'    => 'deny_list',
				),
				'sanitize'   => array( 'Segurium_Firewall_Rules', 'validate_settings' ),
				'pending'    => 'firewall',
				'stage_when' => static function ( $applied ) {
					return ! empty( $applied['enabled'] );
				},
				'autoload'   => true,
				'legacy'     => array(
					'segurium_firewall_enabled' => 'enabled',
					'segurium_firewall_mode'    => 'mode',
				),
				'lists'      => array(
					'ip_list'         => array(
						'read'  => array( 'Segurium_Firewall_Rules', 'read' ),
						'write' => static function ( array $cidrs, array $settings ) {
							Segurium_Firewall_Rules::save( $settings['mode'] ?? 'deny_list', $cidrs );
						},
					),
					'trusted_proxies' => array(
						'read'  => array( 'Segurium_Trusted_Proxies', 'manual_read' ),
						'write' => array( 'Segurium_Trusted_Proxies', 'manual_save' ),
					),
				),
			),
			'alerts'           => array(
				'option'   => self::OPTION_PREFIX . 'alerts',
				'defaults' => array(
					'enabled' => false,
					'email'   => '',
				),
				'sanitize' => array( 'Segurium_Alerts_Settings', 'validate_settings' ),
				'snapshot' => array( 'Segurium_Alerts_Settings', 'snapshot_settings' ),
				'legacy'   => array(
					'segurium_alerts_email_enabled' => 'enabled',
					'segurium_alerts_email_address' => 'email',
				),
			),
			'auto_fix'         => array(
				'option'   => self::OPTION_PREFIX . 'auto_fix',
				'defaults' => array( 'enabled' => false ),
				'sanitize' => array( 'Segurium_Auto_Fix_Settings', 'validate_settings' ),
				'snapshot' => array( 'Segurium_Auto_Fix_Settings', 'snapshot_settings' ),
				'legacy'   => array( 'segurium_auto_fix_enabled' => 'enabled' ),
			),
			'remote_actions'   => array(
				'option'   => self::OPTION_PREFIX . 'remote_actions',
				'defaults' => array( 'enabled' => true ),
				'sanitize' => array( 'Segurium_Remote_Actions', 'validate_settings' ),
				'snapshot' => array( 'Segurium_Remote_Actions', 'snapshot_settings' ),
				'kill'     => array( 'Segurium_Remote_Actions', 'kill_reason' ),
				'legacy'   => array( 'segurium_remote_actions_enabled' => 'enabled' ),
			),
			'general'          => array(
				'option'   => self::OPTION_PREFIX . 'general',
				'defaults' => array(
					'scan_exclude'            => '',
					'cloud_detection_enabled' => false,
					'uninstall_wipe_data'     => false,
				),
				'sanitize' => array( __CLASS__, 'sanitize_general' ),
				'warnings' => array( __CLASS__, 'general_warnings' ),
				'legacy'   => array(
					'segurium_scan_exclude'            => 'scan_exclude',
					'segurium_cloud_detection_enabled' => 'cloud_detection_enabled',
					'segurium_uninstall_wipe_data'     => 'uninstall_wipe_data',
					'segurium_on_premise'              => array(
						'field'     => 'cloud_detection_enabled',
						'transform' => array( __CLASS__, 'invert_on_premise' ),
					),
				),
			),
		);

		foreach ( self::$rows as $slug => $row ) {
			self::$rows[ $slug ] = array_merge(
				array(
					'sanitize'   => null,
					'normalize'  => null,
					'warnings'   => null,
					'secret'     => array(),
					'local'      => array(),
					'pending'    => null,
					'stage_when' => null,
					'kill'       => null,
					'after'      => null,
					'snapshot'   => null,
					'autoload'   => false,
					'legacy'     => array(),
					'lists'      => array(),
				),
				$row
			);
		}

		return self::$rows;
	}

	/**
	 * Drop the memoised registry. Test-only seam.
	 *
	 * @return void
	 */
	public static function reset_registry() {
		self::$rows = null;
	}

	/**
	 * Replace one registry row. Test-only seam alongside reset_registry(),
	 * for exercising a save-path branch a real feature reaches only from
	 * wp-config.php.
	 *
	 * @param string $slug Feature slug.
	 * @param array  $row  Complete row, as registry() returns it.
	 * @return void
	 */
	public static function set_row( $slug, array $row ) {
		self::registry();
		self::$rows[ $slug ] = $row;
	}

	/**
	 * Every feature slug, in registry order.
	 *
	 * @return string[]
	 */
	public static function slugs() {
		return array_keys( self::registry() );
	}

	/**
	 * Whether a slug has a registry row.
	 *
	 * @param string $slug Feature slug.
	 * @return bool
	 */
	public static function has( $slug ) {
		return isset( self::registry()[ $slug ] );
	}

	/**
	 * One registry row.
	 *
	 * @param string $slug Feature slug.
	 * @return array Empty array when the slug is unknown.
	 */
	public static function row( $slug ) {
		$rows = self::registry();
		return isset( $rows[ $slug ] ) ? $rows[ $slug ] : array();
	}

	/**
	 * Option key holding a feature's settings.
	 *
	 * @param string $slug Feature slug.
	 * @return string Empty string when the slug is unknown.
	 */
	public static function option_key( $slug ) {
		$row = self::row( $slug );
		return isset( $row['option'] ) ? $row['option'] : '';
	}

	/**
	 * Every settings option key.
	 *
	 * @return string[]
	 */
	public static function option_keys() {
		$keys = array();
		foreach ( self::registry() as $row ) {
			$keys[] = $row['option'];
		}
		return $keys;
	}

	/**
	 * Every option key an earlier layout used for a setting. Uninstall still
	 * removes them so a site that never ran the upgrade leaves nothing behind.
	 *
	 * @return string[]
	 */
	public static function legacy_keys() {
		$keys = array();
		foreach ( self::registry() as $row ) {
			foreach ( array_keys( $row['legacy'] ) as $key ) {
				$keys[] = $key;
			}
		}
		return $keys;
	}

	/**
	 * Pending-change option keys the staging layer writes, one per context.
	 *
	 * @return string[]
	 */
	public static function pending_keys() {
		$keys = array();
		foreach ( self::registry() as $row ) {
			if ( null !== $row['pending'] ) {
				$keys[] = 'segurium_pending_ctx_' . $row['pending'];
			}
		}
		return $keys;
	}

	/**
	 * Resolved defaults for a feature.
	 *
	 * @param string $slug Feature slug.
	 * @return array
	 */
	public static function defaults( $slug ) {
		$row = self::row( $slug );
		if ( ! isset( $row['defaults'] ) ) {
			return array();
		}
		$defaults = $row['defaults'];
		if ( is_array( $defaults ) ) {
			return $defaults;
		}
		if ( ! is_callable( $defaults ) ) {
			return array();
		}
		try {
			$resolved = call_user_func( $defaults );
		} catch ( Throwable $e ) {
			// A feature that owns its own default set is only loaded on the
			// tiers that run it. Readers on other tiers want the stored row.
			Segurium_Debug::log( '[segurium] settings_defaults_unavailable slug=' . $slug );
			return array();
		}
		return is_array( $resolved ) ? $resolved : array();
	}

	/**
	 * Sanitiser for a feature, or null when the feature has none.
	 *
	 * @param string $slug Feature slug.
	 * @return callable|null
	 */
	public static function sanitizer( $slug ) {
		$row = self::row( $slug );
		return isset( $row['sanitize'] ) ? $row['sanitize'] : null;
	}

	/**
	 * Fields that must never leave the site.
	 *
	 * @param string $slug Feature slug.
	 * @return string[]
	 */
	public static function secret_fields( $slug ) {
		$row = self::row( $slug );
		return isset( $row['secret'] ) ? $row['secret'] : array();
	}

	/**
	 * Fields that belong to one site and never travel in a profile.
	 *
	 * @param string $slug Feature slug.
	 * @return array<int,string>
	 */
	public static function local_fields( $slug ) {
		return self::has( $slug ) ? (array) self::row( $slug )['local'] : array();
	}

	/**
	 * The pending-change context a feature stages under, or null.
	 *
	 * @param string $slug Feature slug.
	 * @return string|null
	 */
	public static function pending_context( $slug ) {
		$row = self::row( $slug );
		return isset( $row['pending'] ) ? $row['pending'] : null;
	}

	/**
	 * Read one feature's settings, merged over its defaults.
	 *
	 * Field values are coerced to the type of their default, so a row written
	 * by an older layout (where every scalar was its own option and came back
	 * as a string) reads back with the same types as before.
	 *
	 * @param string $slug         Feature slug.
	 * @param bool   $with_lists   Include the feature's ip_list-backed fields.
	 * @return array Empty array when the slug is unknown.
	 */
	public static function get( $slug, $with_lists = false ) {
		if ( ! self::has( $slug ) ) {
			return array();
		}
		$row      = self::row( $slug );
		$defaults = self::defaults( $slug );
		$stored   = self::get_stored( $slug );

		$merged = $defaults;
		foreach ( $stored as $field => $value ) {
			$merged[ $field ] = array_key_exists( $field, $defaults )
				? self::coerce( $value, $defaults[ $field ] )
				: $value;
		}

		if ( is_callable( $row['normalize'] ) ) {
			$merged = call_user_func( $row['normalize'], $merged, $defaults );
		}

		if ( $with_lists ) {
			foreach ( $row['lists'] as $field => $list ) {
				$reader           = isset( $list['read'] ) ? $list['read'] : null;
				$merged[ $field ] = is_callable( $reader ) ? (array) call_user_func( $reader ) : array();
			}
		}

		return $merged;
	}

	/**
	 * Read one field.
	 *
	 * @param string $slug     Feature slug.
	 * @param string $field    Field name.
	 * @param mixed  $fallback Returned when the field has no default and was
	 *                         never written.
	 * @return mixed
	 */
	public static function get_field( $slug, $field, $fallback = null ) {
		$settings = self::get( $slug );
		return array_key_exists( $field, $settings ) ? $settings[ $field ] : $fallback;
	}

	/**
	 * Whether a field has ever been written for this site. Distinguishes
	 * "the user answered no" from "the user was never asked".
	 *
	 * @param string $slug  Feature slug.
	 * @param string $field Field name.
	 * @return bool
	 */
	public static function has_field( $slug, $field ) {
		return array_key_exists( $field, self::get_stored( $slug ) );
	}

	/**
	 * The stored row exactly as written, with no defaults merged in.
	 *
	 * Readers on a tier that does not load the owning feature class use this:
	 * a feature owning its own default set cannot resolve defaults there.
	 *
	 * @param string $slug Feature slug.
	 * @return array
	 */
	public static function get_stored( $slug ) {
		if ( ! self::has( $slug ) ) {
			return array();
		}
		return Segurium_Storage::setting_get_array( self::option_key( $slug ) );
	}

	/**
	 * Read every feature at once, ip_list-backed fields included.
	 *
	 * @return array<string,array> Slug => settings.
	 */
	public static function get_all() {
		$out = array();
		foreach ( array_keys( self::registry() ) as $slug ) {
			$out[ $slug ] = self::get( $slug, true );
		}
		return $out;
	}

	/**
	 * Replace a feature's stored settings. The caller owns validation; this is
	 * the persistence primitive, not the save path.
	 *
	 * Fields backed by the ip_list table are dropped: they live there, and
	 * writing them into the option row would duplicate the list.
	 *
	 * @param string $slug   Feature slug.
	 * @param array  $values Field map to store.
	 * @return bool True when the option changed.
	 */
	public static function put( $slug, array $values ) {
		if ( ! self::has( $slug ) ) {
			Segurium_Debug::log( '[segurium] settings_put_unknown_slug: ' . $slug );
			return false;
		}
		$row = self::row( $slug );
		foreach ( array_keys( $row['lists'] ) as $field ) {
			unset( $values[ $field ] );
		}
		return Segurium_Storage::setting_set( $row['option'], $values, $row['autoload'] );
	}

	/**
	 * Write a single field, leaving the rest of the row untouched.
	 *
	 * @param string $slug  Feature slug.
	 * @param string $field Field name.
	 * @param mixed  $value Value to store.
	 * @return bool True when the option changed.
	 */
	public static function put_field( $slug, $field, $value ) {
		if ( ! self::has( $slug ) ) {
			Segurium_Debug::log( '[segurium] settings_put_field_unknown_slug: ' . $slug );
			return false;
		}
		$stored           = self::get_stored( $slug );
		$stored[ $field ] = $value;
		return self::put( $slug, $stored );
	}

	/**
	 * Move a site from the pre-registry layout: read each replaced key, write
	 * the feature row, drop the replaced key. Idempotent — a second run finds
	 * no legacy keys and writes nothing.
	 *
	 * Runs on every request tier, not just the heavy ones: the firewall, the
	 * geo blocker, the security headers and 2FA all read settings on a visitor
	 * request, and a site whose settings had not been carried yet would serve
	 * that request with every one of them switched off.
	 *
	 * @return bool True when the site is on the current layout afterwards.
	 */
	public static function upgrade() {
		if ( Segurium_Storage::setting_get_int( self::LAYOUT_OPTION, 0 ) >= self::LAYOUT_VERSION ) {
			return true;
		}

		$ok = true;
		foreach ( self::registry() as $slug => $row ) {
			try {
				self::upgrade_row( $row );
			} catch ( Throwable $e ) {
				$ok = false;
				Segurium_Debug::log(
					'[segurium] settings_upgrade_failed slug=' . $slug . ' error=' . $e->getMessage()
				);
			}
		}

		if ( $ok ) {
			Segurium_Storage::setting_set( self::LAYOUT_OPTION, self::LAYOUT_VERSION, true );
		}
		return $ok;
	}

	/**
	 * Carry one feature's legacy keys into its option row.
	 *
	 * The row is written before any replaced key is dropped, and the write is
	 * re-checked against a concurrent one. `upgrade()` runs on every request
	 * tier, so the first requests after an update race each other: deleting
	 * first would let the loser read a half-emptied key set and write a row
	 * missing whatever the winner had already removed.
	 *
	 * @param array $row Registry row.
	 * @return void
	 * @throws RuntimeException When the option write fails, so the caller
	 *                          leaves the layout unstamped and retries.
	 */
	private static function upgrade_row( array $row ) {
		if ( empty( $row['legacy'] ) ) {
			return;
		}

		$seed    = self::ABSENT === Segurium_Storage::setting_get( $row['option'], self::ABSENT );
		$carried = array();
		$present = array();

		foreach ( $row['legacy'] as $legacy_key => $target ) {
			$value = Segurium_Storage::setting_get( $legacy_key, self::ABSENT );
			if ( self::ABSENT === $value ) {
				continue;
			}
			$present[] = $legacy_key;
			if ( ! $seed ) {
				continue;
			}
			if ( '*' === $target ) {
				$carried = is_array( $value ) ? array_merge( $carried, $value ) : $carried;
				continue;
			}
			$field = is_array( $target ) ? $target['field'] : $target;
			if ( is_array( $target ) && isset( $target['transform'] ) && is_callable( $target['transform'] ) ) {
				$value = call_user_func( $target['transform'], $value );
			}
			// An earlier legacy key wins: `segurium_on_premise` is only
			// consulted on a site that never wrote its replacement.
			if ( ! array_key_exists( $field, $carried ) ) {
				$carried[ $field ] = $value;
			}
		}

		if ( empty( $present ) ) {
			return;
		}

		if ( $seed && self::ABSENT === Segurium_Storage::setting_get( $row['option'], self::ABSENT ) ) {
			if ( ! Segurium_Storage::setting_set( $row['option'], $carried, $row['autoload'] ) ) {
				throw new RuntimeException( esc_html( 'settings_upgrade_write_failed option=' . $row['option'] ) );
			}
		}

		foreach ( $present as $legacy_key ) {
			Segurium_Storage::setting_delete( $legacy_key );
		}
	}

	/**
	 * Coerce a stored value to the type of its default. Mirrors the typed
	 * getters the pre-registry layout used per key.
	 *
	 * @param mixed $value    Stored value.
	 * @param mixed $fallback Default carrying the expected type.
	 * @return mixed
	 */
	private static function coerce( $value, $fallback ) {
		if ( is_bool( $fallback ) ) {
			return self::to_bool( $value, $fallback );
		}
		if ( is_int( $fallback ) ) {
			return is_numeric( $value ) ? (int) $value : $fallback;
		}
		if ( is_string( $fallback ) ) {
			if ( is_string( $value ) ) {
				return $value;
			}
			return ( is_int( $value ) || is_float( $value ) ) ? (string) $value : $fallback;
		}
		if ( is_array( $fallback ) ) {
			return is_array( $value ) ? $value : $fallback;
		}
		return $value;
	}

	/**
	 * Boolean coercion matching Segurium_Storage_Settings::get_bool.
	 *
	 * @param mixed $value    Stored value.
	 * @param bool  $fallback Returned when the value is not interpretable.
	 * @return bool
	 */
	private static function to_bool( $value, $fallback ) {
		if ( is_bool( $value ) ) {
			return $value;
		}
		if ( is_numeric( $value ) ) {
			return (bool) (int) $value;
		}
		if ( is_string( $value ) ) {
			$lower = strtolower( trim( $value ) );
			if ( in_array( $lower, array( '1', 'true', 'yes', 'on' ), true ) ) {
				return true;
			}
			if ( in_array( $lower, array( '0', 'false', 'no', 'off', '' ), true ) ) {
				return false;
			}
		}
		return $fallback;
	}

	/**
	 * Security headers keep two nested field trees that a flat merge would
	 * replace wholesale, dropping any key a newer release added.
	 *
	 * @param array $merged   Flat-merged settings.
	 * @param array $defaults Resolved defaults.
	 * @return array
	 */
	public static function normalize_security_headers( array $merged, array $defaults ) {
		if ( ! isset( $defaults['custom'] ) || ! is_array( $defaults['custom'] ) ) {
			return $merged;
		}
		if ( ! isset( $merged['custom'] ) || ! is_array( $merged['custom'] ) ) {
			$merged['custom'] = $defaults['custom'];
			return $merged;
		}

		$merged['custom'] = wp_parse_args( $merged['custom'], $defaults['custom'] );

		if ( ! isset( $merged['custom']['permissions_policy'] ) || ! is_array( $merged['custom']['permissions_policy'] ) ) {
			$merged['custom']['permissions_policy'] = $defaults['custom']['permissions_policy'];
		} else {
			$merged['custom']['permissions_policy'] = wp_parse_args(
				$merged['custom']['permissions_policy'],
				$defaults['custom']['permissions_policy']
			);
		}

		return $merged;
	}

	/**
	 * `segurium_on_premise` stored the inverse of cloud detection.
	 *
	 * @param mixed $value Legacy value.
	 * @return int 1 when cloud detection should be on.
	 */
	public static function invert_on_premise( $value ) {
		return self::to_bool( $value, false ) ? 0 : 1;
	}

	/**
	 * Validate the general group: the scan exclusion list plus two flags.
	 *
	 * The entry ceiling is refused only for a list the caller sent. A site
	 * whose stored list already exceeds it — an import through an older,
	 * uncapped write — keeps that list and can still save its other fields
	 * instead of being locked out of the whole row.
	 *
	 * @param array $input Merged input.
	 * @param array $raw   Raw caller input.
	 * @return array|WP_Error
	 */
	public static function sanitize_general( $input, $raw = array() ) {
		$input  = is_array( $input ) ? $input : array();
		$raw    = is_array( $raw ) ? $raw : array();
		$parsed = Segurium_Scan_Exclusions::parse( (string) ( $input['scan_exclude'] ?? '' ) );
		if ( $parsed['error'] instanceof WP_Error ) {
			if ( array_key_exists( 'scan_exclude', $raw ) ) {
				return $parsed['error'];
			}
			$parsed['value'] = (string) ( $input['scan_exclude'] ?? '' );
		}

		return array(
			'scan_exclude'            => $parsed['value'],
			'cloud_detection_enabled' => ! empty( $input['cloud_detection_enabled'] ),
			'uninstall_wipe_data'     => ! empty( $input['uninstall_wipe_data'] ),
		);
	}

	/**
	 * Notes about exclusion patterns the validator rewrote or dropped.
	 *
	 * @param array $input Raw caller input.
	 * @return array<int,string>
	 */
	public static function general_warnings( $input ) {
		$input = is_array( $input ) ? $input : array();
		if ( ! array_key_exists( 'scan_exclude', $input ) ) {
			return array();
		}
		return Segurium_Scan_Exclusions::parse( (string) $input['scan_exclude'] )['warnings'];
	}
}

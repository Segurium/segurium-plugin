<?php
/**
 * WP-CLI bridge for Segurium support tooling.
 *
 * Only loaded when WP-CLI is the request runner — this file MUST NOT contain
 * web-request-time logic.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * `wp segurium ...` commands.
 */
class Segurium_CLI {

	/**
	 * Dump the current entitlement state for support diagnosis.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. One of: table, json, yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium entitlements
	 *     wp segurium entitlements --format=json
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args.
	 */
	public function entitlements( $args, $assoc_args ) {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$dump   = Segurium_Entitlements::instance()->dump();

		$rows = array(
			array(
				'key'   => 'envelope_cached',
				'value' => ! empty( $dump['envelope_cached'] ) ? 'true' : 'false',
			),
			array(
				'key'   => 'plan_tier',
				'value' => (string) $dump['plan_tier'],
			),
		);
		foreach ( $dump['features'] as $feature => $allowed ) {
			$rows[] = array(
				'key'   => 'feature.' . $feature,
				'value' => $allowed ? 'true' : 'false',
			);
		}

		if ( 'json' === $format || 'yaml' === $format ) {
			WP_CLI\Utils\format_items( $format, array( $dump ), array( 'envelope_cached', 'plan_tier', 'features' ) );
			return;
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'key', 'value' ) );
	}

	/**
	 * Dump current Free-tier remediation quota state for support diagnosis.
	 *
	 * Calls CTI's read-only /v1/quota/state. Pro installs short-circuit
	 * client-side and report `is_pro=true` without touching CTI; if CTI
	 * is unreachable the row reports `fail_open=true`.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. One of: table, json, yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium quota
	 *     wp segurium quota --format=json
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args.
	 */
	public function quota( $args, $assoc_args ) {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$state  = Segurium_Quota::instance()->state();

		if ( 'json' === $format || 'yaml' === $format ) {
			WP_CLI\Utils\format_items(
				$format,
				array( $state ),
				array(
					'allowed',
					'used',
					'limit',
					'window_days',
					'next_slot_at',
					'reset_at',
					'is_pro',
					'fail_open',
					'cached_at',
					'plan_tier',
					'entitlements',
				)
			);
			return;
		}

		$rows = array();
		foreach ( $state as $key => $value ) {
			if ( is_bool( $value ) ) {
				$value = $value ? 'true' : 'false';
			} elseif ( is_array( $value ) ) {
				$value = (string) wp_json_encode( $value );
			}
			$rows[] = array(
				'key'   => (string) $key,
				'value' => (string) $value,
			);
		}
		WP_CLI\Utils\format_items( 'table', $rows, array( 'key', 'value' ) );
	}
}

WP_CLI::add_command( 'segurium', 'Segurium_CLI' );

require_once __DIR__ . '/class-segurium-cli-iid.php';
require_once __DIR__ . '/class-segurium-cli-consent.php';
require_once __DIR__ . '/class-segurium-cli-license.php';
require_once __DIR__ . '/class-segurium-cli-settings.php';
require_once __DIR__ . '/class-segurium-cli-backup.php';

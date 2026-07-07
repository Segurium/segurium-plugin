<?php
/**
 * Firewall IP-rule storage + pending-revert handler.
 *
 * SEGURIUM-540: lives in the firewall include group so the pending-revert
 * action handler is registered on every tier that loads the firewall —
 * not just heavy tiers where the `Segurium` class boots. Without this,
 * `Segurium_Pending_Changes::check_expired( 'firewall' )` firing from a
 * lightweight tier (ajax_other heartbeat, visitor, etc.) had no handler
 * for the firewall context, so `segurium_firewall_enabled` would stay
 * `'1'` while the transient + ctx + scheduled cron were cleared — a
 * permanent self-lockout. Same pattern previously fixed for geo by
 * SEGURIUM-392 in Segurium_Trusted_Proxies.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * User-managed firewall CIDR storage + pending-revert handler.
 */
class Segurium_Firewall_Rules {

	const CONTEXT = 'firewall';

	/**
	 * Register the pending-revert handler. Idempotent — WordPress dedupes
	 * identical (hook, callback, priority) registrations.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		add_action( 'segurium_pending_revert', array( __CLASS__, 'on_pending_revert' ), 10, 3 );
	}

	/**
	 * Read the user-managed firewall CIDR entries from ip_list.
	 *
	 * @return string[] Array of `<ip>/<bits>` strings.
	 */
	public static function read() {
		$mode      = Segurium_Storage::setting_get_string( 'segurium_firewall_mode', 'deny_list' );
		$list_type = 'allow_list' === $mode ? 'allow' : 'block';
		$rows      = Segurium_Storage::ip_list( $list_type, 500, 0 );
		$out       = array();
		foreach ( $rows as $r ) {
			if ( 'firewall_rule' !== ( $r['source'] ?? '' ) ) {
				continue;
			}
			$bin = isset( $r['ip_hex'] ) && '' !== $r['ip_hex'] ? hex2bin( (string) $r['ip_hex'] ) : '';
			$ip  = $bin ? (string) Segurium_IP::unpack( $bin ) : '';
			if ( '' === $ip ) {
				continue;
			}
			$bits = (int) ( $r['cidr_bits'] ?? 128 );
			if ( false === strpos( $ip, ':' ) && $bits > 32 ) {
				$bits -= 96;
			}
			$out[] = $ip . '/' . $bits;
		}
		return $out;
	}

	/**
	 * Replace the user-managed firewall CIDR entries in ip_list.
	 *
	 * @param string   $mode  `deny_list` or `allow_list`.
	 * @param string[] $cidrs Array of `<ip>/<bits>` strings.
	 * @return void
	 */
	public static function save( $mode, array $cidrs ) {
		$list_type = 'allow_list' === $mode ? 'allow' : 'block';
		$entries   = array();
		foreach ( $cidrs as $cidr ) {
			$cidr = trim( (string) $cidr );
			if ( '' === $cidr ) {
				continue;
			}
			$parts     = explode( '/', $cidr, 2 );
			$ip        = $parts[0];
			$bits      = isset( $parts[1] ) && ctype_digit( $parts[1] ) ? (int) $parts[1] : ( false === strpos( $ip, ':' ) ? 32 : 128 );
			$entries[] = array(
				'ip'        => $ip,
				'cidr_bits' => $bits,
				'reason'    => null,
			);
		}
		Segurium_Storage::ip_replace_feed( $list_type, 'firewall_rule', $entries );
		Segurium_Storage::ip_replace_feed( 'allow_list' === $mode ? 'block' : 'allow', 'firewall_rule', array() );
	}

	/**
	 * Restore firewall settings from a pending-revert payload.
	 *
	 * @param string $context   Pending-change context.
	 * @param array  $old_value Snapshot to restore.
	 * @param string $token     Pending change token (unused — accepted for the
	 *                          action signature).
	 * @return void
	 */
	public static function on_pending_revert( $context, $old_value, $token ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( self::CONTEXT !== $context ) {
			return;
		}
		$restored_mode = $old_value['mode'] ?? 'deny_list';
		Segurium_Storage::setting_set( 'segurium_firewall_enabled', ! empty( $old_value['enabled'] ) );
		Segurium_Storage::setting_set( 'segurium_firewall_mode', $restored_mode );
		self::save( $restored_mode, (array) ( $old_value['ip_list'] ?? array() ) );
		Segurium_Trusted_Proxies::manual_save( (array) ( $old_value['trusted_proxies'] ?? array() ) );
	}
}

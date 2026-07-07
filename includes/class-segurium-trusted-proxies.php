<?php
/**
 * Auto-fetched trusted proxy list from the CTI service.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages the auto-fetched trusted proxy IP list.
 *
 * Downloads a consolidated list of CDN/proxy/known-service IP ranges
 * from the CTI server, caches it in WP options, and provides a flat
 * CIDR array for use by the firewall and geo-blocker.
 */
class Segurium_Trusted_Proxies {

	const CRON_HOOK         = 'segurium_trusted_proxies_update';
	const OPTION_ETAG       = 'segurium_trusted_proxies_etag';
	const OPTION_UPDATED_AT = 'segurium_trusted_proxies_updated_at';

	/**
	 * Register the daily WP-Cron event if not already scheduled.
	 *
	 * @return void
	 */
	public static function schedule() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Remove the cron event on plugin deactivation.
	 *
	 * @return void
	 */
	public static function unschedule() {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}

	/**
	 * Download the trusted-proxies list from the CTI server.
	 *
	 * Sends If-None-Match when an ETag is cached; returns true on 304.
	 * Validates the response and stores the parsed data in options.
	 *
	 * @return true|WP_Error
	 */
	public static function fetch() {
		$headers = array();
		$etag    = Segurium_Storage::setting_get_string( self::OPTION_ETAG );
		if ( $etag ) {
			$headers['If-None-Match'] = $etag;
		}
		$iid = Segurium_IID::get_iid();
		if ( $iid ) {
			$headers['X-Segurium-IID'] = $iid;
		}

		// CTI listens on TCP/8901 — see Segurium_CTI_Client class docblock for why wp_safe_remote_* cannot be used here.
		$response = wp_remote_get(
			Segurium_Storage::cti_endpoint( 'trusted_proxies' ),
			array(
				'headers' => $headers,
				'timeout' => 30,
			)
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );

		if ( 304 === $code ) {
			Segurium_Storage::setting_set( self::OPTION_UPDATED_AT, time() );
			return true;
		}

		if ( 200 !== $code ) {
			return new WP_Error(
				'trusted_proxies_http_error',
				sprintf(
					/* translators: %d: HTTP status code */
					__( 'Trusted proxies endpoint returned HTTP %d.', 'segurium' ),
					$code
				)
			);
		}

		// SEGURIUM-194: refuse an Ed25519-invalid feed outright. Before
		// this gate, a MITM who injected `0.0.0.0/0` into the feed would
		// make `ip_is_trusted()` return true for every peer, defeating
		// the whole get_real_ip() trust chain.
		$verified = Segurium_CTI_Signature::verify_response( $response, 'geo/trusted-proxies' );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || ! isset( $data['cidrs'] ) || ! is_array( $data['cidrs'] ) ) {
			return new WP_Error(
				'trusted_proxies_invalid',
				__( 'Trusted proxies response has invalid format.', 'segurium' )
			);
		}

		self::persist_feed( $data['cidrs'] );

		$new_etag = wp_remote_retrieve_header( $response, 'etag' );
		if ( $new_etag ) {
			Segurium_Storage::setting_set( self::OPTION_ETAG, $new_etag );
		}
		Segurium_Storage::setting_set( self::OPTION_UPDATED_AT, time() );

		return true;
	}

	/**
	 * Minimum prefix length a CIDR must carry to be accepted into the
	 * trusted-proxy feed. Anything broader would mark huge swathes of
	 * the public internet as "trust XFF/CF headers from this IP",
	 * which is exactly the primitive SEGURIUM-194 closes.
	 */
	const MIN_IPV4_PREFIX_BITS = 8;
	const MIN_IPV6_PREFIX_BITS = 16;

	/**
	 * Atomically replace the `trusted_proxy` feed entries in ip_list.
	 *
	 * Entries whose prefix is broader than {@see self::MIN_IPV4_PREFIX_BITS}
	 * (IPv4) or {@see self::MIN_IPV6_PREFIX_BITS} (IPv6) are silently
	 * dropped. This is a belt-and-braces gate on top of the Ed25519
	 * signature verification in {@see self::fetch()} — CTI should never
	 * send a /0 or /4, but a CTI bug or compromised signing key must not
	 * be able to trivially turn every peer into a trusted proxy.
	 *
	 * @param array $cidrs Flat array of `<ip>/<bits>` strings.
	 * @return int Rows upserted.
	 */
	public static function persist_feed( array $cidrs ) {
		$entries = array();
		$dropped = 0;
		foreach ( $cidrs as $cidr ) {
			$cidr = trim( (string) $cidr );
			if ( '' === $cidr ) {
				continue;
			}
			$parts = explode( '/', $cidr, 2 );
			$ip    = $parts[0];
			$is_v6 = false !== strpos( $ip, ':' );
			$bits  = isset( $parts[1] ) && ctype_digit( $parts[1] )
				? (int) $parts[1]
				: ( $is_v6 ? 128 : 32 );

			$min = $is_v6 ? self::MIN_IPV6_PREFIX_BITS : self::MIN_IPV4_PREFIX_BITS;
			if ( $bits < $min ) {
				++$dropped;
				continue;
			}

			$entries[] = array(
				'ip'        => $ip,
				'cidr_bits' => $bits,
				'reason'    => null,
			);
		}
		if ( $dropped > 0 ) {
			// Surface on the admin UI via settings; the status probe
			// already reports `total_cidrs`, so a drop shows up there.
			Segurium_Storage::setting_set( 'segurium_trusted_proxies_dropped', $dropped );
		}
		return Segurium_Storage::ip_replace_feed( 'trusted_proxy', 'trusted_proxy_feed', $entries );
	}

	/**
	 * Read user-managed trusted-proxy CIDR entries from ip_list.
	 *
	 * Lives in the firewall include group (loaded by every light tier),
	 * so the pending-revert path that fires from `Segurium_Geo_Blocker`
	 * does not depend on the heavy `Segurium` class being bootstrapped.
	 * SEGURIUM-392: a visitor-tier expiry of a staged geo-blocking
	 * change used to fatal because it called `Segurium::` from light
	 * tier where that class is not loaded.
	 *
	 * @return string[]
	 */
	public static function manual_read() {
		$rows = Segurium_Storage::ip_list( 'trusted_proxy', 500, 0 );
		$out  = array();
		foreach ( $rows as $r ) {
			if ( 'manual' !== ( $r['source'] ?? '' ) ) {
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
	 * Replace user-managed trusted proxy entries in ip_list.
	 *
	 * Companion to {@see self::manual_read()} — both must live together
	 * in the firewall include group; see SEGURIUM-392.
	 *
	 * @param string[] $cidrs Array of CIDR strings.
	 */
	public static function manual_save( array $cidrs ) {
		$entries = array();
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
			);
		}
		Segurium_Storage::ip_replace_feed( 'trusted_proxy', 'manual', $entries );
	}

	/**
	 * Return the flat array of all trusted proxy CIDRs.
	 *
	 * @return string[]
	 */
	public static function get_all_cidrs() {
		$rows = Segurium_Storage::ip_list( 'trusted_proxy', 500, 0 );
		$out  = array();
		foreach ( $rows as $r ) {
			if ( 'trusted_proxy_feed' !== ( $r['source'] ?? '' ) ) {
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
	 * Return status information for UI display.
	 *
	 * @return array{exists: bool, updated_at: int|null, total_cidrs: int}
	 */
	public static function get_status() {
		$updated_at = Segurium_Storage::setting_get( self::OPTION_UPDATED_AT, null );
		$count      = (int) Segurium_Storage::table_get_var(
			'ip_list',
			'SELECT COUNT(*) FROM {{table}} WHERE list_type = %s AND source = %s',
			array( 'trusted_proxy', 'trusted_proxy_feed' )
		);
		return array(
			'exists'      => $count > 0,
			'updated_at'  => $updated_at ? (int) $updated_at : null,
			'total_cidrs' => $count,
		);
	}
}

<?php
/**
 * Cloud endpoint selection.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sends each request to the Segurium cloud through the selected endpoint and
 * moves to the other endpoint when the selected one refuses the connection.
 */
class Segurium_Cloud_Endpoint {

	const PRIMARY   = 'primary';
	const SECONDARY = 'secondary';

	const PRIMARY_BASE   = 'https://cti.segurium.com:8901';
	const SECONDARY_BASE = 'https://cti2.segurium.com';

	/**
	 * Absent while the primary is selected. On the secondary it holds
	 * `selected` and `since`, the time of the last move.
	 */
	const OPTION = 'segurium_cloud_endpoint';

	const PRIMARY_RETRY_SEC = DAY_IN_SECONDS;

	const RESEND_MIN_TIMEOUT_SEC = 5;

	const PROBE_TIMEOUT_SEC = 10;

	/**
	 * Endpoint the next request uses.
	 *
	 * @return string PRIMARY or SECONDARY.
	 */
	public static function selected() {
		$state = self::state();
		return $state['selected'];
	}

	/**
	 * Whether a name is one of the two endpoints above.
	 *
	 * @param mixed $endpoint Candidate name.
	 * @return bool
	 */
	public static function is_known( $endpoint ) {
		return self::PRIMARY === $endpoint || self::SECONDARY === $endpoint;
	}

	/**
	 * Probe one endpoint's health route and select the endpoint when the
	 * probe passes the rule the fallback applies to that endpoint: any HTTP
	 * status for the primary, a status under 500 for the secondary. The
	 * probe never moves to the other endpoint.
	 *
	 * @param string $endpoint PRIMARY or SECONDARY.
	 * @return string '' after the switch, else `http_<status>`, `curl_<errno>` or `transport`.
	 */
	public static function switch_to( $endpoint ) {
		$response = wp_remote_request(
			self::url( self::PRIMARY_BASE . '/health', $endpoint ),
			array(
				'method'  => 'GET',
				'timeout' => self::PROBE_TIMEOUT_SEC,
			)
		);

		$failure = '';
		if ( is_wp_error( $response ) ) {
			$message = (string) $response->get_error_message();
			$failure = preg_match( '/^cURL error (\d+):/', $message, $match ) ? 'curl_' . $match[1] : 'transport';
			Segurium_Debug::log( '[segurium] cloud endpoint probe of ' . $endpoint . ' failed: ' . $message );
		} elseif ( self::SECONDARY === $endpoint && (int) wp_remote_retrieve_response_code( $response ) >= 500 ) {
			$failure = 'http_' . (int) wp_remote_retrieve_response_code( $response );
		}

		if ( '' === $failure ) {
			self::select( $endpoint );
		}
		return $failure;
	}

	/**
	 * Move a primary URL onto an endpoint.
	 *
	 * @param string      $url      URL built on PRIMARY_BASE.
	 * @param string|null $endpoint Target endpoint, or null for the selected one.
	 * @return string
	 */
	public static function url( $url, $endpoint = null ) {
		$endpoint = null === $endpoint ? self::selected() : $endpoint;
		if ( self::SECONDARY !== $endpoint || 0 !== strpos( $url, self::PRIMARY_BASE . '/' ) ) {
			return $url;
		}
		return self::SECONDARY_BASE . substr( $url, strlen( self::PRIMARY_BASE ) );
	}

	/**
	 * GET through the selected endpoint.
	 *
	 * @param string $url  URL built on PRIMARY_BASE.
	 * @param array  $args wp_remote_request() arguments.
	 * @return array|WP_Error
	 */
	public static function get( $url, array $args = array() ) {
		$args['method'] = 'GET';
		return self::request( $url, $args );
	}

	/**
	 * POST through the selected endpoint.
	 *
	 * @param string $url  URL built on PRIMARY_BASE.
	 * @param array  $args wp_remote_request() arguments.
	 * @return array|WP_Error
	 */
	public static function post( $url, array $args = array() ) {
		$args['method'] = 'POST';
		return self::request( $url, $args );
	}

	/**
	 * Send one request. After a connect failure the request goes to the other
	 * endpoint, and the selection moves there when that endpoint answers.
	 *
	 * @param string $url  URL built on PRIMARY_BASE.
	 * @param array  $args wp_remote_request() arguments.
	 * @return array|WP_Error
	 */
	public static function request( $url, array $args = array() ) {
		$state    = self::state();
		$first    = $state['selected'];
		$blocking = ! isset( $args['blocking'] ) || $args['blocking'];
		// A non-blocking call reports no failure, so a retry of the primary
		// there would lose the request on a host that blocks the port.
		if ( self::SECONDARY === $first && $blocking && abs( time() - $state['since'] ) >= self::PRIMARY_RETRY_SEC ) {
			$first = self::PRIMARY;
		}

		$started  = microtime( true );
		$response = wp_remote_request( self::url( $url, $first ), $args );
		if ( ! self::is_connect_failure( $response ) ) {
			if ( $first !== $state['selected'] ) {
				// An error here leaves the primary unproven, so the site waits another day.
				self::select( is_wp_error( $response ) ? $state['selected'] : $first );
			}
			return $response;
		}

		// The caller budgeted one timeout for the whole call.
		$timeout         = isset( $args['timeout'] ) ? (float) $args['timeout'] : 5.0;
		$args['timeout'] = max( self::RESEND_MIN_TIMEOUT_SEC, $timeout - ( microtime( true ) - $started ) );

		$other  = self::PRIMARY === $first ? self::SECONDARY : self::PRIMARY;
		$resent = wp_remote_request( self::url( $url, $other ), $args );
		// A 5xx from the secondary is the proxy failing to reach the same cloud.
		if ( ! is_wp_error( $resent ) && wp_remote_retrieve_response_code( $resent ) < 500 ) {
			self::select( $other );
		}
		return $resent;
	}

	/**
	 * Whether a transport error happened before any byte of the request left.
	 * An unknown error text counts as sent, so a request never goes out twice
	 * by mistake.
	 *
	 * @param mixed $error wp_remote_request() result.
	 * @return bool
	 */
	public static function is_connect_failure( $error ) {
		if ( ! is_wp_error( $error ) ) {
			return false;
		}
		$message = (string) $error->get_error_message();
		if ( preg_match( '/^cURL error (\d+): (.*)$/s', $message, $match ) ) {
			$errno = (int) $match[1];
			// 5/6 resolve, 7 connect, 35 TLS handshake, 60 TLS certificate, 97 proxy handshake.
			if ( in_array( $errno, array( 5, 6, 7, 35, 60, 97 ), true ) ) {
				return true;
			}
			// cURL reports connect, resolve and read timeouts under one number.
			if ( 28 === $errno ) {
				return 1 === preg_match( '/^(Connection time|Resolving timed out|Failed to connect|SSL connection timeout)/i', $match[2] );
			}
			if ( 56 === $errno ) {
				return 1 === preg_match( '/proxy after CONNECT|CONNECT tunnel failed/i', $match[2] );
			}
			return false;
		}
		if ( 'fsocket timed out' === $message ) {
			return false;
		}
		return 1 === preg_match( '/getaddrinfo|refused|timed out|unreachable|No route to host|unable to connect|SSL operation failed|Failed to enable crypto|certificate/i', $message );
	}

	/**
	 * Stored selection.
	 *
	 * @return array{selected:string,since:int}
	 */
	private static function state() {
		$state = Segurium_Storage::setting_get_array( self::OPTION );
		if ( ! isset( $state['selected'] ) || self::SECONDARY !== $state['selected'] ) {
			return array(
				'selected' => self::PRIMARY,
				'since'    => 0,
			);
		}
		return array(
			'selected' => self::SECONDARY,
			'since'    => isset( $state['since'] ) ? (int) $state['since'] : 0,
		);
	}

	/**
	 * Store the selection.
	 *
	 * @param string $endpoint PRIMARY or SECONDARY.
	 * @return void
	 */
	private static function select( $endpoint ) {
		if ( self::PRIMARY === $endpoint ) {
			Segurium_Storage::setting_delete( self::OPTION );
			return;
		}
		Segurium_Storage::setting_set(
			self::OPTION,
			array(
				'selected' => self::SECONDARY,
				'since'    => time(),
			)
		);
	}
}

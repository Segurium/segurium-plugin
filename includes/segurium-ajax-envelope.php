<?php
/**
 * Segurium AJAX response envelope.
 *
 * Wraps every Segurium AJAX JSON payload in sentinel markers so the client
 * can strip any bytes a contaminated WordPress install may have emitted
 * before or after our handler (mu-plugins, wp-config tampering, BOMs,
 * `auto_prepend_file`, tampered core, PHP notices, and so on).
 *
 * The markers are the only thing the client trusts. Anything outside
 * `<<<SEG-JSON:1:BEGIN>>> … <<<SEG-JSON:1:END>>>` is discarded.
 *
 * See docs/features/ajax-envelope.md for the full threat model.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'SEGURIUM_AJAX_ENVELOPE_VERSION' ) ) {
	define( 'SEGURIUM_AJAX_ENVELOPE_VERSION', 1 );
}
if ( ! defined( 'SEGURIUM_AJAX_ENVELOPE_BEGIN' ) ) {
	define( 'SEGURIUM_AJAX_ENVELOPE_BEGIN', "\n<<<SEG-JSON:1:BEGIN>>>\n" );
}
if ( ! defined( 'SEGURIUM_AJAX_ENVELOPE_END' ) ) {
	define( 'SEGURIUM_AJAX_ENVELOPE_END', "\n<<<SEG-JSON:1:END>>>\n" );
}

/**
 * Emit an enveloped JSON response and terminate the request.
 *
 * The output is deliberately NOT declared as `application/json` — the
 * sentinel markers make the body non-JSON by construction. Clients that
 * call `seguriumFetchJson()` read the body as text and unwrap.
 *
 * @param array|object|null $response    Payload to encode.
 * @param int|null          $status_code Optional HTTP status.
 * @return void
 */
function segurium_send_json( $response, $status_code = null ) {
	if ( ! headers_sent() ) {
		if ( null !== $status_code ) {
			status_header( $status_code );
		}
		header( 'Content-Type: text/plain; charset=' . get_bloginfo( 'charset' ) );
		header( 'X-Segurium-Envelope: v' . (string) SEGURIUM_AJAX_ENVELOPE_VERSION );
	}

	echo SEGURIUM_AJAX_ENVELOPE_BEGIN; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	echo wp_json_encode( $response ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	echo SEGURIUM_AJAX_ENVELOPE_END; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

	wp_die( '', '', array( 'response' => null ) );
}

/**
 * Successful enveloped JSON response.
 *
 * Drop-in replacement for wp_send_json_success().
 *
 * @param mixed    $data        Payload.
 * @param int|null $status_code Optional HTTP status.
 * @return void
 */
function segurium_send_json_success( $data = null, $status_code = null ) {
	segurium_send_json(
		array(
			'success' => true,
			'data'    => $data,
		),
		$status_code
	);
}

/**
 * Error enveloped JSON response.
 *
 * Drop-in replacement for wp_send_json_error().
 *
 * @param mixed    $data        Payload.
 * @param int|null $status_code Optional HTTP status.
 * @return void
 */
function segurium_send_json_error( $data = null, $status_code = null ) {
	segurium_send_json(
		array(
			'success' => false,
			'data'    => $data,
		),
		$status_code
	);
}

/**
 * Error envelope for an AJAX request that omitted a required field.
 *
 * @param string $field Name of the missing $_POST field.
 * @return void
 */
function segurium_send_missing_param( $field ) {
	segurium_send_json_error(
		array(
			'code'    => 'missing_param',
			'field'   => $field,
			/* translators: %s is the name of the missing form field. */
			'message' => sprintf( __( 'Missing parameter: %s', 'segurium' ), $field ),
		)
	);
}

/**
 * Capability gate that envelopes failures.
 *
 * @param string $cap Required capability.
 * @return void
 */
function segurium_ajax_require_cap( $cap ) {
	if ( ! current_user_can( $cap ) ) {
		segurium_send_json_error(
			array(
				'code'    => 'insufficient_permissions',
				'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
			),
			403
		);
	}
}

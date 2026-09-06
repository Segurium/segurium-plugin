<?php
/**
 * WP-CLI `wp segurium license ...` commands.
 *
 * Split out of class-segurium-cli.php so each file holds a single class
 * (Generic.Files.OneObjectStructurePerFile).
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
 * `wp segurium license ...` — activate Pro without a browser session.
 */
class Segurium_CLI_License {

	/**
	 * Activate a Pro licence on this site.
	 *
	 * Runs the same follow-through the Account tab runs: the cloud learns the
	 * new tier and the entitlements envelope flips to unlimited cleanup
	 * without waiting for a webhook.
	 *
	 * Omit the key to use `SEGURIUM_LICENSE_KEY` from wp-config.php. That
	 * keeps the key out of shell history and out of the process list, which
	 * matters on a shared host.
	 *
	 * ## OPTIONS
	 *
	 * [<key>]
	 * : The licence key. Defaults to the SEGURIUM_LICENSE_KEY constant.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium license activate
	 *     wp segurium license activate sk_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args; the licence key, if given.
	 * @param array $assoc_args Flag args (unused).
	 */
	public function activate( $args, $assoc_args ) {
		unset( $assoc_args );

		$key    = isset( $args[0] ) ? (string) $args[0] : '';
		$result = Segurium_License::instance()->activate( $key );

		$this->print_state( $result['state'] );

		if ( ! $result['ok'] ) {
			WP_CLI::error( self::failure_line( $result ) );
			return;
		}

		if ( Segurium_License::CODE_ALREADY_ACTIVE === $result['code'] ) {
			WP_CLI::success( 'That licence is already active. Nothing changed.' );
			return;
		}

		WP_CLI::success( 'Pro licence activated.' );
	}

	/**
	 * Release the Pro licence and free its seat.
	 *
	 * The seat returns to the bundle immediately. The plan tier follows once
	 * the cloud has seen the vendor's cancellation.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium license deactivate
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args (unused).
	 */
	public function deactivate( $args, $assoc_args ) {
		unset( $args, $assoc_args );

		$result = Segurium_License::instance()->deactivate();

		$this->print_state( $result['state'] );

		if ( ! $result['ok'] ) {
			WP_CLI::error( self::failure_line( $result ) );
			return;
		}

		WP_CLI::success( 'Pro licence released. The seat is free.' );
	}

	/**
	 * Report the current licence state.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. One of: table, json, yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium license status
	 *     wp segurium license status --format=json
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args.
	 */
	public function status( $args, $assoc_args ) {
		unset( $args );

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( ! in_array( $format, array( 'table', 'json', 'yaml' ), true ) ) {
			WP_CLI::error( '--format must be table, json or yaml. [license_invalid_format]' );
			return;
		}

		$state = Segurium_License::instance()->state();

		if ( 'json' === $format || 'yaml' === $format ) {
			WP_CLI\Utils\format_items( $format, array( $state ), array_keys( $state ) );
			return;
		}
		WP_CLI\Utils\format_items( 'table', self::rows( $state ), array( 'key', 'value' ) );
	}

	/**
	 * One refusal line carrying our code and, when Freemius supplied one,
	 * the vendor's own code and message.
	 *
	 * @param array $result Result from {@see Segurium_License}.
	 * @return string
	 */
	private static function failure_line( array $result ) {
		$line = self::message_for( $result['code'] );

		if ( '' !== $result['vendor_message'] ) {
			$line .= ' Freemius said: ' . $result['vendor_message'];
		}
		if ( '' !== $result['vendor_code'] ) {
			$line .= ' [vendor: ' . $result['vendor_code'] . ']';
		}

		return $line . ' [license_' . $result['code'] . ']';
	}

	/**
	 * Plain-language line for one refusal code.
	 *
	 * @param string $code One of the Segurium_License::CODE_* constants.
	 * @return string
	 */
	private static function message_for( $code ) {
		$messages = array(
			Segurium_License::CODE_KEY_MISSING      => 'No licence key given, and SEGURIUM_LICENSE_KEY is not set in wp-config.php.',
			Segurium_License::CODE_KEY_INVALID      => 'That is not a licence key. Keys are ' . Segurium_License::KEY_LENGTH . ' characters and carry no spaces.',
			Segurium_License::CODE_CONSENT_REQUIRED => 'Accept the External Service Disclosure first: wp segurium consent accept --i-accept',
			Segurium_License::CODE_SDK_UNAVAILABLE  => 'The billing layer is not available on this install.',
			Segurium_License::CODE_INVALID          => 'Freemius does not recognise that licence key.',
			Segurium_License::CODE_NO_SEATS         => 'That licence has no seats left.',
			Segurium_License::CODE_BOUND_ELSEWHERE  => 'That licence is already in use on another site. Release it there first.',
			Segurium_License::CODE_EXPIRED          => 'That licence has expired.',
			Segurium_License::CODE_NETWORK_FAILURE  => 'Could not reach Freemius.',
			Segurium_License::CODE_NOT_ACTIVE       => 'No licence is active on this site.',
			Segurium_License::CODE_RELEASE_FAILED   => 'Freemius refused to release the licence.',
			Segurium_License::CODE_NOT_CONFIRMED    => 'Freemius accepted the key but this site is not activated yet. If the licence owner already has a Freemius account, check the inbox for an activation email, then run this command again.',
		);

		return isset( $messages[ $code ] ) ? $messages[ $code ] : 'Licence activation was refused.';
	}

	/**
	 * Print the state block that precedes every success and every refusal.
	 *
	 * @param array $state State from {@see Segurium_License::state()}.
	 * @return void
	 */
	private function print_state( array $state ) {
		foreach ( self::rows( $state ) as $row ) {
			WP_CLI::log( str_pad( $row['key'] . ':', 20 ) . $row['value'] );
		}
	}

	/**
	 * Flatten a state array into printable key/value rows.
	 *
	 * @param array $state State from {@see Segurium_License::state()}.
	 * @return array<int,array{key:string,value:string}>
	 */
	private static function rows( array $state ) {
		$rows = array();
		foreach ( $state as $key => $value ) {
			if ( is_bool( $value ) ) {
				$value = $value ? 'yes' : 'no';
			}
			$rows[] = array(
				'key'   => (string) $key,
				'value' => (string) $value,
			);
		}
		return $rows;
	}
}

WP_CLI::add_command( 'segurium license', 'Segurium_CLI_License' );

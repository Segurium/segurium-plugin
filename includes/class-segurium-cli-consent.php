<?php
/**
 * WP-CLI `wp segurium consent ...` commands.
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
 * `wp segurium consent ...` — accept the External Service Disclosure
 * without opening the admin screen.
 */
class Segurium_CLI_Consent {

	/**
	 * Accept the External Service Disclosure.
	 *
	 * Leaves exactly the state a click on the admin screen leaves:
	 * consent and cloud detection on, the alerts contact stored, IID
	 * registration queued on cron, and the activation, consent and
	 * platform-snapshot messages sent. Without `--i-accept` the command
	 * prints the disclosure and exits 1.
	 *
	 * ## OPTIONS
	 *
	 * [--i-accept]
	 * : Confirm that you accept the disclosure this command prints. Required.
	 *
	 * [--email=<address>]
	 * : Contact address for security alerts. Defaults to the WordPress
	 * site admin email.
	 *
	 * [--alerts=<state>]
	 * : Email alerts opt-in. One of: on, off. Default: on, matching the
	 * admin screen.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium consent accept --i-accept
	 *     wp segurium consent accept --email=soc@agency.example --i-accept
	 *     wp segurium consent accept --email=soc@agency.example --alerts=off --i-accept
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args.
	 */
	public function accept( $args, $assoc_args ) {
		unset( $args );

		if ( empty( $assoc_args['i-accept'] ) ) {
			self::print_disclosure();
			WP_CLI::error( 'Re-run with --i-accept to accept the disclosure above. [consent_not_confirmed]' );
			return;
		}

		$alerts = isset( $assoc_args['alerts'] ) ? strtolower( (string) $assoc_args['alerts'] ) : 'on';
		if ( ! in_array( $alerts, array( 'on', 'off' ), true ) ) {
			WP_CLI::error( '--alerts must be on or off. [consent_invalid_alerts]' );
			return;
		}

		$email = isset( $assoc_args['email'] ) ? (string) $assoc_args['email'] : '';
		if ( '' !== $email && ! is_email( $email ) ) {
			WP_CLI::error( '--email is not a valid address. [consent_invalid_email]' );
			return;
		}

		$result = Segurium_Consent::accept(
			Segurium_Consent::SOURCE_CLI,
			array(
				'alerts' => array(
					'enabled' => 'on' === $alerts,
					'email'   => $email,
				),
			)
		);

		foreach ( self::rows( $result['state'] ) as $row ) {
			WP_CLI::log( str_pad( $row['key'] . ':', 18 ) . $row['value'] );
		}

		if ( ! $result['accepted'] ) {
			if ( 'already_accepted' === $result['code'] ) {
				WP_CLI::success( 'Consent was already accepted. Nothing changed.' );
				return;
			}
			WP_CLI::error( 'Consent was not accepted. [consent_' . $result['code'] . ']' );
			return;
		}

		WP_CLI::success( 'External Service Disclosure accepted.' );
		if ( ! $result['state']['iid_registered'] ) {
			WP_CLI::log( 'Registration with Segurium Cloud is queued. Run `wp cron event run --due-now` to complete it.' );
		}
	}

	/**
	 * Report the current consent state.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format. One of: table, json, yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium consent status
	 *     wp segurium consent status --format=json
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
			WP_CLI::error( '--format must be table, json or yaml. [consent_invalid_format]' );
			return;
		}
		$state = Segurium_Consent::state();

		if ( 'json' === $format || 'yaml' === $format ) {
			WP_CLI\Utils\format_items( $format, array( $state ), array_keys( $state ) );
			return;
		}
		WP_CLI\Utils\format_items( 'table', self::rows( $state ), array( 'key', 'value' ) );
	}

	/**
	 * Flatten a state array into printable key/value rows.
	 *
	 * @param array $state State from {@see Segurium_Consent::state()}.
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

	/**
	 * Print the same disclosure the admin screen renders.
	 *
	 * @return void
	 */
	private static function print_disclosure() {
		$disclosure = Segurium_Consent::disclosure();

		WP_CLI::log( $disclosure['title'] );
		WP_CLI::log( '' );
		WP_CLI::log( $disclosure['intro'] );

		foreach ( $disclosure['lists'] as $list ) {
			WP_CLI::log( '' );
			WP_CLI::log( $list['heading'] );
			foreach ( $list['items'] as $item ) {
				WP_CLI::log( '  - ' . $item );
			}
		}

		WP_CLI::log( '' );
		foreach ( $disclosure['facts'] as $fact ) {
			WP_CLI::log( $fact['label'] . ' ' . $fact['value'] );
		}

		WP_CLI::log( '' );
		WP_CLI::log(
			sprintf(
				$disclosure['legal']['format'],
				'',
				' <' . $disclosure['legal']['terms_url'] . '>',
				'',
				' <' . $disclosure['legal']['privacy_url'] . '>'
			)
		);
		WP_CLI::log( '' );
	}
}

WP_CLI::add_command( 'segurium consent', 'Segurium_CLI_Consent' );

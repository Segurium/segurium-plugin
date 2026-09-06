<?php
/**
 * WP-CLI `wp segurium settings ...` commands.
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
 * `wp segurium settings ...` — move a settings profile between sites.
 */
class Segurium_CLI_Settings {

	/**
	 * Write the site's settings as a portable profile.
	 *
	 * The install identity, the consent record, billing, scan state and
	 * telemetry are not settings and never appear in the file. The hCaptcha
	 * secret key is withheld unless you ask for it, and the file names what
	 * was withheld.
	 *
	 * ## OPTIONS
	 *
	 * [--file=<path>]
	 * : Write to this path. Without it the profile goes to standard output.
	 *
	 * [--include-secrets]
	 * : Carry secret fields. The file is then as sensitive as the site.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium settings export --file=profile.json
	 *     wp segurium settings export | ssh site16 wp segurium settings import -
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args.
	 */
	public function export( $args, $assoc_args ) {
		unset( $args );

		$profile = Segurium_Settings_Profile::export(
			array( 'include_secrets' => ! empty( $assoc_args['include-secrets'] ) )
		);

		$json = wp_json_encode( $profile, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		if ( false === $json ) {
			WP_CLI::error( 'The settings could not be encoded. [settings_encode_failed]' );
			return;
		}

		$path = isset( $assoc_args['file'] ) ? (string) $assoc_args['file'] : '';
		if ( '' === $path ) {
			WP_CLI::line( $json );
			return;
		}

		if ( false === file_put_contents( $path, $json . "\n" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- an operator-named path outside the WordPress tree.
			WP_CLI::error( 'Could not write ' . $path . '. [settings_write_failed]' );
			return;
		}

		// A profile carrying a secret is as sensitive as the site. The umask
		// would otherwise leave it world-readable, and an operator writing
		// into a webroot would serve it.
		if ( ! empty( $assoc_args['include-secrets'] ) && ! chmod( $path, 0600 ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- an operator-named path outside the WordPress tree.
			WP_CLI::warning( 'Could not restrict permissions on ' . $path . '; it carries a secret. [settings_chmod_failed]' );
		}

		foreach ( $profile['withheld'] as $field ) {
			WP_CLI::log( 'withheld: ' . $field );
		}
		WP_CLI::success( sprintf( 'Wrote %d features to %s.', count( $profile['features'] ), $path ) );
	}

	/**
	 * Apply a settings profile written by `wp segurium settings export`.
	 *
	 * The site keeps its own identity, its own consent record and its own
	 * licence. Geo blocking and the firewall come up live: the browser flow
	 * arms a 60-second revert nobody is watching on a headless import, so the
	 * import applies straight away instead.
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : Path to the profile, or `-` to read standard input.
	 *
	 * [--dry-run]
	 * : Validate and report without writing anything.
	 *
	 * [--include-secrets]
	 * : Apply secret fields the file carries. Ignored when it carries none.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium settings import profile.json --dry-run
	 *     wp segurium settings import profile.json
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args: the profile path.
	 * @param array $assoc_args Flag args.
	 */
	public function import( $args, $assoc_args ) {
		$path = isset( $args[0] ) ? (string) $args[0] : '';
		if ( '' === $path ) {
			WP_CLI::error( 'Name a profile file, or - to read standard input. [settings_no_file]' );
			return;
		}

		$raw = self::read( $path );
		if ( is_wp_error( $raw ) ) {
			WP_CLI::error( $raw->get_error_message() . ' [' . $raw->get_error_code() . ']' );
			return;
		}

		$profile = Segurium_Settings_Profile::decode( $raw );
		if ( is_wp_error( $profile ) ) {
			WP_CLI::error( $profile->get_error_message() . ' [' . $profile->get_error_code() . ']' );
			return;
		}

		$result = Segurium_Settings_Profile::import(
			$profile,
			array(
				'dry_run'         => ! empty( $assoc_args['dry-run'] ),
				'include_secrets' => ! empty( $assoc_args['include-secrets'] ),
			)
		);

		if ( ! $result['ok'] ) {
			$error = isset( $result['errors'][0] ) ? $result['errors'][0] : array();
			WP_CLI::error( ( $error['message'] ?? 'The profile was refused.' ) . ' [' . ( $error['code'] ?? 'profile_invalid' ) . ']' );
			return;
		}

		$applied = 0;
		$skipped = 0;
		foreach ( $result['features'] as $slug => $feature ) {
			if ( 'applied' === $feature['status'] ) {
				++$applied;
				WP_CLI::log( self::line( $slug, $feature['changed'] ? 'applied' : 'unchanged' ) );
			} else {
				++$skipped;
				$detail = '' !== $feature['message'] ? ' — ' . $feature['message'] : '';
				WP_CLI::log( self::line( $slug, 'skipped: ' . $feature['code'] . $detail ) );
			}
			foreach ( $feature['dropped'] as $field ) {
				WP_CLI::log( self::line( '', '  dropped ' . $field . ', this version does not store it' ) );
			}
			foreach ( $feature['withheld'] as $field ) {
				WP_CLI::log( self::line( '', '  withheld ' . $field . ', re-run with --include-secrets to apply it' ) );
			}
			foreach ( $feature['warnings'] as $warning ) {
				WP_CLI::log( self::line( '', '  ' . $warning ) );
			}
		}

		$summary = sprintf( '%d applied, %d skipped.', $applied, $skipped );

		if ( 0 === $applied ) {
			WP_CLI::error( 'No feature in the profile applied. ' . $summary . ' [settings_nothing_applied]' );
			return;
		}

		if ( $result['dry_run'] ) {
			WP_CLI::success( 'Dry run, nothing written. ' . $summary );
			return;
		}
		WP_CLI::success( $summary );
	}

	/**
	 * Read the profile from a path or from standard input.
	 *
	 * @param string $path Operator-named path, or `-`.
	 * @return string|WP_Error
	 */
	private static function read( string $path ) {
		if ( '-' === $path ) {
			$raw = file_get_contents( 'php://stdin' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a pipe, not a URL.
			if ( false === $raw || '' === $raw ) {
				return new WP_Error( 'settings_empty_stdin', 'Nothing arrived on standard input.' );
			}
			return $raw;
		}

		if ( ! is_readable( $path ) ) {
			return new WP_Error( 'settings_unreadable', 'Cannot read ' . $path . '.' );
		}

		$raw = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- an operator-named path outside the WordPress tree.
		if ( false === $raw ) {
			return new WP_Error( 'settings_unreadable', 'Cannot read ' . $path . '.' );
		}
		return $raw;
	}

	/**
	 * One aligned report line.
	 *
	 * @param string $slug Feature slug, or '' for a continuation line.
	 * @param string $text What happened.
	 * @return string
	 */
	private static function line( string $slug, string $text ): string {
		return str_pad( '' === $slug ? '' : $slug . ':', 18 ) . $text;
	}
}

WP_CLI::add_command( 'segurium settings', 'Segurium_CLI_Settings' );

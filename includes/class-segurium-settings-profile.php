<?php
/**
 * Portable settings profile: read every feature out of the registry, write
 * every feature back through the writer.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Export and import of the plugin's own settings.
 */
class Segurium_Settings_Profile {

	/**
	 * Profile format version. A file naming a higher one is refused rather
	 * than guessed at.
	 */
	const SCHEMA = 1;

	/**
	 * Ceiling on a profile read from disk or a pipe. The firewall list and
	 * the scan exclusions are the only fields that grow, and both are capped
	 * far below this by their own validators.
	 */
	const MAX_BYTES = 524288;

	const CODE_INVALID        = 'profile_invalid';
	const CODE_SCHEMA_MISSING = 'profile_schema_missing';
	const CODE_SCHEMA_NEWER   = 'profile_schema_newer';
	const CODE_TOO_LARGE      = 'profile_too_large';
	const CODE_UNKNOWN        = 'unknown_feature';

	/**
	 * Build a profile of the settings as they stand.
	 *
	 * @param array $options `include_secrets` carries fields the registry
	 *                       marks secret. Off by default.
	 * @return array
	 */
	public static function export( array $options = array() ): array {
		$with_secrets = ! empty( $options['include_secrets'] );

		$features = array();
		$withheld = array();

		foreach ( Segurium_Settings::slugs() as $slug ) {
			$settings = Segurium_Settings::get( $slug, true );

			// A field the site owns alone never travels, whatever the caller
			// asked for. The scheduled scan's randomised slot is the case:
			// carrying it across a fleet fires every site in the same minute.
			foreach ( Segurium_Settings::local_fields( $slug ) as $field ) {
				unset( $settings[ $field ] );
			}

			if ( ! $with_secrets ) {
				foreach ( Segurium_Settings::secret_fields( $slug ) as $field ) {
					if ( ! array_key_exists( $field, $settings ) ) {
						continue;
					}
					unset( $settings[ $field ] );
					$withheld[] = $slug . '.' . $field;
				}
			}

			$features[ $slug ] = $settings;
		}

		return array(
			'schema'         => self::SCHEMA,
			'plugin_version' => defined( 'SEGURIUM_VERSION' ) ? SEGURIUM_VERSION : '',
			'generated_at'   => gmdate( 'c' ),
			'withheld'       => $withheld,
			'features'       => $features,
		);
	}

	/**
	 * Turn profile text into a profile array.
	 *
	 * @param string $json Raw file or stream contents.
	 * @return array|WP_Error
	 */
	public static function decode( string $json ) {
		if ( strlen( $json ) > self::MAX_BYTES ) {
			return new WP_Error(
				self::CODE_TOO_LARGE,
				sprintf( 'A settings profile is limited to %d bytes.', self::MAX_BYTES )
			);
		}

		$decoded = json_decode( $json, true );
		if ( ! is_array( $decoded ) ) {
			return new WP_Error(
				self::CODE_INVALID,
				'The file is not a settings profile.'
			);
		}

		return $decoded;
	}

	/**
	 * Apply a profile.
	 *
	 * Every feature goes through the settings writer, so validation, the
	 * wp-config gates and the CTI snapshot are the ones a click produces.
	 * Staging is off: a headless caller has no browser to confirm the
	 * 60-second fuse with, and an armed fuse would revert the import.
	 *
	 * @param array $profile Decoded profile.
	 * @param array $options `dry_run` validates and writes nothing;
	 *                       `include_secrets` applies secret fields the file
	 *                       carries.
	 * @return array
	 */
	public static function import( $profile, array $options = array() ): array {
		$dry_run = ! empty( $options['dry_run'] );
		$secrets = ! empty( $options['include_secrets'] );

		$result = array(
			'ok'       => false,
			'dry_run'  => $dry_run,
			'schema'   => 0,
			'features' => array(),
			'errors'   => array(),
		);

		if ( ! is_array( $profile ) || ! isset( $profile['features'] ) || ! is_array( $profile['features'] ) ) {
			return self::refuse( $result, self::CODE_INVALID, 'The file is not a settings profile.' );
		}

		if ( array() === $profile['features'] ) {
			return self::refuse( $result, self::CODE_INVALID, 'The profile names no features.' );
		}

		if ( ! isset( $profile['schema'] ) || ! is_numeric( $profile['schema'] ) ) {
			return self::refuse( $result, self::CODE_SCHEMA_MISSING, 'The profile does not say which format it is in.' );
		}

		$schema           = (int) $profile['schema'];
		$result['schema'] = $schema;

		if ( $schema > self::SCHEMA ) {
			return self::refuse(
				$result,
				self::CODE_SCHEMA_NEWER,
				'The profile was written by a newer version of Segurium. Update the plugin and import again.'
			);
		}

		foreach ( $profile['features'] as $slug => $values ) {
			$slug                        = (string) $slug;
			$result['features'][ $slug ] = self::apply_feature( $slug, $values, $dry_run, $secrets );
		}

		$result['ok'] = true;
		return $result;
	}

	/*
	 * ─────────────────────────────────────────────────────────────────────
	 * One feature.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Write one feature and describe what happened.
	 *
	 * @param string $slug    Registry slug named by the file.
	 * @param mixed  $values  Field map the file carries for the feature.
	 * @param bool   $dry_run Validate only.
	 * @param bool   $secrets Apply secret fields the file carries.
	 * @return array
	 */
	private static function apply_feature( string $slug, $values, bool $dry_run, bool $secrets ): array {
		$report = array(
			'status'   => 'skipped',
			'changed'  => false,
			'code'     => '',
			'message'  => '',
			'withheld' => array(),
			'dropped'  => array(),
			'warnings' => array(),
		);

		if ( ! Segurium_Settings::has( $slug ) ) {
			$report['code']    = self::CODE_UNKNOWN;
			$report['message'] = 'This version of Segurium has no such feature.';
			return $report;
		}

		if ( ! is_array( $values ) ) {
			$report['code']    = self::CODE_INVALID;
			$report['message'] = 'The profile holds no settings for this feature.';
			return $report;
		}

		foreach ( Segurium_Settings::local_fields( $slug ) as $field ) {
			unset( $values[ $field ] );
		}

		if ( ! $secrets ) {
			foreach ( Segurium_Settings::secret_fields( $slug ) as $field ) {
				if ( ! array_key_exists( $field, $values ) ) {
					continue;
				}
				unset( $values[ $field ] );
				$report['withheld'][] = $field;
			}
		}

		$saved = Segurium_Settings_Writer::save(
			$slug,
			$values,
			array(
				'stage'   => false,
				'dry_run' => $dry_run,
			)
		);

		if ( ! $saved['ok'] ) {
			$error             = isset( $saved['errors'][0] ) ? $saved['errors'][0] : array();
			$report['code']    = (string) ( $error['code'] ?? Segurium_Settings_Writer::CODE_INVALID_VALUE );
			$report['message'] = Segurium_Settings_Writer::error_message( $error );
			return $report;
		}

		if ( ! $dry_run ) {
			self::disarm( $slug );
		}

		$report['status']   = 'applied';
		$report['changed']  = (bool) $saved['changed'];
		$report['warnings'] = $saved['warnings'];
		$report['dropped']  = array_keys( $saved['skipped'] );

		return $report;
	}

	/**
	 * Clear a fuse armed before the import. A browser save moments earlier
	 * would otherwise revert the imported values with nobody watching.
	 *
	 * @param string $slug Registry slug.
	 * @return void
	 */
	private static function disarm( string $slug ): void {
		$context = Segurium_Settings::pending_context( $slug );
		if ( null === $context ) {
			return;
		}
		$token = Segurium_Storage::setting_get( 'segurium_pending_ctx_' . $context, '' );
		if ( '' === (string) $token ) {
			return;
		}
		Segurium_Pending_Changes::cancel( (string) $token );
	}

	/**
	 * Attach a reason code and hand the result back with nothing written.
	 *
	 * @param array  $result  Result so far.
	 * @param string $code    Reason code.
	 * @param string $message Operator-facing detail.
	 * @return array
	 */
	private static function refuse( array $result, string $code, string $message ): array {
		$result['errors'][] = array(
			'code'    => $code,
			'message' => $message,
		);
		return $result;
	}
}

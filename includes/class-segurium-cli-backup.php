<?php
/**
 * WP-CLI `wp segurium backup ...` commands.
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
 * `wp segurium backup ...`: reach the backups Segurium made when wp-admin
 * cannot load. The CLI reads neither `.user.ini` nor the web server's
 * `auto_prepend_file`, so it runs on a site whose every HTTP request fatals.
 */
class Segurium_CLI_Backup {

	const BUCKETS = array( 'integrity', 'malware', 'component' );

	/**
	 * List the backups on disk, newest first.
	 *
	 * ## OPTIONS
	 *
	 * [--bucket=<bucket>]
	 * : Only this bucket. One of: integrity, malware, component.
	 *
	 * [--format=<format>]
	 * : Output format. One of: table, json, csv, yaml. Default: table.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium backup list
	 *     wp segurium backup list --bucket=integrity --format=json
	 *
	 * @subcommand list
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Flag args.
	 */
	public function list_( $args, $assoc_args ) {
		unset( $args );
		$buckets = self::BUCKETS;
		if ( isset( $assoc_args['bucket'] ) ) {
			$bucket = (string) $assoc_args['bucket'];
			if ( ! in_array( $bucket, self::BUCKETS, true ) ) {
				WP_CLI::error( 'Unknown bucket "' . $bucket . '". Use one of: ' . implode( ', ', self::BUCKETS ) . '. [backup_invalid_bucket]' );
				return;
			}
			$buckets = array( $bucket );
		}

		$rows = array();
		foreach ( $buckets as $bucket ) {
			foreach ( Segurium_Storage::backup_list( $bucket ) as $meta ) {
				$rows[] = array(
					'backup_id'  => (string) ( $meta['backup_id'] ?? '' ),
					'bucket'     => $bucket,
					'path'       => self::display_path( $meta ),
					'action'     => (string) ( $meta['action'] ?? '' ),
					'created_at' => gmdate( 'Y-m-d H:i:s', (int) ( $meta['created_at'] ?? 0 ) ),
				);
			}
		}
		usort(
			$rows,
			static function ( $a, $b ) {
				return strcmp( $b['backup_id'], $a['backup_id'] );
			}
		);

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		WP_CLI\Utils\format_items( $format, $rows, array( 'backup_id', 'bucket', 'path', 'action', 'created_at' ) );
	}

	/**
	 * Restore one backup to where it came from.
	 *
	 * Overwrites whatever sits at the target path, and updates the Integrity
	 * and Malware tabs the way their Restore buttons do.
	 *
	 * ## OPTIONS
	 *
	 * <backup_id>
	 * : Identifier from `wp segurium backup list`.
	 *
	 * ## EXAMPLES
	 *
	 *     wp segurium backup restore 1755500000123456-ab12cd34
	 *
	 * @when after_wp_load
	 *
	 * @param array $args       Positional args.
	 * @param array $assoc_args Flag args (unused).
	 */
	public function restore( $args, $assoc_args ) {
		unset( $assoc_args );
		$backup_id = isset( $args[0] ) ? (string) $args[0] : '';

		$meta = self::find( $backup_id );
		if ( null === $meta ) {
			WP_CLI::error( 'No backup with id "' . $backup_id . '". Run `wp segurium backup list`. [backup_not_found]' );
			return;
		}

		$plugin = Segurium::get_instance();
		switch ( $meta['bucket'] ) {
			case 'malware':
				$issue  = self::integrity_issue( $backup_id );
				$before = '';
				if ( null !== $issue ) {
					$abs    = rtrim( Segurium_Path_Helpers::wp_root(), '/' ) . '/' . ltrim( $issue['file_path'], '/' );
					$before = is_file( $abs ) ? (string) Segurium_Fs::hash_file( 'sha256', $abs ) : '';
				}
				$result = $plugin->restore_malware_backup( $backup_id );
				if ( null !== $issue && ! is_wp_error( $result ) ) {
					$plugin->record_integrity_restore(
						$backup_id,
						$issue['comp_type'],
						$issue['comp_slug'],
						$issue['file_path'],
						$before,
						(string) Segurium_Fs::hash_file( 'sha256', $result )
					);
				}
				break;
			case 'integrity':
				$issue = self::integrity_issue( $backup_id );
				if ( null === $issue ) {
					$issue = self::component_from_path( ltrim( (string) ( $meta['ref'] ?? '' ), '/' ) );
				}
				$result = $plugin->restore_integrity_backup( $backup_id, $issue['comp_type'], $issue['comp_slug'], $issue['file_path'] );
				break;
			default:
				$result = $plugin->restore_component_backup(
					$backup_id,
					(string) ( $meta['component_type'] ?? '' ),
					(string) ( $meta['component_slug'] ?? '' )
				);
		}

		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() . ' [' . $result->get_error_code() . ']' );
			return;
		}
		WP_CLI::success( 'Restored ' . $meta['bucket'] . ' backup ' . $backup_id . ' to ' . $result . '.' );
	}

	/**
	 * Sidecar of the backup with this id, with its bucket set.
	 *
	 * @param string $backup_id Backup identifier.
	 * @return array|null
	 */
	private static function find( $backup_id ) {
		if ( '' === $backup_id ) {
			return null;
		}
		foreach ( self::BUCKETS as $bucket ) {
			foreach ( Segurium_Storage::backup_list( $bucket ) as $meta ) {
				if ( ( $meta['backup_id'] ?? '' ) === $backup_id ) {
					$meta['bucket'] = $bucket;
					return $meta;
				}
			}
		}
		return null;
	}

	/**
	 * Path an operator recognises: relative to the WordPress root for files,
	 * `type/slug` for a whole component.
	 *
	 * @param array $meta Sidecar metadata.
	 * @return string
	 */
	private static function display_path( array $meta ) {
		$path = (string) ( $meta['original_path'] ?? $meta['ref'] ?? '' );
		$root = rtrim( Segurium_Path_Helpers::wp_root(), '/' ) . '/';
		return 0 === strpos( $path, $root ) ? substr( $path, strlen( $root ) ) : $path;
	}

	/**
	 * Integrity issue a backup was taken for. An Integrity fix of a
	 * malicious file stores its backup in the `malware` bucket, so both
	 * per-file buckets can have one.
	 *
	 * @param string $backup_id Backup identifier.
	 * @return array{comp_type: string, comp_slug: string, file_path: string}|null
	 */
	private static function integrity_issue( $backup_id ) {
		$row = Segurium_Storage::table_get_row(
			'integrity_issues',
			'SELECT comp_type, comp_slug, file_path FROM {{table}} WHERE backup_id = %s LIMIT 1',
			array( $backup_id ),
			ARRAY_A
		);
		if ( ! is_array( $row ) || '' === (string) $row['comp_type'] ) {
			return null;
		}
		return array(
			'comp_type' => (string) $row['comp_type'],
			'comp_slug' => (string) $row['comp_slug'],
			'file_path' => (string) $row['file_path'],
		);
	}

	/**
	 * Component of a file whose issue row is gone, read from the path in
	 * the layout the integrity scan walks.
	 *
	 * @param string $rel File path relative to the WordPress root.
	 * @return array{comp_type: string, comp_slug: string, file_path: string}
	 */
	private static function component_from_path( $rel ) {
		if ( preg_match( '#^wp-content/(plugins|themes)/([^/]+)/#', $rel, $m ) ) {
			return array(
				'comp_type' => 'plugins' === $m[1] ? 'plugin' : 'theme',
				'comp_slug' => $m[2],
				'file_path' => $rel,
			);
		}
		return array(
			'comp_type' => 'core',
			'comp_slug' => 'WordPress',
			'file_path' => $rel,
		);
	}
}

WP_CLI::add_command( 'segurium backup', 'Segurium_CLI_Backup' );

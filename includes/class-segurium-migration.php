<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Migration framework for importing settings from other security plugins.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base class for migration source adapters.
 * Each adapter reads data from a competing plugin and maps it to Segurium options.
 */
abstract class Segurium_Migration_Source {

	/**
	 * Human-readable plugin name shown in the UI.
	 *
	 * @return string
	 */
	abstract public static function get_plugin_name();

	/**
	 * Machine slug used to identify this adapter.
	 *
	 * @return string
	 */
	abstract public static function get_plugin_slug();

	/**
	 * Returns true if importable data exists in the DB (regardless of whether
	 * the plugin is currently active or even installed).
	 *
	 * @return bool
	 */
	abstract public static function has_data();

	/**
	 * Returns a preview of what will be migrated without modifying anything.
	 * Each item: {feature, label, count, preview_text, status, action_label, note}
	 * status: 'import' | 'skip' | 'pending_feature'
	 *
	 * @return array
	 */
	abstract public function preview();

	/**
	 * Applies the migration and returns a result summary.
	 * {applied: [...], skipped: [...], pending: [...]}
	 *
	 * @return array
	 */
	abstract public function apply();

	/**
	 * Build a preview item descriptor.
	 *
	 * @param string $feature      Feature key.
	 * @param string $label        Human-readable label.
	 * @param int    $count        Number of items.
	 * @param string $status       Status (import, skip, pending_feature).
	 * @param string $action_label Action button label.
	 * @param string $note         Additional note text.
	 * @return array
	 */
	protected function make_item( $feature, $label, $count, $status, $action_label = '', $note = '' ) {
		return array(
			'feature'      => $feature,
			'label'        => $label,
			'count'        => $count,
			'preview_text' => $count > 0 ? $count . ' ' . $label : $label,
			'status'       => $status,
			'action_label' => $action_label,
			'note'         => $note,
		);
	}

	/**
	 * Merge two IP lists, removing duplicates.
	 *
	 * @param array $existing Current IP list.
	 * @param array $new_ips  New IPs to merge.
	 * @return array Merged unique IP list.
	 */
	protected function merge_ip_list( $existing, $new_ips ) {
		$normalize = static function ( $cidr ) {
			$cidr = trim( (string) $cidr );
			if ( '' === $cidr ) {
				return '';
			}
			$parts = explode( '/', $cidr, 2 );
			if ( 1 === count( $parts ) ) {
				return $cidr;
			}
			$bits = (int) $parts[1];
			$ip   = $parts[0];
			if ( false === strpos( $ip, ':' ) && 32 === $bits ) {
				return $ip;
			}
			if ( false !== strpos( $ip, ':' ) && 128 === $bits ) {
				return $ip;
			}
			return $cidr;
		};
		$seen      = array();
		$out       = array();
		foreach ( array_merge( (array) $existing, (array) $new_ips ) as $entry ) {
			$key = $normalize( $entry );
			if ( '' === $key || isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$out[]        = $key;
		}
		return $out;
	}

	/**
	 * Merge scan exclusion patterns, deduplicating.
	 *
	 * @param string $existing     Current newline-separated exclusions.
	 * @param array  $new_patterns New patterns to merge.
	 * @return string Merged newline-separated exclusions.
	 */
	protected function merge_scan_exclusions( $existing, $new_patterns ) {
		$existing_arr = array_filter( array_map( 'trim', explode( "\n", (string) $existing ) ) );
		$merged       = array_values( array_unique( array_merge( array_values( $existing_arr ), array_values( array_filter( (array) $new_patterns ) ) ) ) );
		return implode( "\n", $merged );
	}

	/**
	 * Validate and filter a list of IP addresses and CIDR ranges.
	 *
	 * @param array $ips Raw IP addresses.
	 * @return array Valid IP addresses.
	 */
	protected function validate_ip_list( $ips ) {
		$valid = array();
		foreach ( (array) $ips as $ip ) {
			$ip = trim( (string) $ip );
			if ( empty( $ip ) ) {
				continue;
			}
			if ( false !== strpos( $ip, '/' ) ) {
				list( $addr, $prefix ) = explode( '/', $ip, 2 );
				if ( filter_var( $addr, FILTER_VALIDATE_IP ) && is_numeric( $prefix ) && $prefix >= 0 && $prefix <= 128 ) {
					$valid[] = $ip;
				}
			} elseif ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$valid[] = $ip;
			}
		}
		return $valid;
	}

	/**
	 * Split a newline-separated string into a filtered array.
	 *
	 * @param string $value Newline-separated string.
	 * @return array Trimmed, non-empty values.
	 */
	protected function parse_newline_list( $value ) {
		$lines = preg_split( '/[\r\n]+/', (string) $value );
		return array_values( array_filter( array_map( 'trim', $lines ) ) );
	}
}

// phpcs:disable Generic.Files.OneObjectStructurePerFile
/**
 * Registry that discovers available migration adapters.
 */
class Segurium_Migration {
// phpcs:enable Generic.Files.OneObjectStructurePerFile

	/**
	 * Map of adapter slugs to class names.
	 *
	 * @var array
	 */
	private static $adapter_classes = array(
		'wordfence'      => 'Segurium_Migration_Wordfence',
		'aios'           => 'Segurium_Migration_AIOS',
		'sucuri'         => 'Segurium_Migration_Sucuri',
		'solid-security' => 'Segurium_Migration_Solid_Security',
	);

	/**
	 * Returns info about all adapters that have detectable data.
	 * Each entry: {slug, name, item_count}
	 *
	 * @return array
	 */
	public static function get_available() {
		$available = array();
		foreach ( self::$adapter_classes as $slug => $class ) {
			if ( $class::has_data() ) {
				$adapter    = new $class();
				$items      = $adapter->preview();
				$importable = 0;
				foreach ( $items as $item ) {
					if ( 'import' === $item['status'] && $item['count'] > 0 ) {
						++$importable;
					}
				}
				$available[] = array(
					'slug'       => $slug,
					'name'       => $class::get_plugin_name(),
					'item_count' => $importable,
				);
			}
		}
		return $available;
	}

	/**
	 * Returns an adapter instance by slug, or null if not available.
	 *
	 * @param string $slug Adapter slug.
	 * @return Segurium_Migration_Source|null
	 */
	public static function get_adapter( $slug ) {
		if ( ! isset( self::$adapter_classes[ $slug ] ) ) {
			return null;
		}
		$class = self::$adapter_classes[ $slug ];
		if ( ! $class::has_data() ) {
			return null;
		}
		return new $class();
	}
}

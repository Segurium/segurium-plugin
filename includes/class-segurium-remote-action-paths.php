<?php
/**
 * Paths the action channel may never read.
 *
 * Kept in its own file, apart from the validator that consults it, so
 * the list can grow without touching action code and a reviewer can see
 * exactly what is off limits in one screen.
 *
 * The owner's decision on the channel was: accept any path under the
 * WordPress root, minus a denied set. What ships here is the minimum
 * that set can be — the files whose contents are credentials rather than
 * evidence. Everything else on a compromised site is fair game for an
 * analyst, because that is the point of the command.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Denied-path list for `upload_file` remote actions.
 */
class Segurium_Remote_Action_Paths {

	/**
	 * Basename prefixes refused anywhere in the tree.
	 *
	 * `wp-config.php` is the file, but it is never the only copy: a host
	 * or an operator leaves `wp-config.php.bak`, `wp-config-local.php`,
	 * `wp-config.save`. Every one of them holds the same database
	 * credentials, so the rule is on the name rather than on one path.
	 *
	 * @var array<int, string>
	 */
	const DENIED_BASENAME_PREFIXES = array(
		'wp-config',
	);

	/**
	 * Basenames refused anywhere in the tree, not only at the WordPress
	 * root. A `.env` under `wp-content/` is the same secret as a `.env`
	 * beside `index.php`.
	 *
	 * @var array<int, string>
	 */
	const DENIED_BASENAMES = array(
		'.env',
		'.htpasswd',
	);

	/**
	 * Exact site-relative paths refused outright. Empty as shipped: what
	 * we know to deny is named above, and this is the hook for an
	 * operator who wants one specific file off the channel.
	 *
	 * @var array<int, string>
	 */
	const DENIED_FILES = array();

	/**
	 * Site-relative directory prefixes refused along with everything
	 * under them.
	 *
	 * @var array<int, string>
	 */
	const DENIED_PREFIXES = array();

	/**
	 * Whether a site-relative path is refused.
	 *
	 * The comparison is on the path the plugin resolved against ABSPATH,
	 * not on the string the action carried, so a denied file cannot be
	 * reached through a directory that resolves onto it.
	 *
	 * @param string $relative Site-relative path, forward slashes, no leading slash.
	 * @return bool
	 */
	public static function is_denied( string $relative ): bool {
		$needle = strtolower( ltrim( str_replace( '\\', '/', $relative ), '/' ) );
		if ( '' === $needle ) {
			return true;
		}

		$basename = (string) substr( strrchr( '/' . $needle, '/' ), 1 );

		foreach ( self::denied_basenames() as $name ) {
			if ( $basename === $name ) {
				return true;
			}
		}

		foreach ( self::denied_basename_prefixes() as $prefix ) {
			if ( 0 === strpos( $basename, $prefix ) ) {
				return true;
			}
		}

		foreach ( self::denied_files() as $file ) {
			if ( $needle === $file ) {
				return true;
			}
		}

		foreach ( self::denied_prefixes() as $prefix ) {
			if ( 0 === strpos( $needle, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Denied basenames, append-only.
	 *
	 * @return array<int, string>
	 */
	public static function denied_basenames(): array {
		$added = apply_filters( 'segurium_remote_action_denied_basenames', self::DENIED_BASENAMES );
		return array_values(
			array_unique( array_merge( self::normalize( self::DENIED_BASENAMES ), self::normalize( $added ) ) )
		);
	}

	/**
	 * Denied basename prefixes, append-only.
	 *
	 * @return array<int, string>
	 */
	public static function denied_basename_prefixes(): array {
		$added = apply_filters( 'segurium_remote_action_denied_basename_prefixes', self::DENIED_BASENAME_PREFIXES );
		return array_values(
			array_unique(
				array_merge(
					self::normalize( self::DENIED_BASENAME_PREFIXES ),
					self::normalize( $added )
				)
			)
		);
	}

	/**
	 * Denied files.
	 *
	 * The shipped set is always included: the filter can only add to it.
	 * Made append-only on purpose — a filter that returns junk, or that
	 * carelessly replaces the array, would otherwise reopen
	 * `wp-config.php` to the channel, and a mistake in a must-use plugin
	 * is not something the site should be able to make that way.
	 *
	 * @return array<int, string>
	 */
	public static function denied_files(): array {
		$added = apply_filters( 'segurium_remote_action_denied_files', self::DENIED_FILES );
		return array_values(
			array_unique( array_merge( self::normalize( self::DENIED_FILES ), self::normalize( $added ) ) )
		);
	}

	/**
	 * Denied directory prefixes, append-only for the same reason. Each is
	 * normalised to end in a slash so `wp-content/uploads-private` cannot
	 * be matched by a `wp-content/uploads` entry.
	 *
	 * @return array<int, string>
	 */
	public static function denied_prefixes(): array {
		$added = apply_filters( 'segurium_remote_action_denied_prefixes', self::DENIED_PREFIXES );
		$all   = array_merge( self::normalize( self::DENIED_PREFIXES ), self::normalize( $added ) );
		$out   = array();
		foreach ( $all as $prefix ) {
			$out[] = rtrim( $prefix, '/' ) . '/';
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Lowercase, trim and drop anything that is not a usable string.
	 *
	 * @param mixed $candidates Candidate list.
	 * @return array<int, string>
	 */
	private static function normalize( $candidates ): array {
		if ( ! is_array( $candidates ) ) {
			return array();
		}
		$out = array();
		foreach ( $candidates as $entry ) {
			if ( ! is_string( $entry ) ) {
				continue;
			}
			$entry = strtolower( trim( ltrim( $entry, '/' ) ) );
			if ( '' !== $entry ) {
				$out[] = $entry;
			}
		}
		return $out;
	}
}

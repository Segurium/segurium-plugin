<?php
/**
 * Core, plugin, and theme file-hash collection for integrity checks.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Walks WordPress directories and collects SHA-256 hashes per file.
 */
class Segurium_Integrity {

	/**
	 * WordPress installation root path.
	 *
	 * @var string
	 */
	private $base_path;

	/**
	 * Compiled user exclusion regex patterns.
	 *
	 * @var array
	 */
	private $exclude_patterns = array();

	/**
	 * Files and paths excluded from integrity checks by default.
	 *
	 * @var array
	 */
	private static $builtin_excludes = array(
		'wp-config.php',
		'wp-config-sample.php',
		'wp-config-ddev.php',
		'.htaccess',
		'.htpasswd',
		'.user.ini',
		'php.ini',
		'.ftpquota',
		'wp-includes/version.php',
		'.DS_Store',
		'Thumbs.db',
		'error_log',
		'robots.txt',
		'sitemap.xml',
		'sitemap.xml.gz',
		'favicon.ico',
		'healthcheck.html',
		'health-check.html',
		'cgi-bin',
		'.well-known',
		'404.php',
		'403.shtml',
		'500.shtml',
	);

	/**
	 * File extensions excluded from integrity checks by default.
	 *
	 * @var array
	 */
	private static $builtin_exclude_extensions = array(
		'log',
	);

	/**
	 * Patterns for files that should never be auto-deleted from core dirs.
	 *
	 * @var array
	 */
	private static $builtin_exclude_patterns = array(
		'/^google[0-9a-f]{16}\.html$/',
		'/^pinterest-[0-9a-z]{5}\.html$/',
		'/^BingSiteAuth\.xml$/i',
		'/^yandex_[0-9a-f]+\.html$/',
		'/^\.well-known\//',
		'/^cgi-bin\//',
		// Favicon / touch-icon variants at the WP root only — narrowed
		// from the spec's bare-extension regex so we don't exclude images
		// shipped inside wp-admin / wp-includes assets.
		'/^[^\/]+\.(ico|png|jpg|jpeg|gif|svg|webp)$/i',
		// Guard against touching wp-content via the core component, but leave
		// plugin/theme files (scanned as their own components) to normal rules.
		'/^wp-content\/(?!plugins\/|themes\/)/',
	);

	/**
	 * Constructor.
	 *
	 * @param string $base_path       WordPress installation root.
	 * @param array  $user_exclusions User-defined exclusion patterns.
	 */
	public function __construct( $base_path, $user_exclusions = array() ) {
		$this->base_path        = rtrim( $base_path, '/' );
		$this->exclude_patterns = $this->compile_patterns( $user_exclusions );
	}

	/**
	 * Check if a relative path is in the exclusion list.
	 *
	 * @param string $relative_path Relative file path.
	 * @return bool
	 */
	public static function is_excluded( $relative_path ) {
		$basename = basename( $relative_path );

		if ( in_array( $relative_path, self::$builtin_excludes, true ) ) {
			return true;
		}
		if ( in_array( $basename, self::$builtin_excludes, true ) ) {
			return true;
		}

		$ext = pathinfo( $basename, PATHINFO_EXTENSION );
		if ( ! empty( $ext ) && in_array( strtolower( $ext ), self::$builtin_exclude_extensions, true ) ) {
			return true;
		}

		foreach ( self::$builtin_exclude_patterns as $pattern ) {
			if ( preg_match( $pattern, $relative_path ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Collect file hashes for WordPress core directories.
	 *
	 * @return array List of path/sha256 pairs.
	 */
	public function collect_core_hashes() {
		$hashes = array();

		$this->walk_directory( $this->base_path . '/wp-admin', $hashes, true, true );
		$this->walk_directory( $this->base_path . '/wp-includes', $hashes, true, true );
		$this->walk_directory( $this->base_path, $hashes, false, true );

		return $hashes;
	}

	/**
	 * Collect file hashes for a specific plugin.
	 *
	 * @param string $slug Plugin directory slug.
	 * @return array List of path/sha256 pairs.
	 */
	public function collect_plugin_hashes( $slug ) {
		$dir = $this->base_path . '/wp-content/plugins/' . $slug;
		if ( ! is_dir( $dir ) ) {
			return array();
		}

		$hashes = array();
		$this->walk_directory( $dir, $hashes, true, false );
		return $hashes;
	}

	/**
	 * Collect file hashes for a specific theme.
	 *
	 * @param string $slug Theme directory slug.
	 * @return array List of path/sha256 pairs.
	 */
	public function collect_theme_hashes( $slug ) {
		$dir = $this->base_path . '/wp-content/themes/' . $slug;
		if ( ! is_dir( $dir ) ) {
			return array();
		}

		$hashes = array();
		$this->walk_directory( $dir, $hashes, true, false );
		return $hashes;
	}

	/**
	 * Recursively walk a directory collecting file hashes.
	 *
	 * @param string $dir             Directory to walk.
	 * @param array  $hashes          Collected hashes array (by reference).
	 * @param bool   $recursive       Whether to recurse into subdirectories.
	 * @param bool   $skip_wp_content Whether to skip wp-content subdirectories.
	 */
	private function walk_directory( $dir, &$hashes, $recursive, $skip_wp_content = false ) {
		$handle = Segurium_Fs::opendir( $dir );
		if ( ! $handle ) {
			return;
		}

		while ( false !== ( $entry = readdir( $handle ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.FoundInWhileCondition
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			$path = $dir . '/' . $entry;

			if ( is_dir( $path ) ) {
				if ( $recursive && ! ( $skip_wp_content && $this->is_wp_content_dir( $path ) ) ) {
					$this->walk_directory( $path, $hashes, true, $skip_wp_content );
				}
				continue;
			}

			if ( ! is_file( $path ) ) {
				continue;
			}

			$relative = $this->make_relative( $path );

			if ( $this->is_builtin_excluded( $relative, $entry ) ) {
				continue;
			}

			if ( $this->is_user_excluded( $relative ) ) {
				continue;
			}

			$sha256 = Segurium_Fs::hash_file( 'sha256', $path );
			if ( false === $sha256 ) {
				continue;
			}

			$hashes[] = array(
				'path'   => $relative,
				'sha256' => $sha256,
			);
		}

		closedir( $handle );
	}

	/**
	 * Check if a path is inside the wp-content directory.
	 *
	 * @param string $path Absolute path.
	 * @return bool
	 */
	private function is_wp_content_dir( $path ) {
		$relative = $this->make_relative( $path );
		return 0 === strpos( $relative, 'wp-content' );
	}

	/**
	 * Check if a file matches built-in exclusion rules.
	 *
	 * @param string $relative Relative file path.
	 * @param string $basename File basename.
	 * @return bool
	 */
	private function is_builtin_excluded( $relative, $basename ) {
		if ( in_array( $relative, self::$builtin_excludes, true ) ) {
			return true;
		}

		if ( in_array( $basename, self::$builtin_excludes, true ) ) {
			return true;
		}

		$ext = pathinfo( $basename, PATHINFO_EXTENSION );
		if ( ! empty( $ext ) && in_array( strtolower( $ext ), self::$builtin_exclude_extensions, true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if a file matches user-defined exclusion patterns.
	 *
	 * @param string $relative Relative file path.
	 * @return bool
	 */
	private function is_user_excluded( $relative ) {
		foreach ( $this->exclude_patterns as $regex ) {
			if ( preg_match( $regex, $relative ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Convert an absolute path to a path relative to the base.
	 *
	 * @param string $path Absolute path.
	 * @return string Relative path.
	 */
	private function make_relative( $path ) {
		$base = $this->base_path . '/';
		if ( 0 === strpos( $path, $base ) ) {
			return substr( $path, strlen( $base ) );
		}
		return $path;
	}

	/**
	 * Compile glob-style exclusion patterns into regex.
	 *
	 * @param array $patterns Glob patterns.
	 * @return array Compiled regex patterns.
	 */
	private function compile_patterns( $patterns ) {
		$compiled = array();
		foreach ( $patterns as $pattern ) {
			$pattern = trim( $pattern );
			if ( '' === $pattern || '*' === $pattern ) {
				continue;
			}
			$regex      = preg_quote( $pattern, '#' );
			$regex      = str_replace( '\\*', '.*', $regex );
			$compiled[] = '#(?:^|/)' . $regex . '$#i';
		}
		return $compiled;
	}
}

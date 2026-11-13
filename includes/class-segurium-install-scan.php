<?php
/**
 * Cloud lookup for the files of a plugin or theme package being installed.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stops plugin and theme installs that carry known malware.
 */
class Segurium_Install_Scan {

	const MAX_SECONDS = 20;

	const TYPES = array( 'plugin', 'theme' );

	/**
	 * Unknown files waiting for their install to finish, by upgrader.
	 *
	 * @var SplObjectStorage|null
	 */
	private static $pending = null;

	/**
	 * Register the installer hooks.
	 *
	 * @return void
	 */
	public static function register_hooks() {
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core WP hook
		add_filter( 'upgrader_source_selection', array( __CLASS__, 'filter_source_selection' ), 20, 4 );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core WP hook
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrader_complete' ), 20, 1 );
	}

	/**
	 * Refuse a package when CTI knows one of its files as malware.
	 *
	 * @param mixed $source        Package folder, or a WP_Error from an earlier check.
	 * @param mixed $remote_source Working folder the package was unpacked into.
	 * @param mixed $upgrader      Upgrader instance.
	 * @param mixed $hook_extra    Install context from core.
	 * @return mixed `$source` unchanged, or a WP_Error that stops the install.
	 */
	public static function filter_source_selection( $source, $remote_source = '', $upgrader = null, $hook_extra = array() ) {
		if ( ! is_string( $source ) || ! self::is_install( $hook_extra ) ) {
			return $source;
		}

		$summary  = self::empty_summary();
		$unknown  = array();
		$deadline = 0.0;
		$dir      = '';
		try {
			$dir = self::look_up( self::local_path( $source ), $summary, $unknown, $deadline );
		} catch ( Throwable $e ) {
			self::exception( $e, $summary );
		}

		if ( '' !== $summary['blocked_path'] ) {
			return self::refuse( $dir, is_string( $remote_source ) ? $remote_source : '', $unknown, $deadline, $summary );
		}
		if ( empty( $unknown ) ) {
			self::finish( $summary );
		} elseif ( ! is_object( $upgrader ) ) {
			self::not_uploaded( $summary, 'no_upgrader', count( $unknown ) );
			self::finish( $summary );
		} else {
			self::pending()->attach(
				$upgrader,
				array(
					'type'    => $hook_extra['type'],
					'unknown' => $unknown,
					'summary' => $summary,
				)
			);
		}
		return $source;
	}

	/**
	 * Upload the unknown files of a looked-up package from its final place.
	 *
	 * @param mixed $upgrader Upgrader instance.
	 * @return void
	 */
	public static function on_upgrader_complete( $upgrader ) {
		$pending = self::pending();
		if ( ! is_object( $upgrader ) || ! $pending->contains( $upgrader ) ) {
			return;
		}
		$job = $pending[ $upgrader ];
		$pending->detach( $upgrader );

		$summary = $job['summary'];
		try {
			list( $root, $logical ) = self::destination_root( $job['type'] );
			$result                 = isset( $upgrader->result ) && is_array( $upgrader->result ) ? $upgrader->result : array();
			$dir                    = isset( $result['destination'] ) && is_string( $result['destination'] ) ? self::inside( $result['destination'], $root ) : '';
			if ( '' === $dir ) {
				self::not_uploaded( $summary, 'not_installed', count( $job['unknown'] ) );
			} else {
				self::upload_from( $dir, $root, $logical, $job['unknown'], microtime( true ) + self::budget(), $summary );
			}
		} catch ( Throwable $e ) {
			self::exception( $e, $summary );
		}
		self::finish( $summary );
	}

	/**
	 * Delete a refused package and return the installer error. The evidence
	 * batch is read before the delete and sent after it.
	 *
	 * @param string $dir           Canonical package folder.
	 * @param string $remote_source Working folder as the installer passed it.
	 * @param array  $unknown       `{pkg, sha256, size}` records.
	 * @param float  $deadline      Microtime after which no submit starts.
	 * @param array  $summary       Run summary.
	 * @return WP_Error
	 */
	private static function refuse( $dir, $remote_source, array $unknown, $deadline, array $summary ) {
		$batch = array();
		try {
			$next = 0;
			if ( Segurium_Storage::on_premise_mode() ) {
				self::not_uploaded( $summary, 'on_premise', count( $unknown ) );
				$next = count( $unknown );
			} elseif ( '' !== $dir ) {
				$batch = self::build_batch( $dir, self::upgrade_root(), 'wp-content/upgrade', $unknown, $next, $summary );
			}
			if ( $next < count( $unknown ) ) {
				self::not_uploaded( $summary, 'refused_install', count( $unknown ) - $next );
			}
		} catch ( Throwable $e ) {
			self::exception( $e, $summary );
		}

		self::discard( $remote_source );

		try {
			$blocked = empty( $batch ) ? '' : self::upload_blocked( $deadline, $summary );
			if ( '' !== $blocked ) {
				self::not_uploaded( $summary, $blocked, count( $batch ) );
			} elseif ( ! empty( $batch ) ) {
				self::send( $batch, $summary );
			}
		} catch ( Throwable $e ) {
			self::exception( $e, $summary );
		}
		self::finish( $summary );

		return new WP_Error(
			'segurium_malware_detected',
			sprintf(
				/* translators: %s: path of the infected file inside the plugin or theme package. */
				__( 'Installation stopped. Segurium found malware in %s.', 'segurium' ),
				esc_html( $summary['blocked_path'] )
			)
		);
	}

	/**
	 * Jobs waiting for upgrader_process_complete.
	 *
	 * @return SplObjectStorage
	 */
	private static function pending() {
		if ( null === self::$pending ) {
			self::$pending = new SplObjectStorage();
		}
		return self::$pending;
	}

	/**
	 * Look up and upload one package folder in a single pass.
	 *
	 * @param string $package_dir Local package folder under the upgrade folder.
	 * @return array Run summary.
	 */
	public static function run( $package_dir ) {
		$summary  = self::empty_summary();
		$unknown  = array();
		$deadline = 0.0;
		try {
			$dir = self::look_up( (string) $package_dir, $summary, $unknown, $deadline );
			if ( '' !== $dir ) {
				self::upload_from( $dir, self::upgrade_root(), 'wp-content/upgrade', $unknown, $deadline, $summary );
			}
		} catch ( Throwable $e ) {
			self::exception( $e, $summary );
		}
		self::finish( $summary );
		return $summary;
	}

	/**
	 * Path relative to the WordPress root, never an absolute server path.
	 *
	 * @param string $path    Canonical absolute path.
	 * @param string $root    Canonical folder the path lives in.
	 * @param string $logical WordPress-relative name of that folder.
	 * @return string
	 */
	public static function site_path( $path, $root, $logical ) {
		$path = (string) $path;
		$rel  = Segurium_Remote_Actions::relative_to_abspath( $path );
		if ( '' !== $rel ) {
			return $rel;
		}
		$root = rtrim( (string) $root, '/' ) . '/';
		return 0 === strpos( $path, $root ) ? $logical . '/' . substr( $path, strlen( $root ) ) : basename( $path );
	}

	/**
	 * Gate, walk and look up. Fills the unknown files, one per content hash.
	 *
	 * @param string $path     Local package folder.
	 * @param array  $summary  Run summary, by reference.
	 * @param array  $unknown  `{pkg, sha256, size}` records, by reference.
	 * @param float  $deadline Set to the time after which no new batch starts.
	 * @return string Canonical package folder, or '' when a gate stopped the run.
	 */
	private static function look_up( $path, array &$summary, array &$unknown, &$deadline ) {
		if ( ! Segurium_Storage::setting_get_bool( 'segurium_cti_consent' ) ) {
			$summary['skipped'] = 'no_consent';
			return '';
		}
		$dir = self::inside( $path, self::upgrade_root() );
		if ( '' === $dir ) {
			$summary['skipped'] = 'bad_source';
			return '';
		}

		// The installer runs on light request tiers, which do not load the
		// scan pipeline classes used below.
		if ( function_exists( 'segurium_load_full_plugin' ) ) {
			segurium_load_full_plugin();
		}
		if ( null === Segurium_IID::get_iid() ) {
			$summary['skipped'] = 'no_iid';
			return '';
		}

		$deadline           = microtime( true ) + self::budget();
		$files              = self::collect( $dir );
		$summary['files']   = count( $files );
		$summary['scan_id'] = wp_generate_uuid4();
		$seen               = array();

		foreach ( array_chunk( $files, Segurium_Verdict_Queue::BATCH_SIZE ) as $i => $chunk ) {
			if ( $i > 0 && microtime( true ) >= $deadline ) {
				$summary['stopped'] = 'budget';
				break;
			}
			$pkg     = array();
			$records = self::hash_files( $chunk, $dir, $pkg );
			if ( empty( $records ) ) {
				continue;
			}
			$result = Segurium_Storage::cti_inspect_hashes( $records, $summary['scan_id'] );
			if ( is_wp_error( $result ) || ! is_array( $result ) ) {
				if ( '' === $summary['error'] ) {
					$summary['error'] = is_wp_error( $result ) ? (string) $result->get_error_code() : 'inspect_invalid_response';
				}
				break;
			}
			$summary['looked_up'] += count( $records );
			$blocking              = self::hashes_with( $result, self::blocking_verdicts() );
			$unknown_sha           = self::hashes_with( $result, array( Segurium_Verdict_Queue::VERDICT_UNKNOWN ) );
			foreach ( $records as $n => $record ) {
				$sha = $record['sha256'];
				if ( isset( $blocking[ $sha ] ) ) {
					++$summary['infected'];
					if ( '' === $summary['blocked_path'] ) {
						$summary['blocked_path'] = $pkg[ $n ];
					}
				} elseif ( isset( $unknown_sha[ $sha ] ) && ! isset( $seen[ $sha ] ) ) {
					$seen[ $sha ] = true;
					$unknown[]    = array(
						'pkg'    => $pkg[ $n ],
						'sha256' => $sha,
						'size'   => $record['size'],
					);
					++$summary['unknown'];
				}
			}
		}
		return $dir;
	}

	/**
	 * Lookup verdicts that stop an install. A method, not a constant: PHP
	 * resolves every class constant on first static access, and light tiers
	 * do not load Segurium_Cleanup.
	 *
	 * @return int[]
	 */
	private static function blocking_verdicts() {
		return array( Segurium_Cleanup::VERDICT_MALICIOUS, Segurium_Cleanup::VERDICT_INJECTION );
	}

	/**
	 * Lowercase hashes whose verdict is in the list.
	 *
	 * @param array $result   Inspect results.
	 * @param int[] $verdicts Verdict codes.
	 * @return array<string, true>
	 */
	private static function hashes_with( array $result, array $verdicts ) {
		$out = array();
		foreach ( $result as $item ) {
			if ( is_array( $item ) && isset( $item['sha256'], $item['verdict'] )
				&& in_array( (int) $item['verdict'], $verdicts, true ) ) {
				$out[ strtolower( (string) $item['sha256'] ) ] = true;
			}
		}
		return $out;
	}

	/**
	 * Whether the hook context is a plugin or theme install.
	 *
	 * @param mixed $hook_extra Install context from core.
	 * @return bool
	 */
	private static function is_install( $hook_extra ) {
		return is_array( $hook_extra )
			&& in_array( $hook_extra['type'] ?? '', self::TYPES, true )
			&& 'install' === ( $hook_extra['action'] ?? '' );
	}

	/**
	 * Canonical local upgrade folder, or '' when it does not exist.
	 *
	 * @return string
	 */
	private static function upgrade_root() {
		return (string) Segurium_Fs::realpath( Segurium_Path_Helpers::content_root() . '/upgrade' );
	}

	/**
	 * Canonical install root and its WordPress-relative name.
	 *
	 * @param string $type `plugin` or `theme`.
	 * @return array{0: string, 1: string}
	 */
	private static function destination_root( $type ) {
		if ( 'theme' === $type ) {
			return array( (string) Segurium_Fs::realpath( get_theme_root() ), 'wp-content/themes' );
		}
		return array( (string) Segurium_Fs::realpath( Segurium_Path_Helpers::plugins_root() ), 'wp-content/plugins' );
	}

	/**
	 * Canonical directory strictly inside the root, or ''.
	 *
	 * @param string $path Local path.
	 * @param string $root Canonical root.
	 * @return string
	 */
	private static function inside( $path, $root ) {
		$real = Segurium_Fs::realpath( (string) $path );
		if ( false === $real || '' === $root || $real === $root || ! is_dir( $real ) ) {
			return '';
		}
		return 0 === strpos( $real, $root . '/' ) ? $real : '';
	}

	/**
	 * Map a filesystem-abstraction path to the local one, as `check_package` does.
	 *
	 * @param string $path Path as the installer passed it.
	 * @return string
	 */
	private static function local_path( $path ) {
		global $wp_filesystem;
		if ( is_object( $wp_filesystem ) && method_exists( $wp_filesystem, 'wp_content_dir' ) ) {
			$content = (string) $wp_filesystem->wp_content_dir();
			if ( '' !== $content && 0 === strpos( $path, $content ) ) {
				return trailingslashit( Segurium_Path_Helpers::content_root() ) . substr( $path, strlen( $content ) );
			}
		}
		return $path;
	}

	/**
	 * Delete the working folder of a refused package; core leaves it behind.
	 *
	 * @param string $remote_source Working folder as the installer passed it.
	 * @return void
	 */
	private static function discard( $remote_source ) {
		$local = self::inside( self::local_path( $remote_source ), self::upgrade_root() );
		if ( '' === $local ) {
			Segurium_Debug::log( '[segurium-install-scan] discard_refused: working folder is outside the upgrade folder' );
			return;
		}
		global $wp_filesystem;
		$deleted = is_object( $wp_filesystem ) && method_exists( $wp_filesystem, 'delete' )
			? (bool) $wp_filesystem->delete( $remote_source, true )
			: self::delete_tree( $local );
		if ( ! $deleted ) {
			Segurium_Debug::log( '[segurium-install-scan] discard_failed: ' . $local );
		}
	}

	/**
	 * Delete a local folder without following symlinks.
	 *
	 * @param string $dir Canonical folder.
	 * @return bool
	 */
	private static function delete_tree( $dir ) {
		$entries = Segurium_Fs::scandir( $dir );
		if ( false === $entries ) {
			return false;
		}
		foreach ( $entries as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $dir . '/' . $entry;
			$ok   = is_dir( $path ) && ! is_link( $path ) ? self::delete_tree( $path ) : Segurium_Fs::delete( $path );
			if ( ! $ok ) {
				return false;
			}
		}
		return Segurium_Fs::rmdir( $dir );
	}

	/**
	 * Seconds a phase may spend before it stops starting new calls.
	 *
	 * @return float
	 */
	private static function budget() {
		$budget = (float) self::MAX_SECONDS;
		$max    = (int) ini_get( 'max_execution_time' );
		if ( $max > 0 && isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ) {
			$elapsed = microtime( true ) - (float) $_SERVER['REQUEST_TIME_FLOAT'];
			$budget  = min( $budget, $max - Segurium_Scan_Runner::TICK_BUDGET_SAFETY_SEC - $elapsed );
		}
		return (float) apply_filters( 'segurium_install_scan_budget', max( 0.0, $budget ) );
	}

	/**
	 * Every regular file under the directory, executable ones first, no symlinks.
	 *
	 * @param string $dir Directory to walk.
	 * @return string[] Absolute paths.
	 */
	private static function collect( $dir ) {
		$executable = array();
		$other      = array();
		$stack      = array( $dir );
		while ( ! empty( $stack ) ) {
			$current = array_pop( $stack );
			$entries = Segurium_Fs::scandir( $current );
			if ( false === $entries ) {
				continue;
			}
			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				$path = $current . '/' . $entry;
				if ( is_link( $path ) ) {
					continue;
				}
				if ( is_dir( $path ) ) {
					$stack[] = $path;
				} elseif ( is_file( $path ) ) {
					if ( Segurium_Realtime_Scan::is_executable_path( $path ) ) {
						$executable[] = $path;
					} else {
						$other[] = $path;
					}
				}
			}
		}
		return array_merge( $executable, $other );
	}

	/**
	 * Lookup records for one batch of files.
	 *
	 * @param string[] $paths Absolute paths.
	 * @param string   $dir   Canonical package folder.
	 * @param array    $pkg   Filled with record index => path inside the package.
	 * @return array[] `{path, sha256, size, mtime}` records.
	 */
	private static function hash_files( array $paths, $dir, array &$pkg ) {
		$records = array();
		$root    = self::upgrade_root();
		foreach ( $paths as $path ) {
			$sha  = Segurium_Fs::hash_file( 'sha256', $path );
			$stat = Segurium_Fs::stat( $path );
			if ( false === $sha || ! $stat ) {
				continue;
			}
			$pkg[ count( $records ) ] = substr( $path, strlen( $dir ) + 1 );
			$records[]                = array(
				'path'   => self::site_path( $path, $root, 'wp-content/upgrade' ),
				'sha256' => $sha,
				'size'   => (int) $stat['size'],
				'mtime'  => (int) $stat['mtime'],
			);
		}
		return $records;
	}

	/**
	 * Queue unknown files for the deep scan, reading them from `$base`.
	 *
	 * @param string $base     Canonical folder holding the package files.
	 * @param string $root     Canonical root `$base` lives in.
	 * @param string $logical  WordPress-relative name of `$root`.
	 * @param array  $unknown  `{pkg, sha256, size}` records.
	 * @param float  $deadline Microtime after which no further submit starts.
	 * @param array  $summary  Run summary, by reference.
	 * @return void
	 */
	private static function upload_from( $base, $root, $logical, array $unknown, $deadline, array &$summary ) {
		if ( empty( $unknown ) ) {
			return;
		}
		if ( Segurium_Storage::on_premise_mode() ) {
			self::not_uploaded( $summary, 'on_premise', count( $unknown ) );
			return;
		}
		$next  = 0;
		$total = count( $unknown );
		while ( $next < $total ) {
			$blocked = self::upload_blocked( $deadline, $summary );
			if ( '' !== $blocked ) {
				self::not_uploaded( $summary, $blocked, $total - $next );
				return;
			}
			$batch = self::build_batch( $base, $root, $logical, $unknown, $next, $summary );
			if ( ! empty( $batch ) ) {
				self::send( $batch, $summary );
			}
		}
	}

	/**
	 * Read the next batch the submit endpoint accepts, from `$unknown[ $next ]` on.
	 *
	 * @param string $base    Canonical folder holding the package files.
	 * @param string $root    Canonical root `$base` lives in.
	 * @param string $logical WordPress-relative name of `$root`.
	 * @param array  $unknown `{pkg, sha256, size}` records.
	 * @param int    $next    Index of the next record, advanced past every record taken or skipped.
	 * @param array  $summary Run summary, by reference.
	 * @return array[] `{sha256, path, body}` files.
	 */
	private static function build_batch( $base, $root, $logical, array $unknown, &$next, array &$summary ) {
		$batch = array();
		$bytes = 0;
		$total = count( $unknown );
		while ( $next < $total ) {
			$record = $unknown[ $next ];
			$size   = (int) $record['size'];
			if ( ! empty( $batch )
				&& ( $bytes + $size > Segurium_Async_Scan_Submitter::MAX_BATCH_BYTES
					|| count( $batch ) >= Segurium_Async_Scan_Submitter::MAX_FILES_PER_BATCH ) ) {
				break;
			}
			++$next;
			if ( $size <= 0 ) {
				self::not_uploaded( $summary, 'empty', 1 );
				continue;
			}
			if ( $size > Segurium_Async_Scan_Submitter::MAX_BATCH_BYTES ) {
				self::not_uploaded( $summary, 'too_large', 1 );
				continue;
			}
			if ( ! Segurium_Async_Scan_Submitter::memory_allows( $bytes, $size ) ) {
				self::not_uploaded( $summary, 'low_memory', 1 );
				continue;
			}
			$abs  = $base . '/' . $record['pkg'];
			$body = Segurium_Fs::read( $abs );
			if ( ! is_string( $body ) || '' === $body || hash( 'sha256', $body ) !== $record['sha256'] ) {
				self::not_uploaded( $summary, 'unreadable', 1 );
				continue;
			}
			$batch[] = array(
				'sha256' => $record['sha256'],
				'path'   => self::site_path( $abs, $root, $logical ),
				'body'   => $body,
			);
			$bytes  += strlen( $body );
		}
		return $batch;
	}

	/**
	 * Why no further submit may start, or ''. A failed submit stops the rest
	 * because each one can hold the request for its full retry window.
	 *
	 * @param float $deadline Microtime after which no further submit starts.
	 * @param array $summary  Run summary, by reference.
	 * @return string Reason code.
	 */
	private static function upload_blocked( $deadline, array &$summary ) {
		if ( ! empty( $summary['not_uploaded']['upload_failed'] ) ) {
			return 'after_error';
		}
		if ( Segurium_Async_Scan_Pause::is_paused( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT ) ) {
			return 'paused';
		}
		if ( $summary['submits'] > 0 && microtime( true ) >= $deadline ) {
			$summary['stopped'] = 'budget';
			return 'budget';
		}
		return '';
	}

	/**
	 * One submit call.
	 *
	 * @param array $batch   `{sha256, path, body}` files.
	 * @param array $summary Run summary, by reference.
	 * @return void
	 */
	private static function send( array $batch, array &$summary ) {
		++$summary['submits'];
		$result = Segurium_Storage::cti_scan_submit( $summary['scan_id'], wp_generate_uuid4(), $batch );
		if ( is_wp_error( $result ) ) {
			if ( '' === $summary['error'] ) {
				$summary['error'] = (string) $result->get_error_code();
			}
			self::not_uploaded( $summary, 'upload_failed', count( $batch ) );
			if ( 'cti_paused' === $result->get_error_code() ) {
				$data = $result->get_error_data();
				self::pause( is_array( $data ) && isset( $data['retry_after'] ) ? (int) $data['retry_after'] : 0 );
			}
			return;
		}
		$accepted             = isset( $result['accepted'] ) && is_array( $result['accepted'] ) ? count( $result['accepted'] ) : 0;
		$rejected             = isset( $result['rejected'] ) && is_array( $result['rejected'] ) ? count( $result['rejected'] ) : 0;
		$summary['uploaded'] += $accepted;
		if ( $rejected > 0 ) {
			self::not_uploaded( $summary, 'rejected', $rejected );
		}
		self::pause( isset( $result['retry_after'] ) ? (int) $result['retry_after'] : 0 );
	}

	/**
	 * Stamp the IID-scoped submit pause CTI asked for.
	 *
	 * @param int $retry_after Seconds.
	 * @return void
	 */
	private static function pause( $retry_after ) {
		if ( $retry_after > 0 ) {
			Segurium_Async_Scan_Pause::set_pause( Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT, $retry_after );
		}
	}

	/**
	 * Count files that were not uploaded, by reason.
	 *
	 * @param array  $summary Run summary, by reference.
	 * @param string $reason  Reason code.
	 * @param int    $count   Files.
	 * @return void
	 */
	private static function not_uploaded( array &$summary, $reason, $count ) {
		$summary['not_uploaded'][ $reason ] = ( $summary['not_uploaded'][ $reason ] ?? 0 ) + (int) $count;
	}

	/**
	 * Record an exception as the run's error.
	 *
	 * @param Throwable $e       Exception.
	 * @param array     $summary Run summary, by reference.
	 * @return void
	 */
	private static function exception( Throwable $e, array &$summary ) {
		if ( '' === $summary['error'] ) {
			$summary['error'] = 'exception';
		}
		Segurium_Debug::log( '[segurium-install-scan] exception: ' . get_class( $e ) . ': ' . $e->getMessage() );
	}

	/**
	 * Log a finished run.
	 *
	 * @param array $summary Run summary.
	 * @return void
	 */
	private static function finish( array $summary ) {
		if ( '' !== $summary['blocked_path'] ) {
			Segurium_Debug::log( '[segurium-install-scan] install stopped, known malware: ' . $summary['blocked_path'] );
		}
		if ( '' !== $summary['error'] ) {
			Segurium_Debug::log( '[segurium-install-scan] stopped with error ' . $summary['error'] . ': ' . wp_json_encode( $summary ) );
		}
		if ( class_exists( 'Segurium_Scan_Runner' ) ) {
			Segurium_Scan_Runner::debug( 'install_scan', $summary );
		}
	}

	/**
	 * Fresh run summary.
	 *
	 * @return array
	 */
	private static function empty_summary() {
		return array(
			'skipped'      => '',
			'scan_id'      => '',
			'files'        => 0,
			'looked_up'    => 0,
			'unknown'      => 0,
			'uploaded'     => 0,
			'submits'      => 0,
			'not_uploaded' => array(),
			'infected'     => 0,
			'blocked_path' => '',
			'stopped'      => '',
			'error'        => '',
		);
	}
}

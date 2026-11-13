<?php
/**
 * Standing remediation orders: cloud-issued orders that act on a path or a
 * one-folder pattern, repeated on every wake until they expire.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Storage, wakes and execution of standing orders.
 */
final class Segurium_Standing_Orders {

	const OPTION       = 'segurium_standing_orders';
	const HOOK         = 'segurium_standing_orders_tick';
	const SCHEDULE     = 'segurium_standing_orders_5min';
	const INTERVAL     = 300;
	const LOCK_KEY     = 'segurium_standing_orders_lock';
	const LOCK_TTL     = 300;
	const MESSAGE_TYPE = 'standing_order';
	const ACTOR        = 'standing_order';

	const MAX_FILES_PER_WAKE  = 20;
	const MAX_LIFETIME        = DAY_IN_SECONDS;
	const REPORT_LIST_MAX     = 20;
	const MAX_NAME_LEN        = 255;
	const BYTES_KEY_PREFIX    = 'standing_order_bytes:';
	const RELEASED_KEY_PREFIX = 'standing_order_released:';

	/** Safe, and pristine release bytes that carry a CVE. */
	const UNTOUCHABLE_VERDICTS = array( 0, 5 );

	const REFUSE_AUTO_FIX_OFF  = 'auto_fix_off';
	const REFUSE_BAD_ARGS      = 'bad_args';
	const REFUSE_BAD_ISSUED_AT = 'bad_issued_at';

	const REPLACE_KEYS = array( 'path', 'generated_at', 'expires_at', 'verdict', 'source_sha256', 'clean_sha256' );
	const PURGE_KEYS   = array( 'folder', 'generated_at', 'expires_at', 'verdict' );

	/** `.ico` is left out: droppers hide PHP behind it. */
	const MEDIA_EXTENSIONS = array( 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'avif', 'heic', 'bmp', 'tif', 'tiff', 'mp3', 'm4a', 'ogg', 'oga', 'wav', 'flac', 'mp4', 'm4v', 'mov', 'webm', 'ogv', 'avi', 'wmv', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'woff', 'woff2', 'ttf', 'otf', 'eot' );

	/**
	 * Wire the tick, its schedule and the admin-page wake.
	 *
	 * @return void
	 */
	public static function register_hooks(): void {
		add_filter( 'cron_schedules', array( __CLASS__, 'cron_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected -- five-minute interval, booked only while an order is live.
		add_action( self::HOOK, array( __CLASS__, 'run_cron' ) );
		add_action( 'load-toplevel_page_segurium', array( __CLASS__, 'run_admin' ) );
	}

	/**
	 * Add the five-minute schedule.
	 *
	 * @param array $schedules Registered schedules.
	 * @return array
	 */
	public static function cron_schedules( $schedules ) {
		$schedules = is_array( $schedules ) ? $schedules : array();
		$label     = 'Every 5 minutes (Segurium standing orders)';
		if ( did_action( 'after_setup_theme' ) ) {
			$label = __( 'Every 5 minutes (Segurium standing orders)', 'segurium' );
		}
		$schedules[ self::SCHEDULE ] = array(
			'interval' => self::INTERVAL,
			'display'  => $label,
		);
		return $schedules;
	}

	/**
	 * Book the tick. Idempotent.
	 *
	 * @return void
	 */
	public static function schedule(): void {
		add_filter( 'cron_schedules', array( __CLASS__, 'cron_schedules' ) ); // phpcs:ignore WordPress.WP.CronInterval.ChangeDetected -- five-minute interval, booked only while an order is live.
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + self::INTERVAL, self::SCHEDULE, self::HOOK );
		}
	}

	/**
	 * Clear the tick.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		wp_clear_scheduled_hook( self::HOOK );
	}

	/**
	 * Stored orders keyed by order id.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function orders(): array {
		return Segurium_Storage::setting_get_array( self::OPTION, array() );
	}

	/**
	 * Cron handler.
	 *
	 * @return void
	 */
	public static function run_cron(): void {
		self::run( 'cron' );
	}

	/**
	 * Segurium admin page: run after the response is closed, or not at all.
	 *
	 * @return void
	 */
	public static function run_admin(): void {
		if ( empty( self::orders() ) || ! Segurium_Rest_Actions_Poke::detach_available() ) {
			return;
		}
		add_action( 'shutdown', array( __CLASS__, 'run_detached' ) );
	}

	/**
	 * Shutdown handler of the admin wake.
	 *
	 * @return void
	 */
	public static function run_detached(): void {
		Segurium_Rest_Actions_Poke::detach_response();
		self::run( 'admin' );
	}

	/**
	 * Grammar, then the Auto-fix toggle. Writes nothing.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string Segurium_Remote_Actions::OK, or the refusal code.
	 */
	public static function evaluate( array $action ): string {
		if ( null === self::parse( $action ) ) {
			return self::REFUSE_BAD_ARGS;
		}
		if ( ! Segurium_Auto_Fix_Settings::is_enabled() ) {
			return self::REFUSE_AUTO_FIX_OFF;
		}
		return Segurium_Remote_Actions::OK;
	}

	/**
	 * Store an evaluated order and report its receipt.
	 *
	 * @param array<string, mixed> $action    One entry from `actions[]`.
	 * @param int                  $issued_at The envelope's `issued_at`, cloud time.
	 * @param string               $verdict   Outcome of the channel's evaluate().
	 * @return string Segurium_Remote_Actions::OK, or the refusal code.
	 */
	public static function receive( array $action, int $issued_at, string $verdict ): string {
		$order = self::parse( $action );
		$code  = $verdict;
		if ( Segurium_Remote_Actions::OK === $code && null !== $order ) {
			$code = self::store( $order, $issued_at );
		}

		self::report(
			array(
				'id'   => isset( $action['id'] ) && is_string( $action['id'] ) ? $action['id'] : '',
				'type' => isset( $action['type'] ) && is_string( $action['type'] ) ? $action['type'] : '',
			),
			'received',
			array(
				'outcome'    => $code,
				'expires_at' => null === $order ? 0 : (int) $order['expires_at'],
			)
		);
		return $code;
	}

	/**
	 * Run every live order once. Never throws.
	 *
	 * @param string $trigger `cron`, `admin` or `pull`.
	 * @return array<int, array<string, mixed>> The run reports sent.
	 */
	public static function run( string $trigger ): array {
		if ( '' !== Segurium_Remote_Actions::closed_reason() ) {
			return array();
		}
		if ( empty( self::orders() ) ) {
			if ( 'cron' === $trigger ) {
				self::unschedule();
			}
			return array();
		}
		self::schedule();
		if ( ! self::lock() ) {
			return array();
		}

		try {
			return self::run_locked( $trigger );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] standing orders run failed: ' . $e->getMessage() );
			return array();
		} finally {
			Segurium_Storage::setting_delete( self::LOCK_KEY );
		}
	}

	/**
	 * Take the run lock atomically; a lock older than its TTL is taken over.
	 *
	 * @return bool
	 */
	private static function lock(): bool {
		$now = (string) time();
		if ( Segurium_Storage::setting_insert_raw( self::LOCK_KEY, $now ) ) {
			return true;
		}
		$held = Segurium_Storage::setting_get_raw( self::LOCK_KEY );
		if ( null === $held || (int) $held > time() - self::LOCK_TTL ) {
			return false;
		}
		return Segurium_Storage::setting_swap_raw( self::LOCK_KEY, $held, $now );
	}

	/**
	 * Store an order. An order generated before the stored one for the same
	 * target is refused; a redelivered order keeps its state.
	 *
	 * @param array<string, mixed> $order     Parsed order.
	 * @param int                  $issued_at The envelope's `issued_at`, cloud time.
	 * @return string
	 */
	private static function store( array $order, int $issued_at ): string {
		if ( $issued_at <= 0 ) {
			return self::REFUSE_BAD_ISSUED_AT;
		}
		$left = (int) $order['expires_at'] - $issued_at;
		if ( $left <= 0 ) {
			return Segurium_Remote_Actions::REFUSE_EXPIRED;
		}

		$orders = self::orders();
		if ( isset( $orders[ $order['id'] ] ) ) {
			return Segurium_Remote_Actions::OK;
		}
		$key = self::target_key( $order );
		foreach ( $orders as $id => $stored ) {
			if ( self::target_key( $stored ) !== $key ) {
				continue;
			}
			if ( (int) $stored['generated_at'] > (int) $order['generated_at'] ) {
				return Segurium_Remote_Actions::REFUSE_SUPERSEDED;
			}
			self::forget( $stored );
			unset( $orders[ $id ] );
		}

		$order['deadline']      = time() + min( $left, self::MAX_LIFETIME );
		$orders[ $order['id'] ] = $order;
		self::save( $orders );
		self::schedule();
		return Segurium_Remote_Actions::OK;
	}

	/**
	 * Expire, then execute. Writes back only the orders it ran, so an order a
	 * pull stored meanwhile survives.
	 *
	 * @param string $trigger Wake label.
	 * @return array<int, array<string, mixed>>
	 */
	private static function run_locked( string $trigger ): array {
		$orders  = self::orders();
		$expired = array();
		foreach ( $orders as $id => $order ) {
			if ( time() >= (int) $order['deadline'] ) {
				self::report(
					$order,
					'expired',
					array(
						'runs'          => (int) $order['runs'],
						'files_touched' => (int) $order['files_touched'],
					)
				);
				self::forget( $order );
				$expired[ $id ] = true;
				unset( $orders[ $id ] );
			}
		}

		$reports = array();
		if ( ! empty( $orders ) && Segurium_Auto_Fix_Settings::is_enabled() ) {
			$reports = self::execute( $orders, $trigger );
		}

		$stored = self::orders();
		$fresh  = $stored;
		foreach ( $fresh as $id => $order ) {
			if ( isset( $expired[ $id ] ) ) {
				unset( $fresh[ $id ] );
			} elseif ( isset( $orders[ $id ] ) ) {
				$fresh[ $id ] = $orders[ $id ];
			}
		}
		if ( $fresh !== $stored ) {
			self::save( $fresh );
		}
		if ( empty( $fresh ) ) {
			self::unschedule();
		}
		return $reports;
	}

	/**
	 * Plan every order, spend the per-wake cap, check verdicts, cure, report.
	 *
	 * @param array<string, array<string, mixed>> $orders  Live orders, state updated in place.
	 * @param string                              $trigger Wake label.
	 * @return array<int, array<string, mixed>>
	 */
	private static function execute( array &$orders, string $trigger ): array {
		$plans = array();
		foreach ( $orders as $id => $order ) {
			$plans[ $id ] = array(
				'matched'    => 0,
				'candidates' => array(),
				'released'   => array_flip( self::released( $order ) ),
				'touched'    => array(),
				'skipped'    => array(),
				'errors'     => array(),
				'loud'       => false,
			);
			if ( Segurium_Remote_Actions::TYPE_REPLACE_FILE_24H === $order['type'] ) {
				self::plan_replace( $orders[ $id ], $plans[ $id ] );
			} else {
				self::plan_purge( $orders[ $id ], $plans[ $id ] );
			}
		}

		$ignore = new Segurium_Ignore_Lists( Segurium_Storage_Fs::data_dir() );
		$ignore->load();
		$skip = array(
			'lists'    => $ignore,
			'excluded' => Segurium_Scanner::compile_patterns( array_merge( Segurium::get_instance()->get_scan_exclusions(), $ignore->get_path_list() ) ),
			'pinned'   => array_flip( array_column( $ignore->get_hash_list(), 'path' ) ),
		);
		self::drop_ignored( $orders, $plans, $skip );
		self::apply_cap( $plans );
		self::hash_candidates( $orders, $plans );
		self::drop_ignored( $orders, $plans, $skip );
		self::drop_untouchable( $orders, $plans );
		if ( self::act( $orders, $plans ) > 0 ) {
			Segurium_Cache_Invalidation::cleaned( Segurium_Cache_Invalidation::TRIGGER_STANDING_ORDER );
		}

		$reports = array();
		foreach ( $plans as $id => $plan ) {
			if ( ! $plan['loud'] ) {
				continue;
			}
			++$orders[ $id ]['runs'];
			$orders[ $id ]['files_touched'] += count( $plan['touched'] );
			$reports[]                       = self::report(
				$orders[ $id ],
				'run',
				array(
					'trigger'       => $trigger,
					'matched'       => $plan['matched'],
					'touched'       => array_slice( $plan['touched'], 0, self::REPORT_LIST_MAX ),
					'skipped'       => array_slice( $plan['skipped'], 0, self::REPORT_LIST_MAX ),
					'skipped_total' => count( $plan['skipped'] ),
					'errors'        => array_slice( $plan['errors'], 0, self::REPORT_LIST_MAX ),
				)
			);
		}
		return $reports;
	}

	/**
	 * One stat of the target; a candidate unless it holds the cure this order
	 * last wrote.
	 *
	 * @param array<string, mixed> $order Order, state updated in place.
	 * @param array<string, mixed> $plan  Plan, filled in place.
	 * @return void
	 */
	private static function plan_replace( array &$order, array &$plan ): void {
		$path = (string) $order['path'];
		// phpcs:ignore -- segurium-wporg-abspath: an order names a path relative to the WordPress root, and containment is the check.
		$abs = ABSPATH . $path;
		clearstatcache( true, $abs );

		if ( is_link( $abs ) ) {
			self::skip_once( $order, $plan, $path, 'protected' );
			return;
		}
		$real = realpath( $abs );
		if ( false === $real || ! is_file( $real ) ) {
			self::skip_once( $order, $plan, $path, 'absent' );
			return;
		}
		self::clear_mark( $order, $path, 'absent' );
		$plan['matched'] = 1;

		if ( ! Segurium_Remote_Actions::inside_abspath( $real ) || self::is_protected( $real ) ) {
			self::skip_once( $order, $plan, $path, 'protected' );
			return;
		}
		if ( isset( $plan['released'][ $path ] ) || isset( $plan['released'][ Segurium_Remote_Actions::relative_to_abspath( $real ) ] ) ) {
			self::skip_once( $order, $plan, $path, 'restored' );
			return;
		}
		$stamp = self::stamp( $real );
		if ( isset( $order['state']['cured'] ) && $stamp === $order['state']['cured'] ) {
			return;
		}
		self::plan_file( $order, $plan, $real, $path, $stamp );
	}

	/**
	 * Read the folder only when its mtime moved; otherwise revisit the names
	 * it matched last time, which catches a payload rewritten in place.
	 *
	 * @param array<string, mixed> $order Order, state updated in place.
	 * @param array<string, mixed> $plan  Plan, filled in place.
	 * @return void
	 */
	private static function plan_purge( array &$order, array &$plan ): void {
		$folder = (string) $order['folder'];
		// phpcs:ignore -- segurium-wporg-abspath: an order names a folder relative to the WordPress root, and containment is the check.
		$abs = '.' === $folder ? untrailingslashit( ABSPATH ) : ABSPATH . $folder;
		clearstatcache( true, $abs );

		if ( is_link( $abs ) ) {
			self::skip_once( $order, $plan, $folder, 'protected' );
			return;
		}
		// phpcs:ignore -- segurium-wporg-abspath: the WordPress root is the one folder `.` may name.
		$root = untrailingslashit( (string) realpath( ABSPATH ) );
		$dir  = realpath( $abs );
		if ( false === $dir || ! is_dir( $dir ) || ( $root !== $dir && ! Segurium_Remote_Actions::inside_abspath( $dir ) ) ) {
			self::skip_once( $order, $plan, $folder, 'absent' );
			return;
		}
		self::clear_mark( $order, $folder, 'absent' );

		$mtime = (int) filemtime( $dir );
		$state = isset( $order['state'] ) && is_array( $order['state'] ) ? $order['state'] : array();
		if ( isset( $state['mtime'], $state['scanned_at'], $state['names'] ) && $state['mtime'] === $mtime && $mtime < $state['scanned_at'] ) {
			$names = (array) $state['names'];
		} else {
			$names = self::matching_names( $dir, $order );
			$keep  = array( $folder => true );
			foreach ( $names as $name ) {
				$keep[ Segurium_Remote_Actions::relative_to_abspath( $dir . '/' . $name ) ] = true;
			}
			$order['state']['mtime']      = $mtime;
			$order['state']['scanned_at'] = time();
			$order['state']['names']      = $names;
			$order['state']['marks']      = array_intersect_key( isset( $state['marks'] ) ? (array) $state['marks'] : array(), $keep );
		}
		$plan['matched'] = count( $names );

		foreach ( $names as $name ) {
			$file = $dir . '/' . $name;
			$rel  = Segurium_Remote_Actions::relative_to_abspath( $file );
			clearstatcache( true, $file );
			if ( is_link( $file ) ) {
				self::skip_once( $order, $plan, $rel, 'protected' );
				continue;
			}
			if ( ! is_file( $file ) ) {
				continue;
			}
			if ( self::is_protected( $file ) ) {
				self::skip_once( $order, $plan, $rel, 'protected' );
				continue;
			}
			if ( isset( $plan['released'][ $rel ] ) ) {
				self::skip_once( $order, $plan, $rel, 'restored' );
				continue;
			}
			if ( 0 === (int) filesize( $file ) ) {
				$plan['skipped'][] = array(
					'path'   => $rel,
					'reason' => 'zero_byte',
				);
				continue;
			}
			self::plan_file( $order, $plan, $file, $rel, self::stamp( $file ) );
		}
	}

	/**
	 * Size, mtime and ctime. Userland can set mtime back but not ctime.
	 *
	 * @param string $abs Resolved absolute path.
	 * @return string
	 */
	private static function stamp( string $abs ): string {
		return (int) filesize( $abs ) . ':' . (int) filemtime( $abs ) . ':' . (int) filectime( $abs );
	}

	/**
	 * Queue one file unless it is too large or already known untouchable as is.
	 *
	 * @param array<string, mixed> $order Order.
	 * @param array<string, mixed> $plan  Plan.
	 * @param string               $abs   Resolved absolute path.
	 * @param string               $rel   Site-relative path.
	 * @param string               $stamp Output of stamp().
	 * @return void
	 */
	private static function plan_file( array &$order, array &$plan, string $abs, string $rel, string $stamp ): void {
		$parts = array_map( 'intval', explode( ':', $stamp ) );
		if ( $parts[0] > Segurium_Scanner::MAX_FILE_SIZE ) {
			self::skip_once( $order, $plan, $rel, 'too_large', $stamp );
			return;
		}
		if ( self::mark( $order, $rel ) === 'safe:' . $stamp ) {
			return;
		}
		$plan['candidates'][] = array(
			'abs'   => $abs,
			'rel'   => $rel,
			'size'  => $parts[0],
			'mtime' => $parts[1],
			'ctime' => $parts[2],
			'stamp' => $stamp,
		);
	}

	/**
	 * Drop what the scanner skips by the user's choice: by path first, by content once hashed.
	 *
	 * @param array<string, array<string, mixed>> $orders Orders, state updated in place.
	 * @param array<string, array<string, mixed>> $plans  Plans, updated in place.
	 * @param array<string, mixed>                $skip   Ignore lists, compiled exclusions, hash-ignored paths.
	 * @return void
	 */
	private static function drop_ignored( array &$orders, array &$plans, array $skip ): void {
		foreach ( $plans as $id => $plan ) {
			$keep = array();
			foreach ( $plan['candidates'] as $candidate ) {
				$rel = $candidate['rel'];
				if ( isset( $candidate['sha256'] ) ) {
					$ignored = $skip['lists']->is_hash_ignored( $rel, $candidate['sha256'] );
				} else {
					$ignored = self::excluded( $skip['excluded'], $rel )
						|| ( isset( $skip['pinned'][ $rel ] ) && self::mark( $orders[ $id ], $rel ) === 'ignored:' . $candidate['stamp'] );
				}
				if ( $ignored ) {
					self::skip_once( $orders[ $id ], $plans[ $id ], $rel, 'ignored', $candidate['stamp'] );
					continue;
				}
				$keep[] = $candidate;
			}
			$plans[ $id ]['candidates'] = $keep;
		}
	}

	/**
	 * The scanner prunes a matching folder, so every ancestor counts.
	 *
	 * @param string[] $compiled Output of Segurium_Scanner::compile_patterns().
	 * @param string   $rel      Site-relative path.
	 * @return bool
	 */
	private static function excluded( array $compiled, string $rel ): bool {
		for ( $path = $rel; '' !== $path && '.' !== $path; $path = dirname( $path ) ) {
			foreach ( $compiled as $regex ) {
				if ( preg_match( $regex, $path ) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Spend the per-wake file budget across orders in storage order.
	 *
	 * @param array<string, array<string, mixed>> $plans Plans, updated in place.
	 * @return void
	 */
	private static function apply_cap( array &$plans ): void {
		$budget = self::MAX_FILES_PER_WAKE;
		foreach ( $plans as $id => $plan ) {
			$keep = array();
			foreach ( $plan['candidates'] as $candidate ) {
				if ( $budget > 0 ) {
					$keep[] = $candidate;
					--$budget;
					continue;
				}
				$plans[ $id ]['skipped'][] = array(
					'path'   => $candidate['rel'],
					'reason' => 'cap',
				);
				$plans[ $id ]['loud']      = true;
			}
			$plans[ $id ]['candidates'] = $keep;
		}
	}

	/**
	 * Hash each candidate; a replace target that already holds the cure is
	 * remembered and dropped.
	 *
	 * @param array<string, array<string, mixed>> $orders Orders, state updated in place.
	 * @param array<string, array<string, mixed>> $plans  Plans, updated in place.
	 * @return void
	 */
	private static function hash_candidates( array &$orders, array &$plans ): void {
		foreach ( $plans as $id => $plan ) {
			$keep = array();
			foreach ( $plan['candidates'] as $candidate ) {
				$hash = Segurium_Fs::hash_file( 'sha256', $candidate['abs'] );
				if ( false === $hash ) {
					self::error( $plans[ $id ], $candidate['rel'], 'unreadable' );
					continue;
				}
				if ( Segurium_Remote_Actions::TYPE_REPLACE_FILE_24H === $orders[ $id ]['type'] && hash_equals( (string) $orders[ $id ]['clean_sha256'], $hash ) ) {
					$orders[ $id ]['state']['cured'] = $candidate['stamp'];
					continue;
				}
				$candidate['sha256'] = $hash;
				$keep[]              = $candidate;
			}
			$plans[ $id ]['candidates'] = $keep;
		}
	}

	/**
	 * One `/v1/inspect` call for every candidate. Safe (manifest hits
	 * included) and Vulnerable files are skipped; a file without an answer
	 * is not touched.
	 *
	 * @param array<string, array<string, mixed>> $orders Orders, state updated in place.
	 * @param array<string, array<string, mixed>> $plans  Plans, updated in place.
	 * @return void
	 */
	private static function drop_untouchable( array &$orders, array &$plans ): void {
		$files = array();
		foreach ( $plans as $plan ) {
			foreach ( $plan['candidates'] as $candidate ) {
				$files[] = array(
					'path'   => $candidate['rel'],
					'sha256' => $candidate['sha256'],
					'size'   => $candidate['size'],
					'mtime'  => $candidate['mtime'],
				);
			}
		}
		if ( empty( $files ) ) {
			return;
		}

		$results  = Segurium_Storage::cti_inspect_hashes( $files );
		$verdicts = array();
		if ( is_wp_error( $results ) ) {
			Segurium_Debug::log( '[segurium] standing orders verdict lookup failed: ' . $results->get_error_code() );
		} else {
			foreach ( (array) $results as $row ) {
				if ( is_array( $row ) && isset( $row['sha256'], $row['verdict'] ) ) {
					$verdicts[ (string) $row['sha256'] ] = (int) $row['verdict'];
				}
			}
		}

		foreach ( $plans as $id => $plan ) {
			$keep = array();
			foreach ( $plan['candidates'] as $candidate ) {
				$verdict = $verdicts[ $candidate['sha256'] ] ?? null;
				if ( null === $verdict ) {
					self::error( $plans[ $id ], $candidate['rel'], 'verdict_unavailable' );
				} elseif ( in_array( $verdict, self::UNTOUCHABLE_VERDICTS, true ) ) {
					self::skip_once( $orders[ $id ], $plans[ $id ], $candidate['rel'], 'safe', $candidate['stamp'] );
				} else {
					$keep[] = $candidate;
				}
			}
			$plans[ $id ]['candidates'] = $keep;
		}
	}

	/**
	 * Cure every remaining candidate through the shared cleanup primitive.
	 *
	 * @param array<string, array<string, mixed>> $orders Orders, state updated in place.
	 * @param array<string, array<string, mixed>> $plans  Plans, updated in place.
	 * @return int Files touched.
	 */
	private static function act( array &$orders, array &$plans ): int {
		$backups = null;
		$touched = 0;
		foreach ( $plans as $id => $plan ) {
			$order   = $orders[ $id ];
			$replace = Segurium_Remote_Actions::TYPE_REPLACE_FILE_24H === $order['type'];
			foreach ( $plan['candidates'] as $candidate ) {
				$content = $replace ? self::cured_bytes( $order, $candidate ) : '';
				if ( is_wp_error( $content ) ) {
					self::error( $plans[ $id ], $candidate['rel'], (string) $content->get_error_code() );
					continue;
				}

				$result = Segurium_Cleanup::remediate(
					$candidate['abs'],
					$candidate['rel'],
					$candidate['sha256'],
					(int) $order['verdict'],
					$content,
					self::ACTOR,
					array( 'order_id' => (string) $order['id'] ),
					$backups
				);
				if ( empty( $result['ok'] ) ) {
					self::error( $plans[ $id ], $candidate['rel'], (string) $result['error_code'] );
					continue;
				}

				++$touched;
				$plans[ $id ]['touched'][] = array(
					'path'          => $candidate['rel'],
					'action'        => $replace ? 'replaced' : 'truncated',
					'backup_id'     => (string) $result['backup_id'],
					'sha256_before' => $candidate['sha256'],
				);
				$plans[ $id ]['loud']      = true;
				if ( $replace ) {
					clearstatcache( true, $candidate['abs'] );
					$orders[ $id ]['state']['cured'] = self::stamp( $candidate['abs'] );
				}
			}
		}
		return $touched;
	}

	/**
	 * Cured bytes of a replace order: fetched once through `/v1/cleanup` by
	 * the infected hash the order names, then cached until the order ends.
	 *
	 * @param array<string, mixed> $order     Replace order.
	 * @param array<string, mixed> $candidate The file about to be replaced.
	 * @return string|WP_Error
	 */
	private static function cured_bytes( array $order, array $candidate ) {
		$clean  = (string) $order['clean_sha256'];
		$key    = self::BYTES_KEY_PREFIX . $clean;
		$cached = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s AND (expires_at IS NULL OR expires_at > %d)',
			array( $key, time() )
		);
		if ( null !== $cached && hash_equals( $clean, hash( 'sha256', (string) $cached ) ) ) {
			return (string) $cached;
		}

		$fetched = Segurium_Storage::cti_fetch_cleanup_file( (string) $order['source_sha256'], $candidate['rel'], (int) $candidate['ctime'] );
		if ( is_wp_error( $fetched ) ) {
			return $fetched;
		}
		$bytes = (string) $fetched['content'];
		if ( ! hash_equals( $clean, hash( 'sha256', $bytes ) ) ) {
			return new WP_Error( 'clean_hash_mismatch' );
		}

		Segurium_Storage::table_upsert(
			'runtime_kv',
			array(
				'kv_key'     => $key,
				'kv_value'   => $bytes,
				'expires_at' => (int) $order['deadline'],
				'updated_at' => time(),
			),
			array( 'kv_key' )
		);
		return $bytes;
	}

	/**
	 * Keep a restored file out of every live order that covers its path.
	 *
	 * @param string $rel Site-relative path.
	 * @return int Live orders that cover the path.
	 */
	public static function release( string $rel ): int {
		$covered = 0;
		foreach ( self::orders() as $order ) {
			if ( ! self::covers( $order, $rel ) ) {
				continue;
			}
			++$covered;
			$paths = self::released( $order );
			if ( in_array( $rel, $paths, true ) ) {
				continue;
			}
			$paths[] = $rel;
			$encoded = wp_json_encode( $paths );
			if ( false === $encoded ) {
				Segurium_Debug::log( '[segurium] standing order ' . $order['id'] . ': released path list is not JSON-encodable, ' . $rel . ' stays in scope' );
				continue;
			}
			Segurium_Storage::table_upsert(
				'runtime_kv',
				array(
					'kv_key'     => self::RELEASED_KEY_PREFIX . $order['id'],
					'kv_value'   => $encoded,
					'expires_at' => (int) $order['deadline'],
					'updated_at' => time(),
				),
				array( 'kv_key' )
			);
		}
		return $covered;
	}

	/**
	 * Whether an order's target names a path.
	 *
	 * @param array<string, mixed> $order Order.
	 * @param string               $rel   Site-relative path.
	 * @return bool
	 */
	private static function covers( array $order, string $rel ): bool {
		if ( Segurium_Remote_Actions::TYPE_REPLACE_FILE_24H === $order['type'] ) {
			return in_array( $rel, self::spellings( (string) $order['path'] ), true );
		}
		$slash  = strrpos( $rel, '/' );
		$parent = false === $slash ? '' : substr( $rel, 0, $slash );
		$name   = false === $slash ? $rel : substr( $rel, $slash + 1 );
		$folder = '.' === $order['folder'] ? '' : (string) $order['folder'];
		return '' !== $name && in_array( $parent, self::spellings( $folder ), true ) && self::name_matches( $order, $name );
	}

	/**
	 * A target as the order spells it and as the filesystem resolves it.
	 *
	 * @param string $target Site-relative path; empty for the root.
	 * @return array<int, string>
	 */
	private static function spellings( string $target ): array {
		// phpcs:ignore -- segurium-wporg-abspath: an order names its target relative to the WordPress root, and containment was checked when it was stored.
		$real = realpath( '' === $target ? untrailingslashit( ABSPATH ) : ABSPATH . $target );
		if ( false === $real ) {
			return array( $target );
		}
		return array_unique( array( $target, Segurium_Remote_Actions::relative_to_abspath( $real ) ) );
	}

	/**
	 * Whether a purge order's glob or name list matches a file name.
	 *
	 * @param array<string, mixed> $order Purge order.
	 * @param string               $name  File name.
	 * @return bool
	 */
	private static function name_matches( array $order, string $name ): bool {
		if ( empty( $order['names'] ) ) {
			return self::glob_matches( (string) $order['glob'], $name );
		}
		return in_array( $name, (array) $order['names'], true );
	}

	/**
	 * Paths a restore released from an order.
	 *
	 * @param array<string, mixed> $order Order.
	 * @return array<int, string>
	 */
	private static function released( array $order ): array {
		$raw   = Segurium_Storage::table_get_var(
			'runtime_kv',
			'SELECT kv_value FROM {{table}} WHERE kv_key = %s AND (expires_at IS NULL OR expires_at > %d)',
			array( self::RELEASED_KEY_PREFIX . $order['id'], time() )
		);
		$paths = null === $raw ? null : json_decode( (string) $raw, true );
		return is_array( $paths ) ? array_values( array_filter( $paths, 'is_string' ) ) : array();
	}

	/**
	 * Drop what an order kept in `runtime_kv`: cached cure bytes and released paths.
	 *
	 * @param array<string, mixed> $order Order.
	 * @return void
	 */
	private static function forget( array $order ): void {
		if ( ! empty( $order['clean_sha256'] ) ) {
			Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::BYTES_KEY_PREFIX . $order['clean_sha256'] ) );
		}
		Segurium_Storage::table_delete( 'runtime_kv', array( 'kv_key' => self::RELEASED_KEY_PREFIX . $order['id'] ) );
	}

	/**
	 * Credentials, the plugin's own files and data, and media under uploads.
	 *
	 * @param string $real Resolved absolute path.
	 * @return bool
	 */
	private static function is_protected( string $real ): bool {
		if ( Segurium_Remote_Action_Paths::is_denied( Segurium_Remote_Actions::relative_to_abspath( $real ) ) ) {
			return true;
		}

		$roots = array( Segurium_Path_Helpers::plugins_root() . '/' . Segurium_Remote_Actions::SELF_SLUG, Segurium_Storage_Fs::data_dir() );
		if ( defined( 'SEGURIUM_PLUGIN_DIR' ) ) {
			$roots[] = SEGURIUM_PLUGIN_DIR;
		}
		foreach ( $roots as $root ) {
			$resolved = realpath( $root );
			if ( false !== $resolved && 0 === strpos( $real . '/', trailingslashit( $resolved ) ) ) {
				return true;
			}
		}

		$uploads = wp_upload_dir( null, false );
		$base    = empty( $uploads['basedir'] ) ? false : realpath( $uploads['basedir'] );
		return false !== $base
			&& 0 === strpos( $real, trailingslashit( $base ) )
			&& in_array( strtolower( pathinfo( $real, PATHINFO_EXTENSION ) ), self::MEDIA_EXTENSIONS, true );
	}

	/**
	 * Names in one folder that match the order. No recursion.
	 *
	 * @param string               $dir   Resolved folder.
	 * @param array<string, mixed> $order Purge order.
	 * @return string[]
	 */
	private static function matching_names( string $dir, array $order ): array {
		$entries = scandir( $dir );
		$names   = array();
		foreach ( false === $entries ? array() : $entries as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			if ( self::name_matches( $order, $entry ) ) {
				$names[] = $entry;
			}
		}
		return $names;
	}

	/**
	 * `*` matches any run of characters, `?` one; the rest is literal and
	 * case-sensitive. A name that is not valid UTF-8 matches nothing.
	 *
	 * @param string $glob Pattern.
	 * @param string $name File name.
	 * @return bool
	 */
	public static function glob_matches( string $glob, string $name ): bool {
		$chars = preg_split( '//u', $glob, -1, PREG_SPLIT_NO_EMPTY );
		if ( false === $chars ) {
			return false;
		}
		$regex = '';
		foreach ( $chars as $char ) {
			if ( '*' === $char ) {
				$regex .= '.*';
			} elseif ( '?' === $char ) {
				$regex .= '.';
			} else {
				$regex .= preg_quote( $char, '/' );
			}
		}
		return 1 === preg_match( '/\A' . $regex . '\z/su', $name );
	}

	/**
	 * Validate an action into an order, or null. Mirrors the cloud's grammar.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return array<string, mixed>|null
	 */
	private static function parse( array $action ): ?array {
		$id   = isset( $action['id'] ) && is_string( $action['id'] ) ? $action['id'] : '';
		$type = isset( $action['type'] ) && is_string( $action['type'] ) ? $action['type'] : '';
		$args = isset( $action['args'] ) && is_array( $action['args'] ) ? $action['args'] : null;
		if ( 1 !== preg_match( '/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/', $id ) || null === $args ) {
			return null;
		}
		foreach ( $args as $key => $value ) {
			if ( ! is_string( $key ) || ! is_string( $value ) ) {
				return null;
			}
		}

		if ( Segurium_Remote_Actions::TYPE_REPLACE_FILE_24H === $type ) {
			$keys = self::REPLACE_KEYS;
		} elseif ( Segurium_Remote_Actions::TYPE_PURGE_PATTERN_24H === $type ) {
			$keys   = self::PURGE_KEYS;
			$keys[] = isset( $args['glob'] ) ? 'glob' : 'names';
		} else {
			return null;
		}
		if ( count( $args ) !== count( $keys ) || array_diff( $keys, array_keys( $args ) ) ) {
			return null;
		}

		$generated = self::unix_secs( $args['generated_at'] );
		$expires   = self::unix_secs( $args['expires_at'] );
		if ( null === $generated || null === $expires || $expires <= $generated || $expires - $generated > self::MAX_LIFETIME ) {
			return null;
		}
		if ( ! in_array( $args['verdict'], array( '1', '2' ), true ) ) {
			return null;
		}

		$order = array(
			'id'            => $id,
			'type'          => $type,
			'verdict'       => (int) $args['verdict'],
			'generated_at'  => $generated,
			'expires_at'    => $expires,
			'runs'          => 0,
			'files_touched' => 0,
			'state'         => array(),
		);

		if ( Segurium_Remote_Actions::TYPE_REPLACE_FILE_24H === $type ) {
			$hex = '/\A[0-9a-f]{64}\z/';
			if ( ! Segurium_Remote_Actions::path_acceptable( $args['path'] )
				|| 1 !== preg_match( $hex, $args['source_sha256'] )
				|| 1 !== preg_match( $hex, $args['clean_sha256'] )
				|| $args['source_sha256'] === $args['clean_sha256'] ) {
				return null;
			}
			return $order + array(
				'path'          => $args['path'],
				'source_sha256' => $args['source_sha256'],
				'clean_sha256'  => $args['clean_sha256'],
			);
		}

		if ( '.' !== $args['folder'] && ! Segurium_Remote_Actions::path_acceptable( $args['folder'] ) ) {
			return null;
		}
		if ( isset( $args['glob'] ) ) {
			if ( ! self::name_acceptable( $args['glob'], '[]{}' ) || '' === str_replace( array( '*', '?' ), '', $args['glob'] ) ) {
				return null;
			}
			return $order + array(
				'folder' => $args['folder'],
				'glob'   => $args['glob'],
				'names'  => array(),
			);
		}

		$names = explode( '/', $args['names'] );
		foreach ( $names as $name ) {
			if ( ! self::name_acceptable( $name, '*?[]{}' ) ) {
				return null;
			}
		}
		if ( count( $names ) !== count( array_unique( $names ) ) ) {
			return null;
		}
		return $order + array(
			'folder' => $args['folder'],
			'glob'   => '',
			'names'  => $names,
		);
	}

	/**
	 * One file name: no separator, no control character, none of $denied.
	 *
	 * @param string $name   Candidate.
	 * @param string $denied Characters refused on top of the shared ones.
	 * @return bool
	 */
	private static function name_acceptable( string $name, string $denied ): bool {
		return '' !== $name
			&& strlen( $name ) <= self::MAX_NAME_LEN
			&& '.' !== $name
			&& '..' !== $name
			&& false === strpbrk( $name, '/\\' . $denied )
			&& 1 !== preg_match( '/[\x00-\x1f\x7f]/', $name );
	}

	/**
	 * Positive decimal seconds, no sign, no leading zero.
	 *
	 * @param string $value Candidate.
	 * @return int|null
	 */
	private static function unix_secs( string $value ): ?int {
		if ( '' === $value || strlen( $value ) > 11 || '0' === $value[0] || ! ctype_digit( $value ) ) {
			return null;
		}
		return (int) $value;
	}

	/**
	 * What an order acts on.
	 *
	 * @param array<string, mixed> $order Order.
	 * @return string
	 */
	private static function target_key( array $order ): string {
		if ( Segurium_Remote_Actions::TYPE_REPLACE_FILE_24H === $order['type'] ) {
			return 'replace:' . $order['path'];
		}
		return 'purge:' . $order['folder'] . '/' . ( '' !== $order['glob'] ? $order['glob'] : '{' . implode( '/', (array) $order['names'] ) . '}' );
	}

	/**
	 * Record a skip; reported only when it differs from the last one for the path.
	 *
	 * @param array<string, mixed> $order  Order, state updated in place.
	 * @param array<string, mixed> $plan   Plan, updated in place.
	 * @param string               $rel    Site-relative path.
	 * @param string               $reason Skip reason.
	 * @param string               $stamp  Fingerprint that makes the decision stale when it changes.
	 * @return void
	 */
	private static function skip_once( array &$order, array &$plan, string $rel, string $reason, string $stamp = '' ): void {
		$mark = '' === $stamp ? $reason : $reason . ':' . $stamp;
		if ( self::mark( $order, $rel ) === $mark ) {
			return;
		}
		$order['state']['marks'][ $rel ] = $mark;
		$plan['skipped'][]               = array(
			'path'   => $rel,
			'reason' => $reason,
		);
		$plan['loud']                    = true;
	}

	/**
	 * The decision last recorded for a path, or ''.
	 *
	 * @param array<string, mixed> $order Order.
	 * @param string               $rel   Site-relative path.
	 * @return string
	 */
	private static function mark( array $order, string $rel ): string {
		return isset( $order['state']['marks'][ $rel ] ) ? (string) $order['state']['marks'][ $rel ] : '';
	}

	/**
	 * Forget a recorded decision that no longer holds.
	 *
	 * @param array<string, mixed> $order  Order, state updated in place.
	 * @param string               $rel    Site-relative path.
	 * @param string               $reason Decision to forget.
	 * @return void
	 */
	private static function clear_mark( array &$order, string $rel, string $reason ): void {
		if ( self::mark( $order, $rel ) === $reason ) {
			unset( $order['state']['marks'][ $rel ] );
		}
	}

	/**
	 * Record a failure on a file.
	 *
	 * @param array<string, mixed> $plan Plan, updated in place.
	 * @param string               $rel  Site-relative path.
	 * @param string               $code Error code.
	 * @return void
	 */
	private static function error( array &$plan, string $rel, string $code ): void {
		$plan['errors'][] = array(
			'path' => $rel,
			'code' => $code,
		);
		$plan['loud']     = true;
	}

	/**
	 * Persist orders; no option row once none is left.
	 *
	 * @param array<string, array<string, mixed>> $orders Orders.
	 * @return void
	 */
	private static function save( array $orders ): void {
		if ( empty( $orders ) ) {
			Segurium_Storage::setting_delete( self::OPTION );
			return;
		}
		Segurium_Storage::setting_set( self::OPTION, $orders, true );
	}

	/**
	 * Send one `standing_order` event.
	 *
	 * @param array<string, mixed> $order  Order, or at least its id and type.
	 * @param string               $event  `received`, `run` or `expired`.
	 * @param array<string, mixed> $fields Event fields.
	 * @return array<string, mixed> The payload sent.
	 */
	private static function report( array $order, string $event, array $fields ): array {
		$payload = array_merge(
			array(
				'order_id'   => (string) ( $order['id'] ?? '' ),
				'order_type' => (string) ( $order['type'] ?? '' ),
				'event'      => $event,
				'at'         => time(),
			),
			$fields
		);
		Segurium_Storage::cti_send_message( self::MESSAGE_TYPE, $payload );
		return $payload;
	}
}

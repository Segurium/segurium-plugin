<?php
/**
 * Accounts hidden from WordPress's own user query, and the lock the
 * cloud can put on an account.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Detects hidden accounts, ties each to the code that hides it, and runs
 * the lock / unlock commands. The plugin never decides to lock.
 */
final class Segurium_Account_Lock {

	const OPTION_LOCKS     = 'segurium_account_locks';
	const OPTION_TRUSTED   = 'segurium_trusted_accounts';
	const OPTION_INSTALLER = 'segurium_installer_account';
	const MESSAGE_TYPE     = 'account_lock';
	const SCREEN_THROTTLE  = 'segurium_account_census_screen';

	const ACTOR_MANUAL = 'manual';
	const ACTOR_REMOTE = 'remote';
	const ACTOR_SYSTEM = 'system';

	const STATE_LOCKED   = 'locked';
	const STATE_RESTORED = 'restored';

	const REFUSE_BAD_ARGS       = 'bad_args';
	const REFUSE_AUTO_FIX_OFF   = 'auto_fix_off';
	const REFUSE_MULTISITE      = 'multisite';
	const REFUSE_USER_NOT_FOUND = 'user_not_found';
	const REFUSE_USER_MISMATCH  = 'user_mismatch';
	const REFUSE_INSTALLER      = 'installer';
	const REFUSE_LAST_ADMIN     = 'last_admin';
	const REFUSE_ALREADY_LOCKED = 'already_locked';
	const REFUSE_NOT_LOCKED     = 'not_locked';
	const REFUSE_LOCK_FAILED    = 'lock_failed';
	const REFUSE_RESTORE_FAILED = 'restore_failed';

	const MAX_HIDDEN      = 100;
	const MAX_HIDERS      = 20;
	const MAX_HIDER_BYTES = 5242880;

	const USER_QUERY_HOOKS = array(
		'pre_get_users',
		'pre_user_query',
		'users_pre_query',
		'found_users_query',
		'users_list_table_query_args',
		'pre_count_users',
		'views_users',
		'rest_user_query',
	);

	const PRIVILEGED_CAPS = array( 'manage_options', 'edit_plugins', 'edit_others_posts', 'edit_posts' );

	const ARG_KEYS = array( 'uid', 'uhash' );

	/**
	 * Wire the listeners.
	 */
	public static function register_hooks(): void {
		add_action( 'deleted_user', array( __CLASS__, 'on_user_deleted' ), 10, 1 );
		add_action( 'load-users.php', array( __CLASS__, 'on_users_screen' ) );
	}

	/**
	 * Drop every stored row, trust entry and the installer record.
	 */
	public static function reset_for_tests(): void {
		Segurium_Storage::setting_delete( self::OPTION_LOCKS );
		Segurium_Storage::setting_delete( self::OPTION_TRUSTED );
		Segurium_Storage::setting_delete( self::OPTION_INSTALLER );
		delete_transient( self::SCREEN_THROTTLE );
	}

	/**
	 * Malware often hides an account only on the Users screen, so the
	 * census also runs where the owner looks.
	 */
	public static function on_users_screen(): void {
		if ( get_transient( self::SCREEN_THROTTLE ) ) {
			return;
		}
		set_transient( self::SCREEN_THROTTLE, 1, 10 * MINUTE_IN_SECONDS );
		try {
			Segurium_Activity_Tracker::send_census();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-account-lock] census on users screen failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Accounts the users table holds that the plain user query or the
	 * Users screen query leaves out.
	 *
	 * @return array<int, array{uid:int, uhash:string, role:string, registered:int}>
	 */
	public static function hidden_accounts(): array {
		$out = array();
		foreach ( self::hidden_ids() as $uid ) {
			$user = get_userdata( $uid );
			if ( $user instanceof WP_User ) {
				$out[] = array(
					'uid'        => $uid,
					'uhash'      => self::login_hash( $user ),
					'role'       => self::first_role( $user ),
					'registered' => self::registered( $user ),
				);
			}
		}
		return $out;
	}

	/**
	 * User IDs both queries leave out.
	 *
	 * @return int[]
	 */
	private static function hidden_ids(): array {
		if ( is_multisite() ) {
			return array();
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the point is to bypass every user-query filter.
		$stored = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );
		$counts = array();
		foreach ( array( false, true ) as $as_screen ) {
			$query    = new WP_User_Query( self::query_args( $as_screen, array( 'number' => 1 ) ) );
			$counts[] = (int) $query->get_total();
		}
		if ( min( $counts ) >= $stored ) {
			return array();
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- same reason as the count above.
		$all = array_map( 'intval', (array) $wpdb->get_col( "SELECT ID FROM {$wpdb->users} ORDER BY ID" ) );
		return array_slice( array_values( array_diff( $all, self::visible_ids( array() ) ) ), 0, self::MAX_HIDDEN );
	}

	/**
	 * IDs both queries return, optionally limited to $only.
	 *
	 * @param int[] $only IDs to ask about, or none for every account.
	 * @return int[]
	 */
	private static function visible_ids( array $only ): array {
		$sets = array();
		foreach ( array( false, true ) as $as_screen ) {
			$probe = new WP_User_Query();
			// WP_User_Query ignores `exclude` once `include` is set, so the
			// narrowing folds `exclude` in after every other callback.
			$narrow = static function ( $query ) use ( $only, $probe ) {
				if ( $query !== $probe ) {
					return;
				}
				$theirs = wp_parse_id_list( $query->get( 'include' ) );
				$ids    = array_diff( empty( $theirs ) ? $only : array_intersect( $theirs, $only ), wp_parse_id_list( $query->get( 'exclude' ) ) );
				$query->set( 'include', empty( $ids ) ? array( 0 ) : array_values( $ids ) );
				$query->set( 'exclude', array() );
			};
			if ( ! empty( $only ) ) {
				// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core WP hook.
				add_action( 'pre_get_users', $narrow, PHP_INT_MAX );
			}
			try {
				$probe->prepare_query( self::query_args( $as_screen, array( 'number' => -1 ) ) );
				$probe->query();
			} finally {
				remove_action( 'pre_get_users', $narrow, PHP_INT_MAX );
			}
			$sets[] = array_map( 'intval', (array) $probe->get_results() );
		}
		return array_values( array_intersect( $sets[0], $sets[1] ) );
	}

	/**
	 * Arguments for one view: the plain query, or the one the Users
	 * screen builds after its own filter.
	 *
	 * @param bool                 $as_screen Run the Users screen filter.
	 * @param array<string, mixed> $extra     Fields forced after the filter.
	 * @return array<string, mixed>
	 */
	private static function query_args( bool $as_screen, array $extra ): array {
		$args = array(
			'number'  => 20,
			'offset'  => 0,
			'orderby' => 'login',
			'order'   => 'ASC',
		);
		if ( $as_screen ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core WP hook.
			$args = (array) apply_filters( 'users_list_table_query_args', $args );
		}
		return array_merge(
			$args,
			$extra,
			array(
				'fields'      => 'ID',
				'count_total' => true,
				'offset'      => 0,
				'paged'       => 1,
			)
		);
	}

	/**
	 * Third-party callbacks on the user-query hooks: the file each lives
	 * in, and the hidden accounts that reappear without it.
	 *
	 * @param int[]|null $hidden Hidden IDs when the caller has them.
	 * @return array<int, array{hook:string, origin:string, path:string, sha256:string, uids:int[]}>
	 */
	public static function hiders( ?array $hidden = null ): array {
		global $wp_filter;

		$hidden     = null === $hidden ? self::hidden_ids() : $hidden;
		$candidates = array();
		foreach ( self::USER_QUERY_HOOKS as $hook ) {
			if ( ! isset( $wp_filter[ $hook ] ) || ! $wp_filter[ $hook ] instanceof WP_Hook ) {
				continue;
			}
			foreach ( $wp_filter[ $hook ]->callbacks as $priority => $callbacks ) {
				foreach ( $callbacks as $callback ) {
					$entry = self::describe( $hook, $callback['function'] ?? null );
					if ( null !== $entry && count( $candidates ) < self::MAX_HIDERS ) {
						$candidates[] = array( $entry, $hook, $priority, $callback );
					}
				}
			}
		}

		$out = array();
		foreach ( $candidates as $candidate ) {
			list( $entry, $hook, $priority, $callback ) = $candidate;
			$entry['uids']                              = empty( $hidden ) ? array() : self::freed_by( $hook, $priority, $callback, $hidden );
			$out[]                                      = $entry;
		}
		return $out;
	}

	/**
	 * Hidden IDs that come back while one callback is off its hook.
	 *
	 * @param string               $hook     Hook name.
	 * @param int                  $priority Priority it was added at.
	 * @param array<string, mixed> $callback WP_Hook entry.
	 * @param int[]                $hidden   Hidden IDs.
	 * @return int[]
	 */
	private static function freed_by( string $hook, int $priority, array $callback, array $hidden ): array {
		remove_filter( $hook, $callback['function'], $priority );
		try {
			$freed = array_values( array_intersect( $hidden, self::visible_ids( $hidden ) ) );
		} finally {
			add_filter( $hook, $callback['function'], $priority, (int) ( $callback['accepted_args'] ?? 1 ) );
		}
		sort( $freed );
		return $freed;
	}

	/**
	 * Where one callback's code comes from, or null for core, Segurium
	 * and PHP built-ins.
	 *
	 * @param string $hook     Hook name.
	 * @param mixed  $callback Registered callback.
	 * @return array{hook:string, origin:string, path:string, sha256:string}|null
	 */
	private static function describe( string $hook, $callback ): ?array {
		try {
			if ( $callback instanceof Closure || ( is_string( $callback ) && false === strpos( $callback, '::' ) ) ) {
				$ref = new ReflectionFunction( $callback );
			} elseif ( is_string( $callback ) ) {
				list( $class, $method ) = explode( '::', $callback, 2 );
				$ref                    = new ReflectionMethod( $class, $method );
			} elseif ( is_array( $callback ) && 2 === count( $callback ) ) {
				$ref = new ReflectionMethod( $callback[0], (string) $callback[1] );
			} elseif ( is_object( $callback ) ) {
				$ref = new ReflectionMethod( $callback, '__invoke' );
			} else {
				return null;
			}
		} catch ( ReflectionException $e ) {
			return null;
		}

		$file = $ref->getFileName();
		if ( false === $file ) {
			return null;
		}
		$entry = array(
			'hook'   => $hook,
			'origin' => 'eval',
			'path'   => '',
			'sha256' => '',
		);
		if ( false !== strpos( $file, "eval()'d code" ) || false !== strpos( $file, 'runtime-created function' ) ) {
			return $entry;
		}

		$real = self::resolved( $file );
		foreach ( self::own_roots() as $root ) {
			if ( 0 === strpos( $real, $root ) ) {
				return null;
			}
		}
		$size            = is_file( $real ) ? (int) filesize( $real ) : 0;
		$entry['origin'] = 'file';
		$entry['path']   = self::relative( $real );
		$entry['sha256'] = $size > 0 && $size <= self::MAX_HIDER_BYTES ? (string) hash_file( 'sha256', $real ) : '';
		return $entry;
	}

	/**
	 * A path relative to the WordPress root, or '' outside it: the cloud
	 * fetches a hider by this path, and a guessed one names another file.
	 *
	 * @param string $real Resolved path.
	 * @return string
	 */
	private static function relative( string $real ): string {
		// phpcs:ignore -- segurium-wporg-abspath: the cloud matches the hiding file by its path relative to the WordPress root.
		$root = trailingslashit( self::resolved( ABSPATH ) );
		return 0 === strpos( $real, $root ) ? substr( $real, strlen( $root ) ) : '';
	}

	/**
	 * Folders whose callbacks are never reported.
	 *
	 * @return string[]
	 */
	private static function own_roots(): array {
		// phpcs:ignore -- segurium-wporg-abspath: core callbacks live under the WordPress root and are never reported.
		$abspath = trailingslashit( self::resolved( ABSPATH ) );
		$roots   = array( $abspath . WPINC . '/', $abspath . 'wp-admin/' );
		if ( defined( 'SEGURIUM_PLUGIN_DIR' ) ) {
			$roots[] = trailingslashit( self::resolved( SEGURIUM_PLUGIN_DIR ) );
		}
		return $roots;
	}

	/**
	 * Symlink-free, forward-slash path.
	 *
	 * @param string $path Any path.
	 * @return string
	 */
	private static function resolved( string $path ): string {
		$real = realpath( $path );
		return wp_normalize_path( false === $real ? $path : $real );
	}

	/**
	 * Account fields for the user census.
	 *
	 * @return array<string, mixed>
	 */
	public static function census_fields(): array {
		self::reconcile();
		$hidden = self::hidden_accounts();
		$locked = array();
		foreach ( self::load( self::OPTION_LOCKS ) as $uid => $row ) {
			if ( self::is_locked_row( $row ) ) {
				$locked[] = $uid;
			}
		}
		sort( $locked );
		$trusted = array_keys( self::load( self::OPTION_TRUSTED ) );
		sort( $trusted );

		return array(
			'hidden'    => $hidden,
			'hiders'    => empty( $hidden ) ? array() : self::hiders( array_column( $hidden, 'uid' ) ),
			'locked'    => $locked,
			'trusted'   => $trusted,
			'installer' => self::installer(),
		);
	}

	/**
	 * Remember the admin who activated Segurium while no live record exists.
	 */
	public static function record_installer(): void {
		$uid = (int) get_current_user_id();
		if ( $uid > 0 && 0 === self::installer() ) {
			self::store_installer( $uid );
		}
	}

	/**
	 * User ID of the account that activated Segurium, or 0.
	 *
	 * @return int
	 */
	public static function installer(): int {
		global $wpdb;
		$stored = Segurium_Storage::setting_get_array( self::OPTION_INSTALLER );
		if ( ! isset( $stored['uid'] ) ) {
			$uid    = (int) Segurium_Storage::table_get_var(
				'activity_log',
				'SELECT actor_user FROM {{table}} WHERE event_type = %s AND subject = %s AND data_json LIKE %s AND actor_user > 0 ORDER BY id ASC LIMIT 1',
				array( 'component_activated', self::own_slug(), '%' . $wpdb->esc_like( '"ct":"plugin"' ) . '%' )
			);
			$stored = self::store_installer( $uid );
		}
		$uid  = (int) $stored['uid'];
		$user = $uid > 0 ? get_userdata( $uid ) : false;
		return $user instanceof WP_User && self::registered( $user ) === (int) ( $stored['registered'] ?? -1 ) ? $uid : 0;
	}

	/**
	 * Persist the installer record.
	 *
	 * @param int $uid Account, or 0 for none.
	 * @return array{uid:int, registered:int}
	 */
	private static function store_installer( int $uid ): array {
		$user   = $uid > 0 ? get_userdata( $uid ) : false;
		$record = array(
			'uid'        => $user instanceof WP_User ? $uid : 0,
			'registered' => $user instanceof WP_User ? self::registered( $user ) : 0,
		);
		Segurium_Storage::setting_set( self::OPTION_INSTALLER, $record );
		return $record;
	}

	/**
	 * The slug the activity log records for Segurium's own activation.
	 *
	 * @return string
	 */
	private static function own_slug(): string {
		if ( ! defined( 'SEGURIUM_PLUGIN_FILE' ) ) {
			return 'segurium';
		}
		$file = plugin_basename( SEGURIUM_PLUGIN_FILE );
		$dir  = dirname( $file );
		return ( '.' === $dir || '' === $dir ) ? basename( $file, '.php' ) : $dir;
	}

	/**
	 * Decide whether a lock_user / unlock_user action may run.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string
	 */
	public static function evaluate( array $action ): string {
		if ( null === self::parse( $action ) ) {
			return self::REFUSE_BAD_ARGS;
		}
		if ( Segurium_Remote_Actions::TYPE_LOCK_USER === $action['type'] && ! Segurium_Auto_Fix_Settings::is_enabled() ) {
			return self::REFUSE_AUTO_FIX_OFF;
		}
		return Segurium_Remote_Actions::OK;
	}

	/**
	 * Run an evaluated lock_user / unlock_user action.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return string
	 */
	public static function execute( array $action ): string {
		$args = self::parse( $action );
		if ( null === $args ) {
			return self::REFUSE_BAD_ARGS;
		}
		if ( Segurium_Remote_Actions::TYPE_LOCK_USER === $action['type'] ) {
			return self::lock( $args['uid'], $args['uhash'], self::ACTOR_REMOTE );
		}
		return self::unlock( $args['uid'], $args['uhash'] );
	}

	/**
	 * The args of a lock_user / unlock_user action, or null.
	 *
	 * @param array<string, mixed> $action One entry from `actions[]`.
	 * @return array{uid:int, uhash:string}|null
	 */
	private static function parse( array $action ): ?array {
		$type = isset( $action['type'] ) ? (string) $action['type'] : '';
		$args = isset( $action['args'] ) && is_array( $action['args'] ) ? $action['args'] : array();
		if ( ! in_array( $type, array( Segurium_Remote_Actions::TYPE_LOCK_USER, Segurium_Remote_Actions::TYPE_UNLOCK_USER ), true )
			|| count( $args ) !== count( self::ARG_KEYS ) || array_diff( self::ARG_KEYS, array_keys( $args ) )
			|| ! is_string( $args['uid'] ) || ! is_string( $args['uhash'] )
			|| 1 !== preg_match( '/\A[1-9][0-9]{0,18}\z/', $args['uid'] ) || 1 !== preg_match( '/\A[0-9a-f]{64}\z/', $args['uhash'] ) ) {
			return null;
		}
		return array(
			'uid'   => (int) $args['uid'],
			'uhash' => $args['uhash'],
		);
	}

	/**
	 * Lock one account: no role, a random password, no application
	 * passwords, no sessions. The backup is stored before anything changes.
	 *
	 * @param int    $uid   Account.
	 * @param string $uhash SHA-256 of the login the caller expects.
	 * @param string $actor ACTOR_REMOTE or ACTOR_MANUAL.
	 * @return string
	 */
	public static function lock( int $uid, string $uhash, string $actor ): string {
		if ( is_multisite() ) {
			return self::REFUSE_MULTISITE;
		}
		$code = self::identify( $uid, $uhash );
		if ( Segurium_Remote_Actions::OK !== $code ) {
			return $code;
		}
		if ( self::installer() === $uid ) {
			return self::REFUSE_INSTALLER;
		}

		self::reconcile();
		$rows = self::load( self::OPTION_LOCKS );
		if ( isset( $rows[ $uid ] ) && self::is_locked_row( $rows[ $uid ] ) ) {
			return self::REFUSE_ALREADY_LOCKED;
		}
		if ( ! self::another_admin_remains( $uid, $rows ) ) {
			return self::REFUSE_LAST_ADMIN;
		}

		$user         = get_userdata( $uid );
		$app_key      = WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS;
		$rows[ $uid ] = array(
			'uid'        => $uid,
			'uhash'      => $uhash,
			'login'      => (string) $user->user_login,
			'registered' => self::registered( $user ),
			'state'      => self::STATE_LOCKED,
			'at'         => time(),
			'backup'     => $rows[ $uid ]['backup'] ?? array(
				'caps'  => get_user_meta( $uid, self::meta_key( 'capabilities' ), true ),
				'level' => get_user_meta( $uid, self::meta_key( 'user_level' ), true ),
				'pass'  => (string) $user->user_pass,
				'app'   => get_user_meta( $uid, $app_key, true ),
			),
			'wrote_pass' => '',
		);
		Segurium_Storage::setting_set( self::OPTION_LOCKS, $rows );
		if ( ! self::is_locked( $uid ) ) {
			return self::REFUSE_LOCK_FAILED;
		}

		$user->remove_all_caps();
		wp_set_password( wp_generate_password( 64, true, true ), $uid );
		delete_user_meta( $uid, $app_key );
		WP_Session_Tokens::get_instance( $uid )->destroy_all();

		$rows[ $uid ]['wrote_pass'] = self::stored_pass( $uid );
		Segurium_Storage::setting_set( self::OPTION_LOCKS, $rows );
		self::untrust( $uid );
		self::report( 'locked', $uid, $uhash, $actor );
		return Segurium_Remote_Actions::OK;
	}

	/**
	 * Undo a lock: give back each field that still holds what the lock
	 * wrote, then trust the account.
	 *
	 * @param int    $uid   Account.
	 * @param string $actor ACTOR_MANUAL or ACTOR_REMOTE.
	 * @return string
	 */
	public static function restore( int $uid, string $actor ): string {
		global $wpdb;
		self::reconcile();
		$rows = self::load( self::OPTION_LOCKS );
		if ( ! isset( $rows[ $uid ] ) || ! self::is_locked_row( $rows[ $uid ] ) ) {
			return self::REFUSE_NOT_LOCKED;
		}
		$row    = $rows[ $uid ];
		$backup = (array) $row['backup'];

		if ( ! self::has_role( $uid ) && ! empty( $backup['caps'] ) ) {
			update_user_meta( $uid, self::meta_key( 'capabilities' ), $backup['caps'] );
			if ( '' !== (string) ( $backup['level'] ?? '' ) ) {
				update_user_meta( $uid, self::meta_key( 'user_level' ), $backup['level'] );
			}
			if ( ! self::has_role( $uid ) ) {
				return self::REFUSE_RESTORE_FAILED;
			}
		}

		$pass    = (string) ( $backup['pass'] ?? '' );
		$current = self::stored_pass( $uid );
		if ( '' !== $pass && $pass !== $current && ( '' === $row['wrote_pass'] || hash_equals( (string) $row['wrote_pass'], $current ) ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- writes the stored hash back verbatim; wp_set_password() would hash it again.
			if ( false === $wpdb->update( $wpdb->users, array( 'user_pass' => $pass ), array( 'ID' => $uid ) ) ) {
				return self::REFUSE_RESTORE_FAILED;
			}
		}

		$app_key = WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS;
		if ( ! empty( $backup['app'] ) && empty( get_user_meta( $uid, $app_key, true ) ) && ! update_user_meta( $uid, $app_key, $backup['app'] ) ) {
			return self::REFUSE_RESTORE_FAILED;
		}
		clean_user_cache( $uid );

		$row['state']  = self::STATE_RESTORED;
		$row['at']     = time();
		$row['backup'] = null;
		$rows[ $uid ]  = $row;
		Segurium_Storage::setting_set( self::OPTION_LOCKS, $rows );
		self::trust( $uid );
		self::report( 'restored', $uid, (string) $row['uhash'], $actor );
		return Segurium_Remote_Actions::OK;
	}

	/**
	 * The cloud's unlock: restore when locked, and trust the account either way.
	 *
	 * @param int    $uid   Account.
	 * @param string $uhash SHA-256 of the login the caller expects.
	 * @return string
	 */
	private static function unlock( int $uid, string $uhash ): string {
		$code = self::identify( $uid, $uhash );
		if ( Segurium_Remote_Actions::OK !== $code ) {
			return $code;
		}
		$code = self::restore( $uid, self::ACTOR_REMOTE );
		if ( self::REFUSE_NOT_LOCKED === $code ) {
			self::trust( $uid );
		}
		return $code;
	}

	/**
	 * Check that the account exists and is the one the caller named.
	 *
	 * @param int    $uid   Account.
	 * @param string $uhash Expected login hash.
	 * @return string
	 */
	private static function identify( int $uid, string $uhash ): string {
		clean_user_cache( $uid );
		$user = get_userdata( $uid );
		if ( ! $user instanceof WP_User ) {
			return self::REFUSE_USER_NOT_FOUND;
		}
		return hash_equals( self::login_hash( $user ), $uhash ) ? Segurium_Remote_Actions::OK : self::REFUSE_USER_MISMATCH;
	}

	/**
	 * Whether an administrator WordPress shows stays unlocked once $uid is locked.
	 *
	 * @param int                              $uid  Account about to be locked.
	 * @param array<int, array<string, mixed>> $rows Stored rows.
	 * @return bool
	 */
	private static function another_admin_remains( int $uid, array $rows ): bool {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
				'number' => -1,
			)
		);
		foreach ( array_map( 'intval', $admins ) as $id ) {
			if ( $id !== $uid && ! ( isset( $rows[ $id ] ) && self::is_locked_row( $rows[ $id ] ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Match the rows to the accounts as they are now. A row whose account
	 * is gone or now belongs to someone else is dropped; a locked account
	 * that regained a role is marked Restored and keeps its backup, so a
	 * second lock still restores the original credentials.
	 */
	public static function reconcile(): void {
		$rows    = self::load( self::OPTION_LOCKS );
		$changed = false;
		foreach ( $rows as $uid => $row ) {
			$user = get_userdata( $uid );
			if ( ! $user instanceof WP_User || self::registered( $user ) !== (int) $row['registered'] ) {
				unset( $rows[ $uid ] );
				$changed = true;
				self::report( 'gone', $uid, (string) $row['uhash'], self::ACTOR_SYSTEM );
				continue;
			}
			if ( (string) $row['login'] !== (string) $user->user_login ) {
				$rows[ $uid ]['login'] = (string) $user->user_login;
				$changed               = true;
			}
			if ( self::is_locked_row( $row ) && self::has_role( $uid ) ) {
				$rows[ $uid ]['state'] = self::STATE_RESTORED;
				$rows[ $uid ]['at']    = time();
				$changed               = true;
				self::report( 'unlocked_elsewhere', $uid, self::login_hash( $user ), self::ACTOR_SYSTEM );
			}
		}
		if ( $changed ) {
			self::save( self::OPTION_LOCKS, $rows );
		}

		$trusted = self::load( self::OPTION_TRUSTED );
		$kept    = array();
		foreach ( $trusted as $uid => $entry ) {
			$user = get_userdata( $uid );
			if ( $user instanceof WP_User && self::registered( $user ) === (int) $entry['registered'] ) {
				$kept[ $uid ] = $entry;
			}
		}
		if ( count( $kept ) !== count( $trusted ) ) {
			self::save( self::OPTION_TRUSTED, $kept );
		}
	}

	/**
	 * Forget a deleted account.
	 *
	 * @param int $uid Deleted account.
	 */
	public static function on_user_deleted( $uid ): void {
		$uid  = (int) $uid;
		$rows = self::load( self::OPTION_LOCKS );
		if ( isset( $rows[ $uid ] ) ) {
			$uhash = (string) $rows[ $uid ]['uhash'];
			unset( $rows[ $uid ] );
			self::save( self::OPTION_LOCKS, $rows );
			self::report( 'gone', $uid, $uhash, self::ACTOR_MANUAL );
		}
		self::untrust( $uid );
	}

	/**
	 * Stored rows, newest change first.
	 *
	 * @param bool $recent_only Only rows changed inside the scanner's recent window.
	 * @return array<int, array{uid:int, login:string, state:string, at:int}>
	 */
	public static function rows( bool $recent_only ): array {
		$cutoff = $recent_only ? time() - Segurium_Server_State::RECENT_DAYS * DAY_IN_SECONDS : 0;
		$out    = array();
		foreach ( self::load( self::OPTION_LOCKS ) as $uid => $row ) {
			if ( (int) $row['at'] >= $cutoff ) {
				$out[] = array(
					'uid'   => $uid,
					'login' => (string) $row['login'],
					'state' => (string) $row['state'],
					'at'    => (int) $row['at'],
				);
			}
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return $b['at'] <=> $a['at'];
			}
		);
		return $out;
	}

	/**
	 * Whether the account is locked right now.
	 *
	 * @param int $uid Account.
	 * @return bool
	 */
	public static function is_locked( int $uid ): bool {
		$rows = self::load( self::OPTION_LOCKS );
		return isset( $rows[ $uid ] ) && self::is_locked_row( $rows[ $uid ] );
	}

	/**
	 * Whether the account is on the trusted list.
	 *
	 * @param int $uid Account.
	 * @return bool
	 */
	public static function is_trusted( int $uid ): bool {
		return isset( self::load( self::OPTION_TRUSTED )[ $uid ] );
	}

	/**
	 * AJAX: the Restore item of a locked-account row.
	 */
	public static function ajax_restore(): void {
		check_ajax_referer( 'segurium_cleanup', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			segurium_send_json_error( array( 'message' => __( 'Unauthorized', 'segurium' ) ), 403 );
		}
		$uid  = isset( $_POST['uid'] ) ? absint( wp_unslash( $_POST['uid'] ) ) : 0;
		$code = $uid > 0 ? self::restore( $uid, self::ACTOR_MANUAL ) : self::REFUSE_BAD_ARGS;
		if ( Segurium_Remote_Actions::OK === $code ) {
			segurium_send_json_success( array( 'state' => 'account_restored' ) );
		}
		segurium_send_json_error(
			array(
				'code'    => $code,
				'message' => __( 'Restore failed', 'segurium' ),
			)
		);
	}

	/**
	 * Whether a stored row is a live lock.
	 *
	 * @param array<string, mixed> $row Stored row.
	 * @return bool
	 */
	private static function is_locked_row( array $row ): bool {
		return self::STATE_LOCKED === $row['state'];
	}

	/**
	 * Whether the account has a role or a privileged capability again.
	 *
	 * @param int $uid Account.
	 * @return bool
	 */
	private static function has_role( int $uid ): bool {
		clean_user_cache( $uid );
		$user = get_userdata( $uid );
		if ( ! $user instanceof WP_User ) {
			return false;
		}
		if ( ! empty( $user->roles ) ) {
			return true;
		}
		foreach ( self::PRIVILEGED_CAPS as $cap ) {
			if ( ! empty( $user->caps[ $cap ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * One option as an array keyed by user ID.
	 *
	 * @param string $option OPTION_LOCKS or OPTION_TRUSTED.
	 * @return array<int, array<string, mixed>>
	 */
	private static function load( string $option ): array {
		$out = array();
		foreach ( Segurium_Storage::setting_get_array( $option ) as $uid => $row ) {
			if ( is_array( $row ) && isset( $row['registered'] ) ) {
				$out[ (int) $uid ] = $row;
			}
		}
		return $out;
	}

	/**
	 * Persist one option; it goes away with its last entry.
	 *
	 * @param string                           $option OPTION_LOCKS or OPTION_TRUSTED.
	 * @param array<int, array<string, mixed>> $rows   Entries keyed by user ID.
	 */
	private static function save( string $option, array $rows ): void {
		if ( empty( $rows ) ) {
			Segurium_Storage::setting_delete( $option );
			return;
		}
		Segurium_Storage::setting_set( $option, $rows );
	}

	/**
	 * Put an account on the trusted list.
	 *
	 * @param int $uid Account.
	 */
	private static function trust( int $uid ): void {
		$user = get_userdata( $uid );
		if ( $user instanceof WP_User ) {
			$trusted         = self::load( self::OPTION_TRUSTED );
			$trusted[ $uid ] = array(
				'registered' => self::registered( $user ),
				'at'         => time(),
			);
			self::save( self::OPTION_TRUSTED, $trusted );
		}
	}

	/**
	 * Take an account off the trusted list.
	 *
	 * @param int $uid Account.
	 */
	private static function untrust( int $uid ): void {
		$trusted = self::load( self::OPTION_TRUSTED );
		if ( isset( $trusted[ $uid ] ) ) {
			unset( $trusted[ $uid ] );
			self::save( self::OPTION_TRUSTED, $trusted );
		}
	}

	/**
	 * Tell the cloud an account changed state.
	 *
	 * @param string $event `locked`, `restored`, `unlocked_elsewhere` or `gone`.
	 * @param int    $uid   Account.
	 * @param string $uhash Login hash.
	 * @param string $actor ACTOR_MANUAL, ACTOR_REMOTE or ACTOR_SYSTEM.
	 */
	private static function report( string $event, int $uid, string $uhash, string $actor ): void {
		Segurium_Storage::cti_send_message(
			self::MESSAGE_TYPE,
			array(
				'event' => $event,
				'uid'   => $uid,
				'uhash' => $uhash,
				'actor' => $actor,
				'at'    => time(),
			)
		);
	}

	/**
	 * Password hash as stored, bypassing the user cache.
	 *
	 * @param int $uid Account.
	 * @return string
	 */
	private static function stored_pass( int $uid ): string {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- the cache may still hold the hash from before the write.
		return (string) $wpdb->get_var( $wpdb->prepare( "SELECT user_pass FROM {$wpdb->users} WHERE ID = %d", $uid ) );
	}

	/**
	 * Registration time, the second half of an account's identity.
	 *
	 * @param WP_User $user Account.
	 * @return int
	 */
	private static function registered( WP_User $user ): int {
		return (int) strtotime( (string) $user->user_registered . ' UTC' );
	}

	/**
	 * Login hash as the census sends it.
	 *
	 * @param WP_User $user Account.
	 * @return string
	 */
	private static function login_hash( WP_User $user ): string {
		return hash( 'sha256', (string) $user->user_login );
	}

	/**
	 * First role, or ''.
	 *
	 * @param WP_User $user Account.
	 * @return string
	 */
	private static function first_role( WP_User $user ): string {
		$roles = (array) $user->roles;
		return empty( $roles ) ? '' : (string) reset( $roles );
	}

	/**
	 * Usermeta key for this blog.
	 *
	 * @param string $name `capabilities` or `user_level`.
	 * @return string
	 */
	private static function meta_key( string $name ): string {
		global $wpdb;
		return $wpdb->get_blog_prefix() . $name;
	}
}

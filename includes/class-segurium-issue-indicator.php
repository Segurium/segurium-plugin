<?php
/**
 * Whether the site is carrying a security problem the user has not dealt
 * with yet, in a form cheap enough to read on every wp-admin page.
 *
 * Three signals, kept apart because each leads to its own tab or tooltip:
 *  - malware    open malware findings (Malware Scanner tab)
 *  - vulnerable installed components whose release the cloud flags
 *    (Integrity tab)
 *  - delisted   installed components removed from WordPress.org
 *    (Integrity tab)
 *
 * The answer is stored as one small option. The lightweight admin tier
 * renders the sidebar icon without loading any scan class, so it reads
 * the stored answer and never counts. Counting happens where the numbers
 * move: on the Segurium admin page, and at shutdown of any request that
 * changed a finding or wrote component metadata.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stored open-issue flags behind the admin attention markers.
 */
class Segurium_Issue_Indicator {

	const FLAG_OPTION = 'segurium_issue_flags';

	const SIGNAL_MALWARE    = 'malware';
	const SIGNAL_VULNERABLE = 'vulnerable';
	const SIGNAL_DELISTED   = 'delisted';

	const SIGNALS = array( self::SIGNAL_MALWARE, self::SIGNAL_VULNERABLE, self::SIGNAL_DELISTED );

	/**
	 * Whether a recount is already queued for this request.
	 *
	 * @var bool
	 */
	private static $queued = false;

	/**
	 * Count every signal, store the result, and return it.
	 *
	 * A storage failure yields a clean verdict rather than a mark nobody
	 * measured: an unexplained red dot on the sidebar is worse than a
	 * missing one, because the user has no tab to open to clear it.
	 *
	 * @return array{malware:bool,vulnerable:bool,delisted:bool}
	 */
	public static function recount() {
		if ( ! self::can_count() ) {
			return self::flags();
		}
		$components = self::count_escalated_components();
		$flags      = array(
			self::SIGNAL_MALWARE    => self::count_open_malware() > 0,
			self::SIGNAL_VULNERABLE => $components['vulnerable'] > 0,
			self::SIGNAL_DELISTED   => $components['delisted'] > 0,
		);
		self::store( $flags );
		return $flags;
	}

	/**
	 * Stored flags. Never queries a table.
	 *
	 * @return array{malware:bool,vulnerable:bool,delisted:bool}
	 */
	public static function flags() {
		$stored = class_exists( 'Segurium_Storage' )
			? Segurium_Storage::setting_get( self::FLAG_OPTION, array() )
			: array();
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		$flags = array();
		foreach ( self::SIGNALS as $signal ) {
			$flags[ $signal ] = ! empty( $stored[ $signal ] );
		}
		return $flags;
	}

	/**
	 * Visibility and tooltip of the Integrity tab mark.
	 *
	 * @param array $reasons Truthy `vulnerable` and `delisted` entries: stored flags or live counts.
	 * @return array{raised:bool,label:string}
	 */
	public static function integrity_mark( array $reasons ) {
		$vulnerable = ! empty( $reasons[ self::SIGNAL_VULNERABLE ] );
		$delisted   = ! empty( $reasons[ self::SIGNAL_DELISTED ] );
		return array(
			'raised' => $vulnerable || $delisted,
			'label'  => ( $delisted && ! $vulnerable )
				? __( 'Delisted from official WordPress.org', 'segurium' )
				: __( 'A vulnerable component is installed', 'segurium' ),
		);
	}

	/**
	 * Whether one named signal is raised.
	 *
	 * @param string $signal One of the SIGNAL_* constants.
	 * @return bool
	 */
	public static function has( $signal ) {
		$flags = self::flags();
		return ! empty( $flags[ $signal ] );
	}

	/**
	 * Whether any signal is raised.
	 *
	 * @return bool
	 */
	public static function has_any() {
		return in_array( true, self::flags(), true );
	}

	/**
	 * Queue one recount for the end of this request.
	 *
	 * Called from the write paths, which fire once per file during a scan.
	 * Deferring to shutdown collapses a thousand findings into a single
	 * pair of counts.
	 *
	 * @return void
	 */
	public static function mark_stale() {
		if ( self::$queued ) {
			return;
		}
		self::$queued = true;
		if ( function_exists( 'add_action' ) ) {
			add_action( 'shutdown', array( __CLASS__, 'recount' ), 99 );
			return;
		}
		self::recount();
	}

	/**
	 * Persist the flags for the tiers that cannot count.
	 *
	 * @param array $flags Flag map.
	 * @return void
	 */
	public static function store( array $flags ) {
		if ( ! class_exists( 'Segurium_Storage' ) ) {
			return;
		}
		$stored = array();
		foreach ( self::SIGNALS as $signal ) {
			$stored[ $signal ] = ! empty( $flags[ $signal ] ) ? 1 : 0;
		}
		Segurium_Storage::setting_set( self::FLAG_OPTION, $stored, true );
	}

	/**
	 * Whether this request loaded the classes both counts need.
	 *
	 * The lightweight admin tier loads this class so the sidebar icon can
	 * read the stored answer, and loads neither counter. Recounting there
	 * would measure nothing and store a clean verdict over a real one.
	 *
	 * @return bool
	 */
	private static function can_count() {
		return class_exists( 'Segurium_File_State' )
			&& class_exists( 'Segurium_Integrity_Server_State' );
	}

	/**
	 * Malicious files the user has not dealt with, over the recent window
	 * the scanner list opens on, so a mark never sends anyone to a tab
	 * that shows them an empty table.
	 *
	 * @return int
	 */
	private static function count_open_malware() {
		if ( ! class_exists( 'Segurium_File_State' ) ) {
			return 0;
		}
		try {
			$counts = Segurium_File_State::get_counts( true );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-issue-indicator] malware count failed: ' . $e->getMessage() );
			return 0;
		}
		return isset( $counts['malicious'] ) ? max( 0, (int) $counts['malicious'] ) : 0;
	}

	/**
	 * Vulnerable and delisted components still installed.
	 *
	 * @return array{vulnerable:int,delisted:int}
	 */
	private static function count_escalated_components() {
		$none = array(
			'vulnerable' => 0,
			'delisted'   => 0,
		);
		if ( ! class_exists( 'Segurium_Integrity_Server_State' ) ) {
			return $none;
		}
		try {
			$state = new Segurium_Integrity_Server_State();
			$state->load();
			return $state->count_escalated();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-issue-indicator] component count failed: ' . $e->getMessage() );
			return $none;
		}
	}
}

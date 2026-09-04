<?php
/**
 * Pending core / plugin / theme updates, read from WordPress' own update
 * transients.
 *
 * WordPress already refreshes `update_core`, `update_plugins` and
 * `update_themes` twice a day and every premium updater injects its offer
 * into the same transients. Reading them costs no HTTP request and covers
 * components the wp.org catalogue never sees.
 *
 * The cloud catalogue's `latest_version` stays a cross-check: it is the
 * current stable tag of a wp.org listing and knows nothing about branches
 * or third-party updaters.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reader and executor for pending component updates.
 */
class Segurium_Component_Updates {

	/**
	 * Slug the integrity inventory uses for the core component.
	 */
	const CORE_SLUG = 'WordPress';

	/** Package is served by wp.org. */
	const SOURCE_WPORG = 'wporg';

	/** Package is served by a third-party updater. */
	const SOURCE_EXTERNAL = 'external';

	/** No package URL on the offer at all. */
	const SOURCE_NONE = 'none';

	/**
	 * `message_type` for the record every update leaves. Named apart from
	 * the SOURCE_* constants above, which describe where the package comes
	 * from; TRIGGER_* below describe who asked for the update.
	 */
	const MSG_TYPE = 'component_update';

	/** The Integrity tab's Update button. */
	const TRIGGER_INTEGRITY_TAB = 'integrity_tab';

	/** The unattended remote-action channel. */
	const TRIGGER_REMOTE_ACTION = 'remote_action';

	/**
	 * Every pending update, keyed `{type}:{slug}`.
	 *
	 * Each entry carries:
	 *   - current_version   string  Version on disk right now.
	 *   - new_version       string  Version core would install.
	 *   - package_available bool    Offer names a downloadable package.
	 *   - source            string  wporg | external | none.
	 *   - major             bool    Installed and target majors differ.
	 *   - can_update        bool    This user may install it.
	 *
	 * mu-plugins and dropins never appear: WordPress reports no updates
	 * for them.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function available(): array {
		return array_merge( self::core_entry(), self::plugin_entries(), self::theme_entries() );
	}

	/**
	 * Whether the current user may install this kind of update. On multisite
	 * WordPress grants these to super admins only, so a subsite administrator
	 * sees the badge and no button.
	 *
	 * @param string $type Component type (core|plugin|theme).
	 * @return bool
	 */
	public static function user_can_update( string $type ): bool {
		$cap = self::capability_for( $type );
		return '' !== $cap && current_user_can( $cap );
	}

	/**
	 * One component's pending update, or an empty array.
	 *
	 * @param string $type Component type (core|plugin|theme).
	 * @param string $slug Component slug.
	 * @return array<string, mixed>
	 */
	public static function for_component( string $type, string $slug ): array {
		$map = self::available();
		return $map[ $type . ':' . $slug ] ?? array();
	}

	/**
	 * Whether moving between two versions crosses a major boundary.
	 *
	 * A version that does not start with `<integer>.` has no readable
	 * major — a date stamp, a single segment, a non-numeric prefix — and
	 * counts as a major bump, because guessing wrong here breaks a site.
	 *
	 * @param string $installed Installed version.
	 * @param string $target    Version core would install.
	 * @return bool
	 */
	public static function is_major_bump( string $installed, string $target ): bool {
		$a = self::major_of( $installed );
		$b = self::major_of( $target );
		if ( null === $a || null === $b ) {
			return true;
		}
		return $a !== $b;
	}

	/**
	 * Resolve a plugin slug to its `dir/file.php` entry.
	 *
	 * @param string $slug Plugin directory name.
	 * @return string Plugin file, or '' when not installed.
	 */
	public static function plugin_file_for_slug( string $slug ): string {
		if ( ! function_exists( 'get_plugins' ) ) {
			Segurium_Path_Helpers::wp_admin_include( 'plugin.php' );
		}
		foreach ( array_keys( get_plugins() ) as $file ) {
			if ( dirname( (string) $file ) === $slug ) {
				return (string) $file;
			}
		}
		return '';
	}

	/**
	 * The capability WordPress requires to install this update.
	 *
	 * On multisite these are super-admin-only, so a subsite administrator
	 * is refused here without a separate multisite branch.
	 *
	 * @param string $type Component type (core|plugin|theme).
	 * @return string Capability name, or '' for an unknown type.
	 */
	public static function capability_for( string $type ): string {
		switch ( $type ) {
			case 'core':
				return 'update_core';
			case 'plugin':
				return 'update_plugins';
			case 'theme':
				return 'update_themes';
		}
		return '';
	}

	/**
	 * Hand the update to core's own upgrader and report the attempt. The
	 * package URL comes from core's update transient, never from the caller.
	 *
	 * Every caller reports through here, so the record cannot drift from
	 * what was actually installed.
	 *
	 * @param string     $type    Component type (core|plugin|theme).
	 * @param string     $slug    Component slug.
	 * @param string     $trigger TRIGGER_* constant naming the surface that asked.
	 * @param array|null $offer   Offer the caller already read, to save a second
	 *                            walk of every plugin and theme. Must be this
	 *                            component's own, read before the upgrade.
	 * @return true|WP_Error True on success, the upgrader's own error otherwise.
	 */
	public static function apply( string $type, string $slug, string $trigger = '', ?array $offer = null ) {
		// The remote-action channel names core with an empty slug, because
		// core has none to give. The offer map keys it by CORE_SLUG, so
		// without this the lookups below miss and the row reports a core
		// update with no slug and no versions.
		if ( 'core' === $type ) {
			$slug = self::CORE_SLUG;
		}

		// Both reads have to happen before the upgrade: it clears the offer
		// it acted on, and it moves the component off the version this row
		// is meant to record.
		if ( null === $offer ) {
			$offer = self::for_component( $type, $slug );
		}
		$vulnerable = self::was_vulnerable( $type, $slug );

		$result = self::run_upgrader( $type, $slug );

		self::report( $type, $slug, $trigger, $offer, $vulnerable, $result );

		return $result;
	}

	/**
	 * Report one update attempt to the cloud.
	 *
	 * Core's `upgrader_process_complete` already feeds `component_updated`
	 * into the site-activity batch, but it fires on success only and names
	 * no origin, so a failed update leaves nothing and a successful one
	 * reads like a click on the wp-admin Plugins screen. This row answers
	 * both, and keeps the version the site moved off.
	 *
	 * @param string        $type       Component type.
	 * @param string        $slug       Component slug.
	 * @param string        $trigger    TRIGGER_* constant naming the surface.
	 * @param array         $offer      Pending offer as it stood before the upgrade.
	 * @param int           $vulnerable 1 when the row was flagged vulnerable.
	 * @param true|WP_Error $result     What the upgrader answered.
	 * @return void
	 */
	private static function report( string $type, string $slug, string $trigger, array $offer, int $vulnerable, $result ) {
		$failed = is_wp_error( $result );
		Segurium_Storage::cti_send_message(
			self::MSG_TYPE,
			array(
				'ct'             => $type,
				'slug'           => $slug,
				'from'           => (string) ( $offer['current_version'] ?? '' ),
				'to'             => (string) ( $offer['new_version'] ?? '' ),
				'source'         => $trigger,
				'pkg'            => (string) ( $offer['source'] ?? self::SOURCE_NONE ),
				'major'          => empty( $offer['major'] ) ? 0 : 1,
				'outcome'        => $failed ? 'failed' : 'updated',
				'error_code'     => $failed ? $result->get_error_code() : '',
				'was_vulnerable' => $vulnerable,
			)
		);
	}

	/**
	 * Whether the Integrity tab currently flags this component's release.
	 *
	 * Reads the stored metadata directly: `find_component()` would also
	 * load the component's file issues and re-read every update transient,
	 * which is a lot of work for one boolean.
	 *
	 * @param string $type Component type.
	 * @param string $slug Component slug.
	 * @return int 1 when flagged, 0 otherwise.
	 */
	private static function was_vulnerable( string $type, string $slug ): int {
		if ( ! class_exists( 'Segurium_Integrity_Server_State' ) ) {
			return 0;
		}
		$state = new Segurium_Integrity_Server_State();
		$state->load();
		return $state->is_vulnerable( $slug, $type ) ? 1 : 0;
	}

	/**
	 * Hand the component to WordPress' own upgrader.
	 *
	 * @param string $type Component type (core|plugin|theme).
	 * @param string $slug Component slug.
	 * @return true|WP_Error
	 */
	private static function run_upgrader( string $type, string $slug ) {
		Segurium_Path_Helpers::wp_admin_include( 'file.php' );
		Segurium_Path_Helpers::wp_admin_include( 'misc.php' );
		Segurium_Path_Helpers::wp_admin_include( 'class-wp-upgrader.php' );

		if ( ! class_exists( 'Automatic_Upgrader_Skin' ) ) {
			return new WP_Error( 'upgrader_unavailable', '' );
		}
		require_once SEGURIUM_PLUGIN_DIR . 'includes/class-segurium-upgrader-skin.php';

		$ob_level = ob_get_level();
		$skin     = new Segurium_Upgrader_Skin();
		$result   = false;

		try {
			if ( 'plugin' === $type ) {
				$file = self::plugin_file_for_slug( $slug );
				if ( '' === $file ) {
					return new WP_Error( 'component_not_installed', '' );
				}
				$upgrader = new Plugin_Upgrader( $skin );
				$result   = $upgrader->upgrade( $file );
			} elseif ( 'theme' === $type ) {
				$upgrader = new Theme_Upgrader( $skin );
				$result   = $upgrader->upgrade( $slug );
			} elseif ( 'core' === $type ) {
				$offer = self::core_offer();
				if ( null === $offer ) {
					return new WP_Error( 'no_update_pending', '' );
				}
				$upgrader = new Core_Upgrader( $skin );
				$result   = $upgrader->upgrade( $offer );
			} else {
				return new WP_Error( 'bad_component_type', '' );
			}
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] component update upgrader threw: ' . $e->getMessage() );
			return new WP_Error( 'upgrader_exception', '' );
		} finally {
			// The upgrader skin opens an output buffer and does not always
			// close it again on a failure path. Left open, it would swallow
			// whatever this request still had to emit.
			while ( ob_get_level() > $ob_level ) {
				ob_end_clean();
			}
		}

		if ( is_wp_error( $result ) ) {
			return $result;
		}
		if ( $skin->segurium_error instanceof WP_Error ) {
			return $skin->segurium_error;
		}
		// `WP_Upgrader::run()` returns its still-empty `$result` on an aborted
		// run, so an empty value is a failure and not a silent success. The
		// commonest cause is a host where WordPress cannot write directly and
		// holds no stored credentials; the skin never prompts for FTP, so say
		// so instead of reporting a bare failure.
		if ( empty( $result ) ) {
			return new WP_Error(
				'direct' === get_filesystem_method() ? 'upgrader_failed' : 'fs_credentials_required',
				''
			);
		}
		return true;
	}

	/**
	 * Ask WordPress to re-read its update offers.
	 *
	 * A successful upgrade clears the transient it touched, and an absent
	 * transient reads exactly like "nothing to update": every row would drop
	 * its Outdated badge and the tab would report a site full of pending
	 * updates as clean. Called after an update, never from a status poll.
	 *
	 * Each call is one request to api.wordpress.org, and each returns early
	 * when its transient is still fresh, so a plugin update costs one refresh
	 * and not three.
	 *
	 * @return void
	 */
	public static function refresh(): void {
		if ( function_exists( 'wp_update_plugins' ) ) {
			wp_update_plugins();
		}
		if ( function_exists( 'wp_update_themes' ) ) {
			wp_update_themes();
		}
		if ( function_exists( 'wp_version_check' ) ) {
			wp_version_check( array(), true );
		}
	}

	/**
	 * Core's pending offer, preferring the current branch over a major
	 * upgrade so a site on 6.4.2 is offered 6.4.3 and not 7.0.
	 *
	 * `get_core_updates()` drops every `autoupdate` entry, so the branch
	 * offer is read through core's own `find_core_auto_update()`.
	 *
	 * @return object|null
	 */
	private static function core_offer() {
		$updates = get_site_transient( 'update_core' );
		if ( ! is_object( $updates ) || empty( $updates->updates ) || ! is_array( $updates->updates ) ) {
			return null;
		}
		$dismissed = get_site_option( 'dismissed_update_core', array() );
		if ( ! is_array( $dismissed ) ) {
			$dismissed = array();
		}

		$branch  = null;
		$upgrade = null;
		foreach ( $updates->updates as $offer ) {
			if ( ! is_object( $offer ) ) {
				continue;
			}
			$current = (string) ( $offer->current ?? '' );
			if ( '' === $current ) {
				continue;
			}
			if ( isset( $dismissed[ $current . '|' . (string) ( $offer->locale ?? 'en_US' ) ] ) ) {
				continue;
			}
			$response = (string) ( $offer->response ?? '' );
			if ( 'autoupdate' === $response ) {
				// An autoupdate entry is the installed branch's own offer.
				// One that names a different branch is a major upgrade
				// wearing the wrong label, and the remote-action channel
				// gates core on the branch it approved.
				global $wp_version;
				if ( self::branch_of( $current ) !== self::branch_of( (string) $wp_version ) ) {
					continue;
				}
				if ( null === $branch || version_compare( $current, (string) $branch->current, '>' ) ) {
					$branch = $offer;
				}
			} elseif ( 'upgrade' === $response ) {
				if ( null === $upgrade || version_compare( $current, (string) $upgrade->current, '>' ) ) {
					$upgrade = $offer;
				}
			}
		}

		return $branch ? $branch : $upgrade;
	}

	/**
	 * Core's entry in the map, or an empty array.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function core_entry(): array {
		$offer = self::core_offer();
		if ( null === $offer ) {
			return array();
		}
		$target = (string) ( $offer->current ?? '' );
		if ( '' === $target ) {
			return array();
		}

		// A core offer names its zip in `download`, with `packages->full` as
		// the same URL. It has no `package` key at all — that one belongs to
		// the plugin and theme transients — so reading `package` here left
		// every site with an Outdated WordPress row and no Update button.
		$package = (string) ( $offer->download ?? '' );
		if ( '' === $package && isset( $offer->packages->full ) ) {
			$package = (string) $offer->packages->full;
		}

		global $wp_version;
		return array(
			'core:' . self::CORE_SLUG => self::entry(
				'core',
				(string) $wp_version,
				$target,
				$package
			),
		);
	}

	/**
	 * Plugin entries in the map.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function plugin_entries(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			Segurium_Path_Helpers::wp_admin_include( 'plugin.php' );
		}
		Segurium_Path_Helpers::wp_admin_include( 'update.php' );
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			return array();
		}

		$out = array();
		foreach ( (array) get_plugin_updates() as $file => $data ) {
			$update = is_object( $data ) ? ( $data->update ?? null ) : null;
			if ( empty( $update ) ) {
				continue;
			}
			// Integrity rows are keyed by directory, so a single-file
			// plugin has no row to badge.
			$slug = dirname( (string) $file );
			if ( '.' === $slug || '' === $slug ) {
				continue;
			}
			$new_version = (string) self::field( $update, 'new_version' );
			if ( '' === $new_version ) {
				continue;
			}
			$out[ 'plugin:' . $slug ] = self::entry(
				'plugin',
				(string) ( $data->Version ?? '' ), // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- WP plugin header key.
				$new_version,
				(string) self::field( $update, 'package' )
			);
		}
		return $out;
	}

	/**
	 * Theme entries in the map.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private static function theme_entries(): array {
		Segurium_Path_Helpers::wp_admin_include( 'update.php' );
		if ( ! function_exists( 'get_theme_updates' ) ) {
			return array();
		}

		$out = array();
		foreach ( (array) get_theme_updates() as $slug => $theme ) {
			$update = is_object( $theme ) ? ( $theme->update ?? null ) : null;
			if ( empty( $update ) ) {
				continue;
			}
			$new_version = (string) self::field( $update, 'new_version' );
			if ( '' === $new_version ) {
				continue;
			}
			$installed               = is_object( $theme ) && method_exists( $theme, 'get' )
				? (string) $theme->get( 'Version' )
				: '';
			$out[ 'theme:' . $slug ] = self::entry(
				'theme',
				$installed,
				$new_version,
				(string) self::field( $update, 'package' )
			);
		}
		return $out;
	}

	/**
	 * Shape one map entry.
	 *
	 * @param string $type        Component type (core|plugin|theme).
	 * @param string $installed   Installed version.
	 * @param string $new_version Version core would install.
	 * @param string $package     Package URL from the offer.
	 * @return array<string, mixed>
	 */
	private static function entry( string $type, string $installed, string $new_version, string $package ): array {
		return array(
			'current_version'   => $installed,
			'new_version'       => $new_version,
			'package_available' => '' !== $package,
			'source'            => self::source_of( $package ),
			'major'             => self::is_major_bump( $installed, $new_version ),
			'can_update'        => self::user_can_update( $type ),
		);
	}

	/**
	 * Read a field off an offer that core hands back as either an object
	 * or an array, depending on the transient's age and origin.
	 *
	 * @param object|array $update Offer entry.
	 * @param string       $key    Field name.
	 * @return mixed
	 */
	private static function field( $update, string $key ) {
		if ( is_object( $update ) ) {
			return $update->{$key} ?? '';
		}
		if ( is_array( $update ) ) {
			return $update[ $key ] ?? '';
		}
		return '';
	}

	/**
	 * Who serves the package.
	 *
	 * @param string $package Package URL.
	 * @return string
	 */
	private static function source_of( string $package ): string {
		if ( '' === $package ) {
			return self::SOURCE_NONE;
		}
		$parts = wp_parse_url( $package );
		if ( ! is_array( $parts ) ) {
			return self::SOURCE_EXTERNAL;
		}
		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
		$host   = strtolower( (string) ( $parts['host'] ?? '' ) );
		return ( 'https' === $scheme && 'downloads.wordpress.org' === $host )
			? self::SOURCE_WPORG
			: self::SOURCE_EXTERNAL;
	}

	/**
	 * Major and minor of a version, with any pre-release or build suffix
	 * dropped, so 6.9-RC1 and 6.9 share a branch. Empty when the string
	 * carries no leading number.
	 *
	 * @param string $version Version string.
	 * @return string
	 */
	private static function branch_of( string $version ): string {
		$numeric = (string) preg_replace( '/[^0-9.].*$/', '', trim( $version ) );
		if ( '' === $numeric || '.' === $numeric[0] ) {
			return '';
		}
		$parts = explode( '.', $numeric );
		return (int) $parts[0] . '.' . (int) ( $parts[1] ?? 0 );
	}

	/**
	 * Leading major component of a version, or null when the string does
	 * not start with `<integer>.`.
	 *
	 * @param string $version Version string.
	 * @return int|null
	 */
	private static function major_of( string $version ): ?int {
		if ( ! preg_match( '/^(\d+)\./', trim( $version ), $m ) ) {
			return null;
		}
		return (int) $m[1];
	}
}

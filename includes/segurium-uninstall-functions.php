<?php
/**
 * Functions used during plugin uninstallation.
 *
 * By default the encrypted backup envelopes are preserved across uninstall
 * so a reinstall can still restore components and cured files. Only when
 * the user opts in via the `segurium_uninstall_wipe_data` setting do we
 * wipe `backups/`. Tables and all Segurium options are always dropped so
 * a reinstall lands on clean schema.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Segurium_Debug and Segurium_Fs are hard dependencies of this file: the
// data-dir cleanup below calls Segurium_Fs directly (and via the storage
// tier). Load them unconditionally so a pre-defined Segurium_Storage can't
// cause the guarded block to skip them and fatal during uninstall.
if ( ! class_exists( 'Segurium_Debug' ) ) {
	require_once __DIR__ . '/class-segurium-debug.php';
}
if ( ! class_exists( 'Segurium_Fs' ) ) {
	require_once __DIR__ . '/class-segurium-fs.php';
}

// uninstall.php runs standalone — make sure storage classes are loaded.
if ( ! class_exists( 'Segurium_Storage' ) ) {
	require_once __DIR__ . '/storage/class-segurium-storage-exception.php';
	require_once __DIR__ . '/storage/class-segurium-ip.php';
	require_once __DIR__ . '/storage/class-segurium-storage-settings.php';
	require_once __DIR__ . '/storage/class-segurium-storage-schema-registry.php';
	require_once __DIR__ . '/storage/class-segurium-storage-tables.php';
	require_once __DIR__ . '/storage/class-segurium-storage-tables-query.php';
	require_once __DIR__ . '/storage/class-segurium-storage-fs.php';
	require_once __DIR__ . '/storage/class-segurium-storage-crypto.php';
	require_once __DIR__ . '/storage/class-segurium-storage-tmp.php';
	require_once __DIR__ . '/storage/class-segurium-storage-backup.php';
	require_once __DIR__ . '/storage/class-segurium-storage-ip-list.php';
	require_once __DIR__ . '/storage/class-segurium-storage-gc.php';
	require_once __DIR__ . '/storage/class-segurium-storage.php';
}

/**
 * Name of the setting that opts into a destructive uninstall.
 *
 * Default: absent/false → backups are preserved across uninstall.
 */
if ( ! defined( 'SEGURIUM_UNINSTALL_WIPE_OPTION' ) ) {
	define( 'SEGURIUM_UNINSTALL_WIPE_OPTION', 'segurium_uninstall_wipe_data' );
}

/**
 * Whether the user opted into wiping encrypted backups on uninstall. Falls
 * back to `get_option` if the storage façade can't boot — we must not fail
 * closed on a preserve-by-default semantic and accidentally delete data.
 */
function segurium_uninstall_should_wipe(): bool {
	if ( class_exists( 'Segurium_Storage' ) ) {
		return Segurium_Storage::setting_get_bool( SEGURIUM_UNINSTALL_WIPE_OPTION, false );
	}
	// phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
	return (bool) get_option( SEGURIUM_UNINSTALL_WIPE_OPTION, false );
}

/**
 * Recursively remove the plugin data directory.
 *
 * Always sweeps `tmp/` and un-bucketed junk. `backups/` is preserved unless
 * {@see segurium_uninstall_should_wipe()} is true, in which case we wipe
 * the entire data directory.
 *
 * @param string $dir Top-level segurium-data directory.
 */
function segurium_remove_data_dir( $dir ) {
	if ( class_exists( 'Segurium_Storage' ) ) {
		Segurium_Storage::boot();
		Segurium_Storage::tmp_gc( 0 );
	}

	if ( ! is_dir( $dir ) ) {
		return;
	}

	if ( segurium_uninstall_should_wipe() ) {
		if ( class_exists( 'Segurium_Storage' ) ) {
			Segurium_Storage::backup_gc();
		}
		Segurium_Storage_Fs::recursive_delete( $dir );
		return;
	}

	// Preserve backups/: remove every child except backups/.
	$handle = Segurium_Fs::opendir( $dir );
	if ( false === $handle ) {
		return;
	}
	while ( false !== ( $entry = readdir( $handle ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition
		if ( '.' === $entry || '..' === $entry || 'backups' === $entry ) {
			continue;
		}
		$path = $dir . '/' . $entry;
		if ( is_dir( $path ) && ! is_link( $path ) ) {
			Segurium_Storage_Fs::recursive_delete( $path );
		} else {
			Segurium_Fs::delete( $path );
		}
	}
	closedir( $handle );
}

/**
 * Delete all Segurium data from the database and stop every scheduled event.
 *
 * Always drops tables and Segurium options. The preserved `backups/` tree
 * is still decryptable after a reinstall because the backup key is fixed
 * in the plugin source.
 */
function segurium_delete_options() {
	$wipe = segurium_uninstall_should_wipe();

	if ( class_exists( 'Segurium_Storage' ) ) {
		Segurium_Storage::boot();
		Segurium_Storage::table_drop_all();
		Segurium_Storage::setting_delete_all();
	}

	foreach ( array( 'geo_blocking', 'firewall', 'brute_force' ) as $context ) {
		delete_option( 'segurium_pending_ctx_' . $context ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
	}

	if ( $wipe ) {
		delete_option( SEGURIUM_UNINSTALL_WIPE_OPTION ); // phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
	}

	if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
		wp_clear_scheduled_hook( 'segurium_scheduled_scan' );
		wp_clear_scheduled_hook( 'segurium_scan_worker_cron' );
		wp_clear_scheduled_hook( 'segurium_scan_lock_watchdog' );
		wp_clear_scheduled_hook( 'segurium_realtime_scan' );
		wp_clear_scheduled_hook( 'segurium_bf_prune' );
		wp_clear_scheduled_hook( 'segurium_trusted_proxies_update' );
		wp_clear_scheduled_hook( 'segurium_geo_updater' );
		if ( class_exists( 'Segurium_Storage_GC' ) ) {
			wp_clear_scheduled_hook( Segurium_Storage_GC::HOOK );
		}
	}
}

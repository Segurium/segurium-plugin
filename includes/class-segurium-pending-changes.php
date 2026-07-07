<?php
/**
 * Safe-change staging with auto-revert on timeout.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stages pending configuration changes with automatic revert via WP-Cron.
 */
class Segurium_Pending_Changes {

	const TRANSIENT_PREFIX = 'segurium_pending_';
	const CRON_HOOK        = 'segurium_pending_expire';
	const DEFAULT_TTL      = 60;

	/**
	 * Register WP-Cron hooks.
	 */
	public static function register_hooks() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'expire_pending' ) );
	}

	/**
	 * Stage a pending change. Applies the new value externally before calling this.
	 * Returns a token the frontend uses to confirm or revert.
	 *
	 * @param string $context   Unique identifier for the feature (e.g. 'geo_blocking').
	 * @param mixed  $old_value Previous value to restore on revert/timeout.
	 * @param mixed  $new_value New value that was just applied.
	 * @param int    $ttl       Seconds until auto-revert. Default 60.
	 * @return string Token.
	 */
	public static function stage( $context, $old_value, $new_value, $ttl = self::DEFAULT_TTL ) {
		$existing = Segurium_Storage::setting_get( 'segurium_pending_ctx_' . $context, '' );
		if ( $existing ) {
			self::cancel( $existing );
		}

		$token   = bin2hex( random_bytes( 16 ) );
		$expires = time() + $ttl;
		$data    = array(
			'context' => $context,
			'old'     => $old_value,
			'new'     => $new_value,
			'expires' => $expires,
		);

		set_transient( self::TRANSIENT_PREFIX . $token, $data, $ttl + 300 );
		Segurium_Storage::setting_set( 'segurium_pending_ctx_' . $context, $token );
		wp_schedule_single_event( $expires + 5, self::CRON_HOOK, array( $token ) );

		return $token;
	}

	/**
	 * Confirm a pending change. Deletes the transient; caller must persist the new value.
	 *
	 * @param string $token Pending change token.
	 * @return array|false Stored data or false if token not found.
	 */
	public static function confirm( $token ) {
		$data = get_transient( self::TRANSIENT_PREFIX . $token );
		if ( ! $data ) {
			return false;
		}
		delete_transient( self::TRANSIENT_PREFIX . $token );
		Segurium_Storage::setting_delete( 'segurium_pending_ctx_' . $data['context'] );
		wp_clear_scheduled_hook( self::CRON_HOOK, array( $token ) );
		return $data;
	}

	/**
	 * Revert a pending change. Caller must restore old value after receiving data.
	 *
	 * @param string $token Pending change token.
	 * @return array|false Stored data or false if token not found.
	 */
	public static function revert( $token ) {
		$data = get_transient( self::TRANSIENT_PREFIX . $token );
		if ( ! $data ) {
			return false;
		}
		delete_transient( self::TRANSIENT_PREFIX . $token );
		Segurium_Storage::setting_delete( 'segurium_pending_ctx_' . $data['context'] );
		wp_clear_scheduled_hook( self::CRON_HOOK, array( $token ) );
		return $data;
	}

	/**
	 * Get data for a pending token without consuming it.
	 *
	 * @param string $token Pending change token.
	 * @return array|null
	 */
	public static function get( $token ) {
		$data = get_transient( self::TRANSIENT_PREFIX . $token );
		return $data ? $data : null;
	}

	/**
	 * Get active pending data for a context, if any.
	 *
	 * @param string $context Feature context identifier.
	 * @return array|null
	 */
	public static function get_for_context( $context ) {
		$token = Segurium_Storage::setting_get( 'segurium_pending_ctx_' . $context, '' );
		if ( ! $token ) {
			return null;
		}
		return self::get( $token );
	}

	/**
	 * Cancel a pending change without firing revert action.
	 *
	 * @param string $token Pending change token.
	 */
	public static function cancel( $token ) {
		$data = get_transient( self::TRANSIENT_PREFIX . $token );
		if ( $data ) {
			Segurium_Storage::setting_delete( 'segurium_pending_ctx_' . $data['context'] );
		}
		delete_transient( self::TRANSIENT_PREFIX . $token );
		wp_clear_scheduled_hook( self::CRON_HOOK, array( $token ) );
	}

	/**
	 * Synchronous expiry check for a context, called on every request before blocking runs.
	 * If the pending change has expired, fires segurium_pending_revert immediately so the
	 * revert happens regardless of whether WP-Cron has had a chance to run.
	 *
	 * @param string $context Feature context identifier.
	 */
	public static function check_expired( $context ) {
		$token = Segurium_Storage::setting_get( 'segurium_pending_ctx_' . $context, '' );
		if ( ! $token ) {
			return;
		}
		$data = get_transient( self::TRANSIENT_PREFIX . $token );
		if ( ! $data ) {
			Segurium_Storage::setting_delete( 'segurium_pending_ctx_' . $context );
			return;
		}
		if ( time() < $data['expires'] ) {
			return;
		}
		do_action( 'segurium_pending_revert', $context, $data['old'], $token );
		delete_transient( self::TRANSIENT_PREFIX . $token );
		Segurium_Storage::setting_delete( 'segurium_pending_ctx_' . $context );
		wp_clear_scheduled_hook( self::CRON_HOOK, array( $token ) );
	}

	/**
	 * Called by WP-Cron. Fires segurium_pending_revert action if token has expired.
	 *
	 * @param string $token Pending change token.
	 */
	public static function expire_pending( $token ) {
		$data = get_transient( self::TRANSIENT_PREFIX . $token );
		if ( ! $data ) {
			return;
		}
		if ( time() < $data['expires'] ) {
			return;
		}
		do_action( 'segurium_pending_revert', $data['context'], $data['old'], $token );
		delete_transient( self::TRANSIENT_PREFIX . $token );
		Segurium_Storage::setting_delete( 'segurium_pending_ctx_' . $data['context'] );
	}
}

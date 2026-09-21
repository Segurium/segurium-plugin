<?php
/**
 * Two-Factor Authentication for Segurium.
 *
 * Provides TOTP (RFC 6238), email OTP, backup codes,
 * per-role enforcement with grace period, and trusted devices.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two-factor authentication handler.
 */
class Segurium_2FA {

	const SETTINGS_SLUG   = '2fa';
	const OPTION_SETTINGS = 'segurium_settings_2fa';
	const NONCE_ACTION    = 'segurium_2fa';

	const USER_META_SECRET  = '_segurium_2fa_secret';
	const USER_META_METHOD  = '_segurium_2fa_method';
	const USER_META_BACKUP  = '_segurium_2fa_backup';
	const USER_META_TRUSTED = '_segurium_2fa_trusted';
	const USER_META_SETUP   = '_segurium_2fa_setup_at';
	const USER_META_GRACE   = '_segurium_2fa_grace_start';

	const EMAIL_TRANSIENT        = 'segurium_2fa_email_';
	const PENDING_TRANSIENT      = 'segurium_2fa_pending_';
	const USER_ATTEMPT_TRANSIENT = 'segurium_2fa_user_attempts_';
	const USER_TOKENS_TRANSIENT  = 'segurium_2fa_user_tokens_';
	const SETUP_TRANSIENT        = 'segurium_2fa_setup_';

	const TOTP_WINDOW       = 1;
	const EMAIL_CODE_TTL    = 300;
	const BACKUP_CODE_COUNT = 10;
	const MAX_2FA_ATTEMPTS  = 5;

	/**
	 * Base32 alphabet (RFC 4648).
	 *
	 * @var string
	 */
	private static $base32_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private $settings = null;

	/**
	 * Whether hooks have been registered.
	 *
	 * @var bool
	 */
	private $hooks_registered = false;

	/**
	 * Get singleton instance.
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Read a value from an already-extracted source array (typically the
	 * nonce-verified caller's snapshot of $_POST).
	 *
	 * The helper does NOT touch $_POST itself — that is the caller's job,
	 * gated by check_ajax_referer() and the appropriate capability check
	 * inline in each handler. Centralising the type guard here
	 * just keeps "treat array values as missing" consistent across
	 * endpoints.
	 *
	 * @param array  $source   Caller-owned, already-unslashed input array.
	 * @param string $key      Key to read.
	 * @param mixed  $fallback Default value when the key is missing or array.
	 * @return mixed
	 */
	private static function post_value( array $source, $key, $fallback = '' ) {
		$value = isset( $source[ $key ] ) ? $source[ $key ] : $fallback;
		if ( is_array( $value ) ) {
			return $fallback;
		}
		if ( null === $value ) {
			return null;
		}
		return $value;
	}

	/**
	 * Read a boolean flag from an already-extracted source array.
	 *
	 * @param array  $source Caller-owned input array.
	 * @param string $key    Key to read.
	 * @return bool
	 */
	private static function post_bool( array $source, $key ) {
		$value = self::post_value( $source, $key, null );
		if ( null === $value ) {
			return false;
		}
		$value = strtolower( sanitize_text_field( (string) $value ) );
		return '' !== $value && ! in_array( $value, array( '0', 'false', 'no', 'off' ), true );
	}

	/**
	 * Default settings.
	 *
	 * @return array
	 */
	public static function default_settings() {
		return array(
			'enabled'             => false,
			'enforced_roles'      => array( 'administrator' ),
			'grace_period_days'   => 3,
			'trusted_device_days' => 30,
			'available_methods'   => array( 'totp', 'email' ),
			'email_code_length'   => 6,
		);
	}

	/**
	 * Get current settings merged with defaults.
	 *
	 * @return array
	 */
	public function get_settings() {
		if ( null !== $this->settings ) {
			return $this->settings;
		}
		$this->settings = Segurium_Settings::get( self::SETTINGS_SLUG );
		return $this->settings;
	}

	// =========================================================================
	// Base32 encode / decode (RFC 4648).
	// =========================================================================

	/**
	 * Base32-encode a raw binary string.
	 *
	 * @param string $data Raw bytes.
	 * @return string Base32-encoded string (no padding).
	 */
	public static function base32_encode( $data ) {
		$binary = '';
		for ( $i = 0, $len = strlen( $data ); $i < $len; $i++ ) {
			$binary .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		$encoded = '';
		for ( $i = 0, $blen = strlen( $binary ); $i < $blen; $i += 5 ) {
			$chunk = substr( $binary, $i, 5 );
			if ( strlen( $chunk ) < 5 ) {
				$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			}
			$encoded .= self::$base32_alphabet[ bindec( $chunk ) ];
		}

		return $encoded;
	}

	/**
	 * Base32-decode to raw binary.
	 *
	 * @param string $encoded Base32-encoded string.
	 * @return string|false Raw bytes or false on invalid input.
	 */
	public static function base32_decode( $encoded ) {
		$encoded = strtoupper( trim( $encoded ) );
		$encoded = rtrim( $encoded, '=' );

		if ( '' === $encoded ) {
			return '';
		}

		$binary = '';
		for ( $i = 0, $len = strlen( $encoded ); $i < $len; $i++ ) {
			$pos = strpos( self::$base32_alphabet, $encoded[ $i ] );
			if ( false === $pos ) {
				return false;
			}
			$binary .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}

		$result = '';
		for ( $i = 0, $blen = strlen( $binary ) - ( strlen( $binary ) % 8 ); $i < $blen; $i += 8 ) {
			$result .= chr( bindec( substr( $binary, $i, 8 ) ) );
		}

		return $result;
	}

	// =========================================================================
	// TOTP (RFC 6238).
	// =========================================================================

	/**
	 * Generate a random 160-bit TOTP secret, Base32-encoded.
	 *
	 * @return string 32-character Base32 string.
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Compute a TOTP code for the given secret and time.
	 *
	 * @param string   $secret Base32-encoded secret.
	 * @param int|null $time   Unix timestamp (defaults to now).
	 * @return string 6-digit zero-padded code.
	 */
	public static function totp_code( $secret, $time = null ) {
		if ( null === $time ) {
			$time = time();
		}

		$counter = intdiv( $time, 30 );
		$packed  = pack( 'NN', 0, $counter ); // 8 bytes big-endian.
		$key     = self::base32_decode( $secret );

		if ( false === $key || '' === $key ) {
			return '000000';
		}

		$hash   = hash_hmac( 'sha1', $packed, $key, true );
		$offset = ord( $hash[19] ) & 0x0F;
		$code   = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		) % 1000000;

		return str_pad( (string) $code, 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify a TOTP code, allowing +/- TOTP_WINDOW time steps.
	 *
	 * @param string $secret Base32-encoded secret.
	 * @param string $code   6-digit code to verify.
	 * @return bool True if valid.
	 */
	public static function verify_totp( $secret, $code ) {
		$code = trim( (string) $code );
		$now  = time();

		for ( $i = -self::TOTP_WINDOW; $i <= self::TOTP_WINDOW; $i++ ) {
			if ( hash_equals( self::totp_code( $secret, $now + $i * 30 ), $code ) ) {
				return true;
			}
		}

		return false;
	}

	// =========================================================================
	// Email OTP.
	// =========================================================================

	/**
	 * Generate a random email verification code.
	 *
	 * @param int $length Code length (default 6).
	 * @return int Numeric code.
	 */
	public static function generate_email_code( $length = 6 ) {
		$min = (int) pow( 10, $length - 1 );
		$max = (int) pow( 10, $length ) - 1;
		return wp_rand( $min, $max );
	}

	/**
	 * Hash an email code for transient storage.
	 *
	 * @param int|string $code Numeric code.
	 * @return string Hashed code.
	 */
	public static function hash_email_code( $code ) {
		return wp_hash( (string) $code );
	}

	/**
	 * Verify an email code against a stored hash.
	 *
	 * @param string     $stored_hash Hash from hash_email_code().
	 * @param int|string $code        Code to verify.
	 * @return bool True if valid.
	 */
	public static function verify_email_hash( $stored_hash, $code ) {
		return hash_equals( $stored_hash, wp_hash( (string) $code ) );
	}

	// =========================================================================
	// Backup codes.
	// =========================================================================

	/**
	 * Generate a set of single-use backup codes.
	 *
	 * @param int $count Number of codes (default 10).
	 * @return string[] Array of lowercase alphanumeric 8-character codes.
	 */
	public static function generate_backup_codes( $count = self::BACKUP_CODE_COUNT ) {
		$codes = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$codes[] = strtolower( wp_generate_password( 8, false ) );
		}
		return $codes;
	}

	/**
	 * Hash backup codes for storage.
	 *
	 * @param string[] $codes Plaintext codes.
	 * @return string[] Hashed codes.
	 */
	public static function hash_backup_codes( $codes ) {
		return array_map( 'wp_hash_password', $codes );
	}

	/**
	 * Verify a backup code against stored hashes.
	 *
	 * Returns the matching index so the caller can remove the used code,
	 * or false if no match.
	 *
	 * @param string   $code   Code to verify.
	 * @param string[] $hashes Array of hashed codes.
	 * @return int|false Index of the matching hash, or false.
	 */
	public static function verify_backup_code( $code, $hashes ) {
		$code = strtolower( trim( $code ) );

		foreach ( $hashes as $i => $hash ) {
			if ( wp_check_password( $code, $hash ) ) {
				return $i;
			}
		}

		return false;
	}

	/**
	 * Build an otpauth:// URI for TOTP provisioning.
	 *
	 * @param string $secret Base32-encoded secret.
	 * @param string $user_login WordPress username (used as account label).
	 * @return string otpauth:// URI.
	 */
	public static function build_otpauth_uri( $secret, $user_login ) {
		$site   = preg_replace( '~^https?://(?:www\.)?~i', '', home_url() );
		$issuer = rawurlencode( $site );
		$label  = rawurlencode( $site . ':' . $user_login );

		return sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
			$label,
			$secret,
			$issuer
		);
	}

	// =========================================================================
	// Settings management.
	// =========================================================================

	/**
	 * Validate and save 2FA settings.
	 *
	 * @param array $input Raw settings from POST.
	 * @return array Sanitized settings that were persisted.
	 */
	public function save_settings( $input ) {
		Segurium_Settings_Writer::save( self::SETTINGS_SLUG, $input );
		return $this->get_settings();
	}

	/**
	 * Post-write hook driven by the settings registry: refresh the cached
	 * copy and re-base the grace periods the new role set implies.
	 *
	 * @param array $applied Settings after the write.
	 * @param array $old     Settings before it.
	 * @return void
	 */
	public function on_settings_saved( $applied, $old ) {
		$this->settings = Segurium_Settings::get( self::SETTINGS_SLUG );
		$this->update_grace_periods_on_role_change( $old, $applied );
	}

	/**
	 * Reset grace periods when enforced roles change.
	 *
	 * @param array $old Previous settings.
	 * @param array $updated New settings.
	 * @return void
	 */
	private function update_grace_periods_on_role_change( $old, $updated ) {
		$old_roles = isset( $old['enforced_roles'] ) ? $old['enforced_roles'] : array();
		$new_roles = isset( $updated['enforced_roles'] ) ? $updated['enforced_roles'] : array();

		$newly_enforced = array_diff( $new_roles, $old_roles );
		$removed_roles  = array_diff( $old_roles, $new_roles );

		if ( empty( $newly_enforced ) && empty( $removed_roles ) ) {
			return;
		}

		// Set grace start for users in newly-enforced roles who don't have 2FA.
		foreach ( $newly_enforced as $role ) {
			$users = get_users(
				array(
					'role'   => $role,
					'fields' => 'ids',
				)
			);
			foreach ( $users as $uid ) {
				$method = get_user_meta( $uid, self::USER_META_METHOD, true );
				if ( empty( $method ) || 'none' === $method ) {
					update_user_meta( $uid, self::USER_META_GRACE, time() );
				}
			}
		}

		// Remove grace start for users in roles no longer enforced.
		foreach ( $removed_roles as $role ) {
			$users = get_users(
				array(
					'role'   => $role,
					'fields' => 'ids',
				)
			);
			foreach ( $users as $uid ) {
				delete_user_meta( $uid, self::USER_META_GRACE );
			}
		}
	}

	/**
	 * Validate and sanitize raw settings input.
	 *
	 * @param array $input Raw input.
	 * @return array Sanitized settings.
	 */
	public function validate_settings( $input ) {
		$defaults = self::default_settings();
		$input    = is_array( $input ) ? $input : array();
		$clean    = array();

		$clean['enabled'] = ! empty( $input['enabled'] );

		// Enforced roles: accept only valid registered WP roles.
		$clean['enforced_roles'] = array();
		if ( ! empty( $input['enforced_roles'] ) && is_array( $input['enforced_roles'] ) ) {
			$valid_roles = array_keys( wp_roles()->roles );
			foreach ( $input['enforced_roles'] as $role ) {
				$role = sanitize_text_field( $role );
				if ( in_array( $role, $valid_roles, true ) ) {
					$clean['enforced_roles'][] = $role;
				}
			}
		}

		$clean['grace_period_days']   = max( 0, min( 30, (int) ( $input['grace_period_days'] ?? $defaults['grace_period_days'] ) ) );
		$clean['trusted_device_days'] = max( 0, min( 365, (int) ( $input['trusted_device_days'] ?? $defaults['trusted_device_days'] ) ) );

		// Available methods: only 'totp' and 'email' are valid.
		$clean['available_methods'] = array();
		$allowed_methods            = array( 'totp', 'email' );
		if ( ! empty( $input['available_methods'] ) && is_array( $input['available_methods'] ) ) {
			foreach ( $input['available_methods'] as $method ) {
				$method = sanitize_text_field( $method );
				if ( in_array( $method, $allowed_methods, true ) ) {
					$clean['available_methods'][] = $method;
				}
			}
		}
		if ( empty( $clean['available_methods'] ) ) {
			$clean['available_methods'] = $defaults['available_methods'];
		}

		$length                     = (int) ( $input['email_code_length'] ?? 6 );
		$clean['email_code_length'] = in_array( $length, array( 6, 8 ), true ) ? $length : 6;

		return $clean;
	}

	// =========================================================================
	// Hook registration.
	// =========================================================================

	/**
	 * Register WordPress hooks for 2FA.
	 *
	 * @return void
	 */
	public function init() {
		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}
		if ( $this->hooks_registered ) {
			return;
		}
		$this->hooks_registered = true;

		add_filter( 'authenticate', array( $this, 'check_2fa' ), 99, 3 );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_scripts' ) );
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'admin_notices', array( $this, 'render_enforcement_notice' ) );
	}

	// =========================================================================
	// Authentication filter (priority 99 — after brute-force at 1, core at 20).
	// =========================================================================

	/**
	 * Intercept successful authentication to enforce 2FA.
	 *
	 * For AJAX requests (from segurium-2fa-login.js), return the user as-is
	 * so the AJAX handler can manage the 2FA challenge flow.
	 * For XML-RPC, verify the appended code inline.
	 * For standard form submissions (non-JS fallback), return WP_Error.
	 *
	 * @param WP_User|WP_Error|null $user     Auth result from earlier filters.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error Authenticated user or error.
	 */
	public function check_2fa( $user, $username, $password ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		// Let AJAX handler manage the 2FA flow.
		if ( wp_doing_ajax() ) {
			return $user;
		}

		$method = get_user_meta( $user->ID, self::USER_META_METHOD, true );

		// User has no 2FA configured.
		if ( empty( $method ) || 'none' === $method ) {
			return $this->handle_unenrolled_user( $user );
		}

		// Trusted device bypasses 2FA.
		if ( $this->is_trusted_device( $user->ID ) ) {
			return $user;
		}

		// XML-RPC: extract appended code from password.
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return $this->handle_xmlrpc_2fa( $user, $password );
		}

		// Standard form fallback (non-JS): block login.
		return new WP_Error(
			'segurium_2fa_required',
			__( 'Two-factor authentication is required. Please enable JavaScript to complete login.', 'segurium' )
		);
	}

	/**
	 * Handle an unenrolled user during authentication.
	 *
	 * @param WP_User $user WordPress user.
	 * @return WP_User|WP_Error User or error if enforcement is active and grace expired.
	 */
	private function handle_unenrolled_user( $user ) {
		if ( ! $this->is_enforced_for_user( $user ) ) {
			return $user;
		}
		if ( $this->in_grace_period( $user ) ) {
			return $user;
		}

		return new WP_Error(
			'segurium_2fa_setup_required',
			__( 'Two-factor authentication setup is required for your role. Please contact your administrator.', 'segurium' )
		);
	}

	/**
	 * Handle XML-RPC authentication with appended 2FA code.
	 *
	 * Wordfence-compatible pattern: the 2FA code is appended to the password.
	 * e.g. "mypassword123456" where 123456 is the TOTP code.
	 *
	 * @param WP_User $user     Authenticated user.
	 * @param string  $password Password that may contain an appended code.
	 * @return WP_User|WP_Error User on success, error on failure.
	 */
	private function handle_xmlrpc_2fa( $user, $password ) {
		$method = get_user_meta( $user->ID, self::USER_META_METHOD, true );

		// Try TOTP code (last 6 digits).
		if ( 'totp' === $method && preg_match( '/^.+?(\d{6})$/', $password, $m ) ) {
			$secret = $this->decrypt_user_secret( $user->ID );
			if ( $secret && self::verify_totp( $secret, $m[1] ) ) {
				return $user;
			}
		}

		// Try backup code (last 8 alphanumeric chars).
		if ( preg_match( '/^.+?([a-z0-9]{8})$/i', $password, $m ) ) {
			if ( $this->verify_and_consume_backup( $user->ID, $m[1] ) ) {
				return $user;
			}
		}

		// Try backup code for hex-format Wordfence imports (16 hex chars).
		if ( preg_match( '/^.+?([a-f0-9]{16})$/i', $password, $m ) ) {
			if ( $this->verify_and_consume_backup( $user->ID, $m[1] ) ) {
				return $user;
			}
		}

		return new WP_Error(
			'segurium_2fa_required',
			__( 'Two-factor authentication required. Append your 2FA code to your password.', 'segurium' )
		);
	}

	// =========================================================================
	// Trusted devices.
	// =========================================================================

	/**
	 * Set a trusted-device cookie for the user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return void
	 */
	public function set_trusted_device( $user_id ) {
		$token   = wp_generate_password( 32, false );
		$hash    = wp_hash( $token );
		$days    = $this->get_settings()['trusted_device_days'];
		$expires = time() + $days * DAY_IN_SECONDS;

		$devices   = json_decode( get_user_meta( $user_id, self::USER_META_TRUSTED, true ), true );
		$devices   = is_array( $devices ) ? $devices : array();
		$devices[] = array(
			'hash'    => $hash,
			'expires' => $expires,
		);

		// Prune expired devices.
		$now     = time();
		$devices = array_values(
			array_filter(
				$devices,
				function ( $d ) use ( $now ) {
					return $d['expires'] > $now;
				}
			)
		);

		update_user_meta( $user_id, self::USER_META_TRUSTED, wp_json_encode( $devices ) );

		setcookie(
			'segurium_2fa_trusted',
			$user_id . '|' . $token,
			$expires,
			COOKIEPATH,
			COOKIE_DOMAIN,
			is_ssl(),
			true
		);
	}

	/**
	 * Check if the current request comes from a trusted device.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if the device is trusted.
	 */
	public function is_trusted_device( $user_id ) {
		if ( empty( $_COOKIE['segurium_2fa_trusted'] ) ) {
			return false;
		}

		$parts = explode( '|', sanitize_text_field( wp_unslash( $_COOKIE['segurium_2fa_trusted'] ) ), 2 );
		if ( count( $parts ) !== 2 ) {
			return false;
		}

		$cookie_uid   = (int) $parts[0];
		$cookie_token = $parts[1];

		if ( $cookie_uid !== (int) $user_id ) {
			return false;
		}

		$devices = json_decode( get_user_meta( $user_id, self::USER_META_TRUSTED, true ), true );
		if ( ! is_array( $devices ) ) {
			return false;
		}

		$hash = wp_hash( $cookie_token );
		$now  = time();

		foreach ( $devices as $d ) {
			if ( isset( $d['hash'], $d['expires'] )
				&& hash_equals( $d['hash'], $hash )
				&& $d['expires'] > $now ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Revoke all trusted devices for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return void
	 */
	public function revoke_trusted_devices( $user_id ) {
		delete_user_meta( $user_id, self::USER_META_TRUSTED );
	}

	// =========================================================================
	// Enforcement & grace period.
	// =========================================================================

	/**
	 * Check if 2FA is enforced for a user based on their roles.
	 *
	 * @param WP_User $user WordPress user.
	 * @return bool True if any of the user's roles are in enforced_roles.
	 */
	public function is_enforced_for_user( $user ) {
		$settings = $this->get_settings();
		if ( empty( $settings['enforced_roles'] ) ) {
			return false;
		}
		foreach ( $user->roles as $role ) {
			if ( in_array( $role, $settings['enforced_roles'], true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if a user is still within the grace period.
	 *
	 * @param WP_User $user WordPress user.
	 * @return bool True if within grace period.
	 */
	public function in_grace_period( $user ) {
		$settings = $this->get_settings();
		$days     = (int) $settings['grace_period_days'];
		if ( $days <= 0 ) {
			return false;
		}

		$grace_start = (int) get_user_meta( $user->ID, self::USER_META_GRACE, true );
		if ( 0 === $grace_start ) {
			update_user_meta( $user->ID, self::USER_META_GRACE, time() );
			return true;
		}

		return ( time() - $grace_start ) < ( $days * DAY_IN_SECONDS );
	}

	/**
	 * Get remaining seconds in the grace period.
	 *
	 * @param WP_User $user WordPress user.
	 * @return int Remaining seconds (0 if expired).
	 */
	public function get_grace_remaining( $user ) {
		$settings    = $this->get_settings();
		$days        = (int) $settings['grace_period_days'];
		$grace_start = (int) get_user_meta( $user->ID, self::USER_META_GRACE, true );

		if ( 0 === $grace_start || $days <= 0 ) {
			return 0;
		}

		$remaining = ( $grace_start + $days * DAY_IN_SECONDS ) - time();
		return max( 0, $remaining );
	}

	// =========================================================================
	// Helper methods.
	// =========================================================================

	/**
	 * Record a freshly minted pending token in the user's active-token
	 * index. On lockout we can then wipe every outstanding token for
	 * that user, closing the farm-tokens-in-advance variant of the
	 * brute-force amplification.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $token   Pending token value.
	 * @return void
	 */
	private function track_pending_token( $user_id, $token ) {
		$key    = self::USER_TOKENS_TRANSIENT . $user_id;
		$tokens = get_transient( $key );
		if ( ! is_array( $tokens ) ) {
			$tokens = array();
		}
		$tokens[ $token ] = 1;
		set_transient( $key, $tokens, self::EMAIL_CODE_TTL );
	}

	/**
	 * Delete every outstanding pending token for a user, plus the
	 * index itself. Used on successful verify and on lockout.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return void
	 */
	private function invalidate_pending_tokens_for_user( $user_id ) {
		$key    = self::USER_TOKENS_TRANSIENT . $user_id;
		$tokens = get_transient( $key );
		if ( is_array( $tokens ) ) {
			foreach ( array_keys( $tokens ) as $token ) {
				delete_transient( self::PENDING_TRANSIENT . $token );
			}
		}
		delete_transient( $key );
	}

	/**
	 * Decrypt the user's stored TOTP secret.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string|false Base32-encoded secret or false.
	 */
	public function decrypt_user_secret( $user_id ) {
		$encrypted = get_user_meta( $user_id, self::USER_META_SECRET, true );
		if ( empty( $encrypted ) ) {
			return false;
		}
		return Segurium_2FA_Crypto::decrypt( $encrypted );
	}

	/**
	 * Verify a backup code and consume it if valid.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    Backup code to verify.
	 * @return bool True if valid (and consumed).
	 */
	public function verify_and_consume_backup( $user_id, $code ) {
		$stored = json_decode( get_user_meta( $user_id, self::USER_META_BACKUP, true ), true );
		if ( ! is_array( $stored ) || empty( $stored ) ) {
			return false;
		}

		$index = self::verify_backup_code( $code, $stored );
		if ( false === $index ) {
			return false;
		}

		unset( $stored[ $index ] );
		update_user_meta( $user_id, self::USER_META_BACKUP, wp_json_encode( array_values( $stored ) ) );
		return true;
	}

	/**
	 * Clear all 2FA data for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return void
	 */
	public function reset_user_2fa( $user_id ) {
		delete_user_meta( $user_id, self::USER_META_SECRET );
		delete_user_meta( $user_id, self::USER_META_METHOD );
		delete_user_meta( $user_id, self::USER_META_BACKUP );
		delete_user_meta( $user_id, self::USER_META_TRUSTED );
		delete_user_meta( $user_id, self::USER_META_SETUP );
		delete_user_meta( $user_id, self::USER_META_GRACE );
	}

	/**
	 * Get the count of remaining backup codes for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Number of remaining codes.
	 */
	public function get_backup_code_count( $user_id ) {
		$stored = json_decode( get_user_meta( $user_id, self::USER_META_BACKUP, true ), true );
		return is_array( $stored ) ? count( $stored ) : 0;
	}

	/**
	 * Import 2FA data from Wordfence Login Security.
	 *
	 * @param int    $user_id      WordPress user ID.
	 * @param string $raw_secret   Raw 20-byte TOTP secret from Wordfence.
	 * @param string $raw_recovery Raw concatenated recovery codes from Wordfence.
	 * @return bool True on success.
	 */
	public static function import_from_wordfence( $user_id, $raw_secret, $raw_recovery ) {
		if ( empty( $raw_secret ) ) {
			return false;
		}

		$base32_secret = self::base32_encode( $raw_secret );
		$encrypted     = Segurium_2FA_Crypto::encrypt( $base32_secret );
		if ( false === $encrypted ) {
			return false;
		}

		update_user_meta( $user_id, self::USER_META_SECRET, $encrypted );
		update_user_meta( $user_id, self::USER_META_METHOD, 'totp' );
		update_user_meta( $user_id, self::USER_META_SETUP, time() );

		// Parse Wordfence recovery codes: 8 bytes each, hex-encoded when displayed.
		if ( ! empty( $raw_recovery ) ) {
			$code_size = 8;
			$codes     = array();
			$len       = strlen( $raw_recovery );
			for ( $i = 0; $i + $code_size <= $len; $i += $code_size ) {
				$codes[] = bin2hex( substr( $raw_recovery, $i, $code_size ) );
			}
			if ( ! empty( $codes ) ) {
				$hashed = self::hash_backup_codes( $codes );
				update_user_meta( $user_id, self::USER_META_BACKUP, wp_json_encode( $hashed ) );
			}
		}

		return true;
	}

	/**
	 * Enqueue the 2FA login script on wp-login.php.
	 *
	 * @return void
	 */
	public function enqueue_login_scripts() {
		global $reauth;
		if ( ! empty( $reauth ) ) {
			// wp-login.php deletes the auth cookies on a reauth load, so the AJAX login arrives anonymous and without this session token.
			unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
			wp_set_current_user( 0 );
		}

		wp_enqueue_script(
			'segurium-ajax',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-ajax.js',
			array(),
			self::asset_version( 'assets/js/segurium-ajax.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-2fa-login',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-2fa-login.js',
			array( 'segurium-ajax' ),
			self::asset_version( 'assets/js/segurium-2fa-login.js' ),
			true
		);

		$settings = $this->get_settings();

		wp_localize_script(
			'segurium-2fa-login',
			'seguriumLogin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'segurium_2fa_login' ),
				'i18n'    => array(
					'verifying'       => __( 'Verifying...', 'segurium' ),
					'loggingIn'       => __( 'Logging in...', 'segurium' ),
					'enterTotp'       => __( 'Enter the code from your authenticator app:', 'segurium' ),
					'enterEmail'      => __( 'Enter the code sent to your email:', 'segurium' ),
					'verify'          => __( 'Verify', 'segurium' ),
					'resend'          => __( 'Resend code', 'segurium' ),
					'codeSent'        => __( 'A new code has been sent to your email.', 'segurium' ),
					'backupHint'      => __( 'Lost your device? Enter a backup code instead.', 'segurium' ),
					/* translators: %d: number of days */
					'trustDevice'     => sprintf( __( 'Trust this device for %d days', 'segurium' ), $settings['trusted_device_days'] ),
					'tooManyAttempts' => __( 'Too many failed attempts. Please try again later.', 'segurium' ),
					'setupRequired'   => __( 'Two-factor authentication setup is required for your role.', 'segurium' ),
				),
			)
		);
	}

	/**
	 * Render the 2FA section on the user profile page.
	 *
	 * @param WP_User $user User being edited.
	 * @return void
	 */
	public function render_profile_section( $user ) {
		$settings = $this->get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		$method       = get_user_meta( $user->ID, self::USER_META_METHOD, true );
		$backup_count = $this->get_backup_code_count( $user->ID );
		$enforced     = $this->is_enforced_for_user( $user );
		$can_edit     = ( get_current_user_id() === $user->ID || current_user_can( 'manage_options' ) );

		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication', 'segurium' ); ?></h2>
		<table class="form-table" role="presentation">
		<tr>
			<th><?php esc_html_e( 'Status', 'segurium' ); ?></th>
			<td>
				<div id="segurium-2fa-profile">
					<noscript><?php esc_html_e( 'JavaScript is required for 2FA setup.', 'segurium' ); ?></noscript>
				</div>
			</td>
		</tr>
		</table>
		<?php

		if ( ! $can_edit ) {
			return;
		}

		wp_enqueue_script(
			'segurium-ajax',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-ajax.js',
			array(),
			self::asset_version( 'assets/js/segurium-ajax.js' ),
			true
		);
		wp_enqueue_script(
			'segurium-2fa-profile',
			SEGURIUM_PLUGIN_URL . 'assets/js/segurium-2fa-profile.js',
			array( 'segurium-ajax' ),
			self::asset_version( 'assets/js/segurium-2fa-profile.js' ),
			true
		);

		wp_add_inline_script(
			'segurium-2fa-profile',
			'var segurium2faProfile = ' . wp_json_encode(
				array(
					'ajaxUrl'          => admin_url( 'admin-ajax.php' ),
					'nonce'            => wp_create_nonce( self::NONCE_ACTION ),
					'userId'           => $user->ID,
					'method'           => $method,
					'backupCount'      => $backup_count,
					'enforced'         => $enforced,
					'availableMethods' => $settings['available_methods'],
					'i18n'             => array(
						'notConfigured'    => __( 'Not configured', 'segurium' ),
						'setupTotp'        => __( 'Set up Authenticator App', 'segurium' ),
						'setupEmail'       => __( 'Set up Email Verification', 'segurium' ),
						'currentMethod'    => __( 'Current method:', 'segurium' ),
						'totp'             => __( 'Authenticator App (TOTP)', 'segurium' ),
						'email'            => __( 'Email Verification', 'segurium' ),
						'backupCodes'      => __( 'Backup codes remaining:', 'segurium' ),
						'regenerate'       => __( 'Regenerate Backup Codes', 'segurium' ),
						'disable'          => __( 'Disable 2FA', 'segurium' ),
						'scanQr'           => __( 'Scan this QR code with your authenticator app:', 'segurium' ),
						'manualEntry'      => __( 'Or enter this key manually:', 'segurium' ),
						'enterCode'        => __( 'Enter the 6-digit code from your app to confirm:', 'segurium' ),
						'confirm'          => __( 'Confirm', 'segurium' ),
						'cancel'           => __( 'Cancel', 'segurium' ),
						'saveBackupCodes'  => __( 'Save these backup codes in a safe place. They will not be shown again.', 'segurium' ),
						'setupComplete'    => __( '2FA has been set up successfully.', 'segurium' ),
						'disabled'         => __( '2FA has been disabled.', 'segurium' ),
						'codesRegenerated' => __( 'New backup codes generated.', 'segurium' ),
						'enterToVerify'    => __( 'Enter your current 2FA code to confirm:', 'segurium' ),
						'emailSent'        => __( 'A verification code has been sent to your email.', 'segurium' ),
						'enforced'         => __( 'Your administrator requires 2FA for your role.', 'segurium' ),
					),
				)
			),
			'before'
		);
	}

	/**
	 * Render enforcement admin notices for users who need to set up 2FA.
	 *
	 * @return void
	 */
	public function render_enforcement_notice() {
		$user = wp_get_current_user();
		if ( ! $this->is_enforced_for_user( $user ) ) {
			return;
		}

		$method = get_user_meta( $user->ID, self::USER_META_METHOD, true );
		if ( ! empty( $method ) && 'none' !== $method ) {
			return;
		}

		$profile_url = admin_url( 'profile.php#segurium-2fa' );

		if ( $this->in_grace_period( $user ) ) {
			$remaining = $this->get_grace_remaining( $user );
			$days      = (int) ceil( $remaining / DAY_IN_SECONDS );
			printf(
				'<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
				esc_html(
					sprintf(
						/* translators: %d: number of days remaining */
						__( 'Your administrator requires two-factor authentication. You have %d day(s) remaining to set it up.', 'segurium' ),
						$days
					)
				),
				esc_url( $profile_url ),
				esc_html__( 'Set up now', 'segurium' )
			);
		} else {
			printf(
				'<div class="notice notice-error"><p>%s <a href="%s">%s</a></p></div>',
				esc_html__( 'Two-factor authentication is required for your role. Please set it up immediately.', 'segurium' ),
				esc_url( $profile_url ),
				esc_html__( 'Set up now', 'segurium' )
			);
		}
	}

	/**
	 * Get file version for cache-busting.
	 *
	 * @param string $relative_path Path relative to SEGURIUM_PLUGIN_DIR.
	 * @return string File modification time or plugin version.
	 */
	private static function asset_version( $relative_path ) {
		$file = SEGURIUM_PLUGIN_DIR . $relative_path;
		if ( file_exists( $file ) ) {
			return (string) filemtime( $file );
		}
		return defined( 'SEGURIUM_VERSION' ) ? SEGURIUM_VERSION : '1.0.0';
	}

	/**
	 * Send an email OTP code to the user.
	 *
	 * @param WP_User $user User to send the code to.
	 * @return bool True if email was sent.
	 */
	public function send_email_code( $user ) {
		$settings = $this->get_settings();
		$length   = (int) $settings['email_code_length'];
		$code     = self::generate_email_code( $length );
		$key      = self::EMAIL_TRANSIENT . $user->ID;

		set_transient( $key, self::hash_email_code( $code ), self::EMAIL_CODE_TTL );

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] Your login verification code', 'segurium' ),
			get_bloginfo( 'name' )
		);

		$message = sprintf(
			/* translators: 1: verification code, 2: TTL in minutes */
			__( "Your verification code is: %1\$s\n\nThis code expires in %2\$d minutes.\n\nIf you did not request this, ignore this email.", 'segurium' ),
			$code,
			intdiv( self::EMAIL_CODE_TTL, 60 )
		);

		return wp_mail( $user->user_email, $subject, $message );
	}

	/**
	 * Verify a user's email OTP code.
	 *
	 * @param int        $user_id User ID.
	 * @param int|string $code    Code to verify.
	 * @return bool True if valid.
	 */
	public function verify_email_code( $user_id, $code ) {
		$key    = self::EMAIL_TRANSIENT . $user_id;
		$stored = get_transient( $key );

		if ( false === $stored ) {
			return false;
		}

		if ( self::verify_email_hash( $stored, $code ) ) {
			delete_transient( $key );
			return true;
		}

		return false;
	}

	// =========================================================================
	// AJAX endpoints (profile setup).
	// =========================================================================

	/**
	 * AJAX: Begin TOTP setup — generate secret and QR code.
	 *
	 * @return void
	 */
	public function ajax_setup_totp() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! is_user_logged_in() ) {
			segurium_send_json_error( array( 'message' => __( 'Not authenticated.', 'segurium' ) ), 403 );
		}
		if ( ! current_user_can( 'read' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
		}
		$user_id = get_current_user_id();

		$secret = self::generate_secret();
		set_transient( self::SETUP_TRANSIENT . $user_id, $secret, 600 );

		$user = wp_get_current_user();
		$uri  = self::build_otpauth_uri( $secret, $user->user_login );
		$svg  = Segurium_QR_SVG::generate( $uri );

		segurium_send_json_success(
			array(
				'secret' => $secret,
				'qr_svg' => $svg,
			)
		);
	}

	/**
	 * AJAX: Confirm TOTP setup with a test code.
	 *
	 * @return void
	 */
	public function ajax_confirm_totp() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! is_user_logged_in() ) {
			segurium_send_json_error( array( 'message' => __( 'Not authenticated.', 'segurium' ) ), 403 );
		}
		if ( ! current_user_can( 'read' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
		}
		$user_id = get_current_user_id();

		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';

		$secret = get_transient( self::SETUP_TRANSIENT . $user_id );
		if ( false === $secret ) {
			segurium_send_json_error( array( 'message' => __( 'Setup session expired. Please start again.', 'segurium' ) ) );
		}

		if ( ! self::verify_totp( $secret, $code ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid code. Please try again.', 'segurium' ) ) );
		}

		// Encrypt and save.
		$encrypted = Segurium_2FA_Crypto::encrypt( $secret );
		if ( false === $encrypted ) {
			segurium_send_json_error( array( 'message' => __( 'Encryption error.', 'segurium' ) ) );
		}

		update_user_meta( $user_id, self::USER_META_SECRET, $encrypted );
		update_user_meta( $user_id, self::USER_META_METHOD, 'totp' );
		update_user_meta( $user_id, self::USER_META_SETUP, time() );

		$backup_codes = self::generate_backup_codes();
		$hashed       = self::hash_backup_codes( $backup_codes );
		update_user_meta( $user_id, self::USER_META_BACKUP, wp_json_encode( $hashed ) );

		delete_transient( self::SETUP_TRANSIENT . $user_id );

		segurium_send_json_success(
			array(
				'backup_codes' => $backup_codes,
			)
		);
	}

	/**
	 * AJAX: Begin email 2FA setup — send test code.
	 *
	 * @return void
	 */
	public function ajax_setup_email() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! is_user_logged_in() ) {
			segurium_send_json_error( array( 'message' => __( 'Not authenticated.', 'segurium' ) ), 403 );
		}
		if ( ! current_user_can( 'read' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
		}
		$user = wp_get_current_user();

		$this->send_email_code( $user );

		segurium_send_json_success( array( 'message' => __( 'Verification code sent to your email.', 'segurium' ) ) );
	}

	/**
	 * AJAX: Confirm email 2FA setup with test code.
	 *
	 * @return void
	 */
	public function ajax_confirm_email() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! is_user_logged_in() ) {
			segurium_send_json_error( array( 'message' => __( 'Not authenticated.', 'segurium' ) ), 403 );
		}
		if ( ! current_user_can( 'read' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
		}
		$user_id = get_current_user_id();

		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';

		if ( ! $this->verify_email_code( $user_id, $code ) ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid code. Please try again.', 'segurium' ) ) );
		}

		update_user_meta( $user_id, self::USER_META_METHOD, 'email' );
		update_user_meta( $user_id, self::USER_META_SETUP, time() );

		$backup_codes = self::generate_backup_codes();
		$hashed       = self::hash_backup_codes( $backup_codes );
		update_user_meta( $user_id, self::USER_META_BACKUP, wp_json_encode( $hashed ) );

		segurium_send_json_success(
			array(
				'backup_codes' => $backup_codes,
			)
		);
	}

	/**
	 * AJAX: Disable 2FA for current user.
	 *
	 * @return void
	 */
	public function ajax_disable_2fa() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! is_user_logged_in() ) {
			segurium_send_json_error( array( 'message' => __( 'Not authenticated.', 'segurium' ) ), 403 );
		}
		if ( ! current_user_can( 'read' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
		}
		$user_id = get_current_user_id();
		$user    = wp_get_current_user();

		// Enforced users cannot disable.
		if ( $this->is_enforced_for_user( $user ) ) {
			segurium_send_json_error( array( 'message' => __( '2FA is required for your role and cannot be disabled.', 'segurium' ) ) );
		}

		// Require current code for confirmation.
		$code   = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$method = get_user_meta( $user_id, self::USER_META_METHOD, true );
		$valid  = false;

		if ( 'totp' === $method ) {
			$secret = $this->decrypt_user_secret( $user_id );
			if ( $secret ) {
				$valid = self::verify_totp( $secret, $code );
			}
		} elseif ( 'email' === $method ) {
			$valid = $this->verify_email_code( $user_id, $code );
		}

		if ( ! $valid ) {
			$valid = $this->verify_and_consume_backup( $user_id, $code );
		}

		if ( ! $valid ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid verification code.', 'segurium' ) ) );
		}

		$this->reset_user_2fa( $user_id );

		segurium_send_json_success( array( 'message' => __( '2FA has been disabled.', 'segurium' ) ) );
	}

	/**
	 * AJAX: Regenerate backup codes.
	 *
	 * @return void
	 */
	public function ajax_regenerate_backup() {
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );
		if ( ! is_user_logged_in() ) {
			segurium_send_json_error( array( 'message' => __( 'Not authenticated.', 'segurium' ) ), 403 );
		}
		if ( ! current_user_can( 'read' ) ) {
			segurium_send_json_error(
				array(
					'code'    => 'insufficient_permissions',
					'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
				),
				403
			);
		}
		$user_id = get_current_user_id();

		// Require current code.
		$code   = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$method = get_user_meta( $user_id, self::USER_META_METHOD, true );
		$valid  = false;

		if ( 'totp' === $method ) {
			$secret = $this->decrypt_user_secret( $user_id );
			if ( $secret ) {
				$valid = self::verify_totp( $secret, $code );
			}
		} elseif ( 'email' === $method ) {
			$valid = $this->verify_email_code( $user_id, $code );
		}

		if ( ! $valid ) {
			$valid = $this->verify_and_consume_backup( $user_id, $code );
		}

		if ( ! $valid ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid verification code.', 'segurium' ) ) );
		}

		$backup_codes = self::generate_backup_codes();
		$hashed       = self::hash_backup_codes( $backup_codes );
		update_user_meta( $user_id, self::USER_META_BACKUP, wp_json_encode( $hashed ) );

		segurium_send_json_success(
			array(
				'backup_codes' => $backup_codes,
			)
		);
	}

	// =========================================================================
	// AJAX endpoints (login flow).
	// =========================================================================

	/**
	 * AJAX: Authenticate user credentials and determine 2FA requirement.
	 *
	 * @return void
	 */
	public function ajax_authenticate() {
		check_ajax_referer( 'segurium_2fa_login', 'nonce' );
		if ( is_user_logged_in() ) {
			if ( ! current_user_can( 'read' ) ) {
				segurium_send_json_error(
					array(
						'code'    => 'insufficient_permissions',
						'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
					),
					403
				);
			}
		}

		$post = wp_unslash( $_POST );
		if ( ! is_array( $post ) ) {
			$post = array();
		}

		$username = sanitize_user( (string) self::post_value( $post, 'log' ) );
		$password = (string) self::post_value( $post, 'pwd' );
		$remember = self::post_bool( $post, 'rememberme' );

		if ( '' === $username || '' === $password ) {
			segurium_send_json_error( array( 'message' => __( 'Please enter your username and password.', 'segurium' ) ) );
		}

		// This endpoint validates credentials outside
		// wp-login.php, so brute-force protection cannot see it through the
		// `authenticate` filter or `wp_login_failed` — both bail on
		// `is_login_surface()`. Gate and count here instead, otherwise the
		// endpoint is an unthrottled password oracle that also ignores
		// lockouts earned on the normal login form.
		$brute_force = Segurium_Brute_Force::get_instance();

		$lockout = $brute_force->lockout_error_for_request();
		if ( is_wp_error( $lockout ) ) {
			segurium_send_json_error(
				array(
					'code'    => $lockout->get_error_code(),
					'message' => $lockout->get_error_message(),
					'locked'  => true,
				),
				403
			);
		}

		$user = wp_authenticate( $username, $password );

		if ( is_wp_error( $user ) ) {
			$brute_force->record_failed_attempt( $username );
			segurium_send_json_error( array( 'message' => $user->get_error_message() ) );
		}

		$method = get_user_meta( $user->ID, self::USER_META_METHOD, true );

		// No 2FA configured.
		if ( empty( $method ) || 'none' === $method ) {
			// Check enforcement.
			if ( $this->is_enforced_for_user( $user ) && ! $this->in_grace_period( $user ) ) {
				segurium_send_json_success(
					array(
						'setup_required' => true,
						'profile_url'    => admin_url( 'profile.php#segurium-2fa' ),
					)
				);
			}

			// No 2FA needed — complete login.
			wp_set_current_user( $user->ID );
			wp_set_auth_cookie( $user->ID, $remember );
			do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- re-firing core WP hook after 2FA success

			segurium_send_json_success(
				array(
					'login'    => true,
					'redirect' => admin_url(),
				)
			);
		}

		// Trusted device check.
		if ( $this->is_trusted_device( $user->ID ) ) {
			wp_set_current_user( $user->ID );
			wp_set_auth_cookie( $user->ID, $remember );
			do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- re-firing core WP hook after 2FA success

			segurium_send_json_success(
				array(
					'login'    => true,
					'redirect' => admin_url(),
				)
			);
		}

		// 2FA required — refuse to mint a token if the user is already
		// in the 2FA lockout window, otherwise an attacker can keep
		// farming tokens to burn guesses beyond the per-user budget.
		if ( (int) get_transient( self::USER_ATTEMPT_TRANSIENT . $user->ID ) >= self::MAX_2FA_ATTEMPTS ) {
			segurium_send_json_error(
				array(
					'message' => __( 'Too many failed attempts. Please try again later.', 'segurium' ),
					'locked'  => true,
				)
			);
		}

		// 2FA required — create pending token and index it on the user so
		// we can invalidate every outstanding token on lockout.
		$token = wp_generate_password( 32, false );
		set_transient( self::PENDING_TRANSIENT . $token, $user->ID, self::EMAIL_CODE_TTL );
		$this->track_pending_token( $user->ID, $token );

		if ( 'email' === $method ) {
			$this->send_email_code( $user );
		}

		$settings = $this->get_settings();

		segurium_send_json_success(
			array(
				'two_factor_required' => true,
				'method'              => $method,
				'token'               => $token,
				'trusted_days'        => (int) $settings['trusted_device_days'],
			)
		);
	}

	/**
	 * AJAX: Verify a 2FA code.
	 *
	 * @return void
	 */
	public function ajax_verify() {
		check_ajax_referer( 'segurium_2fa_login', 'nonce' );
		if ( is_user_logged_in() ) {
			if ( ! current_user_can( 'read' ) ) {
				segurium_send_json_error(
					array(
						'code'    => 'insufficient_permissions',
						'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
					),
					403
				);
			}
		}

		$post = wp_unslash( $_POST );
		if ( ! is_array( $post ) ) {
			$post = array();
		}

		$token    = sanitize_text_field( (string) self::post_value( $post, 'token' ) );
		$code     = sanitize_text_field( (string) self::post_value( $post, 'code' ) );
		$trust    = '1' === sanitize_text_field( (string) self::post_value( $post, 'trust' ) );
		$remember = self::post_bool( $post, 'rememberme' );

		$user_id = get_transient( self::PENDING_TRANSIENT . $token );
		if ( false === $user_id ) {
			segurium_send_json_error( array( 'message' => __( 'Session expired. Please log in again.', 'segurium' ) ) );
		}

		$user_id = (int) $user_id;
		$user    = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid session.', 'segurium' ) ) );
		}

		// Attempt counter is keyed on the user, not the token, so an
		// attacker cannot farm fresh tokens to reset the budget.
		$attempt_key = self::USER_ATTEMPT_TRANSIENT . $user_id;
		$attempts    = (int) get_transient( $attempt_key );

		if ( $attempts >= self::MAX_2FA_ATTEMPTS ) {
			$this->invalidate_pending_tokens_for_user( $user_id );

			segurium_send_json_error(
				array(
					'message' => __( 'Too many failed attempts. Please try again later.', 'segurium' ),
					'locked'  => true,
				)
			);
		}

		// Verify code.
		$valid  = false;
		$method = get_user_meta( $user_id, self::USER_META_METHOD, true );

		if ( 'totp' === $method ) {
			$secret = $this->decrypt_user_secret( $user_id );
			if ( $secret ) {
				$valid = self::verify_totp( $secret, $code );
			}
		} elseif ( 'email' === $method ) {
			$valid = $this->verify_email_code( $user_id, $code );
		}

		// Try backup code if primary failed.
		if ( ! $valid ) {
			$valid = $this->verify_and_consume_backup( $user_id, $code );
		}

		if ( $valid ) {
			$this->invalidate_pending_tokens_for_user( $user_id );
			delete_transient( $attempt_key );

			if ( $trust ) {
				$this->set_trusted_device( $user_id );
			}

			wp_set_current_user( $user_id );
			wp_set_auth_cookie( $user_id, $remember );
			do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- re-firing core WP hook after 2FA success

			segurium_send_json_success(
				array(
					'login'    => true,
					'redirect' => admin_url(),
				)
			);
		}

		// Invalid code — increment the per-user counter and feed one
		// brute-force event per failed code so the IP
		// lockout isn't amplified 5× by the per-token batch.
		++$attempts;
		set_transient( $attempt_key, $attempts, self::EMAIL_CODE_TTL );

		$bf = Segurium_Brute_Force::get_instance();
		$bf->record_2fa_failure( $bf->get_real_ip(), $user->user_login );

		if ( $attempts >= self::MAX_2FA_ATTEMPTS ) {
			$this->invalidate_pending_tokens_for_user( $user_id );

			segurium_send_json_error(
				array(
					'message' => __( 'Too many failed attempts. Please try again later.', 'segurium' ),
					'locked'  => true,
				)
			);
		}

		$remaining = self::MAX_2FA_ATTEMPTS - $attempts;
		segurium_send_json_error(
			array(
				'message'            => __( 'Invalid verification code. Please try again.', 'segurium' ),
				'attempts_remaining' => max( 0, $remaining ),
			)
		);
	}

	/**
	 * AJAX: Resend the email verification code.
	 *
	 * @return void
	 */
	public function ajax_resend_email() {
		check_ajax_referer( 'segurium_2fa_login', 'nonce' );
		if ( is_user_logged_in() ) {
			if ( ! current_user_can( 'read' ) ) {
				segurium_send_json_error(
					array(
						'code'    => 'insufficient_permissions',
						'message' => __( 'You do not have permission to perform this action.', 'segurium' ),
					),
					403
				);
			}
		}

		$token   = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		$user_id = get_transient( self::PENDING_TRANSIENT . $token );
		if ( false === $user_id ) {
			segurium_send_json_error( array( 'message' => __( 'Session expired.', 'segurium' ) ) );
		}

		$user = get_user_by( 'id', (int) $user_id );
		if ( ! $user ) {
			segurium_send_json_error( array( 'message' => __( 'Invalid session.', 'segurium' ) ) );
		}

		$this->send_email_code( $user );

		segurium_send_json_success( array( 'message' => __( 'Code sent.', 'segurium' ) ) );
	}
}

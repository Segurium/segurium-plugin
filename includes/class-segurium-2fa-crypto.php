<?php
/**
 * AES-256-GCM encryption helpers for 2FA TOTP secrets.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encrypts and decrypts TOTP secrets at rest using AES-256-GCM.
 *
 * Key is derived from the site's AUTH_KEY and SECURE_AUTH_KEY constants
 * so secrets are bound to the WordPress installation.
 */
class Segurium_2FA_Crypto {

	const CIPHER    = 'aes-256-gcm';
	const NONCE_LEN = 12;
	const TAG_LEN   = 16;

	/**
	 * Derive a 256-bit encryption key from WordPress salts.
	 *
	 * @return string 32-byte raw key.
	 */
	private static function get_key() {
		return hash( 'sha256', AUTH_KEY . SECURE_AUTH_KEY, true );
	}

	/**
	 * Encrypt a plaintext string.
	 *
	 * @param string $plaintext Data to encrypt.
	 * @return string|false Hex-encoded ciphertext or false on failure.
	 */
	public static function encrypt( $plaintext ) {
		if ( ! is_string( $plaintext ) || '' === $plaintext ) {
			return false;
		}

		$key   = self::get_key();
		$nonce = random_bytes( self::NONCE_LEN );
		$tag   = '';

		$ct = openssl_encrypt(
			$plaintext,
			self::CIPHER,
			$key,
			OPENSSL_RAW_DATA,
			$nonce,
			$tag,
			'',
			self::TAG_LEN
		);

		if ( false === $ct ) {
			return false;
		}

		// nonce (12) + ciphertext (variable) + tag (16).
		return bin2hex( $nonce . $ct . $tag );
	}

	/**
	 * Decrypt a hex-encoded ciphertext produced by encrypt().
	 *
	 * @param string $encoded Hex-encoded nonce+ciphertext+tag.
	 * @return string|false Plaintext or false on failure / tampered data.
	 */
	public static function decrypt( $encoded ) {
		if ( ! is_string( $encoded ) || '' === $encoded ) {
			return false;
		}

		if ( ! ctype_xdigit( $encoded ) || 0 !== strlen( $encoded ) % 2 ) {
			return false;
		}

		$raw = hex2bin( $encoded );
		if ( false === $raw ) {
			return false;
		}

		// Minimum length: nonce(12) + 1 byte ciphertext + tag(16) = 29.
		$min_len = self::NONCE_LEN + 1 + self::TAG_LEN;
		if ( strlen( $raw ) < $min_len ) {
			return false;
		}

		$key   = self::get_key();
		$nonce = substr( $raw, 0, self::NONCE_LEN );
		$tag   = substr( $raw, -self::TAG_LEN );
		$ct    = substr( $raw, self::NONCE_LEN, -self::TAG_LEN );

		$pt = openssl_decrypt(
			$ct,
			self::CIPHER,
			$key,
			OPENSSL_RAW_DATA,
			$nonce,
			$tag
		);

		return ( false === $pt ) ? false : $pt;
	}
}

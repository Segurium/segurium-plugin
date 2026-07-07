<?php
/**
 * AES-256-GCM envelope used by the backup layer.
 *
 * Prefers libsodium's AEAD when the hardware path is available, otherwise
 * falls back to openssl. Both paths emit and consume the identical on-disk
 * layout so a file written with sodium decrypts on openssl-only hosts and
 * vice versa:
 *
 *   bytes 0..3   : magic  "SGBK"
 *   byte  4      : version 0x01
 *   bytes 5..16  : 12-byte nonce
 *   bytes 17..N-16 : ciphertext
 *   bytes N-16..N  : GCM tag (16 bytes)
 *
 * Key is a fixed 32-byte value derived from a build-time constant. The goal
 * of the envelope is to keep stored malware/cleanup payloads unreadable to
 * unrelated on-host scanners, not to defeat an attacker with code access.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Symmetric-encryption helper for Layer 3 backups.
 */
class Segurium_Storage_Crypto {

	const BACKEND_SODIUM  = 'sodium';
	const BACKEND_OPENSSL = 'openssl';

	const MAGIC      = 'SGBK';
	const VERSION    = 0x01;
	const NONCE_LEN  = 12;
	const TAG_LEN    = 16;
	const HEADER_LEN = 17;

	/**
	 * Deterministic key-derivation input. Every install produces the same
	 * 32-byte key from sha256 of this string — intentionally, so backups
	 * survive reinstall without any per-site secret management.
	 */
	const KEY_MATERIAL = 'segurium-storage-backup-v1';

	/**
	 * Check whether libsodium's AES-256-GCM is available on this host.
	 *
	 * Requires both the sodium extension and a CPU that exposes AES-NI —
	 * libsodium gates the AEAD behind hardware support.
	 */
	public static function sodium_available(): bool {
		return function_exists( 'sodium_crypto_aead_aes256gcm_is_available' )
			&& sodium_crypto_aead_aes256gcm_is_available();
	}

	/**
	 * Preferred backend for new encryptions.
	 *
	 * @return string One of the BACKEND_* constants.
	 */
	public static function backend(): string {
		return self::sodium_available() ? self::BACKEND_SODIUM : self::BACKEND_OPENSSL;
	}

	/**
	 * Encrypt plaintext using the preferred (or forced) backend.
	 *
	 * @param string      $plaintext Bytes to protect.
	 * @param string|null $backend   Force a backend; defaults to {@see backend()}.
	 * @return string|null Ciphertext envelope, or null on failure.
	 */
	public static function encrypt( string $plaintext, ?string $backend = null ): ?string {
		$key     = self::key();
		$backend = $backend ?? self::backend();
		try {
			$nonce = random_bytes( self::NONCE_LEN );
		} catch ( Exception $e ) {
			Segurium_Debug::log( 'Segurium: random_bytes failed for backup nonce: ' . $e->getMessage() );
			return null;
		}

		if ( self::BACKEND_SODIUM === $backend ) {
			if ( ! self::sodium_available() ) {
				Segurium_Debug::log( 'Segurium: sodium backend requested but unavailable' );
				return null;
			}
			$body = sodium_crypto_aead_aes256gcm_encrypt( $plaintext, '', $nonce, $key );
		} else {
			$tag    = '';
			$cipher = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', self::TAG_LEN );
			if ( false === $cipher ) {
				Segurium_Debug::log( 'Segurium: openssl_encrypt failed: ' . openssl_error_string() );
				return null;
			}
			$body = $cipher . $tag;
		}

		return self::MAGIC . chr( self::VERSION ) . $nonce . $body;
	}

	/**
	 * Decrypt a ciphertext envelope.
	 *
	 * @param string      $cipher  Envelope bytes.
	 * @param string|null $backend Force a backend; defaults to {@see backend()}.
	 * @return string|null Plaintext, or null when the header is wrong or the tag
	 *                    fails to verify.
	 */
	public static function decrypt( string $cipher, ?string $backend = null ): ?string {
		if ( strlen( $cipher ) < self::HEADER_LEN + self::TAG_LEN ) {
			return null;
		}
		if ( self::MAGIC !== substr( $cipher, 0, 4 ) ) {
			return null;
		}
		if ( self::VERSION !== ord( $cipher[4] ) ) {
			return null;
		}
		$key     = self::key();
		$nonce   = substr( $cipher, 5, self::NONCE_LEN );
		$body    = substr( $cipher, self::HEADER_LEN );
		$backend = $backend ?? self::backend();

		if ( self::BACKEND_SODIUM === $backend && self::sodium_available() ) {
			try {
				$plain = sodium_crypto_aead_aes256gcm_decrypt( $body, '', $nonce, $key );
			} catch ( SodiumException $e ) {
				return null;
			}
			return false === $plain ? null : $plain;
		}

		$tag       = substr( $body, -self::TAG_LEN );
		$cipherraw = substr( $body, 0, -self::TAG_LEN );
		$plain     = openssl_decrypt( $cipherraw, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag );
		return false === $plain ? null : $plain;
	}

	/**
	 * Derive the fixed 32-byte key. sha256 is available on every PHP build
	 * we target, so no host-capability check is needed.
	 */
	private static function key(): string {
		return hash( 'sha256', self::KEY_MATERIAL, true );
	}
}

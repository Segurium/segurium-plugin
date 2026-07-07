<?php
/**
 * Per-file ignore lists for scan results (by path or by hash).
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages path-based and hash-based ignore lists for scan findings.
 */
class Segurium_Ignore_Lists {

	const FILE_NAME = 'ignore-lists.json';

	/**
	 * Plugin data directory path.
	 *
	 * @var string
	 */
	private $data_dir;

	/**
	 * Path-based ignore list.
	 *
	 * @var array
	 */
	private $by_path = array();

	/**
	 * Hash-based ignore list.
	 *
	 * @var array
	 */
	private $by_hash = array();

	/**
	 * Constructor.
	 *
	 * @param string $data_dir Plugin data directory.
	 */
	public function __construct( $data_dir ) {
		$this->data_dir = rtrim( $data_dir, '/' );
	}

	/**
	 * Load ignore lists from disk.
	 *
	 * @return bool True if loaded, false otherwise.
	 */
	public function load() {
		$file = $this->data_dir . '/' . self::FILE_NAME;
		$raw  = Segurium_Storage_Fs::get_contents( $file );
		if ( false === $raw ) {
			return false;
		}
		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) ) {
			return false;
		}
		$this->by_path = isset( $data['by_path'] ) ? $data['by_path'] : array();
		$this->by_hash = isset( $data['by_hash'] ) ? $data['by_hash'] : array();
		return true;
	}

	/**
	 * Persist ignore lists to disk.
	 */
	public function save() {
		$file = $this->data_dir . '/' . self::FILE_NAME;
		// Atomic write (fopen+rename) via the shared Layer-3 helper: the
		// ignore-list JSON lands under wp_upload_dir()/segurium-data, never the
		// plugin folder, and readers never observe a half-written file.
		Segurium_Storage_Fs::atomic_put(
			$file,
			(string) wp_json_encode(
				array(
					'by_path' => $this->by_path,
					'by_hash' => $this->by_hash,
				)
			)
		);
	}

	/**
	 * Add a path to the ignore list.
	 *
	 * @param string $path File path to ignore.
	 */
	public function add_path( $path ) {
		if ( ! in_array( $path, $this->by_path, true ) ) {
			$this->by_path[] = $path;
		}
		$this->remove_hash( $path );
	}

	/**
	 * Remove a path from the ignore list.
	 *
	 * @param string $path File path to stop ignoring.
	 */
	public function remove_path( $path ) {
		$this->by_path = array_values( array_diff( $this->by_path, array( $path ) ) );
	}

	/**
	 * Add a hash-based ignore entry.
	 *
	 * @param string $path   File path.
	 * @param string $sha256 SHA-256 hash to ignore.
	 */
	public function add_hash( $path, $sha256 ) {
		$this->remove_hash( $path );
		$this->remove_path( $path );
		$this->by_hash[] = array(
			'path'   => $path,
			'sha256' => $sha256,
		);
	}

	/**
	 * Remove hash-based ignore entries for a path.
	 *
	 * @param string $path File path.
	 */
	public function remove_hash( $path ) {
		$this->by_hash = array_values(
			array_filter(
				$this->by_hash,
				function ( $item ) use ( $path ) {
					return $item['path'] !== $path;
				}
			)
		);
	}

	/**
	 * Check if a path is in the ignore list.
	 *
	 * @param string $path File path.
	 * @return bool
	 */
	public function is_path_ignored( $path ) {
		return in_array( $path, $this->by_path, true );
	}

	/**
	 * Check if a specific hash is ignored for a path.
	 *
	 * @param string $path   File path.
	 * @param string $sha256 SHA-256 hash.
	 * @return bool
	 */
	public function is_hash_ignored( $path, $sha256 ) {
		foreach ( $this->by_hash as $item ) {
			if ( $item['path'] === $path && $item['sha256'] === $sha256 ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Return the path ignore list.
	 *
	 * @return array
	 */
	public function get_path_list() {
		return $this->by_path;
	}

	/**
	 * Return the hash ignore list.
	 *
	 * @return array
	 */
	public function get_hash_list() {
		return $this->by_hash;
	}
}

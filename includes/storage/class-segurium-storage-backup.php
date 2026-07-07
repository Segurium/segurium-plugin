<?php
/**
 * Layer 3 — encrypted rotating backups.
 *
 * Features register a named "bucket" with `max_count` and `max_bytes` caps
 * during init; they then call `backup_store( $bucket, $ref, $bytes )` before
 * overwriting a file and `backup_restore( $bucket, $id )` to undo. Each store
 * rotates the bucket against its caps; the daily cron does a second sweep in
 * case caps were lowered at runtime.
 *
 * File layout per backup (hex-sharded, opaque filenames):
 *   backups/<bucket>/<XX>/<opaque>.sgbk        # gzip → AES-256-GCM envelope
 *   backups/<bucket>/<XX>/<opaque>.meta.json   # plaintext metadata (bucket, ref, …)
 *
 * `<XX>` is the first two hex chars of the backup id's random suffix (256 shards).
 * `<opaque>` is `<epoch>_<sha256_prefix_8>` — sortable but non-reversible.
 * The canonical backup id (`<epoch>-<8hex>`) is stored in `.meta.json`.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Backup store with per-bucket rotation.
 */
class Segurium_Storage_Backup {

	const DEFAULT_MAX_COUNT = 10;
	const DEFAULT_MAX_BYTES = 100 * 1048576; // 100 MB.

	/**
	 * Registered buckets keyed by name.
	 *
	 * @var array<string, array{max_count:int, max_bytes:int, pinned_ids_provider:?callable}>
	 */
	private static $buckets = array();

	/**
	 * Register (or update) a bucket's caps.
	 *
	 * @param string               $bucket  Bucket name (snake_case, 1..40 chars).
	 * @param array<string, mixed> $caps    Recognised keys:
	 *                                      - `max_count` (int) — retained envelope count cap.
	 *                                      - `max_bytes` (int) — retained envelope size cap.
	 *                                      - `pinned_ids_provider` (callable) — optional thunk
	 *                                        returning array<string> of backup ids that must NOT
	 *                                        be evicted by rotation. Called once per rotate sweep.
	 *                                        Used by features whose data model still references
	 *                                        a backup_id (e.g. integrity_issues), so a large
	 *                                        burst of new fixes cannot silently destroy a
	 *                                        backup the UI is still offering as restorable.
	 */
	public static function register_bucket( string $bucket, array $caps = array() ): bool {
		if ( ! self::is_valid_bucket( $bucket ) ) {
			Segurium_Debug::log( 'Segurium: backup_register_bucket: invalid name "' . $bucket . '"' );
			return false;
		}
		$provider = isset( $caps['pinned_ids_provider'] ) && is_callable( $caps['pinned_ids_provider'] )
			? $caps['pinned_ids_provider']
			: null;

		self::$buckets[ $bucket ] = array(
			'max_count'           => isset( $caps['max_count'] ) ? max( 1, (int) $caps['max_count'] ) : self::DEFAULT_MAX_COUNT,
			'max_bytes'           => isset( $caps['max_bytes'] ) ? max( 1, (int) $caps['max_bytes'] ) : self::DEFAULT_MAX_BYTES,
			'pinned_ids_provider' => $provider,
		);
		return true;
	}

	/**
	 * Resolve a bucket's caps, falling back to sensible defaults for buckets
	 * that have files on disk but no runtime registration (e.g. GC after a
	 * feature module is disabled).
	 *
	 * @param string $bucket Bucket name.
	 * @return array{max_count:int, max_bytes:int}
	 */
	public static function bucket_caps( string $bucket ): array {
		if ( isset( self::$buckets[ $bucket ] ) ) {
			return array(
				'max_count' => self::$buckets[ $bucket ]['max_count'],
				'max_bytes' => self::$buckets[ $bucket ]['max_bytes'],
			);
		}
		return array(
			'max_count' => self::DEFAULT_MAX_COUNT,
			'max_bytes' => self::DEFAULT_MAX_BYTES,
		);
	}

	/**
	 * List registered buckets.
	 *
	 * @return array<string>
	 */
	public static function registered(): array {
		return array_keys( self::$buckets );
	}

	/**
	 * Forget all bucket registrations. Tests only.
	 */
	public static function reset_buckets(): void {
		self::$buckets = array();
	}

	/**
	 * Gzip → encrypt → write a backup.
	 *
	 * @param string               $bucket            Target bucket.
	 * @param string               $ref               Identifier of the thing being backed up (e.g. file path).
	 * @param string               $content           Plaintext bytes.
	 * @param array<string, mixed> $extra_meta        Extra key/value pairs stored verbatim in the sidecar.
	 * @param int                  $compression_level gzencode level, 1..9. Default 6. Callers that prefer
	 *                                                speed over ratio (e.g. large component archives) pass 1.
	 * @return string backup_id.
	 * @throws Segurium_Storage_Exception On I/O / encryption failure.
	 */
	public static function store( string $bucket, string $ref, string $content, array $extra_meta = array(), int $compression_level = 6 ): string {
		if ( ! self::is_valid_bucket( $bucket ) ) {
			throw new Segurium_Storage_Exception( esc_html( 'Invalid bucket name: ' . $bucket ) );
		}
		if ( ! Segurium_Storage_Fs::ensure_layout() ) {
			throw new Segurium_Storage_Exception( 'Backup layout not writable' );
		}
		$bucket_dir = Segurium_Storage_Fs::backups_dir() . '/' . $bucket;
		if ( ! Segurium_Storage_Fs::ensure_dir( $bucket_dir, 0755 ) ) {
			throw new Segurium_Storage_Exception( esc_html( 'Failed to create bucket directory ' . $bucket_dir ) );
		}
		Segurium_Storage_Fs::write_guards( $bucket_dir );

		if ( $compression_level < 1 || $compression_level > 9 ) {
			$compression_level = 6;
		}
		$compressed = gzencode( $content, $compression_level );
		if ( false === $compressed ) {
			throw new Segurium_Storage_Exception( esc_html( 'gzencode failed for bucket ' . $bucket ) );
		}
		$cipher = Segurium_Storage_Crypto::encrypt( $compressed );
		if ( null === $cipher ) {
			throw new Segurium_Storage_Exception( esc_html( 'Encryption failed for bucket ' . $bucket ) );
		}

		try {
			$suffix = bin2hex( random_bytes( 4 ) );
		} catch ( Exception $e ) {
			throw new Segurium_Storage_Exception( esc_html( 'random_bytes failed: ' . $e->getMessage() ) );
		}
		// Microsecond-precision so lexicographic id order stays in sync with
		// write order when stores land in the same wall-clock second.
		$backup_id = sprintf( '%d-%s', (int) ( microtime( true ) * 1_000_000 ), $suffix );

		$shard_dir = $bucket_dir . '/' . self::shard_key( $backup_id );
		if ( ! Segurium_Storage_Fs::ensure_dir( $shard_dir, 0755 ) ) {
			throw new Segurium_Storage_Exception( esc_html( 'Failed to create shard directory ' . $shard_dir ) );
		}

		$opaque    = self::opaque_name( $backup_id );
		$sgbk_path = $shard_dir . '/' . $opaque . '.sgbk';
		$meta_path = $shard_dir . '/' . $opaque . '.meta.json';

		$meta = array_merge(
			$extra_meta,
			array(
				'backup_id'    => $backup_id,
				'bucket'       => $bucket,
				'ref'          => $ref,
				'orig_size'    => strlen( $content ),
				'sha256_plain' => hash( 'sha256', $content ),
				'backend'      => Segurium_Storage_Crypto::backend(),
				'created_at'   => time(),
			)
		);

		if ( ! Segurium_Storage_Fs::atomic_put( $sgbk_path, $cipher ) ) {
			throw new Segurium_Storage_Exception( esc_html( sprintf( 'Failed to write backup %s/%s', $bucket, $backup_id ) ) );
		}
		$meta_json = wp_json_encode( $meta );
		if ( false === $meta_json || ! Segurium_Storage_Fs::atomic_put( $meta_path, $meta_json ) ) {
			Segurium_Fs::delete( $sgbk_path );
			throw new Segurium_Storage_Exception( esc_html( sprintf( 'Failed to write backup metadata %s/%s', $bucket, $backup_id ) ) );
		}

		self::rotate( $bucket );

		return $backup_id;
	}

	/**
	 * Decrypt and return the plaintext of a stored backup.
	 *
	 * Returns null when the file is missing, the GCM tag doesn't verify, or
	 * the plaintext hash doesn't match the sidecar — i.e. any integrity fail.
	 * Callers that need to surface a specific failure cause to the UI should
	 * use {@see restore_detailed()}; this method is preserved for code paths
	 * that only care about success/failure.
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier from {@see store()}.
	 */
	public static function restore( string $bucket, string $backup_id ): ?string {
		return self::restore_detailed( $bucket, $backup_id )['content'];
	}

	/**
	 * Decrypt-and-return with a structured failure reason.
	 *
	 * Returns:
	 *   - On success: ['content' => string $plaintext, 'reason' => null].
	 *   - On failure: ['content' => null,             'reason' => string $tag].
	 *
	 * Reason tags (also written to activity_log via log_restore_failure):
	 *   - `invalid_args`     bucket or backup_id failed validation.
	 *   - `envelope_missing` envelope (.sgbk) file is gone — typically rotated out
	 *                       by a later store() call. This is the common case the
	 *                       UI must explain to the operator.
	 *   - `meta_missing`     sidecar metadata is missing, unreadable, or malformed.
	 *   - `read_failed`      envelope exists but is unreadable (perms / I/O).
	 *   - `decrypt_failed`   AEAD authentication tag rejected the ciphertext.
	 *   - `gzdecode_failed`  decrypted payload is not valid gzip.
	 *   - `sha256_mismatch`  recomputed plaintext hash differs from the sidecar.
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier from {@see store()}.
	 * @return array{content: ?string, reason: ?string}
	 */
	public static function restore_detailed( string $bucket, string $backup_id ): array {
		if ( ! self::is_valid_bucket( $bucket ) || ! self::is_valid_backup_id( $backup_id ) ) {
			self::log_restore_failure( $bucket, $backup_id, 'invalid_args' );
			return array(
				'content' => null,
				'reason'  => 'invalid_args',
			);
		}
		$base      = self::sharded_base( $bucket, $backup_id );
		$sgbk_path = $base . '.sgbk';
		$meta_path = $base . '.meta.json';
		if ( ! is_file( $sgbk_path ) ) {
			self::log_restore_failure( $bucket, $backup_id, 'envelope_missing' );
			return array(
				'content' => null,
				'reason'  => 'envelope_missing',
			);
		}
		if ( ! is_file( $meta_path ) ) {
			self::log_restore_failure( $bucket, $backup_id, 'meta_missing' );
			return array(
				'content' => null,
				'reason'  => 'meta_missing',
			);
		}
		$cipher = Segurium_Fs::read( $sgbk_path );
		if ( false === $cipher ) {
			self::log_restore_failure( $bucket, $backup_id, 'read_failed' );
			return array(
				'content' => null,
				'reason'  => 'read_failed',
			);
		}
		$compressed = Segurium_Storage_Crypto::decrypt( $cipher );
		if ( null === $compressed ) {
			self::log_restore_failure( $bucket, $backup_id, 'decrypt_failed' );
			return array(
				'content' => null,
				'reason'  => 'decrypt_failed',
			);
		}
		$plain = @gzdecode( $compressed ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $plain ) {
			self::log_restore_failure( $bucket, $backup_id, 'gzdecode_failed' );
			return array(
				'content' => null,
				'reason'  => 'gzdecode_failed',
			);
		}
		$meta_raw = Segurium_Fs::read( $meta_path );
		$meta     = ( false === $meta_raw ) ? null : json_decode( $meta_raw, true );
		if ( ! is_array( $meta ) || ! isset( $meta['sha256_plain'] ) ) {
			self::log_restore_failure( $bucket, $backup_id, 'meta_missing' );
			return array(
				'content' => null,
				'reason'  => 'meta_missing',
			);
		}
		if ( ! hash_equals( (string) $meta['sha256_plain'], hash( 'sha256', $plain ) ) ) {
			self::log_restore_failure( $bucket, $backup_id, 'sha256_mismatch' );
			return array(
				'content' => null,
				'reason'  => 'sha256_mismatch',
			);
		}
		return array(
			'content' => $plain,
			'reason'  => null,
		);
	}

	/**
	 * Cheap existence check — true iff both envelope and sidecar are on disk.
	 *
	 * Used by features that store backup_id alongside their own data model
	 * (e.g. integrity_issues) to reconcile their UI: a row whose envelope is
	 * gone must not advertise a Restore button.
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier from {@see store()}.
	 */
	public static function exists( string $bucket, string $backup_id ): bool {
		if ( ! self::is_valid_bucket( $bucket ) || ! self::is_valid_backup_id( $backup_id ) ) {
			return false;
		}
		$base = self::sharded_base( $bucket, $backup_id );
		return is_file( $base . '.sgbk' ) && is_file( $base . '.meta.json' );
	}

	/**
	 * List backups in a bucket, newest first.
	 *
	 * @param string $bucket Bucket name.
	 * @return array<int, array<string, mixed>> Meta dicts from each .meta.json.
	 */
	public static function list_backups( string $bucket ): array {
		if ( ! self::is_valid_bucket( $bucket ) ) {
			return array();
		}
		$dir = Segurium_Storage_Fs::backups_dir() . '/' . $bucket;
		if ( ! is_dir( $dir ) ) {
			return array();
		}
		$metas   = array();
		$matches = glob( $dir . '/[0-9a-f][0-9a-f]/*.meta.json' );
		if ( false === $matches ) {
			$matches = array();
		}
		foreach ( $matches as $path ) {
			$raw = Segurium_Fs::read( $path );
			if ( false === $raw ) {
				continue;
			}
			$dec = json_decode( $raw, true );
			if ( is_array( $dec ) ) {
				$metas[] = $dec;
			}
		}
		usort(
			$metas,
			static function ( $a, $b ) {
				return strcmp( (string) ( $b['backup_id'] ?? '' ), (string) ( $a['backup_id'] ?? '' ) );
			}
		);
		return $metas;
	}

	/**
	 * Merge extra key/value pairs into an existing backup's sidecar metadata.
	 *
	 * @param string               $bucket    Bucket name.
	 * @param string               $backup_id Identifier returned by {@see store()}.
	 * @param array<string, mixed> $extra     Key/value pairs to merge.
	 * @throws Segurium_Storage_Exception On I/O failure.
	 */
	public static function update_meta( string $bucket, string $backup_id, array $extra ): void {
		if ( ! self::is_valid_bucket( $bucket ) || ! self::is_valid_backup_id( $backup_id ) ) {
			throw new Segurium_Storage_Exception( 'Invalid bucket or backup_id' );
		}
		$meta_path = self::sharded_base( $bucket, $backup_id ) . '.meta.json';
		if ( ! is_file( $meta_path ) ) {
			throw new Segurium_Storage_Exception( esc_html( 'Metadata file not found: ' . $meta_path ) );
		}
		$raw = Segurium_Fs::read( $meta_path );
		if ( false === $raw ) {
			throw new Segurium_Storage_Exception( esc_html( 'Failed to read metadata: ' . $meta_path ) );
		}
		$meta = json_decode( $raw, true );
		if ( ! is_array( $meta ) ) {
			throw new Segurium_Storage_Exception( esc_html( 'Corrupt metadata JSON: ' . $meta_path ) );
		}
		$meta      = array_merge( $meta, $extra );
		$meta_json = wp_json_encode( $meta );
		if ( false === $meta_json || ! Segurium_Storage_Fs::atomic_put( $meta_path, $meta_json ) ) {
			throw new Segurium_Storage_Exception( esc_html( 'Failed to write updated metadata: ' . $meta_path ) );
		}
	}

	/**
	 * Remove a single backup (both envelope and sidecar).
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier returned by {@see store()}.
	 */
	public static function delete( string $bucket, string $backup_id ): bool {
		if ( ! self::is_valid_bucket( $bucket ) || ! self::is_valid_backup_id( $backup_id ) ) {
			return false;
		}
		return self::delete_at( self::sharded_base( $bucket, $backup_id ) );
	}

	/**
	 * Delete the `.sgbk` + `.meta.json` pair at a given path prefix.
	 *
	 * @param string $base Path prefix without extension.
	 */
	private static function delete_at( string $base ): bool {
		$ok = true;
		foreach ( array( '.sgbk', '.meta.json' ) as $ext ) {
			$path = $base . $ext;
			if ( file_exists( $path ) && ! Segurium_Fs::delete( $path ) ) {
				Segurium_Debug::log( 'Segurium: backup_delete failed on ' . $path );
				$ok = false;
			}
		}
		return $ok;
	}

	/**
	 * Rotate a single bucket, deleting oldest entries first until within caps.
	 *
	 * @param string $bucket Target bucket.
	 * @return int Number of backups removed.
	 */
	public static function rotate( string $bucket ): int {
		$caps = self::bucket_caps( $bucket );
		return self::rotate_with_caps( $bucket, (int) $caps['max_count'], (int) $caps['max_bytes'] );
	}

	/**
	 * Rotate with explicit caps; used internally and by {@see gc()}.
	 *
	 * Unlike {@see list_backups()} this reads only the envelope filenames and
	 * sizes — sidecars are never parsed — because rotation is on the hot path
	 * (every `store()` triggers it).
	 *
	 * @param string $bucket    Bucket name.
	 * @param int    $max_count Maximum number of retained backups.
	 * @param int    $max_bytes Maximum aggregate `.sgbk` size.
	 */
	private static function rotate_with_caps( string $bucket, int $max_count, int $max_bytes ): int {
		$entries = self::list_envelope_stats( $bucket );
		if ( empty( $entries ) ) {
			return 0;
		}
		$pinned_opaque = self::resolve_pinned_opaque_set( $bucket );
		$removed       = 0;
		$total         = 0;
		foreach ( $entries as $e ) {
			$total += $e['size'];
		}
		$bucket_dir = Segurium_Storage_Fs::backups_dir() . '/' . $bucket;
		$count      = count( $entries );
		// Entries are oldest-first. Walk forward, evicting non-pinned victims
		// until under both caps. Pinned entries count toward `count`/`total`
		// but are never deleted — large bursts therefore stay above caps
		// rather than silently destroying a backup the UI still references.
		foreach ( $entries as $e ) {
			if ( $count <= $max_count && $total <= $max_bytes ) {
				break;
			}
			if ( isset( $pinned_opaque[ $e['opaque'] ] ) ) {
				continue;
			}
			$base = $bucket_dir . '/' . $e['shard'] . '/' . $e['opaque'];
			if ( self::delete_at( $base ) ) {
				$total -= $e['size'];
				--$count;
				++$removed;
			} else {
				break;
			}
		}
		return $removed;
	}

	/**
	 * Resolve the pinned-id provider for a bucket into an opaque-name lookup.
	 *
	 * Backup ids and on-disk opaque filenames share the same epoch prefix but
	 * carry different suffixes (random vs. sha256-derived). Mapping the
	 * caller's ids through {@see opaque_name()} once lets the rotation hot
	 * path do an O(1) `isset` check per envelope without re-reading sidecars.
	 *
	 * Returns a map of opaque_name => true. Empty when the bucket has no
	 * provider, the provider returned non-array, or none of the ids are valid.
	 *
	 * @param string $bucket Bucket name.
	 * @return array<string, bool>
	 */
	private static function resolve_pinned_opaque_set( string $bucket ): array {
		if ( empty( self::$buckets[ $bucket ]['pinned_ids_provider'] ) ) {
			return array();
		}
		$provider = self::$buckets[ $bucket ]['pinned_ids_provider'];
		try {
			$ids = $provider();
		} catch ( \Throwable $e ) {
			Segurium_Debug::log( 'Segurium: pinned_ids_provider for "' . $bucket . '" threw: ' . $e->getMessage() );
			return array();
		}
		if ( ! is_array( $ids ) ) {
			return array();
		}
		$out = array();
		foreach ( $ids as $id ) {
			if ( is_string( $id ) && self::is_valid_backup_id( $id ) ) {
				$out[ self::opaque_name( $id ) ] = true;
			}
		}
		return $out;
	}

	/**
	 * Return `[{opaque, shard, size}]` for every envelope in $bucket,
	 * oldest-first.
	 *
	 * Walks `<bucket>/<XX>/` shard directories matching the `[0-9a-f]{2}`
	 * pattern. Opaque filenames carry an epoch prefix so lexicographic
	 * ordering equals chronological ordering.
	 *
	 * @param string $bucket Bucket name.
	 * @return array<int, array{opaque:string, shard:string, size:int}>
	 */
	private static function list_envelope_stats( string $bucket ): array {
		$dir = Segurium_Storage_Fs::backups_dir() . '/' . $bucket;
		if ( ! is_dir( $dir ) ) {
			return array();
		}
		$out    = array();
		$shards = glob( $dir . '/[0-9a-f][0-9a-f]', GLOB_ONLYDIR );
		if ( false === $shards ) {
			$shards = array();
		}
		foreach ( $shards as $shard_path ) {
			$shard_name = basename( $shard_path );
			$fh         = Segurium_Fs::opendir( $shard_path );
			if ( false === $fh ) {
				continue;
			}
			while ( false !== ( $entry = readdir( $fh ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}
				if ( ! preg_match( '/^(\d{1,20}_[0-9a-f]{8})\.sgbk$/', $entry, $m ) ) {
					continue;
				}
				$path  = $shard_path . '/' . $entry;
				$out[] = array(
					'opaque' => $m[1],
					'shard'  => $shard_name,
					'size'   => (int) Segurium_Fs::size( $path ),
				);
			}
			closedir( $fh );
		}
		// Opaque names have an epoch prefix so lexicographic == chronological.
		usort(
			$out,
			static function ( $a, $b ) {
				return strcmp( $a['opaque'], $b['opaque'] );
			}
		);
		return $out;
	}

	/**
	 * Dry-run rotation against a hypothetical batch of pending stores.
	 *
	 * Used by the Integrity Fix-all preflight (SEGURIUM-279) so the operator
	 * sees how much of the existing backup ring would be evicted before we
	 * actually start writing envelopes. Re-implements {@see rotate_with_caps()}
	 * walk — counting victims rather than deleting them — and reports pinned
	 * envelopes that would have been dropped if rotation were unaware of
	 * SEGURIUM-278's pinning. The simulation is approximate by design: we use
	 * the caller's predicted plaintext sizes for the new entries because the
	 * compressed/encrypted envelope sizes are not knowable without writing.
	 * Conservative overestimate is fine — it just nags more.
	 *
	 * @param string         $bucket        Bucket name.
	 * @param array<int,int> $pending_sizes Plaintext byte sizes of envelopes
	 *                                      that would be added by the batch.
	 * @return array{
	 *     bucket_used_count:int,
	 *     bucket_used_bytes:int,
	 *     bucket_max_count:int,
	 *     bucket_max_bytes:int,
	 *     pending_count:int,
	 *     pending_bytes:int,
	 *     would_evict_count:int,
	 *     would_evict_bytes:int,
	 *     would_evict_pinned_count:int
	 * }
	 */
	public static function simulate_rotation( string $bucket, array $pending_sizes ): array {
		$caps          = self::bucket_caps( $bucket );
		$max_count     = (int) $caps['max_count'];
		$max_bytes     = (int) $caps['max_bytes'];
		$entries       = self::is_valid_bucket( $bucket ) ? self::list_envelope_stats( $bucket ) : array();
		$pinned_opaque = self::is_valid_bucket( $bucket ) ? self::resolve_pinned_opaque_set( $bucket ) : array();

		$used_count = count( $entries );
		$used_bytes = 0;
		foreach ( $entries as $e ) {
			$used_bytes += (int) $e['size'];
		}

		$pending_count = 0;
		$pending_bytes = 0;
		foreach ( $pending_sizes as $sz ) {
			$sz = (int) $sz;
			if ( $sz < 0 ) {
				$sz = 0;
			}
			++$pending_count;
			$pending_bytes += $sz;
		}

		$total_count = $used_count + $pending_count;
		$total_bytes = $used_bytes + $pending_bytes;

		$evict_count        = 0;
		$evict_bytes        = 0;
		$evict_pinned_count = 0;

		// Walk oldest-first, mirroring rotate_with_caps()'s eviction order.
		foreach ( $entries as $e ) {
			if ( $total_count <= $max_count && $total_bytes <= $max_bytes ) {
				break;
			}
			if ( isset( $pinned_opaque[ $e['opaque'] ] ) ) {
				++$evict_pinned_count;
				continue;
			}
			++$evict_count;
			$evict_bytes += (int) $e['size'];
			--$total_count;
			$total_bytes -= (int) $e['size'];
		}

		return array(
			'bucket_used_count'        => $used_count,
			'bucket_used_bytes'        => $used_bytes,
			'bucket_max_count'         => $max_count,
			'bucket_max_bytes'         => $max_bytes,
			'pending_count'            => $pending_count,
			'pending_bytes'            => $pending_bytes,
			'would_evict_count'        => $evict_count,
			'would_evict_bytes'        => $evict_bytes,
			'would_evict_pinned_count' => $evict_pinned_count,
		);
	}

	/**
	 * Rotate every registered bucket. Additionally sweeps on-disk bucket dirs
	 * that still exist but aren't currently registered (feature deactivated
	 * at runtime) using default caps.
	 *
	 * @return int Total backups removed.
	 */
	public static function gc(): int {
		$removed = 0;
		foreach ( array_keys( self::$buckets ) as $name ) {
			$removed += self::rotate( $name );
		}
		$root = Segurium_Storage_Fs::backups_dir();
		if ( is_dir( $root ) ) {
			$dirs = glob( $root . '/*', GLOB_ONLYDIR );
			if ( false === $dirs ) {
				$dirs = array();
			}
			foreach ( $dirs as $path ) {
				$name = basename( $path );
				if ( isset( self::$buckets[ $name ] ) ) {
					continue;
				}
				if ( ! self::is_valid_bucket( $name ) ) {
					continue;
				}
				$removed += self::rotate_with_caps( $name, self::DEFAULT_MAX_COUNT, self::DEFAULT_MAX_BYTES );
			}
		}
		return $removed;
	}

	/**
	 * Validate a bucket name against the allowed character class.
	 *
	 * @param string $bucket Candidate value.
	 */
	private static function is_valid_bucket( string $bucket ): bool {
		return (bool) preg_match( '/^[a-z0-9_]{1,40}$/', $bucket );
	}

	/**
	 * Validate a backup id against the `<epoch>-<8hex>` format.
	 *
	 * @param string $id Candidate value.
	 */
	private static function is_valid_backup_id( string $id ): bool {
		return (bool) preg_match( '/^\d{1,20}-[0-9a-f]{8}$/', $id );
	}

	/**
	 * Shard key: first 2 hex chars of the random suffix in a backup id.
	 *
	 * With 256 possible values the backup directory fans out into at most
	 * 256 subdirectories, keeping each one under ~4 000 files at 1 M total.
	 *
	 * @param string $backup_id Identifier from {@see store()}.
	 */
	private static function shard_key( string $backup_id ): string {
		return substr( $backup_id, strrpos( $backup_id, '-' ) + 1, 2 );
	}

	/**
	 * Opaque on-disk filename derived from a backup id.
	 *
	 * Format: `<epoch>_<sha256_prefix_8>`.  The epoch prefix preserves
	 * chronological sort order while the hash suffix makes the name
	 * non-reversible, preventing pattern-based matches across cases.
	 *
	 * @param string $backup_id Identifier from {@see store()}.
	 */
	private static function opaque_name( string $backup_id ): string {
		$dash  = strrpos( $backup_id, '-' );
		$epoch = substr( $backup_id, 0, $dash );
		$hash  = substr( hash( 'sha256', $backup_id ), 0, 8 );
		return $epoch . '_' . $hash;
	}

	/**
	 * Full path prefix (without extension) inside the shard directory.
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier from {@see store()}.
	 */
	private static function sharded_base( string $bucket, string $backup_id ): string {
		return Segurium_Storage_Fs::backups_dir()
			. '/' . $bucket
			. '/' . self::shard_key( $backup_id )
			. '/' . self::opaque_name( $backup_id );
	}

	/**
	 * Absolute path to a backup's `.sgbk` envelope file.
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier from {@see store()}.
	 */
	public static function file_path( string $bucket, string $backup_id ): string {
		return self::sharded_base( $bucket, $backup_id ) . '.sgbk';
	}

	/**
	 * Record a restore failure in activity_log (severity = warning).
	 *
	 * @param string $bucket    Bucket name.
	 * @param string $backup_id Identifier that failed to restore.
	 * @param string $reason    Machine-readable failure tag.
	 */
	private static function log_restore_failure( string $bucket, string $backup_id, string $reason ): void {
		try {
			Segurium_Storage::table_insert(
				'activity_log',
				array(
					'event_type' => 'backup_restore_failed',
					'severity'   => 2,
					'subject'    => $bucket . '/' . $backup_id,
					'data_json'  => wp_json_encode( array( 'reason' => $reason ) ),
					'created_at' => time(),
				)
			);
		} catch ( Segurium_Storage_Exception $e ) {
			Segurium_Debug::log( 'Segurium: failed to log backup restore failure: ' . $e->getMessage() );
		}
	}
}

<?php
/**
 * The settings save path.
 *
 * `Segurium_Settings` owns the registry and the persistence primitives; this
 * class owns everything a save has to do around them — the kill-switch gate,
 * validation, the change check, the list-backed fields, pending-change staging
 * and the CTI snapshot. Request handlers keep their nonce and capability check
 * and hand a plain array to `save()`; nothing else in the tree writes a
 * settings row.
 *
 * Input is merged over the stored row, so a caller may send one field or the
 * whole feature. A rejected value never writes and never reports; it comes back
 * as a reason code.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Single settings writer.
 */
class Segurium_Settings_Writer {

	const CODE_UNKNOWN_SLUG    = 'unknown_slug';
	const CODE_KILL_SWITCH     = 'kill_switch';
	const CODE_INVALID_VALUE   = 'invalid_value';
	const CODE_SANITIZE_FAILED = 'sanitize_failed';
	const CODE_WRITE_FAILED    = 'write_failed';
	const CODE_UNKNOWN_TOKEN   = 'unknown_token';

	/**
	 * The writer's own refusal codes. Their messages describe a condition the
	 * operator did not cause and cannot read — a wp-config switch, a registry
	 * gap, a validator that threw — so they are logged, not shown. A code
	 * outside this set came from a feature validator and carries that
	 * feature's own translated message.
	 */
	const OWN_CODES = array(
		self::CODE_UNKNOWN_SLUG,
		self::CODE_KILL_SWITCH,
		self::CODE_INVALID_VALUE,
		self::CODE_SANITIZE_FAILED,
		self::CODE_WRITE_FAILED,
		self::CODE_UNKNOWN_TOKEN,
	);

	/**
	 * Validate, persist and report one feature's settings.
	 *
	 * @param string $slug    Registry slug.
	 * @param array  $input   Raw values, whole feature or any subset.
	 * @param array  $options 'stage' => bool (default true) to allow a pending
	 *                        fuse, 'report' => bool (default true) to allow the
	 *                        CTI snapshot, 'dry_run' => bool (default false) to
	 *                        validate and report without writing, staging or
	 *                        telling CTI anything.
	 * @return array{ok:bool,slug:string,changed:bool,applied:array,skipped:array,
	 *               warnings:array,errors:array,token:?string,expires_in:int}
	 */
	public static function save( string $slug, array $input, array $options = array() ): array {
		$result = self::result( $slug );

		if ( ! Segurium_Settings::has( $slug ) ) {
			return self::fail( $result, self::CODE_UNKNOWN_SLUG, 'No registry row for this feature.' );
		}

		$row  = Segurium_Settings::row( $slug );
		$kill = self::kill_reason( $row );
		if ( '' !== $kill ) {
			return self::fail( $result, $kill, 'A wp-config switch refuses this change.' );
		}

		// Merged over what is stored, never over the defaults. A validator
		// that branches on key presence — the scheduled scan seeds an
		// off-peak slot only for fields the caller left out — must not see a
		// default it was never given as an answer the operator typed.
		$old    = Segurium_Settings::get( $slug, true );
		$merged = array_merge( Segurium_Settings::get_stored( $slug ), $input );

		$clean = self::sanitize( $row, $merged, $input );
		if ( is_wp_error( $clean ) ) {
			return self::fail( $result, (string) $clean->get_error_code(), (string) $clean->get_error_message() );
		}
		if ( ! is_array( $clean ) ) {
			return self::fail( $result, self::CODE_SANITIZE_FAILED, 'The feature validator returned no values.' );
		}

		$result['warnings'] = self::warnings( $row, $input, $clean );
		$result['skipped']  = self::skipped( $row, $input, $clean );

		$lists                  = self::split_lists( $row, $clean );
		list( $clean, $listed ) = $lists;

		if ( ! empty( $options['dry_run'] ) ) {
			$result['ok']      = true;
			$result['changed'] = self::differs( array_merge( $clean, $listed ), $old );
			$result['applied'] = array_merge( $old, $clean, $listed );
			return $result;
		}

		$changed = self::write( $slug, $row, $clean, $listed, $old );
		if ( is_wp_error( $changed ) ) {
			return self::fail( $result, (string) $changed->get_error_code(), (string) $changed->get_error_message() );
		}

		$result['ok']      = true;
		$result['changed'] = $changed;
		$result['applied'] = Segurium_Settings::get( $slug, true );

		// Staging is not gated on `changed`. Re-saving identical values still
		// has to answer for the fuse already armed: leaving it would auto-revert
		// a feature the operator just told us to keep, with a token the reply
		// never handed back.
		if ( false !== ( $options['stage'] ?? true ) ) {
			$staged               = self::stage( $row, $result['applied'], $old );
			$result['token']      = $staged['token'];
			$result['expires_in'] = $staged['expires_in'];
		}

		if ( ! $changed ) {
			return $result;
		}

		self::run_after( $row, $result['applied'], $old );

		if ( false !== ( $options['report'] ?? true ) ) {
			self::report( $slug, $row, $result['applied'] );
		}

		return $result;
	}

	/**
	 * Confirm a staged change. Callable with no browser: it consumes the
	 * token, cancels the auto-revert and fires the confirmation hook the
	 * feature listens on.
	 *
	 * @param string $token Pending-change token.
	 * @return array{ok:bool,context:string,errors:array}
	 */
	public static function confirm( string $token ): array {
		$data = Segurium_Pending_Changes::confirm( $token );
		if ( false === $data ) {
			return array(
				'ok'      => false,
				'context' => '',
				'errors'  => array(
					array(
						'code'    => self::CODE_UNKNOWN_TOKEN,
						'message' => 'No pending change for this token.',
					),
				),
			);
		}

		do_action( 'segurium_pending_confirmed', $data['context'], $data['old'], $data['new'] );

		return array(
			'ok'      => true,
			'context' => (string) $data['context'],
			'errors'  => array(),
		);
	}

	/**
	 * Emit one feature's snapshot without writing anything. For the callers
	 * that have to re-report state the save path already stored — a backfill,
	 * or a field that reaches CTI later than the setting did.
	 *
	 * @param string $slug Registry slug.
	 * @return bool
	 */
	public static function push_snapshot( string $slug ): bool {
		if ( ! Segurium_Settings::has( $slug ) ) {
			Segurium_Debug::log( '[segurium] settings_snapshot_unknown_slug: ' . $slug );
			return false;
		}
		return self::report( $slug, Segurium_Settings::row( $slug ), Segurium_Settings::get( $slug, true ) );
	}

	/*
	 * ─────────────────────────────────────────────────────────────────────
	 * Steps.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * Reason the feature refuses to be written, or '' when it is open.
	 *
	 * @param array $row Registry row.
	 * @return string
	 */
	private static function kill_reason( array $row ): string {
		if ( ! is_callable( $row['kill'] ) ) {
			return '';
		}
		return (string) call_user_func( $row['kill'] );
	}

	/**
	 * Run the feature's validator. A validator that throws is reported as a
	 * refusal rather than taking the request down with it.
	 *
	 * The raw caller input goes with it. A validator that enforces a ceiling
	 * needs to know which values the caller actually sent: an oversized list
	 * an older release stored is not a reason to refuse an unrelated field.
	 *
	 * @param array $row    Registry row.
	 * @param array $merged Input merged over the stored values.
	 * @param array $input  Raw caller input.
	 * @return array|WP_Error
	 */
	private static function sanitize( array $row, array $merged, array $input ) {
		if ( ! is_callable( $row['sanitize'] ) ) {
			return $merged;
		}
		try {
			return call_user_func( $row['sanitize'], $merged, $input );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] settings_sanitize_failed: ' . $e->getMessage() );
			return new WP_Error( self::CODE_SANITIZE_FAILED, $e->getMessage() );
		}
	}

	/**
	 * Human-readable notes about values the validator rewrote. Only features
	 * that rewrite rather than reject declare one.
	 *
	 * @param array $row   Registry row.
	 * @param array $input Raw caller input.
	 * @param array $clean Validated values.
	 * @return array<int,string>
	 */
	private static function warnings( array $row, array $input, array $clean ): array {
		if ( ! is_callable( $row['warnings'] ) ) {
			return array();
		}
		return (array) call_user_func( $row['warnings'], $input, $clean );
	}

	/**
	 * Fields the caller sent that the validator refused to store.
	 *
	 * @param array $row   Registry row.
	 * @param array $input Raw caller input.
	 * @param array $clean Validated values.
	 * @return array<string,string> Field => reason code.
	 */
	private static function skipped( array $row, array $input, array $clean ): array {
		$skipped = array();
		foreach ( array_keys( $input ) as $field ) {
			if ( array_key_exists( $field, $clean ) || isset( $row['lists'][ $field ] ) ) {
				continue;
			}
			$skipped[ $field ] = self::CODE_INVALID_VALUE;
		}
		return $skipped;
	}

	/**
	 * Separate the fields that live in the ip_list table from the ones that
	 * live in the option row.
	 *
	 * @param array $row   Registry row.
	 * @param array $clean Validated values.
	 * @return array{0:array,1:array} Option fields, list fields.
	 */
	private static function split_lists( array $row, array $clean ): array {
		$listed = array();
		foreach ( array_keys( $row['lists'] ) as $field ) {
			if ( array_key_exists( $field, $clean ) ) {
				$listed[ $field ] = (array) $clean[ $field ];
			}
			unset( $clean[ $field ] );
		}
		return array( $clean, $listed );
	}

	/**
	 * Persist the option row and the list-backed fields.
	 *
	 * @param string $slug   Registry slug.
	 * @param array  $row    Registry row.
	 * @param array  $clean  Option fields.
	 * @param array  $listed List fields.
	 * @param array  $old    Settings as they read before the write.
	 * @return bool|WP_Error True when anything changed.
	 */
	private static function write( string $slug, array $row, array $clean, array $listed, array $old ) {
		// Two different questions. The option row is rewritten whenever it
		// stops matching what is stored, so an operator who explicitly picks
		// the default value is recorded as having answered — the consent
		// screen reads exactly that distinction. `changed` is narrower: it
		// asks whether the settings a reader sees actually moved, and that
		// is what earns a snapshot.
		if ( Segurium_Settings::get_stored( $slug ) !== $clean ) {
			Segurium_Settings::put( $slug, $clean );
		}
		$row_changed = self::differs( $clean, $old );
		$changed     = $row_changed;

		foreach ( $listed as $field => $values ) {
			$list_changed = self::differs( array( $field => $values ), $old );
			// A list writer can key off the option row — the firewall picks
			// the allow or the block feed from `mode`. Flipping the mode with
			// the same addresses would otherwise leave every entry in the
			// feed nobody reads any more.
			if ( ! $list_changed && ! $row_changed ) {
				continue;
			}
			$writer = $row['lists'][ $field ]['write'] ?? null;
			if ( ! is_callable( $writer ) ) {
				return new WP_Error( self::CODE_WRITE_FAILED, 'The list field ' . $field . ' has no writer.' );
			}
			call_user_func( $writer, $values, $clean );
			$changed = $changed || $list_changed;
		}

		return $changed;
	}

	/**
	 * Whether any of these fields reads differently from the stored settings.
	 *
	 * @param array $values Fields to compare.
	 * @param array $old    Settings as they read before the write.
	 * @return bool
	 */
	private static function differs( array $values, array $old ): bool {
		foreach ( $values as $field => $value ) {
			if ( ! array_key_exists( $field, $old ) || $old[ $field ] !== $value ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Post-write side effects the feature owns — grace periods, caches.
	 *
	 * @param array $row     Registry row.
	 * @param array $applied Settings as they read after the write.
	 * @param array $old     Settings as they read before it.
	 * @return void
	 */
	private static function run_after( array $row, array $applied, array $old ): void {
		if ( ! is_callable( $row['after'] ) ) {
			return;
		}
		try {
			call_user_func( $row['after'], $applied, $old );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium] settings_after_failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Stage the change for confirmation when the feature can lock its owner
	 * out. A feature switching itself off cannot, so it cancels the fuse
	 * instead of arming a new one.
	 *
	 * @param array $row     Registry row.
	 * @param array $applied Settings as they read after the write.
	 * @param array $old     Settings as they read before it.
	 * @return array{token:?string,expires_in:int}
	 */
	private static function stage( array $row, array $applied, array $old ): array {
		$none = array(
			'token'      => null,
			'expires_in' => 0,
		);

		$context = $row['pending'];
		if ( null === $context ) {
			return $none;
		}

		$stage = is_callable( $row['stage_when'] )
			? (bool) call_user_func( $row['stage_when'], $applied, $old )
			: true;

		if ( ! $stage ) {
			$existing = Segurium_Storage::setting_get( 'segurium_pending_ctx_' . $context, '' );
			if ( $existing ) {
				Segurium_Pending_Changes::cancel( $existing );
			}
			return $none;
		}

		return array(
			'token'      => Segurium_Pending_Changes::stage( $context, $old, $applied ),
			'expires_in' => Segurium_Pending_Changes::DEFAULT_TTL,
		);
	}

	/**
	 * Push the feature's snapshot to CTI. Registry secrets are stripped
	 * unless the feature's own builder puts them back — the alerts contact
	 * address is the one field CTI cannot do its job without.
	 *
	 * @param string $slug    Registry slug.
	 * @param array  $row     Registry row.
	 * @param array  $applied Settings as they read after the write.
	 * @return bool
	 */
	private static function report( string $slug, array $row, array $applied ): bool {
		if ( ! class_exists( 'Segurium_CTI_Client' ) ) {
			return false;
		}

		// Before the install has an IID there is nothing to address the
		// message to, and sending one would register synchronously inside
		// whatever request is saving the setting. The register body carries
		// the same fields, and the next save reports the rest.
		if ( null === Segurium_IID::get_iid() ) {
			return false;
		}

		if ( is_callable( $row['snapshot'] ) ) {
			$settings = (array) call_user_func( $row['snapshot'], $applied );
		} else {
			$settings = $applied;
			// The stored option row, minus the fields the row marks secret.
			// A list-backed field is neither: the addresses live in the
			// ip_list table, and an allow list is the operator's network
			// layout, not a preference the fleet view needs.
			foreach ( array_merge( $row['secret'], array_keys( $row['lists'] ) ) as $field ) {
				unset( $settings[ $field ] );
			}
		}

		return Segurium_Storage::cti_send_settings_snapshot( $slug, $settings );
	}

	/*
	 * ─────────────────────────────────────────────────────────────────────
	 * Result shape.
	 * ─────────────────────────────────────────────────────────────────────
	 */

	/**
	 * A blank result for one feature.
	 *
	 * @param string $slug Registry slug.
	 * @return array
	 */
	private static function result( string $slug ): array {
		return array(
			'ok'         => false,
			'slug'       => $slug,
			'changed'    => false,
			'applied'    => array(),
			'skipped'    => array(),
			'warnings'   => array(),
			'errors'     => array(),
			'token'      => null,
			'expires_in' => 0,
		);
	}

	/**
	 * Attach a reason code and hand the result back unwritten.
	 *
	 * @param array  $result  Result so far.
	 * @param string $code    Reason code.
	 * @param string $message Detail for the log.
	 * @return array
	 */
	private static function fail( array $result, string $code, string $message ): array {
		$result['errors'][] = array(
			'code'    => $code,
			'message' => $message,
		);
		if ( in_array( $code, self::OWN_CODES, true ) ) {
			Segurium_Debug::log(
				'[segurium] settings_save_refused slug=' . $result['slug'] . ' code=' . $code . ' ' . $message
			);
		}
		return $result;
	}

	/**
	 * Message to put in front of the operator for one refusal. A feature
	 * validator's own message is already translated and says something the
	 * operator can act on; the writer's own describe a fault, and those get
	 * one sentence plus a code in the log.
	 *
	 * @param array $error One entry from a result's `errors`.
	 * @return string
	 */
	public static function error_message( array $error ): string {
		$code = (string) ( $error['code'] ?? '' );
		if ( in_array( $code, self::OWN_CODES, true ) ) {
			return __( 'The setting could not be saved.', 'segurium' );
		}
		return (string) ( $error['message'] ?? '' );
	}
}

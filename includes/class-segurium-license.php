<?php
/**
 * Pro licence activation without a browser.
 *
 * One path for every caller. The Account tab drives the Freemius SDK's own
 * form; this class drives the same SDK from a command, so a fleet rollout
 * does not need a browser session per site.
 *
 * Two things about the SDK shape the code here:
 *
 *   - The plugin calls `skip_connection()` on every install, so `$fs` has no
 *     site object until a licence lands. `activate_license()` then takes its
 *     `opt_in()` branch, which never reaches `_sync_plugin_license()` — the
 *     one place `after_license_change` is fired. So `Segurium_Pro_Transition`
 *     does not run on its own here and this class calls it directly. The call
 *     is idempotent, so a hook that did fire costs nothing.
 *   - Freemius flattens its refusal to prose and drops the machine-readable
 *     code, and the two branches do not even refuse alike. The registered
 *     branch answers `{"error":{"code":…}}`, so the code is read back off the
 *     response. The opt-in branch answers `{"error":"<prose>"}` and carries no
 *     code at all, so on the path every field install takes the prose is the
 *     only signal there is. Both are mapped; an unrecognised refusal keeps the
 *     vendor's own words.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Activates, deactivates and reports the Pro licence.
 */
final class Segurium_License {

	const CONSTANT_KEY = 'SEGURIUM_LICENSE_KEY';

	/**
	 * Freemius issues fixed-width keys and refuses anything else with
	 * "License key must be 32 characters long." Checking locally turns a
	 * typo into an instant refusal instead of a round-trip.
	 */
	const KEY_LENGTH = 32;

	const CODE_OK               = 'ok';
	const CODE_ALREADY_ACTIVE   = 'already_active';
	const CODE_KEY_MISSING      = 'key_missing';
	const CODE_KEY_INVALID      = 'key_invalid';
	const CODE_CONSENT_REQUIRED = 'consent_required';
	const CODE_SDK_UNAVAILABLE  = 'sdk_unavailable';
	const CODE_INVALID          = 'invalid';
	const CODE_NO_SEATS         = 'no_seats';
	const CODE_BOUND_ELSEWHERE  = 'bound_elsewhere';
	const CODE_EXPIRED          = 'expired';
	const CODE_NETWORK_FAILURE  = 'network_failure';
	const CODE_REFUSED          = 'refused';
	const CODE_NOT_ACTIVE       = 'not_active';
	const CODE_RELEASE_FAILED   = 'release_failed';
	const CODE_NOT_CONFIRMED    = 'not_confirmed';

	const SOURCE_ARG      = 'argument';
	const SOURCE_CONSTANT = 'constant';

	/**
	 * Codes from `api.freemius.com`, which an install that already carries a
	 * Freemius user talks to. Anything outside this map falls through to the
	 * prose patterns below.
	 *
	 * @var array<string,string>
	 */
	const VENDOR_CODES = array(
		'invalid_license_key' => self::CODE_INVALID,
		'license_utilized'    => self::CODE_NO_SEATS,
		'license_expired'     => self::CODE_EXPIRED,
	);

	/**
	 * The opt-in endpoint an install with no Freemius user talks to answers
	 * `{"error":"<prose>"}` and carries no code at all, so prose is the only
	 * signal available on the path every field install takes.
	 *
	 * Matched case-insensitively, most specific first. A reworded vendor
	 * message costs a refusal its precise code and nothing else: the fallback
	 * is {@see self::CODE_REFUSED}, which still prints what Freemius said.
	 *
	 * @var array<string,string>
	 */
	const VENDOR_MESSAGES = array(
		'invalid license key'   => self::CODE_INVALID,
		'must be 32 characters' => self::CODE_KEY_INVALID,
		'already in use'        => self::CODE_BOUND_ELSEWHERE,
		'has been reached'      => self::CODE_NO_SEATS,
		'no more available'     => self::CODE_NO_SEATS,
		'has expired'           => self::CODE_EXPIRED,
		'license was cancelled' => self::CODE_EXPIRED,
	);

	/**
	 * Process-wide singleton.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Returns the Freemius SDK instance.
	 *
	 * @var callable
	 */
	private $sdk_accessor;

	/**
	 * Returns the pro-transition listener.
	 *
	 * @var callable
	 */
	private $transition_accessor;

	/**
	 * Performs one install-scope vendor API call.
	 *
	 * @var callable
	 */
	private $api_caller;

	/**
	 * Construct a licence controller.
	 *
	 * The accessors are pluggable so tests drive the class without a live
	 * Freemius SDK. In production each falls back to the real dependency.
	 *
	 * @param callable|null $sdk_accessor        Returns the Freemius SDK instance, or null.
	 * @param callable|null $transition_accessor Returns Segurium_Pro_Transition (or compatible).
	 * @param callable|null $api_caller          Signature ( $fs, $path, $method ); returns the decoded vendor response.
	 */
	public function __construct( $sdk_accessor = null, $transition_accessor = null, $api_caller = null ) {
		$this->sdk_accessor = is_callable( $sdk_accessor )
			? $sdk_accessor
			: static function () {
				return function_exists( 'segurium_fs' ) ? segurium_fs() : null;
			};

		$this->transition_accessor = is_callable( $transition_accessor )
			? $transition_accessor
			: static function () {
				return class_exists( 'Segurium_Pro_Transition' )
					? Segurium_Pro_Transition::instance()
					: null;
			};

		$this->api_caller = is_callable( $api_caller )
			? $api_caller
			: array( __CLASS__, 'install_scope_call' );
	}

	/**
	 * Process-wide singleton.
	 *
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Drop the singleton so the next caller builds a fresh one.
	 *
	 * @return void
	 */
	public static function reset_for_testing() {
		self::$instance = null;
	}

	/**
	 * Install a pre-built instance for tests.
	 *
	 * @param self $instance Replacement singleton.
	 * @return void
	 */
	public static function set_instance_for_testing( self $instance ) {
		self::$instance = $instance;
	}

	/**
	 * The key templated into wp-config, if any.
	 *
	 * @return string Empty when the constant is absent or not a string.
	 */
	public static function constant_key() {
		if ( ! defined( self::CONSTANT_KEY ) ) {
			return '';
		}
		$value = constant( self::CONSTANT_KEY );
		return is_string( $value ) ? trim( $value ) : '';
	}

	/**
	 * Activate a licence. An explicit key wins over the wp-config constant.
	 *
	 * @param string $key Optional. Licence key; falls back to the constant.
	 * @return array{ok:bool,code:string,source:string,vendor_code:string,vendor_message:string,state:array}
	 */
	public function activate( $key = '' ) {
		$key    = is_string( $key ) ? trim( $key ) : '';
		$source = '' !== $key ? self::SOURCE_ARG : self::SOURCE_CONSTANT;

		if ( '' === $key ) {
			$key = self::constant_key();
		}
		if ( '' === $key ) {
			return $this->result( false, self::CODE_KEY_MISSING, $source );
		}
		if ( ! self::key_is_wellformed( $key ) ) {
			return $this->result( false, self::CODE_KEY_INVALID, $source );
		}
		if ( class_exists( 'Segurium_Consent' ) && ! Segurium_Consent::given() ) {
			return $this->result( false, self::CODE_CONSENT_REQUIRED, $source );
		}

		$fs = $this->load_sdk();
		if ( null === $fs || ! method_exists( $fs, 'activate_migrated_license' ) ) {
			return $this->result( false, self::CODE_SDK_UNAVAILABLE, $source );
		}

		if ( $key === $this->active_key( $fs ) ) {
			// Still drive the follow-through. A first run can bind the
			// licence at Freemius and then fail to tell the cloud, which
			// leaves the site Free with the key already in place; re-running
			// the command is the operator's obvious repair and has to be
			// able to finish the job. The call is idempotent, so a site that
			// is already settled pays nothing for it.
			$this->drive_transition( $fs, 'activated' );
			return $this->result( true, self::CODE_ALREADY_ACTIVE, $source );
		}

		$vendor = new Segurium_License_Vendor_Error();
		$vendor->watch();
		try {
			$outcome = $fs->activate_migrated_license( $key );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-license] activate failed: code=exception — ' . $e->getMessage() );
			return $this->result( false, self::CODE_REFUSED, $source );
		} finally {
			$vendor->release();
		}

		if ( ! is_array( $outcome ) || empty( $outcome['success'] ) ) {
			$message = self::error_text( is_array( $outcome ) && isset( $outcome['error'] ) ? $outcome['error'] : null );
			return $this->result(
				false,
				$this->map_failure( $vendor->code(), $message, $vendor->answered() ),
				$source,
				$vendor->code(),
				$message
			);
		}

		// The SDK reports success as "no error was raised", which is not the
		// same as "a licence is now bound". An undecodable vendor body and a
		// checkout that ends in Freemius pending activation both leave the
		// flag true and the install still Free. Confirm against the SDK
		// rather than let a rollout script move on.
		if ( ! is_object( $this->license_object( $fs ) ) ) {
			return $this->result( false, self::CODE_NOT_CONFIRMED, $source );
		}

		$this->drive_transition( $fs, 'activated' );

		return $this->result( true, self::CODE_OK, $source );
	}

	/**
	 * Release the licence and free its seat.
	 *
	 * The SDK's own `_deactivate_license()` is protected and reachable only
	 * from the admin page behind a nonce, so the same sequence is assembled
	 * here from public methods.
	 *
	 * @return array{ok:bool,code:string,source:string,vendor_code:string,vendor_message:string,state:array}
	 */
	public function deactivate() {
		$fs = $this->load_sdk();
		if ( null === $fs || ! method_exists( $fs, '_get_license' ) ) {
			return $this->result( false, self::CODE_SDK_UNAVAILABLE, '' );
		}

		$license = $fs->_get_license();
		$site    = method_exists( $fs, 'get_site' ) ? $fs->get_site() : null;
		if ( ! is_object( $license ) || ! isset( $license->id ) || ! is_object( $site ) ) {
			return $this->result( false, self::CODE_NOT_ACTIVE, '' );
		}

		try {
			$response = call_user_func( $this->api_caller, $fs, '/licenses/' . $license->id . '.json', 'delete' );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-license] deactivate failed: code=exception — ' . $e->getMessage() );
			return $this->result( false, self::CODE_RELEASE_FAILED, '' );
		}

		if ( is_object( $response ) && isset( $response->error ) ) {
			$code    = is_object( $response->error ) && isset( $response->error->code ) ? (string) $response->error->code : '';
			$message = is_object( $response->error ) && isset( $response->error->message ) ? (string) $response->error->message : '';
			Segurium_Debug::log( '[segurium-license] deactivate refused: code=' . ( '' !== $code ? $code : 'unknown' ) );
			return $this->result( false, self::CODE_RELEASE_FAILED, '', $code, $message );
		}

		// `_update_site_license( null )` only clears the in-memory install;
		// the SDK's own handler persists separately. `sync_install()` cannot
		// be relied on for that — it writes nothing when the vendor call
		// fails, which would leave a site that has already given up its seat
		// still loading as Pro on the next request. Persist first, refresh
		// second.
		if ( method_exists( $fs, '_update_site_license' ) ) {
			$fs->_update_site_license( null );
		}
		if ( method_exists( $fs, 'store_site' ) && is_object( $fs->get_site() ) ) {
			$fs->store_site( $fs->get_site() );
		}
		if ( method_exists( $fs, 'sync_install' ) ) {
			$fs->sync_install( array(), true );
		}

		$this->drive_transition( $fs, 'cancelled' );

		return $this->result( true, self::CODE_OK, '' );
	}

	/**
	 * Current licence state, safe to print.
	 *
	 * @return array{is_pro:bool,plan_tier:string,license_id:string,license_key:string,constant_present:bool}
	 */
	public function state() {
		$fs      = $this->load_sdk();
		$license = is_object( $fs ) && method_exists( $fs, '_get_license' ) ? $fs->_get_license() : null;

		return array(
			'is_pro'           => $this->sdk_is_paying( $fs ),
			'plan_tier'        => class_exists( 'Segurium_Quota' ) ? (string) Segurium_Quota::plan_tier() : '',
			'license_id'       => is_object( $license ) && isset( $license->id ) ? (string) $license->id : '',
			'license_key'      => self::mask( $this->active_key( $fs ) ),
			'constant_present' => '' !== self::constant_key(),
		);
	}

	/**
	 * Freemius keys are fixed width and carry no whitespace. Anything else
	 * is a copy-paste accident and never reaches the vendor.
	 *
	 * @param string $key Candidate key.
	 * @return bool
	 */
	public static function key_is_wellformed( $key ) {
		if ( ! is_string( $key ) || self::KEY_LENGTH !== strlen( $key ) ) {
			return false;
		}
		return 1 !== preg_match( '/[\s\x00-\x1f\x7f]/', $key );
	}

	/**
	 * Show enough of a key to recognise it, never enough to reuse it.
	 *
	 * @param string $key Licence key.
	 * @return string
	 */
	public static function mask( $key ) {
		$key = (string) $key;
		if ( '' === $key ) {
			return '';
		}
		if ( strlen( $key ) <= 10 ) {
			return str_repeat( '*', strlen( $key ) );
		}
		return substr( $key, 0, 6 ) . str_repeat( '*', strlen( $key ) - 10 ) . substr( $key, -4 );
	}

	/**
	 * Turn a vendor refusal into one of our codes.
	 *
	 * @param string $vendor_code Freemius `error.code`, when recovered.
	 * @param string $message     Freemius prose, used only when no code arrived.
	 * @param bool   $answered    Whether the vendor responded at all.
	 * @return string
	 */
	private function map_failure( $vendor_code, $message, $answered = true ) {
		// A transport failure never reaches `http_response`, so silence from
		// the vendor is the reliable signal — more so than the prose, which
		// on that path is a WP_Error string that reads like anything.
		if ( ! $answered ) {
			return self::CODE_NETWORK_FAILURE;
		}

		if ( '' !== $vendor_code && isset( self::VENDOR_CODES[ $vendor_code ] ) ) {
			return self::VENDOR_CODES[ $vendor_code ];
		}

		$haystack = strtolower( $message );
		foreach ( self::VENDOR_MESSAGES as $needle => $code ) {
			if ( '' !== $haystack && false !== strpos( $haystack, $needle ) ) {
				return $code;
			}
		}

		if ( '' === $vendor_code && '' === $message ) {
			return self::CODE_NETWORK_FAILURE;
		}
		return self::CODE_REFUSED;
	}

	/**
	 * Read the vendor's message out of whatever `activate_license()` put in
	 * its `error` slot. The two branches do not agree: the opt-in branch
	 * hands back the raw error, which is an object whenever the request
	 * itself failed, and casting that to string is a fatal.
	 *
	 * @param mixed $error Whatever the SDK returned.
	 * @return string
	 */
	private static function error_text( $error ) {
		if ( is_string( $error ) ) {
			return $error;
		}
		if ( is_object( $error ) && isset( $error->message ) && is_string( $error->message ) ) {
			return $error->message;
		}
		if ( is_scalar( $error ) ) {
			return (string) $error;
		}
		return '';
	}

	/**
	 * The licence the SDK currently has bound, if any.
	 *
	 * @param object|null $fs Freemius SDK instance.
	 * @return object|null
	 */
	private function license_object( $fs ) {
		if ( ! is_object( $fs ) || ! method_exists( $fs, '_get_license' ) ) {
			return null;
		}
		$license = $fs->_get_license();
		return is_object( $license ) ? $license : null;
	}

	/**
	 * Run the plugin-side follow-through the SDK hook would have run.
	 *
	 * @param object $fs          Freemius SDK instance.
	 * @param string $plan_change Freemius change tag, for audit context.
	 * @return void
	 */
	private function drive_transition( $fs, $plan_change ) {
		$transition = call_user_func( $this->transition_accessor );
		if ( ! is_object( $transition ) || ! method_exists( $transition, 'on_license_change' ) ) {
			Segurium_Debug::log( '[segurium-license] follow-through skipped: code=transition_unavailable' );
			return;
		}
		$plan = method_exists( $fs, 'get_plan' ) ? $fs->get_plan() : null;
		try {
			$transition->on_license_change( $plan_change, $plan );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-license] follow-through failed: ' . $e->getMessage() );
		}
	}

	/**
	 * Build the install-scope API the SDK uses for licence calls. Assembled
	 * from public getters because `get_api_site_scope()` is private.
	 *
	 * @param object $fs     Freemius SDK instance.
	 * @param string $path   API path.
	 * @param string $method HTTP verb.
	 * @return mixed Decoded vendor response.
	 */
	private static function install_scope_call( $fs, $path, $method ) {
		$site = $fs->get_site();
		$api  = FS_Api::instance(
			$fs->get_id(),
			'install',
			$site->id,
			$site->public_key,
			! $fs->is_live(),
			$site->secret_key,
			$fs->get_sdk_version(),
			Freemius::get_unfiltered_site_url()
		);
		return $api->call( $path, $method );
	}

	/**
	 * Secret key of the licence currently bound to this install.
	 *
	 * @param object|null $fs Freemius SDK instance.
	 * @return string Secret key of the bound licence, or ''.
	 */
	private function active_key( $fs ) {
		if ( ! is_object( $fs ) || ! method_exists( $fs, '_get_license' ) ) {
			return '';
		}
		$license = $fs->_get_license();
		return is_object( $license ) && isset( $license->secret_key ) ? (string) $license->secret_key : '';
	}

	/**
	 * `is_paying()` is the only SDK predicate correct immediately after an
	 * activation; `is_registered()` still reports the pre-activation value
	 * in the same request.
	 *
	 * @param object|null $fs Freemius SDK instance.
	 * @return bool
	 */
	private function sdk_is_paying( $fs ) {
		if ( ! is_object( $fs ) || ! method_exists( $fs, 'is_paying' ) ) {
			return false;
		}
		try {
			return (bool) $fs->is_paying();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-license] is_paying failed: ' . $e->getMessage() );
			return false;
		}
	}

	/**
	 * Resolve the Freemius SDK instance.
	 *
	 * @return object|null
	 */
	private function load_sdk() {
		$fs = call_user_func( $this->sdk_accessor );
		return is_object( $fs ) ? $fs : null;
	}

	/**
	 * Build the return envelope every public method hands back.
	 *
	 * @param bool   $ok             Whether the operation did what was asked.
	 * @param string $code           One of the CODE_* constants.
	 * @param string $source         Where the key came from.
	 * @param string $vendor_code    Freemius `error.code`, when recovered.
	 * @param string $vendor_message Freemius prose, when present.
	 * @return array{ok:bool,code:string,source:string,vendor_code:string,vendor_message:string,state:array}
	 */
	private function result( $ok, $code, $source, $vendor_code = '', $vendor_message = '' ) {
		return array(
			'ok'             => (bool) $ok,
			'code'           => (string) $code,
			'source'         => (string) $source,
			'vendor_code'    => (string) $vendor_code,
			'vendor_message' => (string) $vendor_message,
			'state'          => $this->state(),
		);
	}
}

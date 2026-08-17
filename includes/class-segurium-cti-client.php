<?php
/**
 * CTI client for communicating with the Segurium cloud service.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * HTTP client for all Segurium CTI API endpoints.
 *
 * NOTE: every call in this class targets cti.segurium.com on TCP/8901, which
 * wp_http_validate_url() rejects (allowed cross-host ports are {80,443,8080}).
 * That is why we use wp_remote_* here instead of the safer wp_safe_remote_*
 * variants — the safe variants would refuse the request before it leaves
 * the site.
 */
class Segurium_CTI_Client {

	/**
	 * Kill-switch option for gzip-compressed `/v1/scan/submit` (and the
	 * inline-poll fallback that still wears the legacy `neo_ray_scan`
	 * name in PHP). String sentinel: `'0'` disables compression, any
	 * other value (including the absent / default state) enables it.
	 * String form sidesteps the WordPress `update_option('opt', false)`
	 * no-op when the option row does not yet exist.
	 *
	 * Option key is unchanged from SEGURIUM-443 for backward compat with
	 * sites that already wrote it; the constant name still reads as
	 * `OPTION_NEO_RAY_GZIP` for the same reason.
	 */
	const OPTION_NEO_RAY_GZIP = 'segurium_use_content_encoding_gzip';

	const BASE_URL                      = 'https://cti.segurium.com:8901';
	const ENDPOINT                      = 'https://cti.segurium.com:8901/v1/inspect';
	const SCAN_SUBMIT_ENDPOINT          = 'https://cti.segurium.com:8901/v1/scan/submit';
	const SCAN_RESULTS_ENDPOINT         = 'https://cti.segurium.com:8901/v1/scan/results';
	const CLEAN_ENDPOINT                = 'https://cti.segurium.com:8901/v1/cleanup';
	const MESSAGES_ENDPOINT             = 'https://cti.segurium.com:8901/v1/messages';
	const INTEGRITY_ENDPOINT            = 'https://cti.segurium.com:8901/v1/integrity/check';
	const ORIGINAL_ENDPOINT             = 'https://cti.segurium.com:8901/v1/integrity/original-content';
	const LOG_ACTION_ENDPOINT           = 'https://cti.segurium.com:8901/v1/integrity/log-action';
	const LOG_COMPONENT_ACTION_ENDPOINT = 'https://cti.segurium.com:8901/v1/integrity/log-component-action';
	const COMPONENTS_ENDPOINT           = 'https://cti.segurium.com:8901/v1/integrity/components';
	const GEO_DB_ENDPOINT               = 'https://cti.segurium.com:8901/v1/geo/db';
	const TRUSTED_PROXIES_ENDPOINT      = 'https://cti.segurium.com:8901/v1/geo/trusted-proxies';
	const SUPPORT_ENDPOINT              = 'https://cti.segurium.com:8901/v1/support/ticket';
	const SUBMISSIONS_ENDPOINT          = 'https://cti.segurium.com:8901/v1/submissions';
	// SEGURIUM-353: /v1/quota/consume removed. /v1/cleanup auto-consumes
	// the slot when it serves a body, so the plugin no longer needs a
	// separate consume hop. /v1/quota/state remains for the read-only
	// dashboard counter.
	// SEGURIUM-366: /v1/quota/reset is gone — quota resets are now an
	// operator action via the admin-only /v1/admin/quota/reset endpoint
	// on the local-bind listener. Pro IIDs already get unbounded
	// cleanups via plan-tier source-of-truth (SEGURIUM-348), so the
	// plugin has nothing to reset on Pro transition.
	const QUOTA_STATE_ENDPOINT = 'https://cti.segurium.com:8901/v1/quota/state';
	const PLATFORM_ENDPOINT    = 'https://cti.segurium.com:8901/v1/platform';
	// SEGURIUM-378: replaces the SEGURIUM-347 bind/unbind pair. CTI proves
	// install ownership by comparing fs_install_secret_key to the install's
	// secret in Freemius — the plugin sends a tuple, never a verdict.
	const BILLING_SYNC_ENDPOINT = 'https://cti.segurium.com:8901/v1/billing/sync';

	/**
	 * SEGURIUM-469: maximum number of HTTP attempts the scan-pipeline
	 * methods ({@see scan_submit()}, {@see scan_results()}) will make
	 * against /v1/scan/* before giving up. Includes the initial attempt
	 * — i.e. up to two retries after a transport error (WP_Error) or
	 * 5xx response. 4xx is treated as deterministic and never retried.
	 * Retries are immediate (no sleep) per direction on the ticket.
	 */
	const MAX_SCAN_ATTEMPTS = 3;

	/**
	 * SEGURIUM-578: wall-clock ceiling (seconds) for a single `/v1/inspect`
	 * POST. A healthy inspect (bloom + RocksDB hash lookups) answers in
	 * sub-second to a couple of seconds; a stalled gateway used to hang the
	 * worker tick for ~28s before a 504. 8s fails fast while still sitting
	 * above CTI's 5s server-side ceiling (SEGURIUM-404), so the plugin never
	 * times out before CTI can return its own bounded response/error. The
	 * verdict queue's bounded cross-tick retry then re-runs the batch instead
	 * of burning the files' verdict on one transient stall.
	 */
	const INSPECT_TIMEOUT_SEC = 8;

	/**
	 * SEGURIUM-745: `/v1/scan/submit` timeout used outside a runner tick —
	 * the realtime, upload and test paths, where `time_left_in_tick()`
	 * returns 0.0 because there is no budget to derive from.
	 */
	const SUBMIT_TIMEOUT_DEFAULT_SEC = 30;

	/**
	 * SEGURIUM-745: smallest remaining budget that still justifies a *retry*.
	 * Never applies to a batch's first attempt, which always runs with at
	 * least {@see SUBMIT_TIMEOUT_DEFAULT_SEC}. Matches
	 * `Segurium_Scan_Runner::TICK_BUDGET_MIN_SEC`.
	 */
	const SUBMIT_TIMEOUT_MIN_SEC = 5;

	/**
	 * SEGURIUM-745: hard ceiling for a derived submit timeout.
	 *
	 * No heartbeat is stamped while `wp_remote_post()` blocks — the runner
	 * stamps per file, before the POST — so a single upload must stay well
	 * inside `Segurium_Scan_Lock::HEARTBEAT_MAX_AGE` (60). Its docblock puts
	 * the longest legitimate gap at one in-flight RTT and sizes the 60 s
	 * around that; a longer POST makes `is_stale()` true and invites
	 * `run_watchdog()` to reclaim a scan that is uploading fine. The same
	 * ceiling keeps a POST under `compute_mutex_ttl()`, which caps at 300 s,
	 * so the tick mutex cannot lapse mid-upload and let a second worker into
	 * the same scan (the corruption SEGURIUM-426 closed). Without this a host
	 * with `max_execution_time = 600` would derive a 588 s timeout.
	 */
	const SUBMIT_TIMEOUT_MAX_SEC = 50;

	/**
	 * SEGURIUM-477: classification buckets returned by
	 * {@see classify_scan_response()}. Stringly-typed enum so callers
	 * can `switch` / `===` on stable symbols instead of magic strings.
	 *
	 * `SCAN_CLASS_DROP` is advisory — the inner retry loop only checks
	 * for `SCAN_CLASS_RETRY`, so DROP and PAUSE both break the loop;
	 * the post-loop branch distinguishes them by checking for PAUSE.
	 */
	const SCAN_CLASS_OK    = 'ok';
	const SCAN_CLASS_RETRY = 'retry';
	const SCAN_CLASS_PAUSE = 'pause';
	const SCAN_CLASS_DROP  = 'drop';

	/**
	 * SEGURIUM-376: standard authenticated-request headers — the IID
	 * bearer plus the per-request fingerprint the CTI knock middleware
	 * checks against the anchor. Centralised so the four inline-multipart
	 * paths (support, submissions, neo-ray, ad-hoc) carry the same set
	 * as the JSON path through `request()`.
	 *
	 * @param string $iid Already-resolved IID string.
	 * @return array<string,string>
	 */
	private function auth_headers( $iid ) {
		return array(
			'X-Segurium-IID' => $iid,
			'X-Fingerprint'  => Segurium_IID::fingerprint_header(),
		);
	}

	/**
	 * Returns the current IID string, attempting registration if absent.
	 * Returns WP_Error if IID cannot be obtained.
	 *
	 * @return string|WP_Error
	 */
	private function ensure_iid() {
		$iid = Segurium_IID::get_iid();
		if ( $iid ) {
			return $iid;
		}
		Segurium_IID::maybe_register();
		$iid = Segurium_IID::get_iid();
		if ( $iid ) {
			return $iid;
		}
		return new WP_Error(
			'cti_no_iid',
			__( 'Installation ID unavailable. Please ensure the plugin is properly activated.', 'segurium' )
		);
	}

	/**
	 * Classify a /v1/scan/* HTTP response into one of the SCAN_CLASS_*
	 * buckets, returning the bucket plus any parsed Retry-After.
	 *
	 * - OK    : 2xx success. `retry_after` is pre-emptive pacing.
	 * - RETRY : inline-retriable — WP_Error or 5xx with no Retry-After.
	 *           4xx that isn't 429 is NOT inline-retriable; retrying a
	 *           deterministic server-side rejection just wastes bandwidth.
	 * - PAUSE : back-off signal — 429 (any) or 5xx with Retry-After.
	 *           Inner loop must break; caller propagates `retry_after`
	 *           so the scan-runner can stamp the IID-scoped pause.
	 * - DROP  : deterministic 4xx other than 429.
	 *
	 * @param mixed $response wp_remote_* return value.
	 * @return array{mode:string,retry_after:int}
	 */
	private function classify_scan_response( $response ) {
		if ( is_wp_error( $response ) ) {
			return array(
				'mode'        => self::SCAN_CLASS_RETRY,
				'retry_after' => 0,
			);
		}
		$code        = (int) wp_remote_retrieve_response_code( $response );
		$retry_after = $this->parse_retry_after( $response );
		if ( $code >= 200 && $code < 300 ) {
			return array(
				'mode'        => self::SCAN_CLASS_OK,
				'retry_after' => $retry_after,
			);
		}
		if ( 429 === $code ) {
			return array(
				'mode'        => self::SCAN_CLASS_PAUSE,
				'retry_after' => $retry_after,
			);
		}
		if ( $code >= 500 && $code < 600 ) {
			return array(
				'mode'        => $retry_after > 0 ? self::SCAN_CLASS_PAUSE : self::SCAN_CLASS_RETRY,
				'retry_after' => $retry_after,
			);
		}
		return array(
			'mode'        => self::SCAN_CLASS_DROP,
			'retry_after' => 0,
		);
	}

	/**
	 * SEGURIUM-745: wall-clock ceiling for one `/v1/scan/submit` POST.
	 *
	 * Implements the discipline already documented on
	 * {@see Segurium_Scan_Runner::time_left_in_tick()}:
	 * `min(known_max_call_time, time_left_in_tick() - safety)`. There is no
	 * upper constant, because the host's own `max_execution_time` already
	 * bounds `tick_budget()` — a site with a 300s limit may spend a genuinely
	 * long time on one 34 MB upload, and a site with 30s may not.
	 *
	 * A batch's first attempt never drops below {@see SUBMIT_TIMEOUT_DEFAULT_SEC},
	 * so this method can only widen the pre-745 window, never narrow it. That
	 * floor is not politeness: the end-of-chunk tail flush fires immediately
	 * after `time_allows_next_unknown()` yields at the 2 s safety floor, so a
	 * budget-derived value there would be ~0. Squeezing a 10 MiB buffer into
	 * that window fails, and
	 * {@see Segurium_Verdict_Queue::flush_async_submitter()} counts every
	 * buffered file as `failed` / `neoray_errors` — the submitter is
	 * call-local, so its restored buffer dies with the object while the files
	 * have already been shifted off the cursor's `unknown_queue`. Overrunning
	 * a spent budget is recoverable; losing the files is not.
	 *
	 * Retries take the raw remaining window instead, so a retry can only ever
	 * shorten the tick's overrun, never extend it.
	 *
	 * Callers reach this only from {@see scan_submit()}, which already depends
	 * on `Segurium_Scan_Runner` unconditionally.
	 *
	 * @param bool $is_first_attempt Whether this is the batch's first attempt.
	 * @return int Timeout in seconds.
	 */
	private static function submit_timeout_secs( $is_first_attempt ) {
		if ( ! Segurium_Scan_Runner::in_tick() ) {
			return self::SUBMIT_TIMEOUT_DEFAULT_SEC;
		}
		$usable = (int) floor(
			(float) Segurium_Scan_Runner::time_left_in_tick()
			- (float) Segurium_Scan_Runner::TICK_GRACEFUL_EXIT_SAFETY_SEC
		);
		if ( $is_first_attempt ) {
			$usable = max( self::SUBMIT_TIMEOUT_DEFAULT_SEC, $usable );
		}
		return min( self::SUBMIT_TIMEOUT_MAX_SEC, $usable );
	}

	/**
	 * SEGURIUM-745: whether the tick can still afford another attempt.
	 *
	 * Only gates *retries*. The first attempt always runs, because dropping a
	 * batch costs the files (see {@see submit_timeout_secs()}), while a retry
	 * that cannot fit is pure overrun — and when the previous attempt died on
	 * its own timeout, a shorter retry over the same link cannot succeed
	 * anyway. Transient failures (DNS, TLS, 5xx) return fast and leave the
	 * budget intact, which is the case the retry loop actually exists for.
	 *
	 * @return bool
	 */
	private static function submit_budget_allows_retry() {
		if ( ! Segurium_Scan_Runner::in_tick() ) {
			return true;
		}
		$usable = (float) Segurium_Scan_Runner::time_left_in_tick()
			- (float) Segurium_Scan_Runner::TICK_GRACEFUL_EXIT_SAFETY_SEC;
		return $usable >= (float) self::SUBMIT_TIMEOUT_MIN_SEC;
	}

	/**
	 * Parse the RFC 7231 `Retry-After` header. Accepts both
	 * delta-seconds ("42") and HTTP-date forms ("Wed, 21 Oct 2026
	 * 07:28:00 GMT"). HTTP-date is converted to a positive delta vs.
	 * `time()`; past dates and parse failures both return 0 (treated
	 * as no header). No floor — companion CTI ADR §2.3.4 emits dynamic
	 * values that may legitimately be small.
	 *
	 * @param array|WP_Error $response HTTP response.
	 * @return int Seconds the caller should pause; 0 on missing/invalid.
	 */
	private function parse_retry_after( $response ) {
		if ( is_wp_error( $response ) ) {
			return 0;
		}
		$raw = wp_remote_retrieve_header( $response, 'retry-after' );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return 0;
		}
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return 0;
		}
		if ( ctype_digit( $raw ) ) {
			return (int) $raw;
		}
		$ts = strtotime( $raw );
		if ( false === $ts || $ts <= 0 ) {
			return 0;
		}
		$delta = $ts - time();
		return $delta > 0 ? $delta : 0;
	}

	/**
	 * Emit a `scan_*_pause` debug event and return the matching
	 * `cti_paused` WP_Error. Shared by both /v1/scan/submit and
	 * /v1/scan/results so the error shape stays identical: callers
	 * inspect `get_error_data()` for `status` and `retry_after`.
	 *
	 * @param array  $response  Raw wp_remote_* response (NOT a WP_Error;
	 *                          we already know we're on the pause path).
	 * @param string $endpoint  e.g. '/v1/scan/submit'.
	 * @param string $event     Debug event name, e.g. 'scan_submit_pause'.
	 * @param string $label     Short verb for the error message body.
	 * @param int    $attempts  Number of attempts already made.
	 * @param float  $wall_ms   Cumulative wall time across attempts.
	 * @param int    $retry_after Seconds the caller should pause.
	 * @return WP_Error
	 */
	private function pause_error( $response, $endpoint, $event, $label, $attempts, $wall_ms, $retry_after ) {
		$http_code = (int) wp_remote_retrieve_response_code( $response );
		// SEGURIUM-483: emit on the unified `scan_submit_pause` event with
		// the spec's normalized field names. The `endpoint` field is the
		// short label (`submit` / `results`) that matches
		// `Segurium_Async_Scan_Pause::ENDPOINT_*` constants.
		Segurium_Scan_Runner::debug(
			'scan_submit_pause',
			array(
				'endpoint'           => '/v1/scan/results' === $endpoint
					? Segurium_Async_Scan_Pause::ENDPOINT_RESULTS
					: Segurium_Async_Scan_Pause::ENDPOINT_SUBMIT,
				'retry_after_secs'   => (int) $retry_after,
				'reason_http_status' => $http_code,
				'wall_ms'            => $wall_ms,
				'attempts'           => $attempts,
			)
		);
		return new WP_Error(
			'cti_paused',
			sprintf( '%s paused (HTTP %d, Retry-After %ds)', $label, $http_code, $retry_after ),
			array(
				'status'      => $http_code,
				'retry_after' => $retry_after,
			)
		);
	}

	/**
	 * SEGURIUM-376: detect the CTI knock middleware's re-register signal.
	 * Two indicators, either is sufficient:
	 *   1. `X-Segurium-Reregister: true` response header (the canonical
	 *      contract emitted by SEGURIUM-372's middleware).
	 *   2. HTTP 409 status with body `{"action":"re_register"}` (defensive
	 *      — a future server-side variant or a load balancer stripping the
	 *      header would still trip this).
	 *
	 * The clearing/notice/admin_init re-register flow is centralised in
	 * `Segurium_IID::mark_reregister_pending()`; we never re-register
	 * synchronously inside the request that got bounced.
	 *
	 * @param array|WP_Error $response HTTP response or error.
	 * @return void
	 */
	private function maybe_reregister( $response ) {
		if ( is_wp_error( $response ) ) {
			return;
		}
		if ( 'true' === wp_remote_retrieve_header( $response, 'x-segurium-reregister' ) ) {
			Segurium_IID::mark_reregister_pending();
			return;
		}
		if ( 409 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			if ( is_array( $body ) && isset( $body['action'] ) && 're_register' === $body['action'] ) {
				Segurium_IID::mark_reregister_pending();
			}
		}
	}

	/**
	 * Shared HTTP request helper for all authenticated CTI calls.
	 *
	 * Handles IID retrieval, header setup, the wp_remote_* call, and the
	 * x-segurium-reregister response. Returns either a WP_Error (no IID or
	 * network failure) or the raw `$response` array — callers are responsible
	 * for status-code interpretation and body parsing.
	 *
	 * @param string $url  Endpoint URL.
	 * @param array  $opts Options array.
	 *     @type string $method   'POST' (default) or 'GET'.
	 *     @type mixed  $body     PHP value to JSON-encode and send. Omit/null for no body.
	 *     @type int    $timeout  Request timeout in seconds (default 30).
	 *     @type bool   $blocking Whether to wait for the response (default true).
	 * @return array|WP_Error
	 */
	private function request( $url, $opts = array() ) {
		$opts = array_merge(
			array(
				'method'   => 'POST',
				'body'     => null,
				'timeout'  => 30,
				'blocking' => true,
				'headers'  => array(),
			),
			$opts
		);

		$iid = $this->ensure_iid();
		if ( is_wp_error( $iid ) ) {
			return $iid;
		}

		$args = array(
			'headers'  => array_merge(
				$this->auth_headers( $iid ),
				is_array( $opts['headers'] ) ? $opts['headers'] : array()
			),
			'timeout'  => $opts['timeout'],
			'blocking' => $opts['blocking'],
		);

		if ( null !== $opts['body'] ) {
			$args['headers']['Content-Type'] = 'application/json';
			$args['body']                    = wp_json_encode( $opts['body'] );
		}

		$response = ( 'GET' === $opts['method'] )
			? wp_remote_get( $url, $args )
			: wp_remote_post( $url, $args );

		$this->maybe_reregister( $response );

		return $response;
	}

	/**
	 * Check whether the CTI service is reachable.
	 *
	 * @return bool True if the health endpoint returns HTTP 200.
	 */
	public function health() {
		$response = wp_remote_get(
			self::BASE_URL . '/health',
			array(
				'timeout' => 5,
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		return 200 === wp_remote_retrieve_response_code( $response );
	}

	/**
	 * Submit a support ticket to the CTI service.
	 *
	 * When `$attachments` is non-empty the request switches to a
	 * multipart body so each attachment rides through to the support
	 * backend (used by the FN "Report missed malware" flow). Each
	 * attachment is `[filename => string, data => bytes]`.
	 *
	 * @param array $data        Ticket data.
	 * @param array $attachments Optional list of attachments.
	 * @return array|WP_Error Parsed response or error.
	 */
	public function submit_support_ticket( $data, $attachments = array() ) {
		if ( empty( $attachments ) ) {
			$response = $this->request(
				self::SUPPORT_ENDPOINT,
				array(
					'body'    => $data,
					'timeout' => 15,
				)
			);
		} else {
			$iid = $this->ensure_iid();
			if ( is_wp_error( $iid ) ) {
				return $iid;
			}

			$boundary = '----segsupp' . wp_generate_password( 16, false, false );
			$body     = '';
			$add_text = function ( $name, $value ) use ( &$body, $boundary ) {
				$body .= '--' . $boundary . "\r\n"
					. 'Content-Disposition: form-data; name="' . $name . "\"\r\n\r\n"
					. (string) $value . "\r\n";
			};
			foreach ( array( 'subject', 'type', 'message', 'name', 'email' ) as $field ) {
				$add_text( $field, isset( $data[ $field ] ) ? $data[ $field ] : '' );
			}
			if ( isset( $data['diagnostics'] ) ) {
				$add_text( 'diagnostics', wp_json_encode( $data['diagnostics'] ) );
			}
			foreach ( $attachments as $att ) {
				if ( ! is_array( $att ) || empty( $att['data'] ) ) {
					continue;
				}
				$fname = isset( $att['filename'] ) ? (string) $att['filename'] : 'attachment.bin';
				$body .= '--' . $boundary . "\r\n"
					. 'Content-Disposition: form-data; name="attachments[]"; filename="' . $fname . "\"\r\n"
					. "Content-Type: application/octet-stream\r\n\r\n"
					. $att['data'] . "\r\n";
			}
			$body .= '--' . $boundary . "--\r\n";

			$response = wp_remote_post(
				self::SUPPORT_ENDPOINT,
				array(
					'headers' => array_merge(
						$this->auth_headers( $iid ),
						array( 'Content-Type' => 'multipart/form-data; boundary=' . $boundary )
					),
					'body'    => $body,
					'timeout' => 60,
				)
			);
			$this->maybe_reregister( $response );
		}
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = wp_remote_retrieve_response_code( $response );
		if ( 429 === $code ) {
			return new WP_Error( 'support_rate_limit', __( 'Too many requests. Please try again later.', 'segurium' ) );
		}
		if ( $code < 200 || $code >= 300 ) {
			$body    = trim( wp_remote_retrieve_body( $response ) );
			$message = $body ? $body : sprintf(
				/* translators: %d: HTTP status code */
				__( 'Support service error (HTTP %d).', 'segurium' ),
				$code
			);
			return new WP_Error( 'cti_error', $message, $code );
		}
		return json_decode( wp_remote_retrieve_body( $response ), true );
	}

	/**
	 * Submit a FP/FN sample body to CTI's /v1/submissions endpoint.
	 *
	 * Builds a multipart body manually (boundary + fields) so we don't
	 * depend on a separate HTTP client. The body is gzip-compressed by the
	 * caller; meta is JSON-encoded as a single text field.
	 *
	 * @param array  $meta Meta fields: report_type, sha256, size_raw,
	 *                     path, note, admin_name, admin_email, site_domain.
	 * @param string $gzip_body Gzip-compressed body bytes.
	 * @return array|WP_Error Decoded JSON on 200, WP_Error otherwise.
	 */
	public function submit_fp( $meta, $gzip_body ) {
		if ( ! is_array( $meta ) || empty( $meta['sha256'] ) ) {
			return new WP_Error( 'cti_invalid_args', 'submit_fp requires meta.sha256' );
		}
		if ( ! is_string( $gzip_body ) || '' === $gzip_body ) {
			return new WP_Error( 'cti_invalid_args', 'submit_fp requires a non-empty gzipped body' );
		}

		$iid = $this->ensure_iid();
		if ( is_wp_error( $iid ) ) {
			return $iid;
		}

		$boundary = '----segsub' . wp_generate_password( 16, false, false );
		$body     = '';
		$add      = function ( $name, $value ) use ( &$body, $boundary ) {
			$body .= '--' . $boundary . "\r\n"
				. 'Content-Disposition: form-data; name="' . $name . "\"\r\n\r\n"
				. $value . "\r\n";
		};
		$add( 'meta', wp_json_encode( $meta ) );
		$add( 'encoding', 'gzip' );
		$body .= '--' . $boundary . "\r\n"
			. 'Content-Disposition: form-data; name="body"; filename="' . $meta['sha256'] . ".bin\"\r\n"
			. "Content-Type: application/octet-stream\r\n\r\n"
			. $gzip_body . "\r\n"
			. '--' . $boundary . "--\r\n";

		$response = wp_remote_post(
			self::SUBMISSIONS_ENDPOINT,
			array(
				'headers' => array_merge(
					$this->auth_headers( $iid ),
					array( 'Content-Type' => 'multipart/form-data; boundary=' . $boundary )
				),
				'body'    => $body,
				'timeout' => 60,
			)
		);
		$this->maybe_reregister( $response );

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'cti_transport_error', $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$raw     = (string) wp_remote_retrieve_body( $response );
			$decoded = json_decode( $raw, true );
			$err     = 'cti_http_error';
			$msg     = sprintf( 'Submission HTTP %d', (int) $code );
			if ( is_array( $decoded ) && ! empty( $decoded['error'] ) ) {
				$err = 'cti_submissions_' . preg_replace( '/[^a-z0-9_]/', '_', strtolower( (string) $decoded['error'] ) );
				if ( ! empty( $decoded['message'] ) ) {
					$msg = (string) $decoded['message'];
				}
			}
			return new WP_Error( $err, $msg, array( 'status' => $code ) );
		}
		$decoded = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $decoded ) ) {
			return new WP_Error( 'cti_invalid_response', 'Invalid submissions response' );
		}
		return $decoded;
	}

	/**
	 * Send file hashes to CTI for malware verdict inspection.
	 *
	 * @param array  $files   Array of file records with SHA-256 hashes.
	 * @param string $scan_id Plugin-side scan UUID. Logged into
	 *                        `segurium.file_check.scan_id` server-side
	 *                        for per-scan analytics; safe to omit
	 *                        (CTI accepts requests without it).
	 * @return array|WP_Error Array of verdict results or error.
	 */
	public function inspect( $files, $scan_id = '' ) {
		$count   = is_array( $files ) ? count( $files ) : 0;
		$scan_id = (string) $scan_id;
		Segurium_Scan_Runner::debug(
			'inspect_send',
			array(
				'endpoint' => '/v1/inspect',
				'count'    => $count,
				'scan_id'  => $scan_id,
			)
		);
		$body = array( 'files' => $files );
		if ( '' !== $scan_id ) {
			$body['scan_id'] = $scan_id;
		}
		$t0       = microtime( true );
		$response = $this->request(
			self::ENDPOINT,
			array(
				'body'    => $body,
				'timeout' => self::INSPECT_TIMEOUT_SEC,
			)
		);
		$wall_ms  = ( microtime( true ) - $t0 ) * 1000.0;
		if ( is_wp_error( $response ) ) {
			Segurium_Scan_Runner::debug(
				'inspect_error',
				array(
					'endpoint' => '/v1/inspect',
					'count'    => $count,
					'wall_ms'  => $wall_ms,
					'code'     => $response->get_error_code(),
					'message'  => $response->get_error_message(),
				)
			);
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			Segurium_Scan_Runner::debug(
				'inspect_error',
				array(
					'endpoint' => '/v1/inspect',
					'count'    => $count,
					'wall_ms'  => $wall_ms,
					'http'     => (int) $code,
					'code'     => 'cti_http_error',
				)
			);
			// SEGURIUM-578: carry the status code so the verdict queue can
			// tell a transient 5xx (retry) from a permanent 4xx (give up).
			return new WP_Error( 'cti_http_error', 'CTI returned HTTP ' . $code, array( 'status' => (int) $code ) );
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ! isset( $data['results'] ) ) {
			Segurium_Scan_Runner::debug(
				'inspect_error',
				array(
					'endpoint' => '/v1/inspect',
					'count'    => $count,
					'wall_ms'  => $wall_ms,
					'http'     => 200,
					'code'     => 'cti_invalid_response',
				)
			);
			return new WP_Error( 'cti_invalid_response', 'Invalid CTI response' );
		}

		Segurium_Scan_Runner::debug(
			'inspect_recv',
			array(
				'endpoint' => '/v1/inspect',
				'count'    => $count,
				'wall_ms'  => $wall_ms,
				'http'     => 200,
				'results'  => is_array( $data['results'] ) ? count( $data['results'] ) : 0,
			)
		);

		return $data['results'];
	}

	/**
	 * Submit a batch of file bodies to the async scan pipeline.
	 *
	 * SEGURIUM-456: replaces the synchronous `/v1/neo-ray` upload. The
	 * plugin POSTs a multipart batch (meta JSON + one part per file, part
	 * name = the claimed sha256 hex) to `/v1/scan/submit`. Body is
	 * gzip-compressed using the SEGURIUM-443 transport (kill-switch
	 * {@see OPTION_NEO_RAY_GZIP}); server decompresses and re-hashes each
	 * part. Verdicts arrive asynchronously via {@see scan_results()} —
	 * this call returns only the accepted/rejected manifest plus a
	 * `next_seq` cursor.
	 *
	 * Limits (enforced server-side and pre-checked here so we never POST
	 * a request CTI is guaranteed to reject): 10 MiB total body, 200
	 * files per batch, 100 MiB per single file.
	 *
	 * @param string $scan_id         Plugin-side scan-run UUID (one per
	 *                                full scan; many submits share it).
	 * @param string $client_batch_id Idempotency key for this POST. Same
	 *                                value + same iid within 24 h yields
	 *                                the same accept/reject decision.
	 * @param array  $files           List of `{sha256, path, body}`. `body`
	 *                                is the raw bytes; `path` rides into
	 *                                the meta JSON and CTI's analytics.
	 * @return array|WP_Error `{accepted, rejected, next_seq}` on 200,
	 *                       WP_Error on transport / HTTP / decode failure.
	 */
	public function scan_submit( $scan_id, $client_batch_id, $files ) {
		// SEGURIUM-689: the only route that ships file bytes on its own,
		// without the user naming the file. `neo_ray_scan()` reaches the
		// network through here too. The two user-initiated uploads
		// ({@see submit_fp()}, {@see submit_support_ticket()}) stay open
		// on purpose: the user picks that file by hand each time.
		//
		// The gate sits ahead of every argument check because a caller
		// that forgets it must still be unable to leak a body — same
		// reasoning as the SEGURIUM-295 consent gate. Anything automatic
		// added to submit_fp() would need its own gate.
		if ( Segurium_Storage::on_premise_mode() ) {
			Segurium_Debug::log(
				'[segurium-cti] scan_submit blocked: on-premise mode keeps file contents on the server'
			);
			return new WP_Error(
				'cti_on_premise_blocked',
				'scan_submit blocked: on-premise mode keeps file contents on the server'
			);
		}

		$scan_id         = is_string( $scan_id ) ? trim( $scan_id ) : '';
		$client_batch_id = is_string( $client_batch_id ) ? trim( $client_batch_id ) : '';
		if ( '' === $scan_id || '' === $client_batch_id ) {
			return new WP_Error( 'cti_invalid_args', 'scan_submit requires scan_id and client_batch_id' );
		}
		if ( ! is_array( $files ) || empty( $files ) ) {
			return new WP_Error( 'cti_invalid_args', 'scan_submit requires a non-empty files array' );
		}
		if ( count( $files ) > 100 ) {
			return new WP_Error( 'cti_invalid_args', 'scan_submit max 100 files per batch' );
		}

		$meta_files    = array();
		$normal_files  = array();
		$total_payload = 0;
		foreach ( $files as $f ) {
			$sha = isset( $f['sha256'] ) ? strtolower( (string) $f['sha256'] ) : '';
			if ( ! preg_match( '/^[0-9a-f]{64}$/', $sha ) ) {
				return new WP_Error( 'cti_invalid_hash', 'scan_submit requires a 64-char hex SHA-256 per file' );
			}
			$body = isset( $f['body'] ) ? (string) $f['body'] : '';
			if ( '' === $body ) {
				return new WP_Error( 'cti_empty_body', 'scan_submit requires non-empty file bodies' );
			}
			$size = strlen( $body );
			if ( $size > Segurium_Async_Scan_Submitter::MAX_SINGLE_FILE_SIZE ) {
				return new WP_Error( 'cti_file_too_large', 'scan_submit single-file cap is 100 MiB' );
			}
			$path           = isset( $f['path'] ) ? (string) $f['path'] : '';
			$meta_files[]   = array(
				'hash' => 'sha256:' . $sha,
				'path' => $path,
				'size' => $size,
			);
			$normal_files[] = array(
				'sha256' => $sha,
				'body'   => $body,
			);
			$total_payload += $size;
		}
		// SEGURIUM-474: the 10 MiB cap applies to multi-file batches only.
		// A single file is allowed to take the whole batch on its own up
		// to the single-file cap (100 MiB) so files between 10 and 100
		// MiB still get scanned instead of being permanently failed.
		$multi_file = count( $normal_files ) > 1;
		$cap_bytes  = $multi_file
			? Segurium_Async_Scan_Submitter::MAX_BATCH_BYTES
			: Segurium_Async_Scan_Submitter::MAX_SINGLE_FILE_SIZE;
		if ( $total_payload > $cap_bytes ) {
			$msg = $multi_file
				? 'scan_submit multi-file batch body cap is 10 MiB'
				: 'scan_submit single-file body cap is 100 MiB';
			return new WP_Error( 'cti_batch_too_large', $msg );
		}

		$iid = $this->ensure_iid();
		if ( is_wp_error( $iid ) ) {
			return $iid;
		}

		$boundary = '----segscan' . wp_generate_password( 16, false, false );
		$meta_str = (string) wp_json_encode(
			array(
				'scan_id'         => $scan_id,
				'client_batch_id' => $client_batch_id,
				'files'           => $meta_files,
			)
		);

		$body = '--' . $boundary . "\r\n"
			. "Content-Disposition: form-data; name=\"meta\"\r\n"
			. "Content-Type: application/json\r\n\r\n"
			. $meta_str . "\r\n";
		foreach ( $normal_files as $f ) {
			$body .= '--' . $boundary . "\r\n"
				. 'Content-Disposition: form-data; name="' . $f['sha256'] . "\"\r\n"
				. "Content-Type: application/octet-stream\r\n\r\n"
				. $f['body'] . "\r\n";
		}
		$body .= '--' . $boundary . "--\r\n";

		$raw_size_b   = strlen( $body );
		$wire_body    = $body;
		$wire_size_b  = $raw_size_b;
		$wire_headers = array_merge(
			$this->auth_headers( $iid ),
			array( 'Content-Type' => 'multipart/form-data; boundary=' . $boundary )
		);
		// SEGURIUM-443 / SEGURIUM-456: same gzip transport as the legacy
		// /v1/neo-ray path. Server decompresses, then multipart-parses,
		// then re-hashes each file part. Skip if compression made it
		// bigger (tiny payloads).
		$gzip_enabled = '0' !== (string) Segurium_Storage::setting_get( self::OPTION_NEO_RAY_GZIP, '1' );
		if ( $gzip_enabled && function_exists( 'gzencode' ) ) {
			$compressed = gzencode( $body, 6 );
			if ( is_string( $compressed ) && strlen( $compressed ) > 0 && strlen( $compressed ) < $raw_size_b ) {
				$wire_body                        = $compressed;
				$wire_size_b                      = strlen( $compressed );
				$wire_headers['Content-Encoding'] = 'gzip';
			}
		}

		Segurium_Scan_Runner::debug(
			'scan_submit_send',
			array(
				'endpoint'        => '/v1/scan/submit',
				'scan_id'         => $scan_id,
				'client_batch_id' => $client_batch_id,
				'files'           => count( $normal_files ),
				'raw_b'           => $raw_size_b,
				'wire_b'          => $wire_size_b,
				'gzip'            => isset( $wire_headers['Content-Encoding'] ),
			)
		);

		$post_args = array(
			'headers'  => $wire_headers,
			'body'     => $wire_body,
			'blocking' => true,
		);

		// Inline retry on WP_Error / 5xx without Retry-After only.
		// 429 and 5xx-with-Retry-After exit the loop and surface as
		// `cti_paused` — re-trying a back-off signal just amplifies the
		// overload the server is telling us to avoid.
		$attempt  = 0;
		$wall_ms  = 0.0;
		$response = null;
		$class    = array(
			'mode'        => self::SCAN_CLASS_RETRY,
			'retry_after' => 0,
		);
		while ( $attempt < self::MAX_SCAN_ATTEMPTS ) {
			// SEGURIUM-745: stop retrying once the budget is spent, but never
			// skip the first attempt — see submit_budget_allows_retry().
			if ( $attempt > 0 && ! self::submit_budget_allows_retry() ) {
				Segurium_Scan_Runner::debug(
					'scan_submit_retry_budget_spent',
					array(
						'endpoint'  => '/v1/scan/submit',
						'scan_id'   => $scan_id,
						'attempts'  => $attempt,
						'time_left' => Segurium_Scan_Runner::time_left_in_tick(),
						'min_sec'   => self::SUBMIT_TIMEOUT_MIN_SEC,
					)
				);
				break;
			}
			// Recompute per attempt so three of them cannot outlive the tick
			// that started them. One value computed once is what let 3 x 30s
			// run inside a 50s budget.
			$post_args['timeout'] = self::submit_timeout_secs( 0 === $attempt );
			++$attempt;
			$t0           = microtime( true );
			$response     = wp_remote_post( self::SCAN_SUBMIT_ENDPOINT, $post_args );
			$attempt_wall = ( microtime( true ) - $t0 ) * 1000.0;
			$wall_ms     += $attempt_wall;
			$class        = $this->classify_scan_response( $response );
			if ( self::SCAN_CLASS_RETRY !== $class['mode'] || $attempt >= self::MAX_SCAN_ATTEMPTS ) {
				break;
			}
			Segurium_Scan_Runner::debug(
				'scan_submit_retry',
				array(
					'endpoint'  => '/v1/scan/submit',
					'attempt'   => $attempt,
					'remaining' => self::MAX_SCAN_ATTEMPTS - $attempt,
					'wall_ms'   => $attempt_wall,
					'reason'    => is_wp_error( $response )
						? 'transport:' . $response->get_error_message()
						: 'http_' . wp_remote_retrieve_response_code( $response ),
				)
			);
		}
		$this->maybe_reregister( $response );

		if ( self::SCAN_CLASS_PAUSE === $class['mode'] ) {
			return $this->pause_error(
				$response,
				'/v1/scan/submit',
				'scan_submit_pause',
				'scan_submit',
				$attempt,
				$wall_ms,
				$class['retry_after']
			);
		}

		if ( is_wp_error( $response ) ) {
			Segurium_Scan_Runner::debug(
				'scan_submit_error',
				array(
					'endpoint' => '/v1/scan/submit',
					'wall_ms'  => $wall_ms,
					'attempts' => $attempt,
					'code'     => 'cti_transport_error',
					'message'  => $response->get_error_message(),
				)
			);
			return new WP_Error( 'cti_transport_error', $response->get_error_message() );
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$raw     = (string) wp_remote_retrieve_body( $response );
			$decoded = json_decode( $raw, true );
			$err     = 'cti_http_error';
			$msg     = sprintf( 'scan_submit HTTP %d', (int) $code );
			if ( is_array( $decoded ) && ! empty( $decoded['error'] ) ) {
				$err = 'cti_scan_submit_' . preg_replace( '/[^a-z0-9_]/', '_', strtolower( (string) $decoded['error'] ) );
				if ( ! empty( $decoded['message'] ) ) {
					$msg = (string) $decoded['message'];
				}
			}
			Segurium_Scan_Runner::debug(
				'scan_submit_error',
				array(
					'endpoint' => '/v1/scan/submit',
					'wall_ms'  => $wall_ms,
					'attempts' => $attempt,
					'http'     => (int) $code,
					'code'     => $err,
					'message'  => $msg,
				)
			);
			return new WP_Error( $err, $msg, array( 'status' => $code ) );
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ! array_key_exists( 'next_seq', $data ) ) {
			return new WP_Error( 'cti_invalid_response', 'Invalid scan_submit response' );
		}

		// CTI emits Retry-After on 200 to pace the next submit when the
		// NRS queue is close to saturating (SEGURIUM-476). Already
		// parsed by classify_scan_response().
		$retry_after = $class['retry_after'];

		Segurium_Scan_Runner::debug(
			'scan_submit_recv',
			array(
				'endpoint'    => '/v1/scan/submit',
				'wall_ms'     => $wall_ms,
				'attempts'    => $attempt,
				'http'        => 200,
				'accepted'    => isset( $data['accepted'] ) && is_array( $data['accepted'] ) ? count( $data['accepted'] ) : 0,
				'rejected'    => isset( $data['rejected'] ) && is_array( $data['rejected'] ) ? count( $data['rejected'] ) : 0,
				'next_seq'    => (int) $data['next_seq'],
				'retry_after' => $retry_after,
			)
		);

		return array(
			'accepted'    => isset( $data['accepted'] ) && is_array( $data['accepted'] ) ? $data['accepted'] : array(),
			'rejected'    => isset( $data['rejected'] ) && is_array( $data['rejected'] ) ? $data['rejected'] : array(),
			'next_seq'    => (int) $data['next_seq'],
			'retry_after' => $retry_after,
		);
	}

	/**
	 * Pull verdicts incrementally from the async scan pipeline.
	 *
	 * SEGURIUM-456: short-poll cursor over the per-IID monotonic
	 * `result_seq`. Returns immediately — no long-poll. IID comes from
	 * the `X-Segurium-IID` middleware header; the per-IID stream is
	 * implicit in the authenticated identity.
	 *
	 * @param int    $since   Last `result_seq` the caller saw. Use 0 for
	 *                        "from the very beginning". Server rejects
	 *                        negatives and missing values.
	 * @param string $scan_id Optional filter — only results for this
	 *                        scan-run UUID. Empty = no filter.
	 * @param int    $limit   Max rows in one response. Server clamps to
	 *                        [1, 500]; we pass through.
	 * @return array|WP_Error `{results, next_seq, more}` on 200,
	 *                       WP_Error otherwise. `results` is a list of
	 *                       `{seq, hash, verdict, family?, scanned_at, scan_id}`.
	 */
	public function scan_results( $since, $scan_id = '', $limit = 0 ) {
		$since = (int) $since;
		if ( $since < 0 ) {
			return new WP_Error( 'cti_invalid_args', 'scan_results since must be non-negative' );
		}
		$qs = array( 'since' => (string) $since );
		if ( is_string( $scan_id ) && '' !== trim( $scan_id ) ) {
			$qs['scan_id'] = (string) $scan_id;
		}
		if ( $limit > 0 ) {
			$qs['limit'] = (string) (int) $limit;
		}
		$url = self::SCAN_RESULTS_ENDPOINT . '?' . http_build_query( $qs, '', '&', PHP_QUERY_RFC3986 );

		// Same retry semantics as scan_submit() — see classify_scan_response().
		$attempt  = 0;
		$wall_ms  = 0.0;
		$response = null;
		$class    = array(
			'mode'        => self::SCAN_CLASS_RETRY,
			'retry_after' => 0,
		);
		while ( $attempt < self::MAX_SCAN_ATTEMPTS ) {
			++$attempt;
			$t0           = microtime( true );
			$response     = $this->request(
				$url,
				array(
					'method'  => 'GET',
					'timeout' => 15,
				)
			);
			$attempt_wall = ( microtime( true ) - $t0 ) * 1000.0;
			$wall_ms     += $attempt_wall;
			$class        = $this->classify_scan_response( $response );
			if ( self::SCAN_CLASS_RETRY !== $class['mode'] || $attempt >= self::MAX_SCAN_ATTEMPTS ) {
				break;
			}
			Segurium_Scan_Runner::debug(
				'scan_results_retry',
				array(
					'endpoint'  => '/v1/scan/results',
					'attempt'   => $attempt,
					'remaining' => self::MAX_SCAN_ATTEMPTS - $attempt,
					'wall_ms'   => $attempt_wall,
					'reason'    => is_wp_error( $response )
						? 'transport:' . $response->get_error_message()
						: 'http_' . wp_remote_retrieve_response_code( $response ),
				)
			);
		}
		if ( self::SCAN_CLASS_PAUSE === $class['mode'] ) {
			return $this->pause_error(
				$response,
				'/v1/scan/results',
				'scan_results_pause',
				'scan_results',
				$attempt,
				$wall_ms,
				$class['retry_after']
			);
		}
		if ( is_wp_error( $response ) ) {
			Segurium_Scan_Runner::debug(
				'scan_results_error',
				array(
					'endpoint' => '/v1/scan/results',
					'wall_ms'  => $wall_ms,
					'attempts' => $attempt,
					'code'     => $response->get_error_code(),
					'message'  => $response->get_error_message(),
				)
			);
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			Segurium_Scan_Runner::debug(
				'scan_results_error',
				array(
					'endpoint' => '/v1/scan/results',
					'wall_ms'  => $wall_ms,
					'attempts' => $attempt,
					'http'     => (int) $code,
					'code'     => 'cti_http_error',
				)
			);
			return new WP_Error( 'cti_http_error', 'scan_results HTTP ' . $code, array( 'status' => $code ) );
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ! array_key_exists( 'results', $data ) || ! array_key_exists( 'next_seq', $data ) ) {
			return new WP_Error( 'cti_invalid_response', 'Invalid scan_results response' );
		}

		Segurium_Scan_Runner::debug(
			'scan_results_recv',
			array(
				'endpoint' => '/v1/scan/results',
				'wall_ms'  => $wall_ms,
				'attempts' => $attempt,
				'http'     => 200,
				'count'    => is_array( $data['results'] ) ? count( $data['results'] ) : 0,
				'next_seq' => (int) $data['next_seq'],
				'more'     => ! empty( $data['more'] ),
			)
		);

		return array(
			'results'  => is_array( $data['results'] ) ? $data['results'] : array(),
			'next_seq' => (int) $data['next_seq'],
			'more'     => ! empty( $data['more'] ),
			// SEGURIUM-564: whether the server still has jobs queued for
			// this scan. Absent on pre-564 CTI builds → null ("unknown"),
			// which the results loop treats as "do not seal" so existing
			// installs keep working unchanged.
			'pending'  => array_key_exists( 'pending', $data ) ? (bool) $data['pending'] : null,
		);
	}

	/**
	 * Synchronous-looking facade kept for realtime / upload scans.
	 *
	 * SEGURIUM-456: the on-the-wire `/v1/neo-ray` route is gone. This
	 * helper now submits the file through {@see scan_submit()} and
	 * inline-polls {@see scan_results()} for up to ~55s for the verdict
	 * to land. Used by upload-time scan and realtime scan where the
	 * caller needs a verdict before responding to the request — the
	 * batched malware-scan loop does NOT use this path; it goes through
	 * {@see Segurium_Async_Scan_Submitter} and lets
	 * {@see Segurium_Async_Scan_Results_Loop} apply verdicts in the background.
	 *
	 * Return shape preserved from the legacy implementation
	 * (`{sha256, verdict: clean|malicious|injection}`) so existing
	 * verdict-queue / realtime / upload code paths keep working. The
	 * async pipeline collapses `Verdict::Injection` into the same
	 * `malware` bucket as `Verdict::Malware` (spec §4.2), so this
	 * helper always returns `malicious` for any malware-class verdict.
	 *
	 * @param string $sha256        Lowercase hex SHA-256 of the file body.
	 * @param string $body          Raw file bytes (<= 100 MiB).
	 * @param string $relative_path Optional site-relative path for
	 *                              analytics; rides along in the meta JSON.
	 * @return array|WP_Error `{sha256, verdict}` on success, WP_Error
	 *                       (with the legacy `cti_neoray_*` code shape
	 *                        callers parse) on failure or timeout.
	 */
	public function neo_ray_scan( $sha256, $body, $relative_path = '' ) {
		$sha256 = is_string( $sha256 ) ? strtolower( $sha256 ) : '';
		if ( ! preg_match( '/^[0-9a-f]{64}$/', $sha256 ) ) {
			return new WP_Error( 'cti_invalid_hash', 'Neo-Ray scan requires a 64-char hex SHA-256' );
		}
		if ( ! is_string( $body ) || '' === $body ) {
			return new WP_Error( 'cti_empty_body', 'Neo-Ray scan requires a non-empty file body' );
		}

		$scan_id   = wp_generate_uuid4();
		$client_id = wp_generate_uuid4();
		$submitted = $this->scan_submit(
			$scan_id,
			$client_id,
			array(
				array(
					'sha256' => $sha256,
					'path'   => (string) $relative_path,
					'body'   => $body,
				),
			)
		);
		if ( is_wp_error( $submitted ) ) {
			$code = $submitted->get_error_code();
			if ( 0 === strpos( (string) $code, 'cti_scan_submit_' ) ) {
				$code = 'cti_neoray_' . substr( $code, strlen( 'cti_scan_submit_' ) );
			}
			return new WP_Error( $code, $submitted->get_error_message(), $submitted->get_error_data() );
		}

		$rejected = isset( $submitted['rejected'] ) ? $submitted['rejected'] : array();
		foreach ( $rejected as $r ) {
			$rsha = isset( $r['hash'] ) ? strtolower( str_replace( 'sha256:', '', (string) $r['hash'] ) ) : '';
			if ( $rsha === $sha256 ) {
				$reason = isset( $r['reason'] ) ? (string) $r['reason'] : 'rejected';
				return new WP_Error(
					'cti_neoray_' . preg_replace( '/[^a-z0-9_]/', '_', strtolower( $reason ) ),
					'scan_submit rejected file: ' . $reason
				);
			}
		}

		$since    = (int) $submitted['next_seq'];
		$deadline = microtime( true ) + 55.0;
		$verdict  = '';

		// Short-poll loop. Server side typically delivers within seconds;
		// p99 is bounded by the NRS 60s per-file cap which the worker
		// pool services as fast as it can.
		while ( microtime( true ) < $deadline && '' === $verdict ) {
			$poll = $this->scan_results( $since, $scan_id, 50 );
			if ( is_wp_error( $poll ) ) {
				return new WP_Error( 'cti_neoray_poll_failed', $poll->get_error_message(), $poll->get_error_data() );
			}
			foreach ( $poll['results'] as $row ) {
				$rhash = isset( $row['hash'] ) ? strtolower( str_replace( 'sha256:', '', (string) $row['hash'] ) ) : '';
				if ( $rhash !== $sha256 ) {
					continue;
				}
				$verdict = isset( $row['verdict'] ) ? (string) $row['verdict'] : '';
				break;
			}
			if ( '' !== $verdict ) {
				break;
			}
			if ( $poll['next_seq'] > $since ) {
				$since = (int) $poll['next_seq'];
			}
			if ( empty( $poll['more'] ) ) {
				// Server has no more rows right now — wait a beat before
				// asking again.
				usleep( 750 * 1000 ); // 0.75s — bounded short-poll cadence.
			}
		}

		if ( '' === $verdict ) {
			return new WP_Error( 'cti_neoray_timeout', 'scan_results did not deliver a verdict within 55s' );
		}

		// Translate async verdict string to the legacy shape callers
		// expect. `error` from NRS surfaces as a WP_Error so the caller
		// counts it as a Neo-Ray failure (the synchronous path's
		// neoray_errors stat block).
		if ( 'error' === $verdict ) {
			return new WP_Error( 'cti_neoray_engine_error', 'NRS returned verdict=error for ' . $sha256 );
		}
		$legacy = ( 'malware' === $verdict ) ? 'malicious' : $verdict;
		return array(
			'sha256'  => $sha256,
			'verdict' => $legacy,
		);
	}

	/**
	 * Request a clean version of a malicious file by its hash.
	 *
	 * SEGURIUM-353: `/v1/cleanup` now auto-consumes one quota slot every
	 * time it serves a body — there is no separate `/v1/quota/consume`
	 * endpoint to ask first. The Free-tier cap surfaces here as HTTP 402
	 * with a `{ code, quota }` envelope; we bubble it up as a `WP_Error`
	 * with code `paywall_quota_exceeded` so callers can render the
	 * paywall modal without re-deriving the envelope shape.
	 *
	 * SEGURIUM-356: `/v1/cleanup` validates the JSON body strictly and
	 * rejects the request with HTTP 400 when `filename` or `ctime` are
	 * absent — they are required for the ClickHouse `malware_cleanup`
	 * telemetry row CTI writes per attempt. Callers must supply the
	 * site-relative path and the inode change time of the file being
	 * cleaned (see Segurium_Cleanup::cleanup_file).
	 *
	 * @param string $sha256   SHA-256 hash of the malicious file.
	 * @param string $filename Site-relative path of the infected file.
	 * @param int    $ctime    Inode change time of the file (unix epoch).
	 * @return array|WP_Error Clean file data or error.
	 */
	public function clean( $sha256, $filename, $ctime ) {
		$response = $this->request(
			self::CLEAN_ENDPOINT,
			array(
				'body' => array(
					'sha256'   => (string) $sha256,
					'filename' => (string) $filename,
					'ctime'    => (int) $ctime,
				),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 402 === $code ) {
			$paywall = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! is_array( $paywall ) ) {
				$paywall = array();
			}
			return new WP_Error(
				'paywall_quota_exceeded',
				__( 'Cleanup quota reached.', 'segurium' ),
				$paywall
			);
		}
		if ( 404 === $code || 501 === $code ) {
			return new WP_Error(
				'cti_clean_not_available',
				__( 'Clean version not available for this file', 'segurium' )
			);
		}
		if ( 200 !== $code ) {
			return new WP_Error( 'cti_http_error', 'CTI returned HTTP ' . $code );
		}

		// SEGURIUM-192: refuse a MITM-tampered body before we act on it.
		$verified = Segurium_CTI_Signature::verify_response( $response, 'cleanup' );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ! isset( $data['content'] ) ) {
			return new WP_Error( 'cti_invalid_response', 'Invalid CTI clean response' );
		}

		return $data;
	}

	/**
	 * Check file integrity for WordPress core, plugins, or themes.
	 *
	 * @param array  $components Array of component data to check.
	 * @param string $trigger    Optional scan trigger ('scheduled', 'manual',
	 *                           'post_update', 'unspecified'). Sent as
	 *                           `X-Segurium-Integrity-Trigger` header so CTI
	 *                           can record what caused the scan.
	 * @return array|WP_Error Array of component integrity results or error.
	 */
	public function integrity_check( $components, $trigger = '' ) {
		$opts = array(
			'body'    => array( 'components' => $components ),
			'timeout' => 60,
		);
		if ( is_string( $trigger ) && '' !== $trigger ) {
			$opts['headers'] = array( 'X-Segurium-Integrity-Trigger' => $trigger );
		}
		$response = $this->request( self::INTEGRITY_ENDPOINT, $opts );
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			// Carry the HTTP status so the caller can tell a permanent 4xx
			// (retrying the same body is futile) from a transient 5xx/timeout.
			return new WP_Error( 'cti_http_error', 'CTI returned HTTP ' . $code, array( 'status' => (int) $code ) );
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ! isset( $data['components'] ) ) {
			return new WP_Error( 'cti_invalid_response', 'Invalid CTI integrity response' );
		}

		return $data['components'];
	}

	/**
	 * Retrieve original file content from the CTI integrity store.
	 *
	 * @param string $type    Component type (core, plugin, theme).
	 * @param string $path    Relative file path within the component.
	 * @param string $slug    Component slug.
	 * @param string $version Component version.
	 * @return string|WP_Error Original file content or error.
	 */
	public function get_original_content( $type, $path, $slug = '', $version = '' ) {
		$params = array(
			'type'    => $type,
			'version' => $version,
			'path'    => $path,
		);
		if ( ! empty( $slug ) ) {
			$params['name'] = $slug;
		}

		$url      = self::ORIGINAL_ENDPOINT . '?' . http_build_query( $params );
		$response = $this->request( $url, array( 'method' => 'GET' ) );
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return new WP_Error( 'cti_http_error', 'CTI returned HTTP ' . $code );
		}

		// SEGURIUM-192: verify signature before returning the body.
		$verified = Segurium_CTI_Signature::verify_response( $response, 'integrity/original-content' );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}

		return wp_remote_retrieve_body( $response );
	}

	/**
	 * Log an integrity action asynchronously to the CTI service.
	 *
	 * @param array $data Action data to log.
	 * @return void
	 */
	public function log_integrity_action( $data ) {
		$this->request(
			self::LOG_ACTION_ENDPOINT,
			array(
				'body'     => $data,
				'timeout'  => 5,
				'blocking' => false,
			)
		);
	}

	/**
	 * Log a whole-component action (delete/restore/ignore/unignore) to CTI
	 * asynchronously.
	 *
	 * @param array $data Action payload. See Segurium_Storage::cti_log_component_action.
	 * @return void
	 */
	public function log_component_action( $data ) {
		$this->request(
			self::LOG_COMPONENT_ACTION_ENDPOINT,
			array(
				'body'     => $data,
				'timeout'  => 5,
				'blocking' => false,
			)
		);
	}

	/**
	 * Push a full component-inventory snapshot to CTI asynchronously.
	 *
	 * @param array $components Array of { component_type, slug, version, status }.
	 * @return void
	 */
	public function log_components_inventory( $components ) {
		$this->request(
			self::COMPONENTS_ENDPOINT,
			array(
				'body'     => array( 'components' => $components ),
				'timeout'  => 5,
				'blocking' => false,
			)
		);
	}

	/**
	 * Push a hosting-platform snapshot to CTI asynchronously
	 * (SEGURIUM-329 → /v1/platform). Routed through {@see request()}
	 * so the SEGURIUM-295 consent / IID gate fires.
	 *
	 * @param array $payload Snapshot body matching PlatformSnapshotRequest
	 *                       on the CTI side. Must include `snapshot_hash`.
	 * @return bool True if the request did not error before send.
	 */
	public function send_platform_snapshot( array $payload ) {
		$response = $this->request(
			self::PLATFORM_ENDPOINT,
			array(
				'body'     => $payload,
				'timeout'  => 5,
				'blocking' => false,
			)
		);
		return ! is_wp_error( $response );
	}

	/**
	 * Send an informational message to the CTI service.
	 *
	 * @param string $message_type Type of message to send.
	 * @param string $payload      Optional message payload.
	 * @return bool True if the request did not error.
	 */
	public function send_message( $message_type, $payload = '' ) {
		global $wp_version;

		$response = $this->request(
			self::MESSAGES_ENDPOINT,
			array(
				'body'     => array(
					'message_type'   => $message_type,
					'domain'         => wp_parse_url( home_url(), PHP_URL_HOST ),
					'site_url'       => home_url(),
					'wp_version'     => $wp_version,
					'plugin_version' => SEGURIUM_VERSION,
					'php_version'    => PHP_VERSION,
					'payload'        => $payload,
				),
				'timeout'  => 10,
				'blocking' => false,
			)
		);

		return ! is_wp_error( $response );
	}

	/**
	 * Read-only quota state for the calling install. Same envelope
	 * shape `/v1/cleanup` returns inside its `quota` echo (with
	 * `allowed = used < limit`).
	 *
	 * @return array|WP_Error
	 */
	public function quota_state() {
		return $this->quota_call( self::QUOTA_STATE_ENDPOINT, 'GET', null );
	}

	/**
	 * SEGURIUM-378: race-resolver sync. POSTs the Freemius
	 * `(install_id, install_secret_key, license_id, license_key)` tuple;
	 * CTI cross-checks every field against the Freemius developer API
	 * before writing the binding row, so the plugin never gets to assert
	 * Pro tier — it only forwards proof of install ownership. The install
	 * secret_key is unforgeable from outside the WordPress site, so it
	 * doubles as the user-id authority — the plugin never has to assert
	 * a user_id and CTI never has to defensively cross-check it.
	 *
	 * Response shape:
	 * `{ tier, period: { start, end }, used, remaining, license_state }`.
	 * Wired into `Segurium_Quota::apply_billing_sync_envelope()` by the
	 * pro-transition handler so the local quota envelope refreshes
	 * without a follow-up `/v1/quota/state` round-trip.
	 *
	 * @param string $install_id          Freemius `Install.id`.
	 * @param string $install_secret_key  Freemius `Install.secret_key`.
	 * @param string $license_id          Freemius `License.id`.
	 * @param string $license_key         Freemius `License.secret_key`.
	 * @return array|WP_Error Parsed response or transport/HTTP error.
	 */
	public function billing_sync( $install_id, $install_secret_key, $license_id, $license_key ) {
		$body = array(
			'fs_install_id'         => (string) $install_id,
			'fs_install_secret_key' => (string) $install_secret_key,
			'fs_license_id'         => (string) $license_id,
			'fs_license_key'        => (string) $license_key,
		);
		// SEGURIUM-385: identify which Freemius product this install
		// belongs to, so the multi-tenant CTI deployment can route
		// developer-API validation to the right product. Defaults to
		// the prod product (26814) in production builds; DDEV/test
		// installs override `SEGURIUM_FS_PRODUCT_ID` in wp-config.php
		// to drive the test product (29175) end-to-end.
		if ( defined( 'SEGURIUM_FS_PRODUCT_ID' ) ) {
			$body['fs_plugin_id'] = (string) SEGURIUM_FS_PRODUCT_ID;
		}
		return $this->billing_call( self::BILLING_SYNC_ENDPOINT, $body );
	}

	/**
	 * Shared helper for the billing endpoints. Same shape as `quota_call`
	 * — decode JSON, coerce non-2xx into WP_Error.
	 *
	 * @param string $url  Endpoint URL.
	 * @param array  $body POST body (encoded as JSON).
	 * @return array|WP_Error
	 */
	private function billing_call( $url, $body ) {
		$response = $this->request(
			$url,
			array(
				'method'  => 'POST',
				'body'    => $body,
				'timeout' => 10,
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$raw  = wp_remote_retrieve_body( $response );
		$data = json_decode( $raw, true );
		if ( $code < 200 || $code >= 300 ) {
			return new WP_Error(
				'cti_billing_http_' . $code,
				is_array( $data ) && isset( $data['error'] )
					? (string) $data['error']
					: trim( (string) $raw ),
				array(
					'status' => $code,
					'body'   => $raw,
				)
			);
		}
		if ( ! is_array( $data ) ) {
			return new WP_Error(
				'cti_billing_invalid_response',
				__( 'Invalid billing response from Segurium Cloud.', 'segurium' ),
				array( 'body' => $raw )
			);
		}
		return $data;
	}

	/**
	 * Shared helper for the three quota endpoints. Decodes JSON,
	 * coerces non-2xx into WP_Error so callers can short-circuit
	 * uniformly.
	 *
	 * @param string     $url    Endpoint URL.
	 * @param string     $method 'GET' or 'POST'.
	 * @param array|null $body   Request body, or null for GET.
	 * @return array|WP_Error
	 */
	private function quota_call( $url, $method, $body ) {
		$response = $this->request(
			$url,
			array(
				'method'  => $method,
				'body'    => $body,
				'timeout' => 5,
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$raw  = wp_remote_retrieve_body( $response );
		$data = json_decode( $raw, true );
		if ( $code < 200 || $code >= 300 || ! is_array( $data ) ) {
			return new WP_Error(
				'cti_quota_http_' . $code,
				is_array( $data ) && isset( $data['error'] ) ? $data['error'] : 'quota call failed',
				array(
					'status' => $code,
					'body'   => $raw,
				)
			);
		}
		return $data;
	}
}

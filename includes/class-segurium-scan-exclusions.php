<?php
/**
 * Scan exclusion patterns: parsing, normalisation and the limits.
 *
 * The general settings row stores the list as one newline-separated string.
 * `parse()` turns raw operator input into the storable form plus the notes the
 * settings screen shows, so the save path holds no parsing of its own.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scan exclusion list rules.
 */
class Segurium_Scan_Exclusions {

	/**
	 * Longest pattern the ignore-list column accepts.
	 */
	const MAX_PATTERN_LENGTH = 191;

	/**
	 * Most patterns one site may store.
	 */
	const MAX_PATTERNS = 500;

	/**
	 * Reduce raw input to the storable string.
	 *
	 * @param string $raw Newline-separated patterns as typed.
	 * @return array{value:string,warnings:array<int,string>,error:?WP_Error}
	 */
	public static function parse( string $raw ): array {
		$warnings   = array();
		$clean      = array();
		$rejected   = 0;
		$normalized = 0;

		foreach ( explode( "\n", $raw ) as $line ) {
			$trimmed = trim( $line );
			if ( '*' === $trimmed ) {
				$warnings[] = __( 'A bare * pattern was removed because it would exclude all files.', 'segurium' );
				continue;
			}
			if ( strlen( $trimmed ) > self::MAX_PATTERN_LENGTH ) {
				++$rejected;
				continue;
			}
			$rewritten = self::normalize_pattern( $line );
			if ( $rewritten !== $line ) {
				++$normalized;
				$line = $rewritten;
			}
			$clean[] = $line;
		}

		if ( $normalized > 0 ) {
			$warnings[] = sprintf(
				/* translators: %d: number of rewritten lines */
				_n(
					'%d absolute path was rewritten to a path relative to the WordPress install root.',
					'%d absolute paths were rewritten to paths relative to the WordPress install root.',
					$normalized,
					'segurium'
				),
				$normalized
			);
		}

		if ( count( $clean ) > self::MAX_PATTERNS ) {
			return array(
				'value'    => '',
				'warnings' => $warnings,
				'error'    => new WP_Error(
					'scan_exclude_too_large',
					__( 'Scan exclusion list is limited to 500 entries.', 'segurium' )
				),
			);
		}

		if ( $rejected > 0 ) {
			$warnings[] = sprintf(
				/* translators: %d: number of rejected lines */
				_n(
					'%d entry longer than 191 characters was removed.',
					'%d entries longer than 191 characters were removed.',
					$rejected,
					'segurium'
				),
				$rejected
			);
		}

		return array(
			'value'    => implode( "\n", $clean ),
			'warnings' => $warnings,
			'error'    => null,
		);
	}

	/**
	 * Rewrite an absolute path under the install root to the relative form the
	 * scanner matches against. A path outside the root is kept verbatim.
	 *
	 * @param string $line One pattern as typed.
	 * @return string
	 */
	public static function normalize_pattern( $line ) {
		$trimmed = trim( (string) $line );
		if ( '' === $trimmed ) {
			return $line;
		}
		// Only rewrite absolute paths. Linux: leading "/", Windows: "C:\" or "C:/".
		$is_abs = ( '/' === $trimmed[0] )
			|| (bool) preg_match( '#^[A-Za-z]:[\\\\/]#', $trimmed );
		if ( ! $is_abs ) {
			return $line;
		}
		$wp_root   = Segurium_Path_Helpers::wp_root();
		$abspath   = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $wp_root ) : $wp_root;
		$abspath   = rtrim( $abspath, '/' ) . '/';
		$candidate = function_exists( 'wp_normalize_path' ) ? wp_normalize_path( $trimmed ) : $trimmed;
		if ( 0 === strpos( $candidate, $abspath ) ) {
			$relative = substr( $candidate, strlen( $abspath ) );
			if ( '' !== $relative ) {
				return $relative;
			}
		}
		return $line;
	}
}

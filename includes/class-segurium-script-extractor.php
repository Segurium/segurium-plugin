<?php
/**
 * Script elements inside a stored field value.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Finds the script elements of one field value and the bytes that name each one.
 */
final class Segurium_Script_Extractor {

	const PLAIN      = 'plain';
	const SERIALIZED = 'serialized';
	const BASE64     = 'base64';
	const JSON       = 'json';

	const MIN_BASE64_CHARS = 12;
	const SPACE            = " \t\n\r\f";
	const MAX_DEPTH        = 2;
	const NONE             = array(
		'scripts' => array(),
		'sources' => array(),
	);

	/**
	 * The scripts of one field value.
	 *
	 * @param string $value  Field value as stored.
	 * @param bool   $decode Whether a base64 value is read decoded and a JSON value with its escaped end tags.
	 * @return array{encoding:string,scripts:array<string,string>,sources:array<string,string>}
	 *         Identities by SHA-256, in order of appearance: `scripts` of the inline scripts, `sources` of the external ones.
	 */
	public static function field( $value, $decode ) {
		$value = (string) $value;
		$lower = self::lower( $value );
		if ( false === strpos( $lower, '<script' ) ) {
			$decoded = $decode ? self::base64( $value ) : '';
			$low     = self::lower( $decoded );
			$found   = '' !== $decoded && false !== strpos( $low, '<script' );
			return array( 'encoding' => $found ? self::BASE64 : self::PLAIN ) + ( $found ? self::scripts( $decoded, $low, false ) : self::NONE );
		}
		$encoding = self::shape( $value, $decode );
		return array( 'encoding' => $encoding ) + self::read( $value, $lower, $encoding, $decode, self::MAX_DEPTH, false );
	}

	/**
	 * The field value without one script, or with the cleaned code inside
	 * each element of an inline script. The result is checked: it parses
	 * again where the value parsed, the script is gone, the cleaned script is
	 * there and every other script reads as before.
	 *
	 * @param string $value   Field value as stored.
	 * @param bool   $decode  As for {@see field()}.
	 * @param string $sha256  SHA-256 of the identity of the script.
	 * @param string $cleaned '' removes each element; else the code that takes the place of the inline script.
	 * @param bool   $source  Whether the script is an external one, named by its address.
	 * @return string|WP_Error The code names the check that failed.
	 */
	public static function rewrite( $value, $decode, $sha256, $cleaned, $source = false ) {
		$value   = (string) $value;
		$cleaned = (string) $cleaned;
		if ( $source && '' !== $cleaned ) {
			return new WP_Error( 'cleaned_unsupported', 'an external script takes no cleaned version' );
		}
		$map    = $source ? 'sources' : 'scripts';
		$before = self::field( $value, $decode );
		if ( ! isset( $before[ $map ][ $sha256 ] ) ) {
			return new WP_Error( 'script_gone', 'the value holds no element of the script' );
		}
		if ( '' !== $cleaned && '' === trim( $cleaned ) ) {
			return new WP_Error( 'cleaned_blank', 'the cleaned version holds whitespace only' );
		}
		if ( '' !== $cleaned && hash( 'sha256', $cleaned ) === $sha256 ) {
			return new WP_Error( 'cleaned_unchanged', 'the cleaned version equals the script' );
		}
		$edit = array(
			'sha'     => $sha256,
			'source'  => (bool) $source,
			'cleaned' => $cleaned,
			'count'   => 0,
			'fault'   => '',
		);
		if ( self::BASE64 === $before['encoding'] ) {
			$decoded = self::base64( $value );
			$new     = base64_encode( self::edit_text( $decoded, self::lower( $decoded ), false, $edit ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- writes a base64 value back in its own encoding.
		} else {
			$new = self::edit( $value, self::lower( $value ), $before['encoding'], $decode, self::MAX_DEPTH, false, $edit );
		}
		if ( '' !== $edit['fault'] ) {
			return new WP_Error( $edit['fault'], 'the rewrite fails the check ' . $edit['fault'] );
		}
		$expect = array_intersect_key( $before, self::NONE );
		unset( $expect[ $map ][ $sha256 ] );
		if ( '' !== $cleaned ) {
			$expect[ $map ][ hash( 'sha256', $cleaned ) ] = $cleaned;
		}
		$after = array_intersect_key( self::field( $new, $decode ), self::NONE );
		foreach ( array_keys( self::NONE ) as $kind ) {
			ksort( $expect[ $kind ] );
			ksort( $after[ $kind ] );
			$expect[ $kind ] = array_keys( $expect[ $kind ] );
			$after[ $kind ]  = array_keys( $after[ $kind ] );
		}
		if ( 0 === $edit['count'] || $expect !== $after ) {
			return new WP_Error( 'rewrite_unverified', 'the scripts of the rewritten value are not the expected ones' );
		}
		return $new;
	}

	/**
	 * Encoding of a value that holds `<script`.
	 *
	 * @param string $value  Value.
	 * @param bool   $decode Whether a JSON value counts as JSON.
	 * @return string
	 */
	private static function shape( $value, $decode ) {
		if ( is_serialized( $value ) ) {
			return self::SERIALIZED;
		}
		return $decode && self::looks_json( $value ) ? self::JSON : self::PLAIN;
	}

	/**
	 * Scripts of a value, each string of a serialized or JSON value apart.
	 * A `<script` outside every string reads the value as a whole.
	 *
	 * @param string $value    Value.
	 * @param string $lower    The value in ASCII lower case.
	 * @param string $encoding Encoding of the value.
	 * @param bool   $decode   Whether a JSON string counts as JSON.
	 * @param int    $depth    Levels of strings still to open.
	 * @param bool   $escaped  Whether the value is a string of a JSON value.
	 * @return array{scripts:array<string,string>,sources:array<string,string>}
	 */
	private static function read( $value, $lower, $encoding, $decode, $depth, $escaped ) {
		$json   = $escaped || self::JSON === $encoding;
		$ranges = self::PLAIN === $encoding || $depth < 1 ? null : self::ranges( $value, $lower, $encoding );
		if ( null === $ranges ) {
			return self::scripts( $value, $lower, $json );
		}
		$found = self::NONE;
		foreach ( $ranges as $range ) {
			$text = (string) substr( $value, $range[0], $range[1] - $range[0] );
			$part = self::read( $text, (string) substr( $lower, $range[0], $range[1] - $range[0] ), self::shape( $text, $decode ), $decode, $depth - 1, $json );
			foreach ( $part as $kind => $identities ) {
				$found[ $kind ] += $identities;
			}
		}
		return $found;
	}

	/**
	 * The value with the script edited, read as {@see read()} reads it.
	 *
	 * @param string $value    Value.
	 * @param string $lower    The value in ASCII lower case.
	 * @param string $encoding Encoding of the value.
	 * @param bool   $decode   Whether a JSON string counts as JSON.
	 * @param int    $depth    Levels of strings still to open.
	 * @param bool   $escaped  Whether the value is a string of a JSON value.
	 * @param array  $edit     The edit: `sha`, `cleaned`, and the `count` and `fault` it sets.
	 * @return string
	 */
	private static function edit( $value, $lower, $encoding, $decode, $depth, $escaped, array &$edit ) {
		$json   = $escaped || self::JSON === $encoding;
		$ranges = self::PLAIN === $encoding || $depth < 1 ? null : self::ranges( $value, $lower, $encoding );
		if ( null === $ranges ) {
			$out = self::edit_text( $value, $lower, $json, $edit );
		} else {
			$out  = '';
			$done = 0;
			foreach ( $ranges as $range ) {
				$text = (string) substr( $value, $range[0], $range[1] - $range[0] );
				$new  = self::edit( $text, (string) substr( $lower, $range[0], $range[1] - $range[0] ), self::shape( $text, $decode ), $decode, $depth - 1, $json, $edit );
				if ( $new === $text ) {
					continue;
				}
				$out .= substr( $value, $done, $range[2] - $done ) . ( self::SERIALIZED === $encoding ? strlen( $new ) . ':"' : '' ) . $new;
				$done = $range[1];
			}
			$out .= substr( $value, $done );
		}
		if ( $out !== $value && self::PLAIN !== $encoding && self::parses( $value, $encoding ) && ! self::parses( $out, $encoding ) ) {
			$edit['fault'] = '' === $edit['fault'] ? 'rewrite_breaks_value' : $edit['fault'];
		}
		return $out;
	}

	/**
	 * A text with the script edited at each of its elements.
	 *
	 * @param string $text  Text.
	 * @param string $lower The text in ASCII lower case.
	 * @param bool   $json  Whether `<\/script` ends a script too.
	 * @param array  $edit  The edit, as for {@see edit()}.
	 * @return string
	 */
	private static function edit_text( $text, $lower, $json, array &$edit ) {
		$out     = '';
		$done    = 0;
		$cleaned = $edit['cleaned'];
		foreach ( self::elements( $text, $lower, $json ) as $element ) {
			if ( '' === $element['identity'] || ( null !== $element['src'] ) !== $edit['source'] || hash( 'sha256', $element['identity'] ) !== $edit['sha'] ) {
				continue;
			}
			++$edit['count'];
			if ( '' === $cleaned ) {
				$cut = array( $element['start'], $element['close'] );
			} else {
				$cut  = array( $element['from'], $element['end'] );
				$tail = self::lower( $cleaned );
				if ( false !== strpos( $tail, '</script' ) || false !== strpos( $tail, '<\\/script' ) ) {
					$edit['fault'] = 'cleaned_bad_script';
				}
			}
			$out .= substr( $text, $done, $cut[0] - $done ) . $cleaned;
			$done = $cut[1];
		}
		return $out . substr( $text, $done );
	}

	/**
	 * The strings of a serialized or JSON value that hold a script, or null
	 * when a `<script` lies outside every string and the value reads as a whole.
	 *
	 * @param string $value    Value.
	 * @param string $lower    The value in ASCII lower case.
	 * @param string $encoding SERIALIZED or JSON.
	 * @return array|null Ranges `[from, to, head)`; head is where the declared length starts.
	 */
	private static function ranges( $value, $lower, $encoding ) {
		$hits = array();
		$next = strpos( $lower, '<script' );
		foreach ( self::JSON === $encoding ? self::json_strings( $value ) : self::serialized_strings( $value ) as $range ) {
			if ( false === $next ) {
				return $hits;
			}
			if ( null === $range || $next < $range[0] ) {
				return null;
			}
			if ( $next < $range[1] ) {
				$hits[] = $range;
				$next   = strpos( $lower, '<script', $range[1] );
			}
		}
		return false === $next ? $hits : null;
	}

	/**
	 * Whether a value parses in its encoding.
	 *
	 * @param string $value    Value.
	 * @param string $encoding SERIALIZED or JSON.
	 * @return bool
	 */
	private static function parses( $value, $encoding ) {
		if ( self::JSON === $encoding ) {
			json_decode( $value );
			return JSON_ERROR_NONE === json_last_error();
		}
		$value = trim( $value );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize, WordPress.PHP.NoSilencedErrors.Discouraged -- checks that a stored value still parses; no class is built.
		return 'b:0;' === $value || false !== @unserialize( $value, array( 'allowed_classes' => false ) );
	}

	/**
	 * The `s:<length>:"…";` strings of a serialized value, by their declared lengths.
	 *
	 * @param string $value Serialized value.
	 * @return Generator Yields ranges `[from, to, head)`, then null when a declared length does not fit.
	 */
	private static function serialized_strings( $value ) {
		$size = strlen( $value );
		$pos  = 0;
		for ( $at = strpos( $value, 's:' ); false !== $at; $at = strpos( $value, 's:', $pos ) ) {
			$pos    = $at + 2;
			$digits = strspn( $value, '0123456789', $pos );
			if ( 0 === $digits || $digits > 10 || ':"' !== substr( $value, $pos + $digits, 2 ) ) {
				continue;
			}
			$from = $pos + $digits + 2;
			$to   = $from + (int) substr( $value, $pos, $digits );
			if ( $to + 2 > $size || '";' !== substr( $value, $to, 2 ) ) {
				yield null;
				return;
			}
			yield array( $from, $to, $pos );
			$pos = $to + 2;
		}
	}

	/**
	 * The string literals of a JSON value, escapes kept.
	 *
	 * @param string $value JSON text.
	 * @return Generator Yields ranges `[from, to, from)`, then null when a string does not close.
	 */
	private static function json_strings( $value ) {
		for ( $open = strpos( $value, '"' ); false !== $open; $open = strpos( $value, '"', $close + 1 ) ) {
			$close = $open;
			do {
				$close = strpos( $value, '"', $close + 1 );
				if ( false === $close ) {
					yield null;
					return;
				}
				$slashes = 0;
				for ( $back = $close - 1; $back > $open && '\\' === $value[ $back ]; $back-- ) {
					++$slashes;
				}
			} while ( 1 === $slashes % 2 );
			yield array( $open + 1, $close, $open + 1 );
		}
	}

	/**
	 * Identities of the script elements of a text: the trimmed `src` of an
	 * external script, the bytes between the tags of an inline one.
	 *
	 * @param string $text  Text.
	 * @param string $lower The text in ASCII lower case.
	 * @param bool   $json  Whether `<\/script` ends a script too.
	 * @return array{scripts:array<string,string>,sources:array<string,string>} Identities by SHA-256.
	 */
	private static function scripts( $text, $lower, $json ) {
		$found = self::NONE;
		foreach ( self::elements( $text, $lower, $json ) as $element ) {
			if ( '' !== $element['identity'] ) {
				$found[ null === $element['src'] ? 'scripts' : 'sources' ][ hash( 'sha256', $element['identity'] ) ] = $element['identity'];
			}
		}
		return $found;
	}

	/**
	 * The script elements of a text, with the offsets a rewrite needs.
	 *
	 * @param string $text  Text.
	 * @param string $lower The text in ASCII lower case.
	 * @param bool   $json  Whether `<\/script` ends a script too.
	 * @return Generator Yields `{start, from, end, close, src, identity}`: the element runs from
	 *         `start` to `close`, its content from `from` to `end`; `src` is `[from, to)` of the
	 *         address of an external script, else null; `identity` is '' for no script.
	 */
	private static function elements( $text, $lower, $json ) {
		$size = strlen( $text );
		$ends = $json ? array(
			'</script'   => -1,
			'<\\/script' => -1,
		) : array( '</script' => -1 );
		$gt   = -1;
		$at   = 0;
		while ( $at < $size ) {
			$start = strpos( $lower, '<script', $at );
			if ( false === $start ) {
				return;
			}
			$at = $start + 7;
			if ( $gt < $at ) {
				$gt = strpos( $text, '>', $at );
				if ( false === $gt ) {
					return;
				}
			}
			$tag = self::start_tag( $text, $at );
			if ( null === $tag ) {
				return;
			}
			if ( false === $tag ) {
				continue;
			}
			$from = $tag['end'];
			foreach ( $ends as $marker => $position ) {
				if ( $position < $from ) {
					$position        = strpos( $lower, $marker, $from );
					$ends[ $marker ] = false === $position ? $size : $position;
				}
			}
			$end = min( $ends );
			$at  = $end + 1;
			if ( null !== $tag['src'] ) {
				$identity = trim( $tag['src'], self::SPACE );
			} else {
				$identity = (string) substr( $text, $from, $end - $from );
				$identity = '' === trim( $identity ) ? '' : $identity;
			}
			$close = $end < $size ? strpos( $text, '>', $end ) : false;
			yield array(
				'start'    => $start,
				'from'     => $from,
				'end'      => $end,
				'close'    => false === $close ? $size : $close + 1,
				'src'      => null === $tag['src'] ? null : array( $tag['src_at'], $tag['src_at'] + strlen( $tag['src'] ) ),
				'identity' => $identity,
			);
		}
	}

	/**
	 * Read a start tag by the attribute rules of a browser.
	 *
	 * @param string $text Text.
	 * @param int    $at   Offset after `<script`.
	 * @return array{end:int,src:string|null,src_at:int}|false|null False: no start tag here. Null: the tag never ends.
	 */
	private static function start_tag( $text, $at ) {
		$size = strlen( $text );
		if ( $at >= $size || false === strpos( self::SPACE . '/>', $text[ $at ] ) ) {
			return false;
		}
		$src    = null;
		$src_at = 0;
		$pos    = $at;
		while ( true ) {
			$pos += strspn( $text, self::SPACE . '/', $pos );
			if ( $pos >= $size ) {
				return null;
			}
			if ( '>' === $text[ $pos ] ) {
				return array(
					'end'    => $pos + 1,
					'src'    => $src,
					'src_at' => $src_at,
				);
			}
			$name      = $pos++;
			$pos      += $pos < $size ? strcspn( $text, self::SPACE . '/>=', $pos ) : 0;
			$attribute = self::lower( substr( $text, $name, $pos - $name ) );
			$pos      += $pos < $size ? strspn( $text, self::SPACE, $pos ) : 0;
			$value     = '';
			$value_at  = $pos;
			if ( $pos < $size && '=' === $text[ $pos ] ) {
				++$pos;
				$pos     += $pos < $size ? strspn( $text, self::SPACE, $pos ) : 0;
				$quote    = $pos < $size ? $text[ $pos ] : '';
				$value_at = $pos;
				if ( '"' === $quote || "'" === $quote ) {
					$end = strpos( $text, $quote, $pos + 1 );
					if ( false === $end ) {
						return null;
					}
					$value    = (string) substr( $text, $pos + 1, $end - $pos - 1 );
					$value_at = $pos + 1;
					$pos      = $end + 1;
				} elseif ( $pos < $size ) {
					$length = strcspn( $text, self::SPACE . '>', $pos );
					$value  = (string) substr( $text, $pos, $length );
					$pos   += $length;
				}
			}
			if ( 'src' === $attribute && null === $src ) {
				$src    = $value;
				$src_at = $value_at;
			}
		}
	}

	/**
	 * Decoded bytes of a value that is base64 as a whole.
	 *
	 * @param string $value Field value.
	 * @return string '' when the value is no base64.
	 */
	private static function base64( $value ) {
		$value = trim( $value );
		if ( strlen( $value ) < self::MIN_BASE64_CHARS || ! preg_match( '~^[A-Za-z0-9+/\s]++={0,2}$~', $value ) ) {
			return '';
		}
		$decoded = base64_decode( $value, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- reads a stored value to find a script in it, strict.
		return false === $decoded ? '' : $decoded;
	}

	/**
	 * ASCII lower case, the same in every locale.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private static function lower( $text ) {
		return strtr( $text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz' );
	}

	/**
	 * Whether a value is shaped as a JSON object or list.
	 *
	 * @param string $value Field value.
	 * @return bool
	 */
	private static function looks_json( $value ) {
		$value = trim( $value );
		$ends  = substr( $value, 0, 1 ) . substr( $value, -1 );
		return '{}' === $ends || '[]' === $ends;
	}
}

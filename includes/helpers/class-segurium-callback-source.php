<?php
/**
 * Where the code of a registered callback lives.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolves a hook callback to its defining file through PHP Reflection.
 */
final class Segurium_Callback_Source {

	const ORIGIN_FILE       = 'file';
	const ORIGIN_EVAL       = 'eval';
	const ORIGIN_INTERNAL   = 'internal';
	const ORIGIN_UNRESOLVED = 'unresolved';

	/**
	 * Describe one callback.
	 *
	 * @param mixed $callback Callback as a hook stores it.
	 * @return array{type:string,name:string,origin:string,file:string,start:int,end:int}
	 *         `file` is the resolved path for the origin `file`, else ''.
	 *         `origin` is `internal` for a PHP built-in and `unresolved` for a
	 *         callback PHP cannot reflect.
	 */
	public static function locate( $callback ) {
		$source = array(
			'type'   => 'unknown',
			'name'   => '',
			'origin' => self::ORIGIN_UNRESOLVED,
			'file'   => '',
			'start'  => 0,
			'end'    => 0,
		);
		if ( is_array( $callback ) && 2 === count( $callback ) && isset( $callback[0], $callback[1] ) && $callback[0] instanceof Closure
			&& is_string( $callback[1] ) && in_array( strtolower( $callback[1] ), array( '__invoke', 'call' ), true ) ) {
			// PHP reports no file for a method of Closure, and these two run the closure's code.
			$callback = $callback[0];
		}
		try {
			if ( $callback instanceof Closure ) {
				$source['type'] = 'closure';
				$ref            = new ReflectionFunction( $callback );
			} elseif ( is_string( $callback ) && false === strpos( $callback, '::' ) ) {
				$source['type'] = 'function';
				$source['name'] = $callback;
				$ref            = new ReflectionFunction( $callback );
			} elseif ( is_string( $callback ) ) {
				$source['type']         = 'static_method';
				$source['name']         = $callback;
				list( $class, $method ) = explode( '::', $callback, 2 );
				$ref                    = new ReflectionMethod( $class, $method );
			} elseif ( is_array( $callback ) && 2 === count( $callback ) && isset( $callback[0], $callback[1] )
				&& ( is_object( $callback[0] ) || is_string( $callback[0] ) ) && is_string( $callback[1] ) ) {
				$bound          = is_object( $callback[0] );
				$source['type'] = $bound ? 'method' : 'static_method';
				$source['name'] = ( $bound ? self::class_name( $callback[0] ) : (string) $callback[0] ) . '::' . (string) $callback[1];
				$ref            = new ReflectionMethod( $callback[0], (string) $callback[1] );
			} elseif ( is_object( $callback ) ) {
				$source['type'] = 'invokable';
				$source['name'] = self::class_name( $callback ) . '::__invoke';
				$ref            = new ReflectionMethod( $callback, '__invoke' );
			} else {
				return $source;
			}
		} catch ( ReflectionException $e ) {
			return $source;
		}

		$file = $ref->getFileName();
		if ( false === $file ) {
			$source['origin'] = self::ORIGIN_INTERNAL;
			return $source;
		}
		$source['start'] = (int) $ref->getStartLine();
		$source['end']   = (int) $ref->getEndLine();
		if ( false !== strpos( $file, "eval()'d code" ) || false !== strpos( $file, 'runtime-created function' ) ) {
			$source['origin'] = self::ORIGIN_EVAL;
			return $source;
		}
		$source['origin'] = self::ORIGIN_FILE;
		$source['file']   = self::resolved( $file );
		return $source;
	}

	/**
	 * Class name of an object. An anonymous class reads as `class@anonymous`:
	 * PHP appends the defining path to the name.
	 *
	 * @param object $instance Object.
	 * @return string
	 */
	private static function class_name( $instance ) {
		$name = get_class( $instance );
		$cut  = strpos( $name, "\0" );
		return false === $cut ? $name : substr( $name, 0, $cut );
	}

	/**
	 * A path relative to the WordPress root, or '' outside the root.
	 *
	 * @param string $real Path from {@see resolved()}.
	 * @return string
	 */
	public static function relative( $real ) {
		$root = trailingslashit( self::resolved( Segurium_Path_Helpers::wp_root() ) );
		return 0 === strpos( (string) $real, $root ) ? substr( (string) $real, strlen( $root ) ) : '';
	}

	/**
	 * Symlink-free, forward-slash path.
	 *
	 * @param string $path Any path.
	 * @return string
	 */
	public static function resolved( $path ) {
		$real = realpath( (string) $path );
		return wp_normalize_path( false === $real ? (string) $path : $real );
	}
}

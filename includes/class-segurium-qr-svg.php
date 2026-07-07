<?php
/**
 * Pure PHP QR Code SVG generator.
 *
 * Generates QR codes in SVG format without external dependencies.
 * Supports byte-mode encoding for UTF-8 data (e.g. otpauth:// URIs).
 * Error correction level M, versions 1-10 (up to ~150 bytes).
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * QR Code SVG generator.
 */
class Segurium_QR_SVG {

	// Error-correction level M constants.
	const EC_LEVEL = 0; // Index into per-version arrays (M level).

	/**
	 * Total data codewords per version at EC level M (versions 1-10).
	 *
	 * @var int[]
	 */
	private static $data_codewords = array(
		1  => 16,
		2  => 28,
		3  => 44,
		4  => 64,
		5  => 86,
		6  => 108,
		7  => 124,
		8  => 154,
		9  => 182,
		10 => 216,
	);

	/**
	 * EC codewords per block at level M (versions 1-10).
	 *
	 * @var int[]
	 */
	private static $ec_per_block = array(
		1  => 10,
		2  => 16,
		3  => 26,
		4  => 18,
		5  => 24,
		6  => 16,
		7  => 18,
		8  => 22,
		9  => 22,
		10 => 26,
	);

	/**
	 * Block layout [group1_blocks, group1_data_per_block, group2_blocks, group2_data_per_block]
	 * at EC level M for versions 1-10.
	 *
	 * @var int[][]
	 */
	private static $block_layout = array(
		1  => array( 1, 16, 0, 0 ),
		2  => array( 1, 28, 0, 0 ),
		3  => array( 1, 44, 0, 0 ),
		4  => array( 2, 32, 0, 0 ),
		5  => array( 2, 43, 0, 0 ),
		6  => array( 4, 27, 0, 0 ),
		7  => array( 4, 31, 0, 0 ),
		8  => array( 2, 38, 2, 39 ),
		9  => array( 3, 36, 2, 37 ),
		10 => array( 4, 43, 1, 44 ),
	);

	/**
	 * Alignment pattern positions per version (empty for v1).
	 *
	 * @var int[][]
	 */
	private static $align_pos = array(
		1  => array(),
		2  => array( 6, 18 ),
		3  => array( 6, 22 ),
		4  => array( 6, 26 ),
		5  => array( 6, 30 ),
		6  => array( 6, 34 ),
		7  => array( 6, 22, 38 ),
		8  => array( 6, 24, 42 ),
		9  => array( 6, 26, 46 ),
		10 => array( 6, 28, 50 ),
	);

	/**
	 * Generate an SVG QR code for the given data.
	 *
	 * @param string $data       The data to encode (e.g. otpauth:// URI).
	 * @param int    $module_size Pixel size of each module (default 4).
	 * @param int    $margin     Quiet zone in modules (default 4).
	 * @return string|false SVG markup or false if data is too large.
	 */
	public static function generate( $data, $module_size = 4, $margin = 4 ) {
		$version = self::pick_version( strlen( $data ) );
		if ( false === $version ) {
			return false;
		}

		$bits    = self::encode_data( $data, $version );
		$size    = 17 + $version * 4;
		$modules = self::init_matrix( $size );
		$mask    = self::init_mask( $size );

		self::place_finder_patterns( $modules, $mask, $size );
		self::place_alignment_patterns( $modules, $mask, $version );
		self::place_timing_patterns( $modules, $mask, $size );
		self::place_dark_module( $modules, $mask, $version );
		self::reserve_format_area( $mask, $size );
		if ( $version >= 7 ) {
			self::reserve_version_area( $mask, $size );
		}

		// Save function-pattern mask before data placement so apply_mask
		// can distinguish function modules from data modules.
		$func_mask = $mask;

		self::place_data_bits( $modules, $mask, $bits, $size );

		$best_mask = self::select_best_mask( $modules, $func_mask, $size );
		$masked    = self::apply_mask( $modules, $func_mask, $best_mask, $size );

		self::place_format_info( $masked, $size, $best_mask );
		if ( $version >= 7 ) {
			self::place_version_info( $masked, $size, $version );
		}

		return self::render_svg( $masked, $size, $module_size, $margin );
	}

	/**
	 * Find minimum version that fits the data (byte mode, EC level M).
	 *
	 * @param int $length Data length in bytes.
	 * @return int|false Version number or false if too large.
	 */
	private static function pick_version( $length ) {
		foreach ( self::$data_codewords as $v => $capacity ) {
			// Byte-mode overhead: 4 (mode) + char-count bits + data bits.
			$cc_bits     = ( $v <= 9 ) ? 8 : 16;
			$header_bits = 4 + $cc_bits;
			$avail_bits  = $capacity * 8;
			$needed_bits = $header_bits + $length * 8 + 4; // +4 for terminator.
			if ( $needed_bits <= $avail_bits ) {
				return $v;
			}
		}
		return false;
	}

	/**
	 * Encode data as a bit string and apply EC coding.
	 *
	 * @param string $data    Raw data bytes.
	 * @param int    $version QR version.
	 * @return string Binary string of '0'/'1' characters.
	 */
	private static function encode_data( $data, $version ) {
		$cc_bits  = ( $version <= 9 ) ? 8 : 16;
		$capacity = self::$data_codewords[ $version ] * 8;

		// Mode indicator (byte = 0100) + character count + data.
		$bits  = '0100';
		$bits .= str_pad( decbin( strlen( $data ) ), $cc_bits, '0', STR_PAD_LEFT );
		for ( $i = 0, $len = strlen( $data ); $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		// Terminator (up to 4 zero bits).
		$term  = min( 4, $capacity - strlen( $bits ) );
		$bits .= str_repeat( '0', $term );

		// Pad to byte boundary.
		if ( strlen( $bits ) % 8 !== 0 ) {
			$bits .= str_repeat( '0', 8 - ( strlen( $bits ) % 8 ) );
		}

		// Pad codewords (0xEC, 0x11 alternating).
		$pads     = array( '11101100', '00010001' );
		$pi       = 0;
		$bits_len = strlen( $bits );
		while ( $bits_len < $capacity ) {
			$bits    .= $pads[ $pi ];
			$pi       = 1 - $pi;
			$bits_len = strlen( $bits );
		}

		// Convert to codeword array.
		$codewords = array();
		for ( $i = 0; $i < $capacity; $i += 8 ) {
			$codewords[] = (int) bindec( substr( $bits, $i, 8 ) );
		}

		return self::interleave_with_ec( $codewords, $version );
	}

	/**
	 * Split codewords into blocks, compute EC for each, interleave.
	 *
	 * @param int[] $codewords Data codewords.
	 * @param int   $version   QR version.
	 * @return string Binary string of all data+EC bits.
	 */
	private static function interleave_with_ec( $codewords, $version ) {
		$layout   = self::$block_layout[ $version ];
		$ec_count = self::$ec_per_block[ $version ];

		$blocks    = array();
		$ec_blocks = array();
		$offset    = 0;

		// Group 1.
		for ( $i = 0; $i < $layout[0]; $i++ ) {
			$block       = array_slice( $codewords, $offset, $layout[1] );
			$blocks[]    = $block;
			$offset     += $layout[1];
			$ec_blocks[] = self::reed_solomon( $block, $ec_count );
		}

		// Group 2 (if present).
		for ( $i = 0; $i < $layout[2]; $i++ ) {
			$block       = array_slice( $codewords, $offset, $layout[3] );
			$blocks[]    = $block;
			$offset     += $layout[3];
			$ec_blocks[] = self::reed_solomon( $block, $ec_count );
		}

		// Interleave data codewords.
		$max_data = max( $layout[1], $layout[3] );
		$result   = '';
		for ( $i = 0; $i < $max_data; $i++ ) {
			foreach ( $blocks as $block ) {
				if ( isset( $block[ $i ] ) ) {
					$result .= str_pad( decbin( $block[ $i ] ), 8, '0', STR_PAD_LEFT );
				}
			}
		}

		// Interleave EC codewords.
		for ( $i = 0; $i < $ec_count; $i++ ) {
			foreach ( $ec_blocks as $ec ) {
				$result .= str_pad( decbin( $ec[ $i ] ), 8, '0', STR_PAD_LEFT );
			}
		}

		// Remainder bits (versions 2-6: 7 bits).
		$total_modules = self::total_data_modules( $version );
		if ( strlen( $result ) < $total_modules ) {
			$result .= str_repeat( '0', $total_modules - strlen( $result ) );
		}

		return $result;
	}

	/**
	 * Total data modules available (excluding function patterns).
	 *
	 * @param int $version QR version.
	 * @return int Number of data bit positions.
	 */
	private static function total_data_modules( $version ) {
		return ( self::$data_codewords[ $version ] + self::$ec_per_block[ $version ] * self::total_blocks( $version ) ) * 8;
	}

	/**
	 * Total number of EC blocks for a version.
	 *
	 * @param int $version QR version.
	 * @return int Block count.
	 */
	private static function total_blocks( $version ) {
		$l = self::$block_layout[ $version ];
		return $l[0] + $l[2];
	}

	/**
	 * Reed-Solomon error correction over GF(2^8).
	 *
	 * @param int[] $data     Data codewords.
	 * @param int   $ec_count Number of EC codewords to generate.
	 * @return int[] EC codewords.
	 */
	private static function reed_solomon( $data, $ec_count ) {
		$gf_exp = array();
		$gf_log = array();
		$val    = 1;
		for ( $i = 0; $i < 256; $i++ ) {
			$gf_exp[ $i ]   = $val;
			$gf_log[ $val ] = $i;
			$val          <<= 1;
			if ( $val >= 256 ) {
				$val ^= 0x11D;
			}
		}
		$gf_exp[255] = $gf_exp[0];

		// Build generator polynomial.
		$gen = array( 1 );
		for ( $i = 0; $i < $ec_count; $i++ ) {
			$new_gen = array_fill( 0, count( $gen ) + 1, 0 );
			for ( $j = 0, $jlen = count( $gen ); $j < $jlen; $j++ ) {
				$new_gen[ $j ]     ^= $gen[ $j ];
				$new_gen[ $j + 1 ] ^= self::gf_mul( $gen[ $j ], $gf_exp[ $i ], $gf_exp, $gf_log );
			}
			$gen = $new_gen;
		}

		// Polynomial division.
		$remainder = array_merge( $data, array_fill( 0, $ec_count, 0 ) );
		for ( $i = 0, $dlen = count( $data ); $i < $dlen; $i++ ) {
			$coef = $remainder[ $i ];
			if ( 0 !== $coef ) {
				for ( $j = 0, $glen = count( $gen ); $j < $glen; $j++ ) {
					$remainder[ $i + $j ] ^= self::gf_mul( $gen[ $j ], $coef, $gf_exp, $gf_log );
				}
			}
		}

		return array_slice( $remainder, count( $data ) );
	}

	/**
	 * GF(2^8) multiplication.
	 *
	 * @param int   $a      First operand.
	 * @param int   $b      Second operand.
	 * @param int[] $gf_exp Exponent table.
	 * @param int[] $gf_log Log table.
	 * @return int Product.
	 */
	private static function gf_mul( $a, $b, $gf_exp, $gf_log ) {
		if ( 0 === $a || 0 === $b ) {
			return 0;
		}
		return $gf_exp[ ( $gf_log[ $a ] + $gf_log[ $b ] ) % 255 ];
	}

	/**
	 * Initialize an empty module matrix.
	 *
	 * @param int $size Matrix size.
	 * @return int[][] Matrix filled with -1 (unset).
	 */
	private static function init_matrix( $size ) {
		$row = array_fill( 0, $size, -1 );
		return array_fill( 0, $size, $row );
	}

	/**
	 * Initialize a mask matrix to track reserved modules.
	 *
	 * @param int $size Matrix size.
	 * @return bool[][] Matrix filled with false.
	 */
	private static function init_mask( $size ) {
		$row = array_fill( 0, $size, false );
		return array_fill( 0, $size, $row );
	}

	/**
	 * Place the three finder patterns and their separators.
	 *
	 * @param int[][]  $modules Matrix (by reference).
	 * @param bool[][] $mask    Mask (by reference).
	 * @param int      $size    Matrix size.
	 */
	private static function place_finder_patterns( &$modules, &$mask, $size ) {
		$positions = array(
			array( 0, 0 ),
			array( 0, $size - 7 ),
			array( $size - 7, 0 ),
		);

		foreach ( $positions as $pos ) {
			$r0 = $pos[0];
			$c0 = $pos[1];
			for ( $r = 0; $r < 7; $r++ ) {
				for ( $c = 0; $c < 7; $c++ ) {
					$dark                            = (
						0 === $r || 6 === $r || 0 === $c || 6 === $c ||
						( $r >= 2 && $r <= 4 && $c >= 2 && $c <= 4 )
					);
					$modules[ $r0 + $r ][ $c0 + $c ] = $dark ? 1 : 0;
					$mask[ $r0 + $r ][ $c0 + $c ]    = true;
				}
			}
		}

		// Separators.
		for ( $i = 0; $i < 8; $i++ ) {
			// Top-left.
			self::set_module( $modules, $mask, 7, $i, 0, $size );
			self::set_module( $modules, $mask, $i, 7, 0, $size );
			// Top-right.
			self::set_module( $modules, $mask, 7, $size - 8 + $i, 0, $size );
			self::set_module( $modules, $mask, $i, $size - 8, 0, $size );
			// Bottom-left.
			self::set_module( $modules, $mask, $size - 8, $i, 0, $size );
			self::set_module( $modules, $mask, $size - 8 + $i, 7, 0, $size );
		}
	}

	/**
	 * Set a single module if within bounds.
	 *
	 * @param int[][]  $modules Matrix.
	 * @param bool[][] $mask    Mask.
	 * @param int      $r       Row.
	 * @param int      $c       Column.
	 * @param int      $val     0 or 1.
	 * @param int      $size    Matrix size.
	 */
	private static function set_module( &$modules, &$mask, $r, $c, $val, $size ) {
		if ( $r >= 0 && $r < $size && $c >= 0 && $c < $size ) {
			$modules[ $r ][ $c ] = $val;
			$mask[ $r ][ $c ]    = true;
		}
	}

	/**
	 * Place alignment patterns.
	 *
	 * @param int[][]  $modules Matrix.
	 * @param bool[][] $mask    Mask.
	 * @param int      $version QR version.
	 */
	private static function place_alignment_patterns( &$modules, &$mask, $version ) {
		$positions = self::$align_pos[ $version ];
		if ( empty( $positions ) ) {
			return;
		}

		$count = count( $positions );
		for ( $i = 0; $i < $count; $i++ ) {
			for ( $j = 0; $j < $count; $j++ ) {
				$cr = $positions[ $i ];
				$cc = $positions[ $j ];

				// Skip if overlaps with finder pattern.
				if ( $mask[ $cr ][ $cc ] ) {
					continue;
				}

				for ( $r = -2; $r <= 2; $r++ ) {
					for ( $c = -2; $c <= 2; $c++ ) {
						$dark                            = ( abs( $r ) === 2 || abs( $c ) === 2 || ( 0 === $r && 0 === $c ) );
						$modules[ $cr + $r ][ $cc + $c ] = $dark ? 1 : 0;
						$mask[ $cr + $r ][ $cc + $c ]    = true;
					}
				}
			}
		}
	}

	/**
	 * Place timing patterns.
	 *
	 * @param int[][]  $modules Matrix.
	 * @param bool[][] $mask    Mask.
	 * @param int      $size    Matrix size.
	 */
	private static function place_timing_patterns( &$modules, &$mask, $size ) {
		for ( $i = 8; $i < $size - 8; $i++ ) {
			if ( ! $mask[6][ $i ] ) {
				$modules[6][ $i ] = ( 0 === $i % 2 ) ? 1 : 0;
				$mask[6][ $i ]    = true;
			}
			if ( ! $mask[ $i ][6] ) {
				$modules[ $i ][6] = ( 0 === $i % 2 ) ? 1 : 0;
				$mask[ $i ][6]    = true;
			}
		}
	}

	/**
	 * Place the single dark module.
	 *
	 * @param int[][]  $modules Matrix.
	 * @param bool[][] $mask    Mask.
	 * @param int      $version QR version.
	 */
	private static function place_dark_module( &$modules, &$mask, $version ) {
		$r                = 4 * $version + 9;
		$modules[ $r ][8] = 1;
		$mask[ $r ][8]    = true;
	}

	/**
	 * Reserve format information area (15 bits near finders).
	 *
	 * @param bool[][] $mask Mask.
	 * @param int      $size Matrix size.
	 */
	private static function reserve_format_area( &$mask, $size ) {
		// Around top-left finder.
		for ( $i = 0; $i <= 8; $i++ ) {
			$mask[8][ $i ] = true;
			$mask[ $i ][8] = true;
		}
		// Below top-right finder.
		for ( $i = 0; $i <= 7; $i++ ) {
			$mask[8][ $size - 1 - $i ] = true;
		}
		// Right of bottom-left finder.
		for ( $i = 0; $i <= 7; $i++ ) {
			$mask[ $size - 1 - $i ][8] = true;
		}
	}

	/**
	 * Reserve version information area (versions >= 7).
	 *
	 * @param bool[][] $mask Mask.
	 * @param int      $size Matrix size.
	 */
	private static function reserve_version_area( &$mask, $size ) {
		for ( $i = 0; $i < 6; $i++ ) {
			for ( $j = 0; $j < 3; $j++ ) {
				$mask[ $i ][ $size - 11 + $j ] = true;
				$mask[ $size - 11 + $j ][ $i ] = true;
			}
		}
	}

	/**
	 * Place data bits in the matrix following the upward/downward zigzag.
	 *
	 * @param int[][]  $modules Matrix.
	 * @param bool[][] $mask    Reserved-module mask.
	 * @param string   $bits    Binary string.
	 * @param int      $size    Matrix size.
	 */
	private static function place_data_bits( &$modules, &$mask, $bits, $size ) {
		$bit_idx = 0;
		$bit_len = strlen( $bits );
		$col     = $size - 1;

		while ( $col >= 0 ) {
			// Skip the vertical timing pattern column.
			if ( 6 === $col ) {
				--$col;
			}

			// Upward pass.
			for ( $row = $size - 1; $row >= 0; $row-- ) {
				for ( $c = 0; $c < 2; $c++ ) {
					$cc = $col - $c;
					if ( $cc < 0 ) {
						continue;
					}
					if ( $mask[ $row ][ $cc ] ) {
						continue;
					}
					$modules[ $row ][ $cc ] = ( $bit_idx < $bit_len && '1' === $bits[ $bit_idx ] ) ? 1 : 0;
					$mask[ $row ][ $cc ]    = true;
					++$bit_idx;
				}
			}

			$col -= 2;
			if ( $col < 0 ) {
				break;
			}

			// Skip the vertical timing pattern column.
			if ( 6 === $col ) {
				--$col;
			}

			// Downward pass.
			for ( $row = 0; $row < $size; $row++ ) {
				for ( $c = 0; $c < 2; $c++ ) {
					$cc = $col - $c;
					if ( $cc < 0 ) {
						continue;
					}
					if ( $mask[ $row ][ $cc ] ) {
						continue;
					}
					$modules[ $row ][ $cc ] = ( $bit_idx < $bit_len && '1' === $bits[ $bit_idx ] ) ? 1 : 0;
					$mask[ $row ][ $cc ]    = true;
					++$bit_idx;
				}
			}

			$col -= 2;
		}
	}

	/**
	 * Evaluate all 8 mask patterns and return the best one.
	 *
	 * @param int[][]  $modules Data matrix.
	 * @param bool[][] $mask    Reserved-module mask.
	 * @param int      $size    Matrix size.
	 * @return int Best mask pattern (0-7).
	 */
	private static function select_best_mask( $modules, $mask, $size ) {
		$best_score = PHP_INT_MAX;
		$best_mask  = 0;

		for ( $m = 0; $m < 8; $m++ ) {
			$candidate = self::apply_mask( $modules, $mask, $m, $size );
			$score     = self::evaluate_penalty( $candidate, $size );
			if ( $score < $best_score ) {
				$best_score = $score;
				$best_mask  = $m;
			}
		}

		return $best_mask;
	}

	/**
	 * Apply a mask pattern to data modules.
	 *
	 * @param int[][]  $modules Data matrix.
	 * @param bool[][] $func_mask Function-pattern mask (true = reserved, skip).
	 * @param int      $pattern  Mask pattern (0-7).
	 * @param int      $size     Matrix size.
	 * @return int[][] Masked matrix.
	 */
	private static function apply_mask( $modules, $func_mask, $pattern, $size ) {
		$result = $modules;
		for ( $r = 0; $r < $size; $r++ ) {
			for ( $c = 0; $c < $size; $c++ ) {
				// Only flip data modules: skip function-pattern areas.
				if ( $func_mask[ $r ][ $c ] ) {
					continue;
				}
				if ( self::should_mask( $r, $c, $pattern ) ) {
					$result[ $r ][ $c ] ^= 1;
				}
			}
		}
		return $result;
	}

	/**
	 * Check if a module should be masked.
	 *
	 * @param int $r       Row.
	 * @param int $c       Column.
	 * @param int $pattern Mask pattern (0-7).
	 * @return bool True if module should be flipped.
	 */
	private static function should_mask( $r, $c, $pattern ) {
		switch ( $pattern ) {
			case 0:
				return ( ( $r + $c ) % 2 === 0 );
			case 1:
				return ( 0 === $r % 2 );
			case 2:
				return ( 0 === $c % 3 );
			case 3:
				return ( ( $r + $c ) % 3 === 0 );
			case 4:
				return ( ( intdiv( $r, 2 ) + intdiv( $c, 3 ) ) % 2 === 0 );
			case 5:
				return ( ( ( $r * $c ) % 2 + ( $r * $c ) % 3 ) === 0 );
			case 6:
				return ( ( ( $r * $c ) % 2 + ( $r * $c ) % 3 ) % 2 === 0 );
			case 7:
				return ( ( ( $r + $c ) % 2 + ( $r * $c ) % 3 ) % 2 === 0 );
			default:
				return false;
		}
	}

	/**
	 * Evaluate penalty score for a masked matrix (simplified).
	 *
	 * @param int[][] $matrix Masked matrix.
	 * @param int     $size   Matrix size.
	 * @return int Penalty score.
	 */
	private static function evaluate_penalty( $matrix, $size ) {
		$penalty = 0;

		// Rule 1: Runs of same color >= 5.
		for ( $r = 0; $r < $size; $r++ ) {
			$count = 1;
			for ( $c = 1; $c < $size; $c++ ) {
				if ( $matrix[ $r ][ $c ] === $matrix[ $r ][ $c - 1 ] ) {
					++$count;
				} else {
					if ( $count >= 5 ) {
						$penalty += $count - 2;
					}
					$count = 1;
				}
			}
			if ( $count >= 5 ) {
				$penalty += $count - 2;
			}
		}
		for ( $c = 0; $c < $size; $c++ ) {
			$count = 1;
			for ( $r = 1; $r < $size; $r++ ) {
				if ( $matrix[ $r ][ $c ] === $matrix[ $r - 1 ][ $c ] ) {
					++$count;
				} else {
					if ( $count >= 5 ) {
						$penalty += $count - 2;
					}
					$count = 1;
				}
			}
			if ( $count >= 5 ) {
				$penalty += $count - 2;
			}
		}

		// Rule 2: 2x2 blocks of same color.
		for ( $r = 0; $r < $size - 1; $r++ ) {
			for ( $c = 0; $c < $size - 1; $c++ ) {
				$v = $matrix[ $r ][ $c ];
				if ( $v === $matrix[ $r ][ $c + 1 ]
					&& $v === $matrix[ $r + 1 ][ $c ]
					&& $v === $matrix[ $r + 1 ][ $c + 1 ] ) {
					$penalty += 3;
				}
			}
		}

		// Rule 4: Proportion of dark modules.
		$dark = 0;
		for ( $r = 0; $r < $size; $r++ ) {
			for ( $c = 0; $c < $size; $c++ ) {
				if ( 1 === $matrix[ $r ][ $c ] ) {
					++$dark;
				}
			}
		}
		$total    = $size * $size;
		$percent  = ( $dark * 100 ) / $total;
		$prev5    = (int) ( floor( $percent / 5 ) * 5 );
		$next5    = $prev5 + 5;
		$penalty += min( abs( $prev5 - 50 ) / 5, abs( $next5 - 50 ) / 5 ) * 10;

		return (int) $penalty;
	}

	/**
	 * Place format information bits.
	 *
	 * @param int[][] $modules Matrix.
	 * @param int     $size    Matrix size.
	 * @param int     $mask_pattern Mask pattern used.
	 */
	private static function place_format_info( &$modules, $size, $mask_pattern ) {
		// EC level M = 00, mask pattern 3 bits.
		$data = ( 0 << 3 ) | $mask_pattern; // EC M = 0b00.
		$bits = self::format_info_bits( $data );

		// Around top-left finder (row 8 horizontal, column 8 vertical).
		$positions_h = array(
			array( 8, 0 ),
			array( 8, 1 ),
			array( 8, 2 ),
			array( 8, 3 ),
			array( 8, 4 ),
			array( 8, 5 ),
			array( 8, 7 ),
			array( 8, 8 ),
			array( 7, 8 ),
			array( 5, 8 ),
			array( 4, 8 ),
			array( 3, 8 ),
			array( 2, 8 ),
			array( 1, 8 ),
			array( 0, 8 ),
		);

		for ( $i = 0; $i < 15; $i++ ) {
			$modules[ $positions_h[ $i ][0] ][ $positions_h[ $i ][1] ] = ( ( $bits >> ( 14 - $i ) ) & 1 );
		}

		// Second copy: bottom-left vertical (column 8) + top-right horizontal (row 8).
		for ( $i = 0; $i < 7; $i++ ) {
			$modules[ $size - 1 - $i ][8] = ( ( $bits >> $i ) & 1 );
		}
		for ( $i = 0; $i < 8; $i++ ) {
			$modules[8][ $size - 8 + $i ] = ( ( $bits >> ( 7 + $i ) ) & 1 );
		}
	}

	/**
	 * Compute 15-bit format information with BCH error correction.
	 *
	 * @param int $data 5-bit format data (EC level + mask).
	 * @return int 15-bit format info with mask applied.
	 */
	private static function format_info_bits( $data ) {
		$poly = 0x537; // Generator polynomial x^10 + x^8 + x^5 + x^4 + x^2 + x + 1.
		$bits = $data << 10;
		$rem  = $bits;
		for ( $i = 4; $i >= 0; $i-- ) {
			if ( $rem & ( 1 << ( $i + 10 ) ) ) {
				$rem ^= $poly << $i;
			}
		}
		$result = ( $bits | $rem ) ^ 0x5412; // XOR mask pattern.
		return $result;
	}

	/**
	 * Place version information bits (versions >= 7).
	 *
	 * @param int[][] $modules Matrix.
	 * @param int     $size    Matrix size.
	 * @param int     $version QR version.
	 */
	private static function place_version_info( &$modules, $size, $version ) {
		$bits = self::version_info_bits( $version );

		for ( $i = 0; $i < 18; $i++ ) {
			$bit                 = ( $bits >> $i ) & 1;
			$r                   = intdiv( $i, 3 );
			$c                   = ( $i % 3 ) + $size - 11;
			$modules[ $r ][ $c ] = $bit;
			$modules[ $c ][ $r ] = $bit;
		}
	}

	/**
	 * Compute 18-bit version information with BCH.
	 *
	 * @param int $version QR version.
	 * @return int 18-bit version info.
	 */
	private static function version_info_bits( $version ) {
		$poly = 0x1F25;
		$bits = $version << 12;
		$rem  = $bits;
		for ( $i = 5; $i >= 0; $i-- ) {
			if ( $rem & ( 1 << ( $i + 12 ) ) ) {
				$rem ^= $poly << $i;
			}
		}
		return $bits | $rem;
	}

	/**
	 * Render the module matrix as an SVG string.
	 *
	 * @param int[][] $modules     Module matrix.
	 * @param int     $size        Matrix size.
	 * @param int     $module_size Pixel size of each module.
	 * @param int     $margin      Quiet zone in modules.
	 * @return string SVG markup.
	 */
	private static function render_svg( $modules, $size, $module_size, $margin ) {
		$full = ( $size + 2 * $margin ) * $module_size;
		$svg  = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $full . ' ' . $full . '" width="' . $full . '" height="' . $full . '">';
		$svg .= '<rect width="' . $full . '" height="' . $full . '" fill="#ffffff"/>';

		// Build path for all dark modules.
		$path = '';
		for ( $r = 0; $r < $size; $r++ ) {
			for ( $c = 0; $c < $size; $c++ ) {
				if ( 1 === $modules[ $r ][ $c ] ) {
					$x     = ( $c + $margin ) * $module_size;
					$y     = ( $r + $margin ) * $module_size;
					$path .= 'M' . $x . ',' . $y . 'h' . $module_size . 'v' . $module_size . 'h-' . $module_size . 'z';
				}
			}
		}

		if ( '' !== $path ) {
			$svg .= '<path d="' . $path . '" fill="#000000"/>';
		}

		$svg .= '</svg>';
		return $svg;
	}
}

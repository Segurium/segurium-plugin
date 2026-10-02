<?php
/**
 * Outline icons for the Segurium admin, drawn from Tabler Icons 3.48.0
 * (MIT, Copyright (c) 2020-2026 Paweł Kuna; licence text in
 * assets/licenses/tabler-icons.txt).
 *
 * The admin page prints one hidden sprite. Each icon is a small inline
 * `<svg>` that points at a sprite symbol, so PHP templates and the admin
 * scripts draw the same shapes.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tabler sprite and the markup that references it.
 */
class Segurium_Icons {

	const ID_PREFIX = 'segurium-icon-';

	/**
	 * Path data per icon on a 24x24 grid, stroked 2px with round caps.
	 */
	const PATHS = array(
		'stethoscope'       => array(
			'M6 4h-1a2 2 0 0 0 -2 2v3.5a5.5 5.5 0 0 0 11 0v-3.5a2 2 0 0 0 -2 -2h-1',
			'M8 15a6 6 0 1 0 12 0v-3',
			'M11 3v2',
			'M6 3v2',
			'M18 10a2 2 0 1 0 4 0a2 2 0 1 0 -4 0',
		),
		'virus-search'      => array(
			'M17 12a5 5 0 1 0 -5 5',
			'M12 7v-4',
			'M11 3h2',
			'M15.536 8.464l2.828 -2.828',
			'M17.657 4.929l1.414 1.414',
			'M17 12h4',
			'M21 11v2',
			'M12 17v4',
			'M13 21h-2',
			'M8.465 15.536l-2.829 2.828',
			'M6.343 19.071l-1.413 -1.414',
			'M7 12h-4',
			'M3 13v-2',
			'M8.464 8.464l-2.828 -2.828',
			'M4.929 6.343l1.414 -1.413',
			'M15 17.5a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0 -5 0',
			'M19.5 19.5l2.5 2.5',
		),
		'file-check'        => array(
			'M14 3v4a1 1 0 0 0 1 1h4',
			'M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2',
			'M9 15l2 2l4 -4',
		),
		'world-cancel'      => array(
			'M21 12a9 9 0 1 0 -8.985 9',
			'M3.6 9h16.8',
			'M3.6 15h9.9',
			'M11.5 3a17 17 0 0 0 0 18',
			'M12.5 3a16.991 16.991 0 0 1 2.53 10.275',
			'M16 19a3 3 0 1 0 6 0a3 3 0 1 0 -6 0',
			'M17 21l4 -4',
		),
		'wall'              => array(
			'M4 6a2 2 0 0 1 2 -2h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2l0 -12',
			'M4 8h16',
			'M20 12h-16',
			'M4 16h16',
			'M9 4v4',
			'M14 8v4',
			'M8 12v4',
			'M16 12v4',
			'M11 16v4',
		),
		'lock-password'     => array(
			'M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2l0 -6',
			'M8 11v-4a4 4 0 1 1 8 0v4',
			'M15 16h.01',
			'M12.01 16h.01',
			'M9.02 16h.01',
		),
		'key'               => array(
			'M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1 -4.069 0l-.301 -.301l-6.558 6.558a2 2 0 0 1 -1.239 .578l-.175 .008h-1.172a1 1 0 0 1 -.993 -.883l-.007 -.117v-1.172a2 2 0 0 1 .467 -1.284l.119 -.13l.414 -.414h2v-2h2v-2l2.144 -2.144l-.301 -.301a2.877 2.877 0 0 1 0 -4.069l2.643 -2.643a2.877 2.877 0 0 1 4.069 0',
			'M15 9h.01',
		),
		'code'              => array(
			'M7 8l-4 4l4 4',
			'M17 8l4 4l-4 4',
			'M14 4l-4 16',
		),
		'eye-off'           => array(
			'M10.585 10.587a2 2 0 0 0 2.829 2.828',
			'M16.681 16.673a8.717 8.717 0 0 1 -4.681 1.327c-3.6 0 -6.6 -2 -9 -6c1.272 -2.12 2.712 -3.678 4.32 -4.674m2.86 -1.146a9.055 9.055 0 0 1 1.82 -.18c3.6 0 6.6 2 9 6c-.666 1.11 -1.379 2.067 -2.138 2.87',
			'M3 3l18 18',
		),
		'settings'          => array(
			'M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065',
			'M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0',
		),
		'arrows-left-right' => array(
			'M21 17l-18 0',
			'M6 10l-3 -3l3 -3',
			'M3 7l18 0',
			'M18 20l3 -3l-3 -3',
		),
		'lifebuoy'          => array(
			'M8 12a4 4 0 1 0 8 0a4 4 0 1 0 -8 0',
			'M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0',
			'M15 15l3.35 3.35',
			'M9 15l-3.35 3.35',
			'M5.65 5.65l3.35 3.35',
			'M18.35 5.65l-3.35 3.35',
		),
		'diamond'           => array(
			'M6 5h12l3 5l-8.5 9.5a.7 .7 0 0 1 -1 0l-8.5 -9.5l3 -5',
			'M10 12l-2 -2.2l.6 -1',
		),
		'history'           => array(
			'M12 8l0 4l2 2',
			'M3.05 11a9 9 0 1 1 .5 4m-.5 5v-5h5',
		),
		'cloud-check'       => array(
			'M11 18.004h-4.343c-2.572 -.004 -4.657 -2.011 -4.657 -4.487c0 -2.475 2.085 -4.482 4.657 -4.482c.393 -1.762 1.794 -3.2 3.675 -3.773c1.88 -.572 3.956 -.193 5.444 1c1.488 1.19 2.162 3.007 1.77 4.769h.99c1.388 0 2.585 .82 3.138 2.007',
			'M15 19l2 2l4 -4',
		),
		'cloud-off'         => array(
			'M9.58 5.548c.24 -.11 .492 -.207 .752 -.286c1.88 -.572 3.956 -.193 5.444 1c1.488 1.19 2.162 3.007 1.77 4.769h.99c1.913 0 3.464 1.56 3.464 3.486c0 .957 -.383 1.824 -1.003 2.454m-2.997 1.033h-11.343c-2.572 -.004 -4.657 -2.011 -4.657 -4.487c0 -2.475 2.085 -4.482 4.657 -4.482c.13 -.582 .37 -1.128 .7 -1.62',
			'M3 3l18 18',
		),
		'stopwatch'         => array(
			'M5 13a7 7 0 1 0 14 0a7 7 0 0 0 -14 0',
			'M14.5 10.5l-2.5 2.5',
			'M17 8l1 -1',
			'M14 3h-4',
		),
		'circle-check'      => array(
			'M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0',
			'M9 12l2 2l4 -4',
		),
		'alert-triangle'    => array(
			'M12 9v4',
			'M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.87l-8.106 -13.536a1.914 1.914 0 0 0 -3.274 0',
			'M12 16h.01',
		),
		'circle-x'          => array(
			'M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0',
			'M10 10l4 4m0 -4l-4 4',
		),
		'check'             => array(
			'M5 12l5 5l10 -10',
		),
		'copy'              => array(
			'M7 9.667a2.667 2.667 0 0 1 2.667 -2.667h8.666a2.667 2.667 0 0 1 2.667 2.667v8.666a2.667 2.667 0 0 1 -2.667 2.667h-8.666a2.667 2.667 0 0 1 -2.667 -2.667l0 -8.666',
			'M4.012 16.737a2.005 2.005 0 0 1 -1.012 -1.737v-10c0 -1.1 .9 -2 2 -2h10c.75 0 1.158 .385 1.5 1',
		),
		'dots'              => array(
			'M4 12a1 1 0 1 0 2 0a1 1 0 1 0 -2 0',
			'M11 12a1 1 0 1 0 2 0a1 1 0 1 0 -2 0',
			'M18 12a1 1 0 1 0 2 0a1 1 0 1 0 -2 0',
		),
		'chevron-right'     => array(
			'M9 6l6 6l-6 6',
		),
		'brand-wordpress'   => array(
			'M9.5 9h3',
			'M4 9h2.5',
			'M11 9l3 11l4 -9',
			'M5.5 9l3.5 11l3 -7',
			'M18 11c.177 -.528 1 -1.364 1 -2.5c0 -1.78 -.776 -2.5 -1.875 -2.5c-.898 0 -1.125 .812 -1.125 1.429c0 1.83 2 2.058 2 3.571',
			'M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0',
		),
		'plug'              => array(
			'M9.785 6l8.215 8.215l-2.054 2.054a5.81 5.81 0 1 1 -8.215 -8.215l2.054 -2.054',
			'M4 20l3.5 -3.5',
			'M15 4l-3.5 3.5',
			'M20 9l-3.5 3.5',
		),
		'brush'             => array(
			'M3 21v-4a4 4 0 1 1 4 4h-4',
			'M21 3a16 16 0 0 0 -12.8 10.2',
			'M21 3a16 16 0 0 1 -10.2 12.8',
			'M10.6 9a9 9 0 0 1 4.4 4.4',
		),
		'help'              => array(
			'M3 12a9 9 0 1 0 18 0a9 9 0 1 0 -18 0',
			'M12 17l0 .01',
			'M12 13.5a1.5 1.5 0 0 1 1 -1.5a2.6 2.6 0 1 0 -3 -4',
		),
	);

	/**
	 * Every icon the sprite carries.
	 *
	 * @return string[]
	 */
	public static function names() {
		return array_keys( self::PATHS );
	}

	/**
	 * The hidden sprite, one `<symbol>` per icon.
	 *
	 * @return string
	 */
	public static function sprite() {
		$symbols = '';
		foreach ( self::PATHS as $name => $paths ) {
			$symbols .= '<symbol id="' . self::ID_PREFIX . $name . '" viewBox="0 0 24 24">';
			foreach ( $paths as $d ) {
				$symbols .= '<path d="' . $d . '"></path>';
			}
			$symbols .= '</symbol>';
		}
		return '<svg xmlns="http://www.w3.org/2000/svg" class="segurium-icon-sprite" width="0" height="0" aria-hidden="true" focusable="false">' . $symbols . '</svg>';
	}

	/**
	 * Markup for one icon. Empty string, plus a developer notice, for a
	 * name the sprite does not carry.
	 *
	 * @param string $name        Icon name, one of names().
	 * @param string $extra_class Extra classes for the `<svg>`.
	 * @return string
	 */
	public static function svg( $name, $extra_class = '' ) {
		if ( ! is_string( $name ) || ! isset( self::PATHS[ $name ] ) ) {
			_doing_it_wrong( __METHOD__, esc_html( sprintf( 'Unknown Segurium icon: %s.', is_scalar( $name ) ? (string) $name : gettype( $name ) ) ), '' );
			return '';
		}
		$class = 'segurium-icon segurium-icon--' . $name . ( '' !== $extra_class ? ' ' . $extra_class : '' );
		return '<svg class="' . esc_attr( $class ) . '" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
			. '<use href="#' . self::ID_PREFIX . $name . '"></use></svg>';
	}

	/**
	 * Echo one icon.
	 *
	 * @param string $name        Icon name, one of names().
	 * @param string $extra_class Extra classes for the `<svg>`.
	 * @return void
	 */
	public static function render( $name, $extra_class = '' ) {
		echo wp_kses( self::svg( $name, $extra_class ), self::allowed_html() );
	}

	/**
	 * Echo the sprite. Call once per page, before any icon.
	 *
	 * @return void
	 */
	public static function render_sprite() {
		echo wp_kses( self::sprite(), self::allowed_html() );
	}

	/**
	 * The tags and attributes sprite() and svg() emit, for wp_kses().
	 *
	 * @return array<string, array<string, bool>>
	 */
	public static function allowed_html() {
		return array(
			'svg'    => array(
				'xmlns'           => true,
				'class'           => true,
				'width'           => true,
				'height'          => true,
				'viewbox'         => true,
				'fill'            => true,
				'stroke'          => true,
				'stroke-width'    => true,
				'stroke-linecap'  => true,
				'stroke-linejoin' => true,
				'aria-hidden'     => true,
				'focusable'       => true,
			),
			'symbol' => array(
				'id'      => true,
				'viewbox' => true,
			),
			'path'   => array( 'd' => true ),
			'use'    => array( 'href' => true ),
		);
	}
}

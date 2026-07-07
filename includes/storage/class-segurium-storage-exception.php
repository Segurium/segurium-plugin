<?php
/**
 * Storage-layer exception.
 *
 * Thrown when $wpdb reports an error during an insert/update/delete/upsert
 * operation issued through the façade. Callers either catch and log it or
 * let it bubble up — either way the error surface is uniform.
 *
 * @package Segurium
 */

declare(strict_types=1);

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Storage error wrapper.
 */
class Segurium_Storage_Exception extends RuntimeException {
}

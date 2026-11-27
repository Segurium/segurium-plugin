<?php
/**
 * What one content kind does for its findings.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handler of one content kind. A finding is its table row with `detail`
 * decoded; during a cleanup it also carries `actor`.
 */
interface Segurium_Content_Finding_Kind {

	/**
	 * Content kind, as the pipeline and the cloud name it.
	 *
	 * @return string
	 */
	public function kind();

	/**
	 * Whether a cleanup can be undone. Without Restore a cured row offers no
	 * action and keeps no backup once the cleanup is done.
	 *
	 * @return bool
	 */
	public function restorable();

	/**
	 * Findings of one completed run.
	 *
	 * @param array $verdicts Items with a verdict, as {@see Segurium_Content_Items::verdicts()} returns them.
	 * @return array{threats:array,clean:array} `threats`: list of `{key, locator, sha256, verdict, detail}`;
	 *         `clean`: keys of the items that ended clean. The key names the target: one key, one row.
	 */
	public function detections( array $verdicts );

	/**
	 * Whether the target of a finding is still on the site.
	 *
	 * @param array $finding Finding.
	 * @return bool
	 */
	public function exists( array $finding );

	/**
	 * The site state a cleanup changes, as the bytes of its backup.
	 *
	 * @param array $finding Finding.
	 * @return string|WP_Error The error code becomes the reason of the refusal.
	 */
	public function snapshot( array $finding );

	/**
	 * Apply the cloud's cleaned version. On an error nothing changed, unless
	 * the error data holds `staged`: writes {@see Segurium_Content_Findings::stage()}
	 * recorded could not be undone, and the next cleanup undoes them first.
	 *
	 * @param array  $finding  Finding.
	 * @param string $snapshot Bytes {@see snapshot()} returned, stored and verified.
	 * @param string $cleaned  Cleaned version; '' removes the target.
	 * @return array|WP_Error What Restore needs to undo, stored with the finding.
	 */
	public function apply( array $finding, $snapshot, $cleaned );

	/**
	 * Put the backup back and undo what {@see apply()} put in place. With
	 * `staged_undo` set the finding names writes that may not have run.
	 *
	 * @param array  $finding  Finding, with `detail.applied`.
	 * @param string $snapshot Backup bytes; '' when the backup cannot be read.
	 * @return true|WP_Error `backup_unreadable` when the bytes are needed and '' or broken.
	 */
	public function restore( array $finding, $snapshot );

	/**
	 * Row label on the Malware Scanner tab.
	 *
	 * @param array $finding Finding.
	 * @return string Translated.
	 */
	public function label( array $finding );

	/**
	 * Location text under the label.
	 *
	 * @param array $finding Finding.
	 * @return string Translated.
	 */
	public function location( array $finding );
}

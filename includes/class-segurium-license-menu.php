<?php
/**
 * Activate License entry points for free sites.
 *
 * @package Segurium
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds routes to the Freemius license dialog. Labels are the SDK's own strings.
 */
final class Segurium_License_Menu {

	const PARENT_SLUG   = 'segurium';
	const ACCOUNT_SLUG  = 'segurium-account';
	const OPEN_HASH     = 'segurium-activate-license';
	const ACTIVATE_SLUG = 'admin.php?page=' . self::ACCOUNT_SLUG . '#' . self::OPEN_HASH;

	/**
	 * Singleton.
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
	 * Returns the cached cloud plan tier.
	 *
	 * @var callable
	 */
	private $tier_accessor;

	/**
	 * Constructor.
	 *
	 * @param callable|null $sdk_accessor  Returns the Freemius SDK instance, or null.
	 * @param callable|null $tier_accessor Returns the cloud plan tier.
	 */
	public function __construct( $sdk_accessor = null, $tier_accessor = null ) {
		$this->sdk_accessor  = is_callable( $sdk_accessor ) ? $sdk_accessor : static function () {
			return function_exists( 'segurium_fs' ) ? segurium_fs() : null;
		};
		$this->tier_accessor = is_callable( $tier_accessor ) ? $tier_accessor : static function () {
			return class_exists( 'Segurium_Quota' ) ? Segurium_Quota::plan_tier() : 'free';
		};
	}

	/**
	 * Singleton.
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
	 * Wire the menu, the dialog style, the auto-open script and the Account page button.
	 *
	 * @return bool False when the SDK is unavailable.
	 */
	public function register_hooks() {
		$fs = $this->load_sdk();
		if ( null === $fs || ! method_exists( $fs, 'add_action' ) ) {
			return false;
		}

		add_action( 'admin_menu', array( $this, 'add_menu_items' ), PHP_INT_MAX );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_dialog_style' ) );
		add_action( 'admin_footer', array( $this, 'print_auto_open' ), PHP_INT_MAX );

		try {
			$fs->add_action( 'after_account_details', array( $this, 'render_account_trigger' ) );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-license-menu] add_action failed: code=sdk_hook_rejected — ' . $e->getMessage() );
			return false;
		}
		return true;
	}

	/**
	 * Admin_menu callback, after the SDK has built its submenu.
	 *
	 * @return void
	 */
	public function add_menu_items() {
		global $submenu;

		$fs = $this->load_sdk();
		if ( null === $fs || ! $this->is_free_site( $fs ) ) {
			return;
		}

		if ( '' === menu_page_url( self::ACCOUNT_SLUG, false ) ) {
			$account = $this->label( $fs, 'Account', 'account' );
			add_submenu_page( self::PARENT_SLUG, $account, $account, 'manage_options', self::ACCOUNT_SLUG, array( $this, 'render_account_page' ), 1 );
		}

		$items    = isset( $submenu[ self::PARENT_SLUG ] ) ? array_values( (array) $submenu[ self::PARENT_SLUG ] ) : array();
		$position = array_search( self::ACCOUNT_SLUG, array_column( $items, 2 ), true );
		$activate = $this->label( $fs, 'Activate License', 'activate-license' );
		add_submenu_page(
			self::PARENT_SLUG,
			$activate,
			$activate,
			'manage_options',
			self::ACTIVATE_SLUG,
			'',
			false === $position ? count( $items ) : $position + 1
		);
	}

	/**
	 * Account route for installs the SDK has not registered.
	 *
	 * @return void
	 */
	public function render_account_page() {
		$fs = $this->load_sdk();
		if ( null === $fs ) {
			return;
		}

		$upgrade_url = class_exists( 'Segurium_Entitlements' ) ? Segurium_Entitlements::instance()->upgrade_url() : '';
		$offsite     = '' !== $upgrade_url && Segurium_Entitlements::is_offsite_url( $upgrade_url );
		?>
		<div class="wrap">
			<h1><?php echo esc_html( $this->label( $fs, 'Account', 'account' ) ); ?></h1>
			<div class="card">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Plan', 'segurium' ); ?></th>
						<td><?php esc_html_e( 'Free', 'segurium' ); ?></td>
					</tr>
				</table>
				<p>
					<?php $this->print_trigger( $fs ); ?>
					<?php if ( '' !== $upgrade_url ) : ?>
						<a class="button" href="<?php echo esc_url( $upgrade_url ); ?>"<?php echo $offsite ? ' target="_blank" rel="noopener noreferrer"' : ''; ?>><?php esc_html_e( 'Upgrade to Pro', 'segurium' ); ?></a>
					<?php endif; ?>
				</p>
			</div>
		</div>
		<?php
		if ( method_exists( $fs, '_add_license_activation_dialog_box' ) ) {
			$fs->_add_license_activation_dialog_box();
		}
	}

	/**
	 * SDK `after_account_details` callback on the registered Account page.
	 *
	 * @return void
	 */
	public function render_account_trigger() {
		$fs = $this->load_sdk();
		if ( null === $fs || ! $this->is_free_site( $fs ) ) {
			return;
		}
		?>
		<div class="postbox">
			<h3><span class="dashicons dashicons-admin-network"></span> <?php echo esc_html( $this->label( $fs, 'License', 'license' ) ); ?></h3>
			<div class="inside">
				<p><?php $this->print_trigger( $fs ); ?></p>
			</div>
		</div>
		<?php
	}

	/**
	 * The SDK template enqueues this stylesheet mid-render, so it prints after the modal it hides.
	 *
	 * @return void
	 */
	public function enqueue_dialog_style() {
		if ( self::on_account_page() && function_exists( 'fs_enqueue_local_style' ) ) {
			fs_enqueue_local_style( 'fs_dialog_boxes', '/admin/dialog-boxes.css' );
		}
	}

	/**
	 * Open the dialog once the SDK's jQuery ready callback has appended it; with a warm cache that runs after `load`.
	 *
	 * @return void
	 */
	public function print_auto_open() {
		if ( ! self::on_account_page() ) {
			return;
		}
		$fs = $this->load_sdk();
		if ( null === $fs || ! $this->is_free_site( $fs ) ) {
			return;
		}
		$affix = sanitize_html_class( $fs->get_unique_affix() );
		wp_print_inline_script_tag(
			'(function(){var h=' . wp_json_encode( '#' . self::OPEN_HASH ) . ';function o(n){'
			. 'var m=document.querySelector(' . wp_json_encode( '.fs-modal-license-activation-' . $affix ) . '),'
			. 't=document.querySelector(' . wp_json_encode( '.activate-license-trigger.' . $affix ) . ');'
			. 'if(m&&t){window.history.replaceState(null,"",window.location.pathname+window.location.search);t.click();return;}'
			. 'if(n<50){setTimeout(function(){o(n+1);},100);}}'
			. 'function g(){if(window.location.hash===h){o(0);}}'
			. 'window.addEventListener("hashchange",g);'
			. 'if(document.readyState==="complete"){g();}else{window.addEventListener("load",g);}})();'
		);
	}

	/**
	 * Free on the cloud tier, and not paying in the SDK, which flips first after an activation.
	 *
	 * @param object $fs Freemius SDK instance.
	 * @return bool
	 */
	private function is_free_site( $fs ) {
		if ( 'pro' === call_user_func( $this->tier_accessor ) ) {
			return false;
		}
		try {
			return ! $fs->is_paying();
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-license-menu] is_paying failed: code=sdk_exception — ' . $e->getMessage() );
			return false;
		}
	}

	/**
	 * Print the button the SDK dialog listens for.
	 *
	 * @param object $fs Freemius SDK instance.
	 * @return void
	 */
	private function print_trigger( $fs ) {
		printf(
			'<a class="button button-primary activate-license-trigger %1$s" href="#">%2$s</a>',
			esc_attr( $fs->get_unique_affix() ),
			esc_html( $this->label( $fs, 'Activate License', 'activate-license' ) )
		);
	}

	/**
	 * SDK translation of one of its own strings.
	 *
	 * @param object $fs   Freemius SDK instance.
	 * @param string $text Source string as the SDK spells it.
	 * @param string $key  SDK string key.
	 * @return string
	 */
	private function label( $fs, $text, $key ) {
		return (string) $fs->get_text_inline( $text, $key );
	}

	/**
	 * Whether the request renders the Account route.
	 *
	 * @return bool
	 */
	private static function on_account_page() {
		global $plugin_page;
		return self::ACCOUNT_SLUG === $plugin_page;
	}

	/**
	 * Resolve the Freemius SDK instance.
	 *
	 * @return object|null
	 */
	private function load_sdk() {
		try {
			$fs = call_user_func( $this->sdk_accessor );
		} catch ( Throwable $e ) {
			Segurium_Debug::log( '[segurium-license-menu] SDK load failed: code=sdk_exception — ' . $e->getMessage() );
			return null;
		}
		return is_object( $fs ) ? $fs : null;
	}
}

/**
 * Segurium 2FA AJAX login interceptor.
 *
 * Intercepts the WordPress login form, authenticates via AJAX,
 * and renders an inline 2FA challenge when required.
 *
 * @package Segurium
 */
(function () {
	'use strict';

	var cfg = window.seguriumLogin;
	if ( ! cfg || ! cfg.ajaxUrl ) {
		return;
	}
	var i18n = cfg.i18n || {};

	var form = document.getElementById( 'loginform' );
	if ( ! form ) {
		return;
	}

	var submitBtn   = form.querySelector( '#wp-submit' );
	var userField   = form.querySelector( '#user_login' );
	var passField   = form.querySelector( '#user_pass' );
	var rememberBox = form.querySelector( '#rememberme' );

	// State for the 2FA challenge phase.
	var tfaToken    = null;
	var tfaMethod   = null;
	var inChallenge = false;

	/**
	 * Show an error message above the form.
	 *
	 * @param {string} message Error text.
	 */
	function showError( message ) {
		var existing = document.getElementById( 'login_error' );
		if ( existing ) {
			existing.innerHTML = '<strong>' + escHtml( message ) + '</strong>';
			return;
		}
		var div = document.createElement( 'div' );
		div.id  = 'login_error';
		div.innerHTML = '<strong>' + escHtml( message ) + '</strong>';
		form.parentNode.insertBefore( div, form );
	}

	/**
	 * Clear error messages.
	 */
	function clearError() {
		var el = document.getElementById( 'login_error' );
		if ( el ) {
			el.parentNode.removeChild( el );
		}
	}

	/**
	 * Clear info/success messages.
	 */
	function clearMessages() {
		var el = document.querySelector( '.message, #login_error' );
		if ( el ) {
			el.parentNode.removeChild( el );
		}
	}

	/**
	 * Show an info message above the form.
	 *
	 * @param {string} message Info text.
	 */
	function showMessage( message ) {
		clearMessages();
		var div = document.createElement( 'p' );
		div.className = 'message';
		div.textContent = message;
		form.parentNode.insertBefore( div, form );
	}

	/**
	 * Escape HTML entities.
	 *
	 * @param {string} str Raw string.
	 * @return {string} Escaped string.
	 */
	function escHtml( str ) {
		var div = document.createElement( 'div' );
		div.appendChild( document.createTextNode( str ) );
		return div.innerHTML;
	}

	/**
	 * POST an AJAX request.
	 *
	 * @param {Object} params Key-value pairs to send.
	 * @return {Promise} Resolves with the JSON response.
	 */
	function post( params ) {
		var body = new URLSearchParams( params );
		return fetch( cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body,
		} ).then( window.seguriumParseResponse );
	}

	/**
	 * Set loading state on submit button.
	 *
	 * @param {boolean} loading Whether to show loading state.
	 * @param {string}  text    Button text.
	 */
	function setLoading( loading, text ) {
		if ( submitBtn ) {
			submitBtn.disabled = loading;
			if ( text ) {
				submitBtn.value = text;
			}
		}
	}

	/**
	 * Switch the form into 2FA challenge mode.
	 *
	 * @param {string} method 'totp' or 'email'.
	 * @param {string} token  Pending login token.
	 * @param {number} trustedDays Trusted device days for label.
	 */
	function showChallenge( method, token, trustedDays ) {
		inChallenge = true;
		tfaToken    = token;
		tfaMethod   = method;

		clearError();

		// Hide password-related fields.
		var passRow = passField ? passField.closest( '.user-pass-wrap, p' ) : null;
		if ( passRow ) {
			passRow.style.display = 'none';
		}
		var userRow = userField ? userField.closest( '.user-login-wrap, p' ) : null;
		if ( userRow ) {
			userRow.style.display = 'none';
		}
		var forgetMeNot = form.querySelector( '.forgetmenot' );
		if ( forgetMeNot ) {
			forgetMeNot.style.display = 'none';
		}

		// Build 2FA challenge form.
		var container = document.createElement( 'div' );
		container.id = 'segurium-2fa-challenge';

		var label = document.createElement( 'label' );
		label.setAttribute( 'for', 'segurium-2fa-code' );
		label.textContent = ( 'totp' === method ) ? ( i18n.enterTotp || 'Enter the code from your authenticator app:' ) : ( i18n.enterEmail || 'Enter the code sent to your email:' );
		container.appendChild( label );

		var input = document.createElement( 'input' );
		input.type         = 'text';
		input.id           = 'segurium-2fa-code';
		input.name         = 'segurium_2fa_code';
		input.className    = 'input';
		input.size         = 20;
		input.maxLength    = 20;
		input.autocomplete = 'one-time-code';
		input.inputMode    = 'numeric';
		input.autofocus    = true;
		input.style.cssText = 'width:100%;font-size:24px;padding:3px;margin:2px 6px 16px 0;';
		container.appendChild( input );

		// Trust device checkbox.
		if ( trustedDays > 0 ) {
			var trustWrap  = document.createElement( 'p' );
			var trustLabel = document.createElement( 'label' );
			var trustCheck = document.createElement( 'input' );
			trustCheck.type = 'checkbox';
			trustCheck.id   = 'segurium-2fa-trust';
			trustCheck.name = 'segurium_2fa_trust';
			trustCheck.value = '1';
			trustLabel.appendChild( trustCheck );
			trustLabel.appendChild( document.createTextNode( ' ' + ( i18n.trustDevice || 'Trust this device' ) ) );
			trustWrap.appendChild( trustLabel );
			container.appendChild( trustWrap );
		}

		// Backup code hint.
		var hint = document.createElement( 'p' );
		hint.className = 'segurium-2fa-backup-hint';
		hint.style.cssText = 'color:#72777c;font-size:13px;margin-top:8px;';
		hint.textContent = i18n.backupHint || 'Lost your device? Enter a backup code instead.';
		container.appendChild( hint );

		// Resend link for email method.
		if ( 'email' === method ) {
			var resendP    = document.createElement( 'p' );
			var resendLink = document.createElement( 'a' );
			resendLink.href = '#';
			resendLink.textContent = i18n.resend || 'Resend code';
			resendLink.style.cssText = 'font-size:13px;';
			resendLink.addEventListener( 'click', function ( e ) {
				e.preventDefault();
				post( {
					action: 'segurium_2fa_resend',
					nonce: cfg.nonce,
					token: tfaToken,
				} ).then( function () {
					showMessage( i18n.codeSent || 'A new code has been sent to your email.' );
				} );
			} );
			resendP.appendChild( resendLink );
			container.appendChild( resendP );
		}

		// Insert before submit button.
		var submitWrap = submitBtn ? submitBtn.closest( '.submit, p' ) : null;
		if ( submitWrap ) {
			form.insertBefore( container, submitWrap );
		} else {
			form.appendChild( container );
		}

		// Update submit button.
		if ( submitBtn ) {
			submitBtn.value    = i18n.verify || 'Verify';
			submitBtn.disabled = false;
		}

		// Focus the code input.
		setTimeout( function () {
			input.focus();
		}, 100 );
	}

	/**
	 * Handle the form submission.
	 *
	 * @param {Event} e Submit event.
	 */
	function onSubmit( e ) {
		e.preventDefault();
		clearError();

		if ( inChallenge ) {
			handleVerify();
		} else {
			handleAuthenticate();
		}
	}

	/**
	 * Phase 1: Send credentials via AJAX.
	 */
	function handleAuthenticate() {
		var username = userField ? userField.value : '';
		var password = passField ? passField.value : '';

		if ( ! username || ! password ) {
			return;
		}

		setLoading( true, i18n.loggingIn || 'Logging in...' );

		post( {
			action: 'segurium_2fa_authenticate',
			nonce: cfg.nonce,
			log: username,
			pwd: password,
			rememberme: ( rememberBox && rememberBox.checked ) ? 'forever' : '',
		} ).then( function ( r ) {
			if ( ! r.success ) {
				setLoading( false, i18n.logIn || 'Log In' );
				showError( r.data && r.data.message ? r.data.message : 'Authentication failed.' );
				return;
			}

			var d = r.data;

			if ( d.login ) {
				window.location = d.redirect || window.location.href;
				return;
			}

			if ( d.two_factor_required ) {
				showChallenge( d.method, d.token, d.trusted_days || 0 );
				return;
			}

			if ( d.setup_required ) {
				showError( i18n.setupRequired || '2FA setup is required for your role.' );
				if ( d.profile_url ) {
					setTimeout( function () {
						window.location = d.profile_url;
					}, 2000 );
				}
				return;
			}
		} ).catch( function () {
			setLoading( false, i18n.logIn || 'Log In' );
			showError( 'Network error. Please try again.' );
		} );
	}

	/**
	 * Phase 2: Verify 2FA code via AJAX.
	 */
	function handleVerify() {
		var codeInput = document.getElementById( 'segurium-2fa-code' );
		var code      = codeInput ? codeInput.value.trim() : '';
		if ( ! code ) {
			return;
		}

		var trustCheck = document.getElementById( 'segurium-2fa-trust' );

		setLoading( true, i18n.verifying || 'Verifying...' );

		post( {
			action: 'segurium_2fa_verify',
			nonce: cfg.nonce,
			token: tfaToken,
			code: code,
			trust: ( trustCheck && trustCheck.checked ) ? '1' : '0',
			rememberme: ( rememberBox && rememberBox.checked ) ? 'forever' : '',
		} ).then( function ( r ) {
			if ( r.success && r.data && r.data.login ) {
				window.location = r.data.redirect || window.location.href;
				return;
			}

			setLoading( false, i18n.verify || 'Verify' );

			if ( r.data && r.data.locked ) {
				showError( i18n.tooManyAttempts || 'Too many failed attempts. Please try again later.' );
				if ( submitBtn ) {
					submitBtn.disabled = true;
				}
				if ( codeInput ) {
					codeInput.disabled = true;
				}
				return;
			}

			var msg = ( r.data && r.data.message ) ? r.data.message : 'Invalid code.';
			if ( r.data && typeof r.data.attempts_remaining !== 'undefined' ) {
				msg += ' (' + r.data.attempts_remaining + ' attempts remaining)';
			}
			showError( msg );
			if ( codeInput ) {
				codeInput.value = '';
				codeInput.focus();
			}
		} ).catch( function () {
			setLoading( false, i18n.verify || 'Verify' );
			showError( 'Network error. Please try again.' );
		} );
	}

	// Attach.
	form.addEventListener( 'submit', onSubmit );
})();

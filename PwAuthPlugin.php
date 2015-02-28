<?php

/**
 * Version 1.0
 *
 * Authentication Plugin for pwauth
 * Derived from AuthPlugin.php
 *
 * Much of the commenting comes straight from AuthPlugin.php
 *
 * Copyright 2006 Nicholas J. Humfrey
 * Released under the GNU General Public License
 *
 * pwauth is available from http://www.unixpapa.com/pwauth/
 *
 * LocalSettings configuration:
 *  require_once("./extensions/PwAuthPlugin.php");
 *  $wgAuth = new PwAuthPlugin();
 *
 *
 */

require_once($IP.'/includes/AuthPlugin.php');


$pwauth_email_domain = "";
$pwauth_bin_path = "/usr/local/sbin/pwauth";


error_reporting(E_ALL); // Debug


// First check if class has already been defined.
if (!class_exists('AuthPlugin')) {

        /**
         * Auth Plugin
         *
         */
        require_once './includes/AuthPlugin.php';

} // End: if (!class_exists('AuthPlugin')) {




class PwAuthPlugin extends AuthPlugin {

	/**
	 * Check whether there exists a user account with the given name.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * @param string $username
	 * @return bool
	 * @access public
	 */
	function userExists( $username ) {
		$user = posix_getpwnam( strtolower($username) );
		return is_array($user);
	}
	
	/**
	 * Check if a username+password pair is a valid login.
	 * The name will be normalized to MediaWiki's requirements, so
	 * you might need to munge it (for instance, for lowercase initial
	 * letters).
	 *
	 * @param string $username
	 * @param string $password
	 * @return bool
	 * @access public
	 */
	function authenticate( $username, $password ) {
		global $pwauth_bin_path;
		
		$username = strtolower( $username );

		$handle = popen($pwauth_bin_path, 'w');
		if ($handle === FALSE) {
			error_log("Error opening pipe to pwauth");
			return false;
		}
		
		if (fwrite($handle, "$username\n$password\n") === FALSE) {
			error_log("Error writing to pwauth pipe");
			return false;
		}
		
		# Is the password valid?
		$result = pclose( $handle );
		if ($result==0) return TRUE;
		
		#0  -  Login OK.
		#1  -  Nonexistant login or (for some configurations) incorrect password.
		#2  -  Incorrect password (for some configurations).
		#3  -  Uid number is below MIN_UNIX_UID value configured in config.h.
		#4  -  Login ID has expired.
		#5  -  Login's password has expired.
		#6  -  Logins to system have been turned off (usually by /etc/nologin file).
		#7  -  Limit on number of bad logins exceeded.
		#50 -  pwauth was not run with real uid SERVER_UID.  If you get this
		#      this error code, you probably have SERVER_UID set incorrectly
		#      in pwauth's config.h file.
		#51 -  pwauth was not given a login & password to check.  The means
		#      the passing of data from mod_auth_external to pwauth is messed
		#      up.  Most likely one is trying to pass data via environment
		#      variables, while the other is trying to pass data via a pipe.
		#52 -  one of several possible internal errors occured.
		error_log("pwauth returned $result for username $username");
		
		return false;
	}
	
	/**
	 * Modify options in the login template.
	 *
	 * @param UserLoginTemplate $template
	 * @access public
	 */
	function modifyUITemplate( &$template ) {
		$template->set('usedomain', false );
		$template->set('useemail', false);	// Disable the mail new password box.
		$template->set('create', false);	// Remove option to create new accounts from the wiki.
	}
	
	/**
	 * Check to see if the specific domain is a valid domain.
	 *
	 * @param string $domain
	 * @return bool
	 * @access public
	 */
	function validDomain( $domain ) {
		# We ignore domains, so erm, yes?
		return true;
	}
	
	/**
	 * When a user logs in, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * @param User $user
	 * @access public
	 */
	function updateUser( &$user ) {
		global $pwauth_email_domain;

		// Lookup information about user
		$username = strtolower( $user->getName() );
		$account = posix_getpwnam( $username );
		$gecos = split( ',', $account['gecos'] );
		
		// Set users real name
		$user->setRealName( $gecos[0] );
		
		// Set email if domain is configured
		if (!empty( $pwauth_email_domain ) )  {
			// Set the email address
			$user->setEmail( $username.'@'.$pwauth_email_domain );
		
			// We set the email address, therefore it is valid
			$user->confirmEmail();
		}
		
                // NOTE: This extension specifically disables password updates,
                // making the third line here fail. See Discussion for details.
                // I'm going to disable this section and hope that the author 
                // comes back, verifies it, and removes these lines. 
                //    - Mythobeast,  02/15/2011

/*		// For security, scramble the password to ensure the user can
		// only login using system password. 
		// This set the password to a 15 byte random string.
		$pass = '';
		for($i=0; $i<15;++$i) $pass .= chr(mt_rand(0,255));
		$user->setPassword($pass);
*/		
		return true;
	}
	
	
	/**
	 * Return true if the wiki should create a new local account automatically
	 * when asked to login a user who doesn't exist locally but does in the
	 * external auth database.
	 *
	 * If you don't automatically create accounts, you must still create
	 * accounts in some way. It's not possible to authenticate without
	 * a local account.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * @return bool
	 * @access public
	 */
	function autoCreate() {
		return true;
	}
	
	
	/**
	 * Can users change their passwords?
	 *
	 * @return bool
	 */
	function allowPasswordChange() {
		# We can't change users system passwords
		return false;
	}
	
	/**
	 * Set the given password in the authentication database.
	 * Return true if successful.
	 *
	 * @param string $password
	 * @return bool
	 * @access public
	 */
	function setPassword( $password ) {
		# We can't change users system passwords
		return false;
	}
	
	/**
	 * Update user information in the external authentication database.
	 * Return true if successful.
	 *
	 * @param User $user
	 * @return bool
	 * @access public
	 */
	function updateExternalDB( $user ) {
		# We can't change users details
		return false;
	}
	
	/**
	 * Check to see if external accounts can be created.
	 * Return true if external accounts can be created.
	 * @return bool
	 * @access public
	 */
	function canCreateAccounts() {
		# We can't create accounts
		return false;
	}
	
	/**
	 * Add a user to the external authentication database.
	 * Return true if successful.
	 *
	 * @param User $user
	 * @param string $password
	 * @return bool
	 * @access public
	 */
	function addUser( $user, $password ) {
		# We can't create accounts
		return false;
	}
	
	
	/**
	 * Return true to prevent logins that don't authenticate here from being
	 * checked against the local database's password fields.
	 *
	 * This is just a question, and shouldn't perform any actions.
	 *
	 * @return bool
	 * @access public
	 */
	function strict() {
		# provide fallback mechanism: authenticate against MediaWiki-
		# users if no matching system user exists
		return false;
	}
	
	/**
	 * When creating a user account, optionally fill in preferences and such.
	 * For instance, you might pull the email address or real name from the
	 * external user database.
	 *
	 * The User object is passed by reference so it can be modified; don't
	 * forget the & on your function declaration.
	 *
	 * @param User $user
	 * @access public
	 */
	function initUser(&$user) {
		# We do everything in updateUser
	}
     
}



/**
 * Some extension information init
 */
$wgExtensionCredits['other'][] = array(
   'name' => 'PWAuthPlugin',
   'version' => '1.0',
   'author' => 'Nicholas Humfrey',
   'description' => 'Automagic login with system accounts, using pwauth',
   'url' => 'http://www.mediawiki.org/wiki/Extension:PwAuthPlugin'
);





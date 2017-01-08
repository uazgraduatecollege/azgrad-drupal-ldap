<?php

namespace Drupal\ldap_authentication\Controller;

use Drupal\ldap_authentication\Helper\LdapAuthenticationConfiguration;
use Drupal\ldap_authentication\LdapAuthenticationConf;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\MassageFunctions;
use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Processor\DrupalUserProcessor;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use Drupal\Core\Form\FormStateInterface;

class LoginValidator {

  protected $drupalUserExists = FALSE;
  protected $drupalUserAuthMapped = FALSE;
  /* @var UserInterface $drupalUser */
  public $drupalUser = FALSE;

  protected $detailedLogging = FALSE;
  protected $tokens =[];

  public function __construct() {
    $this->detailedLogging = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
  }

  public function validateLogin(FormStateInterface $form_state) {
    $authname = trim($form_state->getValue('name'));
    $this->tokens = ['%username' => $authname, '%authname' => $authname];
   
    if ($this->detailedLogging) {
      \Drupal::logger('ldap_authentication')->debug('%username : Beginning authentification....', $this->tokens);
    }

    /**
     * I. Test for previous module authentication success.
     *
     * if already succeeded at authentication, $form_state['uid'] will be set by other authentication module.
     * - if LDAP Mixed mode is set, return and don't disrupt authentication process
     * - otherwise override other authentication by setting $form_state['uid'] = NULL
     */
    if (NULL !== $form_state->getValue('uid') && is_numeric($form_state->getValue('uid'))) {
      if (\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.authenticationMode') == LdapAuthenticationConf::$mode_mixed) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('%username : Previously authenticated in mixed mode or uid=1', $this->tokens);
        }
        // Already passed a previous module's authentication validation.
        return $form_state;
      }
      elseif (\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.authenticationMode') == LdapAuthenticationConf::$mode_exclusive) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('%username : Previously authenticated in exclusive mode or uid is not 1.  Clear uid in form_state and attempt ldap authentication.', $this->tokens);
        }
        // Passed previous authentication, but only ldap should be used so override.
        // Todo: Invalid assignment.
        $form_state->setValue('uid', NULL);
      }
    }

    // Check that enabled servers are available.
    if (!LdapAuthenticationConfiguration::hasEnabledAuthenticationServers()) {
      \Drupal::logger('ldap_authentication')->error('No LDAP servers configured.');
      $form_state->setErrorByName('name', 'Server Error:  No LDAP servers configured.');
      return $form_state;
    }

    /**
     * III. determine if corresponding drupal account exists for $authname
     */
    $this->initializeAuthNameCorrespondingDrupalUser($authname);
    if ($this->drupalUserExists && $this->drupalUser->id() == 1) {
      // User 1 is not allowed to ldap authenticate.
      return $form_state;
    }

    /**
     * IV. test credentials and if available get corresponding ldap user and ldap server
     */
    list($authentication_result, $ldap_user, $userServer) = $this->testCredentials($authname, $form_state->getValue('pass'), $this->tokens);
    if ($authentication_result != LdapAuthenticationConf::$authSuccess) {
      $this->ldap_authentication_fail_response($authentication_result, $this->detailedLogging, $this->tokens);
      return $form_state;
    }

    /**
     * V. if account_name_attr is set, drupal username is different than authname
     */
    if ($userServer->get('account_name_attr') != '') {
      $massager = new MassageFunctions();
      $this->tokens['%account_name_attr'] = $userServer->get('account_name_attr');
      $drupal_accountname = $ldap_user['attr'][$massager->massage_text($userServer->get('account_name_attr'), 'attr_name', $massager::$query_array)][0];
      if (!$drupal_accountname) {
        \Drupal::logger('ldap_authentication')->error('Derived drupal username from attribute %account_name_attr returned no username for authname %authname.', $this->tokens);
      }
      return $form_state;
    }
    else {
      $drupal_accountname = $authname;
    }
    $this->tokens['%drupal_accountname'] = $drupal_accountname;

    /**
     * VI. Find or create corresponding drupal account and set authmaps
     *
     * at this point, the following are know:
     * - a corresponding ldap account has been found
     * - user's credentials tested against it and passed
     * - their drupal accountname has been derived
     *
     */

    /**
     * VI.A: Drupal account doesn't exist with $authname used to logon,
     *  but puid exists in another Drupal account; this means username has changed
     *  and needs to be saved in Drupal account
     *
     */
    // @FIXME: Unported.
    if (!$this->drupalUserExists && $userServer) {
      /* @var Server $userServer*/
      $puid = $userServer->userPuidFromLdapEntry($ldap_user['attr']);
      if ($puid) {
        $drupal_account = $userServer->userUserEntityFromPuid($puid);
        if ($drupal_account) {
          $this->drupalUserExists = TRUE;
          $user_values = array('name' => $drupal_accountname);
          $drupal_account = user_save($drupal_account, $user_values, 'ldap_user');
          user_set_authmaps($drupal_account, array("authname_ldap_user" => $authname));
          $this->drupalUserAuthMapped = TRUE;
        }
      }
    }

    /**
     * VI.B: existing Drupal account but not authmapped to ldap modules,
     *   ldap authmap or disallow
     *
     */

    // Account already exists.
    if ($this->drupalUserExists && !$this->drupalUserAuthMapped) {
      if (\Drupal::config('ldap_user.settings')->get('ldap_user_conf.userConflictResolve') == LdapConfiguration::$userConflictLog) {
        if ($account_with_same_email = user_load_by_mail($ldap_user['mail'])) {
          /* @var UserInterface $account_with_same_email */
          $this->tokens['%conflict_name'] = $account_with_same_email->getUsername();
          \Drupal::logger('ldap_authentication')->error('LDAP user with DN %dn has a naming conflict with a local drupal user %conflict_name', $this->tokens);
        }
        drupal_set_message(t('Another user already exists in the system with the same login name. You should contact the system administrator in order to solve this conflict.'), 'error');
        return $form_state;
      }
      // LDAP_authen.AC.disallow.ldap.drupal.
      else {
        // Add ldap_authentication authmap to user. account name is fine here, though cn could be used.
        ExternalAuthenticationHelper::setUserIdentifier($this->drupalUser, $authname);
        $this->drupalUserAuthMapped = TRUE;
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('set authmap for %username authname_ldap_user', $this->tokens);
        }
      }
    }

    /**
     * VI.C: existing Drupal account with incorrect email.  fix email if appropriate
     *
     */

    if ($this->drupalUserExists && $this->drupalUser->getEmail() != $ldap_user['mail'] && (
        \Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.emailUpdate') == LdapAuthenticationConf::$emailUpdateOnLdapChangeEnableNotify ||
        \Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.emailUpdate')  == LdapAuthenticationConf::$emailUpdateOnLdapChangeEnable
      )) {
      $this->drupalUser->set('mail', $ldap_user['mail']);
      $this->tokens['%username'] = $this->drupalUser->getUsername();
      if (!$updated_account = $this->drupalUser->save()) {
        \Drupal::logger('ldap_authentication')->error('Failed to make changes to user %username updated %changed.', $this->tokens);
      }
      elseif (\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.emailUpdate')  == LdapAuthenticationConf::$emailUpdateOnLdapChangeEnableNotify) {
        if (isset($user_values['mail'])) {
          $this->tokens['%mail'] = $user_values['mail'];
          drupal_set_message(t('Your e-mail has been updated to match your current account (%mail).', $this->tokens), 'status');
        }
        if (isset($user_values['name'])) {
          $this->tokens['%new_username'] = $user_values['name'];
          drupal_set_message(t('Your old account username %username has been updated to %new_username.', $this->tokens), 'status');
        }
      }
    }

    /**
     * VI.C: no existing Drupal account.  consider provisioning Drupal account.
     *
     */
    if (!$this->drupalUserExists) {

      // VI.C.1 Do not provision Drupal account if another account has same email.
      if ($account_with_same_email = user_load_by_mail($ldap_user['mail'])) {
        /**
         * username does not exist but email does.  Since user_external_login_register does not deal with
         * mail attribute and the email conflict error needs to be caught beforehand, need to throw error here
         */
        $this->tokens['%duplicate_name'] = $account_with_same_email->getUsername();
        \Drupal::logger('ldap_authentication')->error('LDAP user with DN %dn has email address (%mail) conflict with a drupal user %duplicate_name', $this->tokens);

        drupal_set_message(t('Another user already exists in the system with the same email address. You should contact the system administrator in order to solve this conflict.'), 'error');
        return $form_state;
      }

      // VI.C.2 Do not provision Drupal account if provisioning disabled.
      if (!LdapConfiguration::provisionAvailableToDrupal(LdapConfiguration::$provisionDrupalUserOnAuthentication)) {
        \Drupal::logger('ldap_authentication')->error('Drupal account for authname=%authname account name=%account_name_attr does not exist and provisioning of Drupal accounts on authentication is not enabled', $this->tokens);
        return $form_state;
      }

      // VI.C.3 Provision Drupal account.
      /**
       *
       * new ldap_authentication provisioned account could let user_external_login_register create the account and set authmaps, but would need
       * to add mail and any other user->data data in hook_user_presave which would mean requerying ldap
       * or having a global variable.  At this point the account does not exist, so there is no
       * reason not to create it here.
       *
       * @todo create patch for core user module's user_external_login_register to deal with new external accounts
       *       a little tweak to add user->data and mail etc as parameters would make it more useful
       *       for external authentication modules
       */

      if (\Drupal::config('ldap_user.settings')->get('ldap_user_conf.acctCreation') == LdapConfiguration::$accountCreationUserSettingsForLdap &&
        \Drupal::config('user.settings')->get('register') == USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL) {
        // If admin approval required, set status to 0.
        $user_values = array('name' => $drupal_accountname, 'status' => 0);
      }
      else {
        $user_values = array('name' => $drupal_accountname, 'status' => 1);
      }

      // don't pass in ldap user to provisionDrupalAccount, because want to re-query with correct attributes needed
      // this may be a case where efficiency dictates querying for all attributes.
      $processor = new DrupalUserProcessor();
      $drupal_account = $processor->provisionDrupalAccount(NULL, $user_values, NULL, TRUE);

      if ($drupal_account === FALSE) {
        \Drupal::logger('ldap_user')->error('Failed to find or create %drupal_accountname on logon.', $this->tokens);
        $form_state->setErrorByName('name', t('Server Error: Failed to create Drupal user account for %drupal_accountname', $this->tokens));
        return $form_state;
      }
    }

    /**
     * we now have valid, ldap authenticated username with an account authmapped to ldap_authentication.
     * since user_external_login_register can't deal with user mail attribute and doesn't do much else, it is not
     * being used here.
     *
     * without doing the user_login_submit,
     * [#1009990],[#1865938]
     */

    if (is_object($this->drupalUser)) {
      $form_state->set('uid', $this->drupalUser->id());
    }
    return $form_state;
  }

  /**
   * Given authname, determine if corresponding drupal account exists and is authmapped.
   *
   * @param $authname
   *
   * @return array
   */
  private function initializeAuthNameCorrespondingDrupalUser($authname) {
    if (!($this->drupalUser = user_load_by_name($authname))) {
      $uid = ExternalAuthenticationHelper::getUidFromIdentifierMap($authname);
      $this->drupalUser = $uid ? user_load($uid) : FALSE;
    }

    if (is_object($this->drupalUser)) {
      $this->drupalUserExists = TRUE;
      $this->drupalUserAuthMapped = ExternalAuthenticationHelper::getUserIdentifierFromMap($this->drupalUser->id());
      if ($this->drupalUser->id() == 1 && $this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username : Drupal username maps to user 1, so do not authenticate with ldap', ['%username' => $authname]);
      }
      elseif ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username : Drupal User Account found.  Continuing on to attempt ldap authentication', ['%username' => $authname]);
      }
    }
    // Account does not exist.
    else {
      $this->drupalUserAuthMapped = FALSE;
      if (LdapConfiguration::createLDAPAccounts() == FALSE) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('%username : Drupal User Account not found and configuration is set to not create new accounts.', ['%username' => $authname]);
        }
      }
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username : Existing Drupal User Account not found.  Continuing on to attempt ldap authentication', ['%username' => $authname]);
      }
    }
  }

  /**
   *
   */
  private function testCredentials($authname, $password, &$watchdog_tokens) {
    $detailed_watchdog_log = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
    $authenticationResult = LdapAuthenticationConf::$authFailGeneric;
    $ldap_user = FALSE;
    $server = NULL;
    $factory = \Drupal::service('ldap.servers');

    /* @var ServerFactory $factory */
    /* @var Server $server */
    foreach (LdapAuthenticationConfiguration::getEnabledAuthenticationServers() as $serverName) {
      $server = $factory->getServerById($serverName);
      $watchdog_tokens['%id'] = $serverName;
      $watchdog_tokens['%bind_method'] = $server->get('bind_method');
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method', $watchdog_tokens);
      }

      // #1 CONNECT TO SERVER.
      $authenticationResult = LdapAuthenticationConf::$authFailGeneric;
      $result = $server->connect();
      if ($result != $server::LDAP_SUCCESS) {
        $authenticationResult = LdapAuthenticationConf::$authFailConnect;
        $watchdog_tokens['%err_msg'] = $server->errorMsg('ldap');
        if ($detailed_watchdog_log) {
          \Drupal::logger('ldap_authentication')->debug('%username : Failed connecting to %id.  Error: %err_msg', $watchdog_tokens);
        }
        $watchdog_tokens['%err_msg'] = NULL;
        // Next server, please.
        continue;
      }
      elseif ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : Success at connecting to %id', $watchdog_tokens);
      }

      /**
       *
       * $bindMethodServiceAccount => t('Service Account Bind.  Use credentials in following section to
       * bind to ldap.  This option is usually a best practice. Service account is entered in next section.'),
       *
       * $bindMethodUser => t('Bind with Users Credentials.  Use users\' entered credentials
       * to bind to LDAP.  This is only useful for modules that work during user logon such
       * as ldap authentication and ldap authorization.  This option is not a best practice in most cases.
       * The users dn must be of the form "cn=[username],[base dn]" for this option to work.'),
       *
       * $bindMethodAnon => t('Anonymous Bind for search, then Bind with Users Credentials.
       * Searches for user DN then uses users\' entered credentials to bind to LDAP.  This is only useful for
       * modules that work during user logon such as ldap authentication and ldap authorization.
       * The users dn must be discovered by an anonymous search for this option to work.'),
       *
       * $bindMethodAnonUser => t('Anonymous Bind. Use no credentials to bind to ldap server.
       * Will not work on most ldaps.'),
       *
       */

      $bind_success = FALSE;
      if ($server->get('bind_method') == Server::$bindMethodServiceAccount) {
        $bind_success = ($server->bind(NULL, NULL, FALSE) == $server::LDAP_SUCCESS);
      }
      elseif ($server->get('bind_method') == Server::$bindMethodAnon ||
        $server->get('bind_method') == Server::$bindMethodAnonUser) {
        $bind_success = ($server->bind(NULL, NULL, TRUE) == $server::LDAP_SUCCESS);
      }
      elseif ($server->get('bind_method') == Server::$bindMethodUser) {
        // With sso enabled this method of binding isn't valid.
        foreach ($server->getBaseDn() as $basedn) {
          $search = array('%basedn', '%username');
          $replace = array($basedn, $authname);
          $userdn = str_replace($search, $replace, $server->get('user_dn_expression'));
          $bind_success = ($server->bind($userdn, $password, FALSE) == $server::LDAP_SUCCESS);
          if ($bind_success) {
            break;
          }
        }
      }
      else {
        \Drupal::logger('ldap_authentication')->debug('No bind method set in server->bind_method in ldap_authentication_user_login_authenticate_validate.', $watchdog_tokens);
      }

      if (!$bind_success) {
        if ($detailed_watchdog_log) {
          $watchdog_tokens['%err_text'] = $server->errorMsg('ldap');
          \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method.  Error: %err_text', $watchdog_tokens);
          $watchdog_tokens['%err_text'] = NULL;
        }
        $authenticationResult = ($server->get('bind_method') == Server::$bindMethodUser) ? LdapAuthenticationConf::$authFailCredentials : LdapAuthenticationConf::$authFailBind;
        // If bind fails, onto next server.
        continue;
      }

      // #3 DOES USER EXIST IN SERVER'S LDAP.
      if ($server->get('bind_method') == Server::$bindMethodAnonUser) {
        $ldap_user = $server->userUserNameToExistingLdapEntry($authname);
      }
      else {
        $ldap_user = $server->userUserNameToExistingLdapEntry($authname);
      }

      if (!$ldap_user) {
        if ($detailed_watchdog_log) {
          $watchdog_tokens['%err_text'] = $server->errorMsg('ldap');
          \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method.  Error: %err_text', $watchdog_tokens);
          $watchdog_tokens['%err_text'] = NULL;
        }
        if ($server->ldapErrorNumber()) {
          $authenticationResult = LdapAuthenticationConf::$authFailServer;
          break;
        }
        $authenticationResult = LdapAuthenticationConf::$authFailFind;
        // Next server, please.
        continue;
      }

      $watchdog_tokens['%dn'] = $ldap_user['dn'];
      $watchdog_tokens['%mail'] = $ldap_user['mail'];

      /**
       * #4 CHECK ALLOWED AND EXCLUDED LIST FOR ALLOWED USERS
       */
      // @FIXME: Method allowUser not defined
      if (!$this->checkAllowedExcluded($authname, $ldap_user)) {
        $authenticationResult = LdapAuthenticationConf::$authFailDisallowed;
        // Regardless of how many servers, disallowed user fails.
        break;
      }

      /**
       * #5 TEST PASSWORD
       */
      $credentials_pass = ($server->bind($ldap_user['dn'], $password, FALSE) == $server::LDAP_SUCCESS);
      if (!$credentials_pass) {
        if ($detailed_watchdog_log) {
          $watchdog_tokens['%err_text'] = $server->errorMsg('ldap');
          \Drupal::logger('ldap_authentication')->debug('%username : Testing user credentials on server %id where bind_method = %bind_method.  Error: %err_text', $watchdog_tokens);
          $watchdog_tokens['%err_text'] = NULL;
        }
        $authenticationResult = LdapAuthenticationConf::$authFailCredentials;
        // Next server, please.
        continue;
      }
      else {
        $authenticationResult = LdapAuthenticationConf::$authSuccess;
        // @FIXME: bind_method not defined
        if ($server->get('bind_method') == Server::$bindMethodAnonUser) {
          // After successful bind, lookup user again to get private attributes.
          $ldap_user = $server->userUserNameToExistingLdapEntry($authname);
          $watchdog_tokens['%mail'] = $ldap_user['mail'];
        }
        if ($server->get('bind_method') == Server::$bindMethodServiceAccount ||
          $server->get('bind_method') == Server::$bindMethodAnonUser) {
          $server->disconnect();
        }
        // Success.
        break;
      }

    }  // end loop through servers

    if ($this->detailedLogging) {
      \Drupal::logger('ldap_authentication')->debug('%username : Authentication result id=%result auth_result=%auth_result (%err_text)',
        [
          '%username' => $authname,
          '%result' => $result,
          '%auth_result' => $authenticationResult,
          '%err_text' => $this->_ldap_authentication_err_text($authenticationResult),
        ]
      );
    }

    return array($authenticationResult, $ldap_user, $server);
  }
  
  public function validateSsoCredentials($authname) {
    //TODO: Verify if $mode_exclusive check is a regression.
    /* @var LdapAuthenticationConf $auth_conf */
    $authenticationResult = LdapAuthenticationConf::$authFailGeneric;
    $ldap_user = FALSE;
    $ldap_server = NULL;

    /* @var Server $ldap_server */
    foreach ($auth_conf->enabledAuthenticationServers as $id => $ldap_server) {
      $tokens['%id'] = $id;
      $tokens['%bind_method'] = $ldap_server->get('bind_method');
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method', $tokens);
      }

      // #1 CONNECT TO SERVER.
      $authenticationResult = LdapAuthenticationConf::$authFailGeneric;
      $result = $ldap_server->connect();
      if ($result != $ldap_server::LDAP_SUCCESS) {
        $authenticationResult = LdapAuthenticationConf::$authFailConnect;
        $tokens['%err_msg'] = $ldap_server->errorMsg('ldap');
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('%username : Failed connecting to %id.  Error: %err_msg', $tokens);
        }
        $tokens['%err_msg'] = NULL;
        // Next server, please.
        continue;
      }
      elseif ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username : Success at connecting to %id', $tokens);
      }

      $bind_success = FALSE;
      if ($ldap_server->get('bind_method') == Server::$bindMethodServiceAccount) {
        $bind_success = ($ldap_server->bind(NULL, NULL, FALSE) == $ldap_server::LDAP_SUCCESS);
      }
      elseif ($ldap_server->get('bind_method') == Server::$bindMethodAnon ||
        $ldap_server->get('bind_method') == Server::$bindMethodAnonUser) {
        $bind_success = ($ldap_server->bind(NULL, NULL, TRUE) == $ldap_server::LDAP_SUCCESS);
      }
      else {
        \Drupal::logger('ldap_authentication')->error('Trying to use SSO with user bind method.', $tokens);
        \Drupal::logger('ldap_authentication')->debug('No bind method set in ldap_server->bind_method in ldap_authentication_user_login_authenticate_validate.', $tokens);
      }

      if (!$bind_success) {
        if ($this->detailedLogging) {
          $tokens['%err_text'] = $ldap_server->errorMsg('ldap');
          \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method.  Error: %err_text', $tokens);
          $tokens['%err_text'] = NULL;
        }
        $authenticationResult = ($ldap_server->get('bind_method') == Server::$bindMethodUser) ? LdapAuthenticationConf::$authFailCredentials : LdapAuthenticationConf::$authFailBind;
        // If bind fails, onto next server.
        continue;
      }
      
      $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($authname);
      
      if (!$ldap_user) {
        if ($this->detailedLogging) {
          $tokens['%err_text'] = $ldap_server->errorMsg('ldap');
          \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method.  Error: %err_text', $tokens);
          $tokens['%err_text'] = NULL;
        }
        if ($ldap_server->ldapErrorNumber()) {
          $authenticationResult = LdapAuthenticationConf::$authFailServer;
          break;
        }
        $authenticationResult = LdapAuthenticationConf::$authFailFind;
        // Next server, please.
        continue;
      }

      $tokens['%dn'] = $ldap_user['dn'];
      $tokens['%mail'] = $ldap_user['mail'];

      /**
       * #4 CHECK ALLOWED AND EXCLUDED LIST FOR ALLOWED USERS
       */
      if (!$auth_conf->allowUser($authname, $ldap_user)) {
        $authenticationResult = LdapAuthenticationConf::$authFailDisallowed;
        // Regardless of how many servers, disallowed user fails.
        break;
      }
      
        $authenticationResult = LdapAuthenticationConf::$authSuccess;
        if ($ldap_server->get('bind_method') == Server::$bindMethodAnonUser) {
          // After successful bind, lookup user again to get private attributes.
          $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($authname);
          $tokens['%mail'] = $ldap_user['mail'];
        }
        if ($ldap_server->get('bind_method') == Server::$bindMethodServiceAccount ||
          $ldap_server->get('bind_method') == Server::$bindMethodAnonUser) {
          $ldap_server->disconnect();
        }
        // Success.
        break;

    }  // end loop through servers
    
    if ($this->detailedLogging) {
      \Drupal::logger('ldap_authentication')->debug('%username : Authentication result id=%result auth_result=%auth_result (%err_text)', 
        [
          '%username' => $authname,
          '%result' => $result,
          '%auth_result' => $authenticationResult,
          '%err_text' => $this->_ldap_authentication_err_text($authenticationResult),
        ]
      );
    }
  }

  /**
   *
   */
  private function ldap_authentication_fail_response($authentication_result, $detailed_watchdog_log, &$watchdog_tokens) {
    $watchdog_tokens['%err_text'] = $this->_ldap_authentication_err_text($authentication_result);
    // Fail scenario 1.  ldap auth exclusive and failed  throw error so no other authentication methods are allowed.
    if (\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.authenticationMode') == LdapAuthenticationConf::$mode_exclusive) {
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : setting error because failed at ldap and
        exclusive authentication is set to true.  So need to stop authentication of Drupal user that is not user 1.
        error message: %err_text', $watchdog_tokens);
      }
      drupal_set_message(t('Error: @token', array('@token' => $watchdog_tokens['%err_text'])), "error");
    }
    else {
      // Fail scenario 2.  simply fails ldap.  return false, but don't throw form error
      // don't show user message, may be using other authentication after this that may succeed.
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : Failed ldap authentication.
        User may have authenticated successfully by other means in a mixed authentication site.
        LDAP Authentication Error #: %auth_result  error message: %err_text',
          $watchdog_tokens);
      }
    }
  }

  /**
   * Get human readable authentication error string.
   *
   * @param int $error
   *
   * @return string human readable error text
   */
  function _ldap_authentication_err_text($error) {

    $msg = t('unknown error: ' . $error);
    switch ($error) {
      case LdapAuthenticationConf::$authFailConnect:
        $msg = t('Failed to connect to ldap server');
        break;

      case LdapAuthenticationConf::$authFailBind:
        $msg = t('Failed to bind to ldap server');
        break;

      case LdapAuthenticationConf::$authFailFind:
        $msg = t('Sorry, unrecognized username or password.');
        break;

      case LdapAuthenticationConf::$authFailDisallowed:
        $msg = t('User disallowed');
        break;

      case LdapAuthenticationConf::$authFailCredentials:
        $msg = t('Sorry, unrecognized username or password.');
        break;

      case LdapAuthenticationConf::$authFailGeneric:
        $msg = t('Sorry, unrecognized username or password.');
        break;

      case LdapAuthenticationConf::$authFailServer:
        $msg = t('Authentication Server or Configuration Error.');
        break;

    }

    return $msg;
  }

  public function checkAllowedExcluded($authname, $ldap_user) {

    /**
     * do one of the exclude attribute pairs match
     */
    // If user does not already exists and deferring to user settings AND user settings only allow.
    $user_register = \Drupal::config('user.settings')->get('register');

    foreach (\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.excludeIfTextInDn') as $test) {
      if (stripos($ldap_user['dn'], $test) !== FALSE) {
        // If a match, return FALSE;.
        return FALSE;
      }
    }

    /**
     * do one of the allow attribute pairs match
     */
    if (count(\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.allowOnlyIfTextInDn'))) {
      $fail = TRUE;
      foreach (\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.allowOnlyIfTextInDn') as $test) {
        if (stripos($ldap_user['dn'], $test) !== FALSE) {
          $fail = FALSE;
        }
      }
      if ($fail) {
        return FALSE;
      }

    }
    /**
     * is excludeIfNoAuthorizations option enabled and user not granted any groups
     */

    if (\Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.excludeIfNoAuthorizations')) {

      if (!\Drupal::moduleHandler()->moduleExists('ldap_authorization')) {
        drupal_set_message(t('The site logon is currently not working due to a configuration error.  Please see logs for additional details.'), 'warning');
        $url = Url::fromRoute('ldap_authentication.admin_form');
        $internal_link = \Drupal::l(t('LDAP Authentication Configuration'), $url);
        $tokens = array('!ldap_authentication_config' => $internal_link);
        \Drupal::logger('ldap_authentication')->notice('LDAP Authentication is configured to deny users without LDAP Authorization mappings, but LDAP Authorization module is not enabled.  Please enable and configure LDAP Authorization or disable this option at !ldap_authentication_config .');
        return FALSE;
      }

      // @FIXME: Several undefined functions in this scope.
      $user = User::create(['name' => $authname]);
      // Fake user property added for query.
      $user->ldap_authenticated = TRUE;
      $consumers = ldap_authorization_get_consumers();
      $has_enabled_consumers = FALSE;
      $has_ldap_authorizations = FALSE;

      foreach ($consumers as $consumer_type => $consumer_config) {
        $consumer_obj = ldap_authorization_get_consumer_object($consumer_type);
        if ($consumer_obj->consumerConf->status) {
          $has_enabled_consumers = TRUE;
          list($authorizations, $notifications) = ldap_authorizations_user_authorizations($user, 'query', $consumer_type, 'test_if_authorizations_granted');
          if (
            isset($authorizations[$consumer_type]) &&
            count($authorizations[$consumer_type]) > 0
          ) {
            $has_ldap_authorizations = TRUE;
          }
        }
      }

      if (!$has_enabled_consumers) {
        drupal_set_message(t('The site logon is currently not working due to a configuration error.  Please see logs for additional details.'), 'warning');
        \Drupal::logger('ldap_authentication')->notice('LDAP Authentication is configured to deny users without LDAP Authorization mappings, but 0 LDAP Authorization consumers are configured.');
        return FALSE;
      }
      elseif (!$has_ldap_authorizations) {
        return FALSE;
      }

    }

    // Allow other modules to hook in and refuse if they like.
    $hook_result = TRUE;
    \Drupal::moduleHandler()->alter('ldap_authentication_allowuser_results', $ldap_user, $name, $hook_result);

    if ($hook_result === FALSE) {
      \Drupal::logger('ldap_authentication')->notice('Authentication Allow User Result=refused for %name', ['%name' => $name]);
      return FALSE;
    }

    /**
     * default to allowed
     */
    return TRUE;
  }


}
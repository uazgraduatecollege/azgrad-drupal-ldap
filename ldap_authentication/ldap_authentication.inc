<?php

/**
 * @file
 * ldap_authentication helper functions
 */

/**
  * helper function for ldap_authn_form_user_login_block_alter and ldap_authn_form_user_login_alter
  *
  * @todo if form is being generated on non https and is set in preferences, set warning and end form development
  */
function _ldap_authentication_login_form_alter(&$form, &$form_state, $form_id) {

  if (!$auth_conf = ldap_authentication_get_valid_conf()) {
    return;
  }
  elseif (!$auth_conf->hasEnabledAuthenticationServers()) {
    return;
  }

  /**
   *
   * add validate function to test for ldap authentication
   * should be placed after user_login_authenticate_validate
   * 1. user_login_name_validate
   * 2. user_login_authenticate_validate
   * 3. external authentication validate functions
   * 4. user_login_final_validate
   *
   * as articulated above user_login_default_validators() in user.module
   *
   * without any other external authentication modules, this array will start out as:
   *    array('user_login_name_validate', 'user_login_authenticate_validate', 'user_login_final_validate')
   */

  if (@in_array('::validateAuthentication', $form['#validate']) && $auth_conf->authenticationMode) {
    $key = array_search('::validateAuthentication', $form['#validate']);
    $form['#validate'][$key] =  'ldap_authentication_core_override_user_login_authenticate_validate';
    array_splice($form['#validate'], $key + 1, 0, 'ldap_authentication_user_login_authenticate_validate');
  }

  if ($form_id == 'user_login_block') {
    $user_register = config('user.settings')->get('register');
    $vars = array(
      'show_reset_pwd' => ldap_authentication_show_reset_pwd(),
      'auth_conf' => $auth_conf,
      );

    $form['links']['#markup'] = theme('ldap_authentication_user_login_block_links', $vars);
  }
  ldap_servers_disable_http_check($form);

  // Add help information for entering in username/password
  $auth_conf = ldap_authentication_get_valid_conf();
  if ($auth_conf) {
    if (isset($auth_conf->loginUIUsernameTxt)) {
      $form['name']['#description'] = t($auth_conf->loginUIUsernameTxt);
    }
    if (isset($auth_conf->loginUIPasswordTxt)) {
      $form['pass']['#description'] = t($auth_conf->loginUIPasswordTxt);
    }
  }
}



/**
  * alter user editing form (profile form) based on ldap authentication configuration
  *
  * @param array $form array from user profile
  * @param array $form_state from user profile
  *
  * @return NULL (alters $form by reference)
  */
function _ldap_authentication_form_user_profile_form_alter(&$form, $form_state) {
  // keep in mind admin may be editing another users profile form.  don't assume current global $user
  $auth_conf = ldap_authentication_get_valid_conf();
  if ($auth_conf && ldap_authentication_ldap_authenticated($form['#user'])) {
    if ($auth_conf->emailOption == LDAP_AUTHENTICATION_EMAIL_FIELD_REMOVE) {
      $form['account']['mail']['#type'] = 'hidden';
    }
    elseif ($auth_conf->emailOption == LDAP_AUTHENTICATION_EMAIL_FIELD_DISABLE) {
      $form['account']['mail']['#disabled'] = TRUE;
      $form['account']['mail']['#description'] = t('This email address is automatically set and may not be changed.');
    }
    elseif ($auth_conf->emailOption == LDAP_AUTHENTICATION_EMAIL_FIELD_ALLOW) {
      // email field is functional
    }

    if (!ldap_authentication_show_reset_pwd($form['#user'])) {
      $form['account']['current_pass']['#disabled'] = TRUE;
      if ($auth_conf->ldapUserHelpLinkUrl) {
        $form['account']['current_pass']['#description'] = l(t($auth_conf->ldapUserHelpLinkText), $auth_conf->ldapUserHelpLinkUrl);
      }
      else {
        $form['account']['current_pass']['#description'] = t('The password cannot be changed using this website');
      }
      $form['account']['pass']['#disabled'] = TRUE;
    }
  }
}


/**
  * user form validation will take care of username, pwd fields
  * this function validates ldap authentication specific
  *
  * @param array $form_state array from user logon form
  * @return null, but success or failure is indicated by:
  * -- form_set_error() to invalidate authentication process
  * -- setting $form_state['uid'] to indicate successful authentication
  */
function _ldap_authentication_user_login_authenticate_validate(&$form_state, $return_user) {

  $detailed_watchdog_log = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
  $authname = trim($form_state->getValue('name')); // $authname is the name the user is authenticated with from the logon form // patch 1599632

  /*
   * If a fake form state was passed into this function from
   * _ldap_authentication_user_login_sso(), there will be a value outside of the
   * form_state[values] array to let us know that we are not authenticating with
   * a password, but instead just looking up a username/dn in LDAP since the web
   * server already authenticated the user.
   */
  $sso_login = (null !== $form_state->getValue('sso_login') && $form_state->getValue('sso_login')) ? TRUE : FALSE;

  $watchdog_tokens = array('%username' => $authname, '%authname' => $authname); // $watchdog_tokens = array('%username' => $name); // patch 1599632
  if ($detailed_watchdog_log) {
    \Drupal::logger('ldap_authentication')->debug('%username : Beginning authentification....', $watchdog_tokens);
  }

  if (!$auth_conf = ldap_authentication_get_valid_conf()) {
    \Drupal::logger('ldap_authentication')->error('Failed to get valid ldap authentication configuration.');
    $form_state->setErrorByName('name', 'Server Error: Failed to get valid ldap authentication configuration.');
    return;
  }

 /**
  * I. Test for previous module authentication success.
  *
  * if already succeeded at authentication, $form_state['uid'] will be set by other authentication module.
  * - if LDAP Mixed mode is set, return and don't disrupt authentication process
  * - otherwise override other authenication by setting $form_state['uid'] = NULL
  */
  if (null !== $form_state->getValue('uid') && is_numeric($form_state->getValue('uid'))) {
    if ($auth_conf->authenticationMode == LDAP_AUTHENTICATION_MIXED || $form_state->getValue('uid') == 1) {
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : Previously authenticated in mixed mode or uid=1', $watchdog_tokens);
      }
      return;  // already passed a previous module's authentication validation
    }
    elseif ($auth_conf->authenticationMode == LDAP_AUTHENTICATION_EXCLUSIVE) {
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : Previously authenticated in exclusive mode or uid is not 1.  Clear uid in form_state and attempt ldap authentication.', $watchdog_tokens);
      }
      $form_state['uid'] = NULL;  // passed previous authentication, but only ldap should be used so override
    }
  }

 /**
  * II. Exit if no authentication servers.
  */
  if (!$auth_conf->hasEnabledAuthenticationServers()) {
    \Drupal::logger('ldap_authentication')->error('No LDAP servers configured.');
    $form_state->setErrorByName('name', 'Server Error:  No LDAP servers configured.');
    return;
  }

  /**
   * III. determine if corresponding drupal account exists for $authname
   */
  $drupal_account_is_authmapped = FALSE;
  list($drupal_account, $drupal_account_is_authmapped) = ldap_authentication_corresponding_drupal_user($authname, $auth_conf, $watchdog_tokens);
  $drupal_account_exists = is_object($drupal_account);
  if ($drupal_account_exists && $drupal_account->id() == 1) {
    return; // user 1 is not allowed to ldap authenticate
  }

  /**
   * IV. test credentials and if available get corresponding ldap user and ldap server
   */
  list($authentication_result, $ldap_user, $ldap_server_authenticated_on) = ldap_authentication_test_credentials($auth_conf, $sso_login, $authname, $form_state->getValue('pass'), $watchdog_tokens);
  if ($authentication_result != LDAP_AUTHENTICATION_RESULT_SUCCESS) {
    ldap_authentication_fail_response($authentication_result, $auth_conf, $detailed_watchdog_log, $watchdog_tokens);
    return;
  }

  /**
   * V. if account_name_attr is set, drupal username is different than authname
   */
  if ($ldap_server_authenticated_on->get('account_name_attr') != '') {
    $watchdog_tokens['%account_name_attr'] = $ldap_server_authenticated_on->get('account_name_attr');
    $drupal_accountname = $ldap_user['attr'][ldap_server_massage_text($ldap_server_authenticated_on->get('account_name_attr'), 'attr_name', LDAP_SERVER_MASSAGE_QUERY_ARRAY)][0];
    if (!$drupal_accountname) {
      \Drupal::logger('ldap_authentication')->error('Derived drupal username from attribute %account_name_attr returned no username for authname %authname.', $watchdog_tokens);
      return;
    }
  }
  else {
    $drupal_accountname = $authname;
  }
  $watchdog_tokens['%drupal_accountname'] = $drupal_accountname;

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
  if (!$drupal_account_exists && $ldap_server_authenticated_on) {
    $puid = $ldap_server_authenticated_on->userPuidFromLdapEntry($ldap_user['attr']);
    if ($puid) {
      $drupal_account = $ldap_server_authenticated_on->userUserEntityFromPuid($puid);
      if ($drupal_account) {
        $drupal_account_exists = TRUE;
        $user_edit = array('name' => $drupal_accountname);
        $drupal_account = user_save($drupal_account, $user_edit, 'ldap_user');
        user_set_authmaps($drupal_account, array("authname_ldap_user" => $authname));
        $drupal_account_is_authmapped = TRUE;
      }
    }
  }

  /**
   * VI.B: existing Drupal account but not authmapped to ldap modules,
   *   ldap authmap or disallow
   *
   */

  if ($drupal_account_exists && !$drupal_account_is_authmapped) {  // account already exists
    if ($auth_conf->ldapUser->loginConflictResolve == LDAP_USER_CONFLICT_LOG) {
      if ($account_with_same_email = user_load_by_mail($ldap_user['mail'])) {
        $watchdog_tokens['%conflict_name'] = $account_with_same_email->name;
        \Drupal::logger('ldap_authentication')->error('LDAP user with DN %dn has a naming conflict with a local drupal user %conflict_name', $watchdog_tokens);
      }
      drupal_set_message(t('Another user already exists in the system with the same login name. You should contact the system administrator in order to solve this conflict.'), 'error');
      return;
    }
    else { // LDAP_authen.AC.disallow.ldap.drupal
      // add ldap_authentication authmap to user. account name is fine here, though cn could be used
      ldap_user_set_identifier($drupal_account, $authname);
      $drupal_account_is_authmapped = TRUE;
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('set authmap for %username authname_ldap_user', $watchdog_tokens);
      }
    }
  }

  /**
   * VI.C: existing Drupal account with incorrect email.  fix email if appropriate
   *
   */
  if ($drupal_account_exists && $drupal_account->mail->value != $ldap_user['mail'] && (
          $auth_conf->emailUpdate == LDAP_AUTHENTICATION_EMAIL_UPDATE_ON_LDAP_CHANGE_ENABLE_NOTIFY ||
          $auth_conf->emailUpdate == LDAP_AUTHENTICATION_EMAIL_UPDATE_ON_LDAP_CHANGE_ENABLE
          ))  {
    $drupal_account->set('mail', $ldap_user['mail']);
    $watchdog_tokens['%username'] = $drupal_account->name->value;
    if (!$updated_account = $drupal_account->save()) {
      \Drupal::logger('ldap_authentication')->error('Failed to make changes to user %username updated %changed.', $watchdog_tokens);
    }
    elseif ($auth_conf->emailUpdate == LDAP_AUTHENTICATION_EMAIL_UPDATE_ON_LDAP_CHANGE_ENABLE_NOTIFY ) {
      if (isset($user_edit['mail'])) {
        $watchdog_tokens['%mail'] = $user_edit['mail'];
        drupal_set_message(t('Your e-mail has been updated to match your current account (%mail).', $watchdog_tokens), 'status');
      }
      if (isset($user_edit['name'])) {
        $watchdog_tokens['%new_username'] = $user_edit['name'];
        drupal_set_message(t('Your old account username %username has been updated to %new_username.', $watchdog_tokens), 'status');
      }
    }
  }

  /**
   * VI.C: no existing Drupal account.  consider provisioning Drupal account.
   *
   */
  if (!$drupal_account_exists) {

    // VI.C.1 Do not provision Drupal account if another account has same email.
    if ($account_with_same_email = user_load_by_mail($ldap_user['mail'])) {
      /**
       * username does not exist but email does.  Since user_external_login_register does not deal with
       * mail attribute and the email conflict error needs to be caught beforehand, need to throw error here
       */
      $watchdog_tokens['%duplicate_name'] = $account_with_same_email->name;
      \Drupal::logger('ldap_authentication')->error('LDAP user with DN %dn has email address (%mail) conflict with a drupal user %duplicate_name', $watchdog_tokens);

      drupal_set_message(t('Another user already exists in the system with the same email address. You should contact the system administrator in order to solve this conflict.'), 'error');
      return;
    }

    // VI.C.2 Do not provision Drupal account if provisioning disabled
    if (!$auth_conf->ldapUser->provisionEnabled(LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, LDAP_USER_DRUPAL_USER_PROV_ON_AUTHENTICATE)) {
      \Drupal::logger('ldap_authentication')->error('Drupal account for authname=%authname account name=%account_name_attr does not exist and provisioning of Drupal accounts on authentication is not enabled', $watchdog_tokens);
      return;
    }

    // VI.C.3 Provision Drupal account
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

    if ($auth_conf->ldapUser->acctCreation == LDAP_AUTHENTICATION_ACCT_CREATION_USER_SETTINGS_FOR_LDAP &&
        config('user.settings')->get('register') == USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL) {
      $user_edit = array('name' => $drupal_accountname, 'status' => 0); // if admin approval required, set status to 0.
    }
    else {
      $user_edit = array('name' => $drupal_accountname, 'status' => 1);
    }

    // don't pass in ldap user to provisionDrupalAccount, because want to requery with correct attributes needed
    // this may be a case where efficiency dictates querying for all attributes
    $drupal_account = $auth_conf->ldapUser->provisionDrupalAccount(NULL, $user_edit, NULL, TRUE);

    if ($drupal_account === FALSE) {
      \Drupal::logger('ldap_user')->error('Failed to find or create %drupal_accountname on logon.', $watchdog_tokens);
      $form_state->setErrorByName('name', t('Server Error: Failed to create Drupal user account for %drupal_accountname', $watchdog_tokens));
      return;
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

  $form_state->set('uid', $drupal_account->id());
 // $fake_form_state = array('uid' => $drupal_account->uid);
 // user_login_submit(array(), $fake_form_state);
 // global $user;
 // $form_state['uid'] = $user->uid;


  // the uid is returned so that special login modules, namely ldap sso, can manually call this function.
  return ($return_user) ? $drupal_account : NULL;
}

/**
 * given authname, determine if corresponding drupal account exists and is authmapped
 */
function ldap_authentication_corresponding_drupal_user($authname, $auth_conf, &$watchdog_tokens) {
  $detailed_watchdog_log = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
  if (!($drupal_account = user_load_by_name($authname))) {
    $uid = ldap_user_get_uid_from_map($authname);
    $drupal_account = $uid ? user_load($uid) : FALSE;
  }

  if (is_object($drupal_account)) {
    $drupal_account_is_authmapped = ldap_user_get_identifier_from_map($drupal_account->id());
    if ($drupal_account->id() == 1 && $detailed_watchdog_log) {
      \Drupal::logger('ldap_authentication')->debug('%username : Drupal username maps to user 1, so do not authenticate with ldap', $watchdog_tokens);
    }
    elseif ($detailed_watchdog_log) {
      \Drupal::logger('ldap_authentication')->debug('%username : Drupal User Account found.  Continuing on to attempt ldap authentication', $watchdog_tokens);
    }
  }
  else {  // account does not exist
    $drupal_account_is_authmapped = FALSE;
    if ($auth_conf->ldapUser->createLDAPAccounts == FALSE) {
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : Drupal User Account not found and configuration is set to not create new accounts.', $watchdog_tokens);
      }
    }
    if ($detailed_watchdog_log) {
      \Drupal::logger('ldap_authentication')->debug('%username : Existing Drupal User Account not found.  Continuing on to attempt ldap authentication', $watchdog_tokens);
    }
  }
  return array($drupal_account, $drupal_account_is_authmapped);
}

function ldap_authentication_test_credentials($auth_conf, $sso_login, $authname, $password, &$watchdog_tokens) {
  $detailed_watchdog_log = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
  $authentication_result = LDAP_AUTHENTICATION_RESULT_FAIL_GENERIC;
  $ldap_user = FALSE;
  $ldap_server = NULL;

  /* @var \Drupal\ldap_servers\Entity\Server $ldap_server */
  foreach ($auth_conf->enabledAuthenticationServers as $id => $ldap_server) {
    $watchdog_tokens['%id'] = $id;
    $watchdog_tokens['%bind_method'] = $ldap_server->get('bind_method');
    if ($detailed_watchdog_log) {
      \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method', $watchdog_tokens);
    }

    // #1 CONNECT TO SERVER
    $authentication_result = LDAP_AUTHENTICATION_RESULT_FAIL_GENERIC;
    $result = $ldap_server->connect();
    if ($result != LDAP_SUCCESS) {
      $authentication_result = LDAP_AUTHENTICATION_RESULT_FAIL_CONNECT;
      $watchdog_tokens['%err_msg'] = $ldap_server->errorMsg('ldap');
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_authentication')->debug('%username : Failed connecting to %id.  Error: %err_msg', $watchdog_tokens);
      }
      $watchdog_tokens['%err_msg'] = NULL;
      continue; // next server, please
    }
    elseif ($detailed_watchdog_log) {
      \Drupal::logger('ldap_authentication')->debug('%username : Success at connecting to %id', $watchdog_tokens);
    }

/**
 *
 * LDAP_SERVERS_BIND_METHOD_SERVICE_ACCT => t('Service Account Bind.  Use credentials in following section to
 * bind to ldap.  This option is usually a best practice. Service account is entered in next section.'),
 *
 * LDAP_SERVERS_BIND_METHOD_USER => t('Bind with Users Credentials.  Use users\' entered credentials
 * to bind to LDAP.  This is only useful for modules that work during user logon such
 * as ldap authentication and ldap authorization.  This option is not a best practice in most cases.
 * The users dn must be of the form "cn=[username],[base dn]" for this option to work.'),
 *
 * LDAP_SERVERS_BIND_METHOD_ANON_USER => t('Anonymous Bind for search, then Bind with Users Credentials.
 * Searches for user DN then uses users\' entered credentials to bind to LDAP.  This is only useful for
 * modules that work during user logon such as ldap authentication and ldap authorization.
 * The users dn must be discovered by an anonymous search for this option to work.'),
 *
 * LDAP_SERVERS_BIND_METHOD_ANON => t('Anonymous Bind. Use no credentials to bind to ldap server.
 * Will not work on most ldaps.'),
 *
 */

    $bind_success = FALSE;
    if ($ldap_server->get('bind_method') == LDAP_SERVERS_BIND_METHOD_SERVICE_ACCT) {
      $bind_success = ($ldap_server->bind(NULL, NULL, FALSE) == LDAP_SUCCESS);
    }
    elseif ($ldap_server->get('bind_method') == LDAP_SERVERS_BIND_METHOD_ANON ||
      $ldap_server->get('bind_method') == LDAP_SERVERS_BIND_METHOD_ANON_USER) {
      $bind_success = ($ldap_server->bind(NULL, NULL, TRUE) == LDAP_SUCCESS);
    }
    elseif ($sso_login) {
      \Drupal::logger('ldap_authentication')->error('Trying to use SSO with LDAP_SERVERS_BIND_METHOD_USER bind method.', $watchdog_tokens);
    }
    elseif ($ldap_server->get('bind_method') == LDAP_SERVERS_BIND_METHOD_USER && $sso_login == FALSE) {
      // with sso enabled this method of binding isn't valid
      foreach ($ldap_server->getBasedn() as $basedn) {
        $search = array('%basedn', '%username');
        $transformname =  $ldap_server->userUsernameToLdapNameTransform($authname, $watchdog_tokens);
        $replace = array($basedn, $transformname);
        $userdn = str_replace($search, $replace, $ldap_server->get('user_dn_expression'));
        $bind_success = ($ldap_server->bind($userdn, $password, FALSE) == LDAP_SUCCESS);
        if ($bind_success) {
          break;
        }
      }
    }
    else {
      \Drupal::logger('ldap_authentication')->debug('No bind method set in ldap_server->bind_method in _ldap_authentication_user_login_authenticate_validate.', $watchdog_tokens);
    }

    if (!$bind_success) {
      if ($detailed_watchdog_log) {
        $watchdog_tokens['%err_text'] = $ldap_server->errorMsg('ldap');
        \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method.  Error: %err_text', $watchdog_tokens);
        $watchdog_tokens['%err_text'] = NULL;
      }
      $authentication_result = ($ldap_server->bind_method == LDAP_SERVERS_BIND_METHOD_USER) ? LDAP_AUTHENTICATION_RESULT_FAIL_CREDENTIALS : LDAP_AUTHENTICATION_RESULT_FAIL_BIND;
      continue; // if bind fails, onto next server
    }

    // #3 DOES USER EXIST IN SERVER'S LDAP
    if ($ldap_server->bind_method == LDAP_SERVERS_BIND_METHOD_ANON_USER) {
      $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($authname);
    }
    elseif ($sso_login) {
      $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($authname);
      if ($detailed_watchdog_log) {
        $watchdog_tokens['%result'] = var_export($result, TRUE);
        \Drupal::logger('ldap_authentication')->debug('%username : attempting single sign-on
          login in bind_method of LDAP_SERVERS_BIND_METHOD_USER. Result of
          userUserNameToExistingLdapEntry: <pre>%result</pre>', $watchdog_tokens);
      }
    }
    else {
      $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($authname);
    }

    if (!$ldap_user) {
      if ($detailed_watchdog_log) {
        $watchdog_tokens['%err_text'] = $ldap_server->errorMsg('ldap');
        \Drupal::logger('ldap_authentication')->debug('%username : Trying server %id where bind_method = %bind_method.  Error: %err_text', $watchdog_tokens);
        $watchdog_tokens['%err_text'] = NULL;
      }
      if ($ldap_server->ldapErrorNumber()) {
        $authentication_result = LDAP_AUTHENTICATION_RESULT_FAIL_SERVER;
        break;
      }
      $authentication_result = LDAP_AUTHENTICATION_RESULT_FAIL_FIND;
      continue; // next server, please
    }

    $watchdog_tokens['%dn'] = $ldap_user['dn'];
    $watchdog_tokens['%mail'] = $ldap_user['mail'];

    /**
    * #4 CHECK ALLOWED AND EXCLUDED LIST AND PHP FOR ALLOWED USERS
    */

    if (!$auth_conf->allowUser($authname, $ldap_user)) {
      $authentication_result = LDAP_AUTHENTICATION_RESULT_FAIL_DISALLOWED;
      break;  // regardless of how many servers, disallowed user fails
    }

    /**
    * #5 TEST PASSWORD
    */
    $credentials_pass = FALSE;
    if ($sso_login) {
      /** If we have $sso_login passed in as true from the fake form state in
        * passed from _ldap_authentication_user_login_sso(), we will be relying
        * on the webserver for actually authenticating the user, either by NTLM
        * or user/password if configured as a fallback. Since the webserver has
        * already authenticated the user, and the web server only contains the
        * user's LDAP user name, instead of binding on the username/pass, we
        * simply look up the user's account in LDAP, and make sure it matches
        * what is contained in the global $_SERVER array populated by the web
        * server authentication.
        */
      $credentials_pass = (boolean)($ldap_user);
    }
    else {
      $credentials_pass = ($ldap_server->bind($ldap_user['dn'], $password, FALSE) == LDAP_SUCCESS);
    }
    if (!$credentials_pass) {
      if ($detailed_watchdog_log) {
        $watchdog_tokens['%err_text'] = $ldap_server->errorMsg('ldap');
        \Drupal::logger('ldap_authentication')->debug('%username : Testing user credentials on server %id where bind_method = %bind_method.  Error: %err_text', $watchdog_tokens);
        $watchdog_tokens['%err_text'] = NULL;
      }
      $authentication_result = LDAP_AUTHENTICATION_RESULT_FAIL_CREDENTIALS;
      continue; // next server, please
    }
    else {
      $authentication_result = LDAP_AUTHENTICATION_RESULT_SUCCESS;
      if ($ldap_server->bind_method == LDAP_SERVERS_BIND_METHOD_ANON_USER) {
        $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($authname); // after successful bind, lookup user again to get private attributes
        $watchdog_tokens['%mail'] = $ldap_user['mail'];
      }
      if ($ldap_server->bind_method == LDAP_SERVERS_BIND_METHOD_SERVICE_ACCT ||
          $ldap_server->bind_method == LDAP_SERVERS_BIND_METHOD_ANON_USER) {
          $ldap_server->disconnect();
      }
      break; //success
    }

  }  // end loop through servers

  $watchdog_tokens['%result'] = $result;
  $watchdog_tokens['%auth_result'] = $authentication_result;
  $watchdog_tokens['%err_text'] =  _ldap_authentication_err_text($authentication_result) ;
  if ($detailed_watchdog_log) {
    \Drupal::logger('ldap_authentication')->debug('%username : Authentication result id=%result auth_result=%auth_result (%err_text)', $watchdog_tokens);
  }

  return array($authentication_result, $ldap_user, $ldap_server);
}

function ldap_authentication_fail_response($authentication_result, $auth_conf, $detailed_watchdog_log, &$watchdog_tokens) {
  $watchdog_tokens['%err_text'] =  _ldap_authentication_err_text($authentication_result);
  // fail scenario 1.  ldap auth exclusive and failed  throw error so no other authentication methods are allowed
  if ($auth_conf->authenticationMode == LDAP_AUTHENTICATION_EXCLUSIVE) {
    if ($detailed_watchdog_log) {
      \Drupal::logger('ldap_authentication')->debug('%username : setting error because failed at ldap and
        LDAP_AUTHENTICATION_EXCLUSIVE is set to true.  So need to stop authentication of Drupal user that is not user 1.
        error message: %err_text', $watchdog_tokens);
    }
    // form_set_error('name', $watchdog_tokens['%err_text']);
    drupal_set_message("TODO: Form set error replacement.", "error");
  }
  else {
    // fail scenario 2.  simply fails ldap.  return false, but don't throw form error
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
 * get human readable authentication error string
 *
 * @param int $error as LDAP_AUTHENTICATION_RESULT_* constant defined in ldap_authentication.module
 * @return string human readable error text
 */
function _ldap_authentication_err_text($error) {

  $msg = t('unknown error: ' . $error);
  switch ($error) {
    case LDAP_AUTHENTICATION_RESULT_FAIL_CONNECT:
    $msg = t('Failed to connect to ldap server');
    break;

    case LDAP_AUTHENTICATION_RESULT_FAIL_BIND:
    $msg = t('Failed to bind to ldap server');
    break;

    case LDAP_AUTHENTICATION_RESULT_FAIL_FIND:
    $msg =  t('Sorry, unrecognized username or password.');
    break;

    case LDAP_AUTHENTICATION_RESULT_FAIL_DISALLOWED:
    $msg = t('User disallowed');
    break;

    case LDAP_AUTHENTICATION_RESULT_FAIL_CREDENTIALS:
    $msg =  t('Sorry, unrecognized username or password.');
    break;

    case LDAP_AUTHENTICATION_RESULT_FAIL_GENERIC:
    $msg = t('Sorry, unrecognized username or password.');
    break;

    case LDAP_AUTHENTICATION_RESULT_FAIL_SERVER:
    $msg = t('Authentication Server or Configuration Error.');
    break;

  }

  return $msg;
}

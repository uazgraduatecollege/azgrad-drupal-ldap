<?php

namespace Drupal\ldap_authentication\Controller;

use Drupal\authorization\Entity\AuthorizationProfile;
use Drupal\Component\Utility\SafeMarkup;
use Drupal\ldap_authentication\Helper\LdapAuthenticationConfiguration;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\MassageAttributes;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Processor\DrupalUserProcessor;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use Drupal\Core\Form\FormStateInterface;

class LoginValidator {

  const AUTHENTICATION_FAILURE_CONNECTION = 1;
  const AUTHENTICATION_FAILURE_BIND = 2;
  const AUTHENTICATION_FAILURE_FIND = 3;
  const AUTHENTICATION_FAILURE_DISALLOWED = 4;
  const AUTHENTICATION_FAILURE_CREDENTIALS = 5;
  const AUTHENTICATION_SUCCESS = 6;
  const AUTHENTICATION_FAILURE_GENERIC = 7;
  const AUTHENTICATION_FAILURE_SERVER = 8;

  protected $authName = FALSE;

  protected $drupalUserAuthMapped = FALSE;
  public $drupalUserName = FALSE;
  /** @var Server $serverDrupalUser */
  public $serverDrupalUser = FALSE;
  /** @var User $drupalUser */
  public $drupalUser = FALSE;
  public $ldapUser = FALSE;

  private $detailedLogging = FALSE;
  private $config;
  private $emailTemplateUsed = FALSE;
  private $emailTemplateTokens = [];

  /** @var FormStateInterface $formState */
  protected $formState;

  public function __construct() {
    $this->detailedLogging = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
    $this->config = \Drupal::config('ldap_authentication.settings');
  }

  public function validateLogin(FormStateInterface $formState) {
    $this->authName = trim($formState->getValue('name'));
    $this->formState = $formState;
   
    if ($this->detailedLogging) {
      \Drupal::logger('ldap_authentication')->debug('%auth_name : Beginning authentication', ['%auth_name' => $this->authName]);
    }

    $this->processLogin();


    return $this->formState;
  }

  /**
   * @return bool
   */
  private function processLogin() {
    if (!$this->validateAlreadyAuthenticated()) {
      return FALSE;
    }
    if (!$this->validateCommonLoginConstraints()) {
      return FALSE;
    }

    $credentialsAuthenticationResult = $this->testCredentials($this->formState->getValue('pass'));

    if ($credentialsAuthenticationResult == self::AUTHENTICATION_FAILURE_FIND &&
      \Drupal::config('ldap_authentication.settings')->get('authenticationMode') == LdapAuthenticationConfiguration::MODE_EXCLUSIVE) {
      $this->formState->setErrorByName('non_ldap_login_not_allowed', t('User disallowed'));
    }

    if ($credentialsAuthenticationResult != self::AUTHENTICATION_SUCCESS) {
      return FALSE;
    }

    if (!$this->deriveDrupalUserName()) {
      return FALSE;
    }

    /**
     * We now have an LDAP account, matching username and password and the
     * reference Drupal user.
     */

    if (!$this->drupalUser && $this->serverDrupalUser) {
      $this->updateAuthNameFromPuid();
    }

    //  Existing Drupal but not mapped to LDAP.
    if ($this->drupalUser && !$this->drupalUserAuthMapped) {
      if (!$this->matchExistingUserWithLdap()) {
        return FALSE;
      }
    }

    /**
     * Existing Drupal account with incorrect email. Fix email if appropriate
     *
     */
    $this->fixOutdatedEmailAddress();

    /**
     * No existing Drupal account. Consider provisioning Drupal account.
     */
    if (!$this->drupalUser) {
      if (!$this->provisionDrupalUser()) {
        return FALSE;
      }
    }

    // All passed, log the user in by handing over the UID.
    if ($this->drupalUser) {
      $this->formState->set('uid', $this->drupalUser->id());
    }

    return TRUE;
  }

  /**
   * Todo: Postprocessing could be wrapped in a function, identical in processLogin().
   * @param $authName
   * @return bool
   */
  public function processSsoLogin($authName) {
    $this->authName = $authName;

    if (!$this->validateCommonLoginConstraints()) {
      return FALSE;
    }

    $credentialsAuthenticationResult = $this->testSsoCredentials($this->authName);

    if ($credentialsAuthenticationResult == self::AUTHENTICATION_FAILURE_FIND &&
      \Drupal::config('ldap_authentication.settings')->get('authenticationMode') == LdapAuthenticationConfiguration::MODE_EXCLUSIVE) {
      $this->formState->setErrorByName('non_ldap_login_not_allowed', t('User disallowed'));
    }

    if ($credentialsAuthenticationResult != self::AUTHENTICATION_SUCCESS) {
      return FALSE;
    }

    if (!$this->deriveDrupalUserName()) {
      return FALSE;
    }

    /**
     * We now have an LDAP account, matching username and password and the
     * reference Drupal user.
     */

    if (!$this->drupalUser && $this->serverDrupalUser) {
      $this->updateAuthNameFromPuid();
    }

    //  Existing Drupal but not mapped to LDAP.
    if ($this->drupalUser && !$this->drupalUserAuthMapped) {
      if (!$this->matchExistingUserWithLdap()) {
        return FALSE;
      }
    }

    /**
     * Existing Drupal account with incorrect email. Fix email if appropriate
     *
     */
    $this->fixOutdatedEmailAddress();

    /**
     * No existing Drupal account. Consider provisioning Drupal account.
     */
    if (!$this->drupalUser) {
      if (!$this->provisionDrupalUser()) {
        return FALSE;
      }
    }

    return TRUE;
  }

  /**
   * Given authname, determine if corresponding drupal account exists and is authmapped.
   *
   * @return array
   */
  private function initializeAuthNameCorrespondingDrupalUser() {
    if (!($this->drupalUser = user_load_by_name($this->authName))) {
      $uid = ExternalAuthenticationHelper::getUidFromIdentifierMap($this->authName);
      $this->drupalUser = $uid ? user_load($uid) : FALSE;
    }

    if (is_object($this->drupalUser)) {
      $this->drupalUserAuthMapped = ExternalAuthenticationHelper::getUserIdentifierFromMap($this->drupalUser->id());
      if ($this->drupalUser->id() == 1 && $this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username: Drupal user name maps to user 1, so do not authenticate with LDAP.', ['%username' => $this->authName]);
      }
      elseif ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username: Drupal user account found. Continuing on to attempt LDAP authentication.', ['%username' => $this->authName]);
      }
    }
    // Account does not exist.
    else {
      $this->drupalUserAuthMapped = FALSE;
      if (LdapConfiguration::createLDAPAccounts() == FALSE) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('%username: Drupal user account not found and configuration is set to not create new accounts.', ['%username' => $this->authName]);
        }
      }
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username: Existing Drupal user account not found. Continuing on to attempt ldap authentication', ['%username' => $this->authName]);
      }
    }
  }

  /**
   *
   */
  private function testCredentials($password) {
    $authenticationResult = self::AUTHENTICATION_FAILURE_GENERIC;
    $factory = \Drupal::service('ldap.servers');

    foreach (LdapAuthenticationConfiguration::getEnabledAuthenticationServers() as $server) {
      $authenticationResult = self::AUTHENTICATION_FAILURE_GENERIC;
      $this->serverDrupalUser = $factory->getServerById($server);
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username: Trying server %id with %bind_method', [
            '%username' => $this->authName,
            '%id' => $this->serverDrupalUser->id(),
            '%bind_method' => $this->serverDrupalUser->getFormattedBind(),
          ]
        );
      }

      if (!$this->connectToServer()) {
        continue;
      }

      $bindStatus = $this->bindToServer($password);
      if ($bindStatus != 'success') {
        $authenticationResult = $bindStatus;
        // If bind fails, onto next server.
        continue;
      }

      // Check if user exists in LDAP.

      $this->ldapUser = $this->serverDrupalUser->userUserNameToExistingLdapEntry($this->authName);

      if (!$this->ldapUser) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('%username: Error trying server %id with %bind_method: %err_text', [
              '%username' => $this->authName,
              '%err_text' => $this->serverDrupalUser->errorMsg('ldap'),
              '%bind_method' => $this->serverDrupalUser->getFormattedBind(),
              '%id' => $this->serverDrupalUser->id(),
            ]
          );
        }
        if ($this->serverDrupalUser->ldapErrorNumber()) {
          $authenticationResult = self::AUTHENTICATION_FAILURE_SERVER;
          break;
        }
        $authenticationResult = self::AUTHENTICATION_FAILURE_FIND;
        // Next server, please.
        continue;
      }


      if (!$this->checkAllowedExcluded($this->authName, $this->ldapUser)) {
        $authenticationResult = self::AUTHENTICATION_FAILURE_DISALLOWED;
        // Regardless of how many servers, disallowed user fails.
        break;
      }

      /**
       * #5 TEST PASSWORD
       */
      $credentials_pass = $this->testUserPassword($password);

      if (!$credentials_pass) {
        $authenticationResult = self::AUTHENTICATION_FAILURE_CREDENTIALS;
        // Next server, please.
        continue;
      }
      else {
        $authenticationResult = self::AUTHENTICATION_SUCCESS;
        if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnonUser) {
          // After successful bind, lookup user again to get private attributes.
          $this->ldapUser = $this->serverDrupalUser->userUserNameToExistingLdapEntry($this->authName);
        }
        if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodServiceAccount ||
          $this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnonUser) {
          $this->serverDrupalUser->disconnect();
        }
        // Success.
        break;
      }

    }  // end loop through servers

    if ($this->detailedLogging) {
      \Drupal::logger('ldap_authentication')->debug('%username: Authentication result is "%err_text"',
        [
          '%username' => $this->authName,
          '%err_text' => $this->authenticationHelpText($authenticationResult) . $this->additionalDebuggingResponse($authenticationResult),
        ]
      );
    }

    if ($authenticationResult != self::AUTHENTICATION_SUCCESS) {
      $this->ldap_authentication_fail_response($authenticationResult);
    }

    return $authenticationResult;
  }

  private function testUserPassword($password) {
    $loginValid = FALSE;
    if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodUser) {
      $loginValid = TRUE;
    }
    elseif ($this->serverDrupalUser->bind($this->ldapUser['dn'], $password, FALSE) == Server::LDAP_SUCCESS) {
      $loginValid = TRUE;
    } else {
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug('%username: Error testing user credentials on server %id with %bind_method. Error: %err_text', [
          '%username' => $this->authName,
          '%bind_method' => $this->serverDrupalUser->getFormattedBind(),
          '%id' => $this->serverDrupalUser->id(),
          '%err_text' => $this->serverDrupalUser->errorMsg('ldap'),
        ]);
      }
    }
    return $loginValid;
  }
  
  public function testSsoCredentials($authName) {
    //TODO: Verify if MODE_EXCLUSIVE check is a regression.
    $authenticationResult = self::AUTHENTICATION_FAILURE_GENERIC;
    $ldap_server = NULL;
    $factory = \Drupal::service('ldap.servers');

    foreach (LdapAuthenticationConfiguration::getEnabledAuthenticationServers() as $server) {
      $authenticationResult = self::AUTHENTICATION_FAILURE_GENERIC;
      $this->serverDrupalUser = $factory->getServerById($server);
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug(
          '%username: Trying server %id where bind_method = %bind_method',
          [
            '%id' => $this->serverDrupalUser->id(),
            '%bind_method' => $this->serverDrupalUser->get('bind_method'),
          ]
        );
      }

      if (!$this->connectToServer()) {
        continue;
      }

      $bindResult = $this->bindToServerSSO();
      if ($bindResult != 'success') {
        $authenticationResult = $bindResult;
        // If bind fails, onto next server.
        continue;
      }
      
      $this->ldapUser = $this->serverDrupalUser->userUserNameToExistingLdapEntry($authName);
      
      if (!$this->ldapUser) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug(
            '%username: Trying server %id where bind_method = %bind_method.  Error: %err_text', [
              '%username' => $authName,
              '%bind_method' => $this->serverDrupalUser->get('bind_method'),
              '%err_text' => $this->serverDrupalUser->errorMsg('ldap'),
            ]
          );
        }
        if ($this->serverDrupalUser->ldapErrorNumber()) {
          $authenticationResult = self::AUTHENTICATION_FAILURE_SERVER;
          break;
        }
        $authenticationResult = self::AUTHENTICATION_FAILURE_FIND;
        // Next server, please.
        continue;
      }

      if (!$this->checkAllowedExcluded($this->authName, $this->ldapUser)) {
        $authenticationResult = self::AUTHENTICATION_FAILURE_DISALLOWED;
        // Regardless of how many servers, disallowed user fails.
        break;
      }
      
      $authenticationResult = self::AUTHENTICATION_SUCCESS;
      if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnonUser) {
        // After successful bind, lookup user again to get private attributes.
        $this->ldapUser = $this->serverDrupalUser->userUserNameToExistingLdapEntry($authName);
      }
      if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodServiceAccount ||
        $this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnonUser) {
        $this->serverDrupalUser->disconnect();
      }
      // Success.
      break;

    }  // end loop through servers
    
    if ($this->detailedLogging) {
      \Drupal::logger('ldap_authentication')->debug('Authentication result for %username is: %err_text',
        [
          '%username' => $authName,
          '%err_text' => $this->authenticationHelpText($authenticationResult) . $this->additionalDebuggingResponse($authenticationResult),
        ]
      );
    }
    return $authenticationResult;
  }

  private function additionalDebuggingResponse($authenticationResult) {
    $information = '';
    switch ($authenticationResult) {
      case self::AUTHENTICATION_FAILURE_FIND:
        $information = t(' (not found)');
        break;
      case self::AUTHENTICATION_FAILURE_CREDENTIALS:
        $information = t(' (wrong credentials)');
        break;
      case self::AUTHENTICATION_FAILURE_GENERIC:
        $information = t(' (generic)');
        break;
    }
    return $information;
  }

  /**
   * @param $authenticationResult
   */
  private function ldap_authentication_fail_response($authenticationResult) {
    // Fail scenario 1.  ldap auth exclusive and failed  throw error so no other authentication methods are allowed.
    if (\Drupal::config('ldap_authentication.settings')->get('authenticationMode') == LdapAuthenticationConfiguration::MODE_EXCLUSIVE) {
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug(
          '%username: Error raised because failure at LDAP and exclusive authentication is set to true.',
          ['%username' => $this->authName]
        );
      }
      drupal_set_message(t('Error: %err_text', ['%err_text' => $this->authenticationHelpText($authenticationResult)]), "error");
    }
    else {
      // Fail scenario 2.  simply fails ldap.  return false, but don't throw form error
      // don't show user message, may be using other authentication after this that may succeed.
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')->debug(
          '%username: Failed LDAP authentication. User may have authenticated successfully by other means in a mixed authentication site.',
          ['%username' => $this->authName]
        );
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
  private function authenticationHelpText($error) {
    
    switch ($error) {
      case self::AUTHENTICATION_FAILURE_CONNECTION:
        $msg = t('Failed to connect to ldap server');
        break;
      case self::AUTHENTICATION_FAILURE_BIND:
        $msg = t('Failed to bind to ldap server');
        break;
      case self::AUTHENTICATION_FAILURE_DISALLOWED:
        $msg = t('User disallowed');
        break;
      case self::AUTHENTICATION_FAILURE_FIND:
      case self::AUTHENTICATION_FAILURE_CREDENTIALS:
      case self::AUTHENTICATION_FAILURE_GENERIC:
        $msg = t('Sorry, unrecognized username or password.');
        break;
      case self::AUTHENTICATION_FAILURE_SERVER:
        $msg = t('Authentication Server or Configuration Error.');
        break;
      case self::AUTHENTICATION_SUCCESS:
        $msg = t('Authentication successful');
        break;
      default:
        $msg = t('unknown error: ' . $error);
        break;
    }

    return $msg;
  }

  public function checkAllowedExcluded($authName, $ldap_user) {

    /**
     * Do one of the exclude attribute pairs match? If user does not already
     * exists and deferring to user settings AND user settings only allow.
     */


    foreach (\Drupal::config('ldap_authentication.settings')->get('excludeIfTextInDn') as $test) {
      if (stripos($ldap_user['dn'], $test) !== FALSE) {
        // If a match, return FALSE;.
        return FALSE;
      }
    }

    /**
     * do one of the allow attribute pairs match
     */
    if (count(\Drupal::config('ldap_authentication.settings')->get('allowOnlyIfTextInDn'))) {
      $fail = TRUE;
      foreach (\Drupal::config('ldap_authentication.settings')->get('allowOnlyIfTextInDn') as $test) {
        if (stripos($ldap_user['dn'], $test) !== FALSE) {
          $fail = FALSE;
        }
      }
      if ($fail) {
        return FALSE;
      }

    }
    /**
     * Handle excludeIfNoAuthorizations enabled and user has no groups.
     */

    if (\Drupal::config('ldap_authentication.settings')->get('excludeIfNoAuthorizations')) {

      $user = User::load($authName);

      if (!$user) {
        $user = User::create(['name' => $authName]);
      }

      $profiles = authorization_get_profiles();
      $authorizations = [];
      foreach ($profiles as $profile_id) {
        $profile = AuthorizationProfile::load($profile_id);
        if ($profile->getProviderId() == 'ldap_provider') {
          list($new_authorizations_i, $notifications_i) = _authorizations_user_authorizations($user, 'query', $profile_id, NULL);
          $authorizations = $authorizations + $new_authorizations_i;
        }
      }

      if (count($authorizations) == 0) {
        drupal_set_message(t('The site logon is currently not working due to a configuration error.  Please see logs for additional details.'), 'warning');
        \Drupal::logger('ldap_authentication')->notice('LDAP Authentication is configured to deny users without LDAP Authorization mappings, but 0 LDAP Authorization consumers are configured.');
        return FALSE;
      }
      elseif (!$profiles) {
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

  /**
   * @return bool
   */
  private function fixOutdatedEmailAddress() {

    if (!($this->config->get('emailTemplateUsageNeverUpdate') && $this->emailTemplateUsed)) {
      return FALSE;
    }

    if (!$this->drupalUser) {
      return FALSE;
    }

    if ($this->drupalUser->getEmail() == $this->ldapUser['mail']) {
      return FALSE;
    }

    if ($this->config->get('emailUpdate') == LdapAuthenticationConfiguration::$emailUpdateOnLdapChangeEnableNotify ||
        $this->config->get('emailUpdate') == LdapAuthenticationConfiguration::$emailUpdateOnLdapChangeEnable) {
      $this->drupalUser->set('mail', $this->ldapUser['mail']);
      if (!$this->drupalUser->save()) {
        \Drupal::logger('ldap_authentication')
          ->error('Failed to make changes to user %username updated %changed.', [
            '%username' => $this->drupalUser->getUsername(),
            '%changed' => $this->ldapUser['mail'],
            ]
          );
        return FALSE;
      }
      elseif ($this->config->get('emailUpdate') == LdapAuthenticationConfiguration::$emailUpdateOnLdapChangeEnableNotify
      ) {
        drupal_set_message(t(
          'Your e-mail has been updated to match your current account (%mail).',
          ['%mail' => $this->ldapUser['mail']]),
          'status'
        );
        return TRUE;
      }
    }
  }

  /**
   * Update the authName if it's no longer valid.
   *
   * Drupal account does not exist for authName used to logon, but puid exists
   * in another Drupal account; this means username has changed and needs to be
   * saved in Drupal account
   *
   */
  private function updateAuthNameFromPuid() {
    $puid = $this->serverDrupalUser->userPuidFromLdapEntry($this->ldapUser['attr']);
    if ($puid) {
      $this->drupalUser = $this->serverDrupalUser->userUserEntityFromPuid($puid);
      /** @var User $userMatchingPuid */
      if ($this->drupalUser) {
        $this->drupalUser->setUsername($this->drupalUserName);
        $this->drupalUser->save();
        ExternalAuthenticationHelper::setUserIdentifier($this->drupalUser, $this->authName);
        $this->drupalUserAuthMapped = TRUE;
          drupal_set_message(
            t('Your old account username %username has been updated to %new_username.',
              ['%username' => $this->authName, '%new_username' => $this->drupalUserName]),
            'status');
      }
    }
  }

  /**
   * @return bool
   */
  private function validateAlreadyAuthenticated() {

    if (!empty($this->formState->get('uid'))) {
      if ($this->config->get('authenticationMode') == LdapAuthenticationConfiguration::MODE_MIXED) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug(
            '%username: Previously authenticated in mixed mode, pass on validation.',
            ['%username' => $this->authName]
          );
        }
        return FALSE;
      }
    }
    return TRUE;
  }

  /**
   * @return bool
   */
  private function validateCommonLoginConstraints() {

    // Check that enabled servers are available.
    if (!LdapAuthenticationConfiguration::hasEnabledAuthenticationServers()) {
      \Drupal::logger('ldap_authentication')->error('No LDAP servers configured.');
      if ($this->formState) {
        $this->formState->setErrorByName('name', 'Server Error:  No LDAP servers configured.');
      }
      return FALSE;
    }

    /**
     * Determine if corresponding drupal account exists for $this->authName.
     */
    $this->initializeAuthNameCorrespondingDrupalUser();

    if ($this->drupalUser && $this->drupalUser->id() == 1) {
      // User 1 is never allowed to authenticate via LDAP.
      return FALSE;
    }

    return TRUE;
  }

  /**
   * @return bool
   */
  private function deriveDrupalUserName() {
    /**
     * If account_name_attr is set, Drupal username is different than authName.
     */
    if (!empty($this->serverDrupalUser->get('account_name_attr'))) {
      $massager = new MassageAttributes();
      $processedName = $massager->processAttributeName($this->serverDrupalUser->get('account_name_attr'));
      $userNameFromAttribute = $this->ldapUser['attr'][$processedName][0];
      if (!$userNameFromAttribute) {
        \Drupal::logger('ldap_authentication')
          ->error('Derived drupal username from attribute %account_name_attr returned no username for authname %authname.', [
              '%authname' => $this->authName,
              '%account_name_attr' => $this->serverDrupalUser->get('account_name_attr'),
            ]
          );
        return FALSE;
      } else {
        $this->drupalUserName = $userNameFromAttribute;
      }
    }
    else {
      $this->drupalUserName = $this->authName;
    }
    $this->prepareEmailTemplateToken();

    return TRUE;
  }

  private function prepareEmailTemplateToken() {
    $this->emailTemplateTokens = [
      '@username' => $this->drupalUserName,
    ];

    if (!empty($this->config->get('emailTemplate'))) {
      $handling = $this->config->get('emailTemplateHandling');
      if (($handling == 'if_empty' && empty($this->ldapUser['mail'])) || $handling == 'always') {
          $this->replaceUserMailWithTemplate();
          if ($this->detailedLogging) {
            \Drupal::logger('ldap_authentication')->debug('Using template generated email for %username', [
              '%username' => $this->drupalUserName
            ]);
          }
          $this->emailTemplateUsed = TRUE;
      }
    }
  }

  /**
   * @return bool
   */
  private function matchExistingUserWithLdap() {
    if (\Drupal::config('ldapUser.settings')
        ->get('userConflictResolve') == LdapConfiguration::$userConflictLog
    ) {
      if ($account_with_same_email = user_load_by_mail($this->ldapUser['mail'])) {
        /** @var UserInterface $account_with_same_email */
        \Drupal::logger('ldap_authentication')
          ->error('LDAP user with DN %dn has a naming conflict with a local drupal user %conflict_name',
            [
              '%dn' => $this->ldapUser['dn'],
              '%conflict_name' => $account_with_same_email->getUsername()
            ]
          );
      }
      drupal_set_message(t('Another user already exists in the system with the same login name. You should contact the system administrator in order to solve this conflict.'), 'error');
      return FALSE;
    }
    else {
      ExternalAuthenticationHelper::setUserIdentifier($this->drupalUser, $this->authName);
      $this->drupalUserAuthMapped = TRUE;
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')
          ->debug('Set authmap for LDAP user %username', ['%username' => $this->authName]);
      }
    }
    return TRUE;
  }

  private function replaceUserMailWithTemplate() {
    // fallback template in case one was not specified.
    $template = '@username@localhost';
    if (!empty($this->config->get('emailTemplate'))) {
      $template = $this->config->get('emailTemplate');
    }
    $this->ldapUser['mail'] = SafeMarkup::format($template, $this->emailTemplateTokens)->__toString();
  }

  /**
   * @return bool
   */
  private function provisionDrupalUser() {

    // Do not provision Drupal account if another account has same email.
    if ($accountDuplicateMail = user_load_by_mail($this->ldapUser['mail'])) {
      $emailAvailable = FALSE;
      if ($this->config->get('emailTemplateUsageResolveConflict') && (!$this->emailTemplateUsed)) {
        if ($this->detailedLogging) {
          \Drupal::logger('ldap_authentication')->debug('Conflict detected, using template generated email for %username', [
            '%duplicate_name' => $accountDuplicateMail->getUsername(),
          ]);
        }
        $this->replaceUserMailWithTemplate();
        $this->emailTemplateUsed = TRUE;
        // recheck with the template email to make sure it doesn't also exist.
        if ($accountDuplicateMail = user_load_by_mail($this->ldapUser['mail'])) {
          $emailAvailable = FALSE;
        } else {
          $emailAvailable = TRUE;
        }
      }
      if (!$emailAvailable) {
        /**
         * Username does not exist but email does. Since
         * user_external_login_register does not deal with mail attribute and the
         * email conflict error needs to be caught beforehand, need to throw error
         * here.
         */
        \Drupal::logger('ldap_authentication')->error(
          'LDAP user with DN %dn has email address (%mail) conflict with a drupal user %duplicate_name', [
            '%dn' => $this->ldapUser['dn'],
            '%duplicate_name' => $accountDuplicateMail->getUsername(),
          ]
        );

        drupal_set_message(t(' Another user already exists in the system with the same email address. You should contact the system administrator in order to solve this conflict.'), 'error');
        return FALSE;
      }

    }

    // Do not provision Drupal account if provisioning disabled.
    if (!LdapConfiguration::provisionAvailableToDrupal(LdapConfiguration::$provisionDrupalUserOnAuthentication)) {
      \Drupal::logger('ldap_authentication')->error(
        'Drupal account for authname=%authname does not exist and provisioning of Drupal accounts on authentication is not enabled',
        ['%authname' => $this->authName]
      );
      return FALSE;
    }

    /**
     * New ldap_authentication provisioned account could let
     * user_external_login_register create the account and set authmaps, but
     * would need to add mail and any other user->data data in hook_user_presave
     * which would mean requerying LDAP or having a global variable. At this
     * point the account does not exist, so there is no reason not to create
     * it here.
     */

    if (\Drupal::config('ldapUser.settings')->get('acctCreation') == LdapConfiguration::$accountCreationUserSettingsForLdap &&
      \Drupal::config('user.settings')->get('register') == USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL
    ) {
      // If admin approval required, set status to 0.
      $user_values = ['name' => $this->drupalUserName, 'status' => 0];
    }
    else {
      $user_values = ['name' => $this->drupalUserName, 'status' => 1];
    }

    if ($this->emailTemplateUsed) {
      $user_values['mail'] = $this->ldapUser['mail'];
    }

    // Don't pass in LDAP user to provisionDrupalAccount, because want to
    // re-query with correct attributes needed this may be a case where
    // efficiency dictates querying for all attributes.
    $processor = new DrupalUserProcessor();
    $this->drupalUser = $processor->provisionDrupalAccount(NULL, $user_values, NULL, TRUE);

    if ($this->drupalUser  === FALSE) {
      \Drupal::logger('ldapUser')
        ->error('Failed to find or create %drupal_accountname on logon.', [
            '%drupal_accountname' => $this->drupalUserName,
          ]
        );
      $this->formState->setErrorByName('name', t(
          'Server Error: Failed to create Drupal user account for %drupal_accountname',
          ['%drupal_accountname' => $this->drupalUserName])
      );
      return FALSE;
    }
    return TRUE;
  }

  /**
   * @return bool
   */
  private function connectToServer() {
    $result = $this->serverDrupalUser->connect();
    if ($result != Server::LDAP_SUCCESS) {
      // self::AUTHENTICATION_FAILURE_CONNECTION
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')
          ->debug('%username: Failed connecting to %id.', [
              '%username' => $this->authName,
              '%id' => $this->serverDrupalUser->id(),
            ]
          );
      }
      // Next server, please.
      return FALSE;
    }
    elseif ($this->detailedLogging) {
      \Drupal::logger('ldap_authentication')
        ->debug('%username: Success at connecting to %id',
          [
            '%username' => $this->authName,
            '%id' => $this->serverDrupalUser->id(),
          ]);
    }
    return TRUE;
  }

  /**
   * @param $password
   * @return mixed
   */
  private function bindToServer($password) {
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
    if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodServiceAccount) {
      $bind_success = ($this->serverDrupalUser->bind(NULL, NULL, FALSE) == Server::LDAP_SUCCESS);
    }
    elseif ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnon ||
      $this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnonUser
    ) {
      $bind_success = ($this->serverDrupalUser->bind(NULL, NULL, TRUE) == Server::LDAP_SUCCESS);
    }
    elseif ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodUser) {
      // With sso enabled this method of binding isn't valid.
      foreach ($this->serverDrupalUser->getBaseDn() as $basedn) {
        $search = array('%basedn', '%username');
        $replace = array($basedn, $this->authName);
        $userdn = str_replace($search, $replace, $this->serverDrupalUser->get('user_dn_expression'));
        $bind_success = ($this->serverDrupalUser->bind($userdn, $password, FALSE) == Server::LDAP_SUCCESS);
        if ($bind_success) {
          break;
        }
      }
    }
    else {
      \Drupal::logger('ldap_authentication')
        ->debug('No bind method set in server->bind_method in ldap_authentication_user_login_authenticate_validate.');
    }

    if (!$bind_success) {
      if ($this->detailedLogging) {
        \Drupal::logger('ldap_authentication')
          ->debug('%username: Trying server %id where bind_method = %bind_method.  Error: %err_text', [
            '%username' => $this->authName,
            '%err_text' => $this->serverDrupalUser->errorMsg('ldap'),
            '%bind_method' => $this->serverDrupalUser->get('bind_method'),
          ]);
      }

      if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodUser) {
        return  self::AUTHENTICATION_FAILURE_CREDENTIALS;
      }
      else {
        return  self::AUTHENTICATION_FAILURE_BIND;

      }
    }
    return 'success';
  }

  /**
   * @return bool
   */
  private function bindToServerSSO() {
    $bind_success = FALSE;
    if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodServiceAccount) {
      $bind_success = ($this->serverDrupalUser->bind(NULL, NULL, FALSE) == Server::LDAP_SUCCESS);
    }
    elseif ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnon ||
      $this->serverDrupalUser->get('bind_method') == Server::$bindMethodAnonUser
    ) {
      $bind_success = ($this->serverDrupalUser->bind(NULL, NULL, TRUE) == Server::LDAP_SUCCESS);
    }
    else {
      \Drupal::logger('ldap_authentication')
        ->error('Trying to use SSO with user bind method.');
      \Drupal::logger('ldap_authentication')
        ->debug('No bind method set in ldap_server->bind_method in ldap_authentication_user_login_authenticate_validate.');
    }

    if (!$bind_success) {
      if ($this->detailedLogging) {
        $tokens['%err_text'] = $this->serverDrupalUser->errorMsg('ldap');
        \Drupal::logger('ldap_authentication')
          ->debug('%username: Trying server %id where bind_method = %bind_method.  Error: %err_text',
            [
              '%username' => $this->authName,
              '%bind_method' => $this->serverDrupalUser->get('bind_method'),
              '%err_text' => $this->serverDrupalUser->errorMsg('ldap'),
            ]
          );
        $tokens['%err_text'] = NULL;
      }
      if ($this->serverDrupalUser->get('bind_method') == Server::$bindMethodUser) {
        return self::AUTHENTICATION_FAILURE_CREDENTIALS;
      } else {
        return self::AUTHENTICATION_FAILURE_BIND;
      }
    }
    return 'success';
  }

}
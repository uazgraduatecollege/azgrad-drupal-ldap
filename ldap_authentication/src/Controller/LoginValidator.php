<?php

namespace Drupal\ldap_authentication\Controller;

use Drupal\Component\Utility\SafeMarkup;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\externalauth\Authmap;
use Drupal\ldap_authentication\Helper\LdapAuthenticationConfiguration;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\CredentialsStorage;
use Drupal\ldap_servers\LdapBridge;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\user\Entity\User;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Handles the actual testing of credentials and authentication of users.
 */
final class LoginValidator implements LdapUserAttributesInterface {

  use StringTranslationTrait;


  const AUTHENTICATION_FAILURE_BIND = 2;
  const AUTHENTICATION_FAILURE_FIND = 3;
  const AUTHENTICATION_FAILURE_DISALLOWED = 4;
  const AUTHENTICATION_FAILURE_CREDENTIALS = 5;
  const AUTHENTICATION_SUCCESS = 6;
  const AUTHENTICATION_FAILURE_SERVER = 8;

  protected $authName = FALSE;
  protected $ssoLogin = FALSE;

  protected $drupalUserAuthMapped = FALSE;
  protected $drupalUserName = FALSE;

  /**
   * The Server for the Drupal user.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  protected $serverDrupalUser;

  /**
   * The Drupal user.
   *
   * @var \Drupal\user\Entity\User
   */
  protected $drupalUser = FALSE;

  /**
   * @var \Symfony\Component\Ldap\Entry
   */
  protected $ldapEntry;

  protected $emailTemplateUsed = FALSE;
  protected $emailTemplateTokens = [];

  /**
   * @var \Drupal\Core\Form\FormState
   */
  protected $formState;

  protected $configFactory;
  protected $config;
  protected $detailLog;
  protected $logger;
  protected $entityTypeManager;
  protected $moduleHandler;
  protected $ldapBridge;
  protected $externalAuth;

  /**
   * Constructor.
   */
  public function __construct(ConfigFactoryInterface $configFactory, LdapDetailLog $detailLog, LoggerChannelInterface $logger, EntityTypeManager $entity_type_manager, ModuleHandler $module_handler, LdapBridge $ldap_bridge, Authmap $external_auth) {
    $this->configFactory = $configFactory;
    $this->config = $configFactory->get('ldap_authentication.settings');
    $this->detailLog = $detailLog;
    $this->logger = $logger;
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->ldapBridge = $ldap_bridge;
    $this->externalAuth = $external_auth;
  }

  /**
   * Starts login process.
   *
   * @param \Drupal\Core\Form\FormStateInterface $formState
   *   The form state.
   *
   * @return \Drupal\Core\Form\FormStateInterface
   *   The form state.
   */
  public function validateLogin(FormStateInterface $formState) {
    $this->authName = trim($formState->getValue('name'));
    $this->formState = $formState;

    $this->detailLog->log(
      '%auth_name : Beginning authentication',
      ['%auth_name' => $this->authName],
    'ldap_authentication'
    );

    $this->processLogin();

    return $this->formState;
  }

  /**
   * Perform the actual logging in.
   */
  private function processLogin() {
    if (!$this->ssoLogin && $this->userAlreadyAuthenticated()) {
      return;
    }

    if (!$this->validateCommonLoginConstraints()) {
      return;
    }

    $credentialsAuthenticationResult = $this->testCredentials();

    if ($credentialsAuthenticationResult == self::AUTHENTICATION_FAILURE_FIND &&
      $this->config->get('authenticationMode') == 'exclusive') {
      $this->formState->setErrorByName('non_ldap_login_not_allowed', $this->t('User disallowed'));
    }

    if ($credentialsAuthenticationResult != self::AUTHENTICATION_SUCCESS) {
      return;
    }

    if (!$this->deriveDrupalUserName()) {
      return;
    }

    // We now have an LDAP account, matching username and password and the
    // reference Drupal user.
    if (!$this->drupalUser && $this->serverDrupalUser) {
      $this->updateAuthNameFromPuid();
    }

    // Existing Drupal but not mapped to LDAP.
    if ($this->drupalUser && !$this->drupalUserAuthMapped) {
      if (!$this->matchExistingUserWithLdap()) {
        return;
      }
    }

    // Existing Drupal account with incorrect email. Fix email if appropriate.
    $this->fixOutdatedEmailAddress();

    // No existing Drupal account. Consider provisioning Drupal account.
    if (!$this->drupalUser) {
      if (!$this->provisionDrupalUser()) {
        return;
      }
    }

    // All passed, log the user in by handing over the UID.
    if (!$this->ssoLogin && $this->drupalUser) {
      $this->formState->set('uid', $this->drupalUser->id());
    }
  }

  /**
   * Processes an SSO login.
   *
   * @param string $authName
   *   The provided authentication name.
   */
  public function processSsoLogin($authName) {
    $this->authName = $authName;
    $this->ssoLogin = TRUE;
    $this->processLogin();
  }

  /**
   * Determine if the corresponding Drupal account exists and is mapped.
   *
   * Ideally we would only ask the external authmap but are allowing matching
   * by name, too, for association handling later.
   */
  private function initializeDrupalUserFromAuthName() {
    $this->drupalUser = user_load_by_name($this->authName);
    if (!$this->drupalUser) {
      $uid = $this->externalAuth->getUid($this->authName, 'ldap_user');
      if ($uid) {
        $this->drupalUser = $this->entityTypeManager->getStorage('user')->load($uid);
      }
    }
    if ($this->drupalUser) {
      $this->drupalUserAuthMapped = TRUE;
    }
  }

  /**
   * Verifies whether the user is available or can be created.
   *
   * @return bool
   *   Whether to allow user login.
   *
   * @TODO: This duplicates DrupalUserProcessor->excludeUser().
   */
  private function verifyUserAllowed() {
    if ($this->config->get('skipAdministrators')) {
      $admin_roles = $this->entityTypeManager
        ->getStorage('user_role')
        ->getQuery()
        ->condition('is_admin', TRUE)
        ->execute();
      if (!empty(array_intersect($this->drupalUser->getRoles(), $admin_roles))) {
        $this->detailLog->log(
          '%username: Drupal user name maps to an administrative user and this group is excluded from LDAP authentication.',
          ['%username' => $this->authName],
          'ldap_authentication'
        );
        return FALSE;
      }
    }

    // Exclude users who have been manually flagged as excluded.
    if ($this->drupalUser->get('ldap_user_ldap_exclude')->value == 1) {
      $this->detailLog->log(
        '%username: User flagged as excluded.',
        ['%username' => $this->authName],
        'ldap_authentication'
      );
      return FALSE;
    }

    // Everyone else is allowed.
    $this->detailLog->log(
      '%username: Drupal user account found. Continuing on to attempt LDAP authentication.',
      ['%username' => $this->authName],
      'ldap_authentication'
    );
    return TRUE;
  }

  /**
   * Verifies whether the user is available or can be created.
   *
   * @return bool
   *   Whether to allow user login and creation.
   */
  private function verifyAccountCreation() {
    $ldapUserConfig = $this->configFactory->get('ldap_user.settings');
    if ($ldapUserConfig->get('acctCreation') == self::ACCOUNT_CREATION_LDAP_BEHAVIOUR ||
      $ldapUserConfig->get('register') == USER_REGISTER_VISITORS) {
      $this->detailLog->log(
        '%username: Existing Drupal user account not found. Continuing on to attempt LDAP authentication', ['%username' => $this->authName],
        'ldap_authentication'
      );
      return TRUE;
    }
    else {
      $this->detailLog->log(
        '%username: Drupal user account not found and configuration is set to not create new accounts.',
        ['%username' => $this->authName],
        'ldap_authentication'
      );
      return FALSE;
    }
  }

  /**
   * Credentials are tested.
   *
   * @return int
   *   Returns the authentication result.
   */
  private function testCredentials() {
    foreach (LdapAuthenticationConfiguration::getEnabledAuthenticationServers() as $server) {
      $this->serverDrupalUser = Server::load($server);
      $this->ldapBridge->setServer($this->serverDrupalUser);
      $this->detailLog->log(
        '%username: Trying server %id with %bind_method', [
          '%username' => $this->authName,
          '%id' => $this->serverDrupalUser->id(),
          '%bind_method' => $this->serverDrupalUser->getFormattedBind(),
        ], 'ldap_authentication'
      );

      // TODO: Verify new usage of credentialsstorage here.
      $bindResult = $this->bindToServer();
      if ($bindResult !== TRUE) {
        $authenticationResult = $bindResult;
        // If bind fails, onto next server.
        continue;
      }

      // Check if user exists in LDAP.
      $this->ldapEntry = $this->serverDrupalUser->matchUsernameToExistingLdapEntry($this->authName);

      if (!$this->ldapEntry) {
        $authenticationResult = self::AUTHENTICATION_FAILURE_FIND;
        // Next server, please.
        continue;
      }

      if (!$this->checkAllowedExcluded($this->authName, $this->ldapEntry)) {
        $authenticationResult = self::AUTHENTICATION_FAILURE_DISALLOWED;
        // Regardless of how many servers, disallowed user fails.
        break;
      }

      if (!$this->ssoLogin && !$this->testUserPassword()) {
        $authenticationResult = self::AUTHENTICATION_FAILURE_CREDENTIALS;
        // Next server, please.
        continue;
      }
      else {
        $authenticationResult = self::AUTHENTICATION_SUCCESS;
        break;
      }
    }

    $this->detailLog->log(
      '%username: Authentication result is "%err_text"',
      [
        '%username' => $this->authName,
        '%err_text' => $this->authenticationHelpText($authenticationResult) . ' ' . $this->additionalDebuggingResponse($authenticationResult),
      ], 'ldap_authentication'
    );

    if (!$this->ssoLogin && $authenticationResult != self::AUTHENTICATION_SUCCESS) {
      $this->failureResponse($authenticationResult);
    }

    return $authenticationResult;
  }

  /**
   * Tests the user's password.
   *
   * @return bool
   *   Valid login.
   */
  private function testUserPassword() {
    $loginValid = FALSE;
    if ($this->serverDrupalUser->get('bind_method') == 'user') {
      $loginValid = TRUE;
    }
    else {
      $this->ldapBridge->setServer($this->serverDrupalUser);
      // TODO: Verify value in userPW, document!
      CredentialsStorage::storeUserDn($this->ldapEntry->getDn());
      CredentialsStorage::testCredentials(TRUE);
      $bindResult = $this->ldapBridge->bind();
      CredentialsStorage::testCredentials(FALSE);
      if ($bindResult) {
        $loginValid = TRUE;
      }
      else {
        $this->detailLog->log(
          '%username: Error testing user credentials on server %id with %bind_method.', [
            '%username' => $this->authName,
            '%bind_method' => $this->serverDrupalUser->getFormattedBind(),
            '%id' => $this->serverDrupalUser->id(),
          ], 'ldap_authentication'
        );
      }
    }
    return $loginValid;
  }

  /**
   * Provides formatting for authentication failures.
   *
   * @return string
   *   Response text.
   */
  private function additionalDebuggingResponse($authenticationResult) {
    $information = '';
    switch ($authenticationResult) {
      case self::AUTHENTICATION_FAILURE_FIND:
        $information = $this->t('(not found)');
        break;

      case self::AUTHENTICATION_FAILURE_CREDENTIALS:
        $information = $this->t('(wrong credentials)');
        break;
    }
    return $information;
  }

  /**
   * Failure response.
   *
   * @param int $authenticationResult
   *   The error code.
   */
  private function failureResponse($authenticationResult) {
    // Fail scenario 1. LDAP auth exclusive and failed  throw error so no other
    // authentication methods are allowed.
    if ($this->config->get('authenticationMode') == 'exclusive') {
      $this->detailLog->log(
        '%username: Error raised because failure at LDAP and exclusive authentication is set to true.',
        ['%username' => $this->authName], 'ldap_authentication'
      );

      drupal_set_message($this->t('Error: %err_text', ['%err_text' => $this->authenticationHelpText($authenticationResult)]), "error");
    }
    else {
      // Fail scenario 2.  Simply fails LDAP. Return false, but don't throw form
      // error don't show user message, may be using other authentication after
      // this that may succeed.
      $this->detailLog->log(
        '%username: Failed LDAP authentication. User may have authenticated successfully by other means in a mixed authentication site.',
        ['%username' => $this->authName],
        'ldap_authentication'
      );
    }
  }

  /**
   * Get human readable authentication error string.
   *
   * @param int $error
   *   Error code.
   *
   * @return string
   *   Human readable error text.
   */
  private function authenticationHelpText($error) {

    switch ($error) {
      case self::AUTHENTICATION_FAILURE_BIND:
        $msg = $this->t('Failed to bind to LDAP server');
        break;

      case self::AUTHENTICATION_FAILURE_DISALLOWED:
        $msg = $this->t('User disallowed');
        break;

      case self::AUTHENTICATION_FAILURE_FIND:
      case self::AUTHENTICATION_FAILURE_CREDENTIALS:
        $msg = $this->t('Sorry, unrecognized username or password.');
        break;

      case self::AUTHENTICATION_SUCCESS:
        $msg = $this->t('Authentication successful');
        break;

      default:
        $msg = $this->t('unknown error: @error', ['@error' => $error]);
        break;
    }

    return $msg;
  }

  /**
   * Check if exclusion criteria match.
   *
   * @param string $authName
   *   Authname.
   * @param \Symfony\Component\Ldap\Entry $ldap_user
   *   LDAP Entry.
   *
   * @return bool
   *   Exclusion result.
   */
  public function checkAllowedExcluded($authName, Entry $ldap_user) {

    // Do one of the exclude attribute pairs match? If user does not already
    // exists and deferring to user settings AND user settings only allow.
    foreach ($this->config->get('excludeIfTextInDn') as $test) {
      if (stripos($ldap_user->getDn(), $test) !== FALSE) {
        return FALSE;
      }
    }

    // Check if one of the allow attribute pairs match.
    if (count($this->config->get('allowOnlyIfTextInDn'))) {
      $fail = TRUE;
      foreach ($this->config->get('allowOnlyIfTextInDn') as $test) {
        if (stripos($ldap_user->getDn(), $test) !== FALSE) {
          $fail = FALSE;
        }
      }
      if ($fail) {
        return FALSE;
      }

    }

    // Handle excludeIfNoAuthorizations enabled and user has no groups.
    if ($this->moduleHandler->moduleExists('ldap_authorization') &&
      $this->config->get('excludeIfNoAuthorizations')) {

      $user = FALSE;
      $id = $this->externalAuth->getUid($authName, 'ldap_user');
      if ($id) {
        $user = $this->entityTypeManager->getStorage('user')->load($id);
      }

      if (!$user) {
        $user = User::create(['name' => $authName]);
      }

      // We are not injecting this service properly to avoid forcing this
      // dependency on authorization.
      /** @var \Drupal\authorization\AuthorizationController $controller */
      $controller = \Drupal::service('authorization.manager');
      $controller->setUser($user);

      $profiles = $this->entityTypeManager
        ->getStorage('authorization_profile')
        ->getQuery()
        ->condition('provider', 'ldap_provider')
        ->execute();
      foreach ($profiles as $profile) {
        $controller->queryIndividualProfile($profile);
      }
      $authorizations = $controller->getProcessedAuthorizations();
      $controller->clearAuthorizations();

      $valid_profile = FALSE;
      foreach ($authorizations as $authorization) {
        if (!empty($authorization->getAuthorizationsApplied())) {
          $valid_profile = TRUE;
        }
      }

      if (!$valid_profile) {
        drupal_set_message($this->t('The site logon is currently not working due to a configuration error. Please see logs for additional details.'), 'warning');
        $this->logger->notice('LDAP Authentication is configured to deny users without LDAP Authorization mappings, but 0 LDAP Authorization consumers are configured.');
        return FALSE;
      }

    }

    // Allow other modules to hook in and refuse if they like.
    $hook_result = TRUE;
    $this->moduleHandler->alter('ldap_authentication_allowuser_results', $ldap_user, $authName, $hook_result);

    if ($hook_result === FALSE) {
      $this->logger->notice('Authentication Allow User Result=refused for %name', ['%name' => $authName]);
      return FALSE;
    }

    // Default to allowed.
    return TRUE;
  }

  /**
   * Update an outdated email address.
   */
  private function fixOutdatedEmailAddress() {

    if ($this->config->get('emailTemplateUsageNeverUpdate') && $this->emailTemplateUsed) {
      return;
    }

    if (!$this->drupalUser) {
      return;
    }

    if ($this->drupalUser->get('mail')->value == $this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry)) {
      return;
    }

    if ($this->config->get('emailUpdate') == 'update_notify' || $this->config->get('emailUpdate') == 'update') {
      $this->drupalUser->set('mail', $this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry));
      if (!$this->drupalUser->save()) {
        $this->logger
          ->error('Failed to make changes to user %username updated %changed.', [
            '%username' => $this->drupalUser->getAccountName(),
            '%changed' => $this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry),
          ]
          );
      }
      else {
        if ($this->config->get('emailUpdate') == 'update_notify') {
          drupal_set_message($this->t(
            'Your e-mail has been updated to match your current account (%mail).',
            ['%mail' => $this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry)]),
            'status'
          );
        }
      }
    }
  }

  /**
   * Update the authName if it's no longer valid.
   *
   * Drupal account does not exist for authName used to logon, but puid exists
   * in another Drupal account; this means username has changed and needs to be
   * saved in Drupal account.
   */
  private function updateAuthNameFromPuid() {
    $puid = $this->serverDrupalUser->userPuidFromLdapEntry($this->ldapEntry);
    if ($puid) {
      $this->drupalUser = $this->serverDrupalUser->userAccountFromPuid($puid);
      /** @var \Drupal\user\Entity\User $userMatchingPuid */
      if ($this->drupalUser) {
        $oldName = $this->drupalUser->getAccountName();
        $this->drupalUser->setUsername($this->drupalUserName);
        $this->drupalUser->save();
        $this->externalAuth->save($this->drupalUser, 'ldap_user', $this->authName);
        $this->drupalUserAuthMapped = TRUE;
        drupal_set_message(
            $this->t('Your existing account %username has been updated to %new_username.',
              ['%username' => $oldName, '%new_username' => $this->drupalUserName]),
            'status');
      }
    }
  }

  /**
   * Validate already authenticated user.
   *
   * @return bool
   *   User already authenticated.
   */
  private function userAlreadyAuthenticated() {

    if (!empty($this->formState->get('uid'))) {
      if ($this->config->get('authenticationMode') == 'mixed') {
        $this->detailLog->log(
            '%username: Previously authenticated in mixed mode, pass on validation.',
            ['%username' => $this->authName],
            'ldap_authentication'
          );
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Validate common login constraints for user.
   *
   * @return bool
   *   Continue authentication.
   */
  private function validateCommonLoginConstraints() {

    // Check that enabled servers are available.
    if (count(LdapAuthenticationConfiguration::getEnabledAuthenticationServers()) == 0) {
      $this->logger->error('No LDAP servers configured.');
      if ($this->formState) {
        $this->formState->setErrorByName('name', 'Server Error:  No LDAP servers configured.');
      }
      return FALSE;
    }

    $this->initializeDrupalUserFromAuthName();

    if ($this->drupalUser) {
      $result = $this->verifyUserAllowed();
    }
    else {
      $result = $this->verifyAccountCreation();
    }
    return $result;
  }

  /**
   * Derives the Drupal user name from server configuration.
   *
   * @return bool
   *   Success of deriving Drupal user name.
   */
  private function deriveDrupalUserName() {
    // If account_name_attr is set, Drupal username is different than authName.
    if (!empty($this->serverDrupalUser->get('account_name_attr'))) {
      $user_attribute = mb_strtolower($this->serverDrupalUser->get('account_name_attr'));
      $user_name_from_attribute = $this->ldapEntry->getAttribute($user_attribute)[0];
      if (!$user_name_from_attribute) {
        $this->logger
          ->error('Derived Drupal username from attribute %account_name_attr returned no username for authname %authname.', [
            '%authname' => $this->authName,
            '%account_name_attr' => $this->serverDrupalUser->get('account_name_attr'),
          ]
          );
        return FALSE;
      }
      else {
        $this->drupalUserName = $user_name_from_attribute;
      }
    }
    else {
      $this->drupalUserName = $this->authName;
    }
    $this->prepareEmailTemplateToken();

    return TRUE;
  }

  /**
   * Prepare the email template token.
   */
  private function prepareEmailTemplateToken() {
    $this->emailTemplateTokens = ['@username' => $this->drupalUserName];

    if (!empty($this->config->get('emailTemplate'))) {
      $handling = $this->config->get('emailTemplateHandling');
      if (($handling == 'if_empty' && empty($this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry))) || $handling == 'always') {
        $this->replaceUserMailWithTemplate();
        $this->detailLog->log(
          'Using template generated email for %username',
          ['%username' => $this->drupalUserName],
          'ldap_authentication'
        );

        $this->emailTemplateUsed = TRUE;
      }
    }
  }

  /**
   * Match existing user with LDAP.
   *
   * @return bool
   *   User matched.
   */
  private function matchExistingUserWithLdap() {
    if ($this->configFactory->get('ldap_user.settings')->get('userConflictResolve') == self::USER_CONFLICT_LOG) {
      if ($account_with_same_email = user_load_by_mail($this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry))) {
        /** @var \Drupal\user\UserInterface $account_with_same_email */
        $this->logger
          ->error('LDAP user with DN %dn has a naming conflict with a local Drupal user %conflict_name',
            [
              '%dn' => $this->ldapEntry->getDn(),
              '%conflict_name' => $account_with_same_email->getAccountName(),
            ]
          );
      }
      drupal_set_message($this->t('Another user already exists in the system with the same login name. You should contact the system administrator in order to solve this conflict.'), 'error');
      return FALSE;
    }
    else {
      $this->externalAuth->save($this->drupalUser, 'ldap_user', $this->authName);
      $this->drupalUserAuthMapped = TRUE;
      $this->detailLog->log(
        'Set authmap for LDAP user %username',
        ['%username' => $this->authName],
        'ldap_authentication'
      );
    }
    return TRUE;
  }

  /**
   * Replace user email address with template.
   */
  private function replaceUserMailWithTemplate() {
    // Fallback template in case one was not specified.
    $template = '@username@localhost';
    if (!empty($this->config->get('emailTemplate'))) {
      $template = $this->config->get('emailTemplate');
    }
    $this->ldapEntry->setAttribute($this->serverDrupalUser->get('mail_attr'), [SafeMarkup::format($template, $this->emailTemplateTokens)->__toString()]);
  }

  /**
   * Provision the Drupal user.
   *
   * @return bool
   *   Provisioning successful.
   */
  private function provisionDrupalUser() {

    // Do not provision Drupal account if another account has same email.
    if ($accountDuplicateMail = user_load_by_mail($this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry))) {
      $emailAvailable = FALSE;
      if ($this->config->get('emailTemplateUsageResolveConflict') && (!$this->emailTemplateUsed)) {
        $this->detailLog->log(
          'Conflict detected, using template generated email for %username',
          ['%duplicate_name' => $accountDuplicateMail->getAccountName()],
          'ldap_authentication'
        );

        $this->replaceUserMailWithTemplate();
        $this->emailTemplateUsed = TRUE;
        // Recheck with the template email to make sure it doesn't also exist.
        if ($accountDuplicateMail = user_load_by_mail($this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry))) {
          $emailAvailable = FALSE;
        }
        else {
          $emailAvailable = TRUE;
        }
      }
      if (!$emailAvailable) {
        /*
         * Username does not exist but email does. Since
         * user_external_login_register does not deal with mail attribute and
         * the email conflict error needs to be caught beforehand, need to throw
         * error here.
         */
        $this->logger->error(
          'LDAP user with DN %dn has email address (%mail) conflict with a Drupal user %duplicate_name', [
            '%dn' => $this->ldapEntry->getDn(),
            '%duplicate_name' => $accountDuplicateMail->getAccountName(),
          ]
        );

        drupal_set_message($this->t('Another user already exists in the system with the same email address. You should contact the system administrator in order to solve this conflict.'), 'error');
        return FALSE;
      }

    }

    // Do not provision Drupal account if provisioning disabled.
    if (!LdapConfiguration::provisionAvailableToDrupal(self::PROVISION_DRUPAL_USER_ON_USER_AUTHENTICATION)) {
      $this->logger->error(
        'Drupal account for authname=%authname does not exist and provisioning of Drupal accounts on authentication is not enabled',
        ['%authname' => $this->authName]
      );
      return FALSE;
    }

    /*
     * New ldap_authentication provisioned account could let
     * user_external_login_register create the account and set authmaps, but
     * would need to add mail and any other user->data data in hook_user_presave
     * which would mean requerying LDAP or having a global variable. At this
     * point the account does not exist, so there is no reason not to create
     * it here.
     */

    if ($this->configFactory->get('ldap_user.settings')->get('acctCreation') == self::ACCOUNT_CREATION_USER_SETTINGS_FOR_LDAP &&
      $this->configFactory->get('user.settings')->get('register') == USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL
    ) {
      // If admin approval required, set status to 0.
      $user_values = ['name' => $this->drupalUserName, 'status' => 0];
    }
    else {
      $user_values = ['name' => $this->drupalUserName, 'status' => 1];
    }

    if ($this->emailTemplateUsed) {
      $user_values['mail'] = $this->serverDrupalUser->userEmailFromLdapEntry($this->ldapEntry);
    }

    // TODO: DI.
    $processor = \Drupal::service('ldap.drupal_user_processor');
    $result = $processor->provisionDrupalAccount($user_values);

    if (!$result) {
      $this->logger->error(
        'Failed to find or create %drupal_accountname on logon.',
        ['%drupal_accountname' => $this->drupalUserName]
        );
      $this->formState->setErrorByName('name', $this->t(
          'Server Error: Failed to create Drupal user account for %drupal_accountname',
          ['%drupal_accountname' => $this->drupalUserName])
      );
      return FALSE;
    }
    else {
      $this->drupalUser = $processor->getUserAccount();
      return TRUE;
    }
  }

  /**
   * Bind to server.
   *
   * @return int|true
   *   Success or failure result.
   */
  private function bindToServer() {
    if ($this->serverDrupalUser->get('bind_method') == 'user') {
      return $this->bindToServerAsUser();
    }

    $bindResult = $this->ldapBridge->bind();

    if (!$bindResult) {
      $this->detailLog->log(
        '%username: Unsuccessful with server %id (bind method: %bind_method)', [
          '%username' => $this->authName,
          '%id' => $this->serverDrupalUser->id(),
          '%bind_method' => $this->serverDrupalUser->get('bind_method'),
        ], 'ldap_authentication'
      );

      return self::AUTHENTICATION_FAILURE_BIND;
    }
    return TRUE;
  }

  /**
   * Bind to server.
   *
   * @return int|true
   *   Success or failure result.
   */
  private function bindToServerAsUser() {
    $bindResult = FALSE;

    if ($this->ssoLogin) {
      $this->logger->error('Trying to use SSO with user bind method.');
      return self::AUTHENTICATION_FAILURE_CREDENTIALS;
    }

    foreach ($this->serverDrupalUser->getBaseDn() as $base_dn) {
      $search = ['%basedn', '%username'];
      $replace = [$base_dn, $this->authName];
      CredentialsStorage::storeUserDn(str_replace($search, $replace, $this->serverDrupalUser->get('user_dn_expression')));
      CredentialsStorage::testCredentials(TRUE);
      $bindResult = $this->ldapBridge->bind();
      if ($bindResult) {
        break;
      }
    }

    if (!$bindResult) {
      $this->detailLog->log(
        '%username: Unsuccessful with server %id (bind method: %bind_method)', [
          '%username' => $this->authName,
          '%id' => $this->serverDrupalUser->id(),
          '%bind_method' => $this->serverDrupalUser->get('bind_method'),
        ], 'ldap_authentication'
      );

      return self::AUTHENTICATION_FAILURE_CREDENTIALS;
    }
    return TRUE;
  }

  /**
   * Returns the derived user account.
   *
   * @return \Drupal\user\Entity\User
   *   User account.
   */
  public function getDrupalUser() {
    return $this->drupalUser;
  }

}

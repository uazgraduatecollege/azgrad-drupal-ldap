<?php

namespace Drupal\ldap_authentication\Controller;

use Drupal\Component\Utility\SafeMarkup;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\externalauth\Authmap;
use Drupal\ldap_authentication\AuthenticationServers;
use Drupal\ldap_servers\Helper\CredentialsStorage;
use Drupal\ldap_servers\LdapBridge;
use Drupal\ldap_servers\LdapUserManager;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Handles the actual testing of credentials and authentication of users.
 */
abstract class LoginValidatorBase implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  const AUTHENTICATION_FAILURE_BIND = 2;
  const AUTHENTICATION_FAILURE_FIND = 3;
  const AUTHENTICATION_FAILURE_DISALLOWED = 4;
  const AUTHENTICATION_FAILURE_CREDENTIALS = 5;
  const AUTHENTICATION_SUCCESS = 6;
  const AUTHENTICATION_FAILURE_SERVER = 8;

  protected $authName = FALSE;

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
   * LDAP Entry.
   *
   * @var \Symfony\Component\Ldap\Entry
   */
  protected $ldapEntry;

  protected $emailTemplateUsed = FALSE;
  protected $emailTemplateTokens = [];

  /**
   * Form State.
   *
   * @var \Drupal\Core\Form\FormState
   *
   * @TODO: Try to push this up into LoginValidatorLoginForm
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
  protected $authenticationServers;
  protected $ldapUserManager;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   * @param \Drupal\ldap_servers\Logger\LdapDetailLog $detailLog
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   * @param \Drupal\Core\Entity\EntityTypeManager $entity_type_manager
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   * @param \Drupal\ldap_servers\LdapBridge $ldap_bridge
   * @param \Drupal\externalauth\Authmap $external_auth
   * @param \Drupal\ldap_authentication\AuthenticationServers $authentication_servers
   * @param \Drupal\ldap_servers\LdapUserManager $ldap_user_manager
   */
  public function __construct(
    ConfigFactoryInterface $configFactory,
    LdapDetailLog $detailLog,
    LoggerChannelInterface $logger,
    EntityTypeManager $entity_type_manager,
    ModuleHandler $module_handler,
    LdapBridge $ldap_bridge,
    Authmap $external_auth,
    AuthenticationServers $authentication_servers,
    LdapUserManager $ldap_user_manager
  ) {
    $this->configFactory = $configFactory;
    $this->config = $configFactory->get('ldap_authentication.settings');
    $this->detailLog = $detailLog;
    $this->logger = $logger;
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->ldapBridge = $ldap_bridge;
    $this->externalAuth = $external_auth;
    $this->authenticationServers = $authentication_servers;
    $this->ldapUserManager = $ldap_user_manager;
  }

  /**
   * Starts login process.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return \Drupal\Core\Form\FormStateInterface
   *   The form state.
   */
  public function validateLogin(FormStateInterface $form_state) {
    $this->authName = trim($form_state->getValue('name'));
    $this->formState = $form_state;

    $this->detailLog->log(
      '%auth_name : Beginning authentication',
      ['%auth_name' => $this->authName],
    'ldap_authentication'
    );

    $this->processLogin();

    return $this->formState;
  }

  /**
   * Determine if the corresponding Drupal account exists and is mapped.
   *
   * Ideally we would only ask the external authmap but are allowing matching
   * by name, too, for association handling later.
   */
  protected function initializeDrupalUserFromAuthName() {
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
  protected function verifyUserAllowed() {
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
  protected function verifyAccountCreation() {
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
   * Tests the user's password.
   *
   * @return bool
   *   Valid login.
   */
  protected function testUserPassword() {
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
  protected function additionalDebuggingResponse($authenticationResult) {
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
  protected function failureResponse($authenticationResult) {
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
  protected function authenticationHelpText($error) {

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
        $user = $this->entityTypeManager->getStorage('user')->create(['name' => $authName]);
      }

      // We are not injecting this service properly to avoid forcing this
      // dependency on authorization.
      /** @var \Drupal\authorization\AuthorizationController $controller */
      // @codingStandardsIgnoreLine
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
  protected function fixOutdatedEmailAddress() {

    if ($this->config->get('emailTemplateUsageNeverUpdate') && $this->emailTemplateUsed) {
      return;
    }

    if (!$this->drupalUser) {
      return;
    }

    if ($this->drupalUser->get('mail')->value == $this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry)) {
      return;
    }

    if ($this->config->get('emailUpdate') == 'update_notify' || $this->config->get('emailUpdate') == 'update') {
      $this->drupalUser->set('mail', $this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry));
      if (!$this->drupalUser->save()) {
        $this->logger
          ->error('Failed to make changes to user %username updated %changed.', [
            '%username' => $this->drupalUser->getAccountName(),
            '%changed' => $this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry),
          ]
          );
      }
      else {
        if ($this->config->get('emailUpdate') == 'update_notify') {
          drupal_set_message($this->t(
            'Your e-mail has been updated to match your current account (%mail).',
            ['%mail' => $this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry)]),
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
  protected function updateAuthNameFromPuid() {
    $puid = $this->serverDrupalUser->derivePuidFromLdapResponse($this->ldapEntry);
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
   * Validate common login constraints for user.
   *
   * @return bool
   *   Continue authentication.
   */
  protected function validateCommonLoginConstraints() {

    if (!$this->authenticationServers->authenticationServersAvailable()) {
      $this->logger->error('No LDAP servers configured for authentication.');
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
  protected function deriveDrupalUserName() {
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
  protected function prepareEmailTemplateToken() {
    $this->emailTemplateTokens = ['@username' => $this->drupalUserName];

    if (!empty($this->config->get('emailTemplate'))) {
      $handling = $this->config->get('emailTemplateHandling');
      if (($handling == 'if_empty' && empty($this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry))) || $handling == 'always') {
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
  protected function matchExistingUserWithLdap() {
    if ($this->configFactory->get('ldap_user.settings')->get('userConflictResolve') == self::USER_CONFLICT_LOG) {
      if ($account_with_same_email = user_load_by_mail($this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry))) {
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
  protected function replaceUserMailWithTemplate() {
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
  protected function provisionDrupalUser() {

    // Do not provision Drupal account if another account has same email.
    if ($accountDuplicateMail = user_load_by_mail($this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry))) {
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
        if ($accountDuplicateMail = user_load_by_mail($this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry))) {
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
    $triggers = $this->config->get('ldap_user.settings')->get('drupalAcctProvisionTriggers');
    if (!in_array(self::PROVISION_DRUPAL_USER_ON_USER_AUTHENTICATION, $triggers)) {
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
      $user_values['mail'] = $this->serverDrupalUser->deriveEmailFromLdapResponse($this->ldapEntry);
    }

    // TODO: DI.
    /** @var \Drupal\ldap_user\Processor\DrupalUserProcessor $processor */
    $processor = \Drupal::service('ldap.drupal_user_processor');
    $result = $processor->createDrupalUserFromLdapEntry($user_values);

    if (!$result) {
      $this->logger->error(
        'Failed to find or create %drupal_accountname on logon.',
        ['%drupal_accountname' => $this->drupalUserName]
        );
      if ($this->formState) {
        $this->formState->setErrorByName('name', $this->t(
          'Server Error: Failed to create Drupal user account for %drupal_accountname',
          ['%drupal_accountname' => $this->drupalUserName])
        );
      }
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
  protected function bindToServer() {
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
  protected function bindToServerAsUser() {
    $bindResult = FALSE;

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
<?php

namespace Drupal\ldap_user\Processor;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\File\FileSystem;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\externalauth\Authmap;
use Drupal\file\Entity\File;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SemaphoreStorage;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\Core\Utility\Token;
use Drupal\user\UserInterface;

/**
 * Handles processing of a user from LDAP to Drupal.
 */
class DrupalUserProcessor implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  protected $logger;
  protected $config;
  protected $configAuthentication;
  protected $factory;
  protected $detailLog;
  protected $tokenProcessor;
  protected $externalAuth;
  protected $entityTypeManager;
  protected $ldapUserProcessor;
  protected $fileSystem;
  protected $token;
  protected $moduleHandler;
  protected $currentUser;
  protected $syncMapper;

  /**
   * The Drupal user account.
   *
   * @var \Drupal\user\Entity\User
   */
  private $account;

  /**
   * @var \Symfony\Component\Ldap\Entry
   */
  private $ldapEntry;

  /**
   * The server interacting with.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  private $server;

  /**
   * Constructor.
   *
   * TODO: Make this service smaller.
   * (The number of dependencies alone makes this clear.)
   */
  public function __construct(LoggerChannelInterface $logger, ConfigFactory $config_factory, LdapDetailLog $detail_log, TokenProcessor $token_processor, ServerFactory $server_factory, Authmap $authmap, EntityTypeManager $entity_type_manager, LdapUserProcessor $ldap_user_processor, FileSystem $file_system, Token $token, ModuleHandler $module_handler, AccountInterface $current_user, SyncMappingHelper $sync_mapper) {
    $this->logger = $logger;
    $this->config = $config_factory->get('ldap_user.settings');
    $this->configAuthentication = $config_factory->get('ldap_authentication.settings');
    $this->detailLog = $detail_log;
    $this->tokenProcessor = $token_processor;
    $this->factory = $server_factory;
    $this->externalAuth = $authmap;
    $this->entityTypeManager = $entity_type_manager;
    // TODO: Improve class structure.
    // Depending on this processor within the other shows bad abstraction.
    $this->ldapUserProcessor = $ldap_user_processor;
    $this->fileSystem = $file_system;
    $this->token = $token;
    $this->moduleHandler = $module_handler;
    $this->currentUser = $current_user;
    $this->syncMapper = $sync_mapper;
  }

  /**
   * Check if user is excluded.
   *
   * @param \Drupal\user\UserInterface $account
   *   A Drupal user object.
   *
   * @return bool
   *   TRUE if user should be excluded from LDAP provision/syncing
   */
  public function excludeUser(UserInterface $account = NULL) {

    if ($this->configAuthentication->get('skipAdministrators')) {
      $admin_roles = $this->entityTypeManager
        ->getStorage('user_role')
        ->getQuery()
        ->condition('is_admin', TRUE)
        ->execute();
      if (!empty(array_intersect($account->getRoles(), $admin_roles))) {
        return TRUE;
      }
    }

    // Exclude users who have been manually flagged as excluded.
    if ($account->get('ldap_user_ldap_exclude')->value == 1) {
      return TRUE;
    }

    // Everyone else is fine.
    return FALSE;
  }

  /**
   * Get the user account.
   *
   * @return \Drupal\user\Entity\User
   *   User account.
   */
  public function getUserAccount() {
    return $this->account;
  }

  /**
   * Set LDAP associations of a Drupal account by altering user fields.
   *
   * @param string $drupalUsername
   *   The Drupal username.
   *
   * @return bool
   *   Returns FALSE on invalid user or LDAP accounts.
   */
  public function ldapAssociateDrupalAccount($drupalUsername) {
    if ($this->config->get('drupalAcctProvisionServer')) {

      $ldapServer = $this->entityTypeManager
        ->getStorage('ldap_server')
        ->load($this->config->get('drupalAcctProvisionServer'));
      $this->account = user_load_by_name($drupalUsername);
      if (!$this->account) {
        $this->logger->error('Failed to LDAP associate Drupal account %drupal_username because account not found', ['%drupal_username' => $drupalUsername]);
        return FALSE;
      }

      $this->ldapEntry = $ldapServer->matchUsernameToExistingLdapEntry($drupalUsername);
      if (!$this->ldapEntry) {
        $this->logger->error('Failed to LDAP associate Drupal account %drupal_username because corresponding LDAP entry not found', ['%drupal_username' => $drupalUsername]);
        return FALSE;
      }

      $persistentUid = $ldapServer->derivePuidFromLdapResponse($this->ldapEntry);
      if ($persistentUid) {
        $this->account->set('ldap_user_puid', $persistentUid);
      }
      $this->account->set('ldap_user_puid_property', $ldapServer->get('unique_persistent_attr'));
      $this->account->set('ldap_user_puid_sid', $ldapServer->id());
      $this->account->set('ldap_user_current_dn', $this->ldapEntry->getDn());
      $this->account->set('ldap_user_last_checked', time());
      $this->account->set('ldap_user_ldap_exclude', 0);
      $this->saveAccount();

      $this->syncToDrupalAccount(self::EVENT_CREATE_DRUPAL_USER);

      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Provision a Drupal user account.
   *
   * Given user data, create a user and apply LDAP attributes or assign to
   * correct user if name has changed through PUID.
   *
   * @param array $userData
   *   A keyed array normally containing 'name' and optionally more.
   *
   * @return bool|\Drupal\user\Entity\User
   *   Return the user on success or FALSE on any problem.
   */
  public function provisionDrupalAccount(array $userData) {

    $this->account = $this->entityTypeManager->getStorage('user')->create($userData);

    // Get an LDAP user from the LDAP server.
    if ($this->config->get('drupalAcctProvisionServer')) {
      $this->ldapEntry = $this->factory->getUserDataFromServerByIdentifier($userData['name'], $this->config->get('drupalAcctProvisionServer'));
    }
    // Still no LDAP user.
    if (!$this->ldapEntry) {
      $this->detailLog->log(
        '@username: Failed to find associated LDAP entry for username in provision.',
        ['@username' => $userData['name']],
        'ldap-user'
      );
      return FALSE;
    }

    $this->server = $this->entityTypeManager
      ->getStorage('ldap_server')
      ->load($this->config->get('drupalAcctProvisionServer'));

    // If we don't have an account name already we should set one.
    if (!$this->account->getAccountName()) {
      $this->account->set('name', $this->ldapEntry->getAttribute($this->server->get('user_attr'))[0]);
    }

    // Can we get details from an LDAP server?
    $params = [
      'account' => $this->account,
      'user_values' => $userData,
      'prov_event' => self::EVENT_CREATE_DRUPAL_USER,
      'module' => 'ldap_user',
      'function' => 'provisionDrupalAccount',
      'direction' => self::PROVISION_TO_DRUPAL,
    ];

    $this->moduleHandler->alter('ldap_entry', $this->ldapEntry, $params);

    // Look for existing Drupal account with the same PUID. If found, update
    // that user instead of creating a new user.
    $persistentUid = $this->server->derivePuidFromLdapResponse($this->ldapEntry);
    $accountFromPuid = ($persistentUid) ? $this->server->userAccountFromPuid($persistentUid) : FALSE;
    if ($accountFromPuid) {
      $this->updateExistingAccountByPersistentUid($accountFromPuid);
    }
    else {
      $this->createDrupalUser();
    }
    return TRUE;
  }

  /**
   * Set flag to exclude user from LDAP association.
   *
   * @param string $drupalUsername
   *   The account username.
   *
   * @return bool
   *   TRUE on success, FALSE on error or failure because of invalid user.
   */
  public function ldapExcludeDrupalAccount($drupalUsername) {
    $account = $this->entityTypeManager->getStorage('user')->load($drupalUsername);
    if (!$account) {
      $this->logger->error('Failed to exclude user from LDAP association because Drupal account %username was not found', ['%username' => $drupalUsername]);
      return FALSE;
    }

    $account->set('ldap_user_ldap_exclude', 1);
    $account->save();
    return (boolean) $account;
  }

  /**
   * Test if the user is LDAP associated.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   *
   * @return bool
   *   Whether the user is LDAP associated.
   */
  public function isUserLdapAssociated(UserInterface $account) {

    $associated = FALSE;

    if (property_exists($account, 'ldap_user_current_dn') &&
      !empty($account->get('ldap_user_current_dn')->value)) {
      $associated = TRUE;
    }
    elseif ($account->id()) {
      if ($this->externalAuth->get($account->id(), 'ldap_user')) {
        $associated = TRUE;
      }
    }

    return $associated;
  }

  /**
   * Callback for hook_ENTITY_TYPE_insert().
   *
   * Perform any actions required, due to possibly not being the module creating
   * the user.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   */
  public function newDrupalUserCreated(UserInterface $account) {
    $this->account = $account;

    if ($this->excludeUser($account)) {
      return;
    }

    if (is_object($account) && $account->getAccountName()) {
      // Check for first time user.
      if (SemaphoreStorage::get('provision', $account->getAccountName())
        || SemaphoreStorage::get('sync', $account->getAccountName())
        || $this->newAccountRequest($account)) {
        return;
      }
    }

    // The account is already created, so do not provisionDrupalAccount(), just
    // syncToDrupalAccount(), even if action is 'provision'.
    if ($account->isActive() && LdapConfiguration::provisionAvailableToDrupal(self::PROVISION_DRUPAL_USER_ON_USER_UPDATE_CREATE)) {
      $this->syncToDrupalAccount(self::EVENT_CREATE_DRUPAL_USER);
    }

    $this->provisionLdapEntryOnUserCreation($account);
  }

  /**
   * Callback for hook_ENTITY_TYPE_update().
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   */
  public function drupalUserUpdated(UserInterface $account) {
    // For some reason cloning was only necessary on the update hook.
    $this->account = clone $account;
    if ($this->excludeUser($this->account)) {
      return;
    }

    // Check for provisioning to LDAP; this will normally occur on
    // hook_user_insert or other event when Drupal user is created.
    if ($this->provisionsLdapEntriesFromDrupalUsers() && LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE)) {
      $this->provisionLdapEntryOnUserUpdateCreateEvent();
    }

    if (SemaphoreStorage::get('sync_drupal', $this->account->getAccountName())) {
      return;
    }
    else {
      SemaphoreStorage::set('sync_drupal', $this->account->getAccountName());
      if (LdapConfiguration::provisionsDrupalAccountsFromLdap() && in_array(self::EVENT_SYNC_TO_DRUPAL_USER, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
        $this->syncToDrupalAccount(self::EVENT_SYNC_TO_DRUPAL_USER);
      }
    }
  }

  /**
   * Handle Drupal user login.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   */
  public function drupalUserLogsIn(UserInterface $account) {
    $this->account = $account;
    if ($this->excludeUser($this->account)) {
      return;
    }

    $this->loginDrupalAccountProvisioning();
    $this->loginLdapEntryProvisioning();
  }

  /**
   * Handle deletion of Drupal user.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user account.
   */
  public function drupalUserDeleted(UserInterface $account) {
    // Drupal user account is about to be deleted.
    $this->deleteProvisionedLdapEntry($account);
    $this->externalAuth->delete($account->id());
  }

  /**
   * Create a Drupal user.
   *
   * @param array $this->ldapEntry
   *   The LDAP user.
   */
  private function createDrupalUser() {
    $this->account->enforceIsNew();
    $this->applyAttributesToAccount(self::PROVISION_TO_DRUPAL, [self::EVENT_CREATE_DRUPAL_USER]);
    $tokens = ['%drupal_username' => $this->account->getAccountName()];
    if (empty($this->account->getAccountName())) {
      drupal_set_message($this->t('User account creation failed because of invalid, empty derived Drupal username.'), 'error');
      $this->logger
        ->error('Failed to create Drupal account %drupal_username because Drupal username could not be derived.', $tokens);
      return FALSE;
    }
    if (!$mail = $this->account->getEmail()) {
      drupal_set_message($this->t('User account creation failed because of invalid, empty derived email address.'), 'error');
      $this->logger
        ->error('Failed to create Drupal account %drupal_username because email address could not be derived by LDAP User module', $tokens);
      return FALSE;
    }

    if ($account_with_same_email = user_load_by_mail($mail)) {
      $this->logger
        ->error('LDAP user %drupal_username has email address (%email) conflict with a Drupal user %duplicate_name', [
          '%drupal_username' => $this->account->getAccountName(),
          '%email' => $mail,
          '%duplicate_name' => $account_with_same_email->getAccountName(),
        ]
      );
      drupal_set_message($this->t('Another user already exists in the system with the same email address. You should contact the system administrator in order to solve this conflict.'), 'error');
      return FALSE;
    }
    $this->saveAccount();
    if (!$this->account) {
      drupal_set_message($this->t('User account creation failed because of system problems.'), 'error');
    }
    else {
      $this->externalAuth->save($this->account, 'ldap_user', $this->account->getAccountName());
    }
  }

  /**
   * Update Drupal user from PUID.
   *
   * @param \Drupal\user\UserInterface $accountFromPuid
   *   The account from the PUID.
   */
  private function updateExistingAccountByPersistentUid(UserInterface $accountFromPuid) {
    $this->account = $accountFromPuid;
    $this->externalAuth->save($this->account, 'ldap_user', $this->account->getAccountName());
    $this->syncToDrupalAccount(self::EVENT_SYNC_TO_DRUPAL_USER);
  }

  /**
   * Process user picture from LDAP entry.
   *
   * @return false|\Drupal\file\Entity\File
   *   Drupal file object image user's thumbnail or FALSE if none present or
   *   an error occurs.
   */
  private function userPictureFromLdapEntry() {
    $picture_attribute = $this->server->get('picture_attr');
    if ($this->ldapEntry && $picture_attribute) {
      // Check if LDAP entry has been provisioned.
      if ($this->ldapEntry->hasAttribute($picture_attribute)) {
        $ldapUserPicture = $this->ldapEntry->getAttribute($picture_attribute)[0];
      }
      else {
        // No picture present.
        return FALSE;
      }

      $currentUserPicture = $this->account->get('user_picture')->getValue();
      if (empty($currentUserPicture)) {
        return $this->saveUserPicture($this->account->get('user_picture'), $ldapUserPicture);
      }
      else {
        $file = File::load($currentUserPicture[0]['target_id']);
        if ($file && md5(file_get_contents($file->getFileUri())) == md5($ldapUserPicture)) {
          // Same image, do nothing.
          return FALSE;
        }
        else {
          return $this->saveUserPicture($this->account->get('user_picture'), $ldapUserPicture);
        }
      }
    }
  }

  /**
   * Save the user's picture.
   *
   * @param \Drupal\Core\Field\FieldItemListInterface $field
   *   The field attached to the user.
   * @param string $ldapUserPicture
   *   The picture itself.
   *
   * @return array|bool
   *   Returns file ID wrapped in target or false.
   */
  private function saveUserPicture(FieldItemListInterface $field, $ldapUserPicture) {
    // Create tmp file to get image format and derive extension.
    $fileName = uniqid();
    $unmanagedFile = file_directory_temp() . '/' . $fileName;
    file_put_contents($unmanagedFile, $ldapUserPicture);
    $image_type = exif_imagetype($unmanagedFile);
    $extension = image_type_to_extension($image_type, FALSE);
    unlink($unmanagedFile);

    $fieldSettings = $field->getFieldDefinition()->getItemDefinition()->getSettings();
    $directory = $this->token->replace($fieldSettings['file_directory']);
    $fullDirectoryPath = $fieldSettings['uri_scheme'] . '://' . $directory;

    if (!is_dir($this->fileSystem->realpath($fullDirectoryPath))) {
      $this->fileSystem->mkdir($fullDirectoryPath, NULL, TRUE);
    }

    $managed_file = file_save_data($ldapUserPicture, $fullDirectoryPath . '/' . $fileName . '.' . $extension);

    $validators = [
      'file_validate_is_image' => [],
      'file_validate_image_resolution' => [$fieldSettings['max_resolution']],
      'file_validate_size' => [$fieldSettings['max_filesize']],
    ];

    $errors = file_validate($managed_file, $validators);
    if ($managed_file && empty(file_validate($managed_file, $validators))) {
      return ['target_id' => $managed_file->id()];
    }
    else {
      // Todo: Verify file garbage collection.
      foreach ($errors as $error) {
        $this->detailLog
          ->log('File upload error for user image with validation error @error',
            ['@error' => $error]
          );
      }

      return FALSE;
    }
  }

  /**
   * TODO: Remove redundancy in LdapConfiguration.
   */
  private function provisionsLdapEntriesFromDrupalUsers() {
    if ($this->config->get('ldapEntryProvisionServer') &&
      count(array_filter(array_values($this->config->get('ldapEntryProvisionTriggers')))) > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Handle account deletion with LDAP entry provisioning.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal account.
   */
  private function deleteProvisionedLdapEntry(UserInterface $account) {
    if ($this->provisionsLdapEntriesFromDrupalUsers()
      && LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE)
    ) {
      $this->ldapUserProcessor->deleteProvisionedLdapEntries($account);
    }
  }

  /**
   * Handle account login with LDAP entry provisioning.
   */
  private function loginLdapEntryProvisioning() {
    if ($this->provisionsLdapEntriesFromDrupalUsers()
      && LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION)) {
      // Provision entry.
      if (SemaphoreStorage::get('provision', $this->account->getAccountName()) == FALSE
      && !$this->ldapUserProcessor->getProvisionRelatedLdapEntry($this->account)) {
        if ($this->ldapUserProcessor->provisionLdapEntry($this->account)) {
          SemaphoreStorage::set('provision', $this->account->getAccountName());
        }
      }

      // Sync entry if not just provisioned.
      if (SemaphoreStorage::get('provision', $this->account->getAccountName()) == FALSE
        && SemaphoreStorage::get('sync', $this->account->getAccountName()) == FALSE) {
        $result = $this->ldapUserProcessor->syncToLdapEntry($this->account);
        if ($result) {
          SemaphoreStorage::set('sync', $this->account->getAccountName());
        }
      }
    }
  }

  /**
   * Handle account login with Drupal provisioning.
   */
  private function loginDrupalAccountProvisioning() {
    if (LdapConfiguration::provisionsDrupalAccountsFromLdap()
      && in_array(self::EVENT_SYNC_TO_DRUPAL_USER, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
      $this->ldapEntry = $this->factory->getUserDataFromServerByAccount($this->account, $this->config->get('drupalAcctProvisionServer'));
      if ($this->ldapEntry) {
        $this->server = $this->entityTypeManager->getStorage('ldap_server')->load($this->config->get('drupalAcctProvisionServer'));
        $this->applyAttributesToAccount(self::PROVISION_TO_DRUPAL, [self::EVENT_SYNC_TO_DRUPAL_USER]);
      }
      $this->saveAccount();
    }
  }

  /**
   * Handle the user update/create event with LDAP entry provisioning.
   */
  private function provisionLdapEntryOnUserUpdateCreateEvent() {
    if (SemaphoreStorage::get('provision', $this->account->getAccountName())
     || SemaphoreStorage::get('sync', $this->account->getAccountName())) {
      return;
    }

    // Check if provisioning to LDAP has already occurred this page load.
    if (!$this->ldapUserProcessor->getProvisionRelatedLdapEntry($this->account)) {
      if ($this->ldapUserProcessor->provisionLdapEntry($this->account)) {
        SemaphoreStorage::set('provision', $this->account->getAccountName());
      }
    }

    // Sync if not just provisioned and enabled.
    if (SemaphoreStorage::get('provision', $this->account->getAccountName()) == FALSE) {
      // Check if provisioning to LDAP has already occurred this page load.
      if (LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE)
        && $this->ldapUserProcessor->getProvisionRelatedLdapEntry($this->account)) {
        if ($this->ldapUserProcessor->syncToLdapEntry($this->account)) {
          SemaphoreStorage::set('sync', $this->account->getAccountName());
        }
      }
    }
  }

  /**
   * Saves the account, separated to make this testable.
   */
  private function saveAccount() {
    $this->account->save();
  }

  /**
   * Apply field values to user account.
   *
   * One should not assume all attributes are present in the LDAP entry.
   *
   * @param string $direction
   *   The provisioning direction.
   * @param array $prov_events
   *   The provisioning events.
   */
  private function applyAttributesToAccount($direction = NULL, array $prov_events = NULL) {
    if ($direction == NULL) {
      $direction = self::PROVISION_TO_DRUPAL;
    }
    if (!$prov_events) {
      $prov_events = LdapConfiguration::getAllEvents();
    }

    $this->setLdapBaseFields($direction, $prov_events);

    if ($direction == self::PROVISION_TO_DRUPAL && in_array(self::EVENT_CREATE_DRUPAL_USER, $prov_events)) {
      // If empty, set initial mail, status active, generate a random password.
      $this->setFieldsOnDrupalUserCreation();
    }

    $this->setUserDefinedMappings($direction, $prov_events);

    $context = ['ldap_server' => $this->server, 'prov_events' => $prov_events];
    $this->moduleHandler
      ->alter('ldap_user_edit_user',
        $this->account,
        $this->ldapEntry,
        $context);

    // Set ldap_user_last_checked.
    $this->account->set('ldap_user_last_checked', time());
  }

  /**
   * For a Drupal account, query LDAP, get all user fields and save.
   *
   * @param int $provisioningEvent
   *   The provisioning event.
   *   already present.
   *
   * @return bool
   *   Attempts to sync, reports failure if unsuccessful.
   */
  private function syncToDrupalAccount($provisioningEvent = NULL) {
    if ($provisioningEvent == NULL) {
      $provisioningEvent = self::EVENT_SYNC_TO_DRUPAL_USER;
    }

    if ((!$this->ldapEntry && !method_exists($this->account, 'getAccountName')) || (!$this->account)) {
      $this->logger
        ->notice('Invalid selection passed to syncToDrupalAccount.');
      return FALSE;
    }

    if (!$this->ldapEntry && $this->config->get('drupalAcctProvisionServer')) {
      $this->ldapEntry = $this->factory->getUserDataFromServerByAccount($this->account, $this->config->get('drupalAcctProvisionServer'));
    }

    if (!$this->ldapEntry) {
      return FALSE;
    }

    if ($this->config->get('drupalAcctProvisionServer')) {
      $this->server = $this->entityTypeManager->getStorage('ldap_server')->load($this->config->get('drupalAcctProvisionServer'));
      $this->applyAttributesToAccount(self::PROVISION_TO_DRUPAL, [$provisioningEvent]);
    }

    $this->saveAccount();
    return TRUE;
  }

  /**
   * Handle LDAP entry provision on user creation.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user account.
   */
  private function provisionLdapEntryOnUserCreation(UserInterface $account) {
    if ($this->provisionsLdapEntriesFromDrupalUsers()) {
      if (LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE)) {
        if (!$this->ldapUserProcessor->getProvisionRelatedLdapEntry($account)) {
          if ($this->ldapUserProcessor->provisionLdapEntry($account)) {
            SemaphoreStorage::set('provision', $account->getAccountName());
          }
        }
        else {
          if ($this->ldapUserProcessor->syncToLdapEntry($account)) {
            SemaphoreStorage::set('sync', $account->getAccountName());
          }
        }
      }
    }
  }

  /**
   * Determine if this a user registration process.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user account.
   *
   * @return bool
   *   It is a registration process.
   */
  private function newAccountRequest(UserInterface $account) {
    if ($this->currentUser->isAnonymous() && $account->isNew()) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Sets the fields for initial users.
   *
   * @param array $ldapUser
   *   Ldap user data.
   */
  private function setFieldsOnDrupalUserCreation() {
    $derived_mail = $this->server->deriveEmailFromLdapResponse($this->ldapEntry);
    if (!$this->account->getEmail()) {
      $this->account->set('mail', $derived_mail);
    }
    if (!$this->account->getPassword()) {
      $this->account->set('pass', user_password(20));
    }
    if (!$this->account->getInitialEmail()) {
      $this->account->set('init', $derived_mail);
    }
    if (!$this->account->isBlocked()) {
      $this->account->set('status', 1);
    }
  }

  /**
   * Sets the fields required by LDAP.
   *
   * @param string $direction
   *   Provision direction.
   * @param array $prov_events
   *   Provisioning event.
   */
  private function setLdapBaseFields($direction, array $prov_events) {
    // Basic $user LDAP fields.
    if ($this->syncMapper->isSynced('[property.name]', $prov_events, $direction)) {
      $this->account->set('name', $this->server->deriveUsernameFromLdapResponse($this->ldapEntry));
    }

    if ($this->syncMapper->isSynced('[property.mail]', $prov_events, $direction)) {
      $derived_mail = $this->server->deriveEmailFromLdapResponse($this->ldapEntry);
      if ($derived_mail) {
        $this->account->set('mail', $derived_mail);
      }
    }

    if ($this->syncMapper->isSynced('[property.picture]', $prov_events, $direction)) {
      $picture = $this->userPictureFromLdapEntry();
      if ($picture) {
        $this->account->set('user_picture', $picture);
      }
    }

    if ($this->syncMapper->isSynced('[field.ldap_user_puid]', $prov_events, $direction)) {
      $ldap_user_puid = $this->server->derivePuidFromLdapResponse($this->ldapEntry);
      if ($ldap_user_puid) {
        $this->account->set('ldap_user_puid', $ldap_user_puid);
      }
    }
    if ($this->syncMapper->isSynced('[field.ldap_user_puid_property]', $prov_events, $direction)) {
      $this->account->set('ldap_user_puid_property', $this->server->get('unique_persistent_attr'));
    }
    if ($this->syncMapper->isSynced('[field.ldap_user_puid_sid]', $prov_events, $direction)) {
      $this->account->set('ldap_user_puid_sid', $this->server->id());
    }
    if ($this->syncMapper->isSynced('[field.ldap_user_current_dn]', $prov_events, $direction)) {
      $this->account->set('ldap_user_current_dn', $this->ldapEntry->getDn());
    }
  }

  /**
   * Sets the additional, user-defined fields.
   *
   * The greyed out user mappings are not passed to this function.
   *
   * @param string $direction
   *   Provision direction.
   * @param array $prov_events
   *   Provisioning event.
   */
  private function setUserDefinedMappings($direction, array $prov_events) {
    // Get any additional mappings.
    $mappings = $this->syncMapper->getSyncMappings($direction, $prov_events);

    // Loop over the mappings.
    foreach ($mappings as $key => $fieldDetails) {
      // Make sure this mapping is relevant to the sync context.
      if ($this->syncMapper->isSynced($key, $prov_events, $direction)) {
        // If "convert from binary is selected" and no particular method is in
        // token default to binaryConversionToString() function.
        if ($fieldDetails['convert'] && strpos($fieldDetails['ldap_attr'], ';') === FALSE) {
          $fieldDetails['ldap_attr'] = str_replace(']', ';binary]', $fieldDetails['ldap_attr']);
        }
        $value = $this->tokenProcessor->tokenReplace($this->ldapEntry, $fieldDetails['ldap_attr'], 'ldap_entry');
        // The ordinal $value_instance is not used and could probably be
        // removed.
        list($value_type, $value_name, $value_instance) = $this->parseUserAttributeNames($key);

        if ($value_type == 'field' || $value_type == 'property') {
          $this->account->set($value_name, $value);
        }
      }
    }
  }

  /**
   * Parse user attribute names.
   *
   * @param string $user_attr_key
   *   A string in the form of <attr_type>.<attr_name>[:<instance>] such as
   *   field.lname, property.mail, field.aliases:2.
   *
   * @return array
   *   An array such as array('field','field_user_lname', NULL).
   */
  private function parseUserAttributeNames($user_attr_key) {
    // Make sure no [] are on attribute.
    $user_attr_key = trim($user_attr_key, TokenProcessor::PREFIX . TokenProcessor::SUFFIX);
    $parts = explode('.', $user_attr_key);
    $attr_type = $parts[0];
    $attr_name = (isset($parts[1])) ? $parts[1] : FALSE;
    $attr_ordinal = FALSE;

    if ($attr_name) {
      $attr_name_parts = explode(':', $attr_name);
      if (isset($attr_name_parts[1])) {
        $attr_name = $attr_name_parts[0];
        $attr_ordinal = $attr_name_parts[1];
      }
    }
    return [$attr_type, $attr_name, $attr_ordinal];
  }

}

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
use Drupal\ldap_servers\LdapUserManager;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_user\Event\LdapUserLoginEvent;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\Core\Utility\Token;
use Drupal\user\UserInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

/**
 * Handles processing of a user from LDAP to Drupal.
 */
class DrupalUserProcessor implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  protected $logger;
  protected $config;
  protected $configAuthentication;
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

  protected $ldapUserManager;

  protected $eventDispatcher;

  /**
   * Constructor.
   *
   * TODO: Make this service smaller.
   * (The number of dependencies alone makes this clear.)
   */
  public function __construct(
    LoggerChannelInterface $logger,
    ConfigFactory $config_factory,
    LdapDetailLog $detail_log,
    TokenProcessor $token_processor,
    Authmap $authmap,
    EntityTypeManager $entity_type_manager,
    FileSystem $file_system,
    Token $token,
    ModuleHandler $module_handler,
    AccountInterface $current_user,
    SyncMappingHelper $sync_mapper,
    LdapUserManager $ldap_user_manager,
    EventDispatcherInterface $event_dispatcher) {
    $this->logger = $logger;
    $this->config = $config_factory->get('ldap_user.settings');
    $this->configAuthentication = $config_factory->get('ldap_authentication.settings');
    $this->detailLog = $detail_log;
    $this->tokenProcessor = $token_processor;
    $this->externalAuth = $authmap;
    $this->entityTypeManager = $entity_type_manager;
    $this->fileSystem = $file_system;
    $this->token = $token;
    $this->moduleHandler = $module_handler;
    $this->currentUser = $current_user;
    $this->syncMapper = $sync_mapper;
    $this->ldapUserManager = $ldap_user_manager;
    $this->eventDispatcher = $event_dispatcher;
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
   * @param array $user_data
   *   A keyed array normally containing 'name' and optionally more.
   *
   * @return bool|\Drupal\user\Entity\User
   *   Return the user on success or FALSE on any problem.
   */
  public function createDrupalUserFromLdapEntry(array $user_data) {

    $this->account = $this->entityTypeManager
      ->getStorage('user')
      ->create($user_data);

    $this->server = $this->entityTypeManager
      ->getStorage('ldap_server')
      ->load($this->config->get('drupalAcctProvisionServer'));

    // Get an LDAP user from the LDAP server.
    if ($this->config->get('drupalAcctProvisionServer')) {
      $this->ldapUserManager->setServer($this->server);
      $this->ldapEntry = $this->ldapUserManager->getUserDataByIdentifier($user_data['name']);
    }

    if (!$this->ldapEntry) {
      $this->detailLog->log(
        '@username: Failed to find associated LDAP entry for username in provision.',
        ['@username' => $user_data['name']],
        'ldap-user'
      );
      return FALSE;
    }

    // If we don't have an account name already we should set one.
    if (!$this->account->getAccountName()) {
      $this->account->set('name', $this->ldapEntry->getAttribute($this->server->get('user_attr'))[0]);
    }

    // Can we get details from an LDAP server?
    $params = [
      'account' => $this->account,
      'user_values' => $user_data,
      'prov_event' => self::EVENT_CREATE_DRUPAL_USER,
      'module' => 'ldap_user',
      'function' => 'createDrupalUserFromLdapEntry',
      'direction' => self::PROVISION_TO_DRUPAL,
    ];

    $this->moduleHandler->alter('ldap_entry', $this->ldapEntry, $params);

    // Look for existing Drupal account with the same PUID. If found, update
    // that user instead of creating a new user.
    $persistentUid = $this->server->derivePuidFromLdapResponse($this->ldapEntry);
    $accountFromPuid = $persistentUid ? $this->ldapUserManager->getUserAccountFromPuid($persistentUid) : FALSE;
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
   * Callback for hook_ENTITY_TYPE_update().
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   */
  public function drupalUserUpdate(UserInterface $account) {
    $this->account = $account;
    if ($this->excludeUser($this->account)) {
      return;
    }
    $server = $this->config->get('drupalAcctProvisionServer');
    $triggers = $this->config->get('drupalAcctProvisionTriggers');
    if ($server && isset($triggers[self::EVENT_SYNC_TO_DRUPAL_USER])) {
      $this->syncToDrupalAccount();
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
    $triggers = $this->config->get('drupalAcctProvisionTriggers');
    $server = $this->config->get('drupalAcctProvisionServer');

    if ($server && isset($triggers[self::EVENT_SYNC_TO_DRUPAL_USER])) {
      $this->syncToDrupalAccount();
    }

    $event = new LdapUserLoginEvent($account);
    $this->eventDispatcher->dispatch(LdapUserLoginEvent::EVENT_NAME, $event);
  }

  /**
   * Create a Drupal user.
   *
   * @param array $this
   *   ->ldapEntry
   *   The LDAP user.
   *
   * @return void
   */
  private function createDrupalUser() {
    $this->account->enforceIsNew();
    $this->applyAttributesToAccountOnCreate();
    $tokens = ['%drupal_username' => $this->account->getAccountName()];
    if (empty($this->account->getAccountName())) {
      drupal_set_message($this->t('User account creation failed because of invalid, empty derived Drupal username.'), 'error');
      $this->logger
        ->error('Failed to create Drupal account %drupal_username because Drupal username could not be derived.', $tokens);
      return;
    }
    if (!$mail = $this->account->getEmail()) {
      drupal_set_message($this->t('User account creation failed because of invalid, empty derived email address.'), 'error');
      $this->logger
        ->error('Failed to create Drupal account %drupal_username because email address could not be derived by LDAP User module', $tokens);
      return;
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
      return;
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
    $this->syncToDrupalAccount();
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
        // TODO: DI.
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
    // TODO: Declare dependency on exif or resolve it.
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
  private function applyAttributesToAccount() {
    $this->setLdapBaseFields(self::EVENT_SYNC_TO_DRUPAL_USER);
    $this->setUserDefinedMappings(self::EVENT_SYNC_TO_DRUPAL_USER);

    $context = ['ldap_server' => $this->server, 'prov_event' => self::EVENT_SYNC_TO_DRUPAL_USER];
    $this->moduleHandler
      ->alter('ldap_user_edit_user',
        $this->account,
        $this->ldapEntry,
        $context);

    // Set ldap_user_last_checked.
    $this->account->set('ldap_user_last_checked', time());
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
  private function applyAttributesToAccountOnCreate() {
    $this->setLdapBaseFields(self::EVENT_CREATE_DRUPAL_USER);
    $this->setFieldsOnDrupalUserCreation();
    $this->setUserDefinedMappings(self::EVENT_CREATE_DRUPAL_USER);

    $context = ['ldap_server' => $this->server, 'prov_event' => self::EVENT_CREATE_DRUPAL_USER];
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
   * @return bool
   *   Attempts to sync, reports failure if unsuccessful.
   */
  private function syncToDrupalAccount() {
    if (!($this->account instanceof UserInterface)) {
      $this->logger
        ->notice('Invalid selection passed to syncToDrupalAccount.');
      return FALSE;
    }

    if (property_exists($this->account, 'ldap_synced')) {
      // We skip syncing if we already did add the fields on the user.
      return FALSE;
    }

    if (!$this->ldapEntry && $this->config->get('drupalAcctProvisionServer')) {
      $this->ldapUserManager->setServerById($this->config->get('drupalAcctProvisionServer'));
      $this->ldapEntry = $this->ldapUserManager->getUserDataByAccount($this->account);
    }

    if (!$this->ldapEntry) {
      return FALSE;
    }

    if ($this->config->get('drupalAcctProvisionServer')) {
      $this->server = $this->entityTypeManager->getStorage('ldap_server')->load($this->config->get('drupalAcctProvisionServer'));
      $this->applyAttributesToAccount();
      $this->account->ldap_synced = TRUE;
    }
    return TRUE;
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
   * @param string $event
   *   Provisioning event.
   */
  private function setLdapBaseFields($event) {
    $direction = self::PROVISION_TO_DRUPAL;
    // Basic $user LDAP fields.
    if ($this->syncMapper->isSyncedToDrupal('[property.name]', $event)) {
      $this->account->set('name', $this->server->deriveUsernameFromLdapResponse($this->ldapEntry));
    }

    if ($this->syncMapper->isSyncedToDrupal('[property.mail]', $event)) {
      $derived_mail = $this->server->deriveEmailFromLdapResponse($this->ldapEntry);
      if ($derived_mail) {
        $this->account->set('mail', $derived_mail);
      }
    }

    if ($this->syncMapper->isSyncedToDrupal('[property.picture]', $event)) {
      $picture = $this->userPictureFromLdapEntry();
      if ($picture) {
        $this->account->set('user_picture', $picture);
      }
    }

    if ($this->syncMapper->isSyncedToDrupal('[field.ldap_user_puid]', $event)) {
      $ldap_user_puid = $this->server->derivePuidFromLdapResponse($this->ldapEntry);
      if ($ldap_user_puid) {
        $this->account->set('ldap_user_puid', $ldap_user_puid);
      }
    }
    if ($this->syncMapper->isSyncedToDrupal('[field.ldap_user_puid_property]', $event)) {
      $this->account->set('ldap_user_puid_property', $this->server->get('unique_persistent_attr'));
    }
    if ($this->syncMapper->isSyncedToDrupal('[field.ldap_user_puid_sid]', $event)) {
      $this->account->set('ldap_user_puid_sid', $this->server->id());
    }
    if ($this->syncMapper->isSyncedToDrupal('[field.ldap_user_current_dn]', $event)) {
      $this->account->set('ldap_user_current_dn', $this->ldapEntry->getDn());
    }
  }

  /**
   * Sets the additional, user-defined fields.
   *
   * The greyed out user mappings are not passed to this function.
   *
   * @param string $event
   *   Provisioning event.
   */
  private function setUserDefinedMappings($event) {
    $direction = self::PROVISION_TO_DRUPAL;
    // Get any additional mappings.
    $mappings = $this->syncMapper->getFieldsSyncedToDrupal($event);

    // Loop over the mappings.
    foreach ($mappings as $key => $fieldDetails) {
      // Make sure this mapping is relevant to the sync context.
      if ($this->syncMapper->isSyncedToDrupal($key, $event)) {
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

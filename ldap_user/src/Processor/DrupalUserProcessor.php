<?php

namespace Drupal\ldap_user\Processor;

use Drupal\Core\Field\FieldItemListInterface;
use Drupal\file\Entity\File;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\ldap_user\LdapUserAttributesInterface;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SemaphoreStorage;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\user\entity\User;
use Drupal\user\UserInterface;

/**
 * Handles processing of a user from LDAP to Drupal.
 */
class DrupalUserProcessor implements LdapUserAttributesInterface {

  private $config;

  /**
   * The Drupal user account.
   *
   * @var \Drupal\user\entity\User
   */
  private $account;

  /**
   * The server interacting with.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  private $server;

  /**
   * Constructor.
   */
  public function __construct() {
    $this->config = \Drupal::config('ldap_user.settings');
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
      $factory = \Drupal::service('ldap.servers');
      /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
      $ldap_server = $factory->getServerByIdEnabled($this->config->get('drupalAcctProvisionServer'));
      $this->account = user_load_by_name($drupalUsername);
      if (!$this->account) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate Drupal account %drupal_username because account not found', ['%drupal_username' => $drupalUsername]);
        return FALSE;
      }

      $ldap_user = $ldap_server->matchUsernameToExistingLdapEntry($drupalUsername);
      if (!$ldap_user) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate Drupal account %drupal_username because corresponding LDAP entry not found', ['%drupal_username' => $drupalUsername]);
        return FALSE;
      }

      $ldap_user_puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      if ($ldap_user_puid) {
        $this->account->set('ldap_user_puid', $ldap_user_puid);
      }
      $this->account->set('ldap_user_puid_property', $ldap_server->get('unique_persistent_attr'));
      $this->account->set('ldap_user_puid_sid', $ldap_server->id());
      $this->account->set('ldap_user_current_dn', $ldap_user['dn']);
      $this->account->set('ldap_user_last_checked', time());
      $this->account->set('ldap_user_ldap_exclude', 0);
      $this->saveAccount();

      $this->syncToDrupalAccount(self::EVENT_CREATE_DRUPAL_USER, $ldap_user);

      return TRUE;
    }
    else {
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
   * Provision a Drupal user account.
   *
   * Given user data, create a user and apply LDAP attributes or assign to
   * correct user if name has changed through PUID.
   *
   * @param array $userData
   *   A keyed array normally containing 'name' and optionally more.
   *
   * @return bool|\Drupal\user\entity\User
   *   Return the user on success or FALSE on any problem.
   */
  public function provisionDrupalAccount(array $userData) {

    $this->account = User::create($userData);
    $ldapUser = FALSE;

    /* @var \Drupal\ldap_servers\ServerFactory $factory */
    $factory = \Drupal::service('ldap.servers');

    // Get an LDAP user from the LDAP server.
    if ($this->config->get('drupalAcctProvisionServer')) {
      $ldapUser = $factory->getUserDataFromServerByIdentifier($userData['name'], $this->config->get('drupalAcctProvisionServer'));
    }
    // Still no LDAP user.
    if (!$ldapUser) {
      if (\Drupal::config('ldap_help.settings')->get('watchdog_detail')) {
        \Drupal::logger('ldap_user')
          ->debug('@username: Failed to find associated LDAP entry for username in provision.',
            ['@username' => $userData['name']]
          );
      }
      return FALSE;
    }

    $this->server = $factory->getServerByIdEnabled($this->config->get('drupalAcctProvisionServer'));

    // If we don't have an account name already we should set one.
    if (!$this->account->getAccountName()) {
      $this->account->set('name', $ldapUser[$this->server->get('user_attr')]);
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

    \Drupal::moduleHandler()->alter('ldap_entry', $ldapUser, $params);

    // Look for existing Drupal account with the same PUID. If found, update
    // that user instead of creating a new user.
    $persistentUid = $this->server->userPuidFromLdapEntry($ldapUser['attr']);
    $accountFromPuid = ($persistentUid) ? $this->server->userAccountFromPuid($persistentUid) : FALSE;
    if ($accountFromPuid) {
      $result = $this->updateExistingAccountByPersistentUid($ldapUser, $accountFromPuid);
    }
    else {
      $result = $this->createDrupalUser($ldapUser);
    }
    return $result;
  }

  /**
   * Apply field values to user account.
   *
   * One should not assume all attributes are present in the LDAP entry.
   *
   * @param array $ldap_user
   *   LDAP entry.
   * @param int $direction
   *   The provisioning direction.
   * @param array $prov_events
   *   The provisioning events.
   */
  private function applyAttributesToAccount(array $ldap_user, $direction = NULL, array $prov_events = NULL) {
    if ($direction == NULL) {
      $direction = self::PROVISION_TO_DRUPAL;
    }
    // Need array of user fields and which direction and when they should be
    // synced.
    if (!$prov_events) {
      $prov_events = LdapConfiguration::getAllEvents();
    }

    $processor = new SyncMappingHelper();
    $mail_synced = $processor->isSynced('[property.mail]', $prov_events, $direction);
    if (!$this->account->getEmail() && $mail_synced) {
      $derived_mail = $this->server->userEmailFromLdapEntry($ldap_user['attr']);
      if ($derived_mail) {
        $this->account->set('mail', $derived_mail);
      }
    }

    $drupal_username = $this->server->userUsernameFromLdapEntry($ldap_user['attr']);
    if ($processor->isSynced('[property.picture]', $prov_events, $direction)) {

      $picture = $this->userPictureFromLdapEntry($ldap_user['attr']);

      if ($picture) {
        $this->account->set('user_picture', $picture);
      }
    }

    if ($processor->isSynced('[property.name]', $prov_events, $direction) && !$this->account->getAccountName() && $drupal_username) {
      $this->account->set('name', $drupal_username);
    }

    // Only fired on self::EVENT_CREATE_DRUPAL_USER. Shouldn't it
    // respect the checkbox on the sync form?
    if ($direction == self::PROVISION_TO_DRUPAL && in_array(self::EVENT_CREATE_DRUPAL_USER, $prov_events)) {
      $derived_mail = $this->server->userEmailFromLdapEntry($ldap_user['attr']);
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

    // Basic $user LDAP fields.
    $processor = new SyncMappingHelper();

    if ($processor->isSynced('[field.ldap_user_puid]', $prov_events, $direction)) {
      $ldap_user_puid = $this->server->userPuidFromLdapEntry($ldap_user['attr']);
      if ($ldap_user_puid) {
        $this->account->set('ldap_user_puid', $ldap_user_puid);
      }
    }
    if ($processor->isSynced('[field.ldap_user_puid_property]', $prov_events, $direction)) {
      $this->account->set('ldap_user_puid_property', $this->server->get('unique_persistent_attr'));
    }
    if ($processor->isSynced('[field.ldap_user_puid_sid]', $prov_events, $direction)) {
      $this->account->set('ldap_user_puid_sid', $this->server->id());
    }
    if ($processor->isSynced('[field.ldap_user_current_dn]', $prov_events, $direction)) {
      $this->account->set('ldap_user_current_dn', $ldap_user['dn']);
    }

    // Get any additional mappings.
    $mappings = $processor->getSyncMappings($direction, $prov_events);

    // Loop over the mappings.
    foreach ($mappings as $user_attr_key => $field_detail) {

      // Make sure this mapping is relevant to the sync context.
      if (!$processor->isSynced($user_attr_key, $prov_events, $direction)) {
        continue;
      }

      // If "convert from binary is selected" and no particular method is in
      // token default to binaryConversionToString() function.
      if ($field_detail['convert'] && strpos($field_detail['ldap_attr'], ';') === FALSE) {
        $field_detail['ldap_attr'] = str_replace(']', ';binary]', $field_detail['ldap_attr']);
      }
      $tokenHelper = new TokenProcessor();
      $value = $tokenHelper->tokenReplace($ldap_user['attr'], $field_detail['ldap_attr'], 'ldap_entry');
      list($value_type, $value_name, $value_instance) = $tokenHelper->parseUserAttributeNames($user_attr_key);

      // $value_instance not used, may have future use case.
      // Are we dealing with a field?
      if ($value_type == 'field' || $value_type == 'property') {
        $this->account->set($value_name, $value);
      }
    }

    $context = ['ldap_server' => $this->server, 'prov_events' => $prov_events];
    \Drupal::moduleHandler()->alter('ldap_user_edit_user', $this->account, $ldap_user, $context);

    // Don't let empty 'name' value pass for user.
    if (empty($this->account->getAccountName())) {
      $this->account->set('name', $ldap_user[$this->server->get('user_attr')]);
    }

    // Set ldap_user_last_checked.
    $this->account->set('ldap_user_last_checked', time());
  }

  /**
   * For a Drupal account, query LDAP, get all user fields and save.
   *
   * @param int $prov_event
   *   The provisioning event.
   * @param array $ldap_user
   *   A user's LDAP entry. Passed to avoid re-querying LDAP in cases where
   *   already present.
   *
   * @return bool
   *   Attempts to sync, reports failure if unsuccessful.
   */
  private function syncToDrupalAccount($prov_event = NULL, array $ldap_user = NULL) {
    if ($prov_event == NULL) {
      $prov_event = self::EVENT_SYNC_TO_DRUPAL_USER;
    }

    if ((!$ldap_user && !method_exists($this->account, 'getUsername')) || (!$this->account)) {
      \Drupal::logger('ldap_user')
        ->notice('Invalid selection passed to syncToDrupalAccount.');
      return FALSE;
    }

    if (!$ldap_user && $this->config->get('drupalAcctProvisionServer')) {
      $factory = \Drupal::service('ldap.servers');
      /** @var \Drupal\ldap_servers\ServerFactory $factory */
      $ldap_user = $factory->getUserDataFromServerByAccount($this->account, $this->config->get('drupalAcctProvisionServer'), 'ldap_user_prov_to_drupal');
    }

    if (!$ldap_user) {
      return FALSE;
    }

    if ($this->config->get('drupalAcctProvisionServer')) {
      $this->server = Server::load($this->config->get('drupalAcctProvisionServer'));
      $this->applyAttributesToAccount($ldap_user, self::PROVISION_TO_DRUPAL, [$prov_event]);
    }

    $this->saveAccount();
    return TRUE;
  }

  /**
   * Set flag to exclude user from LDAP association.
   *
   * @param string $drupal_username
   *   The account username.
   *
   * @return bool
   *   TRUE on success, FALSE on error or failure because of invalid user.
   */
  public function ldapExcludeDrupalAccount($drupal_username) {
    $account = user_load_by_name($drupal_username);
    if (!$account) {
      \Drupal::logger('ldap_user')->error('Failed to exclude user from LDAP association because Drupal account %drupal_username was not found', ['%drupal_username' => $drupal_username]);
      return FALSE;
    }

    $account->set('ldap_user_ldap_exclude', 1);
    $account->save();
    return (boolean) $account;
  }

  /**
   * Alter the user's attributes.
   *
   * @param array $attributes
   *   Attributes to change.
   * @param array $params
   *   Parameters.
   *
   * @return array
   *   Altered attributes.
   */
  public function alterUserAttributes(array $attributes, array $params) {
    // Puid attributes are server specific.
    if (isset($params['sid']) && $params['sid']) {
      if (is_scalar($params['sid'])) {
        $factory = \Drupal::service('ldap.servers');
        /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
        $ldap_server = $factory->getServerByIdEnabled($params['sid']);
      }
      else {
        $ldap_server = $params['sid'];
      }

      if ($ldap_server) {
        if (!isset($attributes['dn'])) {
          $attributes['dn'] = [];
        }
        // Force dn "attribute" to exist.
        $attributes['dn'] = TokenProcessor::setAttributeMap($attributes['dn']);
        // Add the attributes required by the user configuration when
        // provisioning Drupal users.
        switch ($params['ldap_context']) {
          case 'ldap_user_insert_drupal_user':
          case 'ldap_user_update_drupal_user':
          case 'ldap_user_ldap_associate':
            if ($ldap_server->get('user_attr')) {
              $attributes[$ldap_server->get('user_attr')] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->get('user_attr')]);
            }
            if ($ldap_server->get('mail_attr')) {
              $attributes[$ldap_server->get('mail_attr')] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->get('mail_attr')]);
            }
            if ($ldap_server->get('picture_attr')) {
              $attributes[$ldap_server->get('picture_attr')] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->get('picture_attr')]);
            }
            if ($ldap_server->get('unique_persistent_attr')) {
              $attributes[$ldap_server->get('unique_persistent_attr')] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->get('unique_persistent_attr')]);
            }
            if ($ldap_server->get('mail_template')) {
              $tokens = new TokenProcessor();
              $tokens->extractTokenAttributes($attributes, $ldap_server->get('mail_template'));
            }
            break;
        }

        $ldap_context = empty($params['ldap_context']) ? NULL : $params['ldap_context'];
        $direction = empty($params['direction']) ? $this->ldapContextToProvDirection($ldap_context) : $params['direction'];
        $helper = new SyncMappingHelper();
        $attributes_required_by_user_module_mappings = $helper->getLdapUserRequiredAttributes($direction, $ldap_context);
        $attributes = array_merge($attributes_required_by_user_module_mappings, $attributes);
        return $attributes;

      }
    }
    return $attributes;
  }

  /**
   * LDAP attributes to alter.
   *
   * @param array $availableUserAttributes
   *   Available attributes.
   * @param array $params
   *   Parameters.
   *
   * @return array
   *   Altered attributes.
   */
  public function alterLdapUserAttributes(array $availableUserAttributes, array $params) {
    if (isset($params['direction'])) {
      $direction = $params['direction'];
    }
    else {
      $direction = self::PROVISION_TO_NONE;
    }

    if ($direction == self::PROVISION_TO_LDAP) {
      $availableUserAttributes['[property.name]'] = [
        'name' => 'Property: Username',
        'source' => '',
        'direction' => self::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      $availableUserAttributes['[property.mail]'] = [
        'name' => 'Property: Email',
        'source' => '',
        'direction' => self::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      $availableUserAttributes['[property.picture]'] = [
        'name' => 'Property: picture',
        'source' => '',
        'direction' => self::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      $availableUserAttributes['[property.uid]'] = [
        'name' => 'Property: Drupal User Id (uid)',
        'source' => '',
        'direction' => self::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

    }

    // 1. Drupal user properties
    // 1.a make sure empty array are present so array + function works.
    foreach (['property.status', 'property.timezone', 'property.signature'] as $property_id) {
      $property_token = '[' . $property_id . ']';
      if (!isset($availableUserAttributes[$property_token]) || !is_array($availableUserAttributes[$property_token])) {
        $availableUserAttributes[$property_token] = [];
      }
    }

    // @todo make these merges so they don't override saved values such as 'enabled'
    $availableUserAttributes['[property.status]'] = $availableUserAttributes['[property.status]'] + [
      'name' => 'Property: Account Status',
      'configurable_to_drupal' => 1,
      'configurable_to_ldap' => 1,
      'user_tokens' => '1=enabled, 0=blocked.',
      'enabled' => FALSE,
      'config_module' => 'ldap_user',
      'prov_module' => 'ldap_user',
    ];

    $availableUserAttributes['[property.timezone]'] = $availableUserAttributes['[property.timezone]'] + [
      'name' => 'Property: User Timezone',
      'configurable_to_drupal' => 1,
      'configurable_to_ldap' => 1,
      'enabled' => FALSE,
      'config_module' => 'ldap_user',
      'prov_module' => 'ldap_user',
    ];

    $availableUserAttributes['[property.signature]'] = $availableUserAttributes['[property.signature]'] + [
      'name' => 'Property: User Signature',
      'configurable_to_drupal' => 1,
      'configurable_to_ldap' => 1,
      'enabled' => FALSE,
      'config_module' => 'ldap_user',
      'prov_module' => 'ldap_user',
    ];

    // 2. Drupal user fields.
    $user_fields = \Drupal::entityManager()->getFieldStorageDefinitions('user');

    foreach ($user_fields as $field_name => $field_instance) {
      $field_id = "[field.$field_name]";
      if (!isset($availableUserAttributes[$field_id]) || !is_array($availableUserAttributes[$field_id])) {
        $availableUserAttributes[$field_id] = [];
      }

      $availableUserAttributes[$field_id] = $availableUserAttributes[$field_id] + [
        'name' => t('Field: @label', ['@label' => $field_instance->getLabel()]),
        'configurable_to_drupal' => 1,
        'configurable_to_ldap' => 1,
        'enabled' => FALSE,
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
      ];
    }

    if (!LdapConfiguration::provisionsDrupalAccountsFromLdap()) {
      $availableUserAttributes['[property.mail]']['config_module'] = 'ldap_user';
      $availableUserAttributes['[property.name]']['config_module'] = 'ldap_user';
      $availableUserAttributes['[property.picture]']['config_module'] = 'ldap_user';
    }

    if ($direction == self::PROVISION_TO_LDAP) {
      $availableUserAttributes['[password.random]'] = [
        'name' => 'Password: Random password',
        'source' => '',
        'direction' => self::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      // Use user password when available fall back to random pwd.
      $availableUserAttributes['[password.user-random]'] = [
        'name' => 'Password: Plain user password or random',
        'source' => '',
        'direction' => self::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      // Use user password, do not modify if unavailable.
      $availableUserAttributes['[password.user-only]'] = [
        'name' => 'Password: Plain user password',
        'source' => '',
        'direction' => self::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

    }

    // TODO: This is possible an overlap with SyncMappingHelper.
    $mappings = \Drupal::config('ldap_user.settings')->get('ldapUserSyncMappings');

    // This is where need to be added to arrays.
    if (!empty($mappings[$direction])) {
      $availableUserAttributes = $this->applyUserAttributes($availableUserAttributes, $mappings, $direction);
    }

    return [$availableUserAttributes, $params];
  }

  /**
   * Test if the user is LDAP associated.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   * @param int $direction
   *   Indicating which directions to test for association, NULL signifies check
   *   for either direction.
   *
   * @return bool
   *   Whether the user is LDAP associated.
   */
  public function isUserLdapAssociated(UserInterface $account, $direction = NULL) {

    $to_drupal_user = FALSE;
    $to_ldap_entry = FALSE;

    if ($direction === NULL || $direction == self::PROVISION_TO_DRUPAL) {
      if (property_exists($account, 'ldap_user_current_dn') && !empty($account->get('ldap_user_current_dn')->value)) {
        $to_drupal_user = TRUE;
      }
      elseif ($account->id()) {
        $authmaps = ExternalAuthenticationHelper::getUserIdentifierFromMap($account->id());
        $to_drupal_user = (boolean) (count($authmaps));
      }
    }

    if ($direction === NULL || $direction == self::PROVISION_TO_LDAP) {
      if (property_exists($account, 'ldap_user_prov_entries') && !empty($account->get('ldap_user_prov_entries')->value)) {
        $to_ldap_entry = TRUE;
      }
    }

    if ($direction == self::PROVISION_TO_DRUPAL) {
      return $to_drupal_user;
    }
    elseif ($direction == self::PROVISION_TO_LDAP) {
      return $to_ldap_entry;
    }
    else {
      return ($to_ldap_entry || $to_drupal_user);
    }

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
    $not_associated = ExternalAuthenticationHelper::excludeUser($account);
    $processor = new LdapUserProcessor();

    if ($not_associated) {
      return;
    }

    if (is_object($account) && $account->getAccountName()) {
      // Check for first time user.
      $new_account_request = (boolean) (\Drupal::currentUser()
        ->isAnonymous() && $account->isNew());
      $already_provisioned_to_ldap = SemaphoreStorage::get('provision', $account->getAccountName());
      $already_synced_to_ldap = SemaphoreStorage::get('sync', $account->getAccountName());
      if ($already_provisioned_to_ldap || $already_synced_to_ldap || $new_account_request) {
        return;
      }
    }

    // The account is already created, so do not provisionDrupalAccount(), just
    // syncToDrupalAccount(), even if action is 'provision'.
    if ($account->isActive() && LdapConfiguration::provisionAvailableToDrupal(self::PROVISION_DRUPAL_USER_ON_USER_UPDATE_CREATE)) {
      $this->syncToDrupalAccount(self::EVENT_CREATE_DRUPAL_USER, NULL);
    }

    if ($this->provisionsLdapEntriesFromDrupalUsers()) {
      $prov_enabled = LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE);
      if ($prov_enabled) {
        $ldap_provision_entry = $processor->getProvisionRelatedLdapEntry($account);
        if (!$ldap_provision_entry) {
          $ldapProcessor = new LdapUserProcessor();
          $provision_result = $ldapProcessor->provisionLdapEntry($account);
          if ($provision_result['status'] == 'success') {
            SemaphoreStorage::set('provision', $account->getAccountName());
          }
        }
        elseif ($ldap_provision_entry) {
          $ldapProcessor = new LdapUserProcessor();
          $bool_result = $ldapProcessor->syncToLdapEntry($account);
          if ($bool_result) {
            SemaphoreStorage::set('sync', $account->getAccountName());
          }
        }
      }
    }
  }

  /**
   * Callback for hook_ENTITY_TYPE_update().
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   */
  public function drupalUserUpdated(UserInterface $account) {

    if (ExternalAuthenticationHelper::excludeUser($account)) {
      return;
    }

    // Check for provisioning to LDAP; this will normally occur on
    // hook_user_insert or other event when Drupal user is created.
    if ($this->provisionsLdapEntriesFromDrupalUsers() &&
      LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE)) {

      $already_provisioned_to_ldap = SemaphoreStorage::get('provision', $account->getAccountName());
      $already_synced_to_ldap = SemaphoreStorage::get('sync', $account->getAccountName());
      if ($already_provisioned_to_ldap || $already_synced_to_ldap) {
        return;
      }
      $processor = new LdapUserProcessor();

      $provision_result = ['status' => 'none'];
      // Check if provisioning to LDAP has already occurred this page load.
      $ldap_entry = $processor->getProvisionRelatedLdapEntry($account);
      // {.
      if (!$ldap_entry) {
        $provision_result = $processor->provisionLdapEntry($account);
        if ($provision_result['status'] == 'success') {
          SemaphoreStorage::set('provision', $account->getAccountName());
        }
      }
      // Sync if not just provisioned and enabled.
      if ($provision_result['status'] != 'success') {
        // Check if provisioning to LDAP has already occurred this page load.
        $provision_enabled = LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE);
        $ldap_entry = $processor->getProvisionRelatedLdapEntry($account);
        if ($provision_enabled && $ldap_entry) {
          $ldapProcessor = new LdapUserProcessor();
          $bool_result = $ldapProcessor->syncToLdapEntry($account);
          if ($bool_result) {
            SemaphoreStorage::set('sync', $account->getAccountName());
          }
        }
      }
    }
  }

  /**
   * Presave functionality.
   *
   * @param \Drupal\user\UserInterface $account
   *   The user account.
   */
  public function drupalUserPreSave(UserInterface $account) {
    $this->account = $account;

    if (ExternalAuthenticationHelper::excludeUser($this->account) || !$this->account->getAccountName()) {
      return;
    }

    // @TODO: Inject.
    $factory = \Drupal::service('ldap.servers');

    // Check for provisioning to Drupal and override synced user fields/props.
    if (LdapConfiguration::provisionsDrupalAccountsFromLdap() && in_array(self::EVENT_SYNC_TO_DRUPAL_USER, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
      if ($this->isUserLdapAssociated($this->account, self::PROVISION_TO_DRUPAL)) {
        $ldap_user = $factory->getUserDataFromServerByAccount($this->account, $this->config->get('drupalAcctProvisionServer'), 'ldap_user_prov_to_drupal');
        $this->server = $factory->getServerById($this->config->get('drupalAcctProvisionServer'));
        $this->applyAttributesToAccount($ldap_user, self::PROVISION_TO_DRUPAL, [self::EVENT_SYNC_TO_DRUPAL_USER]);
      }
    }
  }

  /**
   * Handle Drupal user login.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user.
   *
   * @TODO: This might be better abstracted into a separate class which
   * selectively calls DrupalUserProcessor and LdapUserProcessor, not one the
   * other.
   */
  public function drupalUserLogsIn(UserInterface $account) {
    $this->account = $account;
    if (ExternalAuthenticationHelper::excludeUser($this->account)) {
      return;
    }

    // Provision or sync to LDAP, not both.
    $provision_result = ['status' => 'none'];
    $processor = new LdapUserProcessor();
    // Provision to LDAP
    // Check for first time user.
    if (
      $this->provisionsLdapEntriesFromDrupalUsers()
      && SemaphoreStorage::get('provision', $this->account->getAccountName()) == FALSE
      && !$processor->getProvisionRelatedLdapEntry($this->account)
      && \Drupal::config('ldap_user.settings')->get('ldapEntryProvisionServer')
      && LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION)
    ) {
      $provision_result = $processor->provisionLdapEntry($this->account);
      if ($provision_result['status'] == 'success') {
        SemaphoreStorage::set('provision', $this->account->getAccountName());
      }
    }
    // Don't sync, if just provisioned.
    if (
      $this->provisionsLdapEntriesFromDrupalUsers()
      && SemaphoreStorage::get('sync', $this->account->getAccountName()) == FALSE
      && $provision_result['status'] != 'success'
      && LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION)
    ) {
      $ldapProcessor = new LdapUserProcessor();
      $bool_result = $ldapProcessor->syncToLdapEntry($this->account);
      if ($bool_result) {
        SemaphoreStorage::set('sync', $this->account->getAccountName());
      }
    }
    /** @var \Drupal\ldap_servers\ServerFactory $factory */
    $factory = \Drupal::service('ldap.servers');
    $config = \Drupal::config('ldap_user.settings')->get();

    if (LdapConfiguration::provisionsDrupalAccountsFromLdap()  && in_array(self::EVENT_SYNC_TO_DRUPAL_USER, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
      $ldap_user = $factory->getUserDataFromServerByAccount($this->account, $config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
      if ($ldap_user) {
        $this->server = $factory->getServerById($config['drupalAcctProvisionServer']);
        $this->applyAttributesToAccount($ldap_user, self::PROVISION_TO_DRUPAL, [self::EVENT_SYNC_TO_DRUPAL_USER]);
      }
      $this->saveAccount();
    }
  }

  /**
   * Handle deletion of Drupal user.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user account.
   */
  public function drupalUserDeleted(UserInterface $account) {
    // Drupal user account is about to be deleted.
    if ($this->provisionsLdapEntriesFromDrupalUsers()
      && LdapConfiguration::provisionAvailableToLdap(self::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE)
    ) {
      $ldapProcessor = new LdapUserProcessor();
      $ldapProcessor->deleteProvisionedLdapEntries($account);
    }
    ExternalAuthenticationHelper::deleteUserIdentifier($account->id());
  }

  /**
   * Apply user attributes.
   *
   * @param array $availableUserAttributes
   *   Available attributes.
   * @param array $mappings
   *   Mappings.
   * @param string $direction
   *   Synchronization direction.
   *
   * @return array
   *   All attributes applied.
   */
  private function applyUserAttributes(array $availableUserAttributes, array $mappings, $direction) {
    foreach ($mappings[$direction] as $target_token => $mapping) {
      if ($direction == self::PROVISION_TO_DRUPAL && isset($mapping['user_attr'])) {
        $key = $mapping['user_attr'];
      }
      elseif ($direction == self::PROVISION_TO_LDAP && isset($mapping['ldap_attr'])) {
        $key = $mapping['ldap_attr'];
      }
      else {
        continue;
      }

      $keys = [
        'ldap_attr',
        'user_attr',
        'convert',
        'direction',
        'enabled',
        'prov_events',
      ];

      foreach ($keys as $subKey) {
        if (isset($mapping[$subKey])) {
          $availableUserAttributes[$key][$subKey] = $mapping[$subKey];
        }
        else {
          $availableUserAttributes[$key][$subKey] = NULL;
        }
        $availableUserAttributes[$key]['config_module'] = 'ldap_user';
        $availableUserAttributes[$key]['prov_module'] = 'ldap_user';
      }
      if ($mapping['user_attr'] == 'user_tokens') {
        $availableUserAttributes['user_attr'] = $mapping['user_tokens'];
      }
    }
    return $availableUserAttributes;
  }

  /**
   * Create a Drupal user.
   *
   * @param array $ldap_user
   *   The LDAP user.
   *
   * @return bool|User
   *   User account if successful.
   */
  private function createDrupalUser(array $ldap_user) {
    $this->account->enforceIsNew();
    $this->applyAttributesToAccount($ldap_user, self::PROVISION_TO_DRUPAL, [self::EVENT_CREATE_DRUPAL_USER]);
    $tokens = ['%drupal_username' => $this->account->get('name')];
    if (empty($this->account->getAccountName())) {
      drupal_set_message(t('User account creation failed because of invalid, empty derived Drupal username.'), 'error');
      \Drupal::logger('ldap_user')
        ->error('Failed to create Drupal account %drupal_username because Drupal username could not be derived.', []);
      return FALSE;
    }
    if (!$mail = $this->account->getEmail()) {
      drupal_set_message(t('User account creation failed because of invalid, empty derived email address.'), 'error');
      \Drupal::logger('ldap_user')
        ->error('Failed to create Drupal account %drupal_username because email address could not be derived by LDAP User module', []);
      return FALSE;
    }

    if ($account_with_same_email = user_load_by_mail($mail)) {
      \Drupal::logger('ldap_user')
        ->error('LDAP user %drupal_username has email address (%email) conflict with a Drupal user %duplicate_name', [
          '%email' => $mail,
          '%duplicate_name' => $account_with_same_email->name,
        ]
      );
      drupal_set_message(t('Another user already exists in the system with the same email address. You should contact the system administrator in order to solve this conflict.'), 'error');
      return FALSE;
    }
    $this->saveAccount();
    if (!$this->account) {
      drupal_set_message(t('User account creation failed because of system problems.'), 'error');
    }
    else {
      ExternalAuthenticationHelper::setUserIdentifier($this->account, $this->account->getAccountName());
    }
    return $this->account;
  }

  /**
   * Update Drupal user from PUID.
   *
   * @param array $ldap_user
   *   The LDAP user.
   * @param \Drupal\user\UserInterface $accountFromPuid
   *   The account from the PUID.
   *
   * @return bool|\Drupal\user\entity\User|\Drupal\user\UserInterface
   *   Returns a user if successful.
   *
   * @todo: Remove return here, we don't want to pass the user around.
   */
  private function updateExistingAccountByPersistentUid(array $ldap_user, UserInterface $accountFromPuid) {
    $this->account = $accountFromPuid;
    // 1. correct username and authmap.
    $this->applyAttributesToAccount($ldap_user, self::PROVISION_TO_DRUPAL, [self::EVENT_SYNC_TO_DRUPAL_USER]);
    $this->account = $accountFromPuid;
    $this->saveAccount();
    // Update the identifier table.
    ExternalAuthenticationHelper::setUserIdentifier($this->account, $this->account->getAccountName());

    // 2. attempt sync if appropriate for current context.
    if ($this->account) {
      $this->syncToDrupalAccount(self::EVENT_SYNC_TO_DRUPAL_USER, $ldap_user);
    }
    return $this->account;
  }

  /**
   * Process user picture from LDAP entry.
   *
   * @param array $ldap_entry
   *   The LDAP entry.
   *
   * @return bool|\Drupal\file\Entity\File
   *   Drupal file object image user's thumbnail or FALSE if none present or
   *   an error occurs.
   */
  private function userPictureFromLdapEntry(array $ldap_entry) {
    if ($ldap_entry && $this->server->get('picture_attr')) {
      // Check if LDAP entry has been provisioned.
      if (isset($ldap_entry[$this->server->get('picture_attr')][0])) {
        $ldapUserPicture = $ldap_entry[$this->server->get('picture_attr')][0];
      }
      else {
        // No picture present.
        return FALSE;
      }

      if (!$this->account || $this->account->isAnonymous() || $this->account->id() == 1) {
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
    $file_name = uniqid();
    $unmanaged_file = file_directory_temp() . '/' . $file_name;
    file_put_contents($unmanaged_file, $ldapUserPicture);
    $image_type = exif_imagetype($unmanaged_file);
    $extension = image_type_to_extension($image_type, FALSE);
    unlink($unmanaged_file);
    $fieldSettings = $field->getFieldDefinition()->getItemDefinition()->getSettings();
    $token_service = \Drupal::token();

    $directory = $token_service->replace($fieldSettings['file_directory']);

    if (!is_dir(\Drupal::service('file_system')->realpath('public://' . $directory))) {
      \Drupal::service('file_system')->mkdir('public://' . $directory, NULL, TRUE);
    }

    $managed_file = file_save_data($ldapUserPicture, 'public://' . $directory . '/' . $file_name . '.' . $extension);

    $validators = [
      'file_validate_is_image' => [],
      'file_validate_image_resolution' => [$fieldSettings['max_resolution']],
      'file_validate_size' => [$fieldSettings['max_filesize']],
    ];

    if ($managed_file && file_validate($managed_file, $validators)) {
      return ['target_id' => $managed_file->id()];
    }
    else {
      // Uploaded and unfit files will be automatically garbage collected.
      return FALSE;
    }
  }

  /**
   * TODO: Move to Drupal User Processor.
   */
  private function provisionsLdapEntriesFromDrupalUsers() {
    if (\Drupal::config('ldap_user.settings')->get('ldapEntryProvisionServer') &&
      count(array_filter(array_values(\Drupal::config('ldap_user.settings')->get('ldapEntryProvisionTriggers')))) > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Return context to provision direction.
   *
   * Converts the more general ldap_context string to its associated LDAP user
   * prov direction.
   *
   * @param string|null $ldapContext
   *   The relevant context.
   *
   * @return string
   *   The provisioning direction.
   */
  private function ldapContextToProvDirection($ldapContext = NULL) {

    switch ($ldapContext) {
      case 'ldap_user_prov_to_drupal':
        $result = self::PROVISION_TO_DRUPAL;
        break;

      case 'ldap_user_prov_to_ldap':
      case 'ldap_user_delete_drupal_user':
        $result = self::PROVISION_TO_LDAP;
        break;

      // Provisioning is can happen in both directions in most contexts.
      case 'ldap_user_insert_drupal_user':
      case 'ldap_user_update_drupal_user':
      case 'ldap_authentication_authenticate':
      case 'ldap_user_disable_drupal_user':
        $result = self::PROVISION_TO_ALL;
        break;

      default:
        $result = self::PROVISION_TO_ALL;
        break;
    }
    return $result;
  }

}

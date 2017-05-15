<?php

namespace Drupal\ldap_user\Processor;

use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SemaphoreStorage;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\user\entity\User;

/**
 *
 */
class DrupalUserProcessor {

  private $config;

  /**
   *
   */
  public function __construct() {
    $this->config = \Drupal::config('ldap_user.settings')->get();
  }

  /**
   * Set LDAP associations of a Drupal account by altering user fields.
   *
   * @param string $drupal_username
   *
   * @return boolean TRUE on success, FALSE on error or failure because of invalid user or LDAP accounts
   */
  public function ldapAssociateDrupalAccount($drupal_username) {
    if ($this->config['drupalAcctProvisionServer']) {
      $factory = \Drupal::service('ldap.servers');
      /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
      $ldap_server = $factory->getServerByIdEnabled($this->config['drupalAcctProvisionServer']);
      $account = user_load_by_name($drupal_username);
      if (!$account) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because account not found', ['%drupal_username' => $drupal_username]);
        return FALSE;
      }

      $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($drupal_username);
      if (!$ldap_user) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because corresponding LDAP entry not found', ['%drupal_username' => $drupal_username]);
        return FALSE;
      }

      $ldap_user_puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      if ($ldap_user_puid) {
        $account->set('ldap_user_puid', $ldap_user_puid);
      }
      $account->set('ldap_user_puid_property', $ldap_server->get('unique_persistent_attr'));
      $account->set('ldap_user_puid_sid', $ldap_server->id());
      $account->set('ldap_user_current_dn', $ldap_user['dn']);
      $account->set('ldap_user_last_checked', time());
      $account->set('ldap_user_ldap_exclude', 0);
      $account->save();
      $processor = new DrupalUserProcessor();
      $processor->syncToDrupalAccount($account, LdapConfiguration::$eventCreateDrupalUser, $ldap_user, TRUE);

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
   * @param bool $save
   *
   * @return bool|\Drupal\user\entity\User Return the user on success or FALSE on any problem.
   * Return the user on success or FALSE on any problem.
   */
  public function provisionDrupalAccount($userData, $save = TRUE) {

    $tokens = [];
    $account = User::create($userData);
    $ldapUser = FALSE;

    /* @var \Drupal\ldap_servers\ServerFactory $factory */
    $factory = \Drupal::service('ldap.servers');

    // Get an LDAP user from the LDAP server.
    $tokens['%username'] = $userData['name'];
    if ($this->config['drupalAcctProvisionServer']) {
      $ldapUser = $factory->getUserDataFromServerByIdentifier($userData['name'], $this->config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
    }
    // Still no LDAP user.
    if (!$ldapUser) {
      if (\Drupal::config('ldap_help.settings')->get('watchdog_detail')) {
        \Drupal::logger('ldap_user')->debug('%username : failed to find associated ldap entry for username in provision.', []);
      }
      return FALSE;
    }

    $server = $factory->getServerByIdEnabled($this->config['drupalAcctProvisionServer']);

    // If we don't have an account name already we should set one.
    if (!$account->getUsername()) {
      $account->set('name', $ldapUser[$server->get('user_attr')]);
      $tokens['%username'] = $account->getUsername();
    }

    // Can we get details from an LDAP server?
    $params = [
      'account' => $account,
      'user_values' => $userData,
      'prov_event' => LdapConfiguration::$eventCreateDrupalUser,
      'module' => 'ldap_user',
      'function' => 'provisionDrupalAccount',
      'direction' => LdapConfiguration::PROVISION_TO_DRUPAL,
    ];

    \Drupal::moduleHandler()->alter('ldap_entry', $ldapUser, $params);

    /**
     * Look for existing Drupal account with the same PUID. If found, update
     * that user instead of creating a new user.
     */
    $puid = $server->userPuidFromLdapEntry($ldapUser['attr']);
    $accountFromPuid = ($puid) ? $server->userAccountFromPuid($puid) : FALSE;
    if ($accountFromPuid) {
      return $this->updateExistingDrupalAccount($server, $ldapUser, $accountFromPuid, $save);
    }
    else {
      return $this->createDrupalUser($server, $ldapUser, $account, $save);
    }
  }

  /**
   * Populate $user edit array (used in hook_user_save, hook_user_update, etc)
   * ... should not assume all attributes are present in ldap entry.
   *
   * @param array $ldap_user
   *   Ldap entry.
   * @param \Drupal\user\UserInterface $account
   *   see hook_user_save, hook_user_update, etc.
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   * @param int $direction
   * @param array $prov_events
   */
  public function applyAttributesToAccount($ldap_user, &$account, $ldap_server, $direction = NULL, $prov_events = NULL) {
    if ($direction == NULL) {
      $direction = LdapConfiguration::PROVISION_TO_DRUPAL;
    }
    // Need array of user fields and which direction and when they should be synced.
    if (!$prov_events) {
      $prov_events = LdapConfiguration::getAllEvents();
    }

    $processor = new SyncMappingHelper();
    $mail_synced = $processor->isSynced('[property.mail]', $prov_events, $direction);
    if (!$account->getEmail() && $mail_synced) {
      $derived_mail = $ldap_server->userEmailFromLdapEntry($ldap_user['attr']);
      if ($derived_mail) {
        $account->set('mail', $derived_mail);
      }
    }

    $drupal_username = $ldap_server->userUsernameFromLdapEntry($ldap_user['attr']);
    if ($processor->isSynced('[property.picture]', $prov_events, $direction)) {

      $picture = $ldap_server->userPictureFromLdapEntry($ldap_user['attr'], $account);

      if ($picture) {
        $account->set('user_picture', $picture);
      }
    }

    if ($processor->isSynced('[property.name]', $prov_events, $direction) && !$account->getUsername() && $drupal_username) {
      $account->set('name', $drupal_username);
    }

    // Only fired on LdapConfiguration::$eventCreateDrupalUser. Shouldn't it respect the checkbox on the sync form?
    if ($direction == LdapConfiguration::PROVISION_TO_DRUPAL && in_array(LdapConfiguration::$eventCreateDrupalUser, $prov_events)) {
      $derived_mail = $ldap_server->userEmailFromLdapEntry($ldap_user['attr']);
      if (!$account->getEmail()) {
        $account->set('mail', $derived_mail);
      }
      if (!$account->getPassword()) {
        $account->set('pass', user_password(20));
      }
      if (!$account->getInitialEmail()) {
        $account->set('init', $derived_mail);
      }
      if (!$account->isBlocked()) {
        $account->set('status', 1);
      }

    }

    /**
     * basic $user ldap fields
     */
    $processor = new SyncMappingHelper();

    if ($processor->isSynced('[field.ldap_user_puid]', $prov_events, $direction)) {
      $ldap_user_puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      if ($ldap_user_puid) {
        $account->set('ldap_user_puid', $ldap_user_puid);
      }
    }
    if ($processor->isSynced('[field.ldap_user_puid_property]', $prov_events, $direction)) {
      $account->set('ldap_user_puid_property', $ldap_server->get('unique_persistent_attr'));
    }
    if ($processor->isSynced('[field.ldap_user_puid_sid]', $prov_events, $direction)) {
      $account->set('ldap_user_puid_sid', $ldap_server->id());
    }
    if ($processor->isSynced('[field.ldap_user_current_dn]', $prov_events, $direction)) {
      $account->set('ldap_user_current_dn', $ldap_user['dn']);
    }

    // Get any additional mappings.
    $mappings = $processor->getSyncMappings($direction, $prov_events);

    // Loop over the mappings.
    foreach ($mappings as $user_attr_key => $field_detail) {

      // Make sure this mapping is relevant to the sync context.
      if (!$processor->isSynced($user_attr_key, $prov_events, $direction)) {
        continue;
      }
      /**
       * if "convert from binary is selected" and no particular method is in token,
       * default to binaryConversiontoString() function
       */
      if ($field_detail['convert'] && strpos($field_detail['ldap_attr'], ';') === FALSE) {
        $field_detail['ldap_attr'] = str_replace(']', ';binary]', $field_detail['ldap_attr']);
      }
      $tokenHelper = new TokenProcessor();
      $value = $tokenHelper->tokenReplace($ldap_user['attr'], $field_detail['ldap_attr'], 'ldap_entry');
      list($value_type, $value_name, $value_instance) = $tokenHelper->parseUserAttributeNames($user_attr_key);

      // $value_instance not used, may have future use case.
      // Are we dealing with a field?
      if ($value_type == 'field' || $value_type == 'property') {
        $account->set($value_name, $value);
      }
    }

    $context = ['ldap_server' => $ldap_server, 'prov_events' => $prov_events];
    \Drupal::moduleHandler()->alter('ldap_user_edit_user', $account, $ldap_user, $context);

    // Don't let empty 'name' value pass for user.
    if (empty($account->getUsername())) {
      $account->set('name', $ldap_user[$ldap_server->get('user_attr')]);
    }

    // Set ldap_user_last_checked.
    $account->set('ldap_user_last_checked', time());
  }

  /**
   * Given a drupal account, query ldap and get all user fields and create user account.
   *
   * @param \Drupal\user\entity\UserInterface $account
   * @param int $prov_event
   * @param array $ldap_user
   *   A user's ldap entry. Passed to avoid re-querying LDAP in cases where already present.
   * @param bool $save
   *   Indicating if drupal user should be saved.  generally depends on where function is called from.
   *
   * @return bool|UserInterface
   *   User account if $save is true, otherwise return TRUE.
   */
  public function syncToDrupalAccount($account, $prov_event = NULL, $ldap_user = NULL, $save = FALSE) {
    if ($prov_event == NULL) {
      $prov_event = LdapConfiguration::$eventSyncToDrupalUser;
    }

    if ((!$ldap_user && !method_exists($account, 'getUsername')) ||
      (!$account && $save)) {
      \Drupal::logger('ldap_user')->notice('Invalid selection passed to syncToDrupalAccount.');
      return FALSE;
    }

    if (!$ldap_user && $this->config['drupalAcctProvisionServer']) {
      $factory = \Drupal::service('ldap.servers');
      /* @var ServerFactory $factory */
      $ldap_user = $factory->getUserDataFromServerByAccount($account, $this->config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
    }

    if (!$ldap_user) {
      return FALSE;
    }

    if ($this->config['drupalAcctProvisionServer']) {
      $factory = \Drupal::service('ldap.servers');
      $ldap_server = $factory->getServerById($this->config['drupalAcctProvisionServer']);
      $this->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::PROVISION_TO_DRUPAL, [$prov_event]);
    }

    if ($save) {
      $account->save();
      return $account;
    }
    else {
      return TRUE;
    }
  }

  /**
   * Set flag to exclude user from LDAP association.
   *
   * @param string $drupal_username
   *
   * @return boolean TRUE on success, FALSE on error or failure because of invalid user
   */
  public function ldapExcludeDrupalAccount($drupal_username) {
    $account = user_load_by_name($drupal_username);
    if (!$account) {
      \Drupal::logger('ldap_user')->error('Failed to exclude user from LDAP association because drupal account %drupal_username was not found', ['%drupal_username' => $drupal_username]);
      return FALSE;
    }

    $account->set('ldap_user_ldap_exclude', 1);
    $account->save();
    return (boolean) $account;
  }

  /**
   * @param $attributes
   * @param $params
   * @return mixed
   */
  public function alterUserAttributes($attributes, $params) {
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
        // Add the attributes required by the user configuration when provisioning drupal users.
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
        $direction = empty($params['direction']) ? LdapConfiguration::ldapContextToProvDirection($ldap_context) : $params['direction'];
        $helper = new SyncMappingHelper();
        $attributes_required_by_user_module_mappings = $helper->getLdapUserRequiredAttributes($direction, $ldap_context);
        $attributes = array_merge($attributes_required_by_user_module_mappings, $attributes);
        return $attributes;

      }
    }
    return $attributes;
  }

  /**
   * @param $availableUserAttributes
   * @param $params
   * @return array
   */
  public function alterLdapUserAttributes($availableUserAttributes, $params) {
    if (isset($params['direction'])) {
      $direction = $params['direction'];
    }
    else {
      $direction = LdapConfiguration::PROVISION_TO_NONE;
    }

    if ($direction == LdapConfiguration::PROVISION_TO_LDAP) {
      $availableUserAttributes['[property.name]'] = [
        'name' => 'Property: Username',
        'source' => '',
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      $availableUserAttributes['[property.mail]'] = [
        'name' => 'Property: Email',
        'source' => '',
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      $availableUserAttributes['[property.picture]'] = [
        'name' => 'Property: picture',
        'source' => '',
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      $availableUserAttributes['[property.uid]'] = [
        'name' => 'Property: Drupal User Id (uid)',
        'source' => '',
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

    }

    // 1. Drupal user properties
    // 1.a make sure empty array are present so array + function works.
    foreach (['property.status', 'property.timezone', 'property.signature'] as $i => $property_id) {
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
        'name' => t('Field') . ': ' . $field_instance->getLabel(),
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

    if ($direction == LdapConfiguration::PROVISION_TO_LDAP) {
      $availableUserAttributes['[password.random]'] = [
        'name' => 'Password: Random password',
        'source' => '',
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      // Use user password when available fall back to random pwd.
      $availableUserAttributes['[password.user-random]'] = [
        'name' => 'Password: Plain user password or random',
        'source' => '',
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

      // use user password, do not modify if unavailable
      $availableUserAttributes['[password.user-only]'] = [
        'name' => 'Password: Plain user password',
        'source' => '',
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'enabled' => TRUE,
        'prov_events' => [
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ],
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      ];

    }

    $mappings = \Drupal::config('ldap_user.settings')->get('ldapUserSyncMappings');

    // This is where need to be added to arrays.
    if (!empty($mappings[$direction])) {
      $availableUserAttributes = $this->applyUserAttributes($availableUserAttributes, $mappings, $direction);
    }

    return [$availableUserAttributes, $params];
  }

  /**
   * @param object $account
   *   as drupal user object.
   * @param enum int $direction
   *   indicating which directions to test for association
   *   LdapConfiguration::PROVISION_TO_DRUPAL signifies test if drupal account has been provisioned or synced from ldap
   *   LdapConfiguration::PROVISION_TO_LDAP signifies test if ldap account has been provisioned or synced from drupal
   *   NULL signifies check for either direction.
   *
   * @return boolean if user is ldap associated
   */
  public function isUserLdapAssociated($account, $direction = NULL) {

    $to_drupal_user = FALSE;
    $to_ldap_entry = FALSE;

    if ($direction === NULL || $direction == LdapConfiguration::PROVISION_TO_DRUPAL) {
      if (property_exists($account, 'ldap_user_current_dn') && !empty($account->get('ldap_user_current_dn')->value)) {
        $to_drupal_user = TRUE;
      }
      elseif ($account->id()) {
        $authmaps = ExternalAuthenticationHelper::getUserIdentifierFromMap($account->id());
        $to_drupal_user = (boolean) (count($authmaps));
      }
    }

    if ($direction === NULL || $direction == LdapConfiguration::PROVISION_TO_LDAP) {
      if (property_exists($account, 'ldap_user_prov_entries') && !empty($account->get('ldap_user_prov_entries')->value)) {
        $to_ldap_entry = TRUE;
      }
    }

    if ($direction == LdapConfiguration::PROVISION_TO_DRUPAL) {
      return $to_drupal_user;
    }
    elseif ($direction == LdapConfiguration::PROVISION_TO_LDAP) {
      return $to_ldap_entry;
    }
    else {
      return ($to_ldap_entry || $to_drupal_user);
    }

  }

  /**
   * @param \Drupal\user\UserInterface $account
   */
  public function newDrupalUserCreated($account) {

    $not_associated = ExternalAuthenticationHelper::excludeUser($account);
    $processor = new LdapUserProcessor();

    if ($not_associated) {
      return;
    }

    if (is_object($account) && $account->getUsername()) {
      // Check for first time user.
      $new_account_request = (boolean) (\Drupal::currentUser()
        ->isAnonymous() && $account->isNew());
      $already_provisioned_to_ldap = SemaphoreStorage::get('provision', $account->getUsername());
      $already_synced_to_ldap = SemaphoreStorage::get('sync', $account->getUsername());
      if ($already_provisioned_to_ldap || $already_synced_to_ldap || $new_account_request) {
        return;
      }
    }

    /**
     * The account is already created, so do not provisionDrupalAccount(), just
     * syncToDrupalAccount(), even if action is 'provision'.
     */
    if ($account->isActive() && LdapConfiguration::provisionAvailableToDrupal(LdapConfiguration::PROVISION_DRUPAL_USER_ON_USER_UPDATE_CREATE)) {
      $this->syncToDrupalAccount($account, LdapConfiguration::$eventCreateDrupalUser, NULL, TRUE);
    }

    if (LdapConfiguration::provisionsLdapEntriesFromDrupalUsers()) {
      $prov_enabled = LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE);
      if ($prov_enabled) {
        $ldap_provision_entry = $processor->getProvisionRelatedLdapEntry($account);
        if (!$ldap_provision_entry) {
          $ldapProcessor = new LdapUserProcessor();
          $provision_result = $ldapProcessor->provisionLdapEntry($account);
          if ($provision_result['status'] == 'success') {
            SemaphoreStorage::set('provision', $account->getUsername());
          }
        }
        elseif ($ldap_provision_entry) {
          $ldapProcessor = new LdapUserProcessor();
          $bool_result = $ldapProcessor->syncToLdapEntry($account);
          if ($bool_result) {
            SemaphoreStorage::set('sync', $account->getUsername());
          }
        }
      }
    }
  }

  /**
   * @param \Drupal\user\UserInterface $account
   */
  public function drupalUserUpdated($account) {

    if (ExternalAuthenticationHelper::excludeUser($account)) {
      return;
    }

    // Check for provisioning to LDAP; this will normally occur on hook_user_insert or other event when drupal user is created.
    if (LdapConfiguration::provisionsLdapEntriesFromDrupalUsers() &&
      LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE)) {

      $already_provisioned_to_ldap = SemaphoreStorage::get('provision', $account->getUsername());
      $already_synced_to_ldap = SemaphoreStorage::get('sync', $account->getUsername());
      if ($already_provisioned_to_ldap || $already_synced_to_ldap) {
        return;
      }
      $processor = new LdapUserProcessor();

      $provision_result = ['status' => 'none'];
      // Always check if provisioning to ldap has already occurred this page load.
      $ldap_entry = $processor->getProvisionRelatedLdapEntry($account);
      // {.
      if (!$ldap_entry) {
        $provision_result = $processor->provisionLdapEntry($account);
        if ($provision_result['status'] == 'success') {
          SemaphoreStorage::set('provision', $account->getUsername());
        }
      }
      // Sync if not just provisioned and enabled.
      if ($provision_result['status'] != 'success') {
        // Always check if provisioing to ldap has already occurred this page load.
        $provision_enabled = LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_UPDATE_CREATE);
        $ldap_entry = $processor->getProvisionRelatedLdapEntry($account);
        if ($provision_enabled && $ldap_entry) {
          $ldapProcessor = new LdapUserProcessor();
          $bool_result = $ldapProcessor->syncToLdapEntry($account);
          if ($bool_result) {
            SemaphoreStorage::set('sync', $account->getUsername());
          }
        }
      }
    }
  }

  /**
   * @param \Drupal\user\UserInterface $account
   */
  public function drupalUserPreSave($account) {

    if (ExternalAuthenticationHelper::excludeUser($account) || !$account->getUsername()) {
      return;
    }

    $factory = \Drupal::service('ldap.servers');
    $config = \Drupal::config('ldap_user.settings')->get();
    $processor = new DrupalUserProcessor();

    // Check for provisioning to drupal and override synced user fields/props.
    if (LdapConfiguration::provisionsDrupalAccountsFromLdap() && in_array(LdapConfiguration::$eventSyncToDrupalUser, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
      if ($processor->isUserLdapAssociated($account, LdapConfiguration::PROVISION_TO_DRUPAL)) {
        $ldap_user = $factory->getUserDataFromServerByAccount($account, $config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
        $ldap_server = $factory->getServerById($config['drupalAcctProvisionServer']);
        $processor->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::PROVISION_TO_DRUPAL, [LdapConfiguration::$eventSyncToDrupalUser]);
      }
    }
  }

  /**
   * @param \Drupal\user\UserInterface $account
   */
  public function drupalUserLogsIn($account) {
    if (ExternalAuthenticationHelper::excludeUser($account)) {
      return;
    }

    // Provision or sync to ldap, not both.
    $provision_result = ['status' => 'none'];
    $processor = new LdapUserProcessor();
    // Provision to ldap
    // if ($account->access == 0 && $account->login != 0) {} check for first time user.
    if (
      LdapConfiguration::provisionsLdapEntriesFromDrupalUsers()
      && SemaphoreStorage::get('provision', $account->getUsername()) == FALSE
      && !$processor->getProvisionRelatedLdapEntry($account)
      && \Drupal::config('ldap_user.settings')->get('ldapEntryProvisionServer')
      && LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION)
    ) {
      $provision_result = $processor->provisionLdapEntry($account);
      if ($provision_result['status'] == 'success') {
        SemaphoreStorage::set('provision', $account->getUsername());
      }
    }
    // don't sync if just provisioned.
    if (
      LdapConfiguration::provisionsLdapEntriesFromDrupalUsers()
      && SemaphoreStorage::get('sync', $account->getUsername()) == FALSE
      && $provision_result['status'] != 'success'
      && LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_AUTHENTICATION)
    ) {
      $ldapProcessor = new LdapUserProcessor();
      $bool_result = $ldapProcessor->syncToLdapEntry($account);
      if ($bool_result) {
        SemaphoreStorage::set('sync', $account->getUsername());
      }
    }
    /** @var \Drupal\ldap_servers\Entity\ServerFactory $factory */
    $factory = \Drupal::service('ldap.servers');
    $config = \Drupal::config('ldap_user.settings')->get();

    if (LdapConfiguration::provisionsDrupalAccountsFromLdap()  && in_array(LdapConfiguration::$eventSyncToDrupalUser, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
      $ldap_user = $factory->getUserDataFromServerByAccount($account, $config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
      if ($ldap_user) {
        $ldap_server = $factory->getServerById($config['drupalAcctProvisionServer']);
        $processor = new DrupalUserProcessor();
        $processor->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::PROVISION_TO_DRUPAL, [LdapConfiguration::$eventSyncToDrupalUser]);
      }
      $account->save();
    }
  }

  /**
   * @param \Drupal\user\UserInterface $account
   */
  public function drupalUserDeleted($account) {
    // Drupal user account is about to be deleted.
    if (LdapConfiguration::provisionsLdapEntriesFromDrupalUsers()
      && LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::PROVISION_LDAP_ENTRY_ON_USER_ON_USER_DELETE)
    ) {
      $ldapProcessor = new LdapUserProcessor();
      $ldapProcessor->deleteProvisionedLdapEntries($account);
    }
    ExternalAuthenticationHelper::deleteUserIdentifier($account->id());
  }

  /**
   * @param $availableUserAttributes
   * @param $mappings
   * @param $direction
   * @return mixed
   */
  private function applyUserAttributes($availableUserAttributes, $mappings, $direction) {
    foreach ($mappings[$direction] as $target_token => $mapping) {
      if ($direction == LdapConfiguration::PROVISION_TO_DRUPAL && isset($mapping['user_attr'])) {
        $key = $mapping['user_attr'];
      }
      elseif ($direction == LdapConfiguration::PROVISION_TO_LDAP && isset($mapping['ldap_attr'])) {
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
   * @param $ldap_server
   * @param $ldap_user
   * @param $account
   * @param $save
   * @return bool|User
   */
  private function createDrupalUser($ldap_server, $ldap_user, User $account, $save = TRUE) {
    $account->enforceIsNew();
    $this->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::PROVISION_TO_DRUPAL, [LdapConfiguration::$eventCreateDrupalUser]);
    $tokens = ['%drupal_username' => $account->get('name')];
    if (empty($account->getUsername())) {
      drupal_set_message(t('User account creation failed because of invalid, empty derived Drupal username.'), 'error');
      \Drupal::logger('ldap_user')
        ->error('Failed to create Drupal account %drupal_username because drupal username could not be derived.', []);
      return FALSE;
    }
    if (!$mail = $account->getEmail()) {
      drupal_set_message(t('User account creation failed because of invalid, empty derived email address.'), 'error');
      \Drupal::logger('ldap_user')
        ->error('Failed to create Drupal account %drupal_username because email address could not be derived by LDAP User module', []);
      return FALSE;
    }

    if ($account_with_same_email = user_load_by_mail($mail)) {
      $tokens['%email'] = $mail;
      $tokens['%duplicate_name'] = $account_with_same_email->name;
      \Drupal::logger('ldap_user')->error('LDAP user %drupal_username has email address
            (%email) conflict with a drupal user %duplicate_name', []);
      drupal_set_message(t('Another user already exists in the system with the same email address. You should contact the system administrator in order to solve this conflict.'), 'error');
      return FALSE;
    }
    if ($save == TRUE) {
      $account->save();
    }
    if (!$account) {
      drupal_set_message(t('User account creation failed because of system problems.'), 'error');
    }
    else {
      ExternalAuthenticationHelper::setUserIdentifier($account, $account->getUsername());
    }
    return $account;
  }

  /**
   * @param $ldap_server
   * @param $ldap_user
   * @param \Drupal\user\UserInterface $accountFromPuid
   * @param $save
   *
   * @return bool|\Drupal\user\entity\User|\Drupal\user\UserInterface
   */
  private function updateExistingDrupalAccount($ldap_server, $ldap_user, $accountFromPuid, $save) {
    // 1. correct username and authmap.
    $this->applyAttributesToAccount($ldap_user, $accountFromPuid, $ldap_server, LdapConfiguration::PROVISION_TO_DRUPAL, [LdapConfiguration::$eventSyncToDrupalUser]);
    $account = $accountFromPuid;
    if ($save == TRUE) {
      $account->save();
    }
    // Update the identifier table.
    ExternalAuthenticationHelper::setUserIdentifier($account, $account->getUsername());

    // 2. attempt sync if appropriate for current context.
    if ($account) {
      $account = $this->syncToDrupalAccount($account, LdapConfiguration::$eventSyncToDrupalUser, $ldap_user, TRUE);
    }
    return $account;
  }

}

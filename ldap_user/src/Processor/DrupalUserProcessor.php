<?php

namespace Drupal\ldap_user\Processor;


use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_servers\ServerFactory;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SemaphoreStorage;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\user\entity\User;
use Drupal\user\UserInterface;

/**
 *
 */
class DrupalUserProcessor {

  private $config;

  /**
   *
   */
  public function __construct() {
    $this->config = \Drupal::config('ldap_user.settings')->get('ldap_user_conf');
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
      /** @var Server $ldap_server */
      $ldap_server = $factory->getServerByIdEnabled($this->config['drupalAcctProvisionServer']);
      $account = user_load_by_name($drupal_username);
      if (!$account) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because account not found', array('%drupal_username' => $drupal_username));
        return FALSE;
      }

      $ldap_user = $ldap_server->userUserNameToExistingLdapEntry($drupal_username);
      if (!$ldap_user) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because corresponding LDAP entry not found', array('%drupal_username' => $drupal_username));
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
   * Given a drupal account, query LDAP and get all user fields and save the
   * user account.
   *
   * @param User|bool $account
   *   Drupal account object or null.
   *   Todo: Fix default value of false or correct comment.
   * @param array $user_values
   *   A keyed array normally containing 'name' and optionally more.
   * @param array $ldap_user
   *   User's ldap entry. Passed to avoid requerying ldap in cases where already
   *   present.
   * @param bool $save
   *   Indicating if Drupal user should be saved. Generally depends on where
   *   function is called from and if the result of the save is true.
   *   Todo: Fix architecture here.
   *
   * @return bool|User
   *   Return TRUE on success or FALSE on any problem.
   */
  public function provisionDrupalAccount($account = FALSE, $user_values, $ldap_user = NULL, $save = TRUE) {

    $tokens = array();
    /**
     * @TODO: Add error catching for conflicts.
     * Conflicts should be checked before calling this function.
     */

    if (!$account) {
      $account = \Drupal::entityManager()->getStorage('user')->create($user_values);
    }
    $account->enforceIsNew();

    // Should pass in an LDAP record or a username.
    if (!$ldap_user && !isset($user_values['name'])) {
      return FALSE;
    }
    /* @var ServerFactory $factory */
    $factory = \Drupal::service('ldap.servers');

    // Get an LDAP user from the LDAP server.
    if (!$ldap_user) {
      $tokens['%username'] = $user_values['name'];
      if ($this->config['drupalAcctProvisionServer']) {
        $ldap_user = $factory->getUserDataFromServerByIdentifier($user_values['name'], $this->config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
      }
      // Still no LDAP user.
      if (!$ldap_user) {
        if (\Drupal::config('ldap_help.settings')->get('watchdog_detail')) {
          \Drupal::logger('ldap_user')->debug('%username : failed to find associated ldap entry for username in provision.', []);
        }
        return FALSE;
      }
    }

    // If we don't have an account name already we should set one.
    if (!$account->getUsername()) {
      $ldap_server = $factory->getServerByIdEnabled($this->config['drupalAcctProvisionServer']);
      $account->set('name', $ldap_user[$ldap_server->get('user_attr')]);
      $tokens['%username'] = $account->getUsername();
    }

    // Can we get details from an LDAP server?
    if ($this->config['drupalAcctProvisionServer']) {

      $ldap_server = $factory->getServerByIdEnabled($this->config['drupalAcctProvisionServer']);

      $params = array(
        'account' => $account,
        'user_values' => $user_values,
        'prov_event' => LdapConfiguration::$eventCreateDrupalUser,
        'module' => 'ldap_user',
        'function' => 'provisionDrupalAccount',
        'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
      );

      \Drupal::moduleHandler()->alter('ldap_entry', $ldap_user, $params);

      // Look for existing drupal account with same puid.  if so update username and attempt to sync in current context.
      $puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      // FIXME: The entire account2 operation is broken.
      $account2 = ($puid) ? $ldap_server->userUserEntityFromPuid($puid) : FALSE;

      // Sync drupal account, since drupal account exists.
      if ($account2) {
        // 1. correct username and authmap.
        /** @var User $account2 */
        $this->applyAttributesToAccount($ldap_user, $account2, $ldap_server, LdapConfiguration::$provisioningDirectionToDrupalUser, array(LdapConfiguration::$eventSyncToDrupalUser));
        $account = $account2;
        $account->save();
        // Update the identifier table.
        ExternalAuthenticationHelper::setUserIdentifier($account, $account->getUsername());

        // 2. attempt sync if appropriate for current context.
        if ($account) {
          $account = $this->syncToDrupalAccount($account, LdapConfiguration::$eventSyncToDrupalUser, $ldap_user, TRUE);
        }
        return $account;
      }
      // Create drupal account.
      else {
        $this->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::$provisioningDirectionToDrupalUser, array(LdapConfiguration::$eventCreateDrupalUser));
        if ($save) {
          $tokens = array('%drupal_username' => $account->get('name'));
          if (empty($account->getUsername())) {
            drupal_set_message(t('User account creation failed because of invalid, empty derived Drupal username.'), 'error');
            \Drupal::logger('ldap_user')->error('Failed to create Drupal account %drupal_username because drupal username could not be derived.', []);
            return FALSE;
          }
          if (!$mail = $account->getEmail()) {
            drupal_set_message(t('User account creation failed because of invalid, empty derived email address.'), 'error');
            \Drupal::logger('ldap_user')->error('Failed to create Drupal account %drupal_username because email address could not be derived by LDAP User module', []);
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
          $account->save();
          if (!$account) {
            drupal_set_message(t('User account creation failed because of system problems.'), 'error');
          }
          else {
            ExternalAuthenticationHelper::setUserIdentifier($account, $account->getUsername());
          }
          return $account;
        }
        return TRUE;
      }
    }
  }

  /**
   * Populate $user edit array (used in hook_user_save, hook_user_update, etc)
   * ... should not assume all attributes are present in ldap entry.
   *
   * @param array $ldap_user
   *    Ldap entry.
   * @param UserInterface $account
   *   see hook_user_save, hook_user_update, etc.
   * @param Server $ldap_server
   * @param int $direction
   * @param array $prov_events
   */
  public function applyAttributesToAccount($ldap_user, &$account, $ldap_server, $direction = NULL, $prov_events = NULL) {
    if ($direction == NULL) {
      $direction = LdapConfiguration::$provisioningDirectionToDrupalUser;
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
    if ($direction == LdapConfiguration::$provisioningDirectionToDrupalUser && in_array(LdapConfiguration::$eventCreateDrupalUser, $prov_events)) {
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
   * @param UserInterface $account
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
      $this->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::$provisioningDirectionToDrupalUser, array($prov_event));
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
      \Drupal::logger('ldap_user')->error('Failed to exclude user from LDAP associatino because drupal account %drupal_username was not found', array('%drupal_username' => $drupal_username));
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
        $ldap_server = $factory->getServerByIdEnabled($params['sid']);
      }
      else {
        $ldap_server = $params['sid'];
      }

      if ($ldap_server) {
        if (!isset($attributes['dn'])) {
          $attributes['dn'] = array();
        }
        // Force dn "attribute" to exist.
        $attributes['dn'] = TokenProcessor::setAttributeMap($attributes['dn']);
        // Add the attributes required by the user configuration when provisioning drupal users.
        switch ($params['ldap_context']) {
          case 'ldap_user_insert_drupal_user':
          case 'ldap_user_update_drupal_user':
          case 'ldap_user_ldap_associate':
            // array($ldap_server->user_attr, 0, NULL);.
            $attributes[$ldap_server->user_attr] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->user_attr]);
            $attributes[$ldap_server->mail_attr] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->mail_attr]);
            $attributes[$ldap_server->picture_attr] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->picture_attr]);
            $attributes[$ldap_server->unique_persistent_attr] = TokenProcessor::setAttributeMap(@$attributes[$ldap_server->unique_persistent_attr]);
            if ($ldap_server->mail_template) {
              $tokens = new TokenProcessor();
              $tokens->extractTokenAttributes($attributes, $ldap_server->mail_template);
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
      $direction = LdapConfiguration::$provisioningDirectionNone;
    }

    if ($direction == LdapConfiguration::$provisioningDirectionToLDAPEntry) {
      $availableUserAttributes['[property.name]'] = array(
        'name' => 'Property: Username',
        'source' => '',
        'direction' => LdapConfiguration::$provisioningDirectionToLDAPEntry,
        'enabled' => TRUE,
        'prov_events' => array(
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ),
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      );

      $availableUserAttributes['[property.mail]'] = array(
        'name' => 'Property: Email',
        'source' => '',
        'direction' => LdapConfiguration::$provisioningDirectionToLDAPEntry,
        'enabled' => TRUE,
        'prov_events' => array(
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ),
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      );

      $availableUserAttributes['[property.picture]'] = array(
        'name' => 'Property: picture',
        'source' => '',
        'direction' => LdapConfiguration::$provisioningDirectionToLDAPEntry,
        'enabled' => TRUE,
        'prov_events' => array(
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ),
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      );

      $availableUserAttributes['[property.uid]'] = array(
        'name' => 'Property: Drupal User Id (uid)',
        'source' => '',
        'direction' => LdapConfiguration::$provisioningDirectionToLDAPEntry,
        'enabled' => TRUE,
        'prov_events' => array(
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ),
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      );

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

    $availableUserAttributes['[property.signature]'] = $availableUserAttributes['[property.signature]'] + array(
      'name' => 'Property: User Signature',
      'configurable_to_drupal' => 1,
      'configurable_to_ldap' => 1,
      'enabled' => FALSE,
      'config_module' => 'ldap_user',
      'prov_module' => 'ldap_user',
    );

    // 2. Drupal user fields.
    $user_fields = \Drupal::entityManager()->getFieldStorageDefinitions('user');

    foreach ($user_fields as $field_name => $field_instance) {
      $field_id = "[field.$field_name]";
      if (!isset($availableUserAttributes[$field_id]) || !is_array($availableUserAttributes[$field_id])) {
        $availableUserAttributes[$field_id] = array();
      }

      $availableUserAttributes[$field_id] = $availableUserAttributes[$field_id] + array(
        'name' => t('Field') . ': ' . $field_instance->getLabel(),
        'configurable_to_drupal' => 1,
        'configurable_to_ldap' => 1,
        'enabled' => FALSE,
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
      );
    }

    if (!LdapConfiguration::provisionsDrupalAccountsFromLdap()) {
      $availableUserAttributes['[property.mail]']['config_module'] = 'ldap_user';
      $availableUserAttributes['[property.name]']['config_module'] = 'ldap_user';
      $availableUserAttributes['[property.picture]']['config_module'] = 'ldap_user';
    }

    if ($direction == LdapConfiguration::$provisioningDirectionToLDAPEntry) {
      $availableUserAttributes['[password.random]'] = array(
        'name' => 'Pwd: Random',
        'source' => '',
        'direction' => LdapConfiguration::$provisioningDirectionToLDAPEntry,
        'enabled' => TRUE,
        'prov_events' => array(
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ),
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      );

      // Use user password when available fall back to random pwd.
      $availableUserAttributes['[password.user-random]'] = array(
        'name' => 'Pwd: User or Random',
        'source' => '',
        'direction' => LdapConfiguration::$provisioningDirectionToLDAPEntry,
        'enabled' => TRUE,
        'prov_events' => array(
          LdapConfiguration::$eventCreateDrupalUser,
          LdapConfiguration::$eventSyncToDrupalUser,
        ),
        'config_module' => 'ldap_user',
        'prov_module' => 'ldap_user',
        'configurable_to_ldap' => TRUE,
      );

    }

    $mappings = \Drupal::config('ldap_user.settings')->get('ldap_user_conf.ldapUserSyncMappings');

    // This is where need to be added to arrays.
    if (!empty($mappings[$direction])) {
      $availableUserAttributes = $this->applyUserAttributes($availableUserAttributes, $mappings, $direction);
    }

    return array($availableUserAttributes, $params);
  }

  /**
   * @param object $account
   *   as drupal user object.
   * @param enum int $direction
   *   indicating which directions to test for association
   *   LdapConfiguration::$provisioningDirectionToDrupalUser signifies test if drupal account has been provisioned or synced from ldap
   *   LdapConfiguration::$provisioningDirectionToLDAPEntry signifies test if ldap account has been provisioned or synced from drupal
   *   NULL signifies check for either direction.
   *
   * @return boolean if user is ldap associated
   */
  public function isUserLdapAssociated($account, $direction = NULL) {

    $to_drupal_user = FALSE;
    $to_ldap_entry = FALSE;

    if ($direction === NULL || $direction == LdapConfiguration::$provisioningDirectionToDrupalUser) {
      if (property_exists($account, 'ldap_user_current_dn') && !empty($account->get('ldap_user_current_dn')->value)) {
        $to_drupal_user = TRUE;
      }
      elseif ($account->id()) {
        $authmaps = ExternalAuthenticationHelper::getUserIdentifierFromMap($account->id());
        $to_drupal_user = (boolean) (count($authmaps));
      }
    }

    if ($direction === NULL || $direction == LdapConfiguration::$provisioningDirectionToLDAPEntry) {
      if (property_exists($account, 'ldap_user_prov_entries') && !empty($account->get('ldap_user_prov_entries')->value)) {
        $to_ldap_entry = TRUE;
      }
    }

    if ($direction == LdapConfiguration::$provisioningDirectionToDrupalUser) {
      return $to_drupal_user;
    }
    elseif ($direction == LdapConfiguration::$provisioningDirectionToLDAPEntry) {
      return $to_ldap_entry;
    }
    else {
      return ($to_ldap_entry || $to_drupal_user);
    }

  }

  /**
   * @param UserInterface $account
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
    if ($account->isActive() && LdapConfiguration::provisionAvailableToDrupal(LdapConfiguration::$provisionDrupalUserOnUserUpdateCreate)) {
      $this->syncToDrupalAccount($account, LdapConfiguration::$eventCreateDrupalUser, NULL, TRUE);
    }

    if (LdapConfiguration::provisionsLdapEntriesFromDrupalUsers()) {
      $prov_enabled = LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::$provisionLdapEntryOnUserUpdateCreate);
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
   * @param UserInterface $account
   */
  public function drupalUserUpdated($account) {

    if (ExternalAuthenticationHelper::excludeUser($account)) {
      return;
    }

    // Check for provisioning to LDAP; this will normally occur on hook_user_insert or other event when drupal user is created.
    if (LdapConfiguration::provisionsLdapEntriesFromDrupalUsers() &&
      LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::$provisionLdapEntryOnUserUpdateCreate)) {

      $already_provisioned_to_ldap = SemaphoreStorage::get('provision', $account->getUsername());
      $already_synced_to_ldap = SemaphoreStorage::get('sync', $account->getUsername());
      if ($already_provisioned_to_ldap || $already_synced_to_ldap) {
        return;
      }
      $processor = new LdapUserProcessor();

      $provision_result = array('status' => 'none');
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
        $provision_enabled = LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::$provisionLdapEntryOnUserUpdateCreate);
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
   * @param UserInterface $account
   */
  public function drupalUserPreSave($account) {

    if (ExternalAuthenticationHelper::excludeUser($account) || !$account->getUsername()) {
      return;
    }

    $factory = \Drupal::service('ldap.servers');
    $config = \Drupal::config('ldap_user.settings')->get('ldap_user_conf');
    $processor = new DrupalUserProcessor();

    // Check for provisioning to drupal and override synced user fields/props.
    if (LdapConfiguration::provisionsDrupalAccountsFromLdap() && in_array(LdapConfiguration::$eventSyncToDrupalUser, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
      if ($processor->isUserLdapAssociated($account, LdapConfiguration::$provisioningDirectionToDrupalUser)) {
        $ldap_user = $factory->getUserDataFromServerByAccount($account, $config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
        $ldap_server = $factory->getServerById($config['drupalAcctProvisionServer']);
        $processor->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::$provisioningDirectionToDrupalUser, array(LdapConfiguration::$eventSyncToDrupalUser));
      }
    }
  }

  /**
   * @param UserInterface $account
   */
  public function drupalUserLogsIn($account) {
    if (ExternalAuthenticationHelper::excludeUser($account)) {
      return;
    }

    // Provision or sync to ldap, not both.
    $provision_result = array('status' => 'none');
    $processor = new LdapUserProcessor();
    // Provision to ldap
    // if ($account->access == 0 && $account->login != 0) {} check for first time user.
    if (
      LdapConfiguration::provisionsLdapEntriesFromDrupalUsers()
      && SemaphoreStorage::get('provision', $account->getUsername()) == FALSE
      && !$processor->getProvisionRelatedLdapEntry($account)
      && \Drupal::config('ldap_user.settings')->get('ldap_user_conf.ldapEntryProvisionServer')
      && LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::$provisionLdapEntryOnUserAuthentication)
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
      && LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::$provisionLdapEntryOnUserAuthentication)
    ) {
      $ldapProcessor = new LdapUserProcessor();
      $bool_result = $ldapProcessor->syncToLdapEntry($account);
      if ($bool_result) {
        SemaphoreStorage::set('sync', $account->getUsername());
      }
    }
    /** @var ServerFactory $factory */
    $factory = \Drupal::service('ldap.servers');
    $config = \Drupal::config('ldap_user.settings')->get('ldap_user_conf');

    if (LdapConfiguration::provisionsDrupalAccountsFromLdap()  && in_array(LdapConfiguration::$eventSyncToDrupalUser, array_keys(LdapConfiguration::provisionsDrupalEvents()))) {
      $ldap_user = $factory->getUserDataFromServerByAccount($account, $config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
      if ($ldap_user) {
        $ldap_server = $factory->getServerById($config['drupalAcctProvisionServer']);
        $processor = new DrupalUserProcessor();
        $processor->applyAttributesToAccount($ldap_user, $account, $ldap_server, LdapConfiguration::$provisioningDirectionToDrupalUser, array(LdapConfiguration::$eventSyncToDrupalUser));
      }
      $account->save();
    }
  }

  /**
   * @param UserInterface $account
   */
  public function drupalUserDeleted($account) {
    /** @var UserInterface $account */

    // Drupal user account is about to be deleted.
    if (LdapConfiguration::provisionsLdapEntriesFromDrupalUsers()
      && LdapConfiguration::provisionAvailableToLDAP(LdapConfiguration::$provisionLdapEntryOnUserDelete)
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
      if ($direction == LdapConfiguration::$provisioningDirectionToDrupalUser && isset($mapping['user_attr'])) {
        $key = $mapping['user_attr'];
      }
      elseif ($direction == LdapConfiguration::$provisioningDirectionToLDAPEntry && isset($mapping['ldap_attr'])) {
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

}

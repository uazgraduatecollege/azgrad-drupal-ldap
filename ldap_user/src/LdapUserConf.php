<?php

namespace Drupal\ldap_user;

use Drupal\Component\Utility\Unicode;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\TokenFunctions;
use Drupal\ldap_user\Exception\LdapBadParamsException;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;

/**
 * The entry-point to working with users by loading their configuration.
 */
class LdapUserConf {

  use TokenFunctions;
  use LdapUserConfigurationValues;

  public $createLDAPAccounts;
  // TODO: Unused variable.
  public $createLDAPAccountsAdminApproval;
  protected $syncFormRow = 0;

  /**
   * Server providing Drupal account provisioning.
   *
   * @var string
   *
   * @see LdapServer::sid
   */
  public $drupalAcctProvisionServer;

  /**
   * Server providing LDAP entry provisioning.
   *
   * @var string
   *
   * @see LdapServer::sid
   */
  public $ldapEntryProvisionServer;

  /**
   * Associative array mapping sync directions to ldap server instances.
   *
   * @var array
   */
  public $provisionSidFromDirection;


  // @todo default to FALSE and check for mapping to set to true
  public $setsLdapPassword = TRUE;

  public $loginConflictResolve = FALSE;

  /**
   * Array of field sync mappings provided by all modules (via hook_ldap_user_attrs_list_alter())
   * array of the form: array(
   * self:: | s => array(
   *   <server_id> => array(
   *     'sid' => <server_id> (redundant)
   *     'ldap_attr' => e.g. [sn]
   *     'user_attr'  => e.g. [field.field_user_lname] (when this value is set to 'user_tokens', 'user_tokens' value is used.)
   *     'user_tokens' => e.g. [field.field_user_lname], [field.field_user_fname]
   *     'convert' => 1|0 boolean indicating need to covert from binary
   *     'direction' => self::$provisioningDirectionToDrupalUser | self::$provisioningDirectionToLDAPEntry (redundant)
   *     'config_module' => 'ldap_user'
   *     'prov_module' => 'ldap_user'
   *     'enabled' => 1|0 boolean
   *      prov_events' => array( see events above )
   *  )
   *
   * Array of field syncing directions for each operation.  should include ldapUserSyncMappings.
   * Keyed on direction => property, ldap, or field token such as '[field.field_lname] with brackets in them.
   */
  public $syncMapping = NULL;

  /**
   * Sync mappings configured in ldap user module (not in other modules)
   *   array of the form: array(
   * self::$provisioningDirectionToDrupalUser | self::$provisioningDirectionToLDAPEntry => array(
   * 'sid' => <server_id> (redundant)
   * 'ldap_attr' => e.g. [sn]
   * 'user_attr'  => e.g. [field.field_user_lname] (when this value is set to 'user_tokens', 'user_tokens' value is used.)
   * 'user_tokens' => e.g. [field.field_user_lname], [field.field_user_fname]
   * 'convert' => 1|0 boolean indicating need to covert from binary
   * 'direction' => self::$provisioningDirectionToDrupalUser | self::$provisioningDirectionToLDAPEntry (redundant)
   * 'config_module' => 'ldap_user'
   * 'prov_module' => 'ldap_user'
   * 'enabled' => 1|0 boolean
   * prov_events' => array( see events above )
   * )
   * )
   * Keyed on property, ldap, or field token such as '[field.field_lname] with brackets in them.
   * Property removed. TODO: Move configuration to a better place.
   * public $ldapUserSyncMappings = NULL;
   */

  public $detailedWatchdog = FALSE;
  public $provisionsDrupalAccountsFromLdap = FALSE;
  public $provisionsLdapEntriesFromDrupalUsers = FALSE;

  /**
   * Options are partially derived from user module account cancel options:.
   *
   * 'ldap_user_orphan_do_not_check' => Do not check for orphaned Drupal accounts.)
   * 'ldap_user_orphan_email' => Perform no action, but email list of orphaned accounts. (All the other options will send email summaries also.)
   * 'user_cancel_block' => Disable the account and keep its content.
   * 'user_cancel_block_unpublish' => Disable the account and unpublish its content.
   * 'user_cancel_reassign' => Delete the account and make its content belong to the Anonymous user.
   * 'user_cancel_delete' => Delete the account and its content.
   */

  public $provisionsLdapEvents = array();
  public $provisionsDrupalEvents = array();

  public $config;

  /**
   *
   */
  public function __construct() {

    $this->config = \Drupal::config('ldap_user.settings')->get('ldap_user_conf');

    $this->activeUserAuthentication();

    $this->provisionSidFromDirection[self::$provisioningDirectionToDrupalUser] = $this->config['drupalAcctProvisionServer'];
    $this->provisionSidFromDirection[self::$provisioningDirectionToLDAPEntry] = $this->config['ldapEntryProvisionServer'];

    $this->provisionsLdapEvents = array(
      self::$eventCreateLdapEntry => t('On LDAP Entry Creation'),
      self::$eventSyncToLdapEntry => t('On Sync to LDAP Entry'),
    );

    $this->provisionsDrupalEvents = array(
      self::$eventCreateDrupalUser => t('On Drupal User Creation'),
      self::$eventSyncToDrupalUser => t('On Sync to Drupal User'),
    );

    $this->provisionsDrupalAccountsFromLdap = (
      $this->config['drupalAcctProvisionServer'] &&
      $this->config['drupalAcctProvisionServer'] &&
      (count(array_filter(array_values(\Drupal::config('ldap_user.settings')->get('ldap_user_conf.drupalAcctProvisionTriggers')))) > 0)
    );

    $this->provisionsLdapEntriesFromDrupalUsers = (
      $this->config['ldapEntryProvisionServer']
      && $this->config['ldapEntryProvisionServer']
      && (count(array_filter(array_values(\Drupal::config('ldap_user.settings')->get('ldap_user_conf.ldapEntryProvisionTriggers')))) > 0)
      );

    $this->setSyncMapping(TRUE);
    $this->detailedWatchdog = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
  }

  /**
   * Util to fetch mappings for a given direction.
   *
   * @param string $sid
   *   The server id.
   * @param string $direction
   * @param array $prov_events
   *
   * @return array|bool
   *   Array of mappings (may be empty array)
   */
  public function getSyncMappings($direction = NULL, $prov_events = NULL) {
    if (!$prov_events) {
      $prov_events = ldap_user_all_events();
    }
    if ($direction == NULL) {
      $direction = self::$provisioningDirectionAll;
    }

    $mappings = array();
    if ($direction == self::$provisioningDirectionAll) {
      $directions = array(self::$provisioningDirectionToDrupalUser, self::$provisioningDirectionToLDAPEntry);
    }
    else {
      $directions = array($direction);
    }
    foreach ($directions as $direction) {
      if (!empty($this->config['ldapUserSyncMappings'][$direction])) {
        foreach ($this->config['ldapUserSyncMappings'][$direction] as $attribute => $mapping) {
          if (!empty($mapping['prov_events'])) {
            $result = count(array_intersect($prov_events, $mapping['prov_events']));
            if ($result) {
              if ($direction == self::$provisioningDirectionToDrupalUser && isset($mapping['user_attr'])) {
                $key = $mapping['user_attr'];
              }
              elseif ($direction == self::$provisioningDirectionToLDAPEntry && isset($mapping['ldap_attr'])) {
                $key = $mapping['ldap_attr'];
              }
              else {
                continue;
              }
              $mappings[$key] = $mapping;
            }
          }
        }
      }
    }
    return $mappings;
  }

  /**
   * Util to fetch attributes required for this user conf, not other modules.
   *
   * @param enum $direction
   *   LDAP_USER_PROV_DIRECTION_* constants.
   * @param string $ldap_context
   *
   * @return array
   */
  public function getLdapUserRequiredAttributes($direction = NULL, $ldap_context = NULL) {
    if ($direction == NULL) {
      $direction = LdapUserConf::$provisioningDirectionAll;
    }
    $attributes_map = array();
    $required_attributes = array();
    if ($this->config['drupalAcctProvisionServer']) {
      $prov_events = $this->ldapContextToProvEvents($ldap_context);
      $attributes_map = $this->getSyncMappings($direction, $prov_events);
      $required_attributes = array();
      foreach ($attributes_map as $detail) {
        if (count(array_intersect($prov_events, $detail['prov_events']))) {
          // Add the attribute to our array.
          if ($detail['ldap_attr']) {
            $this->extractTokenAttributes($required_attributes, $detail['ldap_attr']);
          }
        }
      }
    }
    return $required_attributes;
  }

  /**
   * Converts the more general ldap_context string to its associated ldap user event.
   */
  private function ldapContextToProvEvents($ldap_context = NULL) {

    switch ($ldap_context) {

      case 'ldap_user_prov_to_drupal':
        $result = [
          LdapUserConf::$eventSyncToDrupalUser,
          LdapUserConf::$eventCreateDrupalUser,
          LdapUserConf::$eventLdapAssociateDrupalAccount,
        ];
        break;

      case 'ldap_user_prov_to_ldap':
        $result = [
          LdapUserConf::$eventSyncToLdapEntry,
          LdapUserConf::$eventCreateLdapEntry,
        ];
        break;

      default:
        $result = ldap_user_all_events();

    }

    return $result;

  }

  /**
   * Converts the more general ldap_context string to its associated ldap user prov direction.
   */
  public function ldapContextToProvDirection($ldap_context = NULL) {

    switch ($ldap_context) {

      case 'ldap_user_prov_to_drupal':
        $result = self::$provisioningDirectionToDrupalUser;
        break;

      case 'ldap_user_prov_to_ldap':
      case 'ldap_user_delete_drupal_user':
        $result = self::$provisioningDirectionToLDAPEntry;
        break;

      // Provisioning is can hapen in both directions in most contexts.
      case 'ldap_user_insert_drupal_user':
      case 'ldap_user_update_drupal_user':
      case 'ldap_authentication_authenticate':
      case 'ldap_user_disable_drupal_user':
        $result = self::$provisioningDirectionAll;
        break;

      default:
        $result = self::$provisioningDirectionAll;

    }

    return $result;
  }

  /**
   * Derive mapping array from ldap user configuration and other configurations.
   * if this becomes a resource hungry function should be moved to ldap_user functions
   * and stored with static variable. should be cached also.
   * This should be cached and modules implementing ldap_user_sync_mapping_alter
   * should know when to invalidate cache.
   */

  /**
   * @todo change default to false after development
   * @param bool $reset
   */
  public function setSyncMapping($reset = TRUE) {

    $sync_mapping_cache = \Drupal::cache()->get('ldap_user_sync_mapping');
    if (!$reset && $sync_mapping_cache) {
      $this->syncMapping = $sync_mapping_cache->data;
    }
    else {
      $available_user_attributes = array();
      foreach (array(self::$provisioningDirectionToDrupalUser, self::$provisioningDirectionToLDAPEntry) as $direction) {
        $sid = $this->provisionSidFromDirection[$direction];
        $available_user_attributes[$direction] = array();
        $ldap_server = FALSE;
        if ($sid) {
          try {
            $factory = \Drupal::service('ldap.servers');
            $ldap_server = $factory->getServerById($sid);
          }
          catch (\Exception $e) {
            \Drupal::logger('ldap_user')->error('Missing server');
          }
        }

        $params = array(
          'ldap_server' => $ldap_server,
          'ldap_user_conf' => $this,
          'direction' => $direction,
        );

        \Drupal::moduleHandler()->alter('ldap_user_attrs_list', $available_user_attributes[$direction], $params);
      }
    }
    $this->syncMapping = $available_user_attributes;

    \Drupal::cache()->set('ldap_user_sync_mapping', $this->syncMapping);
  }

  /**
   * Given a $prov_event determine if ldap user configuration supports it.
   *   this is overall, not per field syncing configuration.
   *
   * @param int $direction
   *   self::$provisioningDirectionToDrupalUser or self::$provisioningDirectionToLDAPEntry.
   *
   * @param int $provision_trigger
   *   see events above.
   *   or
   *   'sync', 'provision', 'delete_ldap_entry', 'delete_drupal_entry', 'cancel_drupal_entry'.
   *
   * @FIXME: Documentation incomplete.
   *
   * @return bool
   */
  public function provisionEnabled($direction, $provision_trigger) {
    $result = FALSE;

    if ($direction == self::$provisioningDirectionToLDAPEntry) {

      if (!$this->config['ldapEntryProvisionServer']) {
        $result = FALSE;
      }
      else {
        $result = in_array($provision_trigger, \Drupal::config('ldap_user.settings')->get('ldap_user_conf.ldapEntryProvisionTriggers'));
      }

    }
    elseif ($direction == self::$provisioningDirectionToDrupalUser) {
      if (!$this->config['drupalAcctProvisionServer']) {
        $result = FALSE;
      }
      else {
        $result = in_array($provision_trigger, \Drupal::config('ldap_user.settings')->get('ldap_user_conf.drupalAcctProvisionTriggers'));
      }
    }

    return $result;
  }

  /**
   * Given a drupal account, provision an ldap entry if none exists.  if one exists do nothing.
   *
   * @param object $account
   *   drupal account object with minimum of name property.
   * @param array $ldap_user
   *   as prepopulated ldap entry.  usually not provided.
   *
   * @return array
   *   Format:
   *     array('status' => 'success', 'fail', or 'conflict'),
   *     array('ldap_server' => ldap server object),
   *     array('proposed' => proposed ldap entry),
   *     array('existing' => existing ldap entry),
   *     array('description' = > blah blah)
   */
  public function provisionLdapEntry($account, $ldap_user = NULL, $test_query = FALSE) {

    $result = array(
      'status' => NULL,
      'ldap_server' => NULL,
      'proposed' => NULL,
      'existing' => NULL,
      'description' => NULL,
    );

    if (is_scalar($account)) {
      $username = $account;
      $account = new \stdClass();
      $account->name = $username;
    }

    /* @var User $account */
    /* @var User $user_entity */
    list($account, $user_entity) = ldap_user_load_user_acct_and_entity($account->getUsername());

    if (is_object($account) && $account->id() == 1) {
      $result['status'] = 'fail';
      $result['error_description'] = 'can not provision drupal user 1';
      // Do not provision or sync user 1.
      return $result;
    }

    if ($account == FALSE || $account->isAnonymous()) {
      $result['status'] = 'fail';
      $result['error_description'] = 'can not provision ldap user unless corresponding drupal account exists first.';
      return $result;
    }

    if (!$this->config['ldapEntryProvisionServer'] || !$this->config['ldapEntryProvisionServer']) {
      $result['status'] = 'fail';
      $result['error_description'] = 'no provisioning server enabled';
      return $result;
    }
    $factory = \Drupal::service('ldap.servers');
    $ldap_server = $factory->getServerById($this->config['ldapEntryProvisionServer']);
    $params = [
      'direction' => self::$provisioningDirectionToLDAPEntry,
      'prov_events' => [self::$eventCreateLdapEntry],
      'module' => 'ldap_user',
      'function' => 'provisionLdapEntry',
      'include_count' => FALSE,
    ];

    try {
      $proposed_ldap_entry = $this->drupalUserToLdapEntry($account, $ldap_server, $params, $ldap_user);
    }
    catch (\Exception $e) {
      \Drupal::logger('ldap_user')->error('User or server is missing.');
      return [
        'status' => 'fail',
        'ldap_server' => $ldap_server,
        'created' => NULL,
        'existing' => NULL,
      ];
    }

    $proposed_dn = (is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn']) && $proposed_ldap_entry['dn']) ? $proposed_ldap_entry['dn'] : NULL;
    $proposed_dn_lcase = Unicode::strtolower($proposed_dn);
    $existing_ldap_entry = ($proposed_dn) ? $ldap_server->dnExists($proposed_dn, 'ldap_entry') : NULL;

    if (!$proposed_dn) {
      return [
        'status' => 'fail',
        'description' => t('failed to derive dn and or mappings'),
      ];
    }
    elseif ($existing_ldap_entry) {
      $result['status'] = 'conflict';
      $result['description'] = 'can not provision ldap entry because exists already';
      $result['existing'] = $existing_ldap_entry;
      $result['proposed'] = $proposed_ldap_entry;
      $result['ldap_server'] = $ldap_server;
    }
    elseif ($test_query) {
      $result['status'] = 'fail';
      $result['description'] = 'not created because flagged as test query';
      $result['proposed'] = $proposed_ldap_entry;
      $result['ldap_server'] = $ldap_server;
    }
    else {
      // Stick $proposed_ldap_entry in $ldap_entries array for drupal_alter call.
      $ldap_entries = array($proposed_dn_lcase => $proposed_ldap_entry);
      $context = array(
        'action' => 'add',
        'corresponding_drupal_data' => array($proposed_dn_lcase => $account),
        'corresponding_drupal_data_type' => 'user',
      );
      \Drupal::moduleHandler()->alter('ldap_entry_pre_provision', $ldap_entries, $ldap_server, $context);
      // Remove altered $proposed_ldap_entry from $ldap_entries array.
      $proposed_ldap_entry = $ldap_entries[$proposed_dn_lcase];

      $ldap_entry_created = $ldap_server->createLdapEntry($proposed_ldap_entry, $proposed_dn);
      if ($ldap_entry_created) {
        \Drupal::moduleHandler()->invokeAll('ldap_entry_post_provision', [$ldap_entries, $ldap_server, $context]);
        $result = [
          'status' => 'success',
          'description' => 'ldap account created',
          'proposed' => $proposed_ldap_entry,
          'created' => $ldap_entry_created,
          'ldap_server' => $ldap_server,
        ];
        // Need to store <sid>|<dn> in ldap_user_prov_entries field, which may contain more than one.
        $ldap_user_prov_entry = $ldap_server->id() . '|' . $proposed_ldap_entry['dn'];
        if (NULL !== $user_entity->get('ldap_user_prov_entries')) {
          $user_entity->set('ldap_user_prov_entries', array());
        }
        $ldap_user_prov_entry_exists = FALSE;
        foreach ($user_entity->get('ldap_user_prov_entries')->value as $i => $field_value_instance) {
          if ($field_value_instance == $ldap_user_prov_entry) {
            $ldap_user_prov_entry_exists = TRUE;
          }
        }
        if (!$ldap_user_prov_entry_exists) {
          // @TODO Serialise?
          $prov_entries = $user_entity->get('ldap_user_prov_entries')->value;
          $prov_entries[] = array(
            'value' => $ldap_user_prov_entry,
            'format' => NULL,
            'save_value' => $ldap_user_prov_entry,
          );
          $user_entity->set('ldap_user_prov_entries', $prov_entries);
          $user_entity->save();
        }

      }
      else {
        $result = [
          'status' => 'fail',
          'proposed' => $proposed_ldap_entry,
          'created' => $ldap_entry_created,
          'ldap_server' => $ldap_server,
          'existing' => NULL,
        ];
      }
    }

    $tokens = [
      '%dn' => isset($result['proposed']['dn']) ? $result['proposed']['dn'] : NULL,
      '%sid' => (isset($result['ldap_server']) && $result['ldap_server']) ? $result['ldap_server']->id() : 0,
      '%username' => @$account->getUsername(),
      '%uid' => @$account->id(),
      '%description' => @$result['description'],
    ];
    if (!$test_query && isset($result['status'])) {
      if ($result['status'] == 'success') {
        if ($this->detailedWatchdog) {
          \Drupal::logger('ldap_user')->info('LDAP entry on server %sid created dn=%dn.  %description. username=%username, uid=%uid', $tokens);
        }
      }
      elseif ($result['status'] == 'conflict') {
        if ($this->detailedWatchdog) {
          \Drupal::logger('ldap_user')->warning('LDAP entry on server %sid not created because of existing ldap entry. %description. username=%username, uid=%uid', $tokens);
        }
      }
      elseif ($result['status'] == 'fail') {
        \Drupal::logger('ldap_user')->error('LDAP entry on server %sid not created because of error. %description. username=%username, uid=%uid, proposed dn=%dn', $tokens);
      }
    }
    return $result;
  }

  /**
   * Given a drupal account, sync to related ldap entry.
   *
   * @param User $account.
   *   Drupal user object.
   * @param array $ldap_user.
   *   current ldap data of user. @see README.developers.txt for structure.
   *
   * @return TRUE on success or FALSE on fail.
   */
  public function syncToLdapEntry($account, $ldap_user = array(), $test_query = FALSE) {

    if (is_object($account) && $account->id() == 1) {
      // Do not provision or sync user 1.
      return FALSE;
    }

    $result = FALSE;

    if ($this->config['ldapEntryProvisionServer']) {

      $factory = \Drupal::service('ldap.servers');
      $ldap_server = $factory->getServerById($this->config['ldapEntryProvisionServer']);

      $params = array(
        'direction' => self::$provisioningDirectionToLDAPEntry,
        'prov_events' => array(self::$eventSyncToLdapEntry),
        'module' => 'ldap_user',
        'function' => 'syncToLdapEntry',
        'include_count' => FALSE,
      );

      try {
        $proposed_ldap_entry = $this->drupalUserToLdapEntry($account, $ldap_server, $params, $ldap_user);
      }
      catch (\Exception $e) {
        \Drupal::logger('ldap_user')->error('User or server is missing.');
        return FALSE;
      }

      if (is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn'])) {
        $existing_ldap_entry = $ldap_server->dnExists($proposed_ldap_entry['dn'], 'ldap_entry');
        // This array represents attributes to be modified; not comprehensive list of attributes.
        $attributes = array();
        foreach ($proposed_ldap_entry as $attr_name => $attr_values) {
          if ($attr_name != 'dn') {
            if (isset($attr_values['count'])) {
              unset($attr_values['count']);
            }
            if (count($attr_values) == 1) {
              $attributes[$attr_name] = $attr_values[0];
            }
            else {
              $attributes[$attr_name] = $attr_values;
            }
          }
        }

        if ($test_query) {
          $proposed_ldap_entry = $attributes;
          $result = [
            'proposed' => $proposed_ldap_entry,
            'server' => $ldap_server,
          ];
        }
        else {
          // //debug('modifyLdapEntry,dn=' . $proposed_ldap_entry['dn']);  //debug($attributes);
          // stick $proposed_ldap_entry in $ldap_entries array for drupal_alter call.
          $proposed_dn_lcase = Unicode::strtolower($proposed_ldap_entry['dn']);
          $ldap_entries = [$proposed_dn_lcase => $attributes];
          $context = [
            'action' => 'update',
            'corresponding_drupal_data' => [$proposed_dn_lcase => $attributes],
            'corresponding_drupal_data_type' => 'user',
          ];
          \Drupal::moduleHandler()->alter('ldap_entry_pre_provision', $ldap_entries, $ldap_server, $context);
          // Remove altered $proposed_ldap_entry from $ldap_entries array.
          $attributes = $ldap_entries[$proposed_dn_lcase];
          $result = $ldap_server->modifyLdapEntry($proposed_ldap_entry['dn'], $attributes);
          // Success.
          if ($result) {
            \Drupal::moduleHandler()->invokeAll('ldap_entry_post_provision', [$ldap_entries, $ldap_server, $context]);
          }
        }
      }
      // Failed to get acceptable proposed ldap entry.
      else {
        $result = FALSE;
      }
    }

    $tokens = [
      '%dn' => isset($result['proposed']['dn']) ? $result['proposed']['dn'] : NULL,
      '%sid' => $this->config['ldapEntryProvisionServer'],
      '%username' => $account->name,
      '%uid' => ($test_query || !method_exists($account,'id') || empty($account->id())) ? '' : $account->id(),
    ];

    if ($result) {
      \Drupal::logger('ldap_user')->info('LDAP entry on server %sid synced dn=%dn. username=%username, uid=%uid', $tokens);
    }
    else {
      \Drupal::logger('ldap_user')->error('LDAP entry on server %sid not synced because error. username=%username, uid=%uid', $tokens);
    }

    return $result;

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
      $prov_event = LdapUserConf::$eventSyncToDrupalUser;
    }

    if ((!$ldap_user && method_exists($account, 'getUsername')) ||
        (!$account && $save) ||
        ($ldap_user && !isset($ldap_user['sid']))) {
      \Drupal::logger('ldap_user')->notice('Invalid selection passed to syncToDrupalAccount.');
      return FALSE;
    }

    if (!$ldap_user && $this->config['drupalAcctProvisionServer']) {
      $factory = \Drupal::service('ldap.servers');
      $ldap_user = $factory->getUsgetUserDataFromServerByAccounterDataFromServerByAccount($account, $this->config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
    }

    if (!$ldap_user) {
      return FALSE;
    }

    if ($this->config['drupalAcctProvisionServer']) {

      $factory = \Drupal::service('ldap.servers');
      $ldap_server = $factory->getServerById($this->config['drupalAcctProvisionServer']);
      $this->applyAttributesToAccount($ldap_user, $account, $ldap_server, self::$provisioningDirectionToDrupalUser, array($prov_event));
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
   * Given a drupal account, delete user account.
   *
   * @param string $username
   *   drupal account name.
   *
   * @return TRUE or FALSE.  FALSE indicates failed or action not enabled in ldap user configuration
   */
  public function deleteDrupalAccount($username) {
    $user = user_load_by_name($username);
    if (is_object($user)) {
      $user->uid->delete();
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Given a drupal account, find the related ldap entry.
   *
   * @param drupal user object $account
   *
   * @return FALSE or ldap entry
   */
  public function getProvisionRelatedLdapEntry($account, $prov_events = NULL) {
    if (!$prov_events) {
      $prov_events = ldap_user_all_events();
    }
    $sid = $this->config['ldapEntryProvisionServer'];
    if (!$sid) {
      return FALSE;
    }
    // $user_entity->ldap_user_prov_entries,.
    $factory = \Drupal::service('ldap.servers');
    $ldap_server = $factory->getServerById($sid);
    $params = [
      'direction' => self::$provisioningDirectionToLDAPEntry,
      'prov_events' => $prov_events,
      'module' => 'ldap_user',
      'function' => 'getProvisionRelatedLdapEntry',
      'include_count' => FALSE,
    ];

    try {
      $proposed_ldap_entry = $this->drupalUserToLdapEntry($account, $ldap_server, $params);
    }
    catch (\Exception $e) {
      \Drupal::logger('ldap_user')->error('User or server is missing.');
      return FALSE;
    }

    if (!(is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn']) && $proposed_ldap_entry['dn'])) {
      return FALSE;
    }

    $ldap_entry = $ldap_server->dnExists($proposed_ldap_entry['dn'], 'ldap_entry', array());
    return $ldap_entry;

  }

  /**
   * Given a drupal account, delete ldap entry that was provisioned based on it
   *   normally this will be 0 or 1 entry, but the ldap_user_provisioned_ldap_entries
   *   field attached to the user entity track each ldap entry provisioned.
   *
   * @param User $account
   *   Drupal user account.
   *
   * @return TRUE or FALSE.  FALSE indicates failed or action not enabled in ldap user configuration
   */
  public function deleteProvisionedLdapEntries($account) {
    // Determine server that is associated with user.
    $boolean_result = FALSE;
    $language = ($account->language) ? $account->language : 'und';
    if (isset($account->ldap_user_prov_entries[$language][0])) {
      foreach ($account->ldap_user_prov_entries[$language] as $i => $field_instance) {
        $parts = explode('|', $field_instance['value']);
        if (count($parts) == 2) {

          list($sid, $dn) = $parts;
          $factory = \Drupal::service('ldap.servers');
          $ldap_server = $factory->getServerById($sid);
          if (is_object($ldap_server) && $dn) {
            $boolean_result = $ldap_server->delete($dn);
            $tokens = array('%sid' => $sid, '%dn' => $dn, '%username' => $account->getUsername(), '%uid' => $account->id());
            if ($boolean_result) {
              \Drupal::logger('ldap_user')->info('LDAP entry on server %sid deleted dn=%dn. username=%username, uid=%uid', $tokens);
            }
            else {
              \Drupal::logger('ldap_user')->error('LDAP entry on server %sid not deleted because error. username=%username, uid=%uid', $tokens);
            }
          }
          else {
            $boolean_result = FALSE;
          }
        }
      }
    }
    return $boolean_result;

  }

  /**
   * Populate ldap entry array for provisioning.
   *
   * @param User $account
   *   drupal account.
   * @param object $ldap_server
   * @param array $params
   *   with the following key values:
   *    'ldap_context' =>
   *   'module' => module calling function, e.g. 'ldap_user'
   *   'function' => function calling function, e.g. 'provisionLdapEntry'
   *   'include_count' => should 'count' array key be included
   *   'direction' => self::$provisioningDirectionToLDAPEntry || self::$provisioningDirectionToDrupalUser.
   * @param null $ldap_user_entry
   *
   * @return array (ldap entry, $result)
   *   In ldap extension array format. THIS IS NOT THE ACTUAL LDAP ENTRY.
   *
   * @throws \Drupal\ldap_user\Exception\LdapBadParamsException
   */
  public function drupalUserToLdapEntry(User $account, $ldap_server, $params, $ldap_user_entry = NULL) {
    $provision = (isset($params['function']) && $params['function'] == 'provisionLdapEntry');
    if (!$ldap_user_entry) {
      $ldap_user_entry = array();
    }

    if (!is_object($account) || !is_object($ldap_server)) {
      throw new LdapBadParamsException('Missing user or server.');
    }

    $include_count = (isset($params['include_count']) && $params['include_count']);

    $direction = isset($params['direction']) ? $params['direction'] : self::$provisioningDirectionAll;
    $prov_events = empty($params['prov_events']) ? ldap_user_all_events() : $params['prov_events'];

    $mappings = $this->getSyncMappings($direction, $prov_events);
    // Loop over the mappings.
    foreach ($mappings as $field_key => $field_detail) {
      // FIXME: Incorrect parameter count.
      list($ldap_attr_name, $ordinal, $conversion) = $this->extractTokenParts($field_key, TRUE);
      $ordinal = (!$ordinal) ? 0 : $ordinal;
      if ($ldap_user_entry && isset($ldap_user_entry[$ldap_attr_name]) && is_array($ldap_user_entry[$ldap_attr_name]) && isset($ldap_user_entry[$ldap_attr_name][$ordinal])) {
        // Don't override values passed in.
        continue;
      }

      $synced = $this->isSynced($field_key, $params['prov_events'], self::$provisioningDirectionToLDAPEntry);
      if ($synced) {
        $token = ($field_detail['user_attr'] == 'user_tokens') ? $field_detail['user_tokens'] : $field_detail['user_attr'];
        $value = $this->tokenReplace($account, $token, 'user_account');

        // Deal with empty/unresolved password.
        if (substr($token, 0, 10) == '[password.' && (!$value || $value == $token)) {
          if (!$provision) {
            // Don't overwrite password on sync if no value provided.
            continue;
          }
        }

        if ($ldap_attr_name == 'dn' && $value) {
          $ldap_user_entry['dn'] = $value;
        }
        elseif ($value) {
          if (!isset($ldap_user_entry[$ldap_attr_name]) || !is_array($ldap_user_entry[$ldap_attr_name])) {
            $ldap_user_entry[$ldap_attr_name] = array();
          }
          $ldap_user_entry[$ldap_attr_name][$ordinal] = $value;
          if ($include_count) {
            $ldap_user_entry[$ldap_attr_name]['count'] = count($ldap_user_entry[$ldap_attr_name]);
          }
        }
      }
    }

    // Allow other modules to alter $ldap_user.
    \Drupal::moduleHandler()->alter('ldap_entry', $ldap_user_entry, $params);

    return $ldap_user_entry;

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
   * @return bool
   *   Return TRUE on success or FALSE on any problem.
   */
  public function provisionDrupalAccount($account = FALSE, &$user_values, $ldap_user = NULL, $save = TRUE) {

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
    $factory = \Drupal::service('ldap.servers');

    // Get an LDAP user from the LDAP server.
    if (!$ldap_user) {
      $tokens['%username'] = $user_values['name'];
      if ($this->config['drupalAcctProvisionServer']) {
        $ldap_user = $factory->getUserDataFromServerByIdentifier($user_values['name'], $this->config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
      }
      // Still no LDAP user.
      if (!$ldap_user) {
        if ($this->detailedWatchdog) {
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

      // $ldap_user['sid'].
      $ldap_server = $factory->getServerByIdEnabled($this->config['drupalAcctProvisionServer']);

      $params = array(
        'account' => $account,
        'user_values' => $user_values,
        'prov_event' => self::$eventCreateDrupalUser,
        'module' => 'ldap_user',
        'function' => 'provisionDrupalAccount',
        'direction' => self::$provisioningDirectionToDrupalUser,
      );

      \Drupal::moduleHandler()->alter('ldap_entry', $ldap_user, $params);

      // Look for existing drupal account with same puid.  if so update username and attempt to sync in current context.
      $puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      // FIXME: The entire account2 operation is broken.
      $account2 = ($puid) ? $ldap_server->userUserEntityFromPuid($puid) : FALSE;

      // Sync drupal account, since drupal account exists.
      if ($account2) {
        // 1. correct username and authmap.
        $this->applyAttributesToAccount($ldap_user, $account2, $ldap_server, self::$provisioningDirectionToDrupalUser, array(LdapUserConf::$eventSyncToDrupalUser));
        $account = $account2;
        $account->save();
        // Update the identifier table.
        self::setUserIdentifier($account, $account->getUsername());

        // 2. attempt sync if appropriate for current context.
        if ($account) {
          $account = $this->syncToDrupalAccount($account, LdapUserConf::$eventSyncToDrupalUser, $ldap_user, TRUE);
        }
        return $account;
      }
      // Create drupal account.
      else {
        $this->applyAttributesToAccount($ldap_user, $account, $ldap_server, self::$provisioningDirectionToDrupalUser, array(self::$eventCreateDrupalUser));
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
            self::setUserIdentifier($account, $account->getUsername());
            if (!empty($user_data)) {
              // FIXME: Undefined function.
              ldap_user_identities_data_update($account, $user_data);
            }
          }
          return $account;
        }
        return TRUE;
      }
    }
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
      /* @var Server $ldap_server */
      $ldap_server = $factory->getServerByIdEnabled($this->config['drupalAcctProvisionServer']);
      $account = user_load_by_name($drupal_username);
      if (!$account) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because account not found', array('%drupal_username' => $drupal_username));
        return FALSE;
      }

      $ldap_user = $factory->getUserDataFromServerByAccount($account, $this->config['drupalAcctProvisionServer'], 'ldap_user_prov_to_drupal');
      if (!$ldap_user) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because corresponding LDAP entry not found', array('%drupal_username' => $drupal_username));
        return FALSE;
      }

      // @TODO Data has been retired. Should we migrate it somewhere else?
      try {
        $data = unserialize($account->get('data'));
        if (!is_array($data)) {
          $data = [];
        }

        $data['ldap_user']['init'] = [
          'sid'  => $ldap_server->id(),
          'dn'   => $ldap_user['dn'],
          'mail'   => $account->mail,
        ];
        $account->set('data', serialize($data));
      }
      catch (\Exception $e) {
        \Drupal::logger('ldap_user')->warning('Setting of serialized \'data\' attributes failed.');
      }

      $ldap_user_puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      if ($ldap_user_puid) {
        $account->set('ldap_user_puid', $ldap_user_puid);
      }
      $account->set('ldap_user_puid_property', $ldap_server->get('unique_persistent_attr'));
      $account->set('ldap_user_puid_sid', $ldap_server->id());
      $account->set('ldap_user_current_dn', $ldap_user['dn']);
      // @TODO Shouldn't we set the "last checked" date?
      $account->set('ldap_user_last_checked', time());
      $account->set('ldap_user_ldap_exclude', 0);
      $account->save();
      return TRUE;
    }
    else {
      return FALSE;
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
      $direction = self::$provisioningDirectionToDrupalUser;
    }
    // Need array of user fields and which direction and when they should be synced.
    if (!$prov_events) {
      $prov_events = ldap_user_all_events();
    }
    $mail_synced = $this->isSynced('[property.mail]', $prov_events, $direction);
    if (!$account->getEmail() && $mail_synced) {
      $derived_mail = $ldap_server->userEmailFromLdapEntry($ldap_user['attr']);
      if ($derived_mail) {
        $account->set('mail', $derived_mail);
      }
    }

    $drupal_username = $ldap_server->userUsernameFromLdapEntry($ldap_user['attr']);
    if ($this->isSynced('[property.picture]', $prov_events, $direction)) {

      $picture = $ldap_server->userPictureFromLdapEntry($ldap_user['attr'], $account);

      if ($picture) {
        $account->set('user_picture', $picture);
      }
    }

    if ($this->isSynced('[property.name]', $prov_events, $direction) && !$account->getUsername() && $drupal_username) {
      $account->set('name', $drupal_username);
    }

    // Only fired on self::$eventCreateDrupalUser. Shouldn't it respect the checkbox on the sync form?
    if ($direction == self::$provisioningDirectionToDrupalUser && in_array(self::$eventCreateDrupalUser, $prov_events)) {
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

      // @FIXME data has gone away (Core). Use external_auth data column?
      $user_data['init'] = array(
        'sid'  => $ldap_server->id(),
        'dn'   => $ldap_user['dn'],
        'mail' => $derived_mail,
      );
    }

    /**
     * basic $user ldap fields
     */
    if ($this->isSynced('[field.ldap_user_puid]', $prov_events, $direction)) {
      $ldap_user_puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      if ($ldap_user_puid) {
        $account->set('ldap_user_puid', $ldap_user_puid);
      }
    }
    if ($this->isSynced('[field.ldap_user_puid_property]', $prov_events, $direction)) {
      $account->set('ldap_user_puid_property', $ldap_server->unique_persistent_attr);
    }
    if ($this->isSynced('[field.ldap_user_puid_sid]', $prov_events, $direction)) {
      $account->set('ldap_user_puid_sid', $ldap_server->id());
    }
    if ($this->isSynced('[field.ldap_user_current_dn]', $prov_events, $direction)) {
      $account->set('ldap_user_current_dn', $ldap_user['dn']);
    }

    // Get any additional mappings.
    $mappings = $this->getSyncMappings($direction, $prov_events);

    // Loop over the mappings.
    foreach ($mappings as $user_attr_key => $field_detail) {

      // Make sure this mapping is relevant to the sync context.
      if (!$this->isSynced($user_attr_key, $prov_events, $direction)) {
        continue;
      }
      /**
        * if "convert from binary is selected" and no particular method is in token,
        * default to binaryConversiontoString() function
        */
      if ($field_detail['convert'] && strpos($field_detail['ldap_attr'], ';') === FALSE) {
        $field_detail['ldap_attr'] = str_replace(']', ';binary]', $field_detail['ldap_attr']);
      }
      $value = $this->tokenReplace($ldap_user['attr'], $field_detail['ldap_attr'], 'ldap_entry');
      list($value_type, $value_name, $value_instance) = $this->parseUserAttributeNames($user_attr_key);

      // $value_instance not used, may have future use case.
      // Are we dealing with a field?
      if ($value_type == 'field') {
        $account->set($value_name, $value);
      }
      elseif ($value_type == 'property') {
        // Straight property.
        // @FIXME We don't know if this is right in Drupal 8 or not.
        $account->set($value_name, $value);
      }
    }

    // @FIXME: Incorrect parameter count
    // Allow other modules to have a say.
    \Drupal::moduleHandler()->alter('ldap_user_edit_user', $account, $ldap_user, $ldap_server, $prov_events);
    // don't let empty 'name' value pass for user.
    if (empty($account->getUsername())) {
      $account->set('name', $ldap_user[$ldap_server->get('user_attr')]);
    }

    // Set ldap_user_last_checked.
    $account->set('ldap_user_last_checked', time());
  }

  /**
   * Given configuration of syncing, determine is a given sync should occur.
   *
   * @param string $attr_token
   *   e.g. [property.mail], [field.ldap_user_puid_property].
   * @param array $prov_events
   *   e.g. array(self::$eventCreateDrupalUser).  typically array with 1 element.
   * @param int $direction
   *   self::$provisioningDirectionToDrupalUser or self::$provisioningDirectionToLDAPEntry.
   *
   * @return bool
   */
  public function isSynced($attr_token, $prov_events, $direction) {
    $result = (boolean) (
      isset($this->syncMapping[$direction][$attr_token]['prov_events']) &&
      count(array_intersect($prov_events, $this->syncMapping[$direction][$attr_token]['prov_events']))
    );
    return $result;
  }

  /**
   * Replaces the authmap table retired in Drupal 8
   * Drupal 7: user_set_authmap.
   */
  public static function setUserIdentifier($account, $identifier) {
    $authmap = \Drupal::service('externalauth.authmap');
    $authmap->save($account, 'ldap_user', $identifier);
  }

  /**
   * Called from hook_user_delete ldap_user_user_delete.
   */
  public static function deleteUserIdentifier($uid) {
    $authmap = \Drupal::service('externalauth.authmap');
    $authmap->delete($uid);
  }

  /**
   * Replaces the authmap table retired in Drupal 8.
   */
  public static function getUidFromIdentifierMap($identifier) {
    $externalauth = \Drupal::service('externalauth.externalauth');
    $externalauth->load($identifier, 'ldap_user');
    if (property_exists($externalauth, 'uid')) {
      return $externalauth->uid;
    }
  }

  /**
   * Replaces the authmap table retired in Drupal 8.
   */
  public static function getUserIdentifierFromMap($uid) {
    $authmap = \Drupal::service('externalauth.authmap');
    $authdata = $authmap->getAuthdata($uid, 'ldap_user');
    if (isset($authdata['authname']) && !empty($authdata['authname'])) {
      return $authdata['authname'];
    }
  }

  /**
   * @param User $account
   *   A drupal user object.
   *
   * @return boolean TRUE if user should be excluded from ldap provision/syncing
   */
  public static function excludeUser($account = NULL) {
    // Always exclude user 1.
    if (is_object($account) && $account->id() == 1) {
      return TRUE;
    }
    // Exclude users who have been manually flagged as excluded.
    if (is_object($account) && $account->get('ldap_user_ldap_exclude')->value == 1) {
      return TRUE;
    }
    // Everyone else is fine.
    return FALSE;
  }

  /**
   *
   */
  private function activeUserAuthentication() {
    $user_register = \Drupal::config('user.settings')
      ->get("register_no_approval_required");
    if ($this->config['acctCreation'] == self::$accountCreationLdapBehaviour || $user_register == USER_REGISTER_VISITORS) {
      $this->createLDAPAccounts = TRUE;
      $this->createLDAPAccountsAdminApproval = FALSE;
    }
    elseif ($user_register == USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL) {
      $this->createLDAPAccounts = FALSE;
      $this->createLDAPAccountsAdminApproval = TRUE;
    }
    else {
      $this->createLDAPAccounts = FALSE;
      $this->createLDAPAccountsAdminApproval = FALSE;
    }
  }

}

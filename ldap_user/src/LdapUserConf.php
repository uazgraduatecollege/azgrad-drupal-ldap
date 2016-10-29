<?php

namespace Drupal\ldap_user;

use Drupal\Component\Utility\Unicode;
use Drupal\user\Entity\User;

/**
 *  The entry-point to working with users by loading their configuration.
 */
class LdapUserConf {

  /**
   * Server providing Drupal account provisioning.
   *
   * @var string
   *
   * @see LdapServer::sid
   */
  public $drupalAcctProvisionServer = LDAP_USER_NO_SERVER_SID;

  /**
   * Server providing LDAP entry provisioning.
   *
   * @var string
   *
   * @see LdapServer::sid
   */
  public $ldapEntryProvisionServer = LDAP_USER_NO_SERVER_SID;

  /**
   * Associative array mapping synch directions to ldap server instances.
   *
   * @var array
   */
  public $provisionSidFromDirection = array(
    LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER => LDAP_USER_NO_SERVER_SID,
    LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY => LDAP_USER_NO_SERVER_SID,
  );

  /**
   * Array of events that trigger provisioning of Drupal Accounts
   * Valid constants are:
   *   LDAP_USER_DRUPAL_USER_PROV_ON_AUTHENTICATE
   *   LDAP_USER_DRUPAL_USER_PROV_ON_USER_UPDATE_CREATE
   *   LDAP_USER_DRUPAL_USER_PROV_ON_ALLOW_MANUAL_CREATE.
   *
   * @var array
   */
  public $drupalAcctProvisionTriggers = array(LDAP_USER_DRUPAL_USER_PROV_ON_AUTHENTICATE, LDAP_USER_DRUPAL_USER_PROV_ON_USER_UPDATE_CREATE, LDAP_USER_DRUPAL_USER_PROV_ON_ALLOW_MANUAL_CREATE);

  /**
   * Array of events that trigger provisioning of LDAP Entries
   * Valid constants are:
   *   LDAP_USER_LDAP_ENTRY_PROV_ON_USER_UPDATE_CREATE
   *   LDAP_USER_LDAP_ENTRY_PROV_ON_AUTHENTICATE
   *   LDAP_USER_LDAP_ENTRY_DELETE_ON_USER_DELETE.
   *
   * @var array
   */
  public $ldapEntryProvisionTriggers = array();

  /**
   * Server providing LDAP entry provisioning.
   *
   * @var string
   *
   * @see LdapServer::sid
   */
  public $userConflictResolve = LDAP_USER_CONFLICT_RESOLVE_DEFAULT;

  /**
   * Drupal account creation model.
   *
   * @var int
   *   LDAP_USER_ACCT_CREATION_LDAP_BEHAVIOR   /admin/config/people/accounts/settings do not affect "LDAP Associated" Drupal accounts.
   *   LDAP_USER_ACCT_CREATION_USER_SETTINGS_FOR_LDAP  use Account creation settings at /admin/config/people/accounts/settings
   */
  public $acctCreation = LDAP_USER_ACCT_CREATION_LDAP_BEHAVIOR_DEFAULT;

  /**
   * Has current object been saved to the database?
   *
   * @var boolean
   */
  public $inDatabase = FALSE;

  /**
   * What to do when an ldap provisioned username conflicts with existing drupal user?
   *
   * @var int
   *   LDAP_USER_CONFLICT_LOG - log the conflict
   *   LDAP_USER_CONFLICT_RESOLVE - LDAP associate the existing drupal user
   */
  public $manualAccountConflict = LDAP_USER_MANUAL_ACCT_CONFLICT_REJECT;

  // @todo default to FALSE and check for mapping to set to true
  public $setsLdapPassword = TRUE;

  public $loginConflictResolve = FALSE;
  /**
   * Array of field synch mappings provided by all modules (via hook_ldap_user_attrs_list_alter())
   * array of the form: array(
   * LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER | LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY => array(
   *   <server_id> => array(
   *     'sid' => <server_id> (redundant)
   *     'ldap_attr' => e.g. [sn]
   *     'user_attr'  => e.g. [field.field_user_lname] (when this value is set to 'user_tokens', 'user_tokens' value is used.)
   *     'user_tokens' => e.g. [field.field_user_lname], [field.field_user_fname]
   *     'convert' => 1|0 boolean indicating need to covert from binary
   *     'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER | LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY (redundant)
   *     'config_module' => 'ldap_user'
   *     'prov_module' => 'ldap_user'
   *     'enabled' => 1|0 boolean
   *      prov_events' => array( of LDAP_USER_EVENT_* constants indicating during which synch actions field should be synched)
   *         - four permutations available
   *            to ldap:   LDAP_USER_EVENT_CREATE_LDAP_ENTRY,  LDAP_USER_EVENT_SYNCH_TO_LDAP_ENTRY,
   *            to drupal: LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER
   *    )
   *  )
   */
  // Array of field synching directions for each operation.  should include ldapUserSynchMappings.
  public $synchMapping = NULL;
  // Keyed on direction => property, ldap, or field token such as '[field.field_lname] with brackets in them.
  /**
   * Synch mappings configured in ldap user module (not in other modules)
   *   array of the form: array(
   * LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER | LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY => array(
   * 'sid' => <server_id> (redundant)
   * 'ldap_attr' => e.g. [sn]
   * 'user_attr'  => e.g. [field.field_user_lname] (when this value is set to 'user_tokens', 'user_tokens' value is used.)
   * 'user_tokens' => e.g. [field.field_user_lname], [field.field_user_fname]
   * 'convert' => 1|0 boolean indicating need to covert from binary
   * 'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER | LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY (redundant)
   * 'config_module' => 'ldap_user'
   * 'prov_module' => 'ldap_user'
   * 'enabled' => 1|0 boolean
   * prov_events' => array( of LDAP_USER_EVENT_* constants indicating during which synch actions field should be synched)
   * - four permutations available
   * to ldap:   LDAP_USER_EVENT_CREATE_LDAP_ENTRY,  LDAP_USER_EVENT_SYNCH_TO_LDAP_ENTRY,
   * to drupal: LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER
   * )
   * )
   * )
   */
  public $ldapUserSynchMappings = NULL;
  // Keyed on property, ldap, or field token such as '[field.field_lname] with brackets in them.
  public $detailedWatchdog = FALSE;
  public $provisionsDrupalAccountsFromLdap = FALSE;
  public $provisionsLdapEntriesFromDrupalUsers = FALSE;

  // What should be done with ldap provisioned accounts that no longer have associated drupal accounts.
  public $orphanedDrupalAcctBehavior = 'ldap_user_orphan_email';
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

  public $orphanedCheckQty = 100;

  // Public $wsKey = NULL;
  //  public $wsEnabled = 0;
  //  public $wsUserIps = array();
  public $provisionsLdapEvents = array();
  public $provisionsDrupalEvents = array();

  public $saveable = array(
    'drupalAcctProvisionServer',
    'ldapEntryProvisionServer',
    'drupalAcctProvisionTriggers',
    'ldapEntryProvisionTriggers',
    'orphanedDrupalAcctBehavior',
    'orphanedCheckQty',
    'userConflictResolve',
    'manualAccountConflict',
    'acctCreation',
    'ldapUserSynchMappings',
  );

  /**
   * 'wsKey','wsEnabled','wsUserIps',.
   */
  function __construct() {
    $this->load();

    $this->provisionSidFromDirection[LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER] = $this->drupalAcctProvisionServer;
    $this->provisionSidFromDirection[LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY] = $this->ldapEntryProvisionServer;

    $this->provisionsLdapEvents = array(
      LDAP_USER_EVENT_CREATE_LDAP_ENTRY => t('On LDAP Entry Creation'),
      LDAP_USER_EVENT_SYNCH_TO_LDAP_ENTRY => t('On Synch to LDAP Entry'),
    );

    $this->provisionsDrupalEvents = array(
      LDAP_USER_EVENT_CREATE_DRUPAL_USER => t('On Drupal User Creation'),
      LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER => t('On Synch to Drupal User'),
    );

    $this->provisionsDrupalAccountsFromLdap = (
      $this->drupalAcctProvisionServer &&
      $this->drupalAcctProvisionServer &&
      (count(array_filter(array_values($this->drupalAcctProvisionTriggers))) > 0)
    );

    $this->provisionsLdapEntriesFromDrupalUsers = (
      $this->ldapEntryProvisionServer
      && $this->ldapEntryProvisionServer
      && (count(array_filter(array_values($this->ldapEntryProvisionTriggers))) > 0)
      );

    $this->setSynchMapping(TRUE);
    $this->detailedWatchdog = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
  }

  /**
   *
   */
  function load() {

    if ($saved = \Drupal::config('ldap_user.settings')->get("ldap_user_conf")) {
      $this->inDatabase = TRUE;
      foreach ($this->saveable as $property) {
        if (isset($saved[$property])) {
          $this->{$property} = $saved[$property];
        }
      }
    }
    else {
      $this->inDatabase = FALSE;
    }
    // Determine account creation configuration.
    // @FIXME
    // $user_register = variable_get('user_register', USER_REGISTER_VISITORS_ADMINISTRATIVE_APPROVAL);.
    $user_register = \Drupal::config('user.settings')->get("register_no_approval_required");
    if ($this->acctCreation == LDAP_USER_ACCT_CREATION_LDAP_BEHAVIOR_DEFAULT || $user_register == USER_REGISTER_VISITORS) {
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

  /**
   * Destructor Method.
   */
  function __destruct() {}

  /**
   * Util to fetch mappings for a given direction.
   *
   * @param string $sid
   *   The server id
   * @param string $direction
   *   LDAP_USER_PROV_DIRECTION_* constant
   * @param array $prov_events
   *
   * @return array/bool
   *   Array of mappings (may be empty array)
   */
  public function getSynchMappings($direction = LDAP_USER_PROV_DIRECTION_ALL, $prov_events = NULL) {
    if (!$prov_events) {
      $prov_events = ldap_user_all_events();
    }

    $mappings = array();
    if ($direction == LDAP_USER_PROV_DIRECTION_ALL) {
      $directions = array(LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY);
    }
    else {
      $directions = array($direction);
    }
    foreach ($directions as $direction) {
      if (!empty($this->ldapUserSynchMappings[$direction])) {
        foreach ($this->ldapUserSynchMappings[$direction] as $attribute => $mapping) {
          if (!empty($mapping['prov_events'])) {
            $result = count(array_intersect($prov_events, $mapping['prov_events']));
            if ($result) {
              if ($direction == LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER && isset($mapping['user_attr'])) {
                $key = $mapping['user_attr'];
              }
              elseif ($direction == LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY && isset($mapping['ldap_attr'])) {
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
   *
   */
  public function isDrupalAcctProvisionServer($sid) {
    if (!$sid || !$this->drupalAcctProvisionServer) {
      return FALSE;
    }
    elseif ($this->ldapEntryProvisionServer == $sid) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   *
   */
  public function isLdapEntryProvisionServer($sid) {
    if (!$sid || !$this->ldapEntryProvisionServer) {
      return FALSE;
    }
    elseif ($this->ldapEntryProvisionServer == $sid) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Util to fetch attributes required for this user conf, not other modules.
   *
   * @param enum $direction
   *   LDAP_USER_PROV_DIRECTION_* constants
   * @param string $ldap_context
   */
  public function getLdapUserRequiredAttributes($direction = LDAP_USER_PROV_DIRECTION_ALL, $ldap_context = NULL) {

    $attributes_map = array();
    $required_attributes = array();
    if ($this->drupalAcctProvisionServer) {
      $prov_events = $this->ldapContextToProvEvents($ldap_context);
      $attributes_map = $this->getSynchMappings($direction, $prov_events);
      $required_attributes = array();
      foreach ($attributes_map as $detail) {
        if (count(array_intersect($prov_events, $detail['prov_events']))) {
          // Add the attribute to our array.
          if ($detail['ldap_attr']) {
            ldap_servers_token_extract_attributes($required_attributes, $detail['ldap_attr']);
          }
        }
      }
    }
    return $required_attributes;
  }

  /**
   * Converts the more general ldap_context string to its associated ldap user event.
   */
  public function ldapContextToProvEvents($ldap_context = NULL) {

    switch ($ldap_context) {

      case 'ldap_user_prov_to_drupal':
        $result = array(LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER, LDAP_USER_EVENT_CREATE_DRUPAL_USER, LDAP_USER_EVENT_LDAP_ASSOCIATE_DRUPAL_ACCT);
        break;

      case 'ldap_user_prov_to_ldap':
        $result = array(LDAP_USER_EVENT_SYNCH_TO_LDAP_ENTRY, LDAP_USER_EVENT_CREATE_LDAP_ENTRY);
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
        $result = LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER;
        break;

      case 'ldap_user_prov_to_ldap':
      case 'ldap_user_delete_drupal_user':
        $result = LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY;
        break;

      // Provisioning is can hapen in both directions in most contexts.
      case 'ldap_user_insert_drupal_user':
      case 'ldap_user_update_drupal_user':
      case 'ldap_authentication_authenticate':
      case 'ldap_user_disable_drupal_user':
        $result = LDAP_USER_PROV_DIRECTION_ALL;
        break;

      default:
        $result = LDAP_USER_PROV_DIRECTION_ALL;

    }

    return $result;
  }

  /**
   * Derive mapping array from ldap user configuration and other configurations.
   * if this becomes a resource hungry function should be moved to ldap_user functions
   * and stored with static variable. should be cached also.
   *    * This should be cached and modules implementing ldap_user_synch_mapping_alter
   * should know when to invalidate cache.   *    .*/

  /**
   * @todo change default to false after development
   */
  function setSynchMapping($reset = TRUE) {

    $synch_mapping_cache = \Drupal::cache()->get('ldap_user_synch_mapping');
    if (!$reset && $synch_mapping_cache) {
      $this->synchMapping = $synch_mapping_cache->data;
    }
    else {
      $available_user_attrs = array();
      foreach (array(LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY) as $direction) {
        $sid = $this->provisionSidFromDirection[$direction];
        $available_user_attrs[$direction] = array();
        $ldap_server = ($sid) ? ldap_servers_get_servers($sid, NULL, TRUE) : FALSE;

        $params = array(
          'ldap_server' => $ldap_server,
          'ldap_user_conf' => $this,
          'direction' => $direction,
        );

        \Drupal::moduleHandler()->alter('ldap_user_attrs_list', $available_user_attrs[$direction], $params);
      }
    }
    $this->synchMapping = $available_user_attrs;

    \Drupal::cache()->set('ldap_user_synch_mapping', $this->synchMapping);
  }

  /**
   * Given a $prov_event determine if ldap user configuration supports it.
   *   this is overall, not per field synching configuration.
   *
   * @param enum $direction
   *   LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER or LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY
   *
   * @param enum $prov_event
   *   LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER, LDAP_USER_EVENT_CREATE_DRUPAL_USER
   *   LDAP_USER_EVENT_SYNCH_TO_LDAP_ENTRY LDAP_USER_EVENT_CREATE_LDAP_ENTRY
   *   LDAP_USER_EVENT_LDAP_ASSOCIATE_DRUPAL_ACCT
   *   LDAP_USER_EVENT_ALL
   *
   * @param enum $action
   *   'synch', 'provision', 'delete_ldap_entry', 'delete_drupal_entry', 'cancel_drupal_entry'
   *
   * @return boolean
   */
  public function provisionEnabled($direction, $provision_trigger) {
    $result = FALSE;

    if ($direction == LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY) {

      if (!$this->ldapEntryProvisionServer) {
        $result = FALSE;
      }
      else {
        $result = in_array($provision_trigger, $this->ldapEntryProvisionTriggers);
      }

    }
    elseif ($direction == LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER) {
      if (!$this->drupalAcctProvisionServer) {
        $result = FALSE;
      }
      else {
        $result = in_array($provision_trigger, $this->drupalAcctProvisionTriggers);
      }
    }

    return $result;
  }

  /**
   * Given a drupal account, provision an ldap entry if none exists.  if one exists do nothing.
   *
   * @param object $account
   *   drupal account object with minimum of name property
   * @param array $ldap_user
   *   as prepopulated ldap entry.  usually not provided
   *
   * @return array of form:
   *     array('status' => 'success', 'fail', or 'conflict'),
   *     array('ldap_server' => ldap server object),
   *     array('proposed' => proposed ldap entry),
   *     array('existing' => existing ldap entry),
   *     array('description' = > blah blah)
   */
  public function provisionLdapEntry($account, $ldap_user = NULL, $test_query = FALSE) {
    // debug('provisionLdapEntry account'); //debug($account);
    $watchdog_tokens = array();
    $result = array(
      'status' => NULL,
      'ldap_server' => NULL,
      'proposed' => NULL,
      'existing' => NULL,
      'description' => NULL,
    );

    if (is_scalar($account)) {
      $username = $account;
      $account = new stdClass();
      $account->name = $username;
    }

    /* @var \Drupal\user\Entity\user $account */
    /* @var \Drupal\user\Entity\user $user_entity */
    list($account, $user_entity) = ldap_user_load_user_acct_and_entity($account->getUsername());

    if (is_object($account) && $account->id() == 1) {
      $result['status'] = 'fail';
      $result['error_description'] = 'can not provision drupal user 1';
      // Do not provision or synch user 1.
      return $result;
    }

    if ($account == FALSE || $account->isAnonymous()) {
      $result['status'] = 'fail';
      $result['error_description'] = 'can not provision ldap user unless corresponding drupal account exists first.';
      return $result;
    }

    if (!$this->ldapEntryProvisionServer || !$this->ldapEntryProvisionServer) {
      $result['status'] = 'fail';
      $result['error_description'] = 'no provisioning server enabled';
      return $result;
    }

    $ldap_server = ldap_servers_get_servers($this->ldapEntryProvisionServer, NULL, TRUE);
    $params = array(
      'direction' => LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY,
      'prov_events' => array(LDAP_USER_EVENT_CREATE_LDAP_ENTRY),
      'module' => 'ldap_user',
      'function' => 'provisionLdapEntry',
      'include_count' => FALSE,
    );

    list($proposed_ldap_entry, $error) = $this->drupalUserToLdapEntry($account, $ldap_server, $params, $ldap_user);
    $proposed_dn = (is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn']) && $proposed_ldap_entry['dn']) ? $proposed_ldap_entry['dn'] : NULL;
    $proposed_dn_lcase = Unicode::strtolower($proposed_dn);
    $existing_ldap_entry = ($proposed_dn) ? $ldap_server->dnExists($proposed_dn, 'ldap_entry') : NULL;

    if ($error == LDAP_USER_PROV_RESULT_NO_PWD) {
      $result['status'] = 'fail';
      $result['description'] = 'Can not provision ldap account without user provided password.';
      $result['existing'] = $existing_ldap_entry;
      $result['proposed'] = $proposed_ldap_entry;
      $result['ldap_server'] = $ldap_server;
    }
    elseif (!$proposed_dn) {
      $result['status'] = 'fail';
      $result['description'] = t('failed to derive dn and or mappings');
      return $result;
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
        $result['status'] = 'success';
        $result['description'] = 'ldap account created';
        $result['proposed'] = $proposed_ldap_entry;
        $result['created'] = $ldap_entry_created;
        $result['ldap_server'] = $ldap_server;

        // Need to store <sid>|<dn> in ldap_user_prov_entries field, which may contain more than one.
        $ldap_user_prov_entry = $ldap_server->id() . '|' . $proposed_ldap_entry['dn'];
        if (null !== $user_entity->get('ldap_user_prov_entries')) {
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
        $result['status'] = 'fail';
        $result['proposed'] = $proposed_ldap_entry;
        $result['created'] = $ldap_entry_created;
        $result['ldap_server'] = $ldap_server;
        $result['existing'] = NULL;
      }
    }

    $tokens = array(
      '%dn' => isset($result['proposed']['dn']) ? $result['proposed']['dn'] : NULL,
      '%sid' => (isset($result['ldap_server']) && $result['ldap_server']) ? $result['ldap_server']->id() : 0,
      '%username' => @$account->getUsername(),
      '%uid' => @$account->id(),
      '%description' => @$result['description'],
    );
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
   * Given a drupal account, synch to related ldap entry.
   *
   * @param drupal user object $account.
   *   Drupal user object
   * @param array $user_edit.
   *   Edit array for user_save.  generally null unless user account is being created or modified in same synching
   * @param array $ldap_user.
   *   current ldap data of user. @see README.developers.txt for structure
   *
   * @return TRUE on success or FALSE on fail.
   */
  public function synchToLdapEntry($account, $user_edit = NULL, $ldap_user = array(), $test_query = FALSE) {

    if (is_object($account) && property_exists($account, 'uid') && $account->uid == 1) {
      // Do not provision or synch user 1.
      return FALSE;
    }

    $watchdog_tokens = array();
    $result = FALSE;
    $proposed_ldap_entry = FALSE;

    if ($this->ldapEntryProvisionServer) {
      $ldap_server = ldap_servers_get_servers($this->ldapEntryProvisionServer, NULL, TRUE);

      $params = array(
        'direction' => LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY,
        'prov_events' => array(LDAP_USER_EVENT_SYNCH_TO_LDAP_ENTRY),
        'module' => 'ldap_user',
        'function' => 'synchToLdapEntry',
        'include_count' => FALSE,
      );

      list($proposed_ldap_entry, $error) = $this->drupalUserToLdapEntry($account, $ldap_server, $params, $ldap_user);
      if ($error != LDAP_USER_PROV_RESULT_NO_ERROR) {
        $result = FALSE;
      }
      elseif (is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn'])) {
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
          $result = array(
            'proposed' => $proposed_ldap_entry,
            'server' => $ldap_server,
          );
        }
        else {
          // //debug('modifyLdapEntry,dn=' . $proposed_ldap_entry['dn']);  //debug($attributes);
          // stick $proposed_ldap_entry in $ldap_entries array for drupal_alter call.
          $proposed_dn_lcase = Unicode::strtolower($proposed_ldap_entry['dn']);
          $ldap_entries = array($proposed_dn_lcase => $attributes);
          $context = array(
            'action' => 'update',
            'corresponding_drupal_data' => array($proposed_dn_lcase => $attributes),
            'corresponding_drupal_data_type' => 'user',
          );
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

    $tokens = array(
      '%dn' => isset($result['proposed']['dn']) ? $result['proposed']['dn'] : NULL,
      '%sid' => $this->ldapEntryProvisionServer,
      '%username' => $account->name,
      '%uid' => ($test_query || !property_exists($account, 'uid')) ? '' : $account->uid,
    );

    if ($result) {
      \Drupal::logger('ldap_user')->info('LDAP entry on server %sid synched dn=%dn. username=%username, uid=%uid', []);
    }
    else {
      \Drupal::logger('ldap_user')->error('LDAP entry on server %sid not synched because error. username=%username, uid=%uid', []);
    }

    return $result;

  }

  /**
   * Given a drupal account, query ldap and get all user fields and create user account.
   *
   * @param array $account
   *   drupal account array with minimum of name
   * @param array $user_edit
   *   drupal edit array in form user_save($account, $user_edit) would take,
   *   generally empty unless overriding synchToDrupalAccount derived values
   * @param array $ldap_user
   *   as user's ldap entry.  passed to avoid requerying ldap in cases where already present
   * @param bool $save
   *   indicating if drupal user should be saved.  generally depends on where function is called from.
   *
   * @return result of user_save() function is $save is true, otherwise return TRUE
   *   $user_edit data returned by reference
   */
  public function synchToDrupalAccount($drupal_user, &$user_edit, $prov_event = LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER, $ldap_user = NULL, $save = FALSE) {

    $debug = array(
      'account' => $drupal_user,
      'user_edit' => $user_edit,
      'ldap_user' => $ldap_user,
    );

    if (
        (!$ldap_user  && !isset($drupal_user->name)) ||
        (!$drupal_user && $save) ||
        ($ldap_user && !isset($ldap_user['sid']))
    ) {
      // Should throw watchdog error also.
      return FALSE;
    }

    if (!$ldap_user && $this->drupalAcctProvisionServer) {
      $ldap_user = ldap_servers_get_user_ldap_data($drupal_user->name, $this->drupalAcctProvisionServer, 'ldap_user_prov_to_drupal');
    }

    if (!$ldap_user) {
      return FALSE;
    }

    if ($this->drupalAcctProvisionServer) {
      $ldap_server = ldap_servers_get_servers($this->drupalAcctProvisionServer, NULL, TRUE);
      // @FIXME $user_edit is deprecated.
      $this->entryToUserEdit($ldap_user, $user_edit, $ldap_server, LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, array($prov_event));
    }

    if ($save) {
      $account = \Drupal::entityManager()->getStorage('user')->load($drupal_user->uid);
      $result = user_save($account, $user_edit, 'ldap_user');
      return $result;
    }
    else {
      return TRUE;
    }
  }

  /**
   * Given a drupal account, delete user account.
   *
   * @param string $username
   *   drupal account name
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
    $sid = $this->ldapEntryProvisionServer;
    // debug("ldapEntryProvisionServer:$sid");.
    if (!$sid) {
      return FALSE;
    }
    // $user_entity->ldap_user_prov_entries,.
    $ldap_server = ldap_servers_get_servers($sid, NULL, TRUE);
    $params = array(
      'direction' => LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY,
      'prov_events' => $prov_events,
      'module' => 'ldap_user',
      'function' => 'getProvisionRelatedLdapEntry',
      'include_count' => FALSE,
    );
    list($proposed_ldap_entry, $error) = $this->drupalUserToLdapEntry($account, $ldap_server, $params);
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
   * @param object $account
   *   drupal account
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
          $ldap_server = ldap_servers_get_servers($sid, NULL, TRUE);
          if (is_object($ldap_server) && $dn) {
            $boolean_result = $ldap_server->delete($dn);
            $tokens = array('%sid' => $sid, '%dn' => $dn, '%username' => $account->name, '%uid' => $account->uid);
            if ($boolean_result) {
              \Drupal::logger('ldap_user')->info('LDAP entry on server %sid deleted dn=%dn. username=%username, uid=%uid', []);
            }
            else {
              \Drupal::logger('ldap_user')->error('LDAP entry on server %sid not deleted because error. username=%username, uid=%uid', []);
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
   *   drupal account
   * @param object $ldap_server
   * @param array $params
   *   with the following key values:
   *    'ldap_context' =>
   *   'module' => module calling function, e.g. 'ldap_user'
   *   'function' => function calling function, e.g. 'provisionLdapEntry'
   *   'include_count' => should 'count' array key be included
   *   'direction' => LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY || LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER
   * @param null $ldap_user_entry
   *
   * @return array(ldap entry, $result)
   *   In ldap extension array format. THIS IS NOT THE ACTUAL LDAP ENTRY.
   */
  function drupalUserToLdapEntry(User $account, $ldap_server, $params, $ldap_user_entry = NULL) {
    // debug('call to drupalUserToLdapEntry, account:'); //debug($account); //debug('ldap_server'); //debug($ldap_server);
    // debug('params'); //debug($params); //debug('ldap_user_entry');//debug($ldap_user_entry);
    $provision = (isset($params['function']) && $params['function'] == 'provisionLdapEntry');
    $result = LDAP_USER_PROV_RESULT_NO_ERROR;
    if (!$ldap_user_entry) {
      $ldap_user_entry = array();
    }

    if (!is_object($account) || !is_object($ldap_server)) {
      return array(NULL, LDAP_USER_PROV_RESULT_BAD_PARAMS);
    }
    $watchdog_tokens = array(
      '%drupal_username' => $account->getUsername(),
    );
    $include_count = (isset($params['include_count']) && $params['include_count']);

    $direction = isset($params['direction']) ? $params['direction'] : LDAP_USER_PROV_DIRECTION_ALL;
    $prov_events = empty($params['prov_events']) ? ldap_user_all_events() : $params['prov_events'];

    $mappings = $this->getSynchMappings($direction, $prov_events);
    // debug('prov_events'); //debug(join(",",$prov_events));
    //  debug('mappings'); debug($mappings);
    // Loop over the mappings.
    foreach ($mappings as $field_key => $field_detail) {
      // trim($field_key, '[]');.
      list($ldap_attr_name, $ordinal, $conversion) = ldap_servers_token_extract_parts($field_key, TRUE);
      $ordinal = (!$ordinal) ? 0 : $ordinal;
      if ($ldap_user_entry && isset($ldap_user_entry[$ldap_attr_name]) && is_array($ldap_user_entry[$ldap_attr_name]) && isset($ldap_user_entry[$ldap_attr_name][$ordinal])) {
        // don't override values passed in;.
        continue;
      }

      $synched = $this->isSynched($field_key, $params['prov_events'], LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY);
      // debug("isSynched $field_key: $synched");.
      if ($synched) {
        $token = ($field_detail['user_attr'] == 'user_tokens') ? $field_detail['user_tokens'] : $field_detail['user_attr'];
        $value = ldap_servers_token_replace($account, $token, 'user_account');

        // Deal with empty/unresolved password.
        if (substr($token, 0, 10) == '[password.' && (!$value || $value == $token)) {
          if (!$provision) {
            // don't overwrite password on synch if no value provided.
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

    /**
     * 4. call drupal_alter() to allow other modules to alter $ldap_user
     */

    \Drupal::moduleHandler()->alter('ldap_entry', $ldap_user_entry, $params);

    return array($ldap_user_entry, $result);

  }

  /**
   * Provision a Drupal user account.
   *
   * Given a drupal account, query LDAP and get all user fields and save the
   * user account. Nnote: parameters are in odd order to match
   * synchDrupalAccount handle.
   *
   * @param User|boolean $account
   *   Drupal account object or null.
   *   Todo: Fix default value of false or correct comment.
   * @param array $user_edit
   *   Drupal edit array in form user_save($account, $user_edit) would take.
   * @param array $ldap_user
   *   User's ldap entry. Passed to avoid requerying ldap in cases where already
   *   present.
   * @param bool $save
   *   Indicating if Drupal user should be saved. Generally depends on where
   *   function is called from and if the result of the save is true.
   *   Todo: Fix architecture here.
   *
   * @return boolean
   *   Return TRUE on success or FALSE on any problem.
   */
  public function provisionDrupalAccount($account = FALSE, &$user_edit, $ldap_user = NULL, $save = TRUE) {

    $watchdog_tokens = array();
    /**
     * @TODO: Add error catching for conflicts.
     * Conflicts should be checked before calling this function.
     */

    if (!$account) {
      $account = \Drupal::entityManager()->getStorage('user')->create($user_edit);
    }
    $account->enforceIsNew();

    // Should pass in an LDAP record or a username.
    if (!$ldap_user && !isset($user_edit['name'])) {
      return FALSE;
    }

    // Get an LDAP user from the LDAP server.
    if (!$ldap_user) {
      $watchdog_tokens['%username'] = $user_edit['name'];
      if ($this->drupalAcctProvisionServer) {
        $ldap_user = ldap_servers_get_user_ldap_data($user_edit['name'], $this->drupalAcctProvisionServer, 'ldap_user_prov_to_drupal');
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
      $ldap_server = ldap_servers_get_servers($this->drupalAcctProvisionServer, 'enabled', TRUE);
      $account->set('name', $ldap_user[$ldap_server->get('user_attr')]);
      $watchdog_tokens['%username'] = $account->getUsername();
    }

    // Can we get details from an LDAP server?
    if ($this->drupalAcctProvisionServer) {

      // $ldap_user['sid'].
      $ldap_server = ldap_servers_get_servers($this->drupalAcctProvisionServer, 'enabled', TRUE);

      $params = array(
        'account' => $account,
        'user_edit' => $user_edit,
        'prov_event' => LDAP_USER_EVENT_CREATE_DRUPAL_USER,
        'module' => 'ldap_user',
        'function' => 'provisionDrupalAccount',
        'direction' => LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER,
      );

      \Drupal::moduleHandler()->alter('ldap_entry', $ldap_user, $params);

      // Look for existing drupal account with same puid.  if so update username and attempt to synch in current context.
      $puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      // FIXME: The entire account2 operation is broken.
      $account2 = ($puid) ? $ldap_server->userUserEntityFromPuid($puid) : FALSE;

      // Synch drupal account, since drupal account exists.
      if ($account2) {
        // 1. correct username and authmap.
        $this->entryToUserEdit($ldap_user, $account2, $ldap_server, LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, array(LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER));
        $account = $account2;
        $account->save();
        // Update the identifier table.
        ldap_user_set_identifier($account, $account->getUsername());

        // 2. attempt synch if appropriate for current context.
        // @FIXME $user_edit is deprecated (LDAP)
        if ($account) {
          $account = $this->synchToDrupalAccount($account, $user_edit, LDAP_USER_EVENT_SYNCH_TO_DRUPAL_USER, $ldap_user, TRUE);
        }
        return $account;
      }
      // Create drupal account.
      else {
        $this->entryToUserEdit($ldap_user, $account, $ldap_server, LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, array(LDAP_USER_EVENT_CREATE_DRUPAL_USER));
        if ($save) {
          $watchdog_tokens = array('%drupal_username' => $account->get('name'));
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
            $watchdog_tokens['%email'] = $mail;
            $watchdog_tokens['%duplicate_name'] = $account_with_same_email->name;
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
            ldap_user_set_identifier($account, $account->getUsername());
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
  function ldapAssociateDrupalAccount($drupal_username) {
    if ($this->drupalAcctProvisionServer) {
      $prov_events = array(LDAP_USER_EVENT_LDAP_ASSOCIATE_DRUPAL_ACCT);
      // $ldap_user['sid'].
      $ldap_server = ldap_servers_get_servers($this->drupalAcctProvisionServer, 'enabled', TRUE);
      $account = user_load_by_name($drupal_username);
      $ldap_user = ldap_servers_get_user_ldap_data($drupal_username, $this->drupalAcctProvisionServer, 'ldap_user_prov_to_drupal');
      if (!$account) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because account not found', array('%drupal_username' => $drupal_username));
        return FALSE;
      }
      elseif (!$ldap_user) {
        \Drupal::logger('ldap_user')->error('Failed to LDAP associate drupal account %drupal_username because corresponding LDAP entry not found', array('%drupal_username' => $drupal_username));
        return FALSE;
      }
      else {
        // @TODO Data has been retired. Should we migrate it somewhere else?
        try {
          $data = unserialize($account->get('data'));
          if (!is_array($data)) {
            $data = array();
          }

          $data['ldap_user']['init'] = array(
            'sid'  => $ldap_server->id(),
            'dn'   => $ldap_user['dn'],
            'mail'   => $account->mail,
          );
          $account->set('data', serialize($data));
        }
        catch (Exception $e) {
          // Do nothing.
        }

        $ldap_user_puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
        if ($ldap_user_puid) {
          $account->set('ldap_user_puid', $ldap_user_puid);
        }
        $account->set('ldap_user_puid_property', $ldap_server->get('unique_persistent_attr'));
        // @TODO Should be changed to ldap_user_puid_server_id
        $account->set('ldap_user_puid_sid', $ldap_server->id());
        $account->set('ldap_user_current_dn', $ldap_user['dn']);
        // @TODO Shouldn't we set the "last checked" date?
        $account->set('ldap_user_last_checked', time());
        $account->set('ldap_user_ldap_exclude', 0);
        $account->save();
        return (boolean) $account;
      }
    }
    else {
      return FALSE;
    }
  }

  /**
   * Set flag to exclude user from LDAP association
   *
   * @param string $drupal_username
   *
   * @return boolean TRUE on success, FALSE on error or failure because of invalid user
   */
  function ldapExcludeDrupalAccount($drupal_username) {
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
   * ... should not assume all attribues are present in ldap entry.
   *
   * @param array ldap entry $ldap_user
   * @param User $account
   *   see hook_user_save, hook_user_update, etc
   * @param object $ldap_server
   * @param enum $direction
   * @param array $prov_events
   */
  function entryToUserEdit($ldap_user, &$account, $ldap_server, $direction = LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER, $prov_events = NULL) {

    // Need array of user fields and which direction and when they should be synched.
    if (!$prov_events) {
      $prov_events = ldap_user_all_events();
    }
    $mail_synched = $this->isSynched('[property.mail]', $prov_events, $direction);
    if (!$account->getEmail() && $mail_synched) {
      $derived_mail = $ldap_server->userEmailFromLdapEntry($ldap_user['attr']);
      if ($derived_mail) {
        $account->set('mail', $derived_mail);
      }
    }

    $drupal_username = $ldap_server->userUsernameFromLdapEntry($ldap_user['attr']);
    if ($this->isSynched('[property.picture]', $prov_events, $direction)) {

      $picture = $ldap_server->userPictureFromLdapEntry($ldap_user['attr'], $drupal_username);

      if ($picture) {
        $account->set('picture', $picture);
      }
    }

    if ($this->isSynched('[property.name]', $prov_events, $direction) && !$account->getUsername() && $drupal_username) {
      $account->set('name', $drupal_username);
    }

    // Only fired on LDAP_USER_EVENT_CREATE_DRUPAL_USER. Shouldn't it respect the checkbox on the sync form?
    if ($direction == LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER && in_array(LDAP_USER_EVENT_CREATE_DRUPAL_USER, $prov_events)) {
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
    if ($this->isSynched('[field.ldap_user_puid]', $prov_events, $direction)) {
      $ldap_user_puid = $ldap_server->userPuidFromLdapEntry($ldap_user['attr']);
      if ($ldap_user_puid) {
        $account->set('ldap_user_puid', $ldap_user_puid);
      }
    }
    if ($this->isSynched('[field.ldap_user_puid_property]', $prov_events, $direction)) {
      $account->set('ldap_user_puid_property', $ldap_server->unique_persistent_attr);
    }
    if ($this->isSynched('[field.ldap_user_puid_sid]', $prov_events, $direction)) {
      $account->set('ldap_user_puid_sid', $ldap_server->id());
    }
    if ($this->isSynched('[field.ldap_user_current_dn]', $prov_events, $direction)) {
      $account->set('ldap_user_current_dn', $ldap_user['dn']);
    }

    // Get any additional mappings.
    $mappings = $this->getSynchMappings($direction, $prov_events);

    // Loop over the mappings.
    foreach ($mappings as $user_attr_key => $field_detail) {

      // Make sure this mapping is relevant to the sync context.
      if (!$this->isSynched($user_attr_key, $prov_events, $direction)) {
        continue;
      }
      /**
        * if "convert from binary is selected" and no particular method is in token,
        * default to ldap_servers_binary() function
        */
      if ($field_detail['convert'] && strpos($field_detail['ldap_attr'], ';') === FALSE) {
        $field_detail['ldap_attr'] = str_replace(']', ';binary]', $field_detail['ldap_attr']);
      }
      $value = ldap_servers_token_replace($ldap_user['attr'], $field_detail['ldap_attr'], 'ldap_entry');
      list($value_type, $value_name, $value_instance) = ldap_servers_parse_user_attr_name($user_attr_key);

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
   * Given configuration of synching, determine is a given synch should occur.
   *
   * @param string $attr_token
   *   e.g. [property.mail], [field.ldap_user_puid_property]
   * @param object $ldap_server
   * @param array $prov_events
   *   e.g. array(LDAP_USER_EVENT_CREATE_DRUPAL_USER).  typically array with 1 element
   * @param scalar $direction
   *   LDAP_USER_PROV_DIRECTION_TO_DRUPAL_USER or LDAP_USER_PROV_DIRECTION_TO_LDAP_ENTRY
   */
  public function isSynched($attr_token, $prov_events, $direction) {
    $result = (boolean) (
      isset($this->synchMapping[$direction][$attr_token]['prov_events']) &&
      count(array_intersect($prov_events, $this->synchMapping[$direction][$attr_token]['prov_events']))
    );
    if (!$result) {
      if (isset($this->synchMapping[$direction][$attr_token])) {
        // debug($this->synchMapping[$direction][$attr_token]);.
      }
      else {
        // debug("$attr_token not in ldapUserConf::synchMapping");.
      }
    }
    return $result;
  }

} // end LdapUserConf class

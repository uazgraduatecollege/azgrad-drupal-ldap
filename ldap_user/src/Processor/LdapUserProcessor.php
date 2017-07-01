<?php

namespace Drupal\ldap_user\Processor;

use Drupal\Component\Utility\Unicode;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Exception\LdapBadParamsException;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\user\Entity\User;

/**
 *
 */
class LdapUserProcessor {

  private $config;
  private $detailedWatchdog = FALSE;

  /**
   *
   */
  public function __construct() {
    $this->config = \Drupal::config('ldap_user.settings')->get();
    $this->detailedWatchdog = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
  }

  /**
   * Given a drupal account, sync to related ldap entry.
   *
   * @param \Drupal\user\Entity\User $account
   *   Drupal user object.
   * @param array $ldap_user
   *   Current LDAP data of user. See README.developers.txt for structure.
   * @param bool $test_query
   *
   * @return TRUE on success or FALSE on fail.
   */
  public function syncToLdapEntry($account, $ldap_user = [], $test_query = FALSE) {

    if (is_object($account) && $account->id() == 1) {
      // Do not provision or sync user 1.
      return FALSE;
    }

    $result = FALSE;

    if ($this->config['ldapEntryProvisionServer']) {

      $factory = \Drupal::service('ldap.servers');
      /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
      $ldap_server = $factory->getServerById($this->config['ldapEntryProvisionServer']);

      $params = [
        'direction' => LdapConfiguration::PROVISION_TO_LDAP,
        'prov_events' => [LdapConfiguration::$eventSyncToLdapEntry],
        'module' => 'ldap_user',
        'function' => 'syncToLdapEntry',
        'include_count' => FALSE,
      ];

      try {
        $processor = new LdapUserProcessor();
        $proposed_ldap_entry = $processor->drupalUserToLdapEntry($account, $ldap_server, $params, $ldap_user);
      }
      catch (\Exception $e) {
        \Drupal::logger('ldap_user')->error('User or server is missing, drupalUserToLdapEntry() failed.');
        return FALSE;
      }

      if (is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn'])) {
        $existing_ldap_entry = $ldap_server->dnExists($proposed_ldap_entry['dn'], 'ldap_entry');
        // This array represents attributes to be modified; not comprehensive list of attributes.
        $attributes = [];
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
      '%dn' => isset($proposed_ldap_entry['dn']) ? $proposed_ldap_entry['dn'] : 'null',
      '%sid' => $this->config['ldapEntryProvisionServer'],
      '%username' => $account->getAccountName(),
      '%uid' => (!method_exists($account, 'id') || empty($account->id())) ? '' : $account->id(),
      '%action' => $result ? t('synced') : t('not synced'),
    ];

    \Drupal::logger('ldap_user')->info('LDAP entry on server %sid %action dn=%dn for username=%username, uid=%uid', $tokens);

    return $result;

  }

  /**
   * Populate ldap entry array for provisioning.
   *
   * @param \Drupal\user\Entity\User $account
   *   drupal account.
   * @param object $ldap_server
   * @param array $params
   *   with the following key values:
   *    'ldap_context' =>
   *   'module' => module calling function, e.g. 'ldap_user'
   *   'function' => function calling function, e.g. 'provisionLdapEntry'
   *   'include_count' => should 'count' array key be included
   *   'direction' => LdapConfiguration::PROVISION_TO_LDAP || LdapConfiguration::PROVISION_TO_DRUPAL.
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
      $ldap_user_entry = [];
    }

    if (!is_object($account) || !is_object($ldap_server)) {
      throw new LdapBadParamsException('Missing user or server.');
    }

    $include_count = (isset($params['include_count']) && $params['include_count']);

    $direction = isset($params['direction']) ? $params['direction'] : LdapConfiguration::PROVISION_TO_ALL;
    $prov_events = empty($params['prov_events']) ? LdapConfiguration::getAllEvents() : $params['prov_events'];

    $tokenHelper = new TokenProcessor();
    $syncMapper = new SyncMappingHelper();
    $mappings = $syncMapper->getSyncMappings($direction, $prov_events);
    // Loop over the mappings.
    foreach ($mappings as $field_key => $field_detail) {
      list($ldap_attr_name, $ordinal, $conversion) = $tokenHelper->extractTokenParts($field_key);
      $ordinal = (!$ordinal) ? 0 : $ordinal;
      if ($ldap_user_entry && isset($ldap_user_entry[$ldap_attr_name]) && is_array($ldap_user_entry[$ldap_attr_name]) && isset($ldap_user_entry[$ldap_attr_name][$ordinal])) {
        // Don't override values passed in.
        continue;
      }

      $synced = $syncMapper->isSynced($field_key, $params['prov_events'], LdapConfiguration::PROVISION_TO_LDAP);
      if ($synced) {
        $token = ($field_detail['user_attr'] == 'user_tokens') ? $field_detail['user_tokens'] : $field_detail['user_attr'];
        $value = $tokenHelper->tokenReplace($account, $token, 'user_account');

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
            $ldap_user_entry[$ldap_attr_name] = [];
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
   * Given a drupal account, provision an ldap entry if none exists.  if one exists do nothing.
   *
   * @param \Drupal\user\Entity\User $account
   *   drupal account object with minimum of name property.
   * @param array $ldap_user
   *   as pre-populated ldap entry.  usually not provided.
   *
   * @return array
   *   Format:
   *     array('status' => 'success', 'fail', or 'conflict'),
   *     array('ldap_server' => ldap server object),
   *     array('proposed' => proposed ldap entry),
   *     array('existing' => existing ldap entry),
   *     array('description' = > blah blah)
   */
  public function provisionLdapEntry($account, $ldap_user = NULL) {

    $result = [
      'status' => NULL,
      'ldap_server' => NULL,
      'proposed' => NULL,
      'existing' => NULL,
      'description' => NULL,
    ];

    if (is_scalar($account)) {
      $account = user_load_by_name($account);
    }

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

    if (!$this->config['ldapEntryProvisionServer']) {
      $result['status'] = 'fail';
      $result['error_description'] = 'no provisioning server enabled';
      return $result;
    }
    $factory = \Drupal::service('ldap.servers');
    /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
    $ldap_server = $factory->getServerById($this->config['ldapEntryProvisionServer']);
    $params = [
      'direction' => LdapConfiguration::PROVISION_TO_LDAP,
      'prov_events' => [LdapConfiguration::$eventCreateLdapEntry],
      'module' => 'ldap_user',
      'function' => 'provisionLdapEntry',
      'include_count' => FALSE,
    ];

    try {
      $proposed_ldap_entry = $this->drupalUserToLdapEntry($account, $ldap_server, $params, $ldap_user);
    }
    catch (\Exception $e) {
      \Drupal::logger('ldap_user')->error('User or server is missing during LDAP provisioning.');
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
    else {
      // Stick $proposed_ldap_entry in $ldap_entries array for drupal_alter call.
      $ldap_entries = [$proposed_dn_lcase => $proposed_ldap_entry];
      $context = [
        'action' => 'add',
        'corresponding_drupal_data' => [$proposed_dn_lcase => $account],
        'corresponding_drupal_data_type' => 'user',
      ];
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
        if (NULL !== $account->get('ldap_user_prov_entries')) {
          $account->set('ldap_user_prov_entries', []);
        }
        $ldap_user_prov_entry_exists = FALSE;
        if ($account->get('ldap_user_prov_entries')->value) {
          foreach ($account->get('ldap_user_prov_entries')->value as $i => $field_value_instance) {
            if ($field_value_instance == $ldap_user_prov_entry) {
              $ldap_user_prov_entry_exists = TRUE;
            }
          }
        }
        if (!$ldap_user_prov_entry_exists) {
          // @TODO Serialise?
          $prov_entries = $account->get('ldap_user_prov_entries')->value;
          $prov_entries[] = [
            'value' => $ldap_user_prov_entry,
            'format' => NULL,
            'save_value' => $ldap_user_prov_entry,
          ];
          $account->set('ldap_user_prov_entries', $prov_entries);
          $account->save();
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
    if (isset($result['status'])) {
      if ($result['status'] == 'success') {
        if ($this->detailedWatchdog) {
          \Drupal::logger('ldap_user')->info('LDAP entry on server %sid created dn=%dn.  %description. username=%username, uid=%uid', $tokens);
        }
      }
      elseif ($result['status'] == 'conflict') {
        if ($this->detailedWatchdog) {
          \Drupal::logger('ldap_user')->warning('LDAP entry on server %sid not created because of existing LDAP entry. %description. username=%username, uid=%uid', $tokens);
        }
      }
      elseif ($result['status'] == 'fail') {
        \Drupal::logger('ldap_user')->error('LDAP entry on server %sid not created because of error. %description. username=%username, uid=%uid, proposed dn=%dn', $tokens);
      }
    }
    return $result;
  }

  /**
   * Delete a provisioned LDAP entry.
   *
   * Given a drupal account, delete LDAP entry that was provisioned based on it
   * normally this will be 0 or 1 entry, but the ldap_user_prov_entries field
   * attached to the user entity track each LDAP entry provisioned.
   *
   * @param \Drupal\user\Entity\User $account
   *   Drupal user account.
   *
   * @return bool
   *   FALSE indicates failed or action not enabled in LDAP user configuration.
   */
  public function deleteProvisionedLdapEntries($account) {
    // Determine server that is associated with user.
    $result = FALSE;
    $entries = $account->get('ldap_user_prov_entries')->getValue();
    foreach ($entries as $i => $entry) {
      $parts = explode('|', $entry['value']);
      if (count($parts) == 2) {
        list($sid, $dn) = $parts;
        $factory = \Drupal::service('ldap.servers');
        $ldap_server = $factory->getServerById($sid);
        if (is_object($ldap_server) && $dn) {
          /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
          $result = $ldap_server->deleteLdapEntry($dn);
          $tokens = ['%sid' => $sid, '%dn' => $dn, '%username' => $account->getUsername(), '%uid' => $account->id()];
          if ($result) {
            \Drupal::logger('ldap_user')->info('LDAP entry on server %sid deleted dn=%dn. username=%username, uid=%uid', $tokens);
          }
          else {
            \Drupal::logger('ldap_user')->error('LDAP entry on server %sid not deleted because error. username=%username, uid=%uid', $tokens);
          }
        }
        else {
          $result = FALSE;
        }
      }
    }
    return $result;
  }

  /**
   * Given a drupal account, find the related LDAP entry.
   *
   * @param \Drupal\user\Entity\User $account
   * @param null $prov_events
   *
   * @return bool|array
   *   False or LDAP entry
   */
  public function getProvisionRelatedLdapEntry($account, $prov_events = NULL) {
    if (!$prov_events) {
      $prov_events = LdapConfiguration::getAllEvents();
    }
    $sid = $this->config['ldapEntryProvisionServer'];
    if (!$sid) {
      return FALSE;
    }
    // $user_entity->ldap_user_prov_entries,.
    $factory = \Drupal::service('ldap.servers');
    /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
    $ldap_server = $factory->getServerById($sid);
    $params = [
      'direction' => LdapConfiguration::PROVISION_TO_LDAP,
      'prov_events' => $prov_events,
      'module' => 'ldap_user',
      'function' => 'getProvisionRelatedLdapEntry',
      'include_count' => FALSE,
    ];

    try {
      $proposed_ldap_entry = $this->drupalUserToLdapEntry($account, $ldap_server, $params);
    }
    catch (\Exception $e) {
      \Drupal::logger('ldap_user')->error('User or server is missing locally for fetching ProvisionRelatedLdapEntry.');
      return FALSE;
    }

    if (!(is_array($proposed_ldap_entry) && isset($proposed_ldap_entry['dn']) && $proposed_ldap_entry['dn'])) {
      return FALSE;
    }

    $ldap_entry = $ldap_server->dnExists($proposed_ldap_entry['dn'], 'ldap_entry', []);
    return $ldap_entry;

  }

}

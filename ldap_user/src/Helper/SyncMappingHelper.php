<?php

namespace Drupal\ldap_user\Helper;

use Drupal\ldap_servers\Processor\TokenProcessor;

/**
 *
 */
class SyncMappingHelper {


  /**
   * Array of field sync mappings provided by all modules (via hook_ldap_user_attrs_list_alter())
   * array of the form: array(
   * LdapConfiguration:: | s => array(
   *   <server_id> => array(
   *     'sid' => <server_id> (redundant)
   *     'ldap_attr' => e.g. [sn]
   *     'user_attr'  => e.g. [field.field_user_lname] (when this value is set to 'user_tokens', 'user_tokens' value is used.)
   *     'user_tokens' => e.g. [field.field_user_lname], [field.field_user_fname]
   *     'convert' => 1|0 boolean indicating need to covert from binary
   *     'direction' => LdapConfiguration::PROVISION_TO_DRUPAL | LdapConfiguration::PROVISION_TO_LDAP (redundant)
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


  private $config;

  /**
   *
   */
  public function __construct() {
    $this->config = \Drupal::config('ldap_user.settings')->get();
    $this->setSyncMapping();
  }

  /**
   * Given configuration of syncing, determine is a given sync should occur.
   *
   * @param string $attr_token
   *   e.g. [property.mail], [field.ldap_user_puid_property].
   * @param array $prov_events
   *   e.g. array(LdapConfiguration::$eventCreateDrupalUser).  typically array with 1 element.
   * @param int $direction
   *   LdapConfiguration::PROVISION_TO_DRUPAL or LdapConfiguration::PROVISION_TO_LDAP.
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
   * Util to fetch mappings for a given direction.
   *
   * @param string $direction
   * @param array $prov_events
   *
   * @return array|bool
   *   Array of mappings (may be empty array)
   */
  public function getSyncMappings($direction = NULL, $prov_events = NULL) {
    if (!$prov_events) {
      $prov_events = LdapConfiguration::getAllEvents();
    }
    if ($direction == NULL) {
      $direction = LdapConfiguration::PROVISION_TO_ALL;
    }

    $mappings = [];
    if ($direction == LdapConfiguration::PROVISION_TO_ALL) {
      $directions = [LdapConfiguration::PROVISION_TO_DRUPAL, LdapConfiguration::PROVISION_TO_LDAP];
    }
    else {
      $directions = [$direction];
    }
    foreach ($directions as $direction) {
      if (!empty($this->config['ldapUserSyncMappings'][$direction])) {
        foreach ($this->config['ldapUserSyncMappings'][$direction] as $attribute => $mapping) {
          if (!empty($mapping['prov_events'])) {
            $result = count(array_intersect($prov_events, $mapping['prov_events']));
            if ($result) {
              if ($direction == LdapConfiguration::PROVISION_TO_DRUPAL && isset($mapping['user_attr'])) {
                $key = $mapping['user_attr'];
              }
              elseif ($direction == LdapConfiguration::PROVISION_TO_LDAP && isset($mapping['ldap_attr'])) {
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
   * Fetches the sync mappings from cache or loads them from configuration.
   */
  public function setSyncMapping() {
    $syncMappingsCache = \Drupal::cache()->get('ldap_user_sync_mapping');
    if ($syncMappingsCache) {
      $this->syncMapping = $syncMappingsCache->data;
    }
    else {
      $this->syncMapping = $this->processSyncMappings();
      \Drupal::cache()->set('ldap_user_sync_mapping', $this->syncMapping);
    }
  }

  /**
   * Derive synchronization mappings from configuration.
   *
   * This function would be private if not for easier access for tests.
   *
   * return array
   */
  public function processSyncMappings() {
    $available_user_attributes = [];
    foreach ([
      LdapConfiguration::PROVISION_TO_DRUPAL,
      LdapConfiguration::PROVISION_TO_LDAP,
    ] as $direction) {
      if ($direction == LdapConfiguration::PROVISION_TO_DRUPAL) {
        $sid = \Drupal::config('ldap_user.settings')
          ->get('drupalAcctProvisionServer');
      }
      else {
        $sid = \Drupal::config('ldap_user.settings')
          ->get('ldapEntryProvisionServer');
      }
      $available_user_attributes[$direction] = [];
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

      $params = [
        'ldap_server' => $ldap_server,
        'ldap_user_conf' => $this,
        'direction' => $direction,
      ];

      \Drupal::moduleHandler()->alter(
        'ldap_user_attrs_list',
        $available_user_attributes[$direction],
        $params
      );
    }
    return $available_user_attributes;
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
      $direction = LdapConfiguration::PROVISION_TO_ALL;
    }
    $attributes_map = [];
    $required_attributes = [];
    if ($this->config['drupalAcctProvisionServer']) {
      $prov_events = LdapConfiguration::ldapContextToProvEvents($ldap_context);
      $attributes_map = $this->getSyncMappings($direction, $prov_events);
      $required_attributes = [];
      foreach ($attributes_map as $detail) {
        if (count(array_intersect($prov_events, $detail['prov_events']))) {
          // Add the attribute to our array.
          if ($detail['ldap_attr']) {
            $tokenProcessor = new TokenProcessor();
            $tokenProcessor->extractTokenAttributes($required_attributes, $detail['ldap_attr']);
          }
        }
      }
    }
    return $required_attributes;
  }

}

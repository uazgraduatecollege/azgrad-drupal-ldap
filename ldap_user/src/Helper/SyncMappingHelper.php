<?php

namespace Drupal\ldap_user\Helper;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\LdapUserAttributesInterface;

/**
 * Helper class to process user field synchronisation mappings.
 */
class SyncMappingHelper implements LdapUserAttributesInterface {

  protected $logger;
  protected $config;
  protected $moduleHandler;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   * @param \Drupal\Core\Config\ConfigFactory $config_factory
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   */
  public function __construct(
    LoggerChannelInterface $logger,
    ConfigFactory $config_factory,
    ModuleHandler $module_handler
  ) {
    $this->logger = $logger;
    $this->config = $config_factory->get('ldap_user.settings');
    $this->moduleHandler = $module_handler;
  }

  /**
   *
   */
  public function isSyncedToDrupalOnCreation($attr_token) {
    $config = $this->config->get('ldapUserSyncMappings');
    return isset($config[self::PROVISION_TO_DRUPAL][$attr_token]['prov_events'][self::EVENT_CREATE_DRUPAL_USER]) ? TRUE : FALSE;
  }

  /**
   *
   */
  public function isSyncedToDrupalOnUpdate($attr_token) {
    $config = $this->config->get('ldapUserSyncMappings');
    return isset($config[self::PROVISION_TO_DRUPAL][$attr_token]['prov_events'][self::EVENT_SYNC_TO_DRUPAL_USER]) ? TRUE : FALSE;
  }

  /**
   *
   */
  public function isSyncedToLDAPOnCreation($attr_token) {
    $config = $this->config->get('ldapUserSyncMappings');
    return isset($config[self::PROVISION_TO_LDAP][$attr_token]['prov_events'][self::EVENT_CREATE_LDAP_ENTRY]) ? TRUE : FALSE;
  }

  /**
   *
   */
  public function isSyncedToLDAPOnUpdate($attr_token) {
    $config = $this->config->get('ldapUserSyncMappings');
    return isset($config[self::PROVISION_TO_LDAP][$attr_token]['prov_events'][self::EVENT_SYNC_TO_LDAP_ENTRY]) ? TRUE : FALSE;
  }

  /**
   *
   */
  public function isSyncedToDrupal($attr_token, $event) {
    $config = $this->config->get('ldapUserSyncMappings');
    return isset($config[self::PROVISION_TO_DRUPAL][$attr_token]['prov_events'][$event]) ? TRUE : FALSE;
  }

  /**
   *
   */
  public function isSyncedToLdap($attr_token, $event) {
    $config = $this->config->get('ldapUserSyncMappings');
    return isset($config[self::PROVISION_TO_LDAP][$attr_token]['prov_events'][$event]) ? TRUE : FALSE;
  }

  /**
   * @param $event
   *
   * @return array
   */
  public function getFieldsSyncedToDrupal($event) {
    $mappings_on_event = [];
    $mappings = $this->config->get('ldapUserSyncMappings')[self::PROVISION_TO_DRUPAL];
    foreach ($mappings as $mapping) {
      if (!empty($mapping['prov_events'])) {
        $result = in_array($event, $mapping['prov_events']);
        if ($result && isset($mapping['user_attr'])) {
          $mappings_on_event[] = $mapping['user_attr'];
        }
      }
    }
    return $mappings_on_event;
  }

  /**
   * @param $event
   *
   * @return array
   */
  public function getFieldsSyncedToLdap($event) {
    $mappings_on_event = [];
    $mappings = $this->config->get('ldapUserSyncMappings')[self::PROVISION_TO_LDAP];
    foreach ($mappings as $mapping) {
      if (!empty($mapping['prov_events'])) {
        $result = in_array($event, $mapping['prov_events']);
        if ($result && isset($mapping['target'])) {
          $mappings_on_event[] = $mapping['target'];
        }
      }
    }
    return $mappings_on_event;
  }

}

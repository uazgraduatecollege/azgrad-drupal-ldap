<?php

namespace Drupal\ldap_user\EventSubscriber;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\LdapUserManager;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Exception\LdapBadParamsException;
use Drupal\ldap_user\Helper\SyncMappingHelper;
use Drupal\user\Entity\User;
use Drupal\user\UserInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Ldap\Entry;

/**
 * Class ProvisionLdapEntryOnUserCreation.
 */
abstract class LdapEntryBaseSubscriber implements EventSubscriberInterface, LdapUserAttributesInterface {

  protected $config;
  protected $logger;
  protected $detailLog;
  protected $entityTypeManager;
  protected $moduleHandler;
  protected $ldapUserManager;
  protected $syncMappingHelper;
  protected $tokenProcessor;

  /**
   * Constructor.
   *
   * @TODO: Consider moving this into the final class, not enough overlap.
   *
   * @param \Drupal\Core\Config\ConfigFactory $config_factory
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   * @param \Drupal\ldap_servers\Logger\LdapDetailLog $detail_log
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   * @param \Drupal\ldap_servers\LdapUserManager $ldap_user_manager
   * @param \Drupal\ldap_user\Helper\SyncMappingHelper $sync_mapping_helper
   * @param \Drupal\ldap_servers\Processor\TokenProcessor $token_processor
   */
  public function __construct(
    ConfigFactory $config_factory,
    LoggerChannelInterface $logger,
    LdapDetailLog $detail_log,
    EntityTypeManagerInterface $entity_type_manager,
    ModuleHandlerInterface $module_handler,
    LdapUserManager $ldap_user_manager,
    SyncMappingHelper $sync_mapping_helper,
    TokenProcessor $token_processor) {
    $this->config = $config_factory->get('ldap_user.settings');
    $this->logger = $logger;
    $this->detailLog = $detail_log;
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->ldapUserManager = $ldap_user_manager;
    $this->syncMappingHelper = $sync_mapping_helper;
    $this->tokenProcessor = $token_processor;
  }

  /**
   * Is provisioning of LDAP entries from Drupal users configured.
   *
   * @return bool
   *   Provisioning available.
   */
  protected function provisionsLdapEntriesFromDrupalUsers() {
    if ($this->config->get('ldapEntryProvisionServer') &&
      count(array_filter(array_values($this->config->get('ldapEntryProvisionTriggers')))) > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Populate LDAP entry array for provisioning.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal account.
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   *   LDAP server.
   * @param string $prov_event
   *   Provisioning event.
   *
   * @return Entry
   *   Entry to send *to* LDAP.
   *
   * @throws \Drupal\ldap_user\Exception\LdapBadParamsException
   */
  public function buildLdapEntry(UserInterface $account, Server $ldap_server, $prov_event) {
    $dn = '';
    $attributes = [];

    if (!is_object($account) || !is_object($ldap_server)) {
      throw new LdapBadParamsException('Missing user or server.');
    }

    $mappings = $this->syncMappingHelper->getFieldsSyncedToLdap($prov_event);

    foreach ($mappings as $field_key => $field_detail) {
      list($ldap_attribute_name, $ordinal) = $this->extractTokenParts($field_key);
      $ordinal = (!$ordinal) ? 0 : $ordinal;
      if ($this->syncMappingHelper->isSyncedToLdap($field_key, array_pop($prov_events))) {
        $token = ($field_detail['user_attr'] == 'user_tokens') ? $field_detail['user_tokens'] : $field_detail['user_attr'];
        $value = $this->tokenProcessor->tokenReplace($account, $token, 'user_account');

        if ($ldap_attribute_name == 'dn' && $value) {
          $dn = $value;
        }
        elseif ($value) {
          $attributes[$ldap_attribute_name][$ordinal] = $value;
        }
      }
    }
    $entry = new Entry($dn, $attributes);

    // Allow other modules to alter $ldap_user.
    $params = [
      'prov_events' => $prov_event,
      'direction' => self::PROVISION_TO_LDAP,
    ];
    $this->moduleHandler->alter('ldap_entry', $ldap_user_entry, $params);

    return $entry;
  }

  /**
   * @param $token
   *
   * @return array
   */
  protected function extractTokenParts($token) {
    $attributes = [];
    ConversionHelper::extractTokenAttributes($attributes, $token);
    if (is_array($attributes)) {
      $keys = array_keys($attributes);
      $attr_name = $keys[0];
      $attr_data = $attributes[$attr_name];
      $ordinals = array_keys($attr_data['values']);
      $ordinal = $ordinals[0];
      return [$attr_name, $ordinal];
    }
    else {
      return [NULL, NULL];
    }
  }

}

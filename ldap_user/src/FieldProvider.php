<?php

namespace Drupal\ldap_user;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityFieldManager;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_user\Helper\LdapConfiguration;

/**
 * Provides the basic and required fields needed for user mappings.
 */
class FieldProvider implements LdapUserAttributesInterface {

  protected $config;
  protected $entityTypeManager;
  protected $moduleHandler;
  protected $entityFieldManager;

  /**
   * Constructor.
   */
  public function __construct(ConfigFactory $config_factory, EntityTypeManager $entity_type_manager, ModuleHandler $module_handler, EntityFieldManager $entity_field_manager) {
    $this->config = $config_factory->get('ldap_user.settings');
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->entityFieldManager = $entity_field_manager;
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
    // TODO: Make parameters more sensible, only pass Server in one way.
    // Puid attributes are server specific.
    if (isset($params['sid']) && $params['sid']) {
      if (is_scalar($params['sid'])) {
        $ldapServer =
         $this->entityTypeManager
           ->getStorage('ldap_server')
           ->load($params['sid']);
      }
      else {
        $ldapServer = $params['sid'];
      }

      if ($ldapServer && $ldapServer->status()) {
        if (!isset($attributes['dn'])) {
          $attributes['dn'] = [];
        }
        // Force dn "attribute" to exist.
        $attributes['dn'] = ConversionHelper::setAttributeMap($attributes['dn']);
        // Add the attributes required by the user configuration when
        // provisioning Drupal users.
        switch ($params['ldap_context']) {
          case 'ldap_user_insert_drupal_user':
          case 'ldap_user_update_drupal_user':
          case 'ldap_user_ldap_associate':
            if ($ldapServer->get('user_attr')) {
              $attributes[$ldapServer->get('user_attr')] = ConversionHelper::setAttributeMap(@$attributes[$ldapServer->get('user_attr')]);
            }
            if ($ldapServer->get('mail_attr')) {
              $attributes[$ldapServer->get('mail_attr')] = ConversionHelper::setAttributeMap(@$attributes[$ldapServer->get('mail_attr')]);
            }
            if ($ldapServer->get('picture_attr')) {
              $attributes[$ldapServer->get('picture_attr')] = ConversionHelper::setAttributeMap(@$attributes[$ldapServer->get('picture_attr')]);
            }
            if ($ldapServer->get('unique_persistent_attr')) {
              $attributes[$ldapServer->get('unique_persistent_attr')] = ConversionHelper::setAttributeMap(@$attributes[$ldapServer->get('unique_persistent_attr')]);
            }
            if ($ldapServer->get('mail_template')) {
              ConversionHelper::extractTokenAttributes($attributes, $ldapServer->get('mail_template'));
            }
            break;
        }

        $ldapContext = empty($params['ldap_context']) ? NULL : $params['ldap_context'];
        $direction = empty($params['direction']) ? $this->ldapContextToProvDirection($ldapContext) : $params['direction'];
        $attributesRequiredByOtherModuleMappings = $this->syncMapper->getLdapUserRequiredAttributes($direction, $ldapContext);
        $attributes = array_merge($attributesRequiredByOtherModuleMappings, $attributes);
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
    $user_fields = $this->entityFieldManager->getFieldStorageDefinitions('user');
    foreach ($user_fields as $field_name => $field_instance) {
      $field_id = "[field.$field_name]";
      if (!isset($availableUserAttributes[$field_id]) || !is_array($availableUserAttributes[$field_id])) {
        $availableUserAttributes[$field_id] = [];
      }

      $availableUserAttributes[$field_id] = $availableUserAttributes[$field_id] + [
        'name' => $this->t('Field: @label', ['@label' => $field_instance->getLabel()]),
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

    // TODO: This is possibly an overlap with SyncMappingHelper.
    $mappings = $this->config->get('ldapUserSyncMappings');

    // This is where need to be added to arrays.
    if (!empty($mappings[$direction])) {
      $availableUserAttributes = $this->applyUserAttributes($availableUserAttributes, $mappings, $direction);
    }

    return [$availableUserAttributes, $params];
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

}

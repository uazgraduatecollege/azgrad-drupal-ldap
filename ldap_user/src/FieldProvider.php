<?php

namespace Drupal\ldap_user;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityFieldManager;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\Mapping;
use Drupal\ldap_user\Helper\SyncMappingHelper;

/**
 * Provides the basic and required fields needed for user mappings.
 */
class FieldProvider implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  protected $config;
  protected $entityTypeManager;
  protected $moduleHandler;
  protected $entityFieldManager;
  protected $syncMapper;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactory $config_factory
   * @param \Drupal\Core\Entity\EntityTypeManager $entity_type_manager
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   * @param \Drupal\Core\Entity\EntityFieldManager $entity_field_manager
   * @param \Drupal\ldap_user\Helper\SyncMappingHelper $sync_mapper
   */
  public function __construct(
    ConfigFactory $config_factory,
    EntityTypeManager $entity_type_manager,
    ModuleHandler $module_handler,
    EntityFieldManager $entity_field_manager,
    SyncMappingHelper $sync_mapper) {
    $this->config = $config_factory->get('ldap_user.settings');
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->entityFieldManager = $entity_field_manager;
    $this->syncMapper = $sync_mapper;
  }

  /**
   * LDAP attributes to alter.
   *
   * @param array $available_user_attributes
   *   Available attributes.
   * @param array $params
   *   Parameters.
   *
   * @return array
   *   Altered attributes.
   */
  public function alterLdapUserAttributes(array $available_user_attributes, array $params) {
    $direction = $params['direction'];

    if ($direction == self::PROVISION_TO_LDAP) {
      $available_user_attributes = $this->addToLdapProvisioningFields($available_user_attributes);
    }

    $available_user_attributes = $this->addUserEntityFields($available_user_attributes);
    $available_user_attributes = $this->exposeAvailableBaseFields($available_user_attributes);

    $mappings = $this->config->get('ldapUserSyncMappings');
    if (!empty($mappings[$direction])) {
      $available_user_attributes = $this->applyUserAttributes($available_user_attributes, $mappings[$direction]);
    }

    return [$available_user_attributes, $params];
  }

  /**
   * Apply user attributes.
   *
   * @param \Drupal\ldap_servers\Mapping[] $available_user_attributes
   *   Available attributes.
   * @param array $saved_mappings
   *   Mappings.
   * @param string $direction
   *   Synchronization direction.
   *
   * @return array
   *   All attributes applied.
   *
   * @TODO: Make this private regular again once the other issues are fixed.
   */
  public static function applyUserAttributes(array $available_user_attributes, array $saved_mappings) {
    foreach ($saved_mappings as $mapping) {
      // Cannot use array key here, needs unsanitized name.
      $key = $mapping['drupal_attr'];

      if (!isset($available_user_attributes[$key])) {
        // Mapping not found in list of available
        // TODO: DI.
        \Drupal::logger('ldap_user')
          ->warning('Configuration contains unavailable field @field', ['@field' => $key]);
        continue;
      }

      if (isset($mapping['ldap_attr'])) {
        $available_user_attributes[$key]->setLdapAttribute($mapping['ldap_attr']);
      }

      if (isset($mapping['drupal_attr'])) {
        if ($mapping['drupal_attr'] == 'user_tokens') {
          $available_user_attributes[$key]->setDrupalAttribute($mapping['user_tokens']);
        }
        else {
          $available_user_attributes[$key]->setDrupalAttribute($mapping['drupal_attr']);
        }
      }

      if (isset($mapping['convert'])) {
        $available_user_attributes[$key]->convertBinary($mapping['convert']);
      }

      if (isset($mapping['enabled'])) {
        $available_user_attributes[$key]->setEnabled($mapping['enabled']);
      }

      if (isset($mapping['prov_events'])) {
        $available_user_attributes[$key]->setProvisioningEvents($mapping['prov_events']);
      }

    }
    return $available_user_attributes;
  }

  /**
   * @param \Drupal\ldap_servers\Mapping[] $availableUserAttributes
   *
   * @return array
   */
  private function addToLdapProvisioningFields(array $availableUserAttributes) {
    if (isset($availableUserAttributes['[property.name]'])) {
      $availableUserAttributes['[property.name]']->setConfigurationModule('ldap_user');
      $availableUserAttributes['[property.name]']->setConfigurable(TRUE);
    }

    $fields = [
      '[property.name]' => 'Property: Name',
      '[property.mail]' => 'Property: Email',
      '[property.picture]' => 'Property: Picture',
      '[property.uid]' => 'Property: Drupal User Id (uid)',
      '[password.random]' => 'Password: Random password',
      '[password.user-random]' => 'Password: Plain user password or random',
      '[password.user-only]' => 'Password: Plain user password',
    ];

    foreach ($fields as $key => $name) {
      if (isset($availableUserAttributes[$key])) {
        $availableUserAttributes[$key]->setConfigurationModule('ldap_user');
        $availableUserAttributes[$key]->setConfigurable(TRUE);
      }
      else {
        $availableUserAttributes[$key] = new Mapping(
          $key,
          $name,
          TRUE,
          FALSE,
          [
            self::EVENT_CREATE_DRUPAL_USER,
            self::EVENT_SYNC_TO_DRUPAL_USER,
          ],
          'ldap_user',
          'ldap_user'
              );
      }
    }
    return $availableUserAttributes;
  }

  /**
   * Additional access needed in direction to Drupal.
   *
   * @param \Drupal\ldap_servers\Mapping[] $availableUserAttributes
   *
   * @return array
   */
  private function exposeAvailableBaseFields(array $availableUserAttributes): array {
    $server = $this->config->get('drupalAcctProvisionServer');
    $triggers = $this->config->get('drupalAcctProvisionTriggers');
    if ($server && !empty($triggers)) {
      /** @var \Drupal\ldap_servers\Mapping availableUserAttributes<> */
      $fields = [
        '[property.mail]',
        '[property.name]',
        '[property.picture]',
        '[field.ldap_user_puid_sid]',
        '[field.ldap_user_puid]',
      ];
      foreach ($fields as $field) {
        if (isset($availableUserAttributes[$field])) {
          $availableUserAttributes[$field]->setConfigurationModule('ldap_user');
        }
      }
    }
    return $availableUserAttributes;
  }

  /**
   * @param \Drupal\ldap_servers\Mapping[] $availableUserAttributes
   * @param $direction
   *
   * @return array
   */
  private function addUserEntityFields(array $availableUserAttributes) {
    // Todo: Verify that the next step (loading fields) cannot do this via BaseDefinition.
    // Drupal user properties.
    $availableUserAttributes['[property.status]'] = new Mapping(
      '[property.status]',
      'Property: Account Status',
      TRUE,
      FALSE,
      [],
       'ldap_user',
       'ldap_user'
    );

    $availableUserAttributes['[property.timezone]'] = new Mapping(
      '[property.timezone]',
       'Property: User Timezone',
      TRUE,
      FALSE,
      [],
      'ldap_user',
      'ldap_user'
    );

    $availableUserAttributes['[property.signature]'] = new Mapping(
      '[property.signature]',
      'Property: User Signature',
      TRUE,
      FALSE,
      [],
      'ldap_user',
      'ldap_user'
    );

    // Load active Drupal user fields.
    // TODO: Consider not hard-coding the other properties.
    $user_fields = $this->entityFieldManager->getFieldStorageDefinitions('user');
    foreach ($user_fields as $field_name => $field_instance) {
      $field_id = "[field." . $field_name . "]";
      if (isset($availableUserAttributes[$field_id])) {
        $availableUserAttributes[$field_id]->isConfigurable(TRUE);
      }
      else {
        $availableUserAttributes[$field_id] = new Mapping(
          $field_id,
          $this->t('Field: @label', ['@label' => $field_instance->getLabel()]),
          TRUE,
          FALSE,
          [],
          'ldap_user',
          'ldap_user'
              );
      }
    }
    return $availableUserAttributes;
  }

}
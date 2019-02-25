<?php

namespace Drupal\ldap_user;

use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Entity\EntityFieldManager;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\Mapping;
use Drupal\Core\Link;
use Drupal\Core\Url;

/**
 * Provides the basic and required fields needed for user mappings.
 */
class FieldProvider implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  protected $config;
  protected $entityTypeManager;
  protected $moduleHandler;
  protected $entityFieldManager;
  protected $syncMappingHelper;

  private $server;
  private $direction;

  /**
   * @var \Drupal\ldap_servers\Mapping[]
   */
  private $attributes;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactory $config_factory
   *   Config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   Entity type manager.
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   *   Module handler.
   * @param \Drupal\Core\Entity\EntityFieldManager $entity_field_manager
   *   Entity field manager.
   */
  public function __construct(
    ConfigFactory $config_factory,
    EntityTypeManagerInterface $entity_type_manager,
    ModuleHandler $module_handler,
    EntityFieldManager $entity_field_manager
  ) {
    $this->config = $config_factory->get('ldap_user.settings');
    $this->entityTypeManager = $entity_type_manager;
    $this->moduleHandler = $module_handler;
    $this->entityFieldManager = $entity_field_manager;
  }

  /**
   * LDAP attributes to alter.
   *
   * @param string $direction
   * @param \Drupal\ldap_servers\Entity\Server $server
   *
   * @return array
   *   All attributes.
   */
  public function loadAttributes(string $direction, Server $server) {
    $this->server = $server;
    $this->direction = $direction;
    if ($this->direction == self::PROVISION_TO_DRUPAL && $this->server) {
      $this->addDn();

      if ($this->server->get('unique_persistent_attr')) {
        $this->addPuidFields();
      }

      $triggers = $this->config->get('drupalAcctProvisionTriggers');
      if (!empty($triggers)) {
        $this->addBaseProperties();
      }
    }

    if ($direction == self::PROVISION_TO_LDAP) {
      $this->addToLdapProvisioningFields();
    }

    $this->addUserEntityFields();
    $this->exposeAvailableBaseFields();

    $this->loadUserDefinedMappings();

    return $this->attributes;
  }

  /**
   *
   */
  private function loadUserDefinedMappings() {
    $database_mappings = $this->config->get('ldapUserSyncMappings');

    foreach ($database_mappings[$this->direction] as $mapping_name => $mapping) {
      $prepared_mapping = new Mapping(
        $mapping_name,
        $mapping_name,
        TRUE,
        TRUE,
        $mapping['prov_events'],
        $mapping['config_module'],
        $mapping['prov_module']
      );
      $prepared_mapping->setDrupalAttribute($mapping['user_attr']);
      $prepared_mapping->setLdapAttribute($mapping['ldap_attr']);
      $prepared_mapping->setUserTokens($mapping['user_tokens']);
      if ($mapping['convert']) {
        $prepared_mapping->isBinary();
      }
      $this->attributes[$mapping['user_attr']] = $prepared_mapping;
    }
  }

  /**
   *
   */
  public function attributeIsSyncedOnEvent($name, $event) {
    if (isset($this->attributes[$name]) && $this->attributes[$name]->isEnabled()) {
      if (in_array($event, $this->attributes[$name]->getProvisioningEvents())) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * @param $event
   *
   * @return \Drupal\ldap_servers\Mapping[]
   */
  public function getAttributesSyncedOnEvent($event) {
    $synced_attributes = [];
    foreach ($this->attributes as $attribute) {
      if ($attribute->isEnabled() &&
        in_array($event, $attribute->getProvisioningEvents())) {
        $synced_attributes[] = $attribute;
      }
    }
    return $synced_attributes;
  }

  /**
   * Add PUID Fields.
   *
   * These 4 user fields identify where in LDAP and which LDAP server they
   * are associated with. They are required for a Drupal account to be
   * "LDAP associated" regardless of if any other fields/properties are
   * provisioned or synced.
   *
   * @return array
   */
  private function addPuidFields() {
    $url = Url::fromRoute('entity.ldap_server.collection');
    $tokens = [
      '%edit_link' => Link::fromTextAndUrl($url->toString(), $url)->toString(),
      '%sid' => $this->server->id(),
    ];

    $fields = [
      '[field.ldap_user_puid_sid]' => $this->t('Field: sid providing PUID'),
      '[field.ldap_user_puid]' => $this->t('Field: PUID'),
      '[field.ldap_user_puid_property]' => $this->t('Field: PUID Attribute'),
    ];
    foreach ($fields as $key => $name) {
      $this->attributes[$key] = new Mapping(
        $key,
        $name,
        FALSE,
        TRUE,
        [self::EVENT_CREATE_DRUPAL_USER],
        'ldap_user',
        'ldap_servers'
      );
      $this->attributes[$key]->setNotes($this->t('configure at %edit_link', $tokens));
    }

    $this->attributes['[field.ldap_user_puid_sid]']->setLdapAttribute($this->server->id());
    $this->attributes['[field.ldap_user_puid]']->setLdapAttribute($this->addTokens($this->server->get('unique_persistent_attr')));
    $this->attributes['[field.ldap_user_puid_property]']->setLdapAttribute($this->server->get('unique_persistent_attr'));
  }

  /**
   * @param \Drupal\ldap_servers\Mapping[] $this->attributes
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   *
   * @return array
   */
  private function addBaseProperties() {
    $fields = [
      '[property.name]' => 'Property: Username',
      '[property.mail]' => 'Property: Email',
    ];

    if ($this->server->get('picture_attr')) {
      $fields['[property.picture]'] = 'Property: Picture';
    }

    foreach ($fields as $key => $name) {
      $this->attributes[$key] = new Mapping(
        $key,
        $name,
        FALSE,
        TRUE,
        [self::EVENT_CREATE_DRUPAL_USER, self::EVENT_SYNC_TO_DRUPAL_USER],
        'ldap_servers',
        'ldap_user'
      );
    }

    $this->attributes['[property.name]']->setLdapAttribute($this->addTokens($this->server->get('user_attr')));

    if ($this->server->get('mail_template')) {
      $this->attributes['[property.mail]']->setLdapAttribute($this->server->get('mail_template'));
    }
    else {
      $this->attributes['[property.mail]']->setLdapAttribute($this->addTokens($this->server->get('mail_attr')));
    }

    if ($this->server->get('picture_attr')) {
      $this->attributes['[property.picture]']->setLdapAttribute($this->addTokens($this->server->get('picture_attr')));
    }
  }

  /**
   * @param $input
   *
   * @return string
   */
  private function addTokens($input) {
    return '[' . $input . ']';
  }

  /**
   * @param \Drupal\ldap_servers\Mapping[] $this->attributes
   * @param $tokens
   *
   * @return array
   */
  private function addDn() {
    $this->attributes['[field.ldap_user_current_dn]'] = new Mapping(
      '[field.ldap_user_current_dn]',
      $this->t('Field: Most Recent DN'),
      FALSE,
      TRUE,
      [self::EVENT_CREATE_DRUPAL_USER, self::EVENT_SYNC_TO_DRUPAL_USER],
      'ldap_user',
      'ldap_servers'
    );
    $this->attributes['[field.ldap_user_current_dn]']->setLdapAttribute('[dn]');
    $this->attributes['[field.ldap_user_current_dn]']->setNotes('not configurable');
  }

  /**
   * Add to LDAP Provisioning fields.
   *
   * @return void Available user attributes.
   *   Available user attributes.
   */
  private function addToLdapProvisioningFields() {
    if (isset($this->attributes['[property.name]'])) {
      $this->attributes['[property.name]']->setConfigurationModule('ldap_user');
      $this->attributes['[property.name]']->setConfigurable(TRUE);
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
      if (isset($this->attributes[$key])) {
        $this->attributes[$key]->setConfigurationModule('ldap_user');
        $this->attributes[$key]->setConfigurable(TRUE);
      }
      else {
        $this->attributes[$key] = new Mapping(
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
  }

  /**
   * Additional access needed in direction to Drupal.
   *
   * @param \Drupal\ldap_servers\Mapping[] $this->attributes
   *   Available user attributes.
   *
   * @return array
   *   Available user attributes.
   */
  private function exposeAvailableBaseFields() {
    $this->server = $this->config->get('drupalAcctProvisionServer');
    $triggers = $this->config->get('drupalAcctProvisionTriggers');
    if ($this->server && !empty($triggers)) {
      /** @var \Drupal\ldap_servers\Mapping availableUserAttributes<> */
      $fields = [
        '[property.mail]',
        '[property.name]',
        '[property.picture]',
        '[field.ldap_user_puid_sid]',
        '[field.ldap_user_puid]',
      ];
      foreach ($fields as $field) {
        if (isset($this->attributes[$field])) {
          $this->attributes[$field]->setConfigurationModule('ldap_user');
        }
      }
    }
  }

  /**
   * Add user entity fields.
   *
   * @param \Drupal\ldap_servers\Mapping[] $this->attributes
   *   Available user attributes.
   *
   * @return array
   *   Available user attributes.
   */
  private function addUserEntityFields() {
    // Todo: Verify that the next step (loading fields) cannot do this via BaseDefinition.
    // Drupal user properties.
    $this->attributes['[property.status]'] = new Mapping(
      '[property.status]',

      'Property: Account Status',
      TRUE,
      FALSE,
      [],
       'ldap_user',
       'ldap_user'
    );

    $this->attributes['[property.timezone]'] = new Mapping(
      '[property.timezone]',

      'Property: User Timezone',
      TRUE,
      FALSE,
      [],
      'ldap_user',
      'ldap_user'
    );

    $this->attributes['[property.signature]'] = new Mapping(
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
      if (isset($this->attributes[$field_id])) {
        $this->attributes[$field_id]->isConfigurable(TRUE);
      }
      else {
        $this->attributes[$field_id] = new Mapping(
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
  }

}

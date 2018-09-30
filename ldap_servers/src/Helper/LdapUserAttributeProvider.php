<?php

namespace Drupal\ldap_servers\Helper;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Link;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\ldap_servers\Entity\Mapping;
use Drupal\ldap_servers\LdapUserAttributesInterface;
use Drupal\ldap_servers\ServerInterface;

/**
 * Helper class to working with the Server classes.
 *
 * Normally called if you need specific sets of serves, such as all enabled
 * ones.
 *
 * @Todo: Split class to remove out-of-scope functions.
 */
class LdapUserAttributeProvider implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  protected $config;
  protected $storage;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   * @param \Drupal\Core\Entity\EntityTypeManager $entity_type_manager
   */
  public function __construct(ConfigFactoryInterface $config_factory, EntityTypeManager $entity_type_manager) {
    $this->config = $config_factory;
    $this->storage = $entity_type_manager->getStorage('ldap_server');
  }

  /**
   * Alter ldap_user attributes lists.
   *
   * @param array $available_user_attrs
   *   Available user attributes.
   * @param array $params
   *   Parameters.
   *
   * @return array
   *   Attribute list.
   *
   *   TODO: Split this out into a separate class.
   *   TODO: $params is a bad argument, it only needs the ldap_server and
   *   direction parameter and otherwise depends on the Server class.
   */
  public function alterLdapUserAttributesList(array &$available_user_attrs, array &$params) {
    if ($params['direction'] != self::PROVISION_TO_DRUPAL) {
      // This module only provides mappings for provisioning to Drupal.
      return;
    }

  if (isset($params['ldap_server']) && $params['ldap_server']) {
    /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
    $ldap_server = $params['ldap_server'];

    $url = Url::fromRoute('entity.ldap_server.collection');
    $tokens = [
      '%edit_link' => Link::fromTextAndUrl($url->toString(), $url)->toString(),
      '%sid' => $ldap_server->id(),
    ];

    $server_edit_path = 'admin/config/people/ldap/servers/edit/' . $ldap_server->id();

    if (!isset($available_user_attrs['[field.ldap_user_current_dn]']) || !is_array($available_user_attrs['[field.ldap_user_current_dn]'])) {
      $available_user_attrs['[field.ldap_user_current_dn]'] = [];
    }
    $available_user_attrs['[field.ldap_user_current_dn]'] =
      [
        'name' => $this->t('Field: Most Recent DN', $tokens),
        'configurable_to_drupal' => 0,
        'configurable_to_ldap' => 0,
        'source' => '[dn]',
        'notes' => 'not configurable',
        'direction' => self::PROVISION_TO_DRUPAL,
        'enabled' => TRUE,
        'prov_events' => [
          self::EVENT_CREATE_DRUPAL_USER,
          self::EVENT_SYNC_TO_DRUPAL_USER,
        ],
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
      ] + $available_user_attrs['[field.ldap_user_current_dn]'];

      if ($ldap_server->get('unique_persistent_attr')) {
        $available_user_attrs = $this->addPuidFields($available_user_attrs, $tokens, $ldap_server, $server_edit_path);
      }


      $config = $this->config->get('ldap_user.settings');
      $server = $config->get('drupalAcctProvisionServer');
      $triggers = $config->get('drupalAcctProvisionTriggers');

      if ($server && !empty($triggers)) {
        if (!isset($available_user_attrs['[property.name]']) || !is_array($available_user_attrs['[property.name]'])) {
          $available_user_attrs['[property.name]'] = [];
        }
        $available_user_attrs['[property.name]'] = [
          'name' => 'Property: Username',
          'source' => '[' . $ldap_server->get('user_attr') . ']',
          'direction' => self::PROVISION_TO_DRUPAL,
          'enabled' => TRUE,
          'prov_events' => [
            self::EVENT_CREATE_DRUPAL_USER,
            self::EVENT_SYNC_TO_DRUPAL_USER,
          ],
          'config_module' => 'ldap_servers',
          'prov_module' => 'ldap_user',
        ] + $available_user_attrs['[property.name]'];

        if (!isset($available_user_attrs['[property.mail]']) || !is_array($available_user_attrs['[property.mail]'])) {
          $available_user_attrs['[property.mail]'] = [];
        }
        $available_user_attrs['[property.mail]'] = [
          'name' => 'Property: Email',
          'source' => ($ldap_server->get('mail_template')) ? $ldap_server->get('mail_template') : '[' . $ldap_server->get('mail_attr') . ']',
          'direction' => self::PROVISION_TO_DRUPAL,
          'enabled' => TRUE,
          'prov_events' => [
            self::EVENT_CREATE_DRUPAL_USER,
            self::EVENT_SYNC_TO_DRUPAL_USER,
          ],
          'config_module' => 'ldap_servers',
          'prov_module' => 'ldap_user',
        ] + $available_user_attrs['[property.mail]'];

        if ($ldap_server->get('picture_attr')) {
          if (!isset($available_user_attrs['[property.picture]']) || !is_array($available_user_attrs['[property.picture]'])) {
            $available_user_attrs['[property.picture]'] = [];
          }
          $available_user_attrs['[property.picture]'] = [
              'name' => 'Property: Picture',
              'source' => '[' . $ldap_server->get('picture_attr') . ']',
              'direction' => self::PROVISION_TO_DRUPAL,
              'enabled' => TRUE,
              'prov_events' => [
                self::EVENT_CREATE_DRUPAL_USER,
                self::EVENT_SYNC_TO_DRUPAL_USER,
              ],
              'config_module' => 'ldap_servers',
              'prov_module' => 'ldap_user',
            ] + $available_user_attrs['[property.picture]'];
        }
      }
    }
  }

  /**
   * Add PUID Fields.
   *
   * These 4 user fields identify where in LDAP and which LDAP server they
   * are associated with. They are required for a Drupal account to be
   * "LDAP associated" regardless of if any other fields/properties are
   * provisioned or synced.
   *
   * @param array $available_user_attrs
   * @param $tokens
   * @param $ldap_server
   * @param $server_edit_path
   *
   * @return array
   */
  private function addPuidFields(array &$available_user_attrs, $tokens, ServerInterface $ldap_server, $server_edit_path) {
    $attributes = [
      'field.ldap_user_puid_sid',
      'field.ldap_user_puid',
      'field.ldap_user_puid_property',
    ];
    foreach ($attributes as $property_id) {
      $property_token = '[' . $property_id . ']';
      if (!isset($available_user_attrs[$property_token]) || !is_array($available_user_attrs[$property_token])) {
        $available_user_attrs[$property_token] = [];
      }
    }

    $available_user_attrs['[field.ldap_user_puid_sid]'] = [
        'name' => $this->t('Field: sid providing PUID'),
        'configurable_to_drupal' => 0,
        'configurable_to_ldap' => 1,
        'source' => $this->t('%sid', $tokens),
        'notes' => 'not configurable',
        'direction' => self::PROVISION_TO_DRUPAL,
        'enabled' => TRUE,
        'prov_events' => [self::EVENT_CREATE_DRUPAL_USER],
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
      ] + $available_user_attrs['[field.ldap_user_puid_sid]'];

    $available_user_attrs['[field.ldap_user_puid]'] = [
        'name' => $this->t('Field: PUID', $tokens),
        'configurable_to_drupal' => 0,
        'configurable_to_ldap' => 1,
        'source' => '[' . $ldap_server->get('unique_persistent_attr') . ']',
        'notes' => 'configure at ' . $server_edit_path,
        'convert' => $ldap_server->get('unique_persistent_attr_binary'),
        'direction' => self::PROVISION_TO_DRUPAL,
        'enabled' => TRUE,
        'prov_events' => [self::EVENT_CREATE_DRUPAL_USER],
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
      ] + $available_user_attrs['[field.ldap_user_puid]'];

    $available_user_attrs['[field.ldap_user_puid_property]'] =
      [
        'name' => $this->t('Field: PUID Attribute', $tokens),
        'configurable_to_drupal' => 0,
        'configurable_to_ldap' => 1,
        'source' => $ldap_server->get('unique_persistent_attr'),
        'notes' => 'configure at ' . $server_edit_path,
        'direction' => self::PROVISION_TO_DRUPAL,
        'enabled' => TRUE,
        'prov_events' => [self::EVENT_CREATE_DRUPAL_USER],
        'config_module' => 'ldap_servers',
        'prov_module' => 'ldap_user',
      ] + $available_user_attrs['[field.ldap_user_puid_property]'];
    return $available_user_attrs;
  }

}

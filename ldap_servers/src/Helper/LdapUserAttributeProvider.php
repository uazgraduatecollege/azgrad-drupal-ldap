<?php

namespace Drupal\ldap_servers\Helper;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Link;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Url;
use Drupal\ldap_servers\Mapping;
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
   */
  public function alterLdapUserAttributesList(array &$available_user_attrs, array &$params) {
    if ($params['direction'] != self::PROVISION_TO_DRUPAL) {
      // This module only provides mappings for provisioning to Drupal.
      return;
    }

    if (isset($params['ldap_server']) && $params['ldap_server']) {
      /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
      $ldap_server = $params['ldap_server'];

      // TODO: Shouldn't this also be as an initial entry on LDAP?
      // on LDAP's side Field: Most Recent DN.
      $available_user_attrs = $this->addDn($available_user_attrs);

      if ($ldap_server->get('unique_persistent_attr')) {
        $available_user_attrs = $this->addPuidFields($available_user_attrs, $ldap_server);
      }

      $config = $this->config->get('ldap_user.settings');
      $triggers = $config->get('drupalAcctProvisionTriggers');
      if (!empty($triggers)) {
        $available_user_attrs = $this->addBaseProperties($available_user_attrs, $ldap_server);
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
   * @param \Drupal\ldap_servers\Mapping[] $available_user_attrs
   * @param $tokens
   * @param $ldap_server
   * @param $server_edit_path
   *
   * @return array
   */
  private function addPuidFields(array &$available_user_attrs, ServerInterface $ldap_server) {
    $url = Url::fromRoute('entity.ldap_server.collection');
    $tokens = [
      '%edit_link' => Link::fromTextAndUrl($url->toString(), $url)->toString(),
      '%sid' => $ldap_server->id(),
    ];

    $fields = [
      '[field.ldap_user_puid_sid]' => $this->t('Field: sid providing PUID'),
      '[field.ldap_user_puid]' => $this->t('Field: PUID'),
      '[field.ldap_user_puid_property]' => $this->t('Field: PUID Attribute'),
    ];
    foreach ($fields as $key => $name) {
      $available_user_attrs[$key] = new Mapping(
        $key,
        $name,
        FALSE,
        TRUE,
        [self::EVENT_CREATE_DRUPAL_USER],
        'ldap_user',
        'ldap_servers'
      );
      $available_user_attrs[$key]->setNotes($this->t('configure at %edit_link', $tokens));
    }

    $available_user_attrs['[field.ldap_user_puid_sid]']->setLdapAttribute($ldap_server->id());
    $available_user_attrs['[field.ldap_user_puid]']->setLdapAttribute($this->addTokens($ldap_server->get('unique_persistent_attr')));
    $available_user_attrs['[field.ldap_user_puid_property]']->setLdapAttribute($ldap_server->get('unique_persistent_attr'));

    return $available_user_attrs;
  }

  /**
   * @param \Drupal\ldap_servers\Mapping[] $available_user_attrs
   * @param \Drupal\ldap_servers\Entity\Server $ldap_server
   *
   * @return array
   */
  private function addBaseProperties(array &$available_user_attrs, $ldap_server) {
    $fields = [
      '[property.name]' => 'Property: Username',
      '[property.mail]' => 'Property: Email',
    ];

    if ($ldap_server->get('picture_attr')) {
      $fields['[property.picture]'] = 'Property: Picture';
    }

    foreach ($fields as $key => $name) {
      $available_user_attrs[$key] = new Mapping(
        $key,
        $name,
        FALSE,
        TRUE,
        [self::EVENT_CREATE_DRUPAL_USER, self::EVENT_SYNC_TO_DRUPAL_USER],
        'ldap_servers',
        'ldap_user'
      );
    }

    $available_user_attrs['[property.name]']->setLdapAttribute($this->addTokens($ldap_server->get('user_attr')));

    if ($ldap_server->get('mail_template')) {
      $available_user_attrs['[property.mail]']->setLdapAttribute($ldap_server->get('mail_template'));
    }
    else {
      $available_user_attrs['[property.mail]']->setLdapAttribute($this->addTokens($ldap_server->get('mail_attr')));
    }

    if ($ldap_server->get('picture_attr')) {
      $available_user_attrs['[property.picture]']->setLdapAttribute($this->addTokens($ldap_server->get('picture_attr')));
    }

    return $available_user_attrs;
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
   * @param \Drupal\ldap_servers\Mapping[] $available_user_attrs
   * @param $tokens
   *
   * @return array
   */
  private function addDn(array &$available_user_attrs) {
    $available_user_attrs['[field.ldap_user_current_dn]'] = new Mapping(
       '[field.ldap_user_current_dn]',
        $this->t('Field: Most Recent DN'),
        FALSE,
        TRUE,
         [self::EVENT_CREATE_DRUPAL_USER, self::EVENT_SYNC_TO_DRUPAL_USER],
      'ldap_user',
        'ldap_servers'
      );
    $available_user_attrs['[field.ldap_user_current_dn]']->setLdapAttribute('[dn]');
    $available_user_attrs['[field.ldap_user_current_dn]']->setNotes('not configurable');

    return $available_user_attrs;
  }

}

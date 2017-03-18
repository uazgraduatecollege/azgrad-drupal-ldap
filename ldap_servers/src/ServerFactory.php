<?php

namespace Drupal\ldap_servers;

use Drupal\Core\Url;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Processor\TokenProcessor;
use Drupal\ldap_user\Helper\ExternalAuthenticationHelper;
use Drupal\ldap_user\Helper\LdapConfiguration;
use Drupal\user\UserInterface;

/**
 *
 */
class ServerFactory {

  /**
   * @return Server
   */
  public function getServerById($sid) {
    return Server::load($sid);
  }

  /**
   * @return Server|bool
   */
  public function getServerByIdEnabled($sid) {
    $server = Server::load($sid);
    if ($server && $server->status()) {
      return $server;
    }
    else {
      return FALSE;
    }
  }

  /**
   * @return Server[]
   */
  public function getAllServers() {
    $query = \Drupal::entityQuery('ldap_server');
    $ids = $query->execute();
    return Server::loadMultiple($ids);
  }

  /**
   * @return Server[]
   */
  public function getEnabledServers() {
    $query = \Drupal::entityQuery('ldap_server')
      ->condition('status', 1);
    $ids = $query->execute();
    return Server::loadMultiple($ids);
  }

  /**
   * @param $identifier
   * @param $id
   * @param null $ldap_context
   *
   * @return array|bool
   */
  public function getUserDataFromServerByIdentifier($identifier, $id, $ldap_context = NULL) {
    // Try to retrieve the user from the cache.
    $cache = \Drupal::cache()->get('ldap_servers:user_data:' . $identifier);
    if ($cache && $cache->data) {
      return $cache->data;
    }

    $server = $this->getServerByIdEnabled($id);

    if (!$server) {
      \Drupal::logger('ldap_servers')->error('Failed to load server object %sid in _ldap_servers_get_user_ldap_data', array('%sid' => $id));
      return FALSE;
    }

    $ldap_user = $server->userUserNameToExistingLdapEntry($identifier, $ldap_context);

    if ($ldap_user) {
      $ldap_user['id'] = $id;
      $cache_expiry = 5 * 60 + time();
      $cache_tags = array('ldap', 'ldap_servers', 'ldap_servers.user_data');
      \Drupal::cache()->set('ldap_servers:user_data:' . $identifier, $ldap_user, $cache_expiry, $cache_tags);
    }

    return $ldap_user;
  }

  /**
   * @param UserInterface $account
   * @param string $id
   * @param null $ldap_context
   * @return mixed
   */
  public function getUserDataFromServerByAccount($account, $id, $ldap_context = NULL) {
    $identifier = ExternalAuthenticationHelper::getUserIdentifierFromMap($account->id());
    if ($identifier) {
      return $this->getUserDataFromServerByIdentifier($identifier, $id, $ldap_context);
    }
    else {
      return FALSE;
    }
  }

  /**
   * @param UserInterface $account
   * @param $ldap_context
   * @return mixed
   */
  public function getUserDataByAccount($account, $ldap_context = NULL) {
    $provisioningServer = \Drupal::config('ldap_user.settings')->get('drupalAcctProvisionServer');
    $id = NULL;
    if (!$account) {
      return FALSE;
    }

    /*
     * TODO: While this functionality is now consistent with 7.x, it hides
     * a corner case: server which are no longer available can still be set in
     * the user as a preference and those users will not be able to sync.
     * This needs to get cleaned up or fallback differently.
     */
    if (property_exists($account, 'ldap_user_puid_sid') &&
      !empty($account->get('ldap_user_puid_sid')->value)) {
      $id = $account->get('ldap_user_puid_sid')->value;
    }
    elseif ($provisioningServer) {
      $id = $provisioningServer;
    }
    else {
      $servers = $this->getEnabledServers();
      if (count($servers) == 1) {
        $ids = array_keys($servers);
        $id = $ids[0];
      }
      else {
        \Drupal::logger('ldap_user')->error('Multiple servers enabled, one has to be set up for user provision.');
        return FALSE;
      }
    }
    return $this->getUserDataFromServerByAccount($account, $id, $ldap_context);
  }

  /**
   * Duplicate function in Server due to test complications.
   *
   * @param $dn
   * @param $attribute
   *
   * @return array
   */
  public function ldapExplodeDn($dn, $attribute) {
    return ldap_explode_dn($dn, $attribute);
  }

  /**
   * @param $attributes
   * @param $params
   * @return mixed
   */
  public function alterLdapAttributes(&$attributes, $params) {
    $token_helper = new TokenProcessor();
    // Force this data type.
    $attributes['dn'] = TokenProcessor::setAttributeMap(@$attributes['dn'], 'ldap_dn');

    // Puid attributes are server specific.
    if (isset($params['sid']) && $params['sid']) {
      if (is_scalar($params['sid'])) {
        $ldap_server = $this->getServerById($params['sid']);

        if ($ldap_server) {
          // mail, unique_persistent_attr, user_attr, mail_template, and user_dn_expression are needed for all functionality.
          if (!isset($attributes[$ldap_server->get('mail_attr')])) {
            $attributes[$ldap_server->get('mail_attr')] = TokenProcessor::setAttributeMap();
          }
          if (!isset($attributes[$ldap_server->get('picture_attr')])) {
            $attributes[$ldap_server->get('picture_attr')] = TokenProcessor::setAttributeMap();
          }
          if ($ldap_server->get('unique_persistent_attr') && !isset($attributes[$ldap_server->get('unique_persistent_attr')])) {
            $attributes[$ldap_server->get('unique_persistent_attr')] = TokenProcessor::setAttributeMap();
          }
          if ($ldap_server->get('user_dn_expression')) {
            $token_helper->extractTokenAttributes($attributes, $ldap_server->get('user_dn_expression'));
          }
          if ($ldap_server->get('mail_template')) {
            $token_helper->extractTokenAttributes($attributes, $ldap_server->get('mail_template'));
          }
          if (!isset($attributes[$ldap_server->get('user_attr')])) {
            $attributes[$ldap_server->get('user_attr')] = TokenProcessor::setAttributeMap();
          }
        }
      }
    }
    return $attributes;
  }

  /**
   * @param $available_user_attrs
   * @param $params
   * @return array
   */
  public function alterLdapUserAttributesList(&$available_user_attrs, &$params) {
    if (isset($params['ldap_server']) && $params['ldap_server']) {
      /** @var Server $ldap_server */
      $ldap_server = $params['ldap_server'];

      $direction = $params['direction'];

      $url = Url::fromRoute('entity.ldap_server.collection');
      $tokens = array(
        '%edit_link' => \Drupal::l($url->toString(), $url),
        '%sid' => $ldap_server->id(),
      );

      $server_edit_path = 'admin/config/people/ldap/servers/edit/' . $ldap_server->id();

      if ($direction == LdapConfiguration::$provisioningDirectionToDrupalUser) {

        /**
         * These 4 user fields identify where in ldap and which ldap server they are
         * associated with. They are required for a Drupal account to be
         * "ldap associated" regardless of if any other fields/properties are
         * provisioned or synced.
         */

        if ($ldap_server->get('unique_persistent_attr')) {
          $attributes = [
            'field.ldap_user_puid_sid',
            'field.ldap_user_puid',
            'field.ldap_user_puid_property',
          ];
          foreach ($attributes as $i => $property_id) {
            $property_token = '[' . $property_id . ']';
            if (!isset($available_user_attrs[$property_token]) || !is_array($available_user_attrs[$property_token])) {
              $available_user_attrs[$property_token] = array();
            }
          }

          $available_user_attrs['[field.ldap_user_puid_sid]'] = array(
            'name' => t('Field: sid providing PUID'),
            'configurable_to_drupal' => 0,
            'configurable_to_ldap' => 1,
            'source' => t('%sid', $tokens),
            'notes' => 'not configurable',
            'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
            'enabled' => TRUE,
            'prov_events' => array(LdapConfiguration::$eventCreateDrupalUser),
            'config_module' => 'ldap_servers',
            'prov_module' => 'ldap_user',
          ) + $available_user_attrs['[field.ldap_user_puid_sid]'];

          $available_user_attrs['[field.ldap_user_puid]'] = array(
            'name' => t('Field: PUID', $tokens),
            'configurable_to_drupal' => 0,
            'configurable_to_ldap' => 1,
            'source' => '[' . $ldap_server->get('unique_persistent_attr') . ']',
            'notes' => 'configure at ' . $server_edit_path,
            'convert' => $ldap_server->get('unique_persistent_attr_binary'),
            'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
            'enabled' => TRUE,
            'prov_events' => array(LdapConfiguration::$eventCreateDrupalUser),
            'config_module' => 'ldap_servers',
            'prov_module' => 'ldap_user',
          ) + $available_user_attrs['[field.ldap_user_puid]'];

          $available_user_attrs['[field.ldap_user_puid_property]'] =
            array(
              'name' => t('Field: PUID Attribute', $tokens),
              'configurable_to_drupal' => 0,
              'configurable_to_ldap' => 1,
              'source' => $ldap_server->get('unique_persistent_attr'),
              'notes' => 'configure at ' . $server_edit_path,
              'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
              'enabled' => TRUE,
              'prov_events' => array(LdapConfiguration::$eventCreateDrupalUser),
              'config_module' => 'ldap_servers',
              'prov_module' => 'ldap_user',
            ) + $available_user_attrs['[field.ldap_user_puid_property]'];
        }

        $token = '[field.ldap_user_current_dn]';
        if (!isset($available_user_attrs[$token]) || !is_array($available_user_attrs[$token])) {
          $available_user_attrs[$token] = array();
        }
        $available_user_attrs[$token] =
          array(
            'name' => t('Field: Most Recent DN', $tokens),
            'configurable_to_drupal' => 0,
            'configurable_to_ldap' => 0,
            'source' => '[dn]',
            'notes' => 'not configurable',
            'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
            'enabled' => TRUE,
            'prov_events' => array(
              LdapConfiguration::$eventCreateDrupalUser,
              LdapConfiguration::$eventSyncToDrupalUser,
            ),
            'config_module' => 'ldap_servers',
            'prov_module' => 'ldap_user',
          ) + $available_user_attrs[$token];

        if (LdapConfiguration::provisionsDrupalAccountsFromLdap()) {
          if (!isset($available_user_attrs['[property.name]']) || !is_array($available_user_attrs['[property.name]'])) {
            $available_user_attrs['[property.name]'] = array();
          }
          $available_user_attrs['[property.name]'] = array(
            'name' => 'Property: Username',
            'source' => '[' . $ldap_server->get('user_attr') . ']',
            'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
            'enabled' => TRUE,
            'prov_events' => array(
              LdapConfiguration::$eventCreateDrupalUser,
              LdapConfiguration::$eventSyncToDrupalUser,
            ),
            'config_module' => 'ldap_servers',
            'prov_module' => 'ldap_user',
          ) + $available_user_attrs['[property.name]'];

          if (!isset($available_user_attrs['[property.mail]']) || !is_array($available_user_attrs['[property.mail]'])) {
            $available_user_attrs['[property.mail]'] = array();
          }
          $available_user_attrs['[property.mail]'] = array(
            'name' => 'Property: Email',
            'source' => ($ldap_server->get('mail_template')) ? $ldap_server->get('mail_template') : '[' . $ldap_server->get('mail_attr') . ']',
            'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
            'enabled' => TRUE,
            'prov_events' => array(
              LdapConfiguration::$eventCreateDrupalUser,
              LdapConfiguration::$eventSyncToDrupalUser,
            ),
            'config_module' => 'ldap_servers',
            'prov_module' => 'ldap_user',
          ) + $available_user_attrs['[property.mail]'];

          if ($ldap_server->get('picture_attr')) {
            if (!isset($available_user_attrs['[property.picture]']) || !is_array($available_user_attrs['[property.picture]'])) {
              $available_user_attrs['[property.picture]'] = array();
            }
            $available_user_attrs['[property.picture]'] = array(
              'name' => 'Property: Picture',
              'source' => '[' . $ldap_server->get('picture_attr') . ']',
              'direction' => LdapConfiguration::$provisioningDirectionToDrupalUser,
              'enabled' => TRUE,
              'prov_events' => array(
                LdapConfiguration::$eventCreateDrupalUser,
                LdapConfiguration::$eventSyncToDrupalUser,
              ),
              'config_module' => 'ldap_servers',
              'prov_module' => 'ldap_user',
            ) + $available_user_attrs['[property.picture]'];
          }
        }
      }
    }
    return array($params, $available_user_attrs);
  }

}

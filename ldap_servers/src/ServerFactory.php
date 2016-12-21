<?php

namespace Drupal\ldap_servers;

use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_user\LdapUserConf;
use Drupal\user\UserInterface;

/**
 *
 */
class ServerFactory {

  public function getServerById($sid) {
    return Server::load($sid);
  }

  public function getServerByIdEnabled($sid) {
    $server = Server::load($sid);
    if ($server->status()) {
      return $server;
    } else {
      return FALSE;
    }
  }

  public function getAllServers() {
    $query = \Drupal::entityQuery('ldap_server');
    $ids = $query->execute();
    return Server::loadMultiple($ids);
  }

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
    $identifier = LdapUserConf::getUserIdentifierFromMap($account->id());
    return $this->getUserDataFromServerByIdentifier($identifier, $id, $ldap_context);
  }

  /**
   * @param UserInterface $account
   * @param $ldap_context
   * @return mixed
   */
  public function getUserDataByAccount($account, $ldap_context = NULL) {
    $provisioningServer = \Drupal::config('ldap_user.settings')->get('ldap_user_conf.drupalAcctProvisionServer');
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
    if (property_exists($account,'ldap_user_puid_sid') &&
      !empty($account->get('ldap_user_puid_sid')->value)) {
      $id = $account->get('ldap_user_puid_sid')->value;
    } else if ($provisioningServer) {
      $id = $provisioningServer;
    } else {
      $servers = $this->getEnabledServers();
      if (count($servers) == 1) {
        $ids = array_keys($servers);
        $id = $ids[0];
      } else {
        \Drupal::logger('ldap_user')->error('Multiple servers enabled, one has to be set up for user provision.');
        return FALSE;
      }
    }
    return $this->getUserDataFromServerByAccount($account, $id, $ldap_context);
  }

  /**
   * Duplicate function in Server due to test complications.
   **/
  public function ldapExplodeDn($dn, $attribute) {
    return ldap_explode_dn($dn, $attribute);
  }
}

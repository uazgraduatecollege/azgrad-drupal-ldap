<?php

namespace Drupal\ldap_authentication\Helper;

use Drupal\ldap_servers\ServerFactory;

class LdapAuthenticationConfiguration {

  public static function hasEnabledAuthenticationServers() {
    return (count(self::getEnabledAuthenticationServers()) > 0) ? TRUE : FALSE;
  }

  public static function getEnabledAuthenticationServers() {
    $servers = \Drupal::config('ldap_authentication.settings')->get('ldap_authentication_conf.sids');
    /* @var ServerFactory $factory */
    $factory = \Drupal::service('ldap.servers');
    $result = [];
    foreach ($servers as $server) {
      if ($factory->getServerByIdEnabled($server)) {
        $result[] = $server;
      }
    }
    return $result;
  }


}
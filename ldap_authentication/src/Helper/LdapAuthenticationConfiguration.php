<?php

namespace Drupal\ldap_authentication\Helper;

use Drupal\ldap_servers\ServerFactory;

class LdapAuthenticationConfiguration {


  // Signifies both LDAP and Drupal authentication are allowed.
  public static $mode_mixed = 1;
  // Signifies only LDAP authentication is allowed.
  public static $mode_exclusive = 2;

  public static $authFailConnect = 1;
  public static $authFailBind = 2;
  public static $authFailFind = 3;
  public static $authFailDisallowed = 4;
  public static $authFailCredentials = 5;
  public static $authSuccess = 6;
  public static $authFailGeneric = 7;
  public static $authFailServer = 8;

  public static $emailUpdateOnLdapChangeEnableNotify = 1;
  public static $emailUpdateOnLdapChangeEnable = 2;
  public static $emailUpdateOnLdapChangeDisable = 3;
  // Remove default later if possible, see also $emailUpdate.
  public static $emailUpdateOnLdapChangeDefault = 1;

  public static $passwordFieldShow = 2;
  public static $passwordFieldHide = 3;
  public static $passwordFieldAllow = 4;
  // Remove default later if possible, see also $passwordOption.
  public static $passwordFieldDefault = 2;

  public static $emailFieldRemove = 2;
  public static $emailFieldDisable = 3;
  public static $emailFieldAllow = 4;
  // Remove default later if possible, see also $emailOption.
  public static $emailFieldDefault = 3;

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

  /**
   *
   */
  public static function arrayToLines($array) {
    $lines = "";
    if (is_array($array)) {
      $lines = join("\n", $array);
    }
    elseif (is_array(@unserialize($array))) {
      $lines = join("\n", unserialize($array));
    }
    return $lines;
  }

  /**
   *
   */
  public static function linesToArray($lines) {
    $lines = trim($lines);

    if ($lines) {
      $array = preg_split('/[\n\r]+/', $lines);
      foreach ($array as $i => $value) {
        $array[$i] = trim($value);
      }
    }
    else {
      $array = array();
    }
    return $array;
  }


}
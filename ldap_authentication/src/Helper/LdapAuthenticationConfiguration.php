<?php

namespace Drupal\ldap_authentication\Helper;

/**
 * Configuration helper class for LDAP authentication.
 *
 * @TODO: Make this class obsolete.
 */
class LdapAuthenticationConfiguration {

  /**
   * Return list of enabled authentication servers.
   *
   * @return \Drupal\ldap_servers\ServerFactory[]
   *   The list of available servers.
   *
   * @deprecated
   */
  public static function getEnabledAuthenticationServers() {
    // FIXME: DI.
    $servers = \Drupal::config('ldap_authentication.settings')->get('sids');
    /** @var \Drupal\ldap_servers\ServerFactory $factory */
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
   * Helper function to convert array to serialized lines.
   *
   * @param array $array
   *   List of items.
   *
   * @return string
   *   Serialized content.
   */
  public static function arrayToLines(array $array) {
    $lines = "";
    if (is_array($array)) {
      $lines = implode("\n", $array);
    }
    elseif (is_array(@unserialize($array))) {
      $lines = implode("\n", unserialize($array));
    }
    return $lines;
  }

  /**
   * Helper function to convert array to serialized lines.
   *
   * @param string $lines
   *   Serialized lines.
   *
   * @return array
   *   Deserialized content.
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
      $array = [];
    }
    return $array;
  }

}

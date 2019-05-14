<?php

namespace Drupal\ldap_servers;

/**
 * Helper functions to work around hard dependencies on the LDAP extension.
 */
trait LdapTransformationTraits {

  /**
   * Wrapper for ldap_escape().
   *
   * Helpful for unit testing without the PHP LDAP module.
   *
   * @param string $string
   *   String to escape.
   *
   * @return string
   *   Escaped string.
   */
  protected function ldapEscapeDn($value) {
    if (function_exists('ldap_escape')) {
      $value = ldap_escape($value, '', LDAP_ESCAPE_DN);
    }
    else {
      $value = str_replace(['*', '\\', '(', ')'], ['\\*', '\\\\', '\\(', '\\)'], $value);
    }

    // Copied from Symfonfy's Adapter.php for ease of use.
    // Per RFC 4514, leading/trailing spaces should be encoded in DNs,
    // as well as carriage returns.
    if (!empty($value) && ' ' === $value[0]) {
      $value = '\\20' . substr($value, 1);
    }
    if (!empty($value) && ' ' === $value[\strlen($value) - 1]) {
      $value = substr($value, 0, -1) . '\\20';
    }
    $value = str_replace("\r", '\0d', $value);

    return $value;
  }

  /**
   * Wrapper for ldap_escape().
   *
   * Helpful for unit testing without the PHP LDAP module.
   *
   * @param string $value
   *   String to escape.
   *
   * @return string
   *   Escaped string.
   */
  protected function ldapEscapeFilter($value) {
    if (function_exists('ldap_escape')) {
      return ldap_escape($value, '', LDAP_ESCAPE_FILTER);
    }
    else {
      // Taken from symfony/polyfill-php56.
      $charMaps['filter'] = ['\\', ',', '=', '+', '<', '>', ';', '"', '#', "\r"];
      for ($i = 0; $i < 256; ++$i) {
        $charMaps[0][\chr($i)] = sprintf('\\%02x', $i);
      }
      for ($i = 0, $l = \count($charMaps['filter']); $i < $l; ++$i) {
        $chr = $charMaps['filter'][$i];
        unset($charMaps['filter'][$i]);
        $charMaps['filter'][$chr] = $charMaps[0][$chr];
      }

      return strtr($value, $charMaps['filter']);
    }
  }

  /**
   * Wrapper for ldap_explode_dn().
   *
   * Helpful for unit testing without the PHP LDAP module.
   *
   * @param string $dn
   *   DN to explode.
   * @param int $attribute
   *   Attribute.
   *
   * @return array
   *   Exploded DN.
   */
  public static function ldapExplodeDn($dn, $attribute) {
    return ldap_explode_dn($dn, $attribute);
  }

}

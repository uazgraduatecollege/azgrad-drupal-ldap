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
   * @return mixed|string
   *   Escaped string.
   */
  protected function ldapEscape($string) {
    if (function_exists('ldap_escape')) {
      return ldap_escape($string);
    }
    else {
      return str_replace(['*', '\\', '(', ')'], ['\\*', '\\\\', '\\(', '\\)'], $string);
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

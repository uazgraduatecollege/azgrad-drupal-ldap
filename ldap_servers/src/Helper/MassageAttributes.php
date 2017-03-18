<?php

namespace Drupal\ldap_servers\Helper;

use Drupal\Component\Utility\Unicode;

/**
 * This class helps you in preparing attributes and values for usage in Drupal.
 */
class MassageAttributes {

  /**
   * Escape filter values and attribute values when querying ldap.
   *
   * @param $value
   *
   * @return array
   */
  public function queryLdapAttributeValue($value) {
    if (!empty($value)) {
      $value = ConversionHelper::escapeFilterValue($value);
    }
    return $value;
  }

  /**
   * Prepare text for storing LDAP attribute values.
   *
   * Use unescaped, mixed case attribute values when storing attribute values
   * in arrays (as keys or values), databases, or object properties.
   *
   * @param $value
   *
   * @return array
   */
  public function storeLdapAttributeValue($value) {
    if (!empty($value)) {
      $value = ConversionHelper::escapeDnValue($value);
    }
    return $value;
  }

  /**
   * Prepare attribute names for usage in Drupal.
   *
   * Use unescaped, lower case attribute names when storing attribute names in
   * arrays (as keys or values), databases, or object properties.
   *
   * @param $value
   *
   * @return array|string
   */
  public function processAttributeName($value) {
    $scalar = is_scalar($value);
    if ($scalar) {
      $value = Unicode::strtolower($value);
    }
    elseif (is_array($value)) {
      foreach ($value as $i => $val) {
        $value[$i] = Unicode::strtolower($val);
      }
    }
    else {
      // Neither scalar nor array $value.
    }

    return $value;
  }

}

<?php

namespace Drupal\ldap_servers;

use Drupal\Component\Utility\Unicode;

/**
 *
 */
class MassageFunctions {

  // ... value is being displayed in UI.
  public static $display = 1;
  // ... value is about to be used to generate token (e.g. [...] to be replaced.
  public static $token_replace = 2;

  // ...value is about to be used in ldap query.
  public static $query_ldap = 5;

  // ...value is about to be in an sql query.
  public static $query_db = 6;

  // ...value is about to be found in array values.
  public static $query_array = 7;

  // ...value is about to be found in object property values.
  public static $query_property = 8;


  // ...value is about to be stored in ldap entry.
  public static $store_ldap = 13;
  // ...value is about to be stored in db.
  public static $store_db = 14;
  // ...value is about to be stored in array.
  public static $store_array = 15;
  // ...value is about to be stored in object property.
  public static $store_property = 16;

  /**
   * Function to massage (change case, escape, unescape) ldap attribute names
   * and values.  The primary purpose of this is to articulate and ensure consistency
   * across ldap modules.
   *
   * @param mixed $value
   *   to be massaged.
   * @param string $value_type
   *   = 'attr_name' or 'attr_value;.
   * @param string $context
   *   ...see
   *   MassageFunction constants.
   *
   * @return array|mixed|string
   */
  public function massage_text($value, $value_type, $context) {
    $helper = new ConversionHelper();
    $scalar = is_scalar($value);

    if ($value_type == 'attr_value') {

      if ($context == self::$query_ldap) {
        $value = $helper->escape_filter_value($value);
      }
      elseif ($context == self::$store_ldap) {
        $value = $helper->escape_dn_value($value);
      }

      switch ($context) {

        case self::$display:
        case self::$token_replace:

        case self::$query_ldap:
        case self::$query_db:
        case self::$query_array:
        case self::$query_property:

        case self::$store_ldap:
        case self::$store_db:
        case self::$store_array:
        case self::$store_property:

          break;

      }
    }
    // attr_name.
    elseif ($value_type == 'attr_name') {
      switch ($context) {

        case self::$display:
          break;

        case self::$token_replace:

        case self::$query_ldap:
        case self::$query_db:
        case self::$query_array:
        case self::$query_property:

        case self::$store_ldap:
        case self::$store_db:
        case self::$store_array:
        case self::$store_property:
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
          break;

      }
    }

    return $value;

  }

}

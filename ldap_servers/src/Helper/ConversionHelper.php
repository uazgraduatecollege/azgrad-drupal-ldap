<?php

namespace Drupal\ldap_servers\Helper;

/**
 * Conversion helper to escape values correctly for LDAP filters.
 */
class ConversionHelper {

  /**
   * Escapes the given values so that they can be safely used in LDAP filters.
   *
   * Follow RFC 2254 so that control characters with an ACII code < 32 as well
   * as the characters with special meaning in LDAP filters "*", "(", ")", and
   * "\" (the backslash) are converted into the representation of a backslash
   * followed by two hex digits representing the hexadecimal value of the
   * character.
   *
   * @param array|string $values
   *   Array of values to escape.
   *
   * @static
   *
   * @return array
   *   Array of values, but escaped.
   */
  public static function escapeFilterValue($values) {
    // Parameter validation.
    $input_is_scalar = is_scalar($values);
    if ($input_is_scalar) {
      $values = [$values];
    }

    foreach ($values as $key => $val) {
      // Might be a Drupal field.
      if (isset($val->value)) {
        $isField = TRUE;
        $val = $val->getValue();
      }
      else {
        $isField = FALSE;
      }
      // Escaping of filter meta characters.
      $val = str_replace('\\', '\5c', $val);
      $val = str_replace('*', '\2a', $val);
      $val = str_replace('(', '\28', $val);
      $val = str_replace(')', '\29', $val);

      // ASCII < 32 escaping.
      $val = self::asc2hex32($val);

      if (NULL === $val) {
        // Apply escaped "null" if string is empty.
        $val = '\0';
      }
      if ($isField) {
        $values[$key]->setValue($val);
      }
      else {
        $values[$key] = $val;
      }
    }

    if (($input_is_scalar)) {
      return $values[0];
    }
    else {
      return $values;
    }
  }

  /**
   * Undoes the conversion done by {@link escape_filter_value()}.
   *
   * Converts any sequences of a backslash followed by two hex digits into the
   * corresponding character.
   *
   * @param mixed $values
   *   Array of values to escape.
   *
   * @static
   *
   * @return array
   *   Unescaped values.
   */
  public static function unescapeFilterValue($values) {
    // Parameter validation.
    $inputIsScalar = is_scalar($values);
    if (!is_array($values)) {
      $values = [$values];
    }

    foreach ($values as $key => $value) {
      // Translate hex code into ascii.
      $values[$key] = self::hex2asc($value);
    }

    if (($inputIsScalar)) {
      return $values[0];
    }
    else {
      return $values;
    }
  }

  /**
   * Escapes a DN value according to RFC 2253.
   *
   * Escapes the given VALUES according to RFC 2253 so that they can be safely
   * used in LDAP DNs. The characters ",", "+", """, "\", "<", ">", ";", "#",
   * "=" with a special meaning in RFC 2252 are preceded by a backslash. Control
   * characters with an ASCII code < 32 are represented as \hexpair. Finally all
   * leading and trailing spaces are converted to sequences of \20.
   *
   * @param array|string $values
   *   An array containing the DN values that should be escaped.
   *
   * @static
   *
   * @return array
   *   The array $values, but escaped.
   */
  public static function escapeDnValue($values) {
    // Parameter validation.
    $inputIsScalar = is_scalar($values);
    if ($inputIsScalar) {
      $values = [$values];
    }

    foreach ($values as $key => $val) {
      // Escaping of filter meta characters.
      $val = str_replace('\\', '\\\\', $val);
      $val = str_replace(',', '\,', $val);
      $val = str_replace('+', '\+', $val);
      $val = str_replace('"', '\"', $val);
      $val = str_replace('<', '\<', $val);
      $val = str_replace('>', '\>', $val);
      $val = str_replace(';', '\;', $val);
      $val = str_replace('#', '\#', $val);
      $val = str_replace('=', '\=', $val);

      // ASCII < 32 escaping.
      $val = self::asc2hex32($val);

      // Convert all leading and trailing spaces to sequences of \20.
      if (preg_match('/^(\s*)(.+?)(\s*)$/', $val, $matches)) {
        $val = $matches[2];
        for ($i = 0; $i < strlen($matches[1]); $i++) {
          $val = '\20' . $val;
        }
        for ($i = 0; $i < strlen($matches[3]); $i++) {
          $val = $val . '\20';
        }
      }

      if (NULL === $val) {
        // Apply escaped "null" if string is empty.
        $val = '\0';
      }
      $values[$key] = $val;
    }

    if (($inputIsScalar)) {
      return $values[0];
    }
    else {
      return $values;
    }
  }

  /**
   * Undoes the conversion done by escape_dn_value().
   *
   * Any escape sequence starting with a baskslash - hexpair or special
   * character - will be transformed back to the corresponding character.
   *
   * @param mixed $values
   *   Array of DN Values.
   *
   * @return array
   *   Same as $values, but unescaped
   */
  public static function unescapeDnValue($values) {
    $inputIsScalar = is_scalar($values);

    // Parameter validation.
    if (!is_array($values)) {
      $values = [$values];
    }

    foreach ($values as $key => $val) {
      // Strip slashes from special chars.
      $val = str_replace('\\\\', '\\', $val);
      $val = str_replace('\,', ',', $val);
      $val = str_replace('\+', '+', $val);
      $val = str_replace('\"', '"', $val);
      $val = str_replace('\<', '<', $val);
      $val = str_replace('\>', '>', $val);
      $val = str_replace('\;', ';', $val);
      $val = str_replace('\#', '#', $val);
      $val = str_replace('\=', '=', $val);

      // Translate hex code into ascii.
      $values[$key] = self::hex2asc($val);
    }

    if (($inputIsScalar)) {
      return $values[0];
    }
    else {
      return $values;
    }
  }

  /**
   * Converts all Hex expressions ("\HEX") to their original ASCII characters.
   *
   * @param string $string
   *   String to convert.
   *
   * @return string
   *   Converted string.
   */
  public static function hex2asc($string) {
    $string = preg_replace_callback(
      "/\\\([0-9A-Fa-f]{2})/",
      function (array $matches) {
        return chr(hexdec($matches[0]));
      },
      $string
    );
    return $string;
  }

  /**
   * Converts all ASCII chars < 32 to "\HEX".
   *
   * @param string $string
   *   String to convert.
   *
   * @return string
   *   Converted string.
   */
  public static function asc2hex32($string) {
    for ($i = 0; $i < strlen($string); $i++) {
      $char = substr($string, $i, 1);
      if (ord($char) < 32) {
        $hex = dechex(ord($char));
        if (strlen($hex) == 1) {
          $hex = '0' . $hex;
        }
        $string = str_replace($char, '\\' . $hex, $string);
      }
    }
    return $string;
  }

}

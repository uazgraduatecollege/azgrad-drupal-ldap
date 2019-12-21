<?php

declare(strict_types=1);

namespace Drupal\ldap_servers\Helper;

/**
 * Conversion helper to escape values correctly for LDAP filters.
 */
class ConversionHelper {

  /**
   * Undoes the conversion done by escape_dn_value().
   *
   * Any escape sequence starting with a baskslash - hexpair or special
   * character - will be transformed back to the corresponding character.
   *
   * @param string $value
   *   DN Value.
   *
   * @return string
   *   Same as $value, but unescaped
   */
  public static function unescapeDnValue(string $value): string {

    // Strip slashes from special chars.
    $value = str_replace('\\\\', '\\', $value);
    $value = str_replace('\,', ',', $value);
    $value = str_replace('\+', '+', $value);
    $value = str_replace('\"', '"', $value);
    $value = str_replace('\<', '<', $value);
    $value = str_replace('\>', '>', $value);
    $value = str_replace('\;', ';', $value);
    $value = str_replace('\#', '#', $value);
    $value = str_replace('\=', '=', $value);

    // Translate hex code into ascii.
    $value = self::hex2asc($value);

    return $value;
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
    return preg_replace_callback(
        "/\\\([0-9A-Fa-f]{2})/",
        function (array $matches) {
          return chr(hexdec($matches[0]));
        },
        $string
      );
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
    $length = strlen($string);
    for ($i = 0; $i < $length; $i++) {
      $char = substr($string, $i, 1);
      if (ord($char) < 32) {
        $hex = dechex(ord($char));
        if (strlen($hex) === 1) {
          $hex = '0' . $hex;
        }
        $string = str_replace($char, '\\' . $hex, $string);
      }
    }
    return $string;
  }

  /**
   * Function to convert microsoft style guids to strings.
   *
   * @param string $value
   *   Value to convert.
   *
   * @return string
   *   Converted value.
   */
  public static function convertMsguidToString($value) {
    $hex_string = bin2hex($value);
    // (MS?) GUID are displayed with first three GUID parts as "big endian"
    // Doing this so String value matches what other LDAP tool displays for AD.
    $value = strtoupper(substr($hex_string, 6, 2) . substr($hex_string, 4, 2) .
      substr($hex_string, 2, 2) . substr($hex_string, 0, 2) . '-' .
      substr($hex_string, 10, 2) . substr($hex_string, 8, 2) . '-' .
      substr($hex_string, 14, 2) . substr($hex_string, 12, 2) . '-' .
      substr($hex_string, 16, 4) . '-' . substr($hex_string, 20, 12));

    return $value;
  }

  /**
   * General binary conversion function for GUID.
   *
   * Tries to determine which approach based on length of string.
   *
   * @param string $value
   *   GUID.
   *
   * @return string
   *   Encoded string.
   */
  public static function binaryConversionToString($value) {
    if (strlen($value) === 16) {
      $value = self::convertMsguidToString($value);
    }
    else {
      $value = bin2hex($value);
    }
    return $value;
  }

  /**
   * Converts an attribute by their format.
   *
   * @param string $value
   *   Value to be converted.
   * @param string $conversion
   *   Conversion type such as base64_encode, bin2hex, msguid, md5.
   *
   * @return string
   *   Converted string.
   */
  public static function convertAttribute($value, $conversion = NULL): string {

    switch ($conversion) {
      case 'base64_encode':
        $value = base64_encode($value);
        break;

      case 'bin2hex':
        $value = bin2hex($value);
        break;

      case 'msguid':
        $value = self::convertMsguidToString($value);
        break;

      case 'binary':
        $value = self::binaryConversionToString($value);
        break;

      case 'md5':
        $value = '{md5}' . base64_encode(pack('H*', md5($value)));
        break;
    }
    return $value;
  }

  /**
   * Find the tokens needed for the template.
   *
   * @param string $template
   *   In the form of [cn]@myuniversity.edu.
   *
   * @return array
   *   Array of all tokens in the template such as array('cn').
   */
  public static function findTokensNeededForTemplate($template) {
    preg_match_all('/
    \[             # [ - pattern start
    ([^\[\]]*)  # match $type not containing whitespace : [ or ]
    \]             # ] - pattern end
    /x', $template, $matches);

    return @$matches[1];

  }

}

<?php

namespace Drupal\ldap_servers\Processor;

use Drupal\Component\Utility\SafeMarkup;
use Drupal\Component\Utility\Unicode;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\Helper\MassageAttributes;
use Drupal\user\UserInterface;

/**
 * Helper to manage LDAP tokens and process their content.
 */
class TokenProcessor {

  const PREFIX = '[';
  const SUFFIX = ']';
  const DELIMITER = ':';
  const MODIFIER_DELIMITER = ';';

  private static $userPassword = NULL;

  /**
   * Store passwords temporarily.
   *
   * Store user entered password during page load and protect unencrypted user
   * password from other modules.
   *
   * @param string $action
   *   Get/set action.
   * @param string $value
   *   A user entered password.
   *
   * @return string|null
   *   Returns the password on get, otherwise nothing.
   */
  public static function passwordStorage($action, $value = NULL) {
    if ($action == 'set') {
      self::$userPassword = $value;
    }
    else {
      return self::$userPassword;
    }
  }

  /**
   * Create tokens.
   *
   * @param string $attr_name
   *   Attribute name such as 'field_user_lname', 'name', 'mail', 'dn'.
   * @param string $attr_type
   *   Attribute type such as 'field', 'property', etc. Null for LDAP
   *   attributes.
   * @param string $ordinal
   *   Ordinal number such as 0, 1, 2, etc.  Not used in general.
   *
   * @return string
   *   Token such as 'field.field_user_lname', 'samaccountname', etc.
   */
  public function createTokens($attr_name, $attr_type = NULL, $ordinal = NULL) {
    $inner_token = $attr_name;
    if ($attr_type) {
      $inner_token .= '.' . $attr_type;
    }
    if ($ordinal) {
      $inner_token .= ':' . $ordinal;
    }
    $token = self::PREFIX . $inner_token . self::SUFFIX;
    return $token;
  }

  /**
   * Parse user attribute names.
   *
   * @param string $user_attr_key
   *   A string in the form of <attr_type>.<attr_name>[:<instance>] such as
   *   field.lname, property.mail, field.aliases:2.
   *
   * @return array
   *   An array such as array('field','field_user_lname', NULL).
   */
  public function parseUserAttributeNames($user_attr_key) {
    // Make sure no [] are on attribute.
    $user_attr_key = trim($user_attr_key, self::PREFIX . self::SUFFIX);
    $parts = explode('.', $user_attr_key);
    $attr_type = $parts[0];
    $attr_name = (isset($parts[1])) ? $parts[1] : FALSE;
    $attr_ordinal = FALSE;

    if ($attr_name) {
      $attr_name_parts = explode(':', $attr_name);
      if (isset($attr_name_parts[1])) {
        $attr_name = $attr_name_parts[0];
        $attr_ordinal = $attr_name_parts[1];
      }
    }
    return [$attr_type, $attr_name, $attr_ordinal];
  }

  /**
   * Replace a token.
   *
   * @param array|UserInterface $resource
   *   The resource to act upon.
   * @param string $text
   *   The text such as "[dn]", "[cn]@my.org", "[displayName] [sn]",
   *   "Drupal Provisioned".
   * @param string $resource_type
   *   What kind of type to replace.
   *
   * @return string
   *   The text with tokens replaced or NULL if replacement not available.
   */
  public function tokenReplace($resource, $text, $resource_type = 'ldap_entry') {
    // Desired tokens are of form "cn","mail", etc.
    $desired_tokens = $this->findTokensNeededForTemplate($text);

    if (empty($desired_tokens)) {
      // If no tokens exist in text, return text itself.  It is literal value.
      return $text;
    }

    $tokens = [];
    switch ($resource_type) {
      case 'ldap_entry':
        $tokens = $this->tokenizeEntry($resource, $desired_tokens, self::PREFIX, self::SUFFIX);
        break;

      case 'user_account':
        $tokens = $this->tokenizeUserAccount($resource, $desired_tokens, self::PREFIX, self::SUFFIX);
        break;
    }

    // Add lowercase tokens to avoid case sensitivity.
    foreach ($tokens as $attribute => $value) {
      $tokens[Unicode::strtolower($attribute)] = $value;
    }

    // Array of attributes (sn, givenname, etc)
    $attributes = array_keys($tokens);
    // Array of attribute values (Lincoln, Abe, etc)
    $values = array_values($tokens);
    $result = str_replace($attributes, $values, $text);

    // Strip out any unreplace tokens.
    $result = preg_replace('/^\[.*\]$/', '', $result);
    // Return NULL if $result is empty, else $result.
    return ($result == '') ? NULL : $result;
  }

  /**
   * Extract token attributes.
   *
   * @param array $attribute_maps
   *   Array of attribute maps passed by reference. For example:
   *   [[<attr_name>, <ordinal>, <data_type>]].
   * @param string $text
   *   Text with tokens in it.
   */
  public function extractTokenAttributes(array &$attribute_maps, $text) {
    $tokens = $this->findTokensNeededForTemplate($text);
    foreach ($tokens as $token) {
      $token = str_replace([self::PREFIX, self::SUFFIX], ['', ''], $token);
      $parts = explode(self::DELIMITER, $token);
      $ordinal = (isset($parts[1]) && $parts[1]) ? $parts[1] : 0;
      $attr_name = $parts[0];
      $source_data_type = NULL;

      $parts2 = explode(self::MODIFIER_DELIMITER, $attr_name);
      if (count($parts2) > 1) {
        $attr_name = $parts2[0];
        $conversion = $parts2[1];
      }
      else {
        $conversion = NULL;
      }
      $attribute_maps[$attr_name] = self::setAttributeMap(@$attribute_maps[$attr_name], $conversion, [$ordinal => NULL]);
    }
  }

  /**
   * Get token attributes.
   *
   * @param string $text
   *   Text to parse.
   *
   * @return array
   *   Maps found.
   */
  public function getTokenAttributes($text) {
    $maps = [];
    $this->extractTokenAttributes($maps, $text);
    return $maps;
  }

  /**
   * Extract parts of token.
   *
   * @param string $token
   *   Token or token expression with singular token in it, eg. [dn],
   *   [dn;binary], [titles:0;binary] [cn]@mycompany.com.
   *
   * @return array
   *   Array triplet containing [<attr_name>, <ordinal>, <conversion>].
   */
  public function extractTokenParts($token) {
    $attributes = [];
    $this->extractTokenAttributes($attributes, $token);
    if (is_array($attributes)) {
      $keys = array_keys($attributes);
      $attr_name = $keys[0];
      $attr_data = $attributes[$attr_name];
      $ordinals = array_keys($attr_data['values']);
      $ordinal = $ordinals[0];
      return [$attr_name, $ordinal, $attr_data['conversion']];
    }
    else {
      return [NULL, NULL, NULL];
    }

  }

  /**
   * Turn an LDAP entry into a token array suitable for the t() function.
   *
   * @param array $ldap_entry
   *   The LDAP entry.
   * @param string $token_keys
   *   Either an array of key names such as array('cn', 'dn') or string 'all' to
   *   return all tokens.
   * @param string $pre
   *   Prefix token prefix such as !,%,[.
   * @param string $post
   *   Suffix token suffix such as ].
   *
   * @return array
   *   Token array suitable for t() functions of with lowercase keys as
   *   exemplified below. The LDAP entry should be in form of single entry
   *   returned from ldap_search() function. For example:
   *   'dn' => 'cn=jdoe,ou=campus accounts,dc=ad,dc=myuniversity,dc=edu',
   *   'mail' => array( 0 => 'jdoe@myuniversity.edu', 'count' => 1),
   *   'sAMAccountName' => array( 0 => 'jdoe', 'count' => 1),
   *
   *   Should return tokens such as:
   *   From dn attribute:
   *     [cn] = jdoe
   *     [cn:0] = jdoe
   *     [cn:last] => jdoe
   *     [ou] = campus accounts
   *     [ou:0] = campus accounts
   *     [ou:last] = toledo campus
   *     [dc] = ad
   *     [dc:0] = ad
   *     [dc:1] = myuniversity
   *     [dc:2] = edu
   *     [dc:last] = edu
   *   From other attributes:
   *     [mail] = jdoe@myuniversity.edu
   *     [mail:0] = jdoe@myuniversity.edu
   *     [mail:last] = jdoe@myuniversity.edu
   *     [samaccountname] = jdoe
   *     [samaccountname:0] = jdoe
   *     [samaccountname:last] = jdoe
   *     [guid:0;base64_encode] = apply base64_encode() function to value
   *     [guid:0;bin2hex] = apply bin2hex() function to value
   *     [guid:0;msguid] = apply convertMsguidToString() function to value
   */
  public function tokenizeEntry(array $ldap_entry, $token_keys = 'all', $pre = self::PREFIX, $post = self::SUFFIX) {

    $detailed_watchdog_log = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
    $tokens = [];
    $log_variables = [];
    $massager = new MassageAttributes();

    if (function_exists('debug_backtrace') && $backtrace = debug_backtrace()) {
      $log_variables['%calling_function'] = $backtrace[1]['function'];
    }
    if (!is_array($ldap_entry)) {
      if ($detailed_watchdog_log) {
        \Drupal::logger('ldap_servers')->debug('Skipped tokenization of LDAP entry because no LDAP entry provided when called from %calling_function.', $log_variables);
      }
      // Empty array.
      return $tokens;
    }

    // Add lowercase keyed entries to LDAP array.
    foreach ($ldap_entry as $key => $values) {
      $ldap_entry[Unicode::strtolower($key)] = $values;
    }

    // 1. tokenize dn
    // escapes attribute values, need to be unescaped later.
    $factory = \Drupal::service('ldap.servers');
    $dn_parts = $factory->ldapExplodeDn($ldap_entry['dn'], 0);
    unset($dn_parts['count']);
    $parts_count = [];
    $parts_last_value = [];
    foreach ($dn_parts as $pair) {
      list($attr_name, $attr_value) = explode('=', $pair);
      $attr_value = ConversionHelper::unescapeDnValue($attr_value);
      try {
        $attr_value = SafeMarkup::checkPlain($attr_value);
      }
      catch (\Exception $e) {
        if ($detailed_watchdog_log) {
          $log_variables['%attr_name'] = $attr_name;
          \Drupal::logger('ldap_servers')->debug('Skipped tokenization of attribute %attr_name because the value would not pass check_plain function.', $log_variables);
        }
        // don't tokenize data that can't pass check_plain.
        continue;
      }

      if (!isset($parts_count[$attr_name])) {
        $tokens[$pre . $massager->processAttributeName($attr_name) . $post] = $attr_value;
        $tokens[$pre . $massager->processAttributeName($attr_name) . $post] = $attr_value;
        $parts_count[$attr_name] = 0;
      }
      $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . (int) $parts_count[$attr_name] . $post] = $attr_value;

      $parts_last_value[$attr_name] = $attr_value;
      $parts_count[$attr_name]++;
    }

    foreach ($parts_count as $attr_name => $count) {
      $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . 'last' . $post] = $parts_last_value[$attr_name];
    }

    // Tokenize other attributes.
    if ($token_keys == 'all') {
      $token_keys = array_keys($ldap_entry);
      $token_keys = array_filter($token_keys, "is_string");
      foreach ($token_keys as $attr_name) {
        $attr_value = $ldap_entry[$attr_name];
        if (is_array($attr_value) && is_scalar($attr_value[0]) && $attr_value['count'] == 1) {
          $tokens[$pre . $massager->processAttributeName($attr_name) . $post] = SafeMarkup::checkPlain($attr_value[0]);
          $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . '0' . $post] = SafeMarkup::checkPlain($attr_value[0]);
          $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . 'last' . $post] = SafeMarkup::checkPlain($attr_value[0]);
        }
        elseif (is_array($attr_value) && $attr_value['count'] > 1) {
          $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . 'last' . $post] = SafeMarkup::checkPlain($attr_value[$attr_value['count'] - 1]);
          for ($i = 0; $i < $attr_value['count']; $i++) {
            $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . $i . $post] = SafeMarkup::checkPlain($attr_value[$i]);
          }
        }
        elseif (is_scalar($attr_value)) {
          $tokens[$pre . $massager->processAttributeName($attr_name) . $post] = SafeMarkup::checkPlain($attr_value);
          $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . '0' . $post] = SafeMarkup::checkPlain($attr_value);
          $tokens[$pre . $massager->processAttributeName($attr_name) . self::DELIMITER . 'last' . $post] = SafeMarkup::checkPlain($attr_value);
        }
      }
    }
    else {
      foreach ($token_keys as $full_token_key) {
        // A token key is for example 'dn', 'mail:0', 'mail:last', or
        // 'guid:0;tobase64'.
        $value = NULL;

        $conversion = FALSE;
        $parts = explode(';', $full_token_key);
        if (count($parts) == 2) {
          $conversion = $parts[1];
          $token_key = $parts[0];
        }
        else {
          $token_key = $full_token_key;
        }

        $parts = explode(self::DELIMITER, $token_key);
        $attr_name = Unicode::strtolower($parts[0]);
        $ordinal_key = isset($parts[1]) ? $parts[1] : 0;
        $i = NULL;

        // don't use empty() since a 0, "", etc value may be a desired value.
        if ($attr_name == 'dn' || !isset($ldap_entry[$attr_name])) {
          continue;
        }
        else {
          $count = $ldap_entry[$attr_name]['count'];
          if ($ordinal_key === 'last') {
            $i = ($count > 0) ? $count - 1 : 0;
            $value = $ldap_entry[$attr_name][$i];
          }
          elseif (is_numeric($ordinal_key) || $ordinal_key == '0') {
            $value = $ldap_entry[$attr_name][$ordinal_key];
          }
          else {
            // don't add token if case not covered.
            continue;
          }
        }

        if ($conversion) {
          switch ($conversion) {

            case 'base64_encode':
              $value = base64_encode($value);
              break;

            case 'bin2hex':
              $value = bin2hex($value);
              break;

            case 'msguid':
              $value = $this->convertMsguidToString($value);
              break;

            case 'binary':
              $value = $this->binaryConversionToString($value);
              break;
          }
        }

        $tokens[$pre . $full_token_key . $post] = SafeMarkup::checkPlain($value);
        if ($full_token_key != Unicode::strtolower($full_token_key)) {
          $tokens[$pre . Unicode::strtolower($full_token_key) . $post] = SafeMarkup::checkPlain($value);
        }
      }
    }

    // Include the dn.  it will not be handled correctly by previous loops.
    $tokens[$pre . 'dn' . $post] = SafeMarkup::checkPlain($ldap_entry['dn']);
    return $tokens;
  }

  /**
   * Tokenize a user account.
   *
   * @param \Drupal\user\UserInterface $account
   *   The Drupal user account.
   * @param array $token_keys
   *   Keys for tokens:
   *     'all' signifies return
   *     all token/value pairs available; otherwise array lists
   *     token keys (e.g. property.name ...NOT [property.name])
   * @param string $pre
   *   Prefix of token.
   * @param string $post
   *   Suffix of token.
   *
   * @return array
   *   Should return token/value pairs in array such as 'status' => 1,
   *   'uid' => 17.
   */
  public function tokenizeUserAccount(UserInterface $account, array $token_keys = [], $pre = self::PREFIX, $post = self::SUFFIX) {

    if (empty($token_keys)) {
      $token_keys = $this->discoverUserAttributes($account);
    }

    $tokens = [];

    foreach ($token_keys as $token_key) {
      $parts = explode('.', $token_key);
      $attr_type = $parts[0];
      $attr_name = $parts[1];
      $attr_conversion = (isset($parts[2])) ? $parts[1] : 'none';
      $value = FALSE;
      $skip = FALSE;

      switch ($attr_type) {
        case 'field':
        case 'property':
          $value = @is_scalar($account->get($attr_name)->value) ? $account->get($attr_name)->value : '';
          break;

        case 'password':

          switch ($attr_name) {

            case 'user':
            case 'user-only':
              $pwd = self::passwordStorage('get');
              $value = ($pwd) ? $pwd : NULL;
              break;

            case 'user-random':
              $pwd = self::passwordStorage('get');
              $value = ($pwd) ? $pwd : user_password();
              break;

            case 'random':
              $value = user_password();
              break;

          }
          if (empty($value)) {
            $skip = TRUE;
          }
          break;
      }

      if (!$skip) {

        switch ($attr_conversion) {

          case 'none':
            break;

          case 'to-md5':
            $value = md5($value);
            break;

          case 'to-lowercase':
            $value = Unicode::strtolower($value);
            break;
        }

        $tokens[$pre . $token_key . $post] = SafeMarkup::checkPlain($value)->__toString();
        if ($token_key != Unicode::strtolower($token_key)) {
          $tokens[$pre . Unicode::strtolower($token_key) . $post] = SafeMarkup::checkPlain($value)->__toString();
        }
      }
    }
    return $tokens;
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
  public function findTokensNeededForTemplate($template) {
    preg_match_all('/
    \[             # [ - pattern start
    ([^\[\]]*)  # match $type not containing whitespace : [ or ]
    \]             # ] - pattern end
    /x', $template, $matches);

    return @$matches[1];

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
    if (strlen($value) == 16) {
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
  public static function convertAttribute($value, $conversion = NULL) {

    if ($conversion) {
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
    }
    return $value;
  }

  /**
   * Set an attribute map.
   *
   * @param array $attribute
   *   For a given attribute in the form ['values' => [], 'data_type' => NULL]
   *   as outlined in ldap_user/README.developers.txt.
   * @param string $conversion
   *   As type of conversion to do @see ldap_servers_convert_attribute(),
   *   e.g. base64_encode, bin2hex, msguid, md5.
   * @param array $values
   *   In form [<ordinal> => <value> | NULL], where NULL indicates value is
   *   needed for provisioning or other operations.
   *
   * @return array
   *   Converted values. If nothing is passed in, create empty array in the
   *   proper structure ['values' => [0 => 'john', 1 => 'johnny']].
   */
  public static function setAttributeMap(array $attribute = NULL, $conversion = NULL, array $values = NULL) {

    $attribute = (is_array($attribute)) ? $attribute : [];
    $attribute['conversion'] = $conversion;
    if (!$values && (!isset($attribute['values']) || !is_array($attribute['values']))) {
      $attribute['values'] = [0 => NULL];
    }
    // Merge into array overwriting ordinals.
    elseif (is_array($values)) {
      foreach ($values as $ordinal => $value) {
        if ($conversion) {
          $value = self::convertAttribute($value, $conversion);
        }
        $attribute['values'][(int) $ordinal] = $value;
      }
    }
    return $attribute;
  }

  /**
   * Discover user attributes from user.
   *
   * @param \Drupal\user\UserInterface $account
   *   User account.
   *
   * @return array
   *   User attributes.
   */
  private function discoverUserAttributes(UserInterface $account) {
    $token_keys = [];
    // Add lowercase keyed entries to LDAP array.
    $userData = $account->toArray();
    foreach ($userData as $propertyName => $propertyData) {
      if (isset($propertyData[0], $propertyData[0]['value']) && is_scalar($propertyData[0]['value'])) {
        if (substr($propertyName, 0, strlen('field')) === 'field') {
          $token_keys[] = 'field.' . Unicode::strtolower($propertyName);
        }
        else {
          $token_keys[] = 'property.' . Unicode::strtolower($propertyName);
        }
      }
    }
    $token_keys[] = 'password.random';
    $token_keys[] = 'password.user-random';
    $token_keys[] = 'password.user-only';
    return $token_keys;
  }

}

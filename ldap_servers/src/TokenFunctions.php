<?php

namespace Drupal\ldap_servers;

use Drupal\Component\Utility\SafeMarkup;
use Drupal\Component\Utility\Unicode;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_user\LdapUserConf;

/**
 *
 */
trait TokenFunctions {

  public static $token_pre = '[';
  public static $token_post = ']';
  public static $token_del = ':';
  public static $token_modifier_del = ';';

  /**
   * @param string $attr_name
   *   such 'field_user_lname', 'name', 'mail', 'dn'.
   * @param string $attr_type
   *   such as 'field', 'property', etc.  NULL for ldap attributes.
   * @param string $attr_ordinal
   *   0, 1, 2, etc.  not used in general.
   *
   * @return string such as 'field.field_user_lname', 'samaccountname', etc.
   */
  public function createTokens($attr_name, $attr_type = NULL, $ordinal = NULL) {
    $inner_token = $attr_name;
    if ($attr_type) {
      $inner_token .= '.' . $attr_type;
    }
    if ($ordinal) {
      $inner_token .= ':' . $ordinal;
    }
    $token = self::$token_pre . $inner_token . self::$token_post;
    return $token;
  }

  /**
   * @param $user_attr_key of form <attr_type>.<attr_name>[:<instance>]
   *   such as field.lname, property.mail, field.aliases:2
   *
   * @return array array($attr_type, $attr_name, $attr_ordinal) such as array('field','field_user_lname', NULL)
   */
  public function parseUserAttributeNames($user_attr_key) {
    // Make sure no [] are on attribute.
    $user_attr_key = trim($user_attr_key, self::$token_pre . self::$token_post);
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
    return array($attr_type, $attr_name, $attr_ordinal);
  }

  /**
   * @param array $ldap_entry
   * @param string $text
   *   such as "[dn]", "[cn]@my.org", "[displayName] [sn]", "Drupal Provisioned".
   * @return string $text with tokens replaced or NULL if replacement not available
   */
  public function tokenReplace($resource, $text, $resource_type = 'ldap_entry') {
    // user_account.
    // Desired tokens are of form "cn","mail", etc.
    $desired_tokens = $this->ldap_servers_token_tokens_needed_for_template($text);

    if (empty($desired_tokens)) {
      // If no tokens exist in text, return text itself.  It is literal value.
      return $text;
    }

    switch ($resource_type) {
      case 'ldap_entry':
        $tokens = $this->tokenizeEntry($resource, $desired_tokens, self::$token_pre, self::$token_post);
        break;

      case 'user_account':
        $tokens = $this->tokenizeUserAccount($resource, $desired_tokens, self::$token_pre, self::$token_post);
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
   * @param array $attributes
   *   array of attributes passed by reference.
   * @param string $text
   *   with tokens in it
   *
   *   by reference return add ldap attribute triplet $attribute_maps[<attr_name>] = (<attr_name>, <ordinal>, <data_type>) to $attributes.
   */
  public function extractTokenAttributes(&$attribute_maps, $text) {
    $tokens = $this->ldap_servers_token_tokens_needed_for_template($text);
    foreach ($tokens as $token) {
      $token = str_replace(array(self::$token_pre, self::$token_post), array('', ''), $token);
      $parts = explode(self::$token_del, $token);
      $ordinal = (isset($parts[1]) && $parts[1]) ? $parts[1] : 0;
      $attr_name = $parts[0];
      $source_data_type = NULL;

      $parts2 = explode(self::$token_modifier_del, $attr_name);
      if (count($parts2) > 1) {
        $attr_name = $parts2[0];
        $conversion = $parts2[1];
      }
      else {
        $conversion = NULL;
      }
      $attribute_maps[$attr_name] = ldap_servers_set_attribute_map(@$attribute_maps[$attr_name], $conversion, array($ordinal => NULL));
    }
  }

  /**
   * @param string $token
   *   or token expression with singular token in it, eg. [dn], [dn;binary], [titles:0;binary] [cn]@mycompany.com.
   *
   *
   *
   * @return array(<attr_name>, <ordinal>, <conversion>)
   */
  public function extractTokenParts($token) {
    $attributes = array();
    $this->extractTokenAttributes($attributes, $token);
    if (is_array($attributes)) {
      $keys = array_keys($attributes);
      $attr_name = $keys[0];
      $attr_data = $attributes[$attr_name];
      $ordinals = array_keys($attr_data['values']);
      $ordinal = $ordinals[0];
      return array($attr_name, $ordinal, $attr_data['conversion']);
    }
    else {
      return array(NULL, NULL, NULL);
    }

  }

  /**
   * Turn an ldap entry into a token array suitable for the t() function.
   *
   * @param array $ldap_entry
   * @param string $token_keys
   *   Either an array of key names such as array('cn', 'dn') or string 'all' to return all tokens.
   * @param string $pre
   *   Prefix token prefix such as !,%,[.
   * @param string $post
   *   Suffix token suffix such as ].
   *
   * @return array
   *   Token array suitable for t() functions of with lowercase keys as exemplified below
   *
   *   $ldap_entry should be in form of single entry returned from ldap_search() function:
   *
   *   'dn' => 'cn=jdoe,ou=campus accounts,ou=toledo campus,dc=ad,dc=myuniversity,dc=edu',
   *   'mail' => array( 0 => 'jdoe@myuniversity.edu', 'count' => 1),
   *   'sAMAccountName' => array( 0 => 'jdoe', 'count' => 1),
   *
   *   Should return tokens such as:
   *
   *   From dn attribute:
   *     [cn] = jdoe
   *     [cn:0] = jdoe
   *     [cn:last] => jdoe
   *     [ou] = campus accounts
   *     [ou:0] = campus accounts
   *     [ou:1] = toledo campus
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
   *     [guid:0;msguid] = apply ldap_servers_msguid() function to value
   */
  public function tokenizeEntry($ldap_entry, $token_keys = 'all', $pre = NULL, $post = NULL) {
    if ($pre == NULL) {
      $pre = self::$token_pre;
    }
    if ($post == NULL) {
      $pre = self::$token_post;
    }

    $detailed_watchdog_log = \Drupal::config('ldap_help.settings')->get('watchdog_detail');
    $tokens = array();
    $log_variables = array();
    $massager = new MassageFunctions();

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

    // Add lowercase keyed entries to ldap array.
    foreach ($ldap_entry as $key => $values) {
      $ldap_entry[Unicode::strtolower($key)] = $values;
    }

    // 1. tokenize dn
    // escapes attribute values, need to be unescaped later.
    $dn_parts = ldap_explode_dn($ldap_entry['dn'], 0);
    unset($dn_parts['count']);
    $parts_count = array();
    $parts_last_value = array();
    foreach ($dn_parts as $pair) {
      list($attr_name, $attr_value) = explode('=', $pair);
      $helper = new ConversionHelper();
      $attr_value = $helper->unescape_dn_value($attr_value);
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
        $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . $post] = $attr_value;
        $parts_count[$attr_name] = 0;
      }
      $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . (int) $parts_count[$attr_name] . $post] = $attr_value;

      $parts_last_value[$attr_name] = $attr_value;
      $parts_count[$attr_name]++;
    }

    foreach ($parts_count as $attr_name => $count) {
      $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . 'last' . $post] = $parts_last_value[$attr_name];
    }

    // Tokenize other attributes.
    if ($token_keys == 'all') {
      $token_keys = array_keys($ldap_entry);
      $token_keys = array_filter($token_keys, "is_string");
      foreach ($token_keys as $attr_name) {
        $attr_value = $ldap_entry[$attr_name];
        if (is_array($attr_value) && is_scalar($attr_value[0]) && $attr_value['count'] == 1) {
          $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . $post] = SafeMarkup::checkPlain($attr_value[0]);
          $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . '0' . $post] = SafeMarkup::checkPlain($attr_value[0]);
          $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . 'last' . $post] = SafeMarkup::checkPlain($attr_value[0]);
        }
        elseif (is_array($attr_value) && $attr_value['count'] > 1) {
          $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . 'last' . $post] = SafeMarkup::checkPlain($attr_value[$attr_value['count'] - 1]);
          for ($i = 0; $i < $attr_value['count']; $i++) {
            $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . $i . $post] = SafeMarkup::checkPlain($attr_value[$i]);
          }
        }
        elseif (is_scalar($attr_value)) {
          $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . $post] = SafeMarkup::checkPlain($attr_value);
          $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . '0' . $post] = SafeMarkup::checkPlain($attr_value);
          $tokens[$pre . $massager->massage_text($attr_name, 'attr_name', $massager::$token_replace) . self::$token_del . 'last' . $post] = SafeMarkup::checkPlain($attr_value);
        }
      }
    }
    else {
      foreach ($token_keys as $full_token_key) {
        // $token_key = 'dn', 'mail', 'mail:0', 'mail:last', 'dept:1', 'guid:0;tobase64etc.
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

        $parts = explode(self::$token_del, $token_key);
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
              $value = ldap_servers_msguid($value);
              break;

            case 'binary':
              $value = ldap_servers_binary($value);
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
   *
   * @param User $user_account
   * @param array|string $token_keys
   *   'all' signifies return
   *   all token/value pairs available; otherwise array lists
   *   token keys (e.g. property.name ...NOT [property.name]).
   * @param string $pre
   *   Prefix of token.
   * @param string $post
   *   Suffix of token.
   *
   * @return array
   *   Should return token/value pairs in array such as 'status' => 1,
   *   'uid' => 17.
   */
  public function tokenizeUserAccount($user_account, $token_keys = 'all', $pre = NULL, $post = NULL) {
    if ($pre == NULL) {
      $pre = self::$token_pre;
    }
    if ($post == NULL) {
      $pre = self::$token_post;
    }

    $tokens = array();

    $user_entered_password_available = (boolean) ldap_user_ldap_provision_pwd('get');
    // ldapUserPwd((property_exists($user_account, 'ldapUserPwd') && $user_account->ldapUserPwd));.
    if ($token_keys == 'all') {
      // Add lowercase keyed entries to ldap array.
      foreach ((array) $user_account as $property_name => $value) {
        if (is_scalar($value) && $property_name != 'password') {
          $token_keys[] = 'property.' . $property_name;
          if (Unicode::strtolower($property_name) != $property_name) {
            $token_keys[] = 'property.' . Unicode::strtolower($property_name);
          }
        }
        // @FIXME: Legacy syntax
        elseif (isset($user_account->{$attr_name}['und'][0]['value']) && is_scalar($user_account->{$attr_name}['und'][0]['value'])) {
          $token_keys[] = 'field.' . $property_name;
          if (Unicode::strtolower($property_name) != $property_name) {
            $token_keys[] = 'field.' . Unicode::strtolower($property_name);
          }
        }
        else {
          // Field or property with no value, so no token can be generated.
        }
      }
      $ldap_user_conf = new LdapUserConf();
      if ($ldap_user_conf->setsLdapPassword) {
        $token_keys[] = 'password.random';
        $token_keys[] = 'password.user-random';
      }
    }

    foreach ($token_keys as $token_key) {
      $parts = explode('.', $token_key);
      $attr_type = $parts[0];
      $attr_name = $parts[1];
      $attr_conversion = (isset($parts[2])) ? $parts[1] : 'none';
      $value = FALSE;
      $skip = FALSE;

      switch ($attr_type) {
        case 'field':
          $value = @is_scalar($user_account->get($attr_name)->value) ? $user_account->get($attr_name)->value : '';
          break;

        case 'property':
          $value = @is_scalar($user_account->get($attr_name)->value) ? $user_account->get($attr_name)->value : '';
          break;

        case 'password':

          switch ($attr_name) {

            case 'user':
              $pwd = ldap_user_ldap_provision_pwd('get');
              break;

            case 'user-random':
              $pwd = ldap_user_ldap_provision_pwd('get');
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

        $tokens[$pre . $token_key . $post] = SafeMarkup::checkPlain($value);
        if ($token_key != Unicode::strtolower($token_key)) {
          $tokens[$pre . Unicode::strtolower($token_key) . $post] = SafeMarkup::checkPlain($value);
        }
      }
    }
    return $tokens;
  }

  /**
   * @param string $template
   *   in form [cn]@myuniversity.edu.
   * @return array of all tokens in the template such as array('cn')
   */
  public function ldap_servers_token_tokens_needed_for_template($template) {
    preg_match_all('/
    \[             # [ - pattern start
    ([^\[\]]*)  # match $type not containing whitespace : [ or ]
    \]             # ] - pattern end
    /x', $template, $matches);

    return @$matches[1];

  }

  /**
   *
   */
  public function showSampleUserTokens($sid) {

    $factory = new ServerFactory($sid, 'all', TRUE);
    /* @var Server $ldap_server */
    $ldap_server = $factory->servers;
    // @FIXME undefined function
    $test_username = $ldap_server->testingDrupalUsername;
    if (!$test_username || !(
        $ldap_server->get('bind_method') == Server::$bindMethodServiceAccount ||
        $ldap_server->get('bind_method') == Server::$bindMethodAnon
      )
    ) {
      return FALSE;
    }

    if ($ldap_user = $ldap_server->userUserNameToExistingLdapEntry($test_username)) {
      // @FIXME
      // $table = theme('ldap_server_ldap_entry_table', array(
      $table = _theme('ldap_server_ldap_entry_table', array(
        'entry' => $ldap_user['attr'],
        'username' => $test_username,
        'dn' => $ldap_user['dn'],
      ));
    }
    else {
      $table = '<p>' . t('No sample user data found') . '</p>';
    }

    return $table;
  }

}

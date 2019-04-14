<?php

namespace Drupal\ldap_servers\Processor;

use Drupal\Component\Utility\Unicode;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapTransformationTraits;
use Drupal\ldap_servers\Logger\LdapDetailLog;
use Symfony\Component\Ldap\Entry;

/**
 * Helper to manage LDAP tokens and process their content.
 */
class TokenProcessor {

  use LdapTransformationTraits;

  protected $detailLog;

  protected $entityTypeManager;

  /**
   * {@inheritdoc}
   */
  public function __construct(LdapDetailLog $ldap_detail_log, EntityTypeManagerInterface $entity_type_manager) {
    $this->detailLog = $ldap_detail_log;
    $this->entityTypeManager = $entity_type_manager;
  }

  /**
   * Replace a single token.
   *
   * @param \Symfony\Component\Ldap\Entry $resource
   *   The resource to act upon.
   * @param string $text
   *   The text such as "[dn]", "[cn]@my.org", "[displayName] [sn]",
   *   "Drupal Provisioned".
   *
   * @return string|null
   */
  public function ldapEntryReplacementsForDrupalAccount(Entry $resource, string $text) {
    // Desired tokens are of form "cn","mail", etc.
    $desired_tokens = ConversionHelper::findTokensNeededForTemplate($text);

    if (empty($desired_tokens)) {
      // If no tokens exist in text, return text itself.
      return $text;
    }

    $tokens = $this->tokenizeLdapEntry($resource, $desired_tokens);

    foreach ($tokens as $attribute => $value) {
      $tokens[mb_strtolower($attribute)] = $value;
    }

    // TODO: This string comparison is likely not ideal.
    // The sub-functions redundantly lowercase replacements in addition to the
    // source formatting. Otherwise comparison would fail here in
    // case-insensitive requests. Ideally, a reimplementation would resolve this
    // redundant and inconsistent approach with a clearer API.
    $attributes = array_keys($tokens);
    $values = array_values($tokens);
    $result = str_replace($attributes, $values, $text);

    // Strip out any un-replaced tokens.
    $result = preg_replace('/^\[.*\]$/', '', $result);

    if ($result == '') {
      $result = NULL;
    }
    return $result;
  }

  /**
   * Turn an LDAP entry into a token array suitable for the t() function.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   The LDAP entry.
   * @param array $token_keys
   *   Either an array of key names such as ['cn', 'dn'] or an empty
   *   array for all items.
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
   *     [cn:reverse:0] = jdoe
   *     [ou] = campus accounts
   *     [ou:0] = campus accounts
   *     [ou:last] = toledo campus
   *     [ou:reverse:0] = toledo campus
   *     [ou:reverse:1] = campus accounts
   *     [dc] = ad
   *     [dc:0] = ad
   *     [dc:1] = myuniversity
   *     [dc:2] = edu
   *     [dc:last] = edu
   *     [dc:reverse:0] = edu
   *     [dc:reverse:1] = myuniversity
   *     [dc:reverse:2] = ad
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
  public function tokenizeLdapEntry(Entry $ldap_entry, array $token_keys) {
    if (empty($ldap_entry->getAttributes())) {
      $this->detailLog->log(
        'Skipped tokenization of LDAP entry because no LDAP entry provided when called from %calling_function.', [
          '%calling_function' => function_exists('debug_backtrace') ? debug_backtrace()[1]['function'] : 'undefined',
        ]
      );
      return [];
    }
    $tokens = $this->compileLdapTokenEntries($ldap_entry, $token_keys);

    // Include the dn.  it will not be handled correctly by previous loops.
    $tokens['[dn]'] = $ldap_entry->getDn();
    return $tokens;
  }

  /**
   * Compile LDAP token entries.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   LDAP entry.
   * @param array $token_keys
   *   Token keys.
   *
   * @return array
   *   Tokens.
   */
  private function compileLdapTokenEntries(Entry $ldap_entry, array $token_keys) {
    $tokens = [];
    $tokens = array_merge($tokens, $this->processDnParts($ldap_entry->getDn()));

    if (empty($token_keys)) {
      // TODO: Check if this really only ever called during the test form.
      // Get all attributes.
      $token_keys = array_keys($ldap_entry->getAttributes());
      $token_keys = array_filter($token_keys, "is_string");
      foreach ($token_keys as $attribute_name) {
        $value = $this->processLdapEntryAttribute($attribute_name, $ldap_entry->getAttribute($attribute_name));
        $tokens = array_merge($tokens, $value);
      }
    }
    else {
      foreach ($token_keys as $attribute_name) {
        $value = $this->processLdapTokenKey($attribute_name, $ldap_entry);
        $tokens = array_merge($tokens, $value);
      }
    }
    return $tokens;
  }

  /**
   * Deconstruct DN parts.
   *
   * @param string $dn
   *   DN.
   *
   * @return array
   *   Tokens.
   */
  private function processDnParts($dn) {
    $tokens = [];
    // 1. Tokenize dn
    // Escapes attribute values, need to be unescaped later.
    $dn_parts = $this->ldapExplodeDn($dn, 0);
    unset($dn_parts['count']);
    $parts_count = [];
    $parts_last_value = [];
    foreach ($dn_parts as $pair) {
      list($name, $value) = explode('=', $pair);
      $value = ConversionHelper::unescapeDnValue($value);
      if (!Unicode::validateUtf8($value)) {
        $this->detailLog->log('Skipped tokenization of attribute %attr_name because the value is not valid UTF-8 string.', [
          '%attr_name' => $name,
        ]);
        continue;
      }
      if (!isset($parts_count[$name])) {
        // First and general entry.
        $tokens[sprintf('[%s]', mb_strtolower($name))] = $value;
        $parts_count[$name] = 0;
      }
      $tokens[sprintf('[%s:%s]', mb_strtolower($name), (int) $parts_count[$name])] = $value;

      $parts_last_value[$name] = $value;
      $parts_count[$name]++;
    }

    // Add DN parts in reverse order to reflect the hierarchy for CN, OU, DC.
    foreach ($parts_count as $name => $count) {
      $part = mb_strtolower($name);
      for ($i = 0; $i < $count; $i++) {
        $reverse_position = $count - $i - 1;
        $tokens[sprintf('[%s:reverse:%s]',  $part, $reverse_position)] = $tokens[sprintf('[%s:%s]', $part, $i)];
      }
    }

    foreach ($parts_count as $name => $count) {
      $tokens[sprintf('[%s:last]', mb_strtolower($name))] = $parts_last_value[$name];
    }
    return $tokens;
  }

  /**
   * Process a single ldap_entry token.
   *
   * @param string $name
   *   Name.
   * @param array|NULL $value
   *   Value.
   *
   * @return array
   *   Tokens.
   */
  private function processLdapEntryAttribute($name, $value) {
    $tokens = [];
    $key = mb_strtolower($name);

    if ($value !== NULL) {
      if (is_array($value)) {
        if (count($value) == 1) {
          // Only one entry, example output: ['cn', 'cn:0', 'cn:last'].
          $tokens[sprintf('[%s]', $key)] = $value[0];
          $tokens[sprintf('[%s:0]', $key)] = $value[0];
          $tokens[sprintf('[%s:last]', $key)] = $value[0];
        }
        elseif (count($value) > 1) {
          // Multiple entries, example: ['cn:last', 'cn:0', 'cn:1'].
          $tokens[sprintf('[%s:last]', $key)] = $value[count($value) - 1];
          for ($i = 0; $i < count($value); $i++) {
            $tokens[sprintf('[%s:%s]', $key, $i)] = $value[$i];
          }
        }
      }
      elseif (is_scalar($value)) {
        // Only one entry (as string), example output: ['cn', 'cn:0', 'cn:last'].
        $tokens[sprintf('[%s]', $key)] = $value;
        $tokens[sprintf('[%s:0]', $key)] = $value;
        $tokens[sprintf('[%s:last]', $key)] = $value;
      }
    }

    return $tokens;
  }

  /**
   * Process a single LDAP Token key.
   *
   * @param string $key
   *   Full token with prefix and suffix.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   Entry.
   *
   * @return array
   *   Tokens.
   */
  private function processLdapTokenKey($key, Entry $entry) {
    $tokens = [];
    // A token key is for example 'dn', 'mail:0', 'mail:last', or
    // 'guid:0;tobase64'. Trailing period to allow for empty value.
    list($token_key, $conversion) = explode(';', $key . ';');

    $parts = explode(':', $token_key);
    $name = mb_strtolower($parts[0]);
    $ordinal_key = isset($parts[1]) ? $parts[1] : 0;
    $i = NULL;

    $value = $entry->getAttribute($name);

    // Don't use empty() since a 0, "", etc value may be a desired value.
    if ($name == 'dn' || $value === NULL) {
      return [];
    }
    else {
      $count = count($value);
      if ($ordinal_key === 'last') {
        $i = ($count > 0) ? $count - 1 : 0;
        $value = $value[$i];
      }
      elseif (is_numeric($ordinal_key) || $ordinal_key == '0') {
        $value = $value[$ordinal_key];
      }
      else {
        // don't add token if case not covered.
        return [];
      }
    }

    $value = ConversionHelper::convertAttribute($value, $conversion);

    $tokens[sprintf('[%s]', $key)] = $value;
    // We are redundantly setting the lowercase value here for consistency with
    // parent function.
    if ($key != mb_strtolower($key)) {
      $tokens[sprintf('[%s]', mb_strtolower($key))] = $value;
    }
    return $tokens;
  }

}

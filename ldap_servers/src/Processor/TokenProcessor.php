<?php

declare(strict_types=1);

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

  /**
   * Detail log.
   *
   * @var \Drupal\ldap_servers\Logger\LdapDetailLog
   */
  protected $detailLog;

  /**
   * Available tokens.
   *
   * Token array suitable for t() functions of with lowercase keys as
   * exemplified below.
   * From dn attribute:
   *   [cn] = jdoe
   *   [cn:0] = jdoe
   *   [cn:last] => jdoe
   *   [cn:reverse:0] = jdoe
   *   [ou] = campus accounts
   *   [ou:0] = campus accounts
   *   [ou:last] = toledo campus
   *   [ou:reverse:0] = toledo campus
   *   [ou:reverse:1] = campus accounts
   *   [dc] = ad
   *   [dc:0] = ad
   *   [dc:1] = myuniversity
   *   [dc:2] = edu
   *   [dc:last] = edu
   *   [dc:reverse:0] = edu
   *   [dc:reverse:1] = myuniversity
   *   [dc:reverse:2] = ad
   * From other attributes:
   *   [mail] = jdoe@myuniversity.edu
   *   [mail:0] = jdoe@myuniversity.edu
   *   [mail:last] = jdoe@myuniversity.edu
   *   [samaccountname] = jdoe
   *   [samaccountname:0] = jdoe
   *   [samaccountname:last] = jdoe
   *   [guid:0;base64_encode] = apply base64_encode() function to value
   *   [guid:0;bin2hex] = apply bin2hex() function to value
   *   [guid:0;msguid] = apply convertMsguidToString() function to value.
   *
   * @var array
   */
  public $tokens = [];

  /**
   * Requested tokens.
   *
   * @var array
   */
  private $requestedTokens = [];

  /**
   * {@inheritdoc}
   */
  public function __construct(LdapDetailLog $ldap_detail_log) {
    $this->detailLog = $ldap_detail_log;
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
   *   Relaced string.
   *
   * @see \Drupal\ldap_user\EventSubscriber\LdapEntryProvisionSubscriber::fetchDrupalAttributeValue()
   */
  public function ldapEntryReplacementsForDrupalAccount(Entry $resource, string $text): string {
    preg_match_all('/\[([^\[\]]*)\]/x', $text, $matches);
    if (!isset($matches[1]) || empty($matches[1])) {
      // If no tokens exist in text, return text itself.
      return $text;
    }

    $this->tokenizeLdapEntry($resource, $matches[1]);

    foreach ($matches[0] as $target) {
      /** @var string $lowercase_target */
      $lowercase_target = mb_strtolower($target);
      if (isset($this->tokens[$lowercase_target])) {
        $text = str_replace($target, $this->tokens[$lowercase_target], $text);
      }
    }

    // Strip out any un-replaced tokens.
    $text = preg_replace('/\[.*\]/', '', $text);

    return $text;
  }

  /**
   * Turn an LDAP entry into a token array suitable for the t() function.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   The LDAP entry.
   */
  public function tokenizeLdapEntry(Entry $ldap_entry, array $required_tokens): void {
    if (empty($ldap_entry->getAttributes())) {
      $this->detailLog->log(
        'Skipped tokenization of LDAP entry because no LDAP entry provided when called from %calling_function.', [
          '%calling_function' => function_exists('debug_backtrace') ? debug_backtrace()[1]['function'] : 'undefined',
        ]
      );
      return;
    }

    $this->processDnParts($ldap_entry->getDn());
    $this->tokens['[dn]'] = $ldap_entry->getDn();

    foreach ($required_tokens as $required_token) {
      $this->processLdapTokenKey($ldap_entry, $required_token);
    }
  }

  /**
   * Deconstruct DN parts.
   *
   * @param string $dn
   *   DN.
   */
  private function processDnParts($dn): void {
    // 1. Tokenize dn
    // Escapes attribute values, need to be unescaped later.
    $dn_parts = self::splitDnWithAttributes($dn);
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
        $this->tokens[sprintf('[%s]', mb_strtolower($name))] = $value;
        $parts_count[$name] = 0;
      }
      $this->tokens[sprintf('[%s:%s]', mb_strtolower($name), $parts_count[$name])] = $value;

      $parts_last_value[$name] = $value;
      $parts_count[$name]++;
    }

    // Add DN parts in reverse order to reflect the hierarchy for CN, OU, DC.
    foreach ($parts_count as $name => $count) {
      $part = mb_strtolower($name);
      for ($i = 0; $i < $count; $i++) {
        $reverse_position = $count - $i - 1;
        $this->tokens[sprintf('[%s:reverse:%s]', $part, $reverse_position)] = $this->tokens[sprintf('[%s:%s]', $part, $i)];
      }
    }

    foreach ($parts_count as $name => $count) {
      $this->tokens[sprintf('[%s:last]', mb_strtolower($name))] = $parts_last_value[$name];
    }
  }

  /**
   * Get Tokens.
   *
   * @return array
   *   Tokens.
   */
  public function getTokens(): array {
    return $this->tokens;
  }

  /**
   * Process a single LDAP Token key.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   Entry.
   * @param string $required_token
   *   What was given as replacement pattern. For example 'dn', 'mail:0',
   *   'mail:last', or 'guid:0;tobase64'.
   */
  private function processLdapTokenKey(Entry $entry, string $required_token): void {
    // Trailing period to allow for empty value.
    [$token_key, $conversion] = explode(';', $required_token . ';');


    $parts = explode(':', $token_key);
    $requested_name = mb_strtolower($parts[0]);
    if ($requested_name === 'dn') {
      return;
    }

    $requested_index = $parts[1] ?? 0;

    $value = NULL;
    $available_attributes = $entry->getAttributes();
    foreach ($available_attributes as $attribute_key => $attribute_value) {
      if ($requested_name === mb_strtolower($attribute_key)) {
        $value = $attribute_value;
      }
    }

    // Don't use empty() since a 0, "", etc value may be a desired value.
    if ($value === NULL) {
      return;
    }

    if ($requested_index === 'last') {
      $i = count($value) > 0 ? count($value) - 1 : 0;
      $value = $value[$i];
    }
    elseif (is_numeric($requested_index)) {
      $value = $value[$requested_index];
    }
    else {
      // Don't add token if case not covered.
      return;
    }

    $value = ConversionHelper::convertAttribute($value, $conversion);

    $this->tokens[sprintf('[%s]', mb_strtolower($required_token))] = $value;
  }

}

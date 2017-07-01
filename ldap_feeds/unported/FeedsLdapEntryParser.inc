<?php

/**
 * @file
 * Provides the Parser for an ldap entry array.
 */

use Drupal\feeds\Annotation\FeedsParser;
use Drupal\feeds\Annotation\FeedsSource;

/**
 *
 */
class FeedsLdapEntryParser extends FeedsParser {
  public $ldap_result;

  /**
   * Implements FeedsParser::parse().
   */
  public function parse(FeedsSource $source, FeedsFetcherResult $fetcher_result) {

    $mappings = feeds_importer($this->id)->processor->config['mappings'];
    $ldap_entries = $fetcher_result->ldap_result;
    $parsed_items = [];
    for ($i = 0; $i < $ldap_entries['count']; $i++) {
      $ldap_entry = $ldap_entries[$i];
      $parsed_item = ['dn' => (string) $ldap_entry['dn']];
      foreach ($mappings as $j => $map) {
        $source_lcase = drupal_strtolower($map['source']);
        $source = $map['source'];
        if (isset($ldap_entry['attr'])) {
          /**
           * Exception need because of unconventional format of LDAP data
           * returned from $ldap_server->matchUsernameToExistingLdapEntry.
           */
          $ldap_attributes = $ldap_entry['attr'];
        }
        else {
          $ldap_attributes = $ldap_entry;
        }
        if ($source_lcase != 'dn' && isset($ldap_attributes[$source_lcase][0])) {
          if ($ldap_attributes[$source_lcase]['count'] == 1 && is_scalar($ldap_attributes[$source_lcase][0])) {
            $parsed_item[$source] = (string) $ldap_attributes[$source_lcase][0];
          }
        }
      }
      $parsed_items[] = $parsed_item;
    }
    $result = new FeedsParserResult();
    $result->items = $parsed_items;
    return $result;
  }

  /**
   * Source form.
   */
  public function sourceForm($source_config) {
    $form = [];
    $mappings = feeds_importer($this->id)->processor->config['mappings'];
    if (empty($source_config)) {
      $source_config = $this->config;
    }
    return $form;
  }

  /**
   * Override parent::configFormValidate().
   */
  public function configFormValidate(&$values) {
    $this->setConfig(['sources' => $values]);
    $this->save();
  }

  /**
   * Override parent::getMappingSources().
   */
  public function getMappingSources() {
    return FALSE;
  }

  /**
   * Override parent::configDefaults().
   */
  public function configDefaults() {
    /** removed until design decisions on multivalued attributes are made
     * return array(
     * 'multivalued' => LDAP_FEEDS_QUERY_FETCHER_MULTI_DEFAULT,
     * );
     *   */
    return [];
  }

  /**
   * Override parent::configForm().
   */
  public function configForm(&$form_state) {
    $form = [];
    return $form;
  }

  /**
   *
   */
  public function sourceDefaults() {
    return [];
  }

}

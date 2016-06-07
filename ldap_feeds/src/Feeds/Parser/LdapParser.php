<?php


/**
 * @file
 * Contains \Drupal\ldap_feeds\Feeds\Parser\LdapParser.
 */

namespace Drupal\ldap_feeds\Feeds\Parser;

use Drupal\feeds\Exception\EmptyFeedException;
use Drupal\feeds\FeedInterface;
use Drupal\feeds\Feeds\Item\SyndicationItem;
use Drupal\feeds\Plugin\Type\Parser\ParserInterface;
use Drupal\feeds\Plugin\Type\PluginBase;
use Drupal\feeds\Result\FetcherResultInterface;
use Drupal\feeds\Result\ParserResult;
use Drupal\feeds\StateInterface;
use Zend\Feed\Reader\Exception\ExceptionInterface;
use Zend\Feed\Reader\Reader;

use Drupal\ldap_user\LdapUserConfAdmin;
/**
 * Defines an RSS and Atom feed parser.
 *
 * @FeedsParser(
 *   id = "ldap",
 *   title = @Translation("LDAP Entry Parser for Feeds"),
 *   description = @Translation("Parse an LDAP Entry Array.")
 * )
 */
class LdapParser extends PluginBase implements ParserInterface {

  public $ldap_result;

  /**
   * Implements FeedsParser::parse().
   */
  public function parse(FeedInterface $feed, FetcherResultInterface $fetcher_result, StateInterface $state) {

    // FIXME Disable parsing for now.
    $result = new ParserResult();
    return $result;


    $mappings = feeds_importer($this->id)->processor->config['mappings'];
    $ldap_entries = $fetcher_result->ldap_result;
    $parsed_items = array();
    for ($i = 0; $i < $ldap_entries['count']; $i++) {
      $ldap_entry = $ldap_entries[$i];
      $parsed_item = array('dn' => (string) $ldap_entry['dn']);
      foreach ($mappings as $j => $map) {
        $source_lcase = drupal_strtolower($map['source']);
        $source = $map['source'];
        if (isset($ldap_entry['attr'])) {
          // Exception need because of unconvential format of ldap data returned from $ldap_server->userUserNameToExistingLdapEntry.
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
    $result = new ParserResult();
    $result->items = $parsed_items;
    return $result;
  }

  /**
   * Override parent::getMappingSources().
   */
  public function getMappingSources() {
    // @TODO get a list of fields from the LDAP server.
    // We could use the configured fields in ldap_user settings for now.
    // Later we could call query on the test user.

    // Currently Feeds for D8 doesn't allow arbitrary field sources (CSV is the example that is waiting to drop).

    // Get the rows from ldap_server
    // Get the rows from ldap_user
    // Get the rows from ldap_authorization (if it exists).

    module_load_include('module', 'ldap_user', 'ldap_user');
    $ldap_user_conf = ldap_user_conf();

    $sources = array();

    $fields = $ldap_user_conf_admin->synch_mapping_fields;
    foreach ( $ldap_user_conf->synchMapping as $mapping ) {
      foreach ($mapping as $key=>$row ) {
        if ( $row['source'] && ! is_object($row['source'])) {
          $sources[$row['source']] = [
            'label' => $this->t($row['source']),
            'description' => $this->t($row['source']),
          ];
        } else {
          $sources[$row['ldap_attr']] = [
            'label' => $row['ldap_attr'],
          ];
        }
      }
    }
    return $sources;
  }

}

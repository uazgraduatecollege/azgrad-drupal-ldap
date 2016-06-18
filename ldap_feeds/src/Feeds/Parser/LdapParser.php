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
use Drupal\Component\Utility\Unicode;

use Drupal\ldap_user\LdapUserConfAdmin;
use Drupal\ldap_feeds\Feeds\Item\LdapUserItem;
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

    $result = new ParserResult();

    foreach ( $fetcher_result->getResults() as $ldap_entry ) {
      $item = new LdapUserItem();
      $item->set('dn', (string) $ldap_entry['dn']);

      // Shouldn't really use getMappingSources. We should use the feed configuration.
      foreach ($this->getMappingSources() as $j => $map) {
        $source_lcase = Unicode::strtolower($map['label']);
        $source = $map['label'];
        $source_lcase = $this->sanitizeAttributeKey($source_lcase);
        if ( empty($source_lcase) ) {
          continue;
        }

        if (isset($ldap_entry['attr'])) {
          // Exception need because of unconvential format of ldap data returned from $ldap_server->userUserNameToExistingLdapEntry.
          $ldap_attributes = $ldap_entry['attr'];
        }
        else {
          $ldap_attributes = $ldap_entry;
        }

        if ($source_lcase != 'dn' && isset($ldap_attributes[$source_lcase][0])) {
          if ($ldap_attributes[$source_lcase]['count'] == 1 && is_scalar($ldap_attributes[$source_lcase][0])) {
            $item->set($source, (string) $ldap_attributes[$source_lcase][0]);
          }
        }
      }
      $result->addItem($item);
    }

    // Report progress.
    $state->total = count($result);
    $state->pointer = count($result);
    $state->progress($state->total, $state->pointer);

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

  private function sanitizeAttributeKey($key) {
    $key = trim($key);
    $key = ltrim($key, '[');
    $key = rtrim($key, ']');
    return $key;
  }

}

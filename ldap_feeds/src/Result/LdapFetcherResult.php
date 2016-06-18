<?php

namespace Drupal\ldap_feeds\Result;

use Drupal\feeds\Result\FetcherResult;

/**
 * The default fetcher result object.
 */
class LdapFetcherResult extends FetcherResult implements LdapFetcherResultInterface {

  public $results;

  /**
   * Constructs an LdapFetcherResult object.
   *
   * @param array $results
   *   An array of results (users).
   */
  public function __construct(array $results) {
    $this->results = $results;
  }

  public function getResults() {
    return $this->results;
  }

}

<?php

namespace Drupal\ldap_feeds\Result;

use Drupal\feeds\Result\FetcherResult;

/**
 * The default fetcher result object.
 */
class LdapFetcherResult extends FetcherResult implements LdapFetcherResultInterface {

  /**
   * Constructs an LdapFetcherResult object.
   *
   * @param array $results
   *   An array of results (users).
   */
  public function __construct(array $results) {
    parent::__construct($file_path);
    $this->results = $results;
    // $this->headers = array_change_key_case($headers);
  }

}

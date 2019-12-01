<?php

namespace Drupal\ldap_query;

/**
 * LDAP Query config entity interface.
 */
interface QueryEntityInterface {

  /**
   * Returns all base DN.
   *
   * @return array
   *   Processed base DN
   */
  public function getProcessedBaseDns(): array;

  /**
   * Returns all processed attributes.
   *
   * @return array
   *   Processed attributes.
   */
  public function getProcessedAttributes(): array;

  /**
   * Get filter.
   *
   * @return string
   *   Value.
   */
  public function getFilter(): string;

  /**
   * Get the size limit.
   *
   * @return int
   *   Value.
   */
  public function getSizeLimit(): int;

  /**
   * Get the time limit.
   *
   * @return int
   *   Value.
   */
  public function getTimeLimit(): int;

  /**
   * Get whether to dereference.
   *
   * @return int
   *   Value.
   */
  public function getDereference(): int;

  /**
   * Get scope.
   *
   * @return string
   *   Value.
   */
  public function getScope(): string;

  /**
   * Get the server ID.
   *
   * @return string
   *   Value.
   */
  public function getServerId(): string;

  /**
   * Whether the query is active.
   *
   * @return bool
   *   Value.
   */
  public function isActive(): bool;

}

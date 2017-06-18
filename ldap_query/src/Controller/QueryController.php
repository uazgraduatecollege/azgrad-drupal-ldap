<?php

namespace Drupal\ldap_query\Controller;

use Drupal\ldap_query\Entity\QueryEntity;

/**
 *
 */
class QueryController {

  private $results = [];
  private $qid;
  private $query;

  public function __construct($id) {
    $this->qid = $id;
    $this->query = QueryEntity::load($this->qid);
  }

  public function getFilter() {
    return $this->query->get('filter');
  }

  /**
   * @param null|string $filter
   *   Optional parameter to override filters. Useful for Views and other
   *   queries requiring filtering.
   */
  public function execute($filter = NULL) {
    $count = 0;

    if ($this->query) {
      $factory = \Drupal::service('ldap.servers');
      /** @var \Drupal\ldap_servers\Entity\Server $ldap_server */
      $ldap_server = $factory->getServerById($this->query->get('server_id'));
      $ldap_server->connect();
      $ldap_server->bind();

      if ($filter == NULL) {
        $filter = $this->query->get('filter');
      }

      foreach ($this->query->getProcessedBaseDns() as $base_dn) {
        $result = $ldap_server->search(
          $base_dn,
          $filter,
          $this->query->getProcessedAttributes(),
          0,
          $this->query->get('size_limit'),
          $this->query->get('time_limit'),
          $this->query->get('dereference'),
          $this->query->get('scope')
        );

        if ($result !== FALSE && $result['count'] > 0) {
          $count = $count + $result['count'];
          $this->results = array_merge($this->results, $result);
        }
      }
      $this->results['count'] = $count;
    }
    else {
      \Drupal::logger('ldap_query')->warning('Could not load query @query', ['@query' => $this->qid]);
    }
  }

  public function getRawResults() {
    return $this->results;
  }

  public function availableFields() {
    $attributes = [];
    /**
     * We loop through all results since some users might not have fields set
     * for them and those are missing and not null.
     */
    foreach ($this->results as $result) {
      if (is_array($result)) {
        foreach ($result as $k => $v) {
          if (is_numeric($k)) {
            $attributes[$v] = $v;
          }
        }
      }
    }
    return $attributes;
  }

  /**
   * TODO: Unported.
   * @deprecated
   */
  public function ldap_query_cache_clear() {
    $this->ldap_query_get_queries(NULL, 'all', FALSE, TRUE);
  }

  /**
   * @deprecated
   * Return ldap query objects.
   *
   * @param string $qid
   * @param string $type
   *   Either all or enabled.
   * @param bool $flatten
   *   signifies if array or single object returned.  Only works if sid is specified.
   * @param bool $reset
   *   do not use cached or static result.
   *
   * @return array|bool
   *   Array of server conf object keyed on sid, single server conf object
   *   (if flatten == TRUE).
   */
  public function ldap_query_get_queries($qid = NULL, $type, $flatten = FALSE, $reset = FALSE) {
    static $queries;

    if ($reset) {
      $queries = [];
    }
    if (!isset($queries['all'])) {
      $queries['all'] = $this->getLdapQueryObjects('all', 'all');
    }
    if (!isset($queries['enabled'])) {
      $queries['enabled'] = [];
      foreach ($queries['all'] as $_qid => $ldap_query) {
        if ($ldap_query->status == 1) {
          $queries['enabled'][$_qid] = $ldap_query;
        }
      }
    }

    if ($qid) {
      if (!isset($queries[$type][$qid])) {
        return FALSE;
      }
      return ($flatten) ? $queries[$type][$qid] : $queries[$type];
    }

    if (isset($queries[$type])) {
      return $queries[$type];
    }
  }

  /**
   *
   */
  public function getAllQueries() {
    $query = \Drupal::entityQuery('ldap_query_entity');
    $ids = $query->execute();
    return QueryEntity::loadMultiple($ids);
  }

  /**
   *
   */
  public function getAllEnabledQueries() {
    $query = \Drupal::entityQuery('ldap_query_entity')
      ->condition('status', 1);
    $ids = $query->execute();
    return QueryEntity::loadMultiple($ids);
  }

  /**
   * @deprecated
   * @param string $sid
   * @param string $type
   * @param string $class
   * @return array|\Drupal\Core\Entity\EntityInterface[]|static[]
   */
  public function getLdapQueryObjects($sid = 'all', $type = 'enabled', $class = 'LdapQuery') {
    // Deprecated, see getAllEnabledQueries() / getAllQueries().
    if ($sid != 'all' && !empty($sid)) {
      return $this->query($sid);
    }
    elseif ($sid = 'all' && $type = 'enabled') {
      return $this->getAllEnabledQueries();
    }
    else {
      return $this->getAllQueries();
    }
  }

}

<?php

namespace Drupal\ldap_query\Controller;

use Drupal\ldap_query\Entity\QueryEntity;
use Drupal\ldap_servers\Entity\Server;
use Symfony\Component\HttpFoundation\Response;

class QueryController {
  public function query($id) {
    $query = QueryEntity::load($id);
    $results = [];
    $count = 0;

    if ($query) {
      $factory = \Drupal::service('ldap.servers');
      /* @var Server $ldap_server */
      $ldap_server = $factory->getServerById( $query->get('server_id'));
      $ldap_server->connect();
      $ldap_server->bind();
      foreach ($query->getProcessedBaseDns() as $base_dn) {
        $result = $ldap_server->search(
          $base_dn,
          $query->get('filter'),
          $query->getProcessedAttributes(),
          0,
          $query->get('size_limit'),
          $query->get('time_limit'),
          $query->get('dereference'),
          $query->get('scope')
        );

        if ($result !== FALSE && $result['count'] > 0) {
          $count = $count + $result['count'];
          $results = array_merge($results, $result);
        }
      }
      $results['count'] = $count;
    } else {
      \Drupal::logger('ldap_query')->warning('Could not load query @query', ['@query' => $id]);
    }

    return $results;
  }

  /**
   * TODO: Unported.
   */
  public function ldap_query_cache_clear() {
    $this->ldap_query_get_queries(NULL, 'all', FALSE, TRUE);
  }

  /**
   * Return ldap query objects.
   * TODO: Unported.
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
      $queries = array();
    }
    if (!isset($queries['all'])) {
      $queries['all'] = $this->getLdapQueryObjects('all', 'all');
    }
    if (!isset($queries['enabled'])) {
      $queries['enabled'] = array();
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

  public function getAllQueries() {
    $query = \Drupal::entityQuery('ldap_query_entity');
    $ids = $query->execute();
    return QueryEntity::loadMultiple($ids);
  }

  public function getAllEnabledQueries() {
    $query = \Drupal::entityQuery('ldap_query_entity')
      ->condition('status', 1);
    $ids = $query->execute();
    return QueryEntity::loadMultiple($ids);
  }

  /**
   * TODO: Remove placeholder.
   * @deprecated
   */
  public function getLdapQueryObjects($sid = 'all', $type = 'enabled', $class = 'LdapQuery') {
    // Deprecated, see getAllEnabledQueries() / getAllQueries().
    if ($sid != 'all' && !empty($sid)) {
      return $this->query($sid);
    } else if ($sid = 'all' && $type = 'enabled') {
      return $this->getAllEnabledQueries();
    } else {
      return $this->getAllQueries();
    }
  }

}
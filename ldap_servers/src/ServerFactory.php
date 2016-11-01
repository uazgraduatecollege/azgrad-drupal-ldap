<?php

namespace Drupal\ldap_servers;

use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\tests\TestServer;

/**
 *
 */
class ServerFactory {

  public $servers;

  /**
   * Return ldap server conf objects.
   *
   * @param string $sid
   * @param string $type
   *   'all', 'enabled',.
   * @param bool $flatten
   *   Signifies if array or single object returned.
   *   Only works if sid is specified.
   * @param bool $reset
   *   do not use cached or static result.
   *
   * @return array|bool|mixed
   *  Array of server conf object keyed on sid, single server conf object (if
   *  flatten == TRUE).
   */
  public function __construct($sid = NULL, $type = NULL, $flatten = FALSE, $reset = FALSE) {
    if (\Drupal::config('ldap_test.settings')->get('simpletest')) {
      $this->servers = $this->getWebTestServers($sid, $type, $flatten, $reset);
    }
    else {
      $this->servers = $this->getServers($sid, $type, $flatten, $reset);
    }
  }

  /**
   * See new ServerFactory().
   *
   * @param $id
   * @param $type
   * @param $flatten
   * @param $reset
   *
   * @return array|bool|mixed
   */
  private function getServers($id, $type, $flatten, $reset) {
    if ($id) {
      return Server::load($id);
    }

    $type = ($type) ? $type : 'all';
    if ($reset) {
      $servers = array();
    }
    if (!isset($servers['all'])) {
      $query = \Drupal::entityQuery('ldap_server');
      $ids = $query->execute();
      $servers['all'] = Server::loadMultiple($ids);
    }

    if (!isset($servers['enabled'])) {
      $servers['enabled'] = array();
      foreach ($servers['all'] as $_id => $ldap_server) {
        if ($ldap_server->get('status') == 1) {
          $servers['enabled'][$_id] = $ldap_server;
        }
      }
    }

    if ($id) {
      if (!isset($servers[$type][$id])) {
        return FALSE;
      }
      return ($flatten) ? $servers[$type][$id] : array($id => $servers[$type][$id]);
    }

    if (isset($servers[$type])) {
      return $servers[$type];
    }
  }

  /**
   * @param $sid
   * @param null $type
   * @param $flatten
   * @param bool $reset
   * @return array|bool
   */
  private function getWebTestServers($sid, $type = NULL, $flatten, $reset = TRUE) {

    if (!$type) {
      $type = 'all';
    }

    // Two flavors of mock servers exist.  ultimately v2 will be used in all simpletests.
    if (\Drupal::config('ldap_test.settings')->get('simpletest') == 2) {
      $servers['all'] = TestServer::getLdapServerObjects(NULL, 'all', FALSE);
      foreach ($servers['all'] as $_sid => $ldap_server) {
        if ($ldap_server->status == 1) {
          $servers['enabled'][$_sid] = $ldap_server;
        }
      }
    }

    if ($sid) {
      if (!isset($servers[$type][$sid])) {
        return FALSE;
      }
      return ($flatten) ? $servers[$type][$sid] : array($sid => $servers[$type][$sid]);
    }

    if (isset($servers[$type])) {
      return $servers[$type];
    }
  }

}

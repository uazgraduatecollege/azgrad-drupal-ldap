<?php

namespace Drupal\ldap_servers;

use Drupal\ldap_servers\Entity\Server;

/**
 *
 */
class ServerFactory {

  public function getServerById($sid) {
  return Server::load($sid);
  }

  public function getServerByIdEnabled($sid) {
    $server = Server::load($sid);
    if ($server->status()) {
      return Server::load($sid);
    } else {
      return FALSE;
    }
  }

  public function getAllServers() {
    $query = \Drupal::entityQuery('ldap_server');
    $ids = $query->execute();
    return Server::loadMultiple($ids);
  }

  public function getEnabledServers() {
    $query = \Drupal::entityQuery('ldap_server')
      ->condition('status', 1);
    $ids = $query->execute();
    return Server::loadMultiple($ids);
  }

}

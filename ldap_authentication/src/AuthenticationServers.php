<?php

namespace Drupal\ldap_authentication;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;

/**
 * Class AuthenticationServers.
 */
class AuthenticationServers {

  protected $storage;
  protected $config;

  protected $servers;
  protected $queried;

  /**
   * Constructs a new AuthenticationServers object.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   Entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   Config factory.
   */
  public function __construct(EntityTypeManagerInterface $entity_type_manager, ConfigFactoryInterface $config_factory) {
    $this->storage = $entity_type_manager->getStorage('ldap_server');
    $this->config = $config_factory->get('ldap_authentication.settings');
  }

  /**
   * @return bool
   */
  public function authenticationServersAvailable() {
    if (empty($this->getAvailableAuthenticationServers())) {
      return FALSE;
    }
    else {
      return TRUE;
    }
  }

  /**
   * @return array
   */
  public function getAvailableAuthenticationServers() {
    $available_servers = $this->storage
      ->getQuery()
      ->condition('status', 1)
      ->execute();

    $result = [];
    foreach ($this->config->get('sids') as $configured_server) {
      if (isset($available_servers[$configured_server])) {
        $result[] = $configured_server;
      }
    }
    return $result;
  }

}

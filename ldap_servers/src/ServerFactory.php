<?php

namespace Drupal\ldap_servers;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\externalauth\Authmap;
use Drupal\externalauth\ExternalAuth;
use Drupal\user\UserInterface;

/**
 * Helper class to working with the Server classes.
 *
 * Normally called if you need specific sets of serves, such as all enabled
 * ones.
 *
 * @Todo: Split class to remove out-of-scope functions.
 */
class ServerFactory implements LdapUserAttributesInterface {

  use StringTranslationTrait;

  protected $config;
  protected $logger;
  protected $storage;
  protected $cache;
  protected $externalAuth;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   * @param \Drupal\Core\Entity\EntityTypeManager $entity_type_manager
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   * @param \Drupal\externalauth\Authmap $external_auth
   *
   * @throws \Drupal\Component\Plugin\Exception\InvalidPluginDefinitionException
   * @throws \Drupal\Component\Plugin\Exception\PluginNotFoundException
   */
  public function __construct(ConfigFactoryInterface $config_factory, LoggerChannelInterface $logger, EntityTypeManager $entity_type_manager, CacheBackendInterface $cache, Authmap $external_auth) {
    $this->config = $config_factory;
    $this->logger = $logger;
    $this->storage = $entity_type_manager->getStorage('ldap_server');
    $this->cache = $cache;
    $this->externalAuth = $external_auth;
  }

  /**
   * Fetch user data from server by Identifier.
   *
   * @param string $identifier
   *   User identifier.
   * @param string $id
   *   Server id.
   *
   * @return \Symfony\Component\Ldap\Entry|false
   *
   * @deprecated moved to LdapUserManager
   */
  public function getUserDataFromServerByIdentifier($identifier, $id) {
    // Try to retrieve the user from the cache.
    $cache = $this->cache->get('ldap_servers:user_data:' . $identifier);
    if ($cache && $cache->data) {
      return $cache->data;
    }

    /** @var \Drupal\ldap_servers\Entity\Server $server */
    $server = $this->storage->load($id);

    if (!$server || !$server->status()) {
      $this->logger->error('Failed to load server object %sid in _ldap_servers_get_user_ldap_data', ['%sid' => $id]);
      return FALSE;
    }

    $ldap_entry = $server->matchUsernameToExistingLdapEntry($identifier);
    if ($ldap_entry) {
      $cache_expiry = 5 * 60 + time();
      $cache_tags = ['ldap', 'ldap_servers', 'ldap_servers.user_data'];
      $this->cache->set('ldap_servers:user_data:' . $identifier, $ldap_entry, $cache_expiry, $cache_tags);
    }

    return $ldap_entry;
  }

  /**
   * Fetch user data from server by user account.
   *
   * @param \Drupal\user\UserInterface $account
   *   Drupal user account.
   * @param string $id
   *   Server id.
   *
   * @return array|bool
   *   Returns data or FALSE.
   *
   * @deprecated moved to LdapUserManager
   */
  public function getUserDataFromServerByAccount(UserInterface $account, $id) {
    $identifier = $this->externalAuth->get($account->id(), 'ldap_user');
    if ($identifier) {
      return $this->getUserDataFromServerByIdentifier($identifier, $id);
    }
    else {
      return FALSE;
    }
  }

}

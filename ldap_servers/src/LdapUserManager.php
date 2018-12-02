<?php

namespace Drupal\ldap_servers;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\externalauth\Authmap;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\user\UserInterface;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\LdapException;

/**
 * LDAP User Manager.
 */
class LdapUserManager extends LdapBaseManager {


  protected $cache;
  protected $externalAuth;

  /**
   *
   */
  public function __construct(
    LoggerChannelInterface $logger,
    EntityTypeManager $entity_type_manager,
    LdapBridge $ldap_bridge,
    ModuleHandler $module_handler,
    CacheBackendInterface $cache,
    Authmap $external_auth) {
    parent::__construct($logger, $entity_type_manager, $ldap_bridge, $module_handler);
    $this->cache = $cache;
    $this->externalAuth = $external_auth;
  }

  /**
   * Create LDAP User entry.
   *
   * Adds AD-specific password handling.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *
   * @return bool
   *   Result of action.
   */
  public function createLdapEntry(Entry $entry) {
    $this->checkAvailability();

    if ($entry->hasAttribute('unicodePwd') && $this->get('type') == 'ad') {
      $entry->setAttribute('unicodePwd', [$this->convertPasswordForActiveDirectoryUnicodePwd($entry->getAttribute('unicodePwd')[0])]);
    }

    try {
      $this->ldap->getEntryManager()->add($entry);
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP server %id exception: %ldap_error", [
        '%id' => $this->id(),
        '%ldap_error' => $e->getMessage(),
      ]
      );
      return FALSE;
    }
    return TRUE;
  }

  /**
   *
   */
  protected function applyModificationsToEntry(Entry $entry, $current) {
    if (!empty($attributes['unicodePwd']) && $this->get('type') == 'ad') {
      $attributes['unicodePwd'] = $this->convertPasswordForActiveDirectoryunicodePwd($attributes['unicodePwd']);
    }

    parent::applyModificationsToEntry($entry, $current);
  }

  /**
   * Convert password to format required by Active Directory.
   *
   * For the purpose of changing or setting the password. Note that AD needs the
   * field to be called unicodePwd (as opposed to userPassword).
   *
   * @param string $password
   *   The password that is being formatted for Active Directory unicodePwd
   *   field.
   *
   * @return string|array
   *   $password surrounded with quotes and in UTF-16LE encoding
   */
  protected function convertPasswordForActiveDirectoryUnicodePwd($password) {
    // This function can be called with $attributes['unicodePwd'] as an array.
    if (!is_array($password)) {
      return mb_convert_encoding("\"{$password}\"", "UTF-16LE");
    }
    else {
      // Presumably there is no use case for there being more than one password
      // in the $attributes array, hence it will be at index 0 and we return in
      // kind.
      return [mb_convert_encoding("\"{$password[0]}\"", "UTF-16LE")];
    }
  }

  /**
   * @deprecated
   */
  public function matchUsernameToExistingLdapEntry($drupal_username) {
    $result = $this->queryAllBaseDnLdapForUsername($drupal_username);
    if ($result !== FALSE) {
      $result = $this->sanitizeUserDataResponse($result, $drupal_username);
    }
    return $result;
  }

  /**
   * Queries LDAP server for the user.
   *
   * @param string $drupal_username
   *   Drupal user name.
   *
   * @return \Symfony\Component\Ldap\Entry|false|null
   *
   * @Todo: This function does return data and check for validity of response.
   *  This makes responses difficult to parse and should be optimized.
   */
  public function queryAllBaseDnLdapForUsername($drupal_username) {
    $this->checkAvailability();

    foreach ($this->server->getBaseDn() as $base_dn) {
      $result = $this->queryLdapForUsername($base_dn, $drupal_username);
      if ($result === FALSE || $result instanceof Entry) {
        return $result;
      }
    }
    return FALSE;
  }

  /**
   * Queries LDAP server for the user.
   *
   * @param string $base_dn
   *   Base DN.
   * @param string $drupal_username
   *   Drupal user name.
   *
   * @return \Symfony\Component\Ldap\Entry|false|null
   *
   * @throws \Drupal\ldap_servers\Exception\LdapManagerException
   *
   * @Todo: This function does return data and check for validity of response.
   *  This makes responses difficult to parse and should be optimized.
   */
  public function queryLdapForUsername($base_dn, $drupal_username) {
    $this->checkAvailability();

    if (empty($base_dn)) {
      return NULL;
    }

    $query = '(' . $this->server->get('user_attr') . '=' . ConversionHelper::escapeFilterValue($drupal_username) . ')';
    try {
      $ldap_response = $this->ldap->query($base_dn, $query)->execute();
    }
    catch (LdapException $e) {
      // Must find exactly one user for authentication to work.
      $this->logger->error('LDAP server query error %message', [
        '%message' => $e->getMessage(),
      ]
      );
      return FALSE;
    }

    if ($ldap_response->count() == 0) {
      return NULL;
    }
    elseif ($ldap_response->count() != 1) {
      // Must find exactly one user for authentication to work.
      $this->logger->error('Error: %count users found with %filter under %base_dn.', [
        '%count' => $ldap_response->count(),
        '%filter' => $query,
        '%base_dn' => $base_dn,
      ]
      );
      return NULL;
    }
    return $ldap_response->toArray()[0];
  }

  /**
   *
   */
  public function sanitizeUserDataResponse(Entry $entry, $drupal_username) {
    // TODO: Make this more elegant.
    foreach ($entry->getAttributes() as $key => $value) {
      $entry->removeAttribute($key);
      $entry->setAttribute(mb_strtolower($key), $value);
    }

    // TODO: Remove this if we are sure no one needs it anymore.
    $entry->setAttribute('ldap_server_id', [$this->server->id()]);

    if ($this->server->get('bind_method') == 'anon_user') {
      return $entry;
    }

    // Filter out results with spaces added before or after, which are
    // considered OK by LDAP but are no good for us. Some setups have multiple
    // $nameAttribute per entry, so we loop through all possible options.
    foreach ($entry->getAttribute($this->server->get('user_attr')) as $value) {
      if (mb_strtolower(trim($value)) == mb_strtolower($drupal_username)) {
        return $entry;
      }
    }
  }

  /**
   * Fetches the user account based on the persistent UID.
   *
   * @param string $puid
   *   As returned from ldap_read or other LDAP function (can be binary).
   *
   * @return false|UserInterface|EntityInterface
   *   The updated user or error.
   */
  public function getUserAccountFromPuid($puid) {
    $this->checkAvailability();

    $query = $this->entityTypeManager->getStorage('user')->getQuery();
    $query->condition('ldap_user_puid_sid', $this->server->id(), '=')
      ->condition('ldap_user_puid', $puid, '=')
      ->condition('ldap_user_puid_property', $this->server->get('unique_persistent_attr'), '=')
      ->accessCheck(FALSE);
    $result = $query->execute();

    if (!empty($result)) {
      if (count($result) == 1) {
        return $this->entityTypeManager->getStorage('user')->load(array_values($result)[0]);
      }
      else {
        $uids = implode(',', $result);
        $this->logger->error('Multiple users (uids: %uids) with same puid (puid=%puid, sid=%sid, ldap_user_puid_property=%ldap_user_puid_property)', [
          '%uids' => $uids,
          '%puid' => $puid,
          '%id' => $this->server->id(),
          '%ldap_user_puid_property' => $this->server->get('unique_persistent_attr'),
        ]
        );
      }
    }
    return FALSE;
  }

  /**
   * Fetch user data from server by Identifier.
   *
   * @param string $identifier
   *   User identifier.
   *
   * @return \Symfony\Component\Ldap\Entry|false
   *
   *   This should go into LdapUserProcessor or LdapUserManager, leaning toward the former.
   */
  public function getUserDataByIdentifier($identifier) {
    $this->checkAvailability();

    // Try to retrieve the user from the cache.
    $cache = $this->cache->get('ldap_servers:user_data:' . $identifier);
    if ($cache && $cache->data) {
      return $cache->data;
    }

    $ldap_entry = $this->queryAllBaseDnLdapForUsername($identifier);
    if ($ldap_entry) {
      $ldap_entry = $this->sanitizeUserDataResponse($ldap_entry, $identifier);
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
   *
   * @return array|bool
   *   Returns data or FALSE.
   *
   *   This should go into LdapUserProcessor or LdapUserManager, leaning toward the former.
   */
  public function getUserDataByAccount(UserInterface $account) {
    $this->checkAvailability();

    $identifier = $this->externalAuth->get($account->id(), 'ldap_user');
    if ($identifier) {
      return $this->getUserDataByIdentifier($identifier);
    }
    else {
      return FALSE;
    }
  }

}

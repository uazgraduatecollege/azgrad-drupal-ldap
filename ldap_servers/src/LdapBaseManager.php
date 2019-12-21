<?php

declare(strict_types=1);

namespace Drupal\ldap_servers;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\Entity\Server;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\LdapException;

/**
 * LDAP Base Manager.
 */
abstract class LdapBaseManager {

  use LdapTransformationTraits;

  /**
   * Logger.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected $logger;

  /**
   * Entity Type Manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * LDAP Bridge.
   *
   * @var \Drupal\ldap_servers\LdapBridge
   */
  protected $ldapBridge;

  /**
   * Module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandler
   */
  protected $moduleHandler;

  /**
   * Symfony Ldap.
   *
   * @var \Symfony\Component\Ldap\Ldap
   */
  protected $ldap;

  /**
   * Server.
   *
   * @var \Drupal\ldap_servers\Entity\Server
   */
  protected $server;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Logger\LoggerChannelInterface $logger
   *   Logger.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   Entity type manager.
   * @param \Drupal\ldap_servers\LdapBridge $ldap_bridge
   *   LDAP Bridge.
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   *   Module handler.
   */
  public function __construct(LoggerChannelInterface $logger, EntityTypeManagerInterface $entity_type_manager, LdapBridge $ldap_bridge, ModuleHandler $module_handler) {
    $this->logger = $logger;
    $this->entityTypeManager = $entity_type_manager;
    $this->ldapBridge = $ldap_bridge;
    $this->moduleHandler = $module_handler;
  }

  /**
   * Set server by ID.
   *
   * @param string $sid
   *   Server machine name.
   *
   * @return bool
   *   Binding successful.
   */
  public function setServerById($sid) {
    $server = $this->entityTypeManager->getStorage('ldap_server')->load($sid);
    return $this->setServer($server);
  }

  /**
   * Set server by ID.
   *
   * @param \Drupal\ldap_servers\Entity\Server $server
   *   LDAP Server.
   *
   * @return bool
   *   Binding successful.
   */
  public function setServer(Server $server) {
    $this->server = $server;
    $this->ldapBridge->setServer($this->server);
    $bind_result = $this->ldapBridge->bind();
    $this->ldap = $this->ldapBridge->get();
    return $bind_result;
  }

  /**
   * Check availability of service.
   *
   * We have to explicitly check this in many calls since the Server might not
   * have been set yet.
   */
  protected function checkAvailability() {
    if ($this->server && $this->ldapBridge->bind()) {
      return TRUE;
    }

    $this->logger->error("LDAP server unavailable");
    return FALSE;
  }

  /**
   * Does dn exist for this server and what is its data?
   *
   * @param string $dn
   *   DN to search for.
   * @param array $attributes
   *   In same form as ldap_read $attributes parameter.
   *
   * @return bool|Entry
   *   Return ldap entry or false.
   */
  public function checkDnExistsIncludeData($dn, array $attributes) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    $options = [
      'filter' => $attributes,
      'scope' => 'base',
    ];

    try {
      $result = $this->ldap->query($dn, '(objectclass=*)', $options)->execute();
    }
    catch (LdapException $e) {
      return FALSE;
    }

    if ($result->count() > 0) {
      return $result->toArray()[0];
    }

    return FALSE;
  }

  /**
   * Does dn exist for this server?
   *
   * @param string $dn
   *   DN to search for.
   *
   * @return bool
   *   DN exists.
   */
  public function checkDnExists($dn) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    $options = [
      'filter' => ['objectclass'],
      'scope' => 'base',
    ];

    try {
      $result = $this->ldap->query($dn, '(objectclass=*)', $options)->execute();
    }
    catch (LdapException $e) {
      return FALSE;
    }
    return $result->count() > 0;
  }

  /**
   * Perform an LDAP search on all base dns and aggregate into one result.
   *
   * @param string $filter
   *   The search filter, such as sAMAccountName=jbarclay. Attribute values
   *   (e.g. jbarclay) should be esacaped before calling.
   * @param array $attributes
   *   List of desired attributes. If omitted, we only return "dn".
   *
   * @return \Symfony\Component\Ldap\Entry[]
   *   An array of matching entries combined from all DN.
   */
  public function searchAllBaseDns($filter, array $attributes = []) {
    $all_entries = [];

    if (!$this->checkAvailability()) {
      return $all_entries;
    }

    $options = [
      'filter' => $attributes,
    ];

    foreach ($this->server->getBaseDn() as $base_dn) {
      $relative_filter = str_replace(',' . $base_dn, '', $filter);
      try {
        $ldap_response = $this->ldap->query($base_dn, $relative_filter, $options)->execute();
      }
      catch (LdapException $e) {
        $this->logger->critical('LDAP search error with @message', [
          '@message' => $e->getMessage(),
        ]);
        continue;
      }

      if ($ldap_response->count() > 0) {
        $all_entries = array_merge($all_entries, $ldap_response->toArray());
      }
    }

    return $all_entries;
  }

  /**
   * Create LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   Entry.
   *
   * @return bool
   *   Result of action.
   */
  public function createLdapEntry(Entry $entry): bool {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    try {
      $this->ldap->getEntryManager()->add($entry);
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP server @sid exception: %ldap_error", [
        '@sid' => $this->server->id(),
        '%ldap_error' => $e->getMessage(),
      ]
      );
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Modify attributes of LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   LDAP entry.
   *
   * @return bool
   *   Result of query.
   */
  public function modifyLdapEntry(Entry $entry): bool {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    // TODO: Verify unicodePwd was modified if present through alter hook.
    try {
      $this->ldap->getEntryManager()->update($entry);
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP server error updating %dn on @sid exception: %ldap_error", [
        '%dn' => $entry->getDn(),
        '@sid' => $this->server->id(),
        '%ldap_error' => $e->getMessage(),
      ]
      );
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Perform an LDAP delete.
   *
   * @param string $dn
   *   DN of entry.
   *
   * @return bool
   *   Result of ldap_delete() call.
   */
  public function deleteLdapEntry($dn): bool {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    try {
      $this->ldap->getEntryManager()->remove(new Entry($dn));
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP entry '%dn' could not be delete from from server @sid: @message", [
        '%dn' => $dn,
        '@sid' => $this->id(),
        '@message' => $e->getMessage(),
      ]
      );
      return FALSE;
    }
    $this->logger->info("LDAP entry '%dn' deleted from server @sid", [
      '%dn' => $dn,
      '@sid' => $this->id(),
    ]);

    return TRUE;
  }

  /**
   * Apply modifications to entry.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   Entry.
   * @param \Symfony\Component\Ldap\Entry $current
   *   Current.
   */
  protected function applyModificationsToEntry(Entry $entry, Entry $current): void {
    // TODO: Make sure the empty attributes sent are actually an array.
    // TODO: Make sure that count et al are gone.
    foreach ($entry->getAttributes() as $new_key => $new_value) {
      if ($current->getAttribute($new_key) == $new_value) {
        $entry->removeAttribute($new_key);
      }
    }
  }

  /**
   * Match username to existing LDAP entry.
   *
   * @param string $drupal_username
   *   Drupal username.
   *
   * @return false|\Symfony\Component\Ldap\Entry
   *   LDAP Entry.
   *
   * @see \Drupal\ldap_servers\LdapUserManager::getUserDataByIdentifier
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
   * @return \Symfony\Component\Ldap\Entry|false
   *   LDAP Entry.
   *
   * @Todo: This function does return data and check for validity of response.
   *  This makes responses difficult to parse and should be optimized.
   */
  public function queryAllBaseDnLdapForUsername($drupal_username) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    foreach ($this->server->getBaseDn() as $base_dn) {
      $result = $this->queryLdapForUsername($base_dn, $drupal_username);
      if (!$result || $result instanceof Entry) {
        return $result;
      }
    }
    return FALSE;
  }

  /**
   * Sanitize user data response.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   LDAP entry.
   * @param string $drupal_username
   *   Drupal username.
   *
   * @return \Symfony\Component\Ldap\Entry
   *   LDAP Entry.
   */
  public function sanitizeUserDataResponse(Entry $entry, $drupal_username): ?Entry {
    // TODO: Make this more elegant.
    foreach ($entry->getAttributes() as $key => $value) {
      $entry->removeAttribute($key);
      $entry->setAttribute(mb_strtolower($key), $value);
    }

    // TODO: Remove this if we are sure no one needs it anymore.
    $entry->setAttribute('ldap_server_id', [$this->server->id()]);

    if ($this->server->get('bind_method') === 'anon_user') {
      return $entry;
    }

    // Filter out results with spaces added before or after, which are
    // considered OK by LDAP but are no good for us. Some setups have multiple
    // $nameAttribute per entry, so we loop through all possible options.
    foreach ($entry->getAttribute($this->server->getAuthenticationNameAttribute()) as $value) {
      if (mb_strtolower(trim($value)) === mb_strtolower($drupal_username)) {
        return $entry;
      }
    }
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
   *   LDAP entry.
   *
   * @Todo: This function does return data and check for validity of response.
   *  This makes responses difficult to parse and should be optimized.
   */
  public function queryLdapForUsername($base_dn, $drupal_username) {
    if (!$this->checkAvailability()) {
      return FALSE;
    }

    if (empty($base_dn)) {
      return NULL;
    }

    $query = sprintf('(%s=%s)', $this->server->getAuthenticationNameAttribute, $this->ldapEscapeFilter($drupal_username));
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

    if ($ldap_response->count() === 0) {
      return NULL;
    }
    elseif ($ldap_response->count() !== 1) {
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

}

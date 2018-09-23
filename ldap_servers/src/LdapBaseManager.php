<?php

namespace Drupal\ldap_servers;

use Drupal\Core\Entity\EntityTypeManager;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Logger\LoggerChannelInterface;
use Drupal\ldap_servers\Entity\Server;
use Drupal\ldap_servers\Exception\LdapManagerException;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\LdapException;

/**
 * LDAP Base Manager.
 */
abstract class LdapBaseManager {

  protected $logger;
  protected $entityTypeManager;
  protected $ldapBridge;
  protected $moduleHandler;

  /**
   * Ldap.
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
   * @param \Drupal\Core\Entity\EntityTypeManager $entity_type_manager
   *   Entity type manager.
   * @param \Drupal\ldap_servers\LdapBridge $ldap_bridge
   *   LDAP Bridge.
   * @param \Drupal\Core\Extension\ModuleHandler $module_handler
   */
  public function __construct(LoggerChannelInterface $logger, EntityTypeManager $entity_type_manager, LdapBridge $ldap_bridge, ModuleHandler $module_handler) {
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
   * @throws \Drupal\ldap_servers\Exception\LdapManagerException
   */
  protected function checkAvailability() {
    if (!$this->server) {
      throw new LdapManagerException('Server not set.');
    }
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
    $this->checkAvailability();

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
    else {
      return FALSE;
    }
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
    $this->checkAvailability();

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

    if ($result->count() > 0) {
      return TRUE;
    }
    else {
      return FALSE;
    }
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
    $this->checkAvailability();

    $all_entries = [];
    $options = [
      'filter' => $attributes,
    ];

    foreach ($this->server->getBaseDn() as $base_dn) {
      $relative_filter = str_replace(',' . $base_dn, '', $filter);
      try {
        $ldap_response = $this->ldap->query($base_dn, $relative_filter, $options)->execute();
      }
      catch (LdapException $e) {
        $this->logger->critical('LDAP search error with %message', [
          '%message' => $e->getMessage(),
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
   *
   * @return bool
   *   Result of action.
   */
  public function createLdapEntry(Entry $entry) {
    $this->checkAvailability();

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
   * Modify attributes of LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   LDAP entry.
   *
   * @return bool
   *   Result of query.
   *
   * @TODO: Untested, can potentially be simplified through symfony/ldap itself.
   */
  public function modifyLdapEntry(Entry $entry) {
    $this->checkAvailability();

    $error_message = FALSE;

    try {
      $current = $this->ldap->query($entry->getDn(), 'objectClass=*')->execute();
    }
    catch (LdapException $e) {
      $error_message = $e->getMessage();
    }

    if ($error_message || $current->count() != 0) {
      $this->logger->error("LDAP server read error on modify in %id: %message ", [
        '%message' => $error_message,
        '%id' => $this->id(),
      ]
      );
      return FALSE;
    }

    $this->applyModificationsToEntry($entry, $current->toArray()[0]);

    if (count($entry->getAttributes()) > 0) {
      try {
        $this->ldap->getEntryManager()->update($entry);
      }
      catch (LdapException $e) {
        $this->logger->error("LDAP server error updating %dn on %id: %message", [
          '%dn' => $entry->getDn(),
          '%id' => $this->id(),
          '%message' => $e->getMessage(),
        ]
        );
        return FALSE;
      }
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
  public function deleteLdapEntry($dn) {
    $this->checkAvailability();

    try {
      $this->ldap->getEntryManager()->remove(new Entry($dn));
    }
    catch (LdapException $e) {
      $this->logger->error("LDAP server deletion error on %id: %message", [
        '%message' => $e->getMessage(),
        '%id' => $this->id(),
      ]
      );
      return FALSE;
    }
    return TRUE;
  }

  /**
   * @param \Symfony\Component\Ldap\Entry $entry
   * @param $current
   */
  protected function applyModificationsToEntry(Entry $entry, Entry $current) {
    // TODO: Make sure the empty attributes sent are actually an array.
    // TODO: Make sure that count et al are gone.
    foreach ($entry->getAttributes() as $new_key => $new_value) {
      if ($current->getAttribute($new_key) == $new_value) {
        $entry->removeAttribute($new_key);
      }
    }
  }

}

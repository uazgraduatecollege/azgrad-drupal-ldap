<?php

namespace Drupal\ldap_servers\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\ldap_servers\Helper\ConversionHelper;
use Drupal\ldap_servers\LdapProtocolInterface;
use Drupal\ldap_servers\LdapTransformationTraits;
use Drupal\ldap_servers\ServerInterface;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Exception\LdapException;

/**
 * Defines the Server entity.
 *
 * @ConfigEntityType(
 *   id = "ldap_server",
 *   label = @Translation("LDAP Server"),
 *   handlers = {
 *     "list_builder" = "Drupal\ldap_servers\ServerListBuilder",
 *     "form" = {
 *       "add" = "Drupal\ldap_servers\Form\ServerForm",
 *       "edit" = "Drupal\ldap_servers\Form\ServerForm",
 *       "delete" = "Drupal\ldap_servers\Form\ServerDeleteForm",
 *       "test" = "Drupal\ldap_servers\Form\ServerTestForm",
 *       "enable_disable" = "Drupal\ldap_servers\Form\ServerEnableDisableForm"
 *     }
 *   },
 *   config_prefix = "server",
 *   admin_permission = "administer ldap",
 *   entity_keys = {
 *     "id" = "id",
 *     "label" = "label",
 *     "uuid" = "uuid"
 *   },
 *   links = {
 *     "edit-form" = "/admin/config/people/ldap/server/{server}/edit",
 *     "delete-form" = "/admin/config/people/ldap/server/{server}/delete",
 *     "collection" = "/admin/config/people/ldap/server"
 *   }
 * )
 */
class Server extends ConfigEntityBase implements ServerInterface, LdapProtocolInterface {

  use LdapTransformationTraits;

  const LDAP_SERVER_LDAP_QUERY_CHUNK = 50;
  const LDAP_SERVER_LDAP_QUERY_RECURSION_LIMIT = 10;


  /**
   * Server machine name.
   *
   * @var string
   */
  protected $id;

  /**
   * Human readable name.
   *
   * @var string
   */
  protected $label;

  /**
   * LDAP Server connection.
   *
   * @var resource|false
   */
  protected $connection = FALSE;

  /**
   * Logger channel.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * LDAP Details logger.
   *
   * @var \Drupal\ldap_servers\Logger\LdapDetailLog
   */
  protected $detailLog;

  /**
   * Token processor.
   *
   * @var \Drupal\ldap_servers\Processor\TokenProcessor
   */
  protected $tokenProcessor;

  /**
   * Module handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandler
   */
  protected $moduleHandler;

  /**
   * LDAP Bridge.
   *
   * @var \Drupal\ldap_servers\LdapBridge
   * @deprecated
   */
  protected $ldapBridge;

  /**
   * Symfony LDAP object.
   *
   * @var \Symfony\Component\Ldap\Ldap
   * @deprecated
   */
  protected $ldap;

  /**
   * Constructor.
   *
   * @param array $values
   * @param $entity_type
   */
  public function __construct(array $values, $entity_type) {
    parent::__construct($values, $entity_type);
    $this->logger = \Drupal::logger('ldap_servers');
    $this->detailLog = \Drupal::service('ldap.detail_log');
    $this->tokenProcessor = \Drupal::service('ldap.token_processor');
    $this->moduleHandler = \Drupal::service('module_handler');
    // TODO: The bridge should not be needed here.
    $this->ldapBridge = \Drupal::service('ldap.bridge');
    $this->ldapBridge->setServer($this);
  }

  /**
   * Returns the formatted label of the bind method.
   *
   * @return string
   *   The formatted text for the current bind.
   */
  public function getFormattedBind() {
    switch ($this->get('bind_method')) {
      case 'service_account':
      default:
        $namedBind = t('service account bind');
        break;

      case 'user':
        $namedBind = t('user credentials bind');
        break;

      case 'anon':
        $namedBind = t('anonymous bind (search), then user credentials');
        break;

      case 'anon_user':
        $namedBind = t('anonymous bind');
        break;
    }
    return $namedBind;
  }

  /**
   * Fetch base DN.
   *
   * @return array
   *   All base DN.
   *
   * @TODO: Improve storage in database (should be a proper array).
   */
  public function getBaseDn() {
    $baseDn = $this->get('basedn');

    if (!is_array($baseDn) && is_scalar($baseDn)) {
      $baseDn = explode("\r\n", $baseDn);
    }
    return $baseDn;
  }

  /**
   * Returns the username from the LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   The LDAP entry.
   *
   * @return string
   *   The user name.
   */
  public function deriveUsernameFromLdapResponse(Entry $ldap_entry) {
    $accountName = FALSE;

    if ($this->get('account_name_attr')) {
      if ($ldap_entry->hasAttribute($this->get('account_name_attr'))) {
        $accountName = $ldap_entry->getAttribute($this->get('account_name_attr'))[0];
      }
    }
    elseif ($this->get('user_attr')) {
      if ($ldap_entry->hasAttribute($this->get('user_attr'))) {
        $accountName = $ldap_entry->getAttribute($this->get('user_attr'))[0];
      }
    }

    return $accountName;
  }

  /**
   * Returns the user's email from the LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $ldap_entry
   *   The LDAP entry.
   *
   * @return string|bool
   *   The user's mail value or FALSE if none present.
   */
  public function deriveEmailFromLdapResponse(Entry $ldap_entry) {
    // Not using template.
    if ($this->get('mail_attr') && $ldap_entry->hasAttribute($this->get('mail_attr'))) {
      if ($ldap_entry->hasAttribute($this->get('mail_attr'))) {
        return $ldap_entry->getAttribute($this->get('mail_attr'))[0];
      }
      else {
        return FALSE;
      }
    }
    // Template is of form [cn]@illinois.edu.
    elseif ($this->get('mail_template')) {
      return $this->tokenProcessor->tokenReplace($ldap_entry, $this->get('mail_template'), 'ldap_entry');
    }
    else {
      return FALSE;
    }
  }

  /**
   * Fetches the persistent UID from the LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $ldapEntry
   *   The LDAP entry.
   *
   * @return string
   *   The user's PUID or permanent user id (within ldap), converted from
   *   binary, if applicable.
   */
  public function derivePuidFromLdapResponse(Entry $ldapEntry) {
    if ($this->get('unique_persistent_attr') && $ldapEntry->hasAttribute($this->get('unique_persistent_attr'))) {
      $puid = $ldapEntry->getAttribute($this->get('unique_persistent_attr'))[0];
      return ($this->get('unique_persistent_attr_binary')) ? ConversionHelper::binaryConversionToString($puid) : $puid;
    }
    else {
      return FALSE;
    }
  }

  /**
   * Fetches the user account based on the persistent UID.
   *
   * @param string $puid
   *   As returned from ldap_read or other LDAP function (can be binary).
   *
   * @return bool|User|EntityInterface
   *   The updated user or error.
   *
   * @deprecated copied to LdapUserManager
   */
  public function userAccountFromPuid($puid) {

    $query = \Drupal::entityQuery('user');
    $query
      ->condition('ldap_user_puid_sid', $this->id(), '=')
      ->condition('ldap_user_puid', $puid, '=')
      ->condition('ldap_user_puid_property', $this->get('unique_persistent_attr'), '=')
      ->accessCheck(FALSE);

    $result = $query->execute();

    if (!empty($result)) {
      if (count($result) == 1) {
        return $this->entityTypeManager()->getStorage('user')->load(array_values($result)[0]);
      }
      else {
        $uids = implode(',', $result);
        $this->logger->error('Multiple users (uids: %uids) with same puid (puid=%puid, sid=%sid, ldap_user_puid_property=%ldap_user_puid_property)', [
          '%uids' => $uids,
          '%puid' => $puid,
          '%id' => $this->id(),
          '%ldap_user_puid_property' => $this->get('unique_persistent_attr'),
        ]
        );
        return FALSE;
      }
    }
    else {
      return FALSE;
    }
  }

  /**
   * Only public for status overview page.
   *
   * @deprecated
   */
  private function bind() {
    if ($this->ldapBridge->bind()) {
      $this->ldap = $this->ldapBridge->get();
    }
  }

  /**
   * Checks if connected and connects and binds otherwise.
   *
   * @deprecated
   */
  public function connectAndBindIfNotAlready() {
    if (!$this->ldap) {
      $this->bind();
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
   *
   * @deprecated Copied to LdapBaseManager
   */
  public function checkDnExistsIncludeData($dn, array $attributes) {
    $this->connectAndBindIfNotAlready();

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
   *
   * @deprecated Copied to LdapBaseManager
   */
  public function checkDnExists($dn) {
    $this->connectAndBindIfNotAlready();

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
   * Modify attributes of LDAP entry.
   *
   * @param \Symfony\Component\Ldap\Entry $entry
   *   LDAP entry.
   *
   * @return bool
   *   Result of query.
   *
   * @deprecated copied to LdapBaseManager
   */
  public function modifyLdapEntry(Entry $entry) {
    $this->connectAndBindIfNotAlready();
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

    $current = $current->toArray()[0];

    if (!empty($attributes['unicodePwd']) && $this->get('type') == 'ad') {
      $attributes['unicodePwd'] = $this->convertPasswordForActiveDirectoryunicodePwd($attributes['unicodePwd']);
    }

    // TODO: Make sure the empty attributes sent are actually an array.
    // TODO: Make sure that count et al are gone.
    foreach ($entry->getAttributes() as $new_key => $new_value) {
      if ($current->getAttribute($new_key) == $new_value) {
        $entry->removeAttribute($new_key);
      }
    }

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
   *
   * @deprecated copied to LdapBaseManager.
   */
  public function searchAllBaseDns($filter, array $attributes = []) {
    $this->connectAndBindIfNotAlready();
    $all_entries = [];
    $options = [
      'filter' => $attributes,
    ];

    foreach ($this->getBaseDn() as $base_dn) {
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
   * Queries LDAP server for the user.
   *
   * @param string $drupal_username
   *   Drupal user name.
   *
   * @return \Symfony\Component\Ldap\Entry|false|null
   *
   *   Todo: This function does return data and check for validity of response,
   *   this makes responses difficult to parse and should be optimized.
   *
   * @deprecated Moved to LdapBaseManager.
   */
  public function matchUsernameToExistingLdapEntry($drupal_username) {

    $this->connectAndBindIfNotAlready();

    foreach ($this->getBaseDn() as $base_dn) {
      if (empty($base_dn)) {
        continue;
      }

      $query = '(' . $this->get('user_attr') . '=' . ConversionHelper::escapeFilterValue($drupal_username) . ')';

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
        continue;
      }
      elseif ($ldap_response->count() != 1) {
        // Must find exactly one user for authentication to work.
        $this->logger->error('Error: %count users found with %filter under %base_dn.', [
          '%count' => $ldap_response->count(),
          '%filter' => $query,
          '%base_dn' => $base_dn,
        ]
                );
        continue;
      }

      $match = $ldap_response->toArray()[0];
      // TODO: Make this more elegant.
      foreach ($match->getAttributes() as $key => $value) {
        $match->removeAttribute($key);
        $match->setAttribute(mb_strtolower($key), $value);
      }

      // TODO: Remove this if we are sure no one needs it anymore.
      $match->setAttribute('ldap_server_id', [$this->id()]);

      if ($this->get('bind_method') == 'anon_user') {
        return $match;
      }

      // Filter out results with spaces added before or after, which are
      // considered OK by LDAP but are no good for us. Some setups have multiple
      // $nameAttribute per entry, so we loop through all possible options.
      foreach ($match->getAttribute($this->get('user_attr')) as $value) {
        if (mb_strtolower(trim($value)) == mb_strtolower($drupal_username)) {
          return $match;
        }
      }
    }
  }

}
